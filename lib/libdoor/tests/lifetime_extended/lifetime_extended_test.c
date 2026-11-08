/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>
#include <sys/door_core.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define WORKER_COUNT 4
#define CALL_STATE_POLL_ATTEMPTS 1000
#define CALL_STATE_POLL_DELAY_US 10000

static int active_notify_fd = -1;
static int active_release_fd = -1;

static int
write_byte(int fd)
{
	char byte;

	byte = 'X';
	return (write(fd, &byte, sizeof(byte)) == sizeof(byte) ? 0 : -1);
}

static int
read_byte(int fd)
{
	char byte;
	ssize_t result;

	do {
		result = read(fd, &byte, sizeof(byte));
	} while (result == -1 && errno == EINTR);
	return (result == sizeof(byte) ? 0 : -1);
}

static int
send_fd(int socket_fd, int fd)
{
	char control[CMSG_SPACE(sizeof(fd))];
	char byte;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr message;

	byte = 'D';
	memset(&message, 0, sizeof(message));
	memset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control;
	message.msg_controllen = sizeof(control);
	cmsg = CMSG_FIRSTHDR(&message);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	message.msg_controllen = CMSG_SPACE(sizeof(fd));
	return (sendmsg(socket_fd, &message, 0) == 1 ? 0 : -1);
}

static int
receive_fd(int socket_fd)
{
	char control[CMSG_SPACE(sizeof(int))];
	char byte;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct msghdr message;
	int fd;

	memset(&message, 0, sizeof(message));
	memset(control, 0, sizeof(control));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control;
	message.msg_controllen = sizeof(control);
	if (recvmsg(socket_fd, &message, 0) != 1)
		return (-1);
	if ((message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
		errno = EMSGSIZE;
		return (-1);
	}
	cmsg = CMSG_FIRSTHDR(&message);
	if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(fd))) {
		errno = EPROTO;
		return (-1);
	}
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return (fd);
}

static void
blocking_server(void *cookie,
		char *data,
		size_t data_size,
		door_desc_t *descs,
		uint_t ndescs)
{
	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	if (write_byte(active_notify_fd) == -1)
		pthread_exit(NULL);
	if (read_byte(active_release_fd) == -1)
		pthread_exit(NULL);
	door_return(NULL, 0, NULL, 0);
}

static void
worker_exit_server(void *cookie,
		   char *data,
		   size_t data_size,
		   door_desc_t *descs,
		   uint_t ndescs)
{
	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	if (active_notify_fd >= 0)
		(void)write_byte(active_notify_fd);
	pthread_exit(NULL);
}

static void
echo_server(void *cookie,
	    char *data,
	    size_t data_size,
	    door_desc_t *descs,
	    uint_t ndescs)
{
	(void)cookie;
	(void)descs;
	(void)ndescs;

	door_return(data, data_size, NULL, 0);
}

static int
perform_empty_call(int fd)
{
	char reply[1];
	door_arg_t arg;

	test_init_call(&arg, reply, sizeof(reply));
	return (door_call(fd, &arg));
}

static int
perform_echo_call(int fd)
{
	static const char request[] = "extended-lifetime";
	char reply[sizeof(request)];
	door_arg_t arg;

	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = (char *)(uintptr_t)request;
	arg.data_size = sizeof(request);
	arg.rbuf = reply;
	arg.rsize = sizeof(reply);
	if (door_call(fd, &arg) == -1)
		return (-1);
	if (arg.data_size != sizeof(request) ||
	    memcmp(arg.data_ptr, request, sizeof(request)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static pid_t
spawn_call_expect_error(int fd, int expected_errno)
{
	pid_t child;

	child = fork();
	ATF_REQUIRE_MSG(child != -1, "fork failed: %s", strerror(errno));
	if (child == 0) {
		int actual_errno;

		alarm(TEST_TIMEOUT_SECONDS);
		errno = 0;
		if (perform_empty_call(fd) == -1) {
			actual_errno = errno;
			if (actual_errno == expected_errno)
				_exit(EXIT_SUCCESS);
			dprintf(STDERR_FILENO,
				"call child: expected errno=%d (%s), got "
				"errno=%d (%s)\n",
				expected_errno,
				strerror(expected_errno),
				actual_errno,
				strerror(actual_errno));
		} else {
			dprintf(STDERR_FILENO,
				"call child: expected errno=%d (%s), call "
				"succeeded\n",
				expected_errno,
				strerror(expected_errno));
		}
		_exit(EXIT_FAILURE);
	}
	return (child);
}

/* Create a kernel Door without a libdoor registry entry or server worker. */
static int
create_unserved_door(void)
{
	return ((int)__syscall((quad_t)SYS_door,
	    DOOR_SC_CREATE,
	    0,
	    0,
	    DOOR_CREATE_F_NORMAL,
	    0,
	    0));
}

/* Wait until the kernel has accepted exactly one pending invocation. */
static void
wait_for_pending_call(int door_fd)
{
	struct door_ioc_info info;
	int attempt;

	for (attempt = 0; attempt < CALL_STATE_POLL_ATTEMPTS; attempt++) {
		memset(&info, 0, sizeof(info));
		if (__syscall((quad_t)SYS_door,
		    DOOR_SC_INFO,
		    (long)door_fd,
		    (long)(uintptr_t)&info,
		    0,
		    0,
		    0) == 0 &&
		    info.di_pending_calls == 1 &&
		    info.di_active_calls == 0)
			return;
		(void)usleep(CALL_STATE_POLL_DELAY_US);
	}
	atf_tc_fail("timed out waiting for pending=1 active=0");
}

static void
require_child_success(pid_t child, const char *description)
{
	int status;

	ATF_REQUIRE_MSG(waitpid(child, &status, 0) == child,
			"waitpid failed: %s",
			strerror(errno));
	ATF_REQUIRE_MSG(WIFEXITED(status),
			"%s terminated by signal %d",
			description,
			WIFSIGNALED(status) ? WTERMSIG(status) : -1);
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == EXIT_SUCCESS,
			"%s returned an unexpected result",
			description);
}

ATF_TC_WITHOUT_HEAD(close_bound_public_descriptor);

ATF_TC_BODY(close_bound_public_descriptor, tc)
{
	int door_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	ATF_REQUIRE_MSG(
	    door_bind(door_fd) == 0, "door_bind failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(
	    close(door_fd) == 0, "close failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(door_unbind() == 0,
			"binding did not survive public descriptor close: %s",
			strerror(errno));
}

ATF_TC_WITHOUT_HEAD(duplicate_chain_last_descriptor_works);

ATF_TC_BODY(duplicate_chain_last_descriptor_works, tc)
{
	int fds[4];
	int i;

	(void)tc;
	fds[0] = test_create_door(echo_server);
	for (i = 1; i < 4; i++) {
		fds[i] = dup(fds[i - 1]);
		ATF_REQUIRE_MSG(
		    fds[i] != -1, "dup failed: %s", strerror(errno));
	}
	for (i = 0; i < 3; i++)
		ATF_REQUIRE_MSG(
		    close(fds[i]) == 0, "close failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(perform_echo_call(fds[3]) == 0,
			"last duplicate stopped working: %s",
			strerror(errno));
	ATF_REQUIRE(close(fds[3]) == 0);
}

ATF_TC_WITHOUT_HEAD(owner_exit_during_pending_call);

ATF_TC_BODY(owner_exit_during_pending_call, tc)
{
	pid_t owner, caller;
	int door_fd, sockets[2], status;

	(void)tc;
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	owner = fork();
	ATF_REQUIRE_MSG(owner != -1, "fork failed: %s", strerror(errno));
	if (owner == 0) {
		(void)close(sockets[0]);
		alarm(TEST_TIMEOUT_SECONDS);
		/*
		 * Create the endpoint through the kernel ABI without registering a
		 * libdoor entry or starting a worker.  The caller below must therefore
		 * remain on d_pending until owner-exit revocation.
		 */
		door_fd = create_unserved_door();
		if (door_fd == -1 || send_fd(sockets[1], door_fd) == -1)
			_exit(EXIT_FAILURE);
		for (;;)
			pause();
	}

	(void)close(sockets[1]);
	door_fd = receive_fd(sockets[0]);
	ATF_REQUIRE_MSG(
	    door_fd != -1, "receive_fd failed: %s", strerror(errno));

	caller = spawn_call_expect_error(door_fd, EBADF);
	/*
	 * Wait for the kernel-visible queue state rather than using a timed delay.
	 * With no server binding, the invocation cannot become active or complete;
	 * owner exit must revoke this pending call and return EBADF to its client.
	 */
	wait_for_pending_call(door_fd);
	ATF_REQUIRE_MSG(
	    kill(owner, SIGKILL) == 0, "SIGKILL failed: %s", strerror(errno));
	ATF_REQUIRE(waitpid(owner, &status, 0) == owner);
	require_child_success(caller, "pending caller");
	ATF_REQUIRE(close(door_fd) == 0);
	ATF_REQUIRE(close(sockets[0]) == 0);
}

ATF_TC_WITHOUT_HEAD(owner_exit_during_active_call);

ATF_TC_BODY(owner_exit_during_active_call, tc)
{
	pid_t owner, caller;
	int active_pipe[2], door_fd, release_pipe[2], sockets[2], status;

	(void)tc;
	ATF_REQUIRE(pipe(active_pipe) == 0);
	ATF_REQUIRE(pipe(release_pipe) == 0);
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	owner = fork();
	ATF_REQUIRE_MSG(owner != -1, "fork failed: %s", strerror(errno));
	if (owner == 0) {
		(void)close(sockets[0]);
		(void)close(active_pipe[0]);
		(void)close(release_pipe[1]);
		active_notify_fd = active_pipe[1];
		active_release_fd = release_pipe[0];
		alarm(TEST_TIMEOUT_SECONDS);
		door_fd = door_create(blocking_server, NULL, 0);
		if (door_fd == -1 || send_fd(sockets[1], door_fd) == -1)
			_exit(EXIT_FAILURE);
		for (;;)
			pause();
	}

	(void)close(sockets[1]);
	(void)close(active_pipe[1]);
	(void)close(release_pipe[0]);
	door_fd = receive_fd(sockets[0]);
	ATF_REQUIRE_MSG(
	    door_fd != -1, "receive_fd failed: %s", strerror(errno));
	caller = spawn_call_expect_error(door_fd, EBADF);
	ATF_REQUIRE_MSG(read_byte(active_pipe[0]) == 0,
			"server did not enter active call");
	ATF_REQUIRE_MSG(
	    kill(owner, SIGKILL) == 0, "SIGKILL failed: %s", strerror(errno));
	ATF_REQUIRE(waitpid(owner, &status, 0) == owner);
	require_child_success(caller, "active caller");
	ATF_REQUIRE(close(door_fd) == 0);
	ATF_REQUIRE(close(sockets[0]) == 0);
	ATF_REQUIRE(close(active_pipe[0]) == 0);
	ATF_REQUIRE(close(release_pipe[1]) == 0);
}

ATF_TC_WITHOUT_HEAD(worker_exit_aborts_active_call);

ATF_TC_BODY(worker_exit_aborts_active_call, tc)
{
	pid_t caller;
	int active_pipe[2], door_fd;

	(void)tc;
	ATF_REQUIRE(pipe(active_pipe) == 0);
	active_notify_fd = active_pipe[1];
	door_fd = test_create_door(worker_exit_server);
	caller = spawn_call_expect_error(door_fd, ECONNRESET);
	ATF_REQUIRE_MSG(read_byte(active_pipe[0]) == 0,
			"worker did not receive call");
	require_child_success(caller, "caller after worker exit");
	ATF_REQUIRE(close(active_pipe[0]) == 0);
	ATF_REQUIRE(close(active_pipe[1]) == 0);
	ATF_REQUIRE(close(door_fd) == 0);
	active_notify_fd = -1;
}

ATF_TC_WITHOUT_HEAD(revoke_during_active_call);

ATF_TC_BODY(revoke_during_active_call, tc)
{
	pid_t caller;
	int active_pipe[2], door_fd, release_pipe[2];

	(void)tc;
	ATF_REQUIRE(pipe(active_pipe) == 0);
	ATF_REQUIRE(pipe(release_pipe) == 0);
	active_notify_fd = active_pipe[1];
	active_release_fd = release_pipe[0];
	door_fd = test_create_door(blocking_server);
	caller = spawn_call_expect_error(door_fd, EBADF);
	ATF_REQUIRE_MSG(read_byte(active_pipe[0]) == 0,
			"server did not enter active call");
	ATF_REQUIRE_MSG(door_revoke(door_fd) == 0,
			"door_revoke failed: %s",
			strerror(errno));
	ATF_REQUIRE_MSG(write_byte(release_pipe[1]) == 0,
			"could not release server callback");
	require_child_success(caller, "revoked active caller");
	ATF_REQUIRE(close(active_pipe[0]) == 0);
	ATF_REQUIRE(close(active_pipe[1]) == 0);
	ATF_REQUIRE(close(release_pipe[0]) == 0);
	ATF_REQUIRE(close(release_pipe[1]) == 0);
	ATF_REQUIRE(close(door_fd) == 0);
	active_notify_fd = -1;
	active_release_fd = -1;
}

struct binding_group {
	pthread_mutex_t bg_lock;
	pthread_cond_t bg_cv;
	int bg_fd;
	int bg_ready;
	bool bg_release;
	int bg_errors;
};

static void *
binding_worker(void *argument)
{
	struct binding_group *group;

	group = argument;
	if (door_bind(group->bg_fd) == -1) {
		pthread_mutex_lock(&group->bg_lock);
		group->bg_errors++;
		group->bg_ready++;
		pthread_cond_broadcast(&group->bg_cv);
		pthread_mutex_unlock(&group->bg_lock);
		return (NULL);
	}

	pthread_mutex_lock(&group->bg_lock);
	group->bg_ready++;
	pthread_cond_broadcast(&group->bg_cv);
	while (!group->bg_release)
		pthread_cond_wait(&group->bg_cv, &group->bg_lock);
	pthread_mutex_unlock(&group->bg_lock);

	if (door_unbind() == -1) {
		pthread_mutex_lock(&group->bg_lock);
		group->bg_errors++;
		pthread_mutex_unlock(&group->bg_lock);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(multiple_worker_bindings_are_independent);

ATF_TC_BODY(multiple_worker_bindings_are_independent, tc)
{
	struct binding_group group;
	pthread_t workers[WORKER_COUNT];
	int door_fd, error, i;

	(void)tc;
	memset(&group, 0, sizeof(group));
	ATF_REQUIRE(pthread_mutex_init(&group.bg_lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&group.bg_cv, NULL) == 0);
	door_fd = test_create_door(echo_server);
	group.bg_fd = door_fd;

	for (i = 0; i < WORKER_COUNT; i++) {
		error =
		    pthread_create(&workers[i], NULL, binding_worker, &group);
		ATF_REQUIRE_MSG(
		    error == 0, "pthread_create failed: %s", strerror(error));
	}
	pthread_mutex_lock(&group.bg_lock);
	while (group.bg_ready != WORKER_COUNT)
		pthread_cond_wait(&group.bg_cv, &group.bg_lock);
	ATF_REQUIRE_MSG(
	    group.bg_errors == 0, "%d worker bindings failed", group.bg_errors);
	group.bg_release = true;
	pthread_cond_broadcast(&group.bg_cv);
	pthread_mutex_unlock(&group.bg_lock);

	for (i = 0; i < WORKER_COUNT; i++)
		ATF_REQUIRE(pthread_join(workers[i], NULL) == 0);
	ATF_REQUIRE_MSG(group.bg_errors == 0,
			"%d worker unbindings failed",
			group.bg_errors);
	ATF_REQUIRE_MSG(perform_echo_call(door_fd) == 0,
			"temporary worker bindings damaged door: %s",
			strerror(errno));
	ATF_REQUIRE(pthread_cond_destroy(&group.bg_cv) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&group.bg_lock) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(independent_doors_survive_peer_revoke);

ATF_TC_BODY(independent_doors_survive_peer_revoke, tc)
{
	int first_fd, second_fd;

	(void)tc;
	first_fd = test_create_door(echo_server);
	second_fd = test_create_door(echo_server);
	ATF_REQUIRE_MSG(door_revoke(first_fd) == 0,
			"first door_revoke failed: %s",
			strerror(errno));
	ATF_REQUIRE_MSG(perform_echo_call(second_fd) == 0,
			"revoking first door damaged second: %s",
			strerror(errno));
	ATF_REQUIRE(close(first_fd) == 0);
	test_close_door(second_fd);
}

ATF_TC_WITHOUT_HEAD(bind_to_second_door_is_rejected);

ATF_TC_BODY(bind_to_second_door_is_rejected, tc)
{
	int first_fd, second_fd;

	(void)tc;
	first_fd = test_create_door(echo_server);
	second_fd = test_create_door(echo_server);
	ATF_REQUIRE_MSG(
	    door_bind(first_fd) == 0, "first bind failed: %s", strerror(errno));
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, door_bind(second_fd));
	ATF_REQUIRE_MSG(
	    door_unbind() == 0, "door_unbind failed: %s", strerror(errno));
	test_close_door(first_fd);
	test_close_door(second_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, close_bound_public_descriptor);
	ATF_TP_ADD_TC(tp, duplicate_chain_last_descriptor_works);
	ATF_TP_ADD_TC(tp, owner_exit_during_pending_call);
	ATF_TP_ADD_TC(tp, owner_exit_during_active_call);
	ATF_TP_ADD_TC(tp, worker_exit_aborts_active_call);
	ATF_TP_ADD_TC(tp, revoke_during_active_call);
	ATF_TP_ADD_TC(tp, multiple_worker_bindings_are_independent);
	ATF_TP_ADD_TC(tp, independent_doors_survive_peer_revoke);
	ATF_TP_ADD_TC(tp, bind_to_second_door_is_rejected);
	return (atf_no_error());
}
