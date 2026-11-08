/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define FORK_CHILDREN 16

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
perform_echo_call(int fd)
{
	static const char request[] = "fork-exec";
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

static int
helper_path(char *path, size_t path_size)
{
	char executable[PATH_MAX];
	char *slash;
	size_t size;
	int mib[4];

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = -1;
	size = sizeof(executable);
	if (sysctl(mib, nitems(mib), executable, &size, NULL, 0) == -1)
		return (-1);
	executable[sizeof(executable) - 1] = '\0';
	slash = strrchr(executable, '/');
	if (slash == NULL) {
		errno = ENOENT;
		return (-1);
	}
	*slash = '\0';
	if (snprintf(path, path_size, "%s/fork_exec_helper", executable) >=
	    (int)path_size) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	return (0);
}

static int
exec_helper(int fd, const char *mode)
{
	char fd_string[32], path[PATH_MAX];
	pid_t child;
	int status;

	if (helper_path(path, sizeof(path)) == -1)
		return (-1);
	if (snprintf(fd_string, sizeof(fd_string), "%d", fd) >=
	    (int)sizeof(fd_string)) {
		errno = EOVERFLOW;
		return (-1);
	}
	child = fork();
	if (child == -1)
		return (-1);
	if (child == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		execl(path, path, mode, fd_string, (char *)NULL);
		_exit(127);
	}
	if (waitpid(child, &status, 0) != child)
		return (-1);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

ATF_TC_WITHOUT_HEAD(inherited_descriptor_survives_exec);

ATF_TC_BODY(inherited_descriptor_survives_exec, tc)
{
	int fd;
	(void)tc;
	fd = test_create_door(echo_server);
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	ATF_REQUIRE_MSG(exec_helper(fd, "call") == 0,
			"exec helper call failed: %s",
			strerror(errno));
	ATF_REQUIRE(perform_echo_call(fd) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(inherited_info_survives_exec);

ATF_TC_BODY(inherited_info_survives_exec, tc)
{
	int fd;
	(void)tc;
	fd = test_create_door(echo_server);
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	ATF_REQUIRE_MSG(exec_helper(fd, "info") == 0,
			"door_info after exec failed: %s",
			strerror(errno));
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(cloexec_descriptor_is_closed);

ATF_TC_BODY(cloexec_descriptor_is_closed, tc)
{
	int fd;
	(void)tc;
	fd = test_create_door(echo_server);
	ATF_REQUIRE(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
	ATF_REQUIRE_MSG(exec_helper(fd, "closed") == 0,
			"FD_CLOEXEC descriptor survived exec: %s",
			strerror(errno));
	ATF_REQUIRE(perform_echo_call(fd) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(cloexec_duplicate_does_not_close_original);

ATF_TC_BODY(cloexec_duplicate_does_not_close_original, tc)
{
	int fd, dupfd;
	(void)tc;
	fd = test_create_door(echo_server);
	dupfd = dup(fd);
	ATF_REQUIRE(dupfd != -1);
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	ATF_REQUIRE(fcntl(dupfd, F_SETFD, FD_CLOEXEC) == 0);
	ATF_REQUIRE(exec_helper(dupfd, "closed") == 0);
	ATF_REQUIRE(exec_helper(fd, "call") == 0);
	ATF_REQUIRE(perform_echo_call(fd) == 0);
	ATF_REQUIRE(close(dupfd) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(exec_child_close_does_not_affect_parent);

ATF_TC_BODY(exec_child_close_does_not_affect_parent, tc)
{
	int fd;
	(void)tc;
	fd = test_create_door(echo_server);
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	ATF_REQUIRE(exec_helper(fd, "close") == 0);
	ATF_REQUIRE_MSG(perform_echo_call(fd) == 0,
			"exec child close affected parent: %s",
			strerror(errno));
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(multiple_exec_children_call);

ATF_TC_BODY(multiple_exec_children_call, tc)
{
	char fd_string[32], path[PATH_MAX];
	pid_t children[FORK_CHILDREN];
	int fd, i, status;
	(void)tc;
	fd = test_create_door(echo_server);
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	ATF_REQUIRE(helper_path(path, sizeof(path)) == 0);
	ATF_REQUIRE(snprintf(fd_string, sizeof(fd_string), "%d", fd) <
		    (int)sizeof(fd_string));
	for (i = 0; i < FORK_CHILDREN; i++) {
		children[i] = fork();
		ATF_REQUIRE(children[i] != -1);
		if (children[i] == 0) {
			alarm(TEST_TIMEOUT_SECONDS);
			execl(path, path, "call", fd_string, (char *)NULL);
			_exit(127);
		}
	}
	for (i = 0; i < FORK_CHILDREN; i++) {
		ATF_REQUIRE(waitpid(children[i], &status, 0) == children[i]);
		ATF_REQUIRE(WIFEXITED(status));
		ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
				"exec child %d failed with status %d",
				i,
				WEXITSTATUS(status));
	}
	ATF_REQUIRE(perform_echo_call(fd) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(repeated_fork_exec_cycles);

ATF_TC_BODY(repeated_fork_exec_cycles, tc)
{
	int fd, i;
	(void)tc;
	fd = test_create_door(echo_server);
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	for (i = 0; i < 32; i++)
		ATF_REQUIRE_MSG(exec_helper(fd, "call") == 0,
				"cycle %d failed: %s",
				i,
				strerror(errno));
	ATF_REQUIRE(perform_echo_call(fd) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(fork_child_can_call);

ATF_TC_BODY(fork_child_can_call, tc)
{
	pid_t child;
	int fd, status;

	(void)tc;
	fd = test_create_door(echo_server);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		_exit(perform_echo_call(fd) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == EXIT_SUCCESS,
			"fork child could not call inherited door");
	ATF_REQUIRE(perform_echo_call(fd) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(fork_child_close_does_not_affect_parent);

ATF_TC_BODY(fork_child_close_does_not_affect_parent, tc)
{
	pid_t child;
	int fd, status;

	(void)tc;
	fd = test_create_door(echo_server);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0)
		_exit(close(fd) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE(WEXITSTATUS(status) == EXIT_SUCCESS);
	ATF_REQUIRE(perform_echo_call(fd) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(parent_close_does_not_invalidate_fork_child);

ATF_TC_BODY(parent_close_does_not_invalidate_fork_child, tc)
{
	int sync_pipe[2];
	pid_t child;
	char byte;
	int fd, status;

	(void)tc;
	ATF_REQUIRE(pipe(sync_pipe) == 0);
	fd = test_create_door(echo_server);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		(void)close(sync_pipe[1]);
		alarm(TEST_TIMEOUT_SECONDS);
		if (read(sync_pipe[0], &byte, 1) != 1)
			_exit(2);
		_exit(perform_echo_call(fd) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	ATF_REQUIRE(close(sync_pipe[0]) == 0);
	ATF_REQUIRE(close(fd) == 0);
	byte = 'C';
	ATF_REQUIRE(write(sync_pipe[1], &byte, 1) == 1);
	ATF_REQUIRE(close(sync_pipe[1]) == 0);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(
	    WEXITSTATUS(status) == EXIT_SUCCESS,
	    "child lost inherited door after parent close, status=%d",
	    WEXITSTATUS(status));
}

ATF_TC_WITHOUT_HEAD(exec_duplicate_survives_original_cloexec);

ATF_TC_BODY(exec_duplicate_survives_original_cloexec, tc)
{
	int duplicate, fd;

	(void)tc;
	fd = test_create_door(echo_server);
	duplicate = dup(fd);
	ATF_REQUIRE(duplicate != -1);
	ATF_REQUIRE(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
	ATF_REQUIRE(fcntl(duplicate, F_SETFD, 0) == 0);
	ATF_REQUIRE_MSG(exec_helper(duplicate, "call") == 0,
			"non-CLOEXEC duplicate did not survive exec: %s",
			strerror(errno));
	ATF_REQUIRE(perform_echo_call(fd) == 0);
	ATF_REQUIRE(close(duplicate) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(exec_remapped_descriptor_can_call);

ATF_TC_BODY(exec_remapped_descriptor_can_call, tc)
{
	const int target_fd = 63;
	int fd;

	(void)tc;
	fd = test_create_door(echo_server);
	ATF_REQUIRE(dup2(fd, target_fd) == target_fd);
	ATF_REQUIRE(fcntl(target_fd, F_SETFD, 0) == 0);
	ATF_REQUIRE_MSG(exec_helper(target_fd, "call") == 0,
			"remapped descriptor failed after exec: %s",
			strerror(errno));
	ATF_REQUIRE(perform_echo_call(fd) == 0);
	ATF_REQUIRE(close(target_fd) == 0);
	test_close_door(fd);
}

static int
exec_helper_no_fd(const char *mode)
{
	char path[PATH_MAX];
	pid_t child;
	int status;

	if (helper_path(path, sizeof(path)) == -1)
		return (-1);
	child = fork();
	if (child == -1)
		return (-1);
	if (child == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		execl(path, path, mode, (char *)NULL);
		_exit(127);
	}
	if (waitpid(child, &status, 0) != child)
		return (-1);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

ATF_TC_WITHOUT_HEAD(exec_fresh_process_creates_door);

ATF_TC_BODY(exec_fresh_process_creates_door, tc)
{
	(void)tc;
	ATF_REQUIRE_MSG(exec_helper_no_fd("create-own") == 0,
			"exec helper could not create independent door: %s",
			strerror(errno));
}

ATF_TC_WITHOUT_HEAD(exec_after_revoke_observes_revoked);

ATF_TC_BODY(exec_after_revoke_observes_revoked, tc)
{
	int fd;
	(void)tc;
	fd = test_create_door(echo_server);
	ATF_REQUIRE(fcntl(fd, F_SETFD, 0) == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	ATF_REQUIRE_MSG(exec_helper(fd, "revoked") == 0,
			"exec helper did not observe revoked door: %s",
			strerror(errno));
	ATF_REQUIRE(close(fd) == 0);
}

static int exec_active_notify = -1;
static int exec_active_release = -1;

static void
exec_blocking_server(
    void *cookie, char *data, size_t size, door_desc_t *descs, uint_t ndescs)
{
	char byte = 'X';
	(void)cookie;
	(void)data;
	(void)size;
	(void)descs;
	(void)ndescs;
	if (write(exec_active_notify, &byte, 1) != 1)
		pthread_exit(NULL);
	if (read(exec_active_release, &byte, 1) != 1)
		pthread_exit(NULL);
	door_return(__DECONST(char *, "ok"), 3, NULL, 0);
}

static void *
exec_blocking_call(void *arg)
{
	int fd = *(int *)arg;
	char reply[8];
	door_arg_t a;
	test_init_call(&a, reply, sizeof(reply));
	(void)door_call(fd, &a);
	return NULL;
}

ATF_TC_WITHOUT_HEAD(exec_while_active_call_pending_then_completes);

ATF_TC_BODY(exec_while_active_call_pending_then_completes, tc)
{
	int n[2], r[2], fd, status;
	pthread_t thread;
	pid_t child;
	char byte;
	char path[PATH_MAX], fdstr[32];
	(void)tc;
	ATF_REQUIRE(pipe(n) == 0);
	ATF_REQUIRE(pipe(r) == 0);
	exec_active_notify = n[1];
	exec_active_release = r[0];
	fd = test_create_door(exec_blocking_server);
	ATF_REQUIRE(pthread_create(&thread, NULL, exec_blocking_call, &fd) ==
		    0);
	ATF_REQUIRE(read(n[0], &byte, 1) == 1);
	ATF_REQUIRE(helper_path(path, sizeof(path)) == 0);
	ATF_REQUIRE(snprintf(fdstr, sizeof(fdstr), "%d", fd) <
		    (int)sizeof(fdstr));
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		execl(path, path, "call-success", fdstr, (char *)NULL);
		_exit(127);
	}
	usleep(50000);
	byte = 'R';
	ATF_REQUIRE(write(r[1], &byte, 1) == 1);
	ATF_REQUIRE(pthread_join(thread, NULL) == 0);
	/* The exec child runs the same blocking callback; release it too. */
	ATF_REQUIRE(read(n[0], &byte, 1) == 1);
	byte = 'R';
	ATF_REQUIRE(write(r[1], &byte, 1) == 1);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE(WEXITSTATUS(status) == 0);
	test_close_door(fd);
	close(n[0]);
	close(n[1]);
	close(r[0]);
	close(r[1]);
}

struct exec_xstate {
	int notify[2];
	int release[2];
};

static void
exec_xblocking(
    void *cookie, char *data, size_t size, door_desc_t *descs, uint_t ndescs)
{
	struct exec_xstate *s = cookie;
	char b = 'X';
	(void)data;
	(void)size;
	(void)descs;
	(void)ndescs;
	if (write(s->notify[1], &b, 1) != 1)
		pthread_exit(NULL);
	if (read(s->release[0], &b, 1) != 1)
		pthread_exit(NULL);
	door_return(__DECONST(char *, "ok"), 3, NULL, 0);
}

static int
exec_xfactory(door_info_t *info,
	      void *(*start)(void *),
	      void *arg,
	      void *cookie)
{
	pthread_t thread;
	int error;
	(void)info;
	(void)cookie;
	error = pthread_create(&thread, NULL, start, arg);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	(void)pthread_detach(thread);
	return (1);
}

ATF_TC_WITHOUT_HEAD(exec_during_xcreate_depletion_progresses);

ATF_TC_BODY(exec_during_xcreate_depletion_progresses, tc)
{
	struct exec_xstate state;
	pthread_t first;
	int fd, status;
	char byte, path[PATH_MAX], fdstr[32];
	pid_t child;
	(void)tc;
	ATF_REQUIRE(pipe(state.notify) == 0);
	ATF_REQUIRE(pipe(state.release) == 0);
	fd = door_xcreate(
	    exec_xblocking, &state, 0, exec_xfactory, NULL, &state, 1);
	ATF_REQUIRE_MSG(fd != -1, "door_xcreate: %s", strerror(errno));
	ATF_REQUIRE(pthread_create(&first, NULL, exec_blocking_call, &fd) == 0);
	ATF_REQUIRE(read(state.notify[0], &byte, 1) == 1);
	ATF_REQUIRE(helper_path(path, sizeof(path)) == 0);
	ATF_REQUIRE(snprintf(fdstr, sizeof(fdstr), "%d", fd) <
		    (int)sizeof(fdstr));
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		execl(path, path, "call-success", fdstr, (char *)NULL);
		_exit(127);
	}
	/* The exec child must be accepted by a depletion-created worker. */
	ATF_REQUIRE(read(state.notify[0], &byte, 1) == 1);
	byte = 'R';
	ATF_REQUIRE(write(state.release[1], &byte, 1) == 1);
	ATF_REQUIRE(write(state.release[1], &byte, 1) == 1);
	ATF_REQUIRE(pthread_join(first, NULL) == 0);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	test_close_door(fd);
	close(state.notify[0]);
	close(state.notify[1]);
	close(state.release[0]);
	close(state.release[1]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fork_child_can_call);
	ATF_TP_ADD_TC(tp, fork_child_close_does_not_affect_parent);
	ATF_TP_ADD_TC(tp, parent_close_does_not_invalidate_fork_child);
	ATF_TP_ADD_TC(tp, exec_duplicate_survives_original_cloexec);
	ATF_TP_ADD_TC(tp, exec_remapped_descriptor_can_call);
	ATF_TP_ADD_TC(tp, inherited_descriptor_survives_exec);
	ATF_TP_ADD_TC(tp, inherited_info_survives_exec);
	ATF_TP_ADD_TC(tp, cloexec_descriptor_is_closed);
	ATF_TP_ADD_TC(tp, cloexec_duplicate_does_not_close_original);
	ATF_TP_ADD_TC(tp, exec_child_close_does_not_affect_parent);
	ATF_TP_ADD_TC(tp, multiple_exec_children_call);
	ATF_TP_ADD_TC(tp, repeated_fork_exec_cycles);
	ATF_TP_ADD_TC(tp, exec_fresh_process_creates_door);
	ATF_TP_ADD_TC(tp, exec_after_revoke_observes_revoked);
	ATF_TP_ADD_TC(tp, exec_while_active_call_pending_then_completes);
	ATF_TP_ADD_TC(tp, exec_during_xcreate_depletion_progresses);
	return (atf_no_error());
}
