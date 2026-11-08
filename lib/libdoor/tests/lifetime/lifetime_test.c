/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

struct call_context {
	int cc_fd;
};

static void
null_server(void *cookie,
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

	door_return(NULL, 0, NULL, 0);
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
perform_echo_call(int fd)
{
	static const char request[] = "lifetime";
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
child_echo_call(void *arg)
{
	struct call_context *context;

	context = arg;
	return (perform_echo_call(context->cc_fd));
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

ATF_TC_WITHOUT_HEAD(close_duplicate_preserves_original);

ATF_TC_BODY(close_duplicate_preserves_original, tc)
{
	int door_fd, duplicate_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	duplicate_fd = dup(door_fd);
	ATF_REQUIRE_MSG(duplicate_fd != -1, "dup failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(
	    close(duplicate_fd) == 0, "close failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(perform_echo_call(door_fd) == 0,
			"original descriptor stopped working: %s",
			strerror(errno));
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(close_original_preserves_duplicate);

ATF_TC_BODY(close_original_preserves_duplicate, tc)
{
	struct call_context context;
	int door_fd, duplicate_fd, exit_code, signal_number;

	(void)tc;
	door_fd = test_create_door(echo_server);
	duplicate_fd = dup(door_fd);
	ATF_REQUIRE_MSG(duplicate_fd != -1, "dup failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(
	    close(door_fd) == 0, "close failed: %s", strerror(errno));

	context.cc_fd = duplicate_fd;
	ATF_REQUIRE(
	    test_run_child(
		child_echo_call, &context, &exit_code, &signal_number) == 0);
	ATF_REQUIRE_MSG(signal_number == 0,
			"call through duplicate was terminated by signal %d",
			signal_number);
	ATF_REQUIRE_MSG(
	    exit_code == EXIT_SUCCESS,
	    "duplicate descriptor became unusable after original close");
	ATF_REQUIRE(close(duplicate_fd) == 0);
}

ATF_TC_WITHOUT_HEAD(fork_child_can_call_inherited_descriptor);

ATF_TC_BODY(fork_child_can_call_inherited_descriptor, tc)
{
	struct call_context context;
	int door_fd, exit_code, signal_number;

	(void)tc;
	door_fd = test_create_door(echo_server);
	context.cc_fd = door_fd;
	ATF_REQUIRE(
	    test_run_child(
		child_echo_call, &context, &exit_code, &signal_number) == 0);
	ATF_REQUIRE_MSG(
	    signal_number == 0, "child terminated by signal %d", signal_number);
	ATF_REQUIRE_MSG(exit_code == EXIT_SUCCESS,
			"child could not call inherited door descriptor");
	ATF_REQUIRE_MSG(perform_echo_call(door_fd) == 0,
			"parent door stopped working: %s",
			strerror(errno));
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(child_close_does_not_affect_parent);

ATF_TC_BODY(child_close_does_not_affect_parent, tc)
{
	pid_t child;
	int door_fd, status;

	(void)tc;
	door_fd = test_create_door(echo_server);
	child = fork();
	ATF_REQUIRE_MSG(child != -1, "fork failed: %s", strerror(errno));
	if (child == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		_exit(close(door_fd) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE(WEXITSTATUS(status) == EXIT_SUCCESS);
	ATF_REQUIRE_MSG(perform_echo_call(door_fd) == 0,
			"child close affected parent: %s",
			strerror(errno));
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(inherited_info_preserves_owner);

ATF_TC_BODY(inherited_info_preserves_owner, tc)
{
	door_info_t info;
	pid_t owner, child;
	int door_fd, status;

	(void)tc;
	owner = getpid();
	door_fd = test_create_door(null_server);
	child = fork();
	ATF_REQUIRE_MSG(child != -1, "fork failed: %s", strerror(errno));
	if (child == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		if (door_info(door_fd, &info) == -1)
			_exit(EXIT_FAILURE);
		_exit(info.di_target == owner ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == EXIT_SUCCESS,
			"child observed itself as door owner");
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(child_cannot_revoke_parent_door);

ATF_TC_BODY(child_cannot_revoke_parent_door, tc)
{
	pid_t child;
	int door_fd, status;

	(void)tc;
	door_fd = test_create_door(echo_server);
	child = fork();
	ATF_REQUIRE_MSG(child != -1, "fork failed: %s", strerror(errno));
	if (child == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		errno = 0;
		if (door_revoke(door_fd) == -1 && errno == EPERM)
			_exit(EXIT_SUCCESS);
		_exit(EXIT_FAILURE);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(
	    WEXITSTATUS(status) == EXIT_SUCCESS,
	    "child was able to revoke parent-owned door or wrong errno");
	ATF_REQUIRE_MSG(perform_echo_call(door_fd) == 0,
			"unauthorized revoke affected parent door: %s",
			strerror(errno));
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(bind_unbind_lifecycle);

ATF_TC_BODY(bind_unbind_lifecycle, tc)
{
	int door_fd;

	(void)tc;
	door_fd = test_create_door(null_server);
	ATF_REQUIRE_MSG(
	    door_bind(door_fd) == 0, "door_bind failed: %s", strerror(errno));
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, door_bind(door_fd));
	ATF_REQUIRE_MSG(
	    door_unbind() == 0, "door_unbind failed: %s", strerror(errno));
	errno = 0;
	ATF_REQUIRE_ERRNO(EINVAL, door_unbind());
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(worker_binding_not_inherited);

ATF_TC_BODY(worker_binding_not_inherited, tc)
{
	pid_t child;
	int door_fd, status;

	(void)tc;
	door_fd = test_create_door(null_server);
	ATF_REQUIRE_MSG(
	    door_bind(door_fd) == 0, "door_bind failed: %s", strerror(errno));
	child = fork();
	ATF_REQUIRE_MSG(child != -1, "fork failed: %s", strerror(errno));
	if (child == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		errno = 0;
		if (door_unbind() == -1 && errno == EINVAL)
			_exit(EXIT_SUCCESS);
		_exit(EXIT_FAILURE);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == EXIT_SUCCESS,
			"worker binding was inherited across fork");
	ATF_REQUIRE_MSG(
	    door_unbind() == 0, "parent unbind failed: %s", strerror(errno));
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(owner_exit_invalidates_remote_descriptor);

ATF_TC_BODY(owner_exit_invalidates_remote_descriptor, tc)
{
	char reply[16];
	door_arg_t arg;
	pid_t child;
	int door_fd, sockets[2], status;

	(void)tc;
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	child = fork();
	ATF_REQUIRE_MSG(child != -1, "fork failed: %s", strerror(errno));
	if (child == 0) {
		(void)close(sockets[0]);
		alarm(TEST_TIMEOUT_SECONDS);
		door_fd = door_create(null_server, NULL, 0);
		if (door_fd == -1 || send_fd(sockets[1], door_fd) == -1)
			_exit(EXIT_FAILURE);
		(void)close(sockets[1]);
		_exit(EXIT_SUCCESS);
	}

	(void)close(sockets[1]);
	door_fd = receive_fd(sockets[0]);
	ATF_REQUIRE_MSG(
	    door_fd != -1, "receive_fd failed: %s", strerror(errno));
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE(WEXITSTATUS(status) == EXIT_SUCCESS);

	test_init_call(&arg, reply, sizeof(reply));
	errno = 0;
	ATF_REQUIRE_ERRNO(EBADF, door_call(door_fd, &arg));
	ATF_REQUIRE(close(door_fd) == 0);
	ATF_REQUIRE(close(sockets[0]) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, close_duplicate_preserves_original);
	ATF_TP_ADD_TC(tp, close_original_preserves_duplicate);
	ATF_TP_ADD_TC(tp, fork_child_can_call_inherited_descriptor);
	ATF_TP_ADD_TC(tp, child_close_does_not_affect_parent);
	ATF_TP_ADD_TC(tp, inherited_info_preserves_owner);
	ATF_TP_ADD_TC(tp, child_cannot_revoke_parent_door);
	ATF_TP_ADD_TC(tp, bind_unbind_lifecycle);
	ATF_TP_ADD_TC(tp, worker_binding_not_inherited);
	ATF_TP_ADD_TC(tp, owner_exit_invalidates_remote_descriptor);
	return (atf_no_error());
}
