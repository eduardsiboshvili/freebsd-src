/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

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

ATF_TC_WITHOUT_HEAD(create_invalid);

ATF_TC_BODY(create_invalid, tc)
{
	int fd;

	(void)tc;

	ATF_REQUIRE_ERRNO(EINVAL, door_create(NULL, NULL, 0) == -1);
	ATF_REQUIRE_ERRNO(EINVAL,
			  door_create(null_server, NULL, UINT_MAX) == -1);
	ATF_REQUIRE_ERRNO(
	    EINVAL, door_create(null_server, NULL, DOOR_PRIVCREATE) == -1);

	fd = test_create_door(null_server);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(create_attributes);

ATF_TC_BODY(create_attributes, tc)
{
	static const uint_t attributes[] = {
	    DOOR_PRIVATE,
	    DOOR_REFUSE_DESC,
	    DOOR_NO_CANCEL,
	    DOOR_NO_DEPLETION_CB,
	    DOOR_NO_CRED,
	    DOOR_UNREF,
	    DOOR_UNREF_MULTI,
	};
	door_info_t info;
	size_t i;
	int fd;

	(void)tc;

	for (i = 0; i < nitems(attributes); i++) {
		fd = door_create(null_server, NULL, attributes[i]);
		ATF_REQUIRE_MSG(fd != -1,
				"door_create(%#x): %s",
				attributes[i],
				strerror(errno));
		ATF_REQUIRE(door_info(fd, &info) == 0);
		ATF_REQUIRE((info.di_attributes & attributes[i]) ==
			    attributes[i]);
		if ((attributes[i] & DOOR_UNREF_MULTI) != 0)
			ATF_REQUIRE((info.di_attributes & DOOR_UNREF) != 0);
		test_close_door(fd);
	}
}

ATF_TC_WITHOUT_HEAD(info_invalid);

ATF_TC_BODY(info_invalid, tc)
{
	static const int unsupported_errors[] = {
	    ENOTTY,
	    EINVAL,
	    ENOTSUP,
	};
	door_info_t info;
	int closed_fd;
	int door_fd;
	int file_fd;
	int pipe_fds[2];
	int socket_fd;

	(void)tc;

	ATF_REQUIRE_ERRNO(EBADF, door_info(-1, &info) == -1);
	ATF_REQUIRE_ERRNO(EINVAL, door_info(STDIN_FILENO, NULL) == -1);

	file_fd = test_make_regular_fd();
	ATF_REQUIRE(file_fd != -1);
	TEST_REQUIRE_ERRNO_ONE_OF(door_info(file_fd, &info),
				  unsupported_errors);

	ATF_REQUIRE(pipe(pipe_fds) == 0);
	TEST_REQUIRE_ERRNO_ONE_OF(door_info(pipe_fds[0], &info),
				  unsupported_errors);

	socket_fd = test_make_socket_fd();
	ATF_REQUIRE(socket_fd != -1);
	TEST_REQUIRE_ERRNO_ONE_OF(door_info(socket_fd, &info),
				  unsupported_errors);

	closed_fd = dup(file_fd);
	ATF_REQUIRE(closed_fd != -1);
	ATF_REQUIRE(close(closed_fd) == 0);
	ATF_REQUIRE_ERRNO(EBADF, door_info(closed_fd, &info) == -1);

	door_fd = test_create_door(null_server);
	ATF_REQUIRE(door_revoke(door_fd) == 0);
	ATF_REQUIRE(door_info(door_fd, &info) == 0);
	ATF_REQUIRE((info.di_attributes & DOOR_REVOKED) != 0);

	test_close_door(door_fd);
	ATF_REQUIRE(close(file_fd) == 0);
	ATF_REQUIRE(close(pipe_fds[0]) == 0);
	ATF_REQUIRE(close(pipe_fds[1]) == 0);
	ATF_REQUIRE(close(socket_fd) == 0);
}

ATF_TC_WITHOUT_HEAD(call_invalid);

ATF_TC_BODY(call_invalid, tc)
{
	static const int unsupported_errors[] = {
	    ENOTTY,
	    EINVAL,
	};
	char reply[8];
	door_arg_t arg;
	int closed_fd;
	int file_fd;

	(void)tc;

	test_init_call(&arg, reply, sizeof(reply));
	ATF_REQUIRE_ERRNO(EINVAL, door_call(-1, &arg) == -1);
	TEST_REQUIRE_ERRNO_ONE_OF(door_call(STDIN_FILENO, NULL),
	    unsupported_errors);

	test_init_call(&arg, reply, sizeof(reply));
	arg.data_size = 1;
	arg.data_ptr = NULL;
	ATF_REQUIRE_ERRNO(EINVAL, door_call(STDIN_FILENO, &arg) == -1);

	test_init_call(&arg, reply, sizeof(reply));
	arg.desc_num = 1;
	arg.desc_ptr = NULL;
	ATF_REQUIRE_ERRNO(EINVAL, door_call(STDIN_FILENO, &arg) == -1);

	test_init_call(&arg, NULL, 1);
	ATF_REQUIRE_ERRNO(EINVAL, door_call(STDIN_FILENO, &arg) == -1);

	file_fd = test_make_regular_fd();
	ATF_REQUIRE(file_fd != -1);
	test_init_call(&arg, reply, sizeof(reply));
	TEST_REQUIRE_ERRNO_ONE_OF(door_call(file_fd, &arg), unsupported_errors);

	closed_fd = dup(file_fd);
	ATF_REQUIRE(closed_fd != -1);
	ATF_REQUIRE(close(closed_fd) == 0);
	test_init_call(&arg, reply, sizeof(reply));
	ATF_REQUIRE_ERRNO(EBADF, door_call(closed_fd, &arg) == -1);

	ATF_REQUIRE(close(file_fd) == 0);
}

static void *
return_outside_callback(void *argument)
{
	int result;

	(void)argument;

	errno = 0;
	result = door_return(NULL, 0, NULL, 0);
	if (result != -1 || errno != EINVAL)
		return ((void *)(uintptr_t)1);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(return_invalid);

ATF_TC_BODY(return_invalid, tc)
{
	pthread_t thread;
	void *result;

	(void)tc;

	result = NULL;
	ATF_REQUIRE(
	    pthread_create(&thread, NULL, return_outside_callback, NULL) == 0);
	ATF_REQUIRE(pthread_join(thread, &result) == 0);
	ATF_REQUIRE_MSG(
	    result == NULL,
	    "door_return() outside callback did not fail with EINVAL");
}

ATF_TC_WITHOUT_HEAD(revoke_invalid);

ATF_TC_BODY(revoke_invalid, tc)
{
	static const int unsupported_errors[] = {
	    ENOTTY,
	    EINVAL,
	    ENOTSUP,
	};
	static const int repeated_errors[] = {
	    EALREADY,
	    EBADF,
	    EINVAL,
	    ECANCELED,
	};
	int closed_fd;
	int door_fd;
	int file_fd;
	int pipe_fds[2];
	int socket_fd;

	(void)tc;

	ATF_REQUIRE_ERRNO(EBADF, door_revoke(-1) == -1);

	file_fd = test_make_regular_fd();
	ATF_REQUIRE(file_fd != -1);
	TEST_REQUIRE_ERRNO_ONE_OF(door_revoke(file_fd), unsupported_errors);

	ATF_REQUIRE(pipe(pipe_fds) == 0);
	TEST_REQUIRE_ERRNO_ONE_OF(door_revoke(pipe_fds[0]), unsupported_errors);

	socket_fd = test_make_socket_fd();
	ATF_REQUIRE(socket_fd != -1);
	TEST_REQUIRE_ERRNO_ONE_OF(door_revoke(socket_fd), unsupported_errors);

	closed_fd = dup(file_fd);
	ATF_REQUIRE(closed_fd != -1);
	ATF_REQUIRE(close(closed_fd) == 0);
	ATF_REQUIRE_ERRNO(EBADF, door_revoke(closed_fd) == -1);

	door_fd = test_create_door(null_server);
	ATF_REQUIRE(door_revoke(door_fd) == 0);
	TEST_REQUIRE_ERRNO_ONE_OF(door_revoke(door_fd), repeated_errors);

	test_close_door(door_fd);
	ATF_REQUIRE(close(file_fd) == 0);
	ATF_REQUIRE(close(pipe_fds[0]) == 0);
	ATF_REQUIRE(close(pipe_fds[1]) == 0);
	ATF_REQUIRE(close(socket_fd) == 0);
}

ATF_TC_WITHOUT_HEAD(close_semantics);

ATF_TC_BODY(close_semantics, tc)
{
	char reply[16];
	char request[] = "dup";
	door_arg_t arg;
	int copy_fd;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(echo_server);
	copy_fd = dup(door_fd);
	ATF_REQUIRE(copy_fd != -1);
	ATF_REQUIRE(close(copy_fd) == 0);

	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = request;
	arg.data_size = sizeof(request);
	arg.rbuf = reply;
	arg.rsize = sizeof(reply);

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_size == sizeof(request));
	ATF_REQUIRE(memcmp(arg.data_ptr, request, sizeof(request)) == 0);

	test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, create_invalid);
	ATF_TP_ADD_TC(tp, create_attributes);
	ATF_TP_ADD_TC(tp, info_invalid);
	ATF_TP_ADD_TC(tp, call_invalid);
	ATF_TP_ADD_TC(tp, return_invalid);
	ATF_TP_ADD_TC(tp, revoke_invalid);
	ATF_TP_ADD_TC(tp, close_semantics);

	return (atf_no_error());
}
