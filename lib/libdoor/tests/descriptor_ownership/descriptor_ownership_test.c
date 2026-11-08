/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define OWNERSHIP_REPLY_SIZE 32

static const char file_contents[] = "descriptor ownership data";
static int server_source_fd = -1;

static void
close_received_server(void *cookie,
		      char *data,
		      size_t data_size,
		      door_desc_t *descs,
		      uint_t ndescs)
{
	(void)cookie;
	(void)data;
	(void)data_size;

	if (descs == NULL || ndescs != 1)
		door_return(__DECONST(char *, "BAD"), sizeof("BAD"), NULL, 0);
	(void)close(descs[0].d_descriptor);
	door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

static void
close_multiple_server(void *cookie,
		      char *data,
		      size_t data_size,
		      door_desc_t *descs,
		      uint_t ndescs)
{
	uint_t i;

	(void)cookie;
	(void)data;
	(void)data_size;

	if (descs == NULL || ndescs == 0)
		door_return(__DECONST(char *, "BAD"), sizeof("BAD"), NULL, 0);
	for (i = 0; i < ndescs; i++)
		(void)close(descs[i].d_descriptor);
	door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

static void
return_server_source_copy(void *cookie,
			  char *data,
			  size_t data_size,
			  door_desc_t *descs,
			  uint_t ndescs)
{
	door_desc_t output;

	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	test_init_desc(&output, server_source_fd, 0);
	door_return(NULL, 0, &output, 1);
}

static void
return_server_source_move(void *cookie,
			  char *data,
			  size_t data_size,
			  door_desc_t *descs,
			  uint_t ndescs)
{
	door_desc_t output;

	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	test_init_desc(&output, server_source_fd, DOOR_RELEASE);
	door_return(NULL, 0, &output, 1);
}

static void
round_trip_server(void *cookie,
		  char *data,
		  size_t data_size,
		  door_desc_t *descs,
		  uint_t ndescs)
{
	door_desc_t output;

	(void)cookie;
	(void)data;
	(void)data_size;

	if (descs == NULL || ndescs != 1)
		door_return(__DECONST(char *, "BAD"), sizeof("BAD"), NULL, 0);
	test_init_desc(&output, descs[0].d_descriptor, DOOR_RELEASE);
	door_return(NULL, 0, &output, 1);
}

static int
create_data_file(void)
{
	char path[] = "/tmp/libdoor-ownership.XXXXXX";
	int fd;

	fd = mkstemp(path);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(write(fd, file_contents, sizeof(file_contents)) ==
		    (ssize_t)sizeof(file_contents));
	ATF_REQUIRE(lseek(fd, 0, SEEK_SET) == 0);
	return (fd);
}

static void
require_file_contents(int fd)
{
	char buffer[sizeof(file_contents)];

	ATF_REQUIRE(pread(fd, buffer, sizeof(buffer), 0) ==
		    (ssize_t)sizeof(buffer));
	ATF_REQUIRE(memcmp(buffer, file_contents, sizeof(buffer)) == 0);
}

static void
init_descriptor_call(door_arg_t *arg,
		     door_desc_t *descs,
		     uint_t ndescs,
		     char *reply,
		     size_t reply_size)
{
	test_init_call(arg, reply, reply_size);
	arg->desc_ptr = descs;
	arg->desc_num = ndescs;
}

ATF_TC_WITHOUT_HEAD(client_copy_retains_source);

ATF_TC_BODY(client_copy_retains_source, tc)
{
	char reply[OWNERSHIP_REPLY_SIZE];
	door_arg_t arg;
	door_desc_t desc;
	int door_fd;
	int source_fd;

	(void)tc;
	door_fd = test_create_door(close_received_server);
	source_fd = create_data_file();
	test_init_desc(&desc, source_fd, 0);
	init_descriptor_call(&arg, &desc, 1, reply, sizeof(reply));

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_size == sizeof("OK"));
	ATF_REQUIRE(memcmp(arg.data_ptr, "OK", sizeof("OK")) == 0);
	test_require_fd_valid(source_fd);
	require_file_contents(source_fd);

	ATF_REQUIRE(close(source_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(client_move_consumes_source);

ATF_TC_BODY(client_move_consumes_source, tc)
{
	char reply[OWNERSHIP_REPLY_SIZE];
	door_arg_t arg;
	door_desc_t desc;
	int door_fd;
	int source_fd;

	(void)tc;
	door_fd = test_create_door(close_received_server);
	source_fd = create_data_file();
	test_init_desc(&desc, source_fd, DOOR_RELEASE);
	init_descriptor_call(&arg, &desc, 1, reply, sizeof(reply));

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	errno = 0;
	ATF_REQUIRE(fcntl(source_fd, F_GETFD) == -1);
	ATF_REQUIRE(errno == EBADF);

	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(client_move_preserves_duplicate);

ATF_TC_BODY(client_move_preserves_duplicate, tc)
{
	char reply[OWNERSHIP_REPLY_SIZE];
	door_arg_t arg;
	door_desc_t desc;
	int duplicate_fd;
	int door_fd;
	int source_fd;

	(void)tc;
	door_fd = test_create_door(close_received_server);
	source_fd = create_data_file();
	duplicate_fd = dup(source_fd);
	ATF_REQUIRE(duplicate_fd != -1);
	test_init_desc(&desc, source_fd, DOOR_RELEASE);
	init_descriptor_call(&arg, &desc, 1, reply, sizeof(reply));

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	errno = 0;
	ATF_REQUIRE(fcntl(source_fd, F_GETFD) == -1);
	ATF_REQUIRE(errno == EBADF);
	test_require_fd_valid(duplicate_fd);
	require_file_contents(duplicate_fd);

	ATF_REQUIRE(close(duplicate_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(server_copy_retains_source);

ATF_TC_BODY(server_copy_retains_source, tc)
{
	char reply[OWNERSHIP_REPLY_SIZE];
	door_arg_t arg;
	int door_fd;
	int received_fd;

	(void)tc;
	server_source_fd = create_data_file();
	door_fd = test_create_door(return_server_source_copy);
	test_init_call(&arg, reply, sizeof(reply));

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.desc_num == 1);
	received_fd = arg.desc_ptr[0].d_descriptor;
	require_file_contents(received_fd);
	ATF_REQUIRE(close(received_fd) == 0);
	test_require_fd_valid(server_source_fd);
	require_file_contents(server_source_fd);

	ATF_REQUIRE(close(server_source_fd) == 0);
	server_source_fd = -1;
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(server_move_consumes_source);

ATF_TC_BODY(server_move_consumes_source, tc)
{
	char reply[OWNERSHIP_REPLY_SIZE];
	door_arg_t arg;
	int door_fd;
	int original_fd;
	int received_fd;

	(void)tc;
	server_source_fd = create_data_file();
	original_fd = server_source_fd;
	door_fd = test_create_door(return_server_source_move);
	test_init_call(&arg, reply, sizeof(reply));

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.desc_num == 1);
	received_fd = arg.desc_ptr[0].d_descriptor;
	require_file_contents(received_fd);
	ATF_REQUIRE(close(received_fd) == 0);
	errno = 0;
	ATF_REQUIRE(fcntl(original_fd, F_GETFD) == -1);
	ATF_REQUIRE(errno == EBADF);

	server_source_fd = -1;
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(repeated_copy_creates_independent_receivers);

ATF_TC_BODY(repeated_copy_creates_independent_receivers, tc)
{
	char reply[OWNERSHIP_REPLY_SIZE];
	door_arg_t arg;
	door_desc_t descs[3];
	int door_fd;
	int source_fd;
	uint_t i;

	(void)tc;
	door_fd = test_create_door(close_multiple_server);
	source_fd = create_data_file();
	for (i = 0; i < nitems(descs); i++)
		test_init_desc(&descs[i], source_fd, 0);
	init_descriptor_call(&arg, descs, nitems(descs), reply, sizeof(reply));

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	test_require_fd_valid(source_fd);
	require_file_contents(source_fd);

	ATF_REQUIRE(close(source_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(mixed_copy_move_same_source);

ATF_TC_BODY(mixed_copy_move_same_source, tc)
{
	char reply[OWNERSHIP_REPLY_SIZE];
	door_arg_t arg;
	door_desc_t descs[2];
	int door_fd;
	int source_fd;

	(void)tc;
	door_fd = test_create_door(close_multiple_server);
	source_fd = create_data_file();
	test_init_desc(&descs[0], source_fd, 0);
	test_init_desc(&descs[1], source_fd, DOOR_RELEASE);
	init_descriptor_call(&arg, descs, nitems(descs), reply, sizeof(reply));

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	errno = 0;
	ATF_REQUIRE(fcntl(source_fd, F_GETFD) == -1);
	ATF_REQUIRE(errno == EBADF);

	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(round_trip_move_transfers_ownership);

ATF_TC_BODY(round_trip_move_transfers_ownership, tc)
{
	char reply[OWNERSHIP_REPLY_SIZE];
	door_arg_t arg;
	door_desc_t desc;
	int door_fd;
	int original_fd;
	int received_fd;

	(void)tc;
	door_fd = test_create_door(round_trip_server);
	original_fd = create_data_file();
	test_init_desc(&desc, original_fd, DOOR_RELEASE);
	init_descriptor_call(&arg, &desc, 1, reply, sizeof(reply));

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.desc_num == 1);
	ATF_REQUIRE(arg.desc_ptr[0].d_attributes == DOOR_DESCRIPTOR);
	received_fd = arg.desc_ptr[0].d_descriptor;
	require_file_contents(received_fd);
	ATF_REQUIRE(close(received_fd) == 0);
	errno = 0;
	ATF_REQUIRE(fcntl(original_fd, F_GETFD) == -1);
	ATF_REQUIRE(errno == EBADF);

	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(failed_array_preserves_moved_source);

ATF_TC_BODY(failed_array_preserves_moved_source, tc)
{
	char reply[OWNERSHIP_REPLY_SIZE];
	door_arg_t arg;
	door_desc_t descs[2];
	int dead_fd;
	int door_fd;
	int source_fd;

	(void)tc;
	door_fd = test_create_door(close_multiple_server);
	source_fd = create_data_file();
	dead_fd = dup(source_fd);
	ATF_REQUIRE(dead_fd != -1);
	ATF_REQUIRE(close(dead_fd) == 0);
	test_init_desc(&descs[0], source_fd, DOOR_RELEASE);
	test_init_desc(&descs[1], dead_fd, 0);
	init_descriptor_call(&arg, descs, nitems(descs), reply, sizeof(reply));

	errno = 0;
	ATF_REQUIRE(door_call(door_fd, &arg) == -1);
	ATF_REQUIRE(errno == EBADF);
	test_require_fd_valid(source_fd);
	require_file_contents(source_fd);

	ATF_REQUIRE(close(source_fd) == 0);
	test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, client_copy_retains_source);
	ATF_TP_ADD_TC(tp, client_move_consumes_source);
	ATF_TP_ADD_TC(tp, client_move_preserves_duplicate);
	ATF_TP_ADD_TC(tp, server_copy_retains_source);
	ATF_TP_ADD_TC(tp, server_move_consumes_source);
	ATF_TP_ADD_TC(tp, repeated_copy_creates_independent_receivers);
	ATF_TP_ADD_TC(tp, mixed_copy_move_same_source);
	ATF_TP_ADD_TC(tp, round_trip_move_transfers_ownership);
	ATF_TP_ADD_TC(tp, failed_array_preserves_moved_source);

	return (atf_no_error());
}
