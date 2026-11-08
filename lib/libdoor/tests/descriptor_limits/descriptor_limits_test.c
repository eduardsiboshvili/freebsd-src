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

#define TEST_DESC_LIMIT 8

static void
close_descriptors_server(void *cookie,
			 char *data,
			 size_t data_size,
			 door_desc_t *descs,
			 uint_t ndescs)
{
	uint_t expected;
	uint_t i;

	(void)cookie;

	expected = 0;
	if (data != NULL && data_size == sizeof(expected))
		memcpy(&expected, data, sizeof(expected));

	for (i = 0; descs != NULL && i < ndescs; i++)
		(void)close(descs[i].d_descriptor);

	if (ndescs != expected)
		door_return(__DECONST(char *, "BAD"), sizeof("BAD"), NULL, 0);
	door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

static void
reply_descriptors_server(void *cookie,
			 char *data,
			 size_t data_size,
			 door_desc_t *descs,
			 uint_t ndescs)
{
	door_desc_t reply_descs[TEST_DESC_LIMIT];
	uint_t count;
	uint_t i;

	(void)cookie;
	(void)descs;
	(void)ndescs;

	if (data == NULL || data_size != sizeof(count))
		door_return(__DECONST(char *, "BAD"), sizeof("BAD"), NULL, 0);
	memcpy(&count, data, sizeof(count));

	if (count == 0)
		door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
	if (count > nitems(reply_descs))
		door_return(
		    __DECONST(char *, "COUNT"), sizeof("COUNT"), NULL, 0);

	memset(reply_descs, 0, sizeof(reply_descs));
	for (i = 0; i < count; i++) {
		reply_descs[i].d_descriptor = open("/dev/null", O_RDONLY);
		if (reply_descs[i].d_descriptor == -1) {
			while (i > 0) {
				i--;
				(void)close(reply_descs[i].d_descriptor);
			}
			door_return(
			    __DECONST(char *, "OPEN"), sizeof("OPEN"), NULL, 0);
		}
		reply_descs[i].d_attributes = DOOR_DESCRIPTOR | DOOR_RELEASE;
	}

	door_return(__DECONST(char *, "OK"), sizeof("OK"), reply_descs, count);
}

static door_desc_t *
make_descriptors(uint_t count, int **fdsp)
{
	door_desc_t *descs;
	int *fds;
	uint_t i;

	descs = calloc(count, sizeof(*descs));
	fds = calloc(count, sizeof(*fds));
	ATF_REQUIRE(descs != NULL);
	ATF_REQUIRE(fds != NULL);

	for (i = 0; i < count; i++) {
		fds[i] = test_make_regular_fd();
		ATF_REQUIRE(fds[i] != -1);
		test_init_desc(&descs[i], fds[i], DOOR_RELEASE);
	}

	*fdsp = fds;
	return (descs);
}

static void
close_source_descriptors(int *fds, uint_t count)
{
	uint_t i;

	for (i = 0; i < count; i++) {
		if (test_fd_valid(fds[i]))
			ATF_REQUIRE(close(fds[i]) == 0);
	}
	free(fds);
}

static void
require_reply_ok(const door_arg_t *arg)
{
	ATF_REQUIRE(arg->data_size == sizeof("OK"));
	ATF_REQUIRE(memcmp(arg->data_ptr, "OK", sizeof("OK")) == 0);
}

static void
set_descriptor_limit(int door_fd, size_t limit)
{
	size_t value;

	ATF_REQUIRE(door_setparam(door_fd, DOOR_PARAM_DESC_MAX, limit) == 0);
	ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DESC_MAX, &value) == 0);
	ATF_REQUIRE(value == limit);
}

ATF_TC_WITHOUT_HEAD(zero_limit_without_descriptors);

ATF_TC_BODY(zero_limit_without_descriptors, tc)
{
	char reply[8];
	door_arg_t arg;
	uint_t expected;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(close_descriptors_server);
	set_descriptor_limit(door_fd, 0);

	expected = 0;
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = (char *)&expected;
	arg.data_size = sizeof(expected);
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	require_reply_ok(&arg);

	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(zero_limit_rejects_descriptor);

ATF_TC_BODY(zero_limit_rejects_descriptor, tc)
{
	char reply[8];
	door_arg_t arg;
	door_desc_t desc;
	uint_t expected;
	int door_fd;
	int fd;

	(void)tc;

	door_fd = test_create_door(close_descriptors_server);
	set_descriptor_limit(door_fd, 0);
	fd = test_make_regular_fd();
	ATF_REQUIRE(fd != -1);
	test_init_desc(&desc, fd, DOOR_RELEASE);

	expected = 1;
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = (char *)&expected;
	arg.data_size = sizeof(expected);
	arg.desc_ptr = &desc;
	arg.desc_num = 1;
	ATF_REQUIRE_ERRNO(ENFILE, door_call(door_fd, &arg) == -1);
	test_require_fd_valid(fd);

	ATF_REQUIRE(close(fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(client_exact_limit);

ATF_TC_BODY(client_exact_limit, tc)
{
	char reply[8];
	door_arg_t arg;
	door_desc_t *descs;
	uint_t expected;
	int *fds;
	int door_fd;
	uint_t i;

	(void)tc;

	door_fd = test_create_door(close_descriptors_server);
	set_descriptor_limit(door_fd, TEST_DESC_LIMIT);
	descs = make_descriptors(TEST_DESC_LIMIT, &fds);

	expected = TEST_DESC_LIMIT;
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = (char *)&expected;
	arg.data_size = sizeof(expected);
	arg.desc_ptr = descs;
	arg.desc_num = TEST_DESC_LIMIT;
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	require_reply_ok(&arg);

	for (i = 0; i < TEST_DESC_LIMIT; i++)
		ATF_REQUIRE(!test_fd_valid(fds[i]));

	free(descs);
	free(fds);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(client_over_limit_is_atomic);

ATF_TC_BODY(client_over_limit_is_atomic, tc)
{
	char reply[8];
	door_arg_t arg;
	door_desc_t *descs;
	uint_t expected;
	uint_t count;
	int *fds;
	int door_fd;
	uint_t i;

	(void)tc;

	count = TEST_DESC_LIMIT + 1;
	door_fd = test_create_door(close_descriptors_server);
	set_descriptor_limit(door_fd, TEST_DESC_LIMIT);
	descs = make_descriptors(count, &fds);

	expected = count;
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = (char *)&expected;
	arg.data_size = sizeof(expected);
	arg.desc_ptr = descs;
	arg.desc_num = count;
	ATF_REQUIRE_ERRNO(ENFILE, door_call(door_fd, &arg) == -1);

	for (i = 0; i < count; i++)
		test_require_fd_valid(fds[i]);

	close_source_descriptors(fds, count);
	free(descs);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(recovery_after_limit_error);

ATF_TC_BODY(recovery_after_limit_error, tc)
{
	char reply[8];
	door_arg_t arg;
	door_desc_t *descs;
	uint_t expected;
	uint_t count;
	int *fds;
	int door_fd;

	(void)tc;

	count = TEST_DESC_LIMIT + 1;
	door_fd = test_create_door(close_descriptors_server);
	set_descriptor_limit(door_fd, TEST_DESC_LIMIT);
	descs = make_descriptors(count, &fds);

	expected = count;
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = (char *)&expected;
	arg.data_size = sizeof(expected);
	arg.desc_ptr = descs;
	arg.desc_num = count;
	ATF_REQUIRE_ERRNO(ENFILE, door_call(door_fd, &arg) == -1);

	expected = TEST_DESC_LIMIT;
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = (char *)&expected;
	arg.data_size = sizeof(expected);
	arg.desc_ptr = descs;
	arg.desc_num = TEST_DESC_LIMIT;
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	require_reply_ok(&arg);

	close_source_descriptors(fds, count);
	free(descs);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(server_exact_limit);

ATF_TC_BODY(server_exact_limit, tc)
{
	char reply[8];
	door_arg_t arg;
	uint_t count;
	int door_fd;
	uint_t i;

	(void)tc;

	door_fd = test_create_door(reply_descriptors_server);
	set_descriptor_limit(door_fd, TEST_DESC_LIMIT);
	count = TEST_DESC_LIMIT;

	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = (char *)&count;
	arg.data_size = sizeof(count);
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	require_reply_ok(&arg);
	ATF_REQUIRE(arg.desc_num == count);
	ATF_REQUIRE(arg.desc_ptr != NULL);

	for (i = 0; i < count; i++) {
		ATF_REQUIRE(arg.desc_ptr[i].d_attributes == DOOR_DESCRIPTOR);
		test_require_fd_valid(arg.desc_ptr[i].d_descriptor);
	}

	test_close_received_descs(&arg);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(limit_can_be_changed);

ATF_TC_BODY(limit_can_be_changed, tc)
{
	char reply[8];
	door_arg_t arg;
	door_desc_t *descs;
	uint_t expected;
	int *fds;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(close_descriptors_server);
	set_descriptor_limit(door_fd, 1);
	set_descriptor_limit(door_fd, TEST_DESC_LIMIT);
	descs = make_descriptors(TEST_DESC_LIMIT, &fds);

	expected = TEST_DESC_LIMIT;
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = (char *)&expected;
	arg.data_size = sizeof(expected);
	arg.desc_ptr = descs;
	arg.desc_num = TEST_DESC_LIMIT;
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	require_reply_ok(&arg);

	close_source_descriptors(fds, TEST_DESC_LIMIT);
	free(descs);
	test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, zero_limit_without_descriptors);
	ATF_TP_ADD_TC(tp, zero_limit_rejects_descriptor);
	ATF_TP_ADD_TC(tp, client_exact_limit);
	ATF_TP_ADD_TC(tp, client_over_limit_is_atomic);
	ATF_TP_ADD_TC(tp, recovery_after_limit_error);
	ATF_TP_ADD_TC(tp, server_exact_limit);
	ATF_TP_ADD_TC(tp, limit_can_be_changed);

	return (atf_no_error());
}
