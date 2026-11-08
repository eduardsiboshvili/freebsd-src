/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "test_common.h"

#define TEST_DATA_MAX (64U * 1024U)
#define TEST_SMALL_REPLY 128U
#define TEST_PATTERN_SEED 0x5aU

static atomic_uint generated_reply_calls;

static uint8_t
pattern_byte(size_t offset)
{
	return ((uint8_t)((offset * 131U + TEST_PATTERN_SEED) & 0xffU));
}

static void
fill_pattern(void *buffer, size_t size)
{
	uint8_t *bytes;
	size_t i;

	bytes = buffer;
	for (i = 0; i < size; i++)
		bytes[i] = pattern_byte(i);
}

static void
require_filled(const void *buffer, size_t size, uint8_t value)
{
	const uint8_t *bytes;
	size_t i;

	bytes = buffer;
	for (i = 0; i < size; i++) {
		ATF_REQUIRE_MSG(
		    bytes[i] == value,
		    "buffer changed at offset %zu: got %#x, expected %#x",
		    i,
		    bytes[i],
		    value);
	}
}

static void
require_pattern(const void *buffer, size_t size)
{
	const uint8_t *bytes;
	size_t i;

	bytes = buffer;
	for (i = 0; i < size; i++) {
		ATF_REQUIRE_MSG(
		    bytes[i] == pattern_byte(i),
		    "payload differs at offset %zu: got %#x, expected %#x",
		    i,
		    bytes[i],
		    pattern_byte(i));
	}
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

static void
generated_reply_server(void *cookie,
		       char *data,
		       size_t data_size,
		       door_desc_t *descs,
		       uint_t ndescs)
{
	uint8_t reply[TEST_DATA_MAX];
	size_t reply_size;

	(void)cookie;
	(void)descs;
	(void)ndescs;
	(void)atomic_fetch_add_explicit(&generated_reply_calls, 1,
	    memory_order_relaxed);

	if (data == NULL || data_size != sizeof(reply_size))
		door_return(__DECONST(char *, "BAD"), sizeof("BAD"), NULL, 0);
	memcpy(&reply_size, data, sizeof(reply_size));

	if (reply_size == 0)
		door_return(NULL, 0, NULL, 0);
	if (reply_size > sizeof(reply))
		door_return(
		    __DECONST(char *, "LARGE"), sizeof("LARGE"), NULL, 0);

	fill_pattern(reply, reply_size);
	door_return((char *)reply, reply_size, NULL, 0);
}

static void
set_data_limits(int door_fd, size_t minimum, size_t maximum)
{
	size_t value;

	ATF_REQUIRE(door_setparam(door_fd, DOOR_PARAM_DATA_MIN, minimum) == 0);
	ATF_REQUIRE(door_setparam(door_fd, DOOR_PARAM_DATA_MAX, maximum) == 0);
	ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DATA_MIN, &value) == 0);
	ATF_REQUIRE(value == minimum);
	ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DATA_MAX, &value) == 0);
	ATF_REQUIRE(value == maximum);
}

static void
run_echo_call(int door_fd, size_t size)
{
	char dummy;
	uint8_t *request;
	uint8_t *reply;
	door_arg_t arg;

	request = NULL;
	reply = NULL;
	dummy = 0;
	if (size != 0) {
		request = malloc(size);
		reply = malloc(size);
		ATF_REQUIRE(request != NULL);
		ATF_REQUIRE(reply != NULL);
		fill_pattern(request, size);
		memset(reply, 0, size);
	}

	test_init_call(&arg, size == 0 ? &dummy : (char *)reply, size);
	arg.data_ptr = size == 0 ? NULL : (char *)request;
	arg.data_size = size;
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_size == size);
	if (size == 0) {
		ATF_REQUIRE(arg.data_ptr == &dummy);
	} else {
		ATF_REQUIRE(arg.data_ptr == (char *)reply);
		require_pattern(reply, size);
	}

	free(reply);
	free(request);
}

ATF_TC_WITHOUT_HEAD(zero_payload);

ATF_TC_BODY(zero_payload, tc)
{
	int door_fd;

	(void)tc;

	door_fd = test_create_door(echo_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	run_echo_call(door_fd, 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(one_byte_payload);

ATF_TC_BODY(one_byte_payload, tc)
{
	int door_fd;

	(void)tc;

	door_fd = test_create_door(echo_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	run_echo_call(door_fd, 1);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(payload_below_limit);

ATF_TC_BODY(payload_below_limit, tc)
{
	int door_fd;

	(void)tc;

	door_fd = test_create_door(echo_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	run_echo_call(door_fd, TEST_DATA_MAX - 1);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(payload_exact_limit);

ATF_TC_BODY(payload_exact_limit, tc)
{
	int door_fd;

	(void)tc;

	door_fd = test_create_door(echo_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	run_echo_call(door_fd, TEST_DATA_MAX);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(payload_over_limit);

ATF_TC_BODY(payload_over_limit, tc)
{
	static const int errors[] = {ENOBUFS};
	uint8_t *request;
	uint8_t reply[16];
	door_arg_t arg;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(echo_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	request = malloc(TEST_DATA_MAX + 1);
	ATF_REQUIRE(request != NULL);
	fill_pattern(request, TEST_DATA_MAX + 1);

	test_init_call(&arg, (char *)reply, sizeof(reply));
	arg.data_ptr = (char *)request;
	arg.data_size = TEST_DATA_MAX + 1;
	TEST_REQUIRE_ERRNO_ONE_OF(door_call(door_fd, &arg), errors);

	free(request);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(recovery_after_oversize_request);

ATF_TC_BODY(recovery_after_oversize_request, tc)
{
	static const int errors[] = {ENOBUFS};
	uint8_t *request;
	uint8_t reply[16];
	door_arg_t arg;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(echo_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	request = malloc(TEST_DATA_MAX + 1);
	ATF_REQUIRE(request != NULL);

	test_init_call(&arg, (char *)reply, sizeof(reply));
	arg.data_ptr = (char *)request;
	arg.data_size = TEST_DATA_MAX + 1;
	TEST_REQUIRE_ERRNO_ONE_OF(door_call(door_fd, &arg), errors);
	free(request);

	run_echo_call(door_fd, TEST_SMALL_REPLY);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(large_server_reply);

ATF_TC_BODY(large_server_reply, tc)
{
	uint8_t *reply;
	door_arg_t arg;
	size_t reply_size;
	int door_fd;

	(void)tc;

	reply_size = TEST_DATA_MAX;
	door_fd = test_create_door(generated_reply_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	reply = malloc(reply_size);
	ATF_REQUIRE(reply != NULL);

	test_init_call(&arg, (char *)reply, reply_size);
	arg.data_ptr = (char *)&reply_size;
	arg.data_size = sizeof(reply_size);
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_size == reply_size);
	require_pattern(reply, reply_size);

	free(reply);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(reply_buffer_too_small);

ATF_TC_BODY(reply_buffer_too_small, tc)
{
	uint8_t reply[TEST_SMALL_REPLY];
	char *mapped;
	door_arg_t arg;
	size_t map_size, reply_size;
	int door_fd;

	(void)tc;

	reply_size = TEST_DATA_MAX;
	door_fd = test_create_door(generated_reply_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	memset(reply, 0xa5, sizeof(reply));

	test_init_call(&arg, (char *)reply, sizeof(reply));
	arg.data_ptr = (char *)&reply_size;
	arg.data_size = sizeof(reply_size);
	atomic_store_explicit(&generated_reply_calls, 0, memory_order_relaxed);
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_size == reply_size);
	ATF_REQUIRE(arg.data_ptr == arg.rbuf);
	ATF_REQUIRE(arg.rbuf != (char *)reply);
	ATF_REQUIRE(arg.rsize == round_page(reply_size));
	ATF_REQUIRE(atomic_load_explicit(&generated_reply_calls,
	    memory_order_relaxed) == 1);
	require_filled(reply, sizeof(reply), 0xa5);
	require_pattern(arg.data_ptr, arg.data_size);
	mapped = arg.rbuf;
	map_size = arg.rsize;
	ATF_REQUIRE(munmap(mapped, map_size) == 0);

	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(null_reply_buffer);

ATF_TC_BODY(null_reply_buffer, tc)
{
	door_arg_t arg;
	size_t reply_size;
	int door_fd;

	(void)tc;

	reply_size = TEST_SMALL_REPLY;
	door_fd = test_create_door(generated_reply_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = (char *)&reply_size;
	arg.data_size = sizeof(reply_size);
	atomic_store_explicit(&generated_reply_calls, 0, memory_order_relaxed);

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_ptr != NULL);
	ATF_REQUIRE(arg.data_ptr == arg.rbuf);
	ATF_REQUIRE(arg.data_size == reply_size);
	ATF_REQUIRE(arg.rsize == round_page(reply_size));
	ATF_REQUIRE(atomic_load_explicit(&generated_reply_calls,
	    memory_order_relaxed) == 1);
	require_pattern(arg.data_ptr, arg.data_size);
	ATF_REQUIRE(munmap(arg.rbuf, arg.rsize) == 0);

	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(very_large_size_value);

ATF_TC_BODY(very_large_size_value, tc)
{
#if SIZE_MAX < UINT64_MAX
    /* Compat range validation precedes the Door's data-limit validation. */
    static const int errors[] = {EFAULT};
#else
	static const int errors[] = {ENOBUFS};
#endif
	char request;
	char reply;
	door_arg_t arg;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(echo_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	request = 0;
	reply = 0;

	test_init_call(&arg, &reply, sizeof(reply));
	arg.data_ptr = &request;
	arg.data_size = SIZE_MAX;
	TEST_REQUIRE_ERRNO_ONE_OF(door_call(door_fd, &arg), errors);

	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(partially_readable_request);

ATF_TC_BODY(partially_readable_request, tc)
{
	struct test_guarded_region region;
	static const int errors[] = {EFAULT};
	char reply[64];
	char *request;
	door_arg_t arg;
	int door_fd;

	(void)tc;

	ATF_REQUIRE(test_guarded_region_create(&region) == 0);
	request = (char *)region.guard - 32;
	memset(request, 0x5a, 32);

	door_fd = test_create_door(echo_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = request;
	arg.data_size = 64;
	TEST_REQUIRE_ERRNO_ONE_OF(door_call(door_fd, &arg), errors);

	test_close_door(door_fd);
	test_guarded_region_destroy(&region);
}

ATF_TC_WITHOUT_HEAD(partially_writable_reply);

ATF_TC_BODY(partially_writable_reply, tc)
{
	struct test_guarded_region region;
	static const int errors[] = {EFAULT};
	door_arg_t arg;
	char *reply;
	size_t reply_size;
	int door_fd;

	(void)tc;

	ATF_REQUIRE(test_guarded_region_create(&region) == 0);
	reply = (char *)region.guard - 32;
	memset(reply, 0, 32);
	reply_size = 64;

	door_fd = test_create_door(generated_reply_server);
	set_data_limits(door_fd, 0, TEST_DATA_MAX);
	test_init_call(&arg, reply, reply_size);
	arg.data_ptr = (char *)&reply_size;
	arg.data_size = sizeof(reply_size);
	TEST_REQUIRE_ERRNO_ONE_OF(door_call(door_fd, &arg), errors);

	test_close_door(door_fd);
	test_guarded_region_destroy(&region);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, zero_payload);
	ATF_TP_ADD_TC(tp, one_byte_payload);
	ATF_TP_ADD_TC(tp, payload_below_limit);
	ATF_TP_ADD_TC(tp, payload_exact_limit);
	ATF_TP_ADD_TC(tp, payload_over_limit);
	ATF_TP_ADD_TC(tp, recovery_after_oversize_request);
	ATF_TP_ADD_TC(tp, large_server_reply);
	ATF_TP_ADD_TC(tp, reply_buffer_too_small);
	ATF_TP_ADD_TC(tp, null_reply_buffer);
	ATF_TP_ADD_TC(tp, very_large_size_value);
	ATF_TP_ADD_TC(tp, partially_readable_request);
	ATF_TP_ADD_TC(tp, partially_writable_reply);

	return (atf_no_error());
}
