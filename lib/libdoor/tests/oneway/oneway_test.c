/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/mman.h>
#include <sys/types.h>

#include <atf-c.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <door.h>

#include "test_common.h"

static atomic_uint oneway_count;
static atomic_uint snapshot_ok;
static atomic_uint no_return_count;
static atomic_uint oneway_gate_entered;
static atomic_uint oneway_gate_release;
static atomic_uint oneway_gate_done;
static atomic_int oneway_gate_return_errno;

static uint64_t
nsec_now(void)
{
	struct timespec ts;

	ATF_REQUIRE(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
	return ((uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec);
}

static void
wait_counter(atomic_uint *counter, unsigned target)
{
	unsigned i;

	for (i = 0; i < 5000; i++) {
		if (atomic_load_explicit(counter, memory_order_acquire) >=
		    target)
			return;
		usleep(1000);
	}
	ATF_REQUIRE_MSG(false, "server did not drain %u calls", target);
}

static void
oneway_count_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	(void)cookie;
	(void)data;
	(void)size;
	(void)desc;
	(void)ndesc;

	atomic_fetch_add_explicit(&oneway_count, 1, memory_order_release);

	/*
	 * Deliberately pass a payload: libdoor must discard it for ONEWAY and
	 * submit only the empty completion token.
	 */
	(void)door_return(
	    __DECONST(char *, "ignored"), sizeof("ignored"), NULL, 0);
}

static void
oneway_snapshot_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	const unsigned char *p;
	size_t i;
	bool ok;

	(void)cookie;
	(void)desc;
	(void)ndesc;

	p = (const unsigned char *)data;
	ok = size != 0;
	for (i = 0; ok && i < size; i++) {
		if (p[i] != (unsigned char)(i * 131U + 17U))
			ok = false;
	}
	if (ok)
		atomic_store_explicit(&snapshot_ok, 1, memory_order_release);

	(void)door_return(NULL, 0, NULL, 0);
}

static void
empty_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	(void)cookie;
	(void)data;
	(void)size;
	(void)desc;
	(void)ndesc;

	atomic_fetch_add_explicit(&no_return_count, 1, memory_order_release);
	(void)door_return(NULL, 0, NULL, 0);
}

static void
reply_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	static char reply[] = "reply";

	(void)cookie;
	(void)data;
	(void)size;
	(void)desc;
	(void)ndesc;

	(void)door_return(reply, sizeof(reply), NULL, 0);
}

static void
oneway_gated_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	(void)cookie;
	(void)data;
	(void)size;
	(void)desc;
	(void)ndesc;

	atomic_store_explicit(&oneway_gate_entered, 1, memory_order_release);
	while (atomic_load_explicit(&oneway_gate_release,
				    memory_order_acquire) == 0)
		sched_yield();

	errno = 0;
	if (door_return(NULL, 0, NULL, 0) == -1)
		atomic_store_explicit(
		    &oneway_gate_return_errno, errno, memory_order_release);
	else
		atomic_store_explicit(
		    &oneway_gate_return_errno, 0, memory_order_release);
	atomic_store_explicit(&oneway_gate_done, 1, memory_order_release);
}

static void
descriptor_reply_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	door_desc_t out;
	int fd;

	(void)cookie;
	(void)data;
	(void)size;
	(void)desc;
	(void)ndesc;

	fd = test_make_regular_fd();
	ATF_REQUIRE(fd >= 0);
	test_init_desc(&out, fd, DOOR_DESCRIPTOR);
	(void)door_return(NULL, 0, &out, 1);
	close(fd);
}

ATF_TC(oneway_returns_before_completion);

ATF_TC_HEAD(oneway_returns_before_completion, tc)
{
	atf_tc_set_md_var(
	    tc,
	    "descr",
	    "ONEWAY returns after submit and server drains asynchronously");
}

ATF_TC_BODY(oneway_returns_before_completion, tc)
{
	enum { NCALLS = 128 };

	door_arg_t arg;
	door_info_t info;
	char request[64];
	uint64_t begin, elapsed;
	unsigned i;
	int fd;

	(void)tc;
	memset(request, 0x5a, sizeof(request));
	atomic_store(&oneway_count, 0);

	fd = door_create(oneway_count_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(door_info(fd, &info) == 0);
	ATF_REQUIRE((info.di_attributes & DOOR_ONEWAY) != 0);
	ATF_REQUIRE((info.di_attributes & DOOR_REFUSE_DESC) != 0);

	begin = nsec_now();
	for (i = 0; i < NCALLS; i++) {
		memset(&arg, 0, sizeof(arg));
		arg.data_ptr = request;
		arg.data_size = sizeof(request);
		ATF_REQUIRE(door_call(fd, &arg) == 0);
		ATF_REQUIRE(arg.data_ptr == NULL);
		ATF_REQUIRE_EQ(arg.data_size, 0);
		ATF_REQUIRE(arg.desc_ptr == NULL);
		ATF_REQUIRE_EQ(arg.desc_num, 0);
	}
	elapsed = nsec_now() - begin;

	/* A very loose guard against accidentally reverting to synchronous RPC.
	 */
	ATF_REQUIRE_MSG(elapsed < 1000000000ULL,
			"%u ONEWAY submits unexpectedly took %.3f ms",
			NCALLS,
			(double)elapsed / 1000000.0);

	wait_counter(&oneway_count, NCALLS);
	ATF_REQUIRE(door_revoke(fd) == 0);
	(void)close(fd);
}

ATF_TC(oneway_snapshot_survives_munmap);

ATF_TC_HEAD(oneway_snapshot_survives_munmap, tc)
{
	atf_tc_set_md_var(tc,
			  "descr",
			  "ONEWAY request is a kernel snapshot even above the "
			  "page threshold");
}

ATF_TC_BODY(oneway_snapshot_survives_munmap, tc)
{
	const size_t size = 64 * 1024;
	door_arg_t arg;
	unsigned char *mapping;
	size_t i;
	int fd;

	(void)tc;
	atomic_store(&snapshot_ok, 0);

	mapping = mmap(
	    NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	ATF_REQUIRE(mapping != MAP_FAILED);
	for (i = 0; i < size; i++)
		mapping[i] = (unsigned char)(i * 131U + 17U);

	fd = door_create(oneway_snapshot_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(fd >= 0);

	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = (char *)mapping;
	arg.data_size = size;
	ATF_REQUIRE(door_call(fd, &arg) == 0);

	/* Caller ownership of the source mapping ends immediately. */
	ATF_REQUIRE(munmap(mapping, size) == 0);

	for (i = 0; i < 5000 && atomic_load(&snapshot_ok) == 0; i++)
		usleep(1000);
	ATF_REQUIRE_EQ(atomic_load(&snapshot_ok), 1U);

	ATF_REQUIRE(door_revoke(fd) == 0);
	(void)close(fd);
}

ATF_TC(oneway_rejects_descriptors);

ATF_TC_HEAD(oneway_rejects_descriptors, tc)
{
	atf_tc_set_md_var(
	    tc, "descr", "ONEWAY is data-only and refuses descriptor transfer");
}

ATF_TC_BODY(oneway_rejects_descriptors, tc)
{
	door_arg_t arg;
	door_desc_t desc;
	int datafd, fd;

	(void)tc;
	atomic_store(&oneway_count, 0);
	fd = door_create(oneway_count_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(fd >= 0);

	datafd = test_make_regular_fd();
	ATF_REQUIRE(datafd >= 0);
	test_init_desc(&desc, datafd, DOOR_DESCRIPTOR);

	memset(&arg, 0, sizeof(arg));
	arg.desc_ptr = &desc;
	arg.desc_num = 1;
	errno = 0;
	ATF_REQUIRE(door_call(fd, &arg) == -1);
	ATF_REQUIRE(errno == ENOTSUP);

	close(datafd);
	ATF_REQUIRE(door_revoke(fd) == 0);
	(void)close(fd);
}

ATF_TC(no_return_empty_success);

ATF_TC_HEAD(no_return_empty_success, tc)
{
	atf_tc_set_md_var(
	    tc,
	    "descr",
	    "NO_RETURN preserves synchronous success for an empty reply");
}

ATF_TC_BODY(no_return_empty_success, tc)
{
	door_arg_t arg;
	char request = 'X';
	int fd;

	(void)tc;
	atomic_store(&no_return_count, 0);
	fd = door_create(empty_server, NULL, DOOR_NO_RETURN);
	ATF_REQUIRE(fd >= 0);

	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = &request;
	arg.data_size = 1;
	ATF_REQUIRE(door_call(fd, &arg) == 0);
	ATF_REQUIRE_EQ(arg.data_size, 0);
	ATF_REQUIRE_EQ(arg.desc_num, 0);
	ATF_REQUIRE_EQ(atomic_load(&no_return_count), 1U);

	ATF_REQUIRE(door_revoke(fd) == 0);
	(void)close(fd);
}

ATF_TC(no_return_nonempty_reply_unchanged);

ATF_TC_HEAD(no_return_nonempty_reply_unchanged, tc)
{
	atf_tc_set_md_var(
	    tc,
	    "descr",
	    "NO_RETURN uses the ordinary reply path for a non-empty result");
}

ATF_TC_BODY(no_return_nonempty_reply_unchanged, tc)
{
	door_arg_t arg;
	char request = 'X';
	char result[32];
	int fd;

	(void)tc;
	fd = door_create(reply_server, NULL, DOOR_NO_RETURN);
	ATF_REQUIRE(fd >= 0);

	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = &request;
	arg.data_size = 1;
	arg.rbuf = result;
	arg.rsize = sizeof(result);
	ATF_REQUIRE(door_call(fd, &arg) == 0);
	ATF_REQUIRE_EQ(arg.data_size, sizeof("reply"));
	ATF_REQUIRE(memcmp(arg.data_ptr, "reply", sizeof("reply")) == 0);

	ATF_REQUIRE(door_revoke(fd) == 0);
	(void)close(fd);
}

ATF_TC(oneway_call_returns_while_callback_blocked);

ATF_TC_HEAD(oneway_call_returns_while_callback_blocked, tc)
{
	atf_tc_set_md_var(
	    tc,
	    "descr",
	    "ONEWAY caller returns while server callback is still blocked");
}

ATF_TC_BODY(oneway_call_returns_while_callback_blocked, tc)
{
	door_arg_t arg;
	uint64_t begin, elapsed;
	unsigned i;
	int fd;

	(void)tc;
	atomic_store(&oneway_gate_entered, 0);
	atomic_store(&oneway_gate_release, 0);
	atomic_store(&oneway_gate_done, 0);
	atomic_store(&oneway_gate_return_errno, 0);

	fd = door_create(oneway_gated_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(fd >= 0);

	memset(&arg, 0, sizeof(arg));
	begin = nsec_now();
	ATF_REQUIRE(door_call(fd, &arg) == 0);
	elapsed = nsec_now() - begin;

	ATF_REQUIRE_MSG(elapsed < 100000000ULL,
			"ONEWAY call waited %.3f ms for blocked callback",
			(double)elapsed / 1000000.0);

	for (i = 0; i < 5000 && atomic_load(&oneway_gate_entered) == 0; i++)
		usleep(1000);
	ATF_REQUIRE_EQ(atomic_load(&oneway_gate_entered), 1U);
	ATF_REQUIRE_EQ(atomic_load(&oneway_gate_done), 0U);

	atomic_store_explicit(&oneway_gate_release, 1, memory_order_release);
	for (i = 0; i < 5000 && atomic_load(&oneway_gate_done) == 0; i++)
		usleep(1000);
	ATF_REQUIRE_EQ(atomic_load(&oneway_gate_done), 1U);

	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
}

ATF_TC(oneway_revoke_with_active_callback);

ATF_TC_HEAD(oneway_revoke_with_active_callback, tc)
{
	atf_tc_set_md_var(tc,
			  "descr",
			  "revoke does not wait for an active ONEWAY callback "
			  "to leave userspace");
}

ATF_TC_BODY(oneway_revoke_with_active_callback, tc)
{
	door_arg_t arg;
	unsigned i;
	int fd;

	(void)tc;
	atomic_store(&oneway_gate_entered, 0);
	atomic_store(&oneway_gate_release, 0);
	atomic_store(&oneway_gate_done, 0);
	atomic_store(&oneway_gate_return_errno, 0);

	fd = door_create(oneway_gated_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(fd >= 0);

	memset(&arg, 0, sizeof(arg));
	ATF_REQUIRE(door_call(fd, &arg) == 0);

	for (i = 0; i < 5000 && atomic_load(&oneway_gate_entered) == 0; i++)
		usleep(1000);
	ATF_REQUIRE_EQ(atomic_load(&oneway_gate_entered), 1U);

	ATF_REQUIRE(door_revoke(fd) == 0);
	atomic_store_explicit(&oneway_gate_release, 1, memory_order_release);

	for (i = 0; i < 5000 && atomic_load(&oneway_gate_done) == 0; i++)
		usleep(1000);
	ATF_REQUIRE_EQ(atomic_load(&oneway_gate_done), 1U);
	ATF_REQUIRE_EQ(atomic_load(&oneway_gate_return_errno), 0);
	close(fd);
}

ATF_TC(oneway_large_snapshot_pattern);

ATF_TC_HEAD(oneway_large_snapshot_pattern, tc)
{
	atf_tc_set_md_var(tc,
			  "descr",
			  "ONEWAY preserves a large request snapshot "
			  "independently of caller memory");
}

ATF_TC_BODY(oneway_large_snapshot_pattern, tc)
{
	const size_t size = 2 * 1024 * 1024;
	door_arg_t arg;
	unsigned char *mapping;
	size_t i;
	int fd;

	(void)tc;
	atomic_store(&snapshot_ok, 0);

	mapping = mmap(
	    NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	ATF_REQUIRE(mapping != MAP_FAILED);
	for (i = 0; i < size; i++)
		mapping[i] = (unsigned char)(i * 131U + 17U);

	fd = door_create(oneway_snapshot_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(fd >= 0);

	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = (char *)mapping;
	arg.data_size = size;
	ATF_REQUIRE(door_call(fd, &arg) == 0);
	ATF_REQUIRE(munmap(mapping, size) == 0);

	for (i = 0; i < 5000 && atomic_load(&snapshot_ok) == 0; i++)
		usleep(1000);
	ATF_REQUIRE_EQ(atomic_load(&snapshot_ok), 1U);

	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
}

ATF_TC(no_return_descriptor_reply_falls_back);

ATF_TC_HEAD(no_return_descriptor_reply_falls_back, tc)
{
	atf_tc_set_md_var(
	    tc,
	    "descr",
	    "NO_RETURN preserves ordinary descriptor reply semantics");
}

ATF_TC_BODY(no_return_descriptor_reply_falls_back, tc)
{
	door_arg_t arg;
	door_desc_t *out;
	int fd;

	(void)tc;
	fd = door_create(descriptor_reply_server, NULL, DOOR_NO_RETURN);
	ATF_REQUIRE(fd >= 0);

	/*
	 * desc_ptr/desc_num on input describe request descriptors.  Leave them
	 * empty; door_call() always provides its internal receive descriptor
	 * capacity and publishes returned descriptors through arg.desc_ptr.
	 */
	memset(&arg, 0, sizeof(arg));
	ATF_REQUIRE_MSG(
	    door_call(fd, &arg) == 0, "door_call failed: %s", strerror(errno));
	ATF_REQUIRE_EQ(arg.desc_num, 1U);
	ATF_REQUIRE(arg.desc_ptr != NULL);

	out = &arg.desc_ptr[0];
	ATF_REQUIRE((out->d_attributes & DOOR_DESCRIPTOR) != 0);
	ATF_REQUIRE(out->d_descriptor >= 0);

	close(out->d_descriptor);
	free(arg.desc_ptr);

	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
}

ATF_TC(no_return_repeated_empty_calls);

ATF_TC_HEAD(no_return_repeated_empty_calls, tc)
{
	atf_tc_set_md_var(
	    tc,
	    "descr",
	    "NO_RETURN empty fast path remains reusable across many calls");
}

ATF_TC_BODY(no_return_repeated_empty_calls, tc)
{
	enum { NCALLS = 10000 };

	door_arg_t arg;
	unsigned i;
	int fd;

	(void)tc;
	atomic_store(&no_return_count, 0);

	fd = door_create(empty_server, NULL, DOOR_NO_RETURN);
	ATF_REQUIRE(fd >= 0);

	for (i = 0; i < NCALLS; i++) {
		memset(&arg, 0, sizeof(arg));
		ATF_REQUIRE(door_call(fd, &arg) == 0);
		ATF_REQUIRE_EQ(arg.data_size, 0U);
		ATF_REQUIRE_EQ(arg.desc_num, 0U);
	}
	ATF_REQUIRE_EQ(atomic_load(&no_return_count), (unsigned)NCALLS);

	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
}

ATF_TC(no_return_attribute_visible);

ATF_TC_HEAD(no_return_attribute_visible, tc)
{
	atf_tc_set_md_var(
	    tc, "descr", "door_info reports DOOR_NO_RETURN on a created door");
}

ATF_TC_BODY(no_return_attribute_visible, tc)
{
	door_info_t info;
	int fd;

	(void)tc;
	fd = door_create(empty_server, NULL, DOOR_NO_RETURN);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(door_info(fd, &info) == 0);
	ATF_REQUIRE((info.di_attributes & DOOR_NO_RETURN) != 0);

	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, oneway_returns_before_completion);
	ATF_TP_ADD_TC(tp, oneway_snapshot_survives_munmap);
	ATF_TP_ADD_TC(tp, oneway_rejects_descriptors);
	ATF_TP_ADD_TC(tp, oneway_call_returns_while_callback_blocked);
	ATF_TP_ADD_TC(tp, oneway_revoke_with_active_callback);
	ATF_TP_ADD_TC(tp, oneway_large_snapshot_pattern);
	ATF_TP_ADD_TC(tp, no_return_empty_success);
	ATF_TP_ADD_TC(tp, no_return_nonempty_reply_unchanged);
	ATF_TP_ADD_TC(tp, no_return_descriptor_reply_falls_back);
	ATF_TP_ADD_TC(tp, no_return_repeated_empty_calls);
	ATF_TP_ADD_TC(tp, no_return_attribute_visible);
	return (atf_no_error());
}
