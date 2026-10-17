/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>

#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <door.h>

#include "test_common.h"

static atomic_uint ow_entered;
static atomic_uint ow_release;
static atomic_uint ow_done;
static volatile uint32_t ow_seen;
static atomic_uint ow_count;

static void
make_name(char *buf, size_t size, const char *tag)
{
	if (access("/dev/doorctl", F_OK) == -1)
		atf_tc_skip("optional doorctl is unavailable: %s",
		    strerror(errno));
	snprintf(buf, size, "libdoor.oneway.%s.%ld", tag, (long)getpid());
}

static void
wait_atomic(atomic_uint *value, unsigned expected)
{
	unsigned i;

	for (i = 0; i < 5000; i++) {
		if (atomic_load(value) == expected)
			return;
		usleep(1000);
	}
	ATF_REQUIRE_MSG(atomic_load(value) == expected,
			"timed out waiting for ONEWAY state %u",
			expected);
}

static void
reset_gate(void)
{
	atomic_store(&ow_entered, 0);
	atomic_store(&ow_release, 0);
	atomic_store(&ow_done, 0);
	ow_seen = 0;
}

static void
gated_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	uint32_t value;

	(void)cookie;
	(void)desc;
	(void)ndesc;

	value = 0;
	if (data != NULL && size >= sizeof(value)) {
		memcpy(&value, data, sizeof(value));
		ow_seen = value;
	}

	atomic_store(&ow_entered, 1);
	while (atomic_load(&ow_release) == 0)
		usleep(1000);
	atomic_store(&ow_done, 1);
	(void)door_return(NULL, 0, NULL, 0);
}

static void
count_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	(void)cookie;
	(void)data;
	(void)size;
	(void)desc;
	(void)ndesc;

	atomic_fetch_add(&ow_count, 1);
	(void)door_return(NULL, 0, NULL, 0);
}

static int
create_named_oneway(const char *name,
		    door_server_procedure_t *proc,
		    door_named_info_t *info)
{
	int door_fd, client_fd;

	door_fd = door_create(proc, NULL, DOOR_ONEWAY);
	ATF_REQUIRE_MSG(
	    door_fd >= 0, "door_create(DOOR_ONEWAY): %s", strerror(errno));
	ATF_REQUIRE_MSG(door_named_register(door_fd, name, 0) == 0,
			"door_named_register: %s",
			strerror(errno));

	client_fd = door_named_connect(name, 0, info);
	ATF_REQUIRE_MSG(
	    client_fd >= 0, "door_named_connect: %s", strerror(errno));
	return (door_fd << 16) | (client_fd & 0xffff);
}

static void
unpack_pair(int pair, int *door_fd, int *client_fd)
{
	*door_fd = (pair >> 16) & 0xffff;
	*client_fd = pair & 0xffff;
}

static void
submit_word(int fd, uint32_t value)
{
	door_arg_t arg;

	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = (char *)(void *)&value;
	arg.data_size = sizeof(value);

	ATF_REQUIRE_MSG(door_call(fd, &arg) == 0,
			"ONEWAY door_call via doorctl capability: %s",
			strerror(errno));
	ATF_REQUIRE(arg.data_ptr == NULL);
	ATF_REQUIRE_EQ((size_t)0, arg.data_size);
	ATF_REQUIRE(arg.desc_ptr == NULL);
	ATF_REQUIRE_EQ(0U, arg.desc_num);
}

ATF_TC_WITHOUT_HEAD(connect_oneway_submit);

ATF_TC_BODY(connect_oneway_submit, tc)
{
	char name[96];
	int pair, door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "submit");
	reset_gate();

	pair = create_named_oneway(name, gated_server, NULL);
	unpack_pair(pair, &door_fd, &client_fd);

	submit_word(client_fd, UINT32_C(0x11223344));
	wait_atomic(&ow_entered, 1);
	ATF_REQUIRE_EQ(0U, atomic_load(&ow_done));
	ATF_REQUIRE_EQ(UINT32_C(0x11223344), ow_seen);

	atomic_store(&ow_release, 1);
	wait_atomic(&ow_done, 1);

	ATF_REQUIRE(door_named_unregister(door_fd, name, 0) == 0);
	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(unregister_capability_survives);

ATF_TC_BODY(unregister_capability_survives, tc)
{
	char name[96];
	int pair, door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "unregister");
	reset_gate();

	pair = create_named_oneway(name, gated_server, NULL);
	unpack_pair(pair, &door_fd, &client_fd);

	ATF_REQUIRE(door_named_unregister(door_fd, name, 0) == 0);
	errno = 0;
	ATF_REQUIRE(door_named_connect(name, 0, NULL) == -1);
	ATF_REQUIRE_EQ(ENOENT, errno);

	submit_word(client_fd, UINT32_C(0xaabbccdd));
	wait_atomic(&ow_entered, 1);
	ATF_REQUIRE_EQ(UINT32_C(0xaabbccdd), ow_seen);
	atomic_store(&ow_release, 1);
	wait_atomic(&ow_done, 1);

	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(revoke_active_capability);

ATF_TC_BODY(revoke_active_capability, tc)
{
	door_arg_t arg;
	char name[96];
	int pair, door_fd, client_fd;
	uint32_t value;

	(void)tc;
	make_name(name, sizeof(name), "revoke");
	reset_gate();

	pair = create_named_oneway(name, gated_server, NULL);
	unpack_pair(pair, &door_fd, &client_fd);

	submit_word(client_fd, UINT32_C(0x55667788));
	wait_atomic(&ow_entered, 1);

	ATF_REQUIRE(door_revoke(door_fd) == 0);

	value = UINT32_C(0x01020304);
	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = (char *)(void *)&value;
	arg.data_size = sizeof(value);
	errno = 0;
	ATF_REQUIRE(door_call(client_fd, &arg) == -1);
	ATF_REQUIRE_EQ(EBADF, errno);

	atomic_store(&ow_release, 1);
	wait_atomic(&ow_done, 1);

	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(replacement_generation);

ATF_TC_BODY(replacement_generation, tc)
{
	door_named_info_t old_info, new_info;
	door_arg_t arg;
	char name[96];
	uint32_t value;
	int old_pair;
	int first, second, old_client, new_client;

	(void)tc;
	make_name(name, sizeof(name), "generation");
	atomic_store(&ow_count, 0);

	old_pair = create_named_oneway(name, count_server, &old_info);
	unpack_pair(old_pair, &first, &old_client);

	submit_word(old_client, UINT32_C(1));
	ATF_REQUIRE(door_revoke(first) == 0);

	second = door_create(count_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(second >= 0);
	ATF_REQUIRE_MSG(door_named_register(second, name, 0) == 0,
			"replacement register: %s",
			strerror(errno));
	new_client = door_named_connect(name, 0, &new_info);
	ATF_REQUIRE(new_client >= 0);
	ATF_REQUIRE(old_info.dni_uniquifier != new_info.dni_uniquifier);

	value = UINT32_C(2);
	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = (char *)(void *)&value;
	arg.data_size = sizeof(value);
	errno = 0;
	ATF_REQUIRE(door_call(old_client, &arg) == -1);
	ATF_REQUIRE_EQ(EBADF, errno);

	submit_word(new_client, UINT32_C(3));

	ATF_REQUIRE(door_named_unregister(second, name, 0) == 0);
	ATF_REQUIRE(close(new_client) == 0);
	ATF_REQUIRE(close(old_client) == 0);
	test_close_door(second);
	test_close_door(first);
}

ATF_TC_WITHOUT_HEAD(burst_submit_revoke);

ATF_TC_BODY(burst_submit_revoke, tc)
{
	char name[96];
	unsigned i;
	int pair, door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "burst");
	atomic_store(&ow_count, 0);

	pair = create_named_oneway(name, count_server, NULL);
	unpack_pair(pair, &door_fd, &client_fd);

	for (i = 0; i < 256; i++)
		submit_word(client_fd, (uint32_t)i);

	ATF_REQUIRE(door_revoke(door_fd) == 0);
	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, connect_oneway_submit);
	ATF_TP_ADD_TC(tp, unregister_capability_survives);
	ATF_TP_ADD_TC(tp, revoke_active_capability);
	ATF_TP_ADD_TC(tp, replacement_generation);
	ATF_TP_ADD_TC(tp, burst_submit_revoke);
	return (atf_no_error());
}
