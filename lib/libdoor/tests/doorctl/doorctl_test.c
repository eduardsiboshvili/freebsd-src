/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <door.h>

#include "test_common.h"

static void
named_echo_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	(void)cookie;
	(void)desc;
	(void)ndesc;

	door_return(data, size, NULL, 0);
}

static void
make_name(char *buf, size_t size, const char *tag)
{
	if (access("/dev/doorctl", F_OK) == -1)
		atf_tc_skip("optional doorctl is unavailable: %s",
		    strerror(errno));
	snprintf(buf, size, "libdoor.test.%s.%ld", tag, (long)getpid());
}

static void
call_ping(int fd)
{
	char request[] = "named-door";
	char reply[64];
	door_arg_t arg;

	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = request;
	arg.data_size = sizeof(request);
	arg.rbuf = reply;
	arg.rsize = sizeof(reply);

	ATF_REQUIRE_MSG(
	    door_call(fd, &arg) == 0, "door_call failed: %s", strerror(errno));
	ATF_REQUIRE_EQ(sizeof(request), arg.data_size);
	ATF_REQUIRE(memcmp(arg.data_ptr, request, sizeof(request)) == 0);
}

ATF_TC_WITHOUT_HEAD(register_lookup_connect);

ATF_TC_BODY(register_lookup_connect, tc)
{
	door_named_info_t lookup, connected;
	door_info_t dinfo;
	char name[96];
	int door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "basic");
	door_fd = test_create_door(named_echo_server);

	ATF_REQUIRE_MSG(door_named_register(door_fd, name, 0) == 0,
			"register failed: %s",
			strerror(errno));

	memset(&lookup, 0, sizeof(lookup));
	ATF_REQUIRE_MSG(door_named_lookup(name, 0, &lookup) == 0,
			"lookup failed: %s",
			strerror(errno));

	memset(&connected, 0, sizeof(connected));
	client_fd = door_named_connect(name, 0, &connected);
	ATF_REQUIRE_MSG(client_fd >= 0, "connect failed: %s", strerror(errno));
	ATF_REQUIRE_EQ(lookup.dni_uniquifier, connected.dni_uniquifier);
	ATF_REQUIRE_EQ(lookup.dni_target_jid, connected.dni_target_jid);

	ATF_REQUIRE_MSG(door_info(door_fd, &dinfo) == 0,
			"door_info failed: %s",
			strerror(errno));
	ATF_REQUIRE_EQ(dinfo.di_uniquifier, connected.dni_uniquifier);
	call_ping(client_fd);

	ATF_REQUIRE(door_named_unregister(door_fd, name, 0) == 0);
	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(duplicate_live_registration);

ATF_TC_BODY(duplicate_live_registration, tc)
{
	char name[96];
	int first, second;

	(void)tc;
	make_name(name, sizeof(name), "duplicate");
	first = test_create_door(named_echo_server);
	second = test_create_door(named_echo_server);

	ATF_REQUIRE(door_named_register(first, name, 0) == 0);
	errno = 0;
	ATF_REQUIRE(door_named_register(second, name, 0) == -1);
	ATF_REQUIRE_EQ(EEXIST, errno);

	ATF_REQUIRE(door_named_unregister(first, name, 0) == 0);
	test_close_door(second);
	test_close_door(first);
}

ATF_TC_WITHOUT_HEAD(unregister_hides_name_but_capability_survives);

ATF_TC_BODY(unregister_hides_name_but_capability_survives, tc)
{
	char name[96];
	int door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "unregister");
	door_fd = test_create_door(named_echo_server);
	ATF_REQUIRE(door_named_register(door_fd, name, 0) == 0);

	client_fd = door_named_connect(name, 0, NULL);
	ATF_REQUIRE_MSG(client_fd >= 0, "connect failed: %s", strerror(errno));

	ATF_REQUIRE(door_named_unregister(door_fd, name, 0) == 0);
	errno = 0;
	ATF_REQUIRE(door_named_lookup(name, 0, NULL) == -1);
	ATF_REQUIRE_EQ(ENOENT, errno);

	/* CONNECT is discovery; the already issued fd remains the capability.
	 */
	call_ping(client_fd);

	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(revoked_generation_replaced);

ATF_TC_BODY(revoked_generation_replaced, tc)
{
	door_named_info_t first_info, second_info;
	char name[96];
	int first, second, old_client, new_client;

	(void)tc;
	make_name(name, sizeof(name), "generation");
	first = test_create_door(named_echo_server);
	ATF_REQUIRE(door_named_register(first, name, 0) == 0);

	old_client = door_named_connect(name, 0, &first_info);
	ATF_REQUIRE(old_client >= 0);
	call_ping(old_client);

	ATF_REQUIRE(door_revoke(first) == 0);

	second = test_create_door(named_echo_server);
	ATF_REQUIRE_MSG(door_named_register(second, name, 0) == 0,
			"replacement register failed: %s",
			strerror(errno));

	new_client = door_named_connect(name, 0, &second_info);
	ATF_REQUIRE(new_client >= 0);
	ATF_REQUIRE(first_info.dni_uniquifier != second_info.dni_uniquifier);
	call_ping(new_client);

	errno = 0;
	{
		char reply[8];
		door_arg_t arg;
		test_init_call(&arg, reply, sizeof(reply));
		ATF_REQUIRE(door_call(old_client, &arg) == -1);
		ATF_REQUIRE_EQ(EBADF, errno);
	}

	ATF_REQUIRE(door_named_unregister(second, name, 0) == 0);
	ATF_REQUIRE(close(new_client) == 0);
	ATF_REQUIRE(close(old_client) == 0);
	test_close_door(second);
	test_close_door(first);
}

ATF_TC_WITHOUT_HEAD(validation);

ATF_TC_BODY(validation, tc)
{
	char name[96];
	int door_fd;

	(void)tc;
	make_name(name, sizeof(name), "flags");
	door_fd = test_create_door(named_echo_server);

	errno = 0;
	ATF_REQUIRE(door_named_register(door_fd, "", 0) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);

	errno = 0;
	ATF_REQUIRE(door_named_register(door_fd, "bad/name", 0) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);

	errno = 0;
	ATF_REQUIRE(door_named_lookup("definitely.not.registered", 0, NULL) ==
		    -1);
	ATF_REQUIRE_EQ(ENOENT, errno);

	errno = 0;
	ATF_REQUIRE(door_named_register(door_fd, name, 0x80000000U) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);

	/* Scope choice is automatic for discovery; GLOBAL is publication-only. */
	errno = 0;
	ATF_REQUIRE(door_named_lookup(name, DOOR_NAMED_GLOBAL, NULL) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);
	errno = 0;
	ATF_REQUIRE(door_named_connect(name, DOOR_NAMED_GLOBAL, NULL) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);

	test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, register_lookup_connect);
	ATF_TP_ADD_TC(tp, duplicate_live_registration);
	ATF_TP_ADD_TC(tp, unregister_hides_name_but_capability_survives);
	ATF_TP_ADD_TC(tp, revoked_generation_replaced);
	ATF_TP_ADD_TC(tp, validation);
	return (atf_no_error());
}
