/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/capsicum.h>

#include <atf-c.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <door.h>
#include <sys/capsicum.h>
#include <sys/door_core.h>
#include <sys/syscall.h>

#include "test_common.h"

static void
echo_server(
    void *cookie, char *data, size_t size, door_desc_t *descs, uint_t ndescs)
{
	(void)cookie;
	(void)descs;
	(void)ndescs;
	door_return(data, size, NULL, 0);
}

static void
rights_server(
    void *cookie, char *data, size_t size, door_desc_t *descs, uint_t ndescs)
{
	cap_rights_t rights;
	bool valid;

	(void)cookie;
	(void)data;
	(void)size;
	valid = ndescs == 1 && descs != NULL &&
		cap_rights_get(descs[0].d_descriptor, &rights) == 0 &&
		cap_rights_is_set(&rights, CAP_READ) &&
		!cap_rights_is_set(&rights, CAP_WRITE);
	if (ndescs == 1 && descs != NULL)
		(void)close(descs[0].d_descriptor);
	door_return(
	    __DECONST(char *, valid ? "OK" : "BAD"), valid ? 3 : 4, NULL, 0);
}

static int
limit_to(int fd, uint64_t right)
{
	cap_rights_t rights;

	cap_rights_init(&rights, right);
	return (cap_rights_limit(fd, &rights));
}

static int
create_in_capmode_child(void *argument)
{
	int fd;

	(void)argument;
	if (cap_enter() != 0)
		return (1);
	fd = door_create(echo_server, NULL, 0);
	if (fd < 0)
		return (1);
	if (door_revoke(fd) != 0 || close(fd) != 0)
		return (1);
	return (0);
}

ATF_TC_WITHOUT_HEAD(create_in_capmode);

ATF_TC_BODY(create_in_capmode, tc)
{
	int exit_code, signal_number;

	(void)tc;
	ATF_REQUIRE(test_run_child(create_in_capmode_child,
				   NULL,
				   &exit_code,
				   &signal_number) == 0);
	ATF_REQUIRE(signal_number == 0);
	ATF_REQUIRE(exit_code == 0);
}

ATF_TC_WITHOUT_HEAD(call_right);

ATF_TC_BODY(call_right, tc)
{
	char request[] = "capsicum";
	char reply[sizeof(request)];
	door_arg_t arg;
	door_info_t info;
	int door_fd, limited_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	limited_fd = dup(door_fd);
	ATF_REQUIRE(limited_fd >= 0);
	ATF_REQUIRE(limit_to(limited_fd, CAP_DOOR_CALL) == 0);
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = request;
	arg.data_size = sizeof(request);
	ATF_REQUIRE(door_call(limited_fd, &arg) == 0);
	ATF_REQUIRE(memcmp(reply, request, sizeof(request)) == 0);
	errno = 0;
	ATF_REQUIRE(door_info(limited_fd, &info) == -1);
	ATF_REQUIRE(errno == ENOTCAPABLE);
	ATF_REQUIRE(close(limited_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(info_right);

ATF_TC_BODY(info_right, tc)
{
	char reply[1];
	door_arg_t arg;
	door_info_t info;
	int door_fd, limited_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	limited_fd = dup(door_fd);
	ATF_REQUIRE(limited_fd >= 0);
	ATF_REQUIRE(limit_to(limited_fd, CAP_DOOR_INFO) == 0);
	ATF_REQUIRE(door_info(limited_fd, &info) == 0);
	test_init_call(&arg, reply, sizeof(reply));
	errno = 0;
	ATF_REQUIRE(door_call(limited_fd, &arg) == -1);
	ATF_REQUIRE(errno == ENOTCAPABLE);
	ATF_REQUIRE(close(limited_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(empty_rights);

ATF_TC_BODY(empty_rights, tc)
{
	char reply[1];
	cap_rights_t rights;
	door_arg_t arg;
	door_info_t info;
	int door_fd, limited_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	limited_fd = dup(door_fd);
	ATF_REQUIRE(limited_fd >= 0);
	cap_rights_init(&rights);
	ATF_REQUIRE(cap_rights_limit(limited_fd, &rights) == 0);
	test_init_call(&arg, reply, sizeof(reply));
	errno = 0;
	ATF_REQUIRE(door_call(limited_fd, &arg) == -1);
	ATF_REQUIRE(errno == ENOTCAPABLE);
	errno = 0;
	ATF_REQUIRE(door_info(limited_fd, &info) == -1);
	ATF_REQUIRE(errno == ENOTCAPABLE);
	ATF_REQUIRE(close(limited_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(service_right);

ATF_TC_BODY(service_right, tc)
{
	int door_fd, limited_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	limited_fd = dup(door_fd);
	ATF_REQUIRE(limited_fd >= 0);
	ATF_REQUIRE(limit_to(limited_fd, CAP_DOOR_SERVICE) == 0);
	/*
	 * Exercise the kernel operation directly.  door_bind() also performs a
	 * userspace registry lookup by descriptor number; a descriptor returned
	 * by dup(2) deliberately has no separate registry entry.
	 */
	ATF_REQUIRE(
	    __syscall(
		(quad_t)SYS_door, DOOR_SC_BIND, (long)limited_fd, 0, 0, 0, 0) ==
	    0);
	ATF_REQUIRE(
	    __syscall((quad_t)SYS_door, DOOR_SC_UNBIND, 0, 0, 0, 0, 0) == 0);
	ATF_REQUIRE(close(limited_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(admin_right);

ATF_TC_BODY(admin_right, tc)
{
	door_info_t info;
	int door_fd, limited_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	limited_fd = dup(door_fd);
	ATF_REQUIRE(limited_fd >= 0);
	ATF_REQUIRE(limit_to(limited_fd, CAP_DOOR_ADMIN) == 0);
	ATF_REQUIRE(door_revoke(limited_fd) == 0);
	errno = 0;
	ATF_REQUIRE(door_info(limited_fd, &info) == -1);
	ATF_REQUIRE(errno == ENOTCAPABLE);
	ATF_REQUIRE(close(limited_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(shm_right);

ATF_TC_BODY(shm_right, tc)
{
	door_info_t info;
	door_shm_t shm;
	int door_fd, limited_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	limited_fd = dup(door_fd);
	ATF_REQUIRE(limited_fd >= 0);
	ATF_REQUIRE(limit_to(limited_fd, CAP_DOOR_SHM) == 0);
	ATF_REQUIRE(door_shm_create(limited_fd, 4096, DOOR_SHM_RW, &shm) == 0);
	errno = 0;
	ATF_REQUIRE(door_info(limited_fd, &info) == -1);
	ATF_REQUIRE(errno == ENOTCAPABLE);
	ATF_REQUIRE(door_shm_destroy_handle(&shm) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	ATF_REQUIRE(close(limited_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(transferred_rights);

ATF_TC_BODY(transferred_rights, tc)
{
	char reply[8];
	cap_rights_t rights;
	door_arg_t arg;
	door_desc_t desc;
	int door_fd, fd;

	(void)tc;
	fd = test_make_regular_fd();
	ATF_REQUIRE(fd >= 0);
	cap_rights_init(&rights, CAP_READ);
	ATF_REQUIRE(cap_rights_limit(fd, &rights) == 0);
	door_fd = test_create_door(rights_server);
	test_init_call(&arg, reply, sizeof(reply));
	test_init_desc(&desc, fd, 0);
	arg.desc_ptr = &desc;
	arg.desc_num = 1;
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_size == 3);
	ATF_REQUIRE(memcmp(arg.data_ptr, "OK", 3) == 0);
	ATF_REQUIRE(close(fd) == 0);
	test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, call_right);
	ATF_TP_ADD_TC(tp, create_in_capmode);
	ATF_TP_ADD_TC(tp, info_right);
	ATF_TP_ADD_TC(tp, empty_rights);
	ATF_TP_ADD_TC(tp, service_right);
	ATF_TP_ADD_TC(tp, admin_right);
	ATF_TP_ADD_TC(tp, shm_right);
	ATF_TP_ADD_TC(tp, transferred_rights);
	return (atf_no_error());
}
