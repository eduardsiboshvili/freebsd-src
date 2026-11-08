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

#define DCSHM_SIZE (64 * 1024)

static volatile uint32_t dcshm_seen;

static void
dcshm_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	uint32_t value;

	(void)cookie;
	(void)desc;
	(void)ndesc;

	if (data != NULL && size >= sizeof(value)) {
		memcpy(&value, data, sizeof(value));
		dcshm_seen = value;
		value += UINT32_C(0x11111111);
		memcpy(data, &value, sizeof(value));
	}
	door_return(NULL, 0, NULL, 0);
}

static void
make_name(char *buf, size_t size, const char *tag)
{
	if (access("/dev/doorctl", F_OK) == -1)
		atf_tc_skip("optional doorctl is unavailable: %s",
		    strerror(errno));
	snprintf(buf, size, "libdoor.shm.%s.%ld", tag, (long)getpid());
}

static void
setup_connected_shm(const char *name,
		    int door_fd,
		    int *client_fdp,
		    door_shm_t *shmp,
		    door_shm_t *attachedp)
{
	int client_fd;

	ATF_REQUIRE(door_named_register(door_fd, name, 0) == 0);
	client_fd = door_named_connect(name, 0, NULL);
	ATF_REQUIRE_MSG(
	    client_fd >= 0, "door_named_connect: %s", strerror(errno));

	memset(shmp, 0, sizeof(*shmp));
	ATF_REQUIRE_MSG(
	    door_shm_create(client_fd, DCSHM_SIZE, DOOR_SHM_RW, shmp) == 0,
	    "door_shm_create(client capability): %s",
	    strerror(errno));

	memset(attachedp, 0, sizeof(*attachedp));
	ATF_REQUIRE_MSG(
	    door_shm_attach(
		door_fd, shmp->dsh_region, DOOR_SHM_RW, attachedp) == 0,
	    "owner door_shm_attach: %s",
	    strerror(errno));

	*client_fdp = client_fd;
}

static void
cleanup_connected_shm(const char *name,
		      int door_fd,
		      int client_fd,
		      door_shm_t *shm,
		      door_shm_t *attached,
		      int registered)
{
	if (shm->dsh_region != 0)
		(void)door_shm_destroy(client_fd, shm->dsh_region);
	if (attached->dsh_addr != NULL && attached->dsh_addr != shm->dsh_addr)
		(void)door_shm_unmap(attached);
	if (shm->dsh_addr != NULL)
		(void)door_shm_unmap(shm);
	if (registered)
		(void)door_named_unregister(door_fd, name, 0);
	if (client_fd >= 0)
		(void)close(client_fd);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(connect_shm_call);

ATF_TC_BODY(connect_shm_call, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	char name[96];
	uint32_t *word;
	int door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "call");
	dcshm_seen = 0;
	door_fd = test_create_door(dcshm_server);
	setup_connected_shm(name, door_fd, &client_fd, &shm, &attached);

	word = shm.dsh_addr;
	*word = UINT32_C(0x12345678);
	ref = (door_shm_ref_t){shm.dsh_region, 0, sizeof(*word), 0};
	ATF_REQUIRE_MSG(door_call_shm(client_fd, &ref) == 0,
			"doorctl capability CALL_SHM: %s",
			strerror(errno));
	ATF_REQUIRE_EQ(UINT32_C(0x12345678), dcshm_seen);
	ATF_REQUIRE_EQ(UINT32_C(0x23456789), *word);

	cleanup_connected_shm(name, door_fd, client_fd, &shm, &attached, 1);
}

ATF_TC_WITHOUT_HEAD(unregister_shm_survives);

ATF_TC_BODY(unregister_shm_survives, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	char name[96];
	uint32_t *word;
	int door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "unregister");
	door_fd = test_create_door(dcshm_server);
	setup_connected_shm(name, door_fd, &client_fd, &shm, &attached);

	ATF_REQUIRE(door_named_unregister(door_fd, name, 0) == 0);
	errno = 0;
	ATF_REQUIRE(door_named_connect(name, 0, NULL) == -1);
	ATF_REQUIRE_EQ(ENOENT, errno);

	word = shm.dsh_addr;
	*word = UINT32_C(0x01020304);
	ref = (door_shm_ref_t){shm.dsh_region, 0, sizeof(*word), 0};
	ATF_REQUIRE(door_call_shm(client_fd, &ref) == 0);
	ATF_REQUIRE_EQ(UINT32_C(0x12131415), *word);

	cleanup_connected_shm(name, door_fd, client_fd, &shm, &attached, 0);
}

ATF_TC_WITHOUT_HEAD(replacement_generation_shm);

ATF_TC_BODY(replacement_generation_shm, tc)
{
	door_shm_t old_shm, old_attached, new_shm, new_attached;
	door_shm_ref_t ref;
	door_named_info_t old_info, new_info;
	char name[96];
	uint32_t *word;
	int first, second, old_client, new_client;

	(void)tc;
	make_name(name, sizeof(name), "generation");
	first = test_create_door(dcshm_server);
	ATF_REQUIRE(door_named_register(first, name, 0) == 0);
	old_client = door_named_connect(name, 0, &old_info);
	ATF_REQUIRE(old_client >= 0);
	ATF_REQUIRE(door_shm_create(
			old_client, DCSHM_SIZE, DOOR_SHM_RW, &old_shm) == 0);
	memset(&old_attached, 0, sizeof(old_attached));
	ATF_REQUIRE(
	    door_shm_attach(
		first, old_shm.dsh_region, DOOR_SHM_RW, &old_attached) == 0);

	ATF_REQUIRE(door_revoke(first) == 0);
	second = test_create_door(dcshm_server);
	ATF_REQUIRE(door_named_register(second, name, 0) == 0);
	new_client = door_named_connect(name, 0, &new_info);
	ATF_REQUIRE(new_client >= 0);
	ATF_REQUIRE(old_info.dni_uniquifier != new_info.dni_uniquifier);

	errno = 0;
	ref = (door_shm_ref_t){old_shm.dsh_region, 0, sizeof(uint32_t), 0};
	ATF_REQUIRE(door_call_shm(old_client, &ref) == -1);
	ATF_REQUIRE_EQ(EBADF, errno);

	ATF_REQUIRE(door_shm_create(
			new_client, DCSHM_SIZE, DOOR_SHM_RW, &new_shm) == 0);
	memset(&new_attached, 0, sizeof(new_attached));
	ATF_REQUIRE(
	    door_shm_attach(
		second, new_shm.dsh_region, DOOR_SHM_RW, &new_attached) == 0);
	word = new_shm.dsh_addr;
	*word = UINT32_C(0x22222222);
	ref = (door_shm_ref_t){new_shm.dsh_region, 0, sizeof(*word), 0};
	ATF_REQUIRE(door_call_shm(new_client, &ref) == 0);
	ATF_REQUIRE_EQ(UINT32_C(0x33333333), *word);

	ATF_REQUIRE(door_named_unregister(second, name, 0) == 0);
	ATF_REQUIRE(door_shm_destroy(new_client, new_shm.dsh_region) == 0);
	if (new_attached.dsh_addr != new_shm.dsh_addr)
		ATF_REQUIRE(door_shm_unmap(&new_attached) == 0);
	ATF_REQUIRE(door_shm_unmap(&new_shm) == 0);
	if (old_attached.dsh_addr != old_shm.dsh_addr)
		ATF_REQUIRE(door_shm_unmap(&old_attached) == 0);
	ATF_REQUIRE(door_shm_unmap(&old_shm) == 0);
	ATF_REQUIRE(close(new_client) == 0);
	ATF_REQUIRE(close(old_client) == 0);
	test_close_door(second);
	test_close_door(first);
}

ATF_TC_WITHOUT_HEAD(cross_generation_region_rejected);

ATF_TC_BODY(cross_generation_region_rejected, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	char first_name[96], second_name[96];
	int first, second, first_client, second_client;

	(void)tc;
	make_name(first_name, sizeof(first_name), "crossA");
	make_name(second_name, sizeof(second_name), "crossB");
	first = test_create_door(dcshm_server);
	second = test_create_door(dcshm_server);

	setup_connected_shm(first_name, first, &first_client, &shm, &attached);
	ATF_REQUIRE(door_named_register(second, second_name, 0) == 0);
	second_client = door_named_connect(second_name, 0, NULL);
	ATF_REQUIRE(second_client >= 0);

	/*
	 * Libdoor passes the strong generation identity. Kernel CALL_SHM rejects
	 * EXDEV before capture/delivery, even if numeric region ids collide.
	 */
	ATF_REQUIRE(door_shm_ref_init(&shm, 0, sizeof(uint32_t), &ref) == 0);
	errno = 0;
	ATF_REQUIRE(door_call_shm(second_client, &ref) == -1);
	ATF_REQUIRE_EQ(EXDEV, errno);

	ATF_REQUIRE(door_named_unregister(second, second_name, 0) == 0);
	ATF_REQUIRE(close(second_client) == 0);
	test_close_door(second);
	cleanup_connected_shm(
	    first_name, first, first_client, &shm, &attached, 1);
}

ATF_TC_WITHOUT_HEAD(destroy_after_unregister);

ATF_TC_BODY(destroy_after_unregister, tc)
{
	door_shm_t shm, attached;
	char name[96];
	uint32_t *word;
	int door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "destroy");
	door_fd = test_create_door(dcshm_server);
	setup_connected_shm(name, door_fd, &client_fd, &shm, &attached);

	word = shm.dsh_addr;
	*word = UINT32_C(0xfeedbeef);
	ATF_REQUIRE(door_named_unregister(door_fd, name, 0) == 0);
	ATF_REQUIRE(door_shm_destroy(client_fd, shm.dsh_region) == 0);

	/* Discovery and handle are gone; existing mapping remains valid. */
	ATF_REQUIRE_EQ(UINT32_C(0xfeedbeef), *word);
	errno = 0;
	ATF_REQUIRE(
	    door_shm_attach(
		door_fd, shm.dsh_region, DOOR_SHM_RW, &(door_shm_t){0}) == -1);
	ATF_REQUIRE_EQ(ENOENT, errno);

	shm.dsh_region = 0;
	cleanup_connected_shm(name, door_fd, client_fd, &shm, &attached, 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, connect_shm_call);
	ATF_TP_ADD_TC(tp, unregister_shm_survives);
	ATF_TP_ADD_TC(tp, replacement_generation_shm);
	ATF_TP_ADD_TC(tp, cross_generation_region_rejected);
	ATF_TP_ADD_TC(tp, destroy_after_unregister);
	return (atf_no_error());
}
