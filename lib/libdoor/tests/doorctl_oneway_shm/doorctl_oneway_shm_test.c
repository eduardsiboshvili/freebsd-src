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

#define OWSHM_SIZE (64 * 1024)

static atomic_uint os_entered;
static atomic_uint os_release;
static atomic_uint os_done;
static atomic_uint os_count;
static volatile uint32_t os_seen;

static void
make_name(char *buf, size_t size, const char *tag)
{
	if (access("/dev/doorctl", F_OK) == -1)
		atf_tc_skip("optional doorctl is unavailable: %s",
		    strerror(errno));
	snprintf(buf, size, "libdoor.oneway.shm.%s.%ld", tag, (long)getpid());
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
			"timed out waiting for ONEWAY+SHM state %u",
			expected);
}

static void
reset_gate(void)
{
	atomic_store(&os_entered, 0);
	atomic_store(&os_release, 0);
	atomic_store(&os_done, 0);
	os_seen = 0;
}

static void
gated_shm_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	uint32_t value;

	(void)cookie;
	(void)desc;
	(void)ndesc;

	value = 0;
	if (data != NULL && size >= sizeof(value)) {
		memcpy(&value, data, sizeof(value));
		os_seen = value;
		value ^= UINT32_C(0xffffffff);
		memcpy(data, &value, sizeof(value));
	}

	atomic_store(&os_entered, 1);
	while (atomic_load(&os_release) == 0)
		usleep(1000);
	atomic_store(&os_done, 1);
	(void)door_return(NULL, 0, NULL, 0);
}

static void
count_shm_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	uint32_t value;

	(void)cookie;
	(void)desc;
	(void)ndesc;

	if (data != NULL && size >= sizeof(value)) {
		memcpy(&value, data, sizeof(value));
		value += 1;
		memcpy(data, &value, sizeof(value));
	}
	atomic_fetch_add(&os_count, 1);
	(void)door_return(NULL, 0, NULL, 0);
}

static void
setup_named_oneway_shm(const char *name,
		       door_server_procedure_t *proc,
		       int *door_fdp,
		       int *client_fdp,
		       door_named_info_t *infop,
		       door_shm_t *shmp,
		       door_shm_t *attachedp)
{
	int door_fd, client_fd;

	door_fd = door_create(proc, NULL, DOOR_ONEWAY);
	ATF_REQUIRE_MSG(
	    door_fd >= 0, "door_create(DOOR_ONEWAY): %s", strerror(errno));
	ATF_REQUIRE_MSG(door_named_register(door_fd, name, 0) == 0,
			"door_named_register: %s",
			strerror(errno));

	client_fd = door_named_connect(name, 0, infop);
	ATF_REQUIRE_MSG(
	    client_fd >= 0, "door_named_connect: %s", strerror(errno));

	memset(shmp, 0, sizeof(*shmp));
	ATF_REQUIRE_MSG(
	    door_shm_create(client_fd, OWSHM_SIZE, DOOR_SHM_RW, shmp) == 0,
	    "door_shm_create(connected capability): %s",
	    strerror(errno));

	memset(attachedp, 0, sizeof(*attachedp));
	ATF_REQUIRE_MSG(
	    door_shm_attach(
		door_fd, shmp->dsh_region, DOOR_SHM_RW, attachedp) == 0,
	    "owner door_shm_attach: %s",
	    strerror(errno));

	*door_fdp = door_fd;
	*client_fdp = client_fd;
}

static void
cleanup_shm(int client_fd, door_shm_t *shm, door_shm_t *attached)
{
	if (shm->dsh_region != 0)
		(void)door_shm_destroy(client_fd, shm->dsh_region);
	if (attached->dsh_addr != NULL && attached->dsh_addr != shm->dsh_addr)
		(void)door_shm_unmap(attached);
	if (shm->dsh_addr != NULL)
		(void)door_shm_unmap(shm);
}

ATF_TC_WITHOUT_HEAD(connect_oneway_shm_submit);

ATF_TC_BODY(connect_oneway_shm_submit, tc)
{
	door_shm_t shm, attached;
	char name[96];
	uint32_t *word;
	int door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "submit");
	reset_gate();

	setup_named_oneway_shm(name,
			       gated_shm_server,
			       &door_fd,
			       &client_fd,
			       NULL,
			       &shm,
			       &attached);

	word = shm.dsh_addr;
	*word = UINT32_C(0x12345678);
	ATF_REQUIRE_MSG(door_call_shm_region(&shm, 0, sizeof(*word)) == 0,
			"doorctl ONEWAY CALL_SHM strong handle: %s",
			strerror(errno));
	wait_atomic(&os_entered, 1);
	ATF_REQUIRE_EQ(0U, atomic_load(&os_done));
	ATF_REQUIRE_EQ(UINT32_C(0x12345678), os_seen);
	ATF_REQUIRE_EQ(UINT32_C(0xedcba987), *word);

	atomic_store(&os_release, 1);
	wait_atomic(&os_done, 1);

	ATF_REQUIRE(door_named_unregister(door_fd, name, 0) == 0);
	cleanup_shm(client_fd, &shm, &attached);
	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(unregister_active_shm_survives);

ATF_TC_BODY(unregister_active_shm_survives, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	char name[96];
	uint32_t *word;
	int door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "unregister");
	reset_gate();

	setup_named_oneway_shm(name,
			       gated_shm_server,
			       &door_fd,
			       &client_fd,
			       NULL,
			       &shm,
			       &attached);

	word = shm.dsh_addr;
	*word = UINT32_C(0xaabbccdd);
	ref = (door_shm_ref_t){shm.dsh_region, 0, sizeof(*word), 0};
	ATF_REQUIRE(door_call_shm(client_fd, &ref) == 0);
	wait_atomic(&os_entered, 1);

	ATF_REQUIRE(door_named_unregister(door_fd, name, 0) == 0);
	errno = 0;
	ATF_REQUIRE(door_named_connect(name, 0, NULL) == -1);
	ATF_REQUIRE_EQ(ENOENT, errno);

	ATF_REQUIRE_EQ(UINT32_C(0x55443322), *word);
	atomic_store(&os_release, 1);
	wait_atomic(&os_done, 1);

	cleanup_shm(client_fd, &shm, &attached);
	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(destroy_handle_while_active);

ATF_TC_BODY(destroy_handle_while_active, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	char name[96];
	uint32_t *word;
	int door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "destroy");
	reset_gate();

	setup_named_oneway_shm(name,
			       gated_shm_server,
			       &door_fd,
			       &client_fd,
			       NULL,
			       &shm,
			       &attached);

	word = shm.dsh_addr;
	*word = UINT32_C(0x01020304);
	ref = (door_shm_ref_t){shm.dsh_region, 0, sizeof(*word), 0};
	ATF_REQUIRE(door_call_shm(client_fd, &ref) == 0);
	wait_atomic(&os_entered, 1);

	ATF_REQUIRE(door_shm_destroy(client_fd, shm.dsh_region) == 0);
	ATF_REQUIRE_EQ(UINT32_C(0xfefdfcfb), *word);

	errno = 0;
	ATF_REQUIRE(
	    door_shm_attach(
		door_fd, shm.dsh_region, DOOR_SHM_RW, &(door_shm_t){0}) == -1);
	ATF_REQUIRE_EQ(ENOENT, errno);

	atomic_store(&os_release, 1);
	wait_atomic(&os_done, 1);

	shm.dsh_region = 0;
	ATF_REQUIRE(door_named_unregister(door_fd, name, 0) == 0);
	cleanup_shm(client_fd, &shm, &attached);
	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(revoke_active_shm);

ATF_TC_BODY(revoke_active_shm, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	char name[96];
	uint32_t *word;
	int door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "revoke");
	reset_gate();

	setup_named_oneway_shm(name,
			       gated_shm_server,
			       &door_fd,
			       &client_fd,
			       NULL,
			       &shm,
			       &attached);

	word = shm.dsh_addr;
	*word = UINT32_C(0x55667788);
	ref = (door_shm_ref_t){shm.dsh_region, 0, sizeof(*word), 0};
	ATF_REQUIRE(door_call_shm(client_fd, &ref) == 0);
	wait_atomic(&os_entered, 1);

	ATF_REQUIRE(door_revoke(door_fd) == 0);
	ATF_REQUIRE_EQ(UINT32_C(0xaa998877), *word);

	errno = 0;
	ATF_REQUIRE(door_call_shm(client_fd, &ref) == -1);
	ATF_REQUIRE_EQ(EBADF, errno);

	atomic_store(&os_release, 1);
	wait_atomic(&os_done, 1);

	cleanup_shm(client_fd, &shm, &attached);
	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(replacement_generation_shm);

ATF_TC_BODY(replacement_generation_shm, tc)
{
	door_named_info_t old_info, new_info;
	door_shm_t old_shm, old_attached, new_shm, new_attached;
	door_shm_ref_t ref;
	char name[96];
	uint32_t *word;
	int first, second, old_client, new_client;

	(void)tc;
	make_name(name, sizeof(name), "generation");
	atomic_store(&os_count, 0);

	setup_named_oneway_shm(name,
			       count_shm_server,
			       &first,
			       &old_client,
			       &old_info,
			       &old_shm,
			       &old_attached);

	ATF_REQUIRE(door_revoke(first) == 0);

	setup_named_oneway_shm(name,
			       count_shm_server,
			       &second,
			       &new_client,
			       &new_info,
			       &new_shm,
			       &new_attached);
	ATF_REQUIRE(old_info.dni_uniquifier != new_info.dni_uniquifier);

	ref = (door_shm_ref_t){old_shm.dsh_region, 0, sizeof(uint32_t), 0};
	errno = 0;
	ATF_REQUIRE(door_call_shm(old_client, &ref) == -1);
	ATF_REQUIRE_EQ(EBADF, errno);

	word = new_shm.dsh_addr;
	*word = UINT32_C(0x41);
	ref = (door_shm_ref_t){new_shm.dsh_region, 0, sizeof(*word), 0};
	ATF_REQUIRE(door_call_shm(new_client, &ref) == 0);

	/*
	 * ONEWAY submission returns after the kernel has accepted the request,
	 * not after the server callback has consumed its SHM mapping.  Do not
	 * destroy/unmap the replacement generation while count_shm_server() may
	 * still be reading or updating that address.
	 */
	wait_atomic(&os_count, 1);
	ATF_REQUIRE_EQ(UINT32_C(0x42), *word);

	ATF_REQUIRE(door_named_unregister(second, name, 0) == 0);
	cleanup_shm(new_client, &new_shm, &new_attached);
	cleanup_shm(old_client, &old_shm, &old_attached);
	ATF_REQUIRE(close(new_client) == 0);
	ATF_REQUIRE(close(old_client) == 0);
	test_close_door(second);
	test_close_door(first);
}

ATF_TC_WITHOUT_HEAD(cross_generation_region_rejected);

ATF_TC_BODY(cross_generation_region_rejected, tc)
{
	door_shm_t first_shm, first_attached, second_shm, second_attached;
	door_shm_ref_t ref;
	char first_name[96], second_name[96];
	int first, second, first_client, second_client;

	(void)tc;
	make_name(first_name, sizeof(first_name), "crossA");
	make_name(second_name, sizeof(second_name), "crossB");

	setup_named_oneway_shm(first_name,
			       count_shm_server,
			       &first,
			       &first_client,
			       NULL,
			       &first_shm,
			       &first_attached);
	setup_named_oneway_shm(second_name,
			       count_shm_server,
			       &second,
			       &second_client,
			       NULL,
			       &second_shm,
			       &second_attached);

	/*
	 * Numeric region ids may collide. Libdoor passes Door A's uniquifier;
	 * kernel CALL_SHM rejects the mismatch before capture/delivery on Door B.
	 */
	ATF_REQUIRE(door_shm_ref_init(&first_shm, 0, sizeof(uint32_t), &ref) ==
		    0);
	errno = 0;
	ATF_REQUIRE(door_call_shm(second_client, &ref) == -1);
	ATF_REQUIRE_EQ(EXDEV, errno);

	ATF_REQUIRE(door_named_unregister(first, first_name, 0) == 0);
	ATF_REQUIRE(door_named_unregister(second, second_name, 0) == 0);
	cleanup_shm(first_client, &first_shm, &first_attached);
	cleanup_shm(second_client, &second_shm, &second_attached);
	ATF_REQUIRE(close(first_client) == 0);
	ATF_REQUIRE(close(second_client) == 0);
	test_close_door(first);
	test_close_door(second);
}

ATF_TC_WITHOUT_HEAD(burst_submit_revoke);

ATF_TC_BODY(burst_submit_revoke, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	char name[96];
	uint32_t *word;
	unsigned i;
	int door_fd, client_fd;

	(void)tc;
	make_name(name, sizeof(name), "burst");
	atomic_store(&os_count, 0);

	setup_named_oneway_shm(name,
			       count_shm_server,
			       &door_fd,
			       &client_fd,
			       NULL,
			       &shm,
			       &attached);

	word = shm.dsh_addr;
	ref = (door_shm_ref_t){shm.dsh_region, 0, sizeof(*word), 0};
	for (i = 0; i < 256; i++) {
		*word = i;
		ATF_REQUIRE_MSG(door_call_shm(client_fd, &ref) == 0,
				"doorctl ONEWAY+SHM submit %u: %s",
				i,
				strerror(errno));
	}

	ATF_REQUIRE(door_revoke(door_fd) == 0);
	cleanup_shm(client_fd, &shm, &attached);
	ATF_REQUIRE(close(client_fd) == 0);
	test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, connect_oneway_shm_submit);
	ATF_TP_ADD_TC(tp, unregister_active_shm_survives);
	ATF_TP_ADD_TC(tp, destroy_handle_while_active);
	ATF_TP_ADD_TC(tp, revoke_active_shm);
	ATF_TP_ADD_TC(tp, replacement_generation_shm);
	ATF_TP_ADD_TC(tp, cross_generation_region_rejected);
	ATF_TP_ADD_TC(tp, burst_submit_revoke);
	return (atf_no_error());
}
