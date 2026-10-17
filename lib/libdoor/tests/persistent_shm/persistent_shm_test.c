/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <door.h>

#include "test_common.h"

#define PSHM_SIZE (128 * 1024)

static volatile uint32_t server_seen_word;

static void
persistent_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	uint32_t value;

	(void)cookie;
	(void)desc;
	(void)ndesc;

	if (data != NULL && size >= sizeof(value)) {
		memcpy(&value, data, sizeof(value));
		server_seen_word = value;
		value ^= UINT32_C(0xffffffff);
		memcpy(data, &value, sizeof(value));
	}
	door_return(NULL, 0, NULL, 0);
}

ATF_TC_WITHOUT_HEAD(create_attach_visibility);

ATF_TC_BODY(create_attach_visibility, tc)
{
	door_shm_t creator, attached;
	uint32_t *a, *b;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(persistent_server);

	memset(&creator, 0, sizeof(creator));
	ATF_REQUIRE_MSG(
	    door_shm_create(door_fd, PSHM_SIZE, DOOR_SHM_RW, &creator) == 0,
	    "door_shm_create: %s",
	    strerror(errno));
	ATF_REQUIRE(creator.dsh_region != 0);
	ATF_REQUIRE(creator.dsh_addr != NULL);
	ATF_REQUIRE_EQ((size_t)PSHM_SIZE, creator.dsh_size);

	memset(&attached, 0, sizeof(attached));
	ATF_REQUIRE_MSG(
	    door_shm_attach(
		door_fd, creator.dsh_region, DOOR_SHM_RW, &attached) == 0,
	    "door_shm_attach: %s",
	    strerror(errno));
	ATF_REQUIRE_EQ(creator.dsh_region, attached.dsh_region);
	ATF_REQUIRE_EQ(creator.dsh_size, attached.dsh_size);

	a = creator.dsh_addr;
	b = attached.dsh_addr;
	*a = UINT32_C(0x11223344);
	ATF_REQUIRE_EQ(UINT32_C(0x11223344), *b);
	*b = UINT32_C(0xaabbccdd);
	ATF_REQUIRE_EQ(UINT32_C(0xaabbccdd), *a);

	/*
	 * Same-process creator/consumer uses one mapping, so unmap only once if
	 * libdoor reports identical addresses.
	 */
	if (attached.dsh_addr != creator.dsh_addr)
		ATF_REQUIRE(door_shm_unmap(&attached) == 0);
	ATF_REQUIRE(door_shm_unmap(&creator) == 0);
	ATF_REQUIRE(door_shm_destroy(door_fd, attached.dsh_region) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(call_shm_offset_length);

ATF_TC_BODY(call_shm_offset_length, tc)
{
	door_shm_t shm;
	door_shm_ref_t ref;
	uint32_t *word;
	uint8_t *base;
	const size_t offset = 4096 + 17;
	int door_fd;

	(void)tc;
	server_seen_word = 0;
	door_fd = test_create_door(persistent_server);
	ATF_REQUIRE(door_shm_create(door_fd, PSHM_SIZE, DOOR_SHM_RW, &shm) ==
		    0);
	ATF_REQUIRE(
	    door_shm_attach(
		door_fd, shm.dsh_region, DOOR_SHM_RW, &(door_shm_t){0}) == 0);

	base = shm.dsh_addr;
	word = (uint32_t *)(void *)(base + offset);
	*word = UINT32_C(0x13572468);

	ref = (door_shm_ref_t){
	    .dsr_region = shm.dsh_region,
	    .dsr_offset = offset,
	    .dsr_size = sizeof(*word),
	};
	ATF_REQUIRE_MSG(door_call_shm(door_fd, &ref) == 0,
			"door_call_shm: %s",
			strerror(errno));
	ATF_REQUIRE_EQ(UINT32_C(0x13572468), server_seen_word);
	ATF_REQUIRE_EQ(UINT32_C(0xeca8db97), *word);

	ATF_REQUIRE(door_shm_destroy(door_fd, shm.dsh_region) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(bounds_rejected);

ATF_TC_BODY(bounds_rejected, tc)
{
	door_shm_t shm;
	door_shm_ref_t ref;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(persistent_server);
	ATF_REQUIRE(door_shm_create(door_fd, PSHM_SIZE, DOOR_SHM_RW, &shm) ==
		    0);
	ATF_REQUIRE(
	    door_shm_attach(
		door_fd, shm.dsh_region, DOOR_SHM_RW, &(door_shm_t){0}) == 0);

	ref = (door_shm_ref_t){
	    .dsr_region = shm.dsh_region,
	    .dsr_offset = PSHM_SIZE - 8,
	    .dsr_size = 16,
	};
	errno = 0;
	ATF_REQUIRE(door_call_shm(door_fd, &ref) == -1);
	ATF_REQUIRE_EQ(EOVERFLOW, errno);

	ATF_REQUIRE(door_shm_destroy(door_fd, shm.dsh_region) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(rounded_tail_rejected);

ATF_TC_BODY(rounded_tail_rejected, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	const size_t usable_size = 4097;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(persistent_server);
	ATF_REQUIRE(door_shm_create(door_fd, usable_size, DOOR_SHM_RW, &shm) ==
	    0);
	ATF_REQUIRE_EQ(usable_size, shm.dsh_size);
	memset(&attached, 0, sizeof(attached));
	ATF_REQUIRE(door_shm_attach(door_fd, shm.dsh_region, DOOR_SHM_RW,
	    &attached) == 0);
	ATF_REQUIRE_EQ(usable_size, attached.dsh_size);

	/* The VM object is 8192 bytes, but byte 4097 is not API-visible. */
	ref = (door_shm_ref_t){
	    .dsr_region = shm.dsh_region,
	    .dsr_offset = usable_size,
	    .dsr_size = 1,
	};
	errno = 0;
	ATF_REQUIRE(door_call_shm(door_fd, &ref) == -1);
	ATF_REQUIRE_EQ(EOVERFLOW, errno);

	errno = 0;
	ATF_REQUIRE(door_shm_ref_init(&shm, usable_size, 1, &ref) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);

	ATF_REQUIRE(door_shm_destroy(door_fd, shm.dsh_region) == 0);
	if (attached.dsh_addr != shm.dsh_addr)
		ATF_REQUIRE(door_shm_unmap(&attached) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(consumer_readonly_policy);

ATF_TC_BODY(consumer_readonly_policy, tc)
{
	door_shm_t shm, attached;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(persistent_server);
	ATF_REQUIRE(door_shm_create(door_fd, 4096,
	    DOOR_SHM_RW | DOOR_SHM_CONSUMER_RO, &shm) == 0);

	errno = 0;
	ATF_REQUIRE(door_shm_attach(door_fd, shm.dsh_region, DOOR_SHM_RW,
	    &attached) == -1);
	ATF_REQUIRE_EQ(EACCES, errno);

	ATF_REQUIRE(door_shm_attach(door_fd, shm.dsh_region, DOOR_SHM_READ,
	    &attached) == 0);

	ATF_REQUIRE(door_shm_destroy(door_fd, shm.dsh_region) == 0);
	ATF_REQUIRE(door_shm_unmap(&attached) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(consumer_readonly_mapping_faults);

ATF_TC_BODY(consumer_readonly_mapping_faults, tc)
{
	door_shm_t attached;
	door_shm_id_t region;
	ssize_t nread;
	int fds[2], status;
	pid_t creator, writer;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(persistent_server);
	ATF_REQUIRE(pipe(fds) == 0);
	creator = fork();
	ATF_REQUIRE(creator >= 0);
	if (creator == 0) {
		door_shm_t shm;

		(void)close(fds[0]);
		if (door_shm_create(door_fd, 4096,
			DOOR_SHM_RW | DOOR_SHM_CONSUMER_RO, &shm) == -1 ||
		    write(fds[1], &shm.dsh_region, sizeof(shm.dsh_region)) !=
			(ssize_t)sizeof(shm.dsh_region))
			_exit(1);
		_exit(0);
	}
	ATF_REQUIRE(close(fds[1]) == 0);
	nread = read(fds[0], &region, sizeof(region));
	ATF_REQUIRE_EQ((ssize_t)sizeof(region), nread);
	ATF_REQUIRE(close(fds[0]) == 0);
	ATF_REQUIRE(waitpid(creator, &status, 0) == creator);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));

	memset(&attached, 0, sizeof(attached));
	ATF_REQUIRE_MSG(door_shm_attach(door_fd, region, DOOR_SHM_READ,
	    &attached) == 0, "read-only attach: %s", strerror(errno));
	writer = fork();
	ATF_REQUIRE(writer >= 0);
	if (writer == 0) {
		volatile unsigned char *byte;

		if (mprotect(attached.dsh_addr, 4096,
			PROT_READ | PROT_WRITE) == 0)
			_exit(2);
		byte = attached.dsh_addr;
		*byte = 0x5a;
		_exit(0);
	}
	ATF_REQUIRE(waitpid(writer, &status, 0) == writer);
	ATF_REQUIRE(WIFSIGNALED(status));
	ATF_REQUIRE(WTERMSIG(status) == SIGSEGV || WTERMSIG(status) == SIGBUS);

	ATF_REQUIRE(door_shm_unmap(&attached) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(destroy_invalidates_handle_not_mapping);

ATF_TC_BODY(destroy_invalidates_handle_not_mapping, tc)
{
	door_shm_t shm;
	uint32_t *word;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(persistent_server);
	ATF_REQUIRE(door_shm_create(door_fd, PSHM_SIZE, DOOR_SHM_RW, &shm) ==
		    0);

	word = shm.dsh_addr;
	*word = UINT32_C(0x55aa55aa);
	ATF_REQUIRE(door_shm_destroy(door_fd, shm.dsh_region) == 0);

	/* Handle is dead, existing VM mapping deliberately remains valid. */
	ATF_REQUIRE_EQ(UINT32_C(0x55aa55aa), *word);
	*word = UINT32_C(0x01020304);
	ATF_REQUIRE_EQ(UINT32_C(0x01020304), *word);

	errno = 0;
	ATF_REQUIRE(
	    door_shm_attach(
		door_fd, shm.dsh_region, DOOR_SHM_RW, &(door_shm_t){0}) == -1);
	ATF_REQUIRE_EQ(ENOENT, errno);

	errno = 0;
	ATF_REQUIRE(door_shm_destroy(door_fd, shm.dsh_region) == -1);
	ATF_REQUIRE_EQ(ENOENT, errno);

	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(nonowner_attach_rejected);

ATF_TC_BODY(nonowner_attach_rejected, tc)
{
	door_shm_t shm;
	int status;
	pid_t pid;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(persistent_server);
	ATF_REQUIRE(door_shm_create(door_fd, PSHM_SIZE, DOOR_SHM_RW, &shm) ==
		    0);

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		door_shm_t child;
		errno = 0;
		if (door_shm_attach(
			door_fd, shm.dsh_region, DOOR_SHM_RW, &child) == -1 &&
		    errno == EPERM)
			_exit(0);
		_exit(1);
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));

	ATF_REQUIRE(door_shm_destroy(door_fd, shm.dsh_region) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(api_validation);

ATF_TC_BODY(api_validation, tc)
{
	door_shm_t shm;
	door_shm_ref_t ref;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(persistent_server);

	errno = 0;
	ATF_REQUIRE(door_shm_create(door_fd, 0, DOOR_SHM_RW, &shm) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);

	errno = 0;
	ATF_REQUIRE(door_shm_create(door_fd, 4096, 0x80000000U, &shm) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);

	ATF_REQUIRE(door_shm_create(door_fd, 4096, DOOR_SHM_RW, &shm) == 0);

	ref = (door_shm_ref_t){
	    .dsr_region = shm.dsh_region,
	    .dsr_offset = 0,
	    .dsr_size = 0,
	};

	/*
	 * A created region has no server-side consumer mapping yet.
	 * CALL_SHM must therefore fail with ENXIO independently of length.
	 */
	errno = 0;
	ATF_REQUIRE(door_call_shm(door_fd, &ref) == -1);
	ATF_REQUIRE_EQ(ENXIO, errno);

	/*
	 * Zero-length references are valid once the region is attached:
	 * offset 0, size 0 is inside the region and carries no payload.
	 */
	{
		door_shm_t attached;

		memset(&attached, 0, sizeof(attached));
		ATF_REQUIRE_MSG(
		    door_shm_attach(
			door_fd, shm.dsh_region, DOOR_SHM_RW, &attached) == 0,
		    "door_shm_attach: %s",
		    strerror(errno));

		ATF_REQUIRE_MSG(door_call_shm(door_fd, &ref) == 0,
				"zero-length door_call_shm: %s",
				strerror(errno));

		if (attached.dsh_addr != shm.dsh_addr)
			ATF_REQUIRE(door_shm_unmap(&attached) == 0);
	}

	ATF_REQUIRE(door_shm_destroy(door_fd, shm.dsh_region) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(door_fd);
}

/* entered: SHM body ran and is gated; done: body released, before RETURN. */
static atomic_uint oneway_shm_entered;
static atomic_uint oneway_shm_release;
static atomic_uint oneway_shm_done;
static volatile uint32_t oneway_shm_seen;

static void
oneway_shm_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	uint32_t value;

	(void)cookie;
	(void)desc;
	(void)ndesc;

	value = 0;
	if (data != NULL && size >= sizeof(value)) {
		memcpy(&value, data, sizeof(value));
		oneway_shm_seen = value;
		value ^= UINT32_C(0xffffffff);
		memcpy(data, &value, sizeof(value));
	}

	atomic_store(&oneway_shm_entered, 1);
	while (atomic_load(&oneway_shm_release) == 0)
		usleep(1000);
	atomic_store(&oneway_shm_done, 1);
	door_return(NULL, 0, NULL, 0);
}

static void
oneway_shm_reset(void)
{
	atomic_store(&oneway_shm_entered, 0);
	atomic_store(&oneway_shm_release, 0);
	atomic_store(&oneway_shm_done, 0);
	oneway_shm_seen = 0;
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
			"timed out waiting for ONEWAY callback state %u",
			expected);
}

ATF_TC_WITHOUT_HEAD(oneway_shm_returns_before_callback);

ATF_TC_BODY(oneway_shm_returns_before_callback, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	uint32_t *word;
	int fd;

	(void)tc;
	oneway_shm_reset();
	fd = door_create(oneway_shm_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE_MSG(fd >= 0, "door_create: %s", strerror(errno));

	ATF_REQUIRE(door_shm_create(fd, 4096, DOOR_SHM_RW, &shm) == 0);
	memset(&attached, 0, sizeof(attached));
	ATF_REQUIRE(
	    door_shm_attach(fd, shm.dsh_region, DOOR_SHM_RW, &attached) == 0);

	word = shm.dsh_addr;
	*word = UINT32_C(0x10203040);
	ref = (door_shm_ref_t){shm.dsh_region, 0, sizeof(*word), 0};

	ATF_REQUIRE_MSG(door_call_shm(fd, &ref) == 0,
			"oneway door_call_shm: %s",
			strerror(errno));
	wait_atomic(&oneway_shm_entered, 1);
	ATF_REQUIRE_EQ(0U, atomic_load(&oneway_shm_done));
	ATF_REQUIRE_EQ(UINT32_C(0x10203040), oneway_shm_seen);
	ATF_REQUIRE_EQ(UINT32_C(0xefdfcfbf), *word);

	atomic_store(&oneway_shm_release, 1);
	wait_atomic(&oneway_shm_done, 1);

	ATF_REQUIRE(door_shm_destroy(fd, shm.dsh_region) == 0);
	if (attached.dsh_addr != shm.dsh_addr)
		ATF_REQUIRE(door_shm_unmap(&attached) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(oneway_shm_destroy_handle_while_active);

ATF_TC_BODY(oneway_shm_destroy_handle_while_active, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	uint32_t *word;
	int fd;

	(void)tc;
	oneway_shm_reset();
	fd = door_create(oneway_shm_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(door_shm_create(fd, 4096, DOOR_SHM_RW, &shm) == 0);
	memset(&attached, 0, sizeof(attached));
	ATF_REQUIRE(
	    door_shm_attach(fd, shm.dsh_region, DOOR_SHM_RW, &attached) == 0);

	word = shm.dsh_addr;
	*word = UINT32_C(0xa1b2c3d4);
	ref = (door_shm_ref_t){shm.dsh_region, 0, sizeof(*word), 0};
	ATF_REQUIRE(door_call_shm(fd, &ref) == 0);
	wait_atomic(&oneway_shm_entered, 1);

	/*
	 * The callback is already delivered. Destroy invalidates the handle but
	 * preserves existing mappings; this does not test destroy before export.
	 */
	ATF_REQUIRE(door_shm_destroy(fd, shm.dsh_region) == 0);
	ATF_REQUIRE_EQ(UINT32_C(0x5e4d3c2b), *word);

	errno = 0;
	ATF_REQUIRE(door_shm_attach(
			fd, shm.dsh_region, DOOR_SHM_RW, &(door_shm_t){0}) ==
		    -1);
	ATF_REQUIRE_EQ(ENOENT, errno);

	atomic_store(&oneway_shm_release, 1);
	wait_atomic(&oneway_shm_done, 1);
	if (attached.dsh_addr != shm.dsh_addr)
		ATF_REQUIRE(door_shm_unmap(&attached) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(oneway_shm_revoke_active);

ATF_TC_BODY(oneway_shm_revoke_active, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	uint32_t *word;
	int fd;

	(void)tc;
	oneway_shm_reset();
	fd = door_create(oneway_shm_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(door_shm_create(fd, 4096, DOOR_SHM_RW, &shm) == 0);
	memset(&attached, 0, sizeof(attached));
	ATF_REQUIRE(
	    door_shm_attach(fd, shm.dsh_region, DOOR_SHM_RW, &attached) == 0);

	word = shm.dsh_addr;
	*word = UINT32_C(0x55667788);
	ref = (door_shm_ref_t){shm.dsh_region, 0, sizeof(*word), 0};
	ATF_REQUIRE(door_call_shm(fd, &ref) == 0);
	wait_atomic(&oneway_shm_entered, 1);

	ATF_REQUIRE(door_revoke(fd) == 0);
	/* Revoke invalidates handles, not mappings already installed in VM. */
	ATF_REQUIRE_EQ(UINT32_C(0xaa998877), *word);

	errno = 0;
	ATF_REQUIRE(door_call_shm(fd, &ref) == -1);
	ATF_REQUIRE_EQ(EBADF, errno);

	atomic_store(&oneway_shm_release, 1);
	wait_atomic(&oneway_shm_done, 1);
	if (attached.dsh_addr != shm.dsh_addr)
		ATF_REQUIRE(door_shm_unmap(&attached) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(oneway_shm_repeated_submit);

ATF_TC_BODY(oneway_shm_repeated_submit, tc)
{
	door_shm_t shm, attached;
	door_shm_ref_t ref;
	uint32_t *word;
	unsigned i;
	int fd;

	(void)tc;
	fd = door_create(persistent_server, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(door_shm_create(fd, 4096, DOOR_SHM_RW, &shm) == 0);
	memset(&attached, 0, sizeof(attached));
	ATF_REQUIRE(
	    door_shm_attach(fd, shm.dsh_region, DOOR_SHM_RW, &attached) == 0);

	word = shm.dsh_addr;
	ref = (door_shm_ref_t){shm.dsh_region, 0, sizeof(*word), 0};
	for (i = 0; i < 256; i++) {
		*word = i;
		ATF_REQUIRE_MSG(door_call_shm(fd, &ref) == 0,
				"ONEWAY SHM submit %u failed: %s",
				i,
				strerror(errno));
	}

	/*
	 * Queue lifetime is the subject here.  Closing/revoking after a burst
	 * must drain/drop all queued SHM call references without leaking.
	 */
	ATF_REQUIRE(door_revoke(fd) == 0);
	if (attached.dsh_addr != shm.dsh_addr)
		ATF_REQUIRE(door_shm_unmap(&attached) == 0);
	ATF_REQUIRE(door_shm_unmap(&shm) == 0);
	test_close_door(fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, create_attach_visibility);
	ATF_TP_ADD_TC(tp, call_shm_offset_length);
	ATF_TP_ADD_TC(tp, bounds_rejected);
	ATF_TP_ADD_TC(tp, rounded_tail_rejected);
	ATF_TP_ADD_TC(tp, consumer_readonly_policy);
	ATF_TP_ADD_TC(tp, consumer_readonly_mapping_faults);
	ATF_TP_ADD_TC(tp, destroy_invalidates_handle_not_mapping);
	ATF_TP_ADD_TC(tp, nonowner_attach_rejected);
	ATF_TP_ADD_TC(tp, api_validation);
	ATF_TP_ADD_TC(tp, oneway_shm_returns_before_callback);
	ATF_TP_ADD_TC(tp, oneway_shm_destroy_handle_while_active);
	ATF_TP_ADD_TC(tp, oneway_shm_revoke_active);
	ATF_TP_ADD_TC(tp, oneway_shm_repeated_submit);
	return (atf_no_error());
}
