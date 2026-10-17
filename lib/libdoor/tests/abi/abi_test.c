/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/door_core.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <door.h>

_Static_assert(sizeof(door_ptr_t) == 8, "door_ptr_t ABI");
_Static_assert(sizeof(door_id_t) == 8, "door_id_t ABI");
_Static_assert(sizeof(door_attr_t) == 4, "door_attr_t ABI");

_Static_assert(sizeof(door_desc_t) == 24, "door_desc_t ABI");
_Static_assert(_Alignof(door_desc_t) == 4, "door_desc_t alignment");
_Static_assert(offsetof(door_desc_t, d_attributes) == 0,
	       "door_desc_t.d_attributes ABI");
_Static_assert(offsetof(door_desc_t, d_descriptor) == 4,
	       "door_desc_t.d_descriptor ABI");
_Static_assert(offsetof(door_desc_t, d_id) == 8, "door_desc_t.d_id ABI");

_Static_assert(sizeof(door_info_t) == 48, "door_info_t ABI");
_Static_assert(_Alignof(door_info_t) == 4, "door_info_t alignment");
_Static_assert(offsetof(door_info_t, di_target) == 0,
	       "door_info_t.di_target ABI");
_Static_assert(offsetof(door_info_t, di_proc) == 4, "door_info_t.di_proc ABI");
_Static_assert(offsetof(door_info_t, di_data) == 12, "door_info_t.di_data ABI");
_Static_assert(offsetof(door_info_t, di_attributes) == 20,
	       "door_info_t.di_attributes ABI");
_Static_assert(offsetof(door_info_t, di_uniquifier) == 24,
	       "door_info_t.di_uniquifier ABI");

_Static_assert(sizeof(door_cred_t) == 36, "door_cred_t ABI");
#include "abi_layout_assert.h"
#include "../../../../sys/sys/door_compat.h"
_Static_assert(sizeof(door_ucred_t) == 100, "door_ucred_t ABI");

_Static_assert(DOOR_PARAM_DESC_MAX == 1, "DESC_MAX number");
_Static_assert(DOOR_PARAM_DATA_MAX == 2, "DATA_MAX number");
_Static_assert(DOOR_PARAM_DATA_MIN == 3, "DATA_MIN number");
_Static_assert((DOOR_CREATE_MASK & DOOR_PRIVCREATE) != 0,
	       "illumos-compatible creation mask");
_Static_assert((DOOR_ATTR_MASK & DOOR_PRIVCREATE) != 0,
	       "DOOR_PRIVCREATE info attribute");
_Static_assert((DOOR_ATTR_MASK & DOOR_DEPLETION_CB) == 0,
	       "depletion callback is transient, not a stored door attribute");

ATF_TC(public_layout);

ATF_TC_HEAD(public_layout, tc)
{
	atf_tc_set_md_var(
	    tc,
	    "descr",
	    "Verify the frozen libdoor 1 public type layout and constants");
}

ATF_TC_BODY(public_layout, tc)
{
	ATF_REQUIRE_EQ(sizeof(door_desc_t), 24U);
	ATF_REQUIRE_EQ(sizeof(door_info_t), 48U);
	ATF_REQUIRE_EQ(sizeof(door_cred_t), 36U);
	ATF_REQUIRE_EQ(sizeof(door_arg_t), sizeof(void *) == 8 ? 48U : 24U);
}

struct resize_client {
	int fd;
	char request[64];
	size_t size;
	int result, error;
	bool send_descriptor;
	door_desc_t descriptor;
};

static void *
resize_call(void *arg)
{
	struct resize_client *client = arg;
	door_arg_t call;

	memset(&call, 0, sizeof(call));
	call.data_ptr = client->request;
	call.data_size = client->size;
	if (client->send_descriptor) {
		call.desc_ptr = &client->descriptor;
		call.desc_num = 1;
	}
	client->result = door_call(client->fd, &call);
	client->error = errno;
	return (NULL);
}

static long
raw_return(struct door_ioc_return *ret)
{
	struct door_ioc_return_shm extended;
	long result;

	/* Native RETURN copies the extended payload, even for copied data. */
	memset(&extended, 0, sizeof(extended));
	extended.dirs_return = *ret;
	/* Old amd64 padding may contain arbitrary bytes; input is ignored. */
	extended.dirs_return.dir_padding = UINT32_MAX;
	result = (long)__syscall((quad_t)SYS_door, DOOR_SC_RETURN,
	    (long)(uintptr_t)&extended, 0, 0, 0, 0);
	if (result == 0) {
		ATF_REQUIRE_EQ(extended.dirs_return.dir_padding, 0U);
		*ret = extended.dirs_return;
	}
	return (result);
}

static void
receive_resize(bool descriptor, bool scalar)
{
	struct resize_client first, second;
	struct door_ioc_return ret;
	struct door_ioc_info info;
	struct door_ioc_cred cred;
	struct door_kdesc received_descriptor;
	struct door_sys_fast_return_out out;
	pthread_t first_thread, second_thread;
	char receive[64];
	uint64_t first_id;
	int fd, attempt, source_fd = -1;

	fd = (int)__syscall((quad_t)SYS_door, DOOR_SC_CREATE,
	    0, 0, DOOR_CREATE_F_NORMAL, 0, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(__syscall((quad_t)SYS_door, DOOR_SC_BIND,
	    (long)fd, 0, 0, 0, 0) == 0);
	memset(&first, 0, sizeof(first));
	first.fd = fd;
	first.size = 1;
	first.request[0] = 'a';
	ATF_REQUIRE(pthread_create(&first_thread, NULL, resize_call, &first) == 0);
	memset(&ret, 0, sizeof(ret));
	ret.dir_version = DOOR_ABI_VERSION;
	ret.dir_flags = DOOR_RETURN_F_RESIZABLE;
	ret.dir_reply_fd = -1;
	ret.dir_request_ptr = (uintptr_t)receive;
	ret.dir_request_size = 1;
	ATF_REQUIRE(raw_return(&ret) == 0);
	first_id = ret.dir_call_id;
	ATF_REQUIRE(first_id != 0 && receive[0] == 'a');
	/* The former amd64 tail padding is ignored on input and cleared out. */
	memset(&cred, 0, sizeof(cred));
	cred.dicr_version = DOOR_ABI_VERSION;
	cred.dicr_call_id = first_id;
	cred.dicr_padding = UINT32_MAX;
	ATF_REQUIRE(__syscall((quad_t)SYS_door, DOOR_SC_CRED,
	    (long)(uintptr_t)&cred, 0, 0, 0, 0) == 0);
	ATF_REQUIRE_EQ(cred.dicr_padding, 0U);


	memset(&second, 0, sizeof(second));
	second.fd = fd;
	second.size = sizeof(second.request);
	memset(second.request, 'b', second.size);
	if (descriptor) {
		source_fd = open("/dev/null", O_RDWR);
		ATF_REQUIRE(source_fd >= 0);
		second.send_descriptor = true;
		second.descriptor.d_attributes = DOOR_DESCRIPTOR;
		second.descriptor.d_descriptor = source_fd;
	}
	ATF_REQUIRE(pthread_create(&second_thread, NULL, resize_call, &second) == 0);
	/* Queue the next request before completing the first, so resize cannot
	 * depend on timing of a future arrival. */
	for (attempt = 0; attempt < 10000; attempt++) {
		memset(&info, 0, sizeof(info));
		info.di_version = DOOR_ABI_VERSION;
		ATF_REQUIRE(__syscall((quad_t)SYS_door, DOOR_SC_INFO,
		    (long)fd, (long)(uintptr_t)&info, 0, 0, 0) == 0);
		if (info.di_pending_calls == 1)
			break;
		usleep(1000);
	}
	ATF_REQUIRE(attempt != 10000);
	ret.dir_flags = DOOR_RETURN_F_RESIZABLE;
	ret.dir_request_desc_ptr = (uintptr_t)&received_descriptor;
	ret.dir_request_desc_count = 0;
	/* Descriptor-only resize keeps enough data capacity. */
	ret.dir_request_size = descriptor && !scalar ? sizeof(receive) : 1;
	if (scalar) {
		memset(&out, 0, sizeof(out));
#if SIZE_MAX < UINT64_MAX
        /* Compat rejects scalar fast selectors; retry the same live call full. */
        ATF_REQUIRE_ERRNO(ENOSYS,
            __syscall((quad_t)SYS_door, DOOR_SC_EMPTY_RETURN,
                (long)first_id, (long)(uintptr_t)receive, 1L,
                (long)(uintptr_t)&out, 0L) == -1);
        ATF_REQUIRE(raw_return(&ret) == 0);
#else
		ATF_REQUIRE(__syscall((quad_t)SYS_door, DOOR_SC_EMPTY_RETURN,
		    (long)first_id, (long)(uintptr_t)receive, 1,
		    (long)(uintptr_t)&out, 0) == 0);
		ret.dir_flags = out.dsfro_flags;
		ret.dir_call_id = out.dsfro_call_id;
		ret.dir_request_size = out.dsfro_request_size;
		ret.dir_request_desc_count = out.dsfro_request_desc_count;
#endif
	} else
		ATF_REQUIRE(raw_return(&ret) == 0);
	ATF_REQUIRE((ret.dir_flags & (DOOR_RETURN_F_COMPLETED |
	    DOOR_RETURN_F_NEED_BUFS)) == (DOOR_RETURN_F_COMPLETED |
	    DOOR_RETURN_F_NEED_BUFS));
	ATF_REQUIRE_EQ(ret.dir_call_id, 0);
	ATF_REQUIRE_EQ(ret.dir_request_size, sizeof(second.request));
	ATF_REQUIRE_EQ(ret.dir_request_desc_count, descriptor ? 1U : 0U);
	ATF_REQUIRE(pthread_join(first_thread, NULL) == 0);
	ATF_REQUIRE_EQ(first.result, 0);

	/* COMPLETED consumed first_id. Pure wait must deliver only the second. */
	ret.dir_flags = DOOR_RETURN_F_RESIZABLE;
	ret.dir_call_id = 0;
	ret.dir_request_size = sizeof(receive);
	ret.dir_request_desc_ptr = (uintptr_t)&received_descriptor;
	ret.dir_request_desc_count = 1;
	ATF_REQUIRE(raw_return(&ret) == 0);
	ATF_REQUIRE(ret.dir_call_id != 0 && ret.dir_call_id != first_id);
	ATF_REQUIRE_EQ(ret.dir_request_size, second.size);
	ATF_REQUIRE(memcmp(receive, second.request, second.size) == 0);
	ATF_REQUIRE_EQ(ret.dir_request_desc_count, descriptor ? 1U : 0U);
	if (descriptor) {
		ATF_REQUIRE(fcntl(received_descriptor.dd_fd, F_GETFD) >= 0);
		ATF_REQUIRE(close(received_descriptor.dd_fd) == 0);
		ATF_REQUIRE(close(source_fd) == 0);
	}
	ATF_REQUIRE(door_revoke(fd) == 0);
	ATF_REQUIRE(__syscall((quad_t)SYS_door, DOOR_SC_WORKER_EXIT,
	    0, 0, 0, 0, 0) == 0);
	ATF_REQUIRE(pthread_join(second_thread, NULL) == 0);
	ATF_REQUIRE(second.result == -1 && second.error == EBADF);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(receive_resize_without_replay);
ATF_TC_BODY(receive_resize_without_replay, tc)
{
	(void)tc;
	receive_resize(false, false);
	receive_resize(true, false);
	receive_resize(true, true);
}

ATF_TC_WITHOUT_HEAD(compat_word_decode);
ATF_TC_BODY(compat_word_decode, tc)
{
    struct door_compat_args out;
    uint32_t words[5] = { UINT32_MAX, 0xf1234567U, 0x87654321U, 0, 0 };
    uint32_t op;
    int error;

    (void)tc;
    ATF_REQUIRE_EQ(door_compat_decode(DOOR_SC_CALL, words, &out), 0);
    ATF_REQUIRE_EQ(out.arg[0], -1);
    ATF_REQUIRE_EQ(out.arg[1], INT64_C(0xf1234567));
    ATF_REQUIRE_EQ(door_compat_decode(DOOR_SC_CREATE, words, &out), 0);
    ATF_REQUIRE_EQ(out.arg[0], UINT32_MAX);
    ATF_REQUIRE_EQ(out.arg[1], INT64_C(0xf1234567));
    ATF_REQUIRE_EQ(door_compat_decode(DOOR_SC_ASYNC_CANCEL, words, &out), 0);
    ATF_REQUIRE_EQ(out.arg[1], (int32_t)words[1]);
    ATF_REQUIRE_EQ(out.arg[2], UINT32_C(0x87654321));
    for (op = DOOR_SC_CALL; op <= DOOR_SC_SHM_VIEW_DESTROY; op++) {
        error = door_compat_decode(op, words, &out);
        if (op == DOOR_SC_FAST_CALL || op == DOOR_SC_FAST_RETURN ||
            op == DOOR_SC_EMPTY_CALL || op == DOOR_SC_EMPTY_RETURN ||
            op == DOOR_SC_FAST_CALL_MAPPED || op == DOOR_SC_EMPTY_CALL_MAPPED)
            ATF_REQUIRE_EQ(error, ENOSYS);
        else
            ATF_REQUIRE_EQ(error, 0);
    }
    ATF_REQUIRE_EQ(door_compat_decode(UINT32_MAX, words, &out), EINVAL);
    ATF_REQUIRE_EQ(door_compat_range(UINT64_C(0xf0000000), 16,
        UINT64_C(0x100000000)), 0);
    ATF_REQUIRE_EQ(door_compat_range(UINT64_C(0x100000001), 0,
        UINT64_C(0x100000000)), EFAULT);
    ATF_REQUIRE_EQ(door_compat_range(1, UINT64_C(0x100000000),
        UINT64_C(0x100000000)), EOVERFLOW);
    ATF_REQUIRE_EQ(door_compat_range(UINT64_C(0xfffffff0), 32,
        UINT64_C(0x100000000)), EFAULT);
    ATF_REQUIRE_EQ(door_compat_range(UINT64_C(0xbffffff0), 32,
        UINT64_C(0xc0000000)), EFAULT);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, public_layout);
	ATF_TP_ADD_TC(tp, compat_word_decode);
	ATF_TP_ADD_TC(tp, receive_resize_without_replay);
	return (atf_no_error());
}
