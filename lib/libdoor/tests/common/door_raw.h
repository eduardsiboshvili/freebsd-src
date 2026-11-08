/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef DOOR_TEST_RAW_H
#define DOOR_TEST_RAW_H
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/door_core.h>
#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static inline long
raw_op(long op, long a, long b, long c, long d, long e)
{
    return ((long)__syscall((quad_t)SYS_door, op, a, b, c, d, e));
}
static inline int
raw_create(uint32_t attributes)
{
    int fd = (int)raw_op(DOOR_SC_CREATE, attributes, 0, DOOR_CREATE_F_NORMAL, 0, 0);
    ATF_REQUIRE(fd >= 0);
    return (fd);
}
static inline void
raw_receive_init(struct door_ioc_return_shm *r, void *buf, size_t size)
{
    memset(r, 0, sizeof(*r));
    r->dirs_return.dir_version = DOOR_ABI_VERSION;
    r->dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
    r->dirs_return.dir_reply_fd = -1;
    r->dirs_return.dir_request_fd = -1;
    r->dirs_return.dir_request_ptr = (uintptr_t)buf;
    r->dirs_return.dir_request_size = size;
}
static inline long
raw_return_shm(struct door_ioc_return_shm *r)
{
    return (raw_op(DOOR_SC_RETURN, (long)(uintptr_t)r, 0, 0, 0, 0));
}
static inline long
raw_submit(int fd, int completion, uint64_t id, const void *buf, size_t size)
{
    struct door_ioc_async_call a;
    memset(&a, 0, sizeof(a));
    a.diac_version = DOOR_ABI_VERSION;
    a.diac_call_id = id;
    a.diac_completion_fd = completion;
    a.diac_request_ptr = (uintptr_t)buf;
    a.diac_request_size = size;
    return (raw_op(DOOR_SC_ASYNC_CALL, fd, (long)(uintptr_t)&a, 0, 0, 0));
}
static inline void
raw_wait_pending(int fd, unsigned count)
{
    struct door_ioc_info i;
    int n;
    for (n = 0; n < 10000; n++) {
        memset(&i, 0, sizeof(i));
        i.di_version = DOOR_ABI_VERSION;
        ATF_REQUIRE(raw_op(DOOR_SC_INFO, fd, (long)(uintptr_t)&i, 0, 0, 0) == 0);
        if (i.di_pending_calls == count)
            return;
        usleep(1000);
    }
    atf_tc_fail("Door pending queue did not reach %u", count);
}
#endif
