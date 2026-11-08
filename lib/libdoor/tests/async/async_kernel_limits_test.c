/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "door_raw.h"
#include <door.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>

ATF_TC_WITHOUT_HEAD(raw_admission_rollback_and_full_queue);
ATF_TC_BODY(raw_admission_rollback_and_full_queue, tc)
{
    struct door_ioc_return_shm r;
    struct door_async_completion h;
    char receive[sizeof(h)];
    bool seen[257] = {false};
    int request, completion;
    unsigned n, index, ordinary = 0, correlated = 0;
    (void)tc;
    request = raw_create(0);
    completion = raw_create(DOOR_ONEWAY);
    /* Bad memory fails after reservation, not at argument validation. */
    for (n = 0; n < 300; n++) {
        errno = 0;
        ATF_REQUIRE(raw_submit(request, completion, 1, (void *)(uintptr_t)1, 4) == -1);
        ATF_REQUIRE_EQ(errno, EFAULT);
    }
    ATF_REQUIRE(raw_submit(request, completion, 1, NULL, 0) == 0);
    errno = 0;
    ATF_REQUIRE(raw_submit(request, completion, 1, NULL, 0) == -1);
    ATF_REQUIRE_EQ(errno, EEXIST); /* Duplicate id must also return its slot. */
    ATF_REQUIRE(raw_op(DOOR_SC_ASYNC_CANCEL, request, completion, 1, 0, 0) == 0);
    raw_wait_pending(completion, 1);
    for (n = 0; n < 256; n++)
        ATF_REQUIRE(raw_submit(request, completion, 100 + n, NULL, 0) == 0);
    errno = 0;
    ATF_REQUIRE(raw_submit(request, completion, 999, NULL, 0) == -1);
    ATF_REQUIRE_EQ(errno, EAGAIN);
    /* One queued completion + 256 reservations leaves 3839 ordinary slots. */
    for (n = 0; n < 3839; n++)
        ATF_REQUIRE(raw_op(DOOR_SC_ONEWAY, completion, 0, 0, 0, 0) == 0);
    errno = 0;
    ATF_REQUIRE(raw_op(DOOR_SC_ONEWAY, completion, 0, 0, 0, 0) == -1);
    ATF_REQUIRE_EQ(errno, EAGAIN);
    for (n = 0; n < 256; n++)
        ATF_REQUIRE(raw_op(DOOR_SC_ASYNC_CANCEL, request, completion, 100 + n, 0, 0) == 0);
    raw_wait_pending(completion, 4096);
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, completion, 0, 0, 0, 0) == 0);
    raw_receive_init(&r, receive, sizeof(receive));
    for (n = 0; n < 4096; n++) {
        ATF_REQUIRE(raw_return_shm(&r) == 0);
        ATF_REQUIRE(r.dirs_return.dir_call_id != 0);
        if (r.dirs_return.dir_request_size == 0) {
            ordinary++;
        } else {
            ATF_REQUIRE_EQ(r.dirs_return.dir_request_size, sizeof(h));
            memcpy(&h, receive, sizeof(h));
            ATF_REQUIRE_EQ(h.dac_version, DOOR_ABI_VERSION);
            ATF_REQUIRE_EQ(h.dac_status, ECANCELED);
            ATF_REQUIRE_EQ(h.dac_data_size, 0);
            ATF_REQUIRE_EQ(h.dac_flags, DOOR_ASYNC_C_CANCELLED);
            if (h.dac_call_id == 1)
                index = 0;
            else {
                ATF_REQUIRE(h.dac_call_id >= 100 && h.dac_call_id < 356);
                index = (unsigned)(h.dac_call_id - 100 + 1);
            }
            ATF_REQUIRE(!seen[index]);
            seen[index] = true;
            correlated++;
        }
        r.dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
        r.dirs_return.dir_request_size = sizeof(receive);
    }
    ATF_REQUIRE_EQ(ordinary, 3839);
    ATF_REQUIRE_EQ(correlated, 257);
    ATF_REQUIRE(raw_return_shm(&r) == 0); /* Complete the last ONEWAY item. */
    ATF_REQUIRE((r.dirs_return.dir_flags & DOOR_RETURN_F_REWAIT) != 0);
    ATF_REQUIRE(raw_op(DOOR_SC_UNBIND, 0, 0, 0, 0, 0) == 0);
    /* A fresh submission proves admission returned after cancellation/drain. */
    ATF_REQUIRE(raw_submit(request, completion, 999, NULL, 0) == 0);
    ATF_REQUIRE(door_revoke(request) == 0);
    raw_wait_pending(completion, 1);
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, completion, 0, 0, 0, 0) == 0);
    raw_receive_init(&r, receive, sizeof(receive));
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    memcpy(&h, receive, sizeof(h));
    ATF_REQUIRE(h.dac_call_id == 999 && h.dac_status == EBADF);
    r.dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
    r.dirs_return.dir_request_size = sizeof(receive);
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    ATF_REQUIRE(raw_op(DOOR_SC_UNBIND, 0, 0, 0, 0, 0) == 0);
    ATF_REQUIRE(door_revoke(completion) == 0);
    close(request); close(completion);
}

ATF_TC_WITHOUT_HEAD(raw_worker_exit_returns_reservation);
ATF_TC_BODY(raw_worker_exit_returns_reservation, tc)
{
    struct door_ioc_return_shm r;
    struct door_async_completion h;
    int request, completion;
    (void)tc;
    request = raw_create(0);
    completion = raw_create(DOOR_ONEWAY);
    ATF_REQUIRE(raw_submit(request, completion, 7, NULL, 0) == 0);
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, request, 0, 0, 0, 0) == 0);
    raw_receive_init(&r, NULL, 0);
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    ATF_REQUIRE(raw_op(DOOR_SC_WORKER_EXIT, 0, 0, 0, 0, 0) == 0);
    raw_wait_pending(completion, 1);
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, completion, 0, 0, 0, 0) == 0);
    raw_receive_init(&r, &h, sizeof(h));
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    ATF_REQUIRE(h.dac_call_id == 7 && h.dac_status == ECONNRESET);
    ATF_REQUIRE_EQ(h.dac_flags, DOOR_ASYNC_C_WORKER_EXIT);
    r.dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
    r.dirs_return.dir_request_size = sizeof(h);
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    ATF_REQUIRE(raw_op(DOOR_SC_UNBIND, 0, 0, 0, 0, 0) == 0);
    for (unsigned n = 0; n < 256; n++)
        ATF_REQUIRE(raw_submit(request, completion, 100 + n, NULL, 0) == 0);
    errno = 0;
    ATF_REQUIRE(raw_submit(request, completion, 999, NULL, 0) == -1);
    ATF_REQUIRE_EQ(errno, EAGAIN);
    ATF_REQUIRE(door_revoke(request) == 0);
    ATF_REQUIRE(door_revoke(completion) == 0);
    close(request); close(completion);
}
#ifdef DOOR_TESTS
#include <sys/ioctl.h>
#include <sys/door_test.h>
#include <fcntl.h>
#endif
struct raw_race {
    pthread_barrier_t start;
    int request, completion, cancel_result, cancel_error, revoke_result;
    uint64_t id;
};
static void *
raw_race_return(void *cookie)
{
    struct raw_race *f = cookie;
    struct door_ioc_return_shm r;
    uint64_t id;
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, f->request, 0, 0, 0, 0) == 0);
    raw_receive_init(&r, NULL, 0);
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    id = r.dirs_return.dir_call_id;
    ATF_REQUIRE(id != 0);
    pthread_barrier_wait(&f->start);
    raw_receive_init(&r, NULL, 0);
    r.dirs_return.dir_call_id = id;
    (void)raw_return_shm(&r);
    /* Revoke/RETURN may already have removed this thread's binding. */
    (void)raw_op(DOOR_SC_WORKER_EXIT, 0, 0, 0, 0, 0);
    return (NULL);
}
static void *
raw_race_cancel(void *cookie)
{
    struct raw_race *f = cookie;
    pthread_barrier_wait(&f->start);
    f->cancel_result = (int)raw_op(DOOR_SC_ASYNC_CANCEL,
        f->request, f->completion, f->id, 0, 0);
    f->cancel_error = errno;
    return (NULL);
}
static void *
raw_race_revoke(void *cookie)
{
    struct raw_race *f = cookie;
    pthread_barrier_wait(&f->start);
    f->revoke_result = door_revoke(f->request);
    return (NULL);
}
static unsigned
raw_pending(int fd)
{
    struct door_ioc_info i;
    memset(&i, 0, sizeof(i));
    i.di_version = DOOR_ABI_VERSION;
    ATF_REQUIRE(raw_op(DOOR_SC_INFO, fd, (long)(uintptr_t)&i, 0, 0, 0) == 0);
    return (i.di_pending_calls);
}
static void
run_raw_race(int probe)
{
#ifndef DOOR_TESTS
    (void)probe;
#endif
    for (unsigned iteration = 0; iteration < 100; iteration++) {
        struct raw_race f;
        struct door_ioc_return_shm r;
        struct door_async_completion h;
        pthread_t worker, cancel, revoke;
        unsigned n, count = 0;
        memset(&f, 0, sizeof(f));
        f.request = raw_create(0);
        f.completion = raw_create(DOOR_ONEWAY);
        f.id = iteration + 1;
        ATF_REQUIRE(pthread_barrier_init(&f.start, NULL, 4) == 0);
        ATF_REQUIRE(raw_submit(f.request, f.completion, f.id, NULL, 0) == 0);
        ATF_REQUIRE(pthread_create(&worker, NULL, raw_race_return, &f) == 0);
        ATF_REQUIRE(pthread_create(&cancel, NULL, raw_race_cancel, &f) == 0);
        ATF_REQUIRE(pthread_create(&revoke, NULL, raw_race_revoke, &f) == 0);
        pthread_barrier_wait(&f.start);
        ATF_REQUIRE(pthread_join(worker, NULL) == 0);
        ATF_REQUIRE(pthread_join(cancel, NULL) == 0);
        ATF_REQUIRE(pthread_join(revoke, NULL) == 0);
        ATF_REQUIRE_EQ(f.revoke_result, 0);
        ATF_REQUIRE(f.cancel_result == 0 || (f.cancel_result == -1 &&
            (f.cancel_error == ESRCH || f.cancel_error == EALREADY ||
             f.cancel_error == EBADF)));
#ifdef DOOR_TESTS
        /* Participants have exited; no new publication can be scheduled by
         * them. Drain includes jobs selected before their post-unlock enqueue. */
        if (probe >= 0) {
            ATF_REQUIRE(ioctl(probe, DOOR_TEST_DRAIN) == 0);
            ATF_REQUIRE_EQ(raw_pending(f.completion), 1);
        }
#endif
        /* Completion taskqueue may run after all syscall participants exit. */
        for (n = 0; n < 10000 && raw_pending(f.completion) == 0; n++)
            usleep(1000);
        ATF_REQUIRE(n != 10000);
        /* FIFO marker follows the first published completion. No libdoor
         * async lookup can hide a duplicate header in this receiver. */
        ATF_REQUIRE(raw_op(DOOR_SC_ONEWAY, f.completion, 0, 0, 0, 0) == 0);
        ATF_REQUIRE(raw_op(DOOR_SC_BIND, f.completion, 0, 0, 0, 0) == 0);
        raw_receive_init(&r, &h, sizeof(h));
        for (;;) {
            ATF_REQUIRE(raw_return_shm(&r) == 0);
            ATF_REQUIRE(r.dirs_return.dir_call_id != 0);
            if (r.dirs_return.dir_request_size == 0)
                break;
            ATF_REQUIRE_EQ(r.dirs_return.dir_request_size, sizeof(h));
            ATF_REQUIRE_EQ(h.dac_version, DOOR_ABI_VERSION);
            ATF_REQUIRE_EQ(h.dac_call_id, f.id);
            ATF_REQUIRE_EQ(h.dac_data_size, 0);
            ATF_REQUIRE(h.dac_status == 0 || h.dac_status == ECANCELED ||
                h.dac_status == EBADF);
            ATF_REQUIRE_EQ(++count, 1);
            r.dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
            r.dirs_return.dir_request_size = sizeof(h);
        }
        ATF_REQUIRE_EQ(count, 1);
        r.dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
        r.dirs_return.dir_request_size = sizeof(h);
        ATF_REQUIRE(raw_return_shm(&r) == 0);
        ATF_REQUIRE((r.dirs_return.dir_flags & DOOR_RETURN_F_REWAIT) != 0);
        ATF_REQUIRE(raw_op(DOOR_SC_UNBIND, 0, 0, 0, 0, 0) == 0);
        /* Observe late taskqueue delivery after the marker was completed. */
        for (n = 0; n < (probe < 0 ? 100u : 1u); n++) {
            ATF_REQUIRE_EQ(raw_pending(f.completion), 0);
            if (probe < 0)
                usleep(1000);
        }
        ATF_REQUIRE(door_revoke(f.completion) == 0);
        ATF_REQUIRE(close(f.request) == 0);
        ATF_REQUIRE(close(f.completion) == 0);
        ATF_REQUIRE(pthread_barrier_destroy(&f.start) == 0);
    }
}

ATF_TC(raw_return_cancel_revoke_completion_count);
ATF_TC_HEAD(raw_return_cancel_revoke_completion_count, tc)
{
    atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(raw_return_cancel_revoke_completion_count, tc)
{
    (void)tc;
    run_raw_race(-1);
}
#ifdef DOOR_TESTS
ATF_TC(raw_return_cancel_revoke_drained);
ATF_TC_HEAD(raw_return_cancel_revoke_drained, tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "120");
}
ATF_TC_BODY(raw_return_cancel_revoke_drained, tc)
{
    int probe;
    (void)tc;
    probe = open("/dev/door_test", O_RDWR | O_CLOEXEC);
    ATF_REQUIRE_MSG(probe >= 0, "Build DOORFS_TEST kernel before running this test");
    run_raw_race(probe);
    ATF_REQUIRE(close(probe) == 0);
}
#endif

ATF_TP_ADD_TCS(tp)
{
#ifdef DOOR_TESTS
    ATF_TP_ADD_TC(tp, raw_return_cancel_revoke_drained);
#endif
    ATF_TP_ADD_TC(tp, raw_admission_rollback_and_full_queue);
    ATF_TP_ADD_TC(tp, raw_worker_exit_returns_reservation);
    ATF_TP_ADD_TC(tp, raw_return_cancel_revoke_completion_count);
    return (atf_no_error());
}
