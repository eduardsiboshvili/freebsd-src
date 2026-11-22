/*-
 * Copyright (c) 2026 Eduard Siboshvili
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "door_raw.h"

#include <door.h>
#include <pthread.h>
#include <stdint.h>

#define TARGETS 4
#define PER_TARGET 128

ATF_TC(pending_ids_cancel_reuse_and_revoke);
ATF_TC_HEAD(pending_ids_cancel_reuse_and_revoke, tc)
{
    atf_tc_set_md_var(tc, "timeout", "30");
}

ATF_TC_BODY(pending_ids_cancel_reuse_and_revoke, tc)
{
    int request, completion[TARGETS], replacement;
    uint64_t id;
    unsigned i, j;

    (void)tc;
    request = raw_create(0);
    for (i = 0; i < TARGETS; i++)
        completion[i] = raw_create(DOOR_ONEWAY);

    /* 512 pending IDs exercise bucket collisions and independent targets. */
    for (i = 0; i < TARGETS; i++) {
        for (j = 0; j < PER_TARGET; j++) {
            id = 1 + i * PER_TARGET + j;
            ATF_REQUIRE(raw_submit(request, completion[i], id, NULL, 0) == 0);
        }
    }

    for (i = 0; i < TARGETS; i++) {
        for (j = 0; j < PER_TARGET; j++) {
            id = 1 + i * PER_TARGET + j;
            errno = 0;
            ATF_REQUIRE(raw_submit(request, completion[(i + 1) % TARGETS],
                id, NULL, 0) == -1);
            ATF_REQUIRE_EQ(errno, EEXIST);
        }
    }

    /* Pending cancellation releases ID membership before completion drain. */
    for (i = 0; i < TARGETS; i++) {
        for (j = 0; j < PER_TARGET; j++) {
            id = 1 + i * PER_TARGET + j;
            ATF_REQUIRE(raw_op(DOOR_SC_ASYNC_CANCEL, request,
                completion[i], id, 0, 0) == 0);
        }
        raw_wait_pending(completion[i], PER_TARGET);
    }

    for (i = 0; i < TARGETS; i++) {
        for (j = 0; j < PER_TARGET; j++) {
            id = 1 + i * PER_TARGET + j;
            ATF_REQUIRE(raw_submit(request, completion[i], id, NULL, 0) == 0);
        }
    }

    ATF_REQUIRE(door_revoke(request) == 0);
    for (i = 0; i < TARGETS; i++) {
        raw_wait_pending(completion[i], 2 * PER_TARGET);
        ATF_REQUIRE(door_revoke(completion[i]) == 0);
        ATF_REQUIRE(close(completion[i]) == 0);
    }
    ATF_REQUIRE(close(request) == 0);

    /* A replacement Door starts with an independent, empty ID index. */
    replacement = raw_create(0);
    completion[0] = raw_create(DOOR_ONEWAY);
    ATF_REQUIRE(raw_submit(replacement, completion[0], 1, NULL, 0) == 0);
    ATF_REQUIRE(door_revoke(replacement) == 0);
    ATF_REQUIRE(door_revoke(completion[0]) == 0);
    ATF_REQUIRE(close(replacement) == 0);
    ATF_REQUIRE(close(completion[0]) == 0);
}

ATF_TC_WITHOUT_HEAD(active_cancel_reserves_id_until_worker_exit);
ATF_TC_BODY(active_cancel_reserves_id_until_worker_exit, tc)
{
    struct door_ioc_return_shm receive;
    int request, completion;
    uint64_t id = UINT64_MAX;

    (void)tc;
    request = raw_create(0);
    completion = raw_create(DOOR_ONEWAY);
    ATF_REQUIRE(raw_submit(request, completion, id, NULL, 0) == 0);
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, request, 0, 0, 0, 0) == 0);
    raw_receive_init(&receive, NULL, 0);
    ATF_REQUIRE(raw_return_shm(&receive) == 0);
    ATF_REQUIRE_EQ(receive.dirs_return.dir_call_id, id);

    errno = 0;
    ATF_REQUIRE(raw_submit(request, completion, id, NULL, 0) == -1);
    ATF_REQUIRE_EQ(errno, EEXIST);
    ATF_REQUIRE(raw_op(DOOR_SC_ASYNC_CANCEL, request, completion, id, 0, 0) == 0);

    /* Cancellation alone does not detach an active server assignment. */
    errno = 0;
    ATF_REQUIRE(raw_submit(request, completion, id, NULL, 0) == -1);
    ATF_REQUIRE_EQ(errno, EEXIST);
    ATF_REQUIRE(raw_op(DOOR_SC_WORKER_EXIT, 0, 0, 0, 0, 0) == 0);
    ATF_REQUIRE(raw_submit(request, completion, id, NULL, 0) == 0);
    ATF_REQUIRE(door_revoke(request) == 0);
    raw_wait_pending(completion, 2);
    ATF_REQUIRE(door_revoke(completion) == 0);
    ATF_REQUIRE(close(request) == 0);
    ATF_REQUIRE(close(completion) == 0);
}

struct submit_race {
    pthread_barrier_t *barrier;
    int request, completion;
    int result, error;
    uint64_t id;
};

static void *
submit_same_id(void *cookie)
{
    struct submit_race *race = cookie;

    (void)pthread_barrier_wait(race->barrier);
    race->result = (int)raw_submit(race->request, race->completion,
        race->id, NULL, 0);
    race->error = errno;
    return (NULL);
}

ATF_TC(concurrent_duplicate_admission);
ATF_TC_HEAD(concurrent_duplicate_admission, tc)
{
    atf_tc_set_md_var(tc, "timeout", "30");
}

ATF_TC_BODY(concurrent_duplicate_admission, tc)
{
    struct submit_race races[8];
    pthread_t threads[8];
    pthread_barrier_t barrier;
    int request, completion;
    unsigned round, i, accepted;

    (void)tc;
    request = raw_create(0);
    completion = raw_create(DOOR_ONEWAY);
    ATF_REQUIRE(pthread_barrier_init(&barrier, NULL, 8) == 0);
    for (round = 0; round < 32; round++) {
        for (i = 0; i < 8; i++) {
            races[i] = (struct submit_race){
                .barrier = &barrier, .request = request,
                .completion = completion, .id = 42
            };
            ATF_REQUIRE(pthread_create(&threads[i], NULL,
                submit_same_id, &races[i]) == 0);
        }

        accepted = 0;
        for (i = 0; i < 8; i++) {
            ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);
            if (races[i].result == 0)
                accepted++;
            else {
                ATF_REQUIRE_EQ(races[i].result, -1);
                ATF_REQUIRE_EQ(races[i].error, EEXIST);
            }
        }
        ATF_REQUIRE_EQ(accepted, 1);
        ATF_REQUIRE(raw_op(DOOR_SC_ASYNC_CANCEL, request,
            completion, 42, 0, 0) == 0);
        raw_wait_pending(completion, round + 1);
    }

    ATF_REQUIRE(pthread_barrier_destroy(&barrier) == 0);
    ATF_REQUIRE(door_revoke(request) == 0);
    ATF_REQUIRE(door_revoke(completion) == 0);
    ATF_REQUIRE(close(request) == 0);
    ATF_REQUIRE(close(completion) == 0);
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, pending_ids_cancel_reuse_and_revoke);
    ATF_TP_ADD_TC(tp, active_cancel_reserves_id_until_worker_exit);
    ATF_TP_ADD_TC(tp, concurrent_duplicate_admission);
    return (atf_no_error());
}
