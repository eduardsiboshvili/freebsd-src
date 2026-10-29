/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static void
server(void *cookie, char *data, size_t size, door_desc_t *desc, uint_t count)
{
    (void)cookie; (void)data; (void)size; (void)desc; (void)count;
    (void)door_return(NULL, 0, NULL, 0);
}

static int
make_door(void)
{
    int fd = door_create(server, NULL, DOOR_NO_DEPLETION_CB);
    ATF_REQUIRE(fd >= 0);
    return (fd);
}

static void
cleanup(int fd, door_shm_t *shm, int revoked)
{
    if (!revoked)
        ATF_REQUIRE(door_shm_destroy_handle(shm) == 0);

    ATF_REQUIRE(door_shm_unmap(shm) == 0);
    if (!revoked)
        ATF_REQUIRE(door_revoke(fd) == 0);

    ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(validation_and_lanes);
ATF_TC_BODY(validation_and_lanes, tc)
{
    door_shm_t shm;
    uint32_t value;
    int fd = make_door();
    (void)tc;

    ATF_REQUIRE(door_shm_pair_create(fd, 1, &shm) == -1);
    ATF_REQUIRE(errno == EINVAL);
    ATF_REQUIRE(door_shm_pair_create(fd, (size_t)getpagesize(), &shm) == 0);
    ATF_REQUIRE(door_shm_pair_load(&shm, 0, &value) == 0 && value == 0);
    ATF_REQUIRE(door_shm_pair_wait(&shm, 0, 0, 0) == -1 && errno == ETIMEDOUT);
    ATF_REQUIRE(door_shm_pair_notify(&shm, 1) == 0);
    ATF_REQUIRE(door_shm_pair_load(&shm, 0, &value) == 0 && value == 0);
    ATF_REQUIRE(door_shm_pair_load(&shm, 1, &value) == 0 && value == 1);
    ATF_REQUIRE(door_shm_pair_wait(&shm, 1, 0, 0) == 0);
    ATF_REQUIRE(door_shm_pair_wait(&shm, 2, 0, 0) == -1 && errno == EINVAL);
    ATF_REQUIRE(door_shm_pair_wait(&shm, 0, 0, 1) == -1 && errno == ETIMEDOUT);
    cleanup(fd, &shm, 0);
}

struct transfer {
    door_shm_t *shm;
    uint32_t *data, *ack;
    int error;
};

static int
await_value(door_shm_t *shm, unsigned lane, uint32_t *word, uint32_t target)
{
    uint32_t sequence;

    while (__atomic_load_n(word, __ATOMIC_ACQUIRE) != target) {
        if (door_shm_pair_load(shm, lane, &sequence) == -1)
            return (errno);

        if (__atomic_load_n(word, __ATOMIC_ACQUIRE) == target)
            break;

        if (door_shm_pair_wait(shm, lane, sequence, 2000000000ULL) == -1)
            return (errno);
    }

    return (0);
}

static void *
receiver(void *arg)
{
    struct transfer *f = arg;

    for (uint32_t i = 1; i <= 10000; i++) {
        f->error = await_value(f->shm, 0, f->data, i);
        if (f->error != 0)
            break;

        __atomic_store_n(f->ack, i, __ATOMIC_RELEASE);
        if (door_shm_pair_notify(f->shm, 1) == -1) {
            f->error = errno;
            break;
        }
    }

    return (NULL);
}

ATF_TC_WITHOUT_HEAD(publication_wait_race);
ATF_TC_BODY(publication_wait_race, tc)
{
    int fd = make_door(), error = 0;
    door_shm_t shm;
    pthread_t thread;
    struct transfer f;
    (void)tc;

    ATF_REQUIRE(door_shm_pair_create(fd, 2 * (size_t)getpagesize(), &shm) == 0);
    f = (struct transfer){.shm = &shm,
        .data = (uint32_t *)((uintptr_t)shm.dsh_addr + getpagesize()),
        .ack = (uint32_t *)((uintptr_t)shm.dsh_addr + getpagesize() + 64)};
    ATF_REQUIRE(pthread_create(&thread, NULL, receiver, &f) == 0);
    for (uint32_t i = 1; i <= 10000; i++) {
        __atomic_store_n(f.data, i, __ATOMIC_RELEASE);
        if (door_shm_pair_notify(&shm, 0) == -1) {
            error = errno;
            break;
        }

        error = await_value(&shm, 1, f.ack, i);
        if (error != 0)
            break;
    }

    /* Join is the last-access barrier before any mapping/fixture teardown. */
    ATF_REQUIRE(pthread_join(thread, NULL) == 0);
    ATF_REQUIRE_EQ(error, 0);
    ATF_REQUIRE_EQ(f.error, 0);
    cleanup(fd, &shm, 0);
}

struct waiting {
    door_shm_t shm;
    int error;
};

static void *
waiter(void *arg)
{
    struct waiting *f = arg;
    f->error = door_shm_pair_wait(&f->shm, 0, 0, 2000000000ULL) == -1 ? errno : 0;
    return (NULL);
}

static void
close_waiter(int revoke)
{
    int fd = make_door();
    struct waiting f = {0};
    pthread_t thread;
    door_shm_t shm;

    ATF_REQUIRE(door_shm_pair_create(fd, (size_t)getpagesize(), &shm) == 0);
    f.shm = shm; /* Stable handle snapshot; destroy edits the original handle. */
    ATF_REQUIRE(pthread_create(&thread, NULL, waiter, &f) == 0);
    if (revoke)
        ATF_REQUIRE(door_revoke(fd) == 0);
    else
        ATF_REQUIRE(door_shm_destroy_handle(&shm) == 0);

    ATF_REQUIRE(pthread_join(thread, NULL) == 0);
    ATF_REQUIRE_EQ(f.error, revoke ? EBADF : ENOENT);
    ATF_REQUIRE(door_shm_unmap(&shm) == 0);
    if (!revoke)
        ATF_REQUIRE(door_revoke(fd) == 0);

    ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(destroy_wait_boundary);
ATF_TC_BODY(destroy_wait_boundary, tc) { (void)tc; close_waiter(0); }
ATF_TC_WITHOUT_HEAD(revoke_wait_boundary);
ATF_TC_BODY(revoke_wait_boundary, tc) { (void)tc; close_waiter(1); }

ATF_TC_WITHOUT_HEAD(guessed_region_denied);
ATF_TC_BODY(guessed_region_denied, tc)
{
    int fd = make_door(), status;
    door_shm_t shm;
    pid_t child;
    (void)tc;

    ATF_REQUIRE(door_shm_pair_create(fd, (size_t)getpagesize(), &shm) == 0);
    child = fork();
    ATF_REQUIRE(child >= 0);
    if (child == 0) {
        struct door_ioc_shm_pair arg = {.disp_version = DOOR_ABI_VERSION,
            .disp_region = shm.dsh_region};
        /* Inherited mappings are explicit fork sharing, not new peer authority. */
        if (__syscall((quad_t)SYS_door, (long)DOOR_SC_SHM_PAIR_WAKE,
            (long)fd, (long)(uintptr_t)&arg, 0L, 0L, 0L) != -1 || errno != EPERM)
            _exit(1);

        _exit(0);
    }

    ATF_REQUIRE(waitpid(child, &status, 0) == child);
    ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    cleanup(fd, &shm, 0);
}

ATF_TC_WITHOUT_HEAD(creator_exit_invalidates_pair);
ATF_TC_BODY(creator_exit_invalidates_pair, tc)
{
    int fd = make_door(), to_parent[2], to_child[2], status;
    door_shm_id_t id;
    door_shm_t shm;
    pid_t child;
    char done = 'x';
    (void)tc;

    ATF_REQUIRE(pipe(to_parent) == 0 && pipe(to_child) == 0);
    child = fork();
    ATF_REQUIRE(child >= 0);
    if (child == 0) {
        if (door_shm_pair_create(fd, (size_t)getpagesize(), &shm) == -1 ||
            write(to_parent[1], &shm.dsh_region, sizeof(id)) != sizeof(id) ||
            read(to_child[0], &done, 1) != 1)
            _exit(1);

        _exit(0);
    }

    ATF_REQUIRE(read(to_parent[0], &id, sizeof(id)) == sizeof(id));
    ATF_REQUIRE(door_shm_pair_attach(fd, id, &shm) == 0);
    ATF_REQUIRE(write(to_child[1], &done, 1) == 1);
    ATF_REQUIRE(waitpid(child, &status, 0) == child);
    ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    ATF_REQUIRE(door_shm_pair_wait(&shm, 0, 0, 0) == -1 && errno == ENOENT);
    ATF_REQUIRE(door_shm_unmap(&shm) == 0);
    ATF_REQUIRE(door_revoke(fd) == 0);
    ATF_REQUIRE(close(fd) == 0);
    for (unsigned int i = 0; i < 2; i++) {
        close(to_parent[i]); close(to_child[i]);
    }
}

ATF_TC_WITHOUT_HEAD(variable_chain_reuse);
ATF_TC_BODY(variable_chain_reuse, tc)
{
    door_shm_pool_t *pool;
    door_shm_chain_t a, b, c, d, forged;
    struct iovec iov[DOOR_SHM_CHAIN_MAX_SEGMENTS];
    int fd = make_door();
    (void)tc;

    ATF_REQUIRE(door_shm_pool_create(fd, 1024, 8, &pool) == 0);
    ATF_REQUIRE(door_shm_pool_reserve(pool, 256, &a) == 0);
    ATF_REQUIRE(door_shm_pool_reserve(pool, 256, &b) == 0);
    ATF_REQUIRE(door_shm_pool_reserve(pool, 256, &c) == 0);
    ATF_REQUIRE(door_shm_pool_destroy(pool) == -1 && errno == EBUSY);
    ATF_REQUIRE(door_shm_pool_release(pool, &a) == 0);
    ATF_REQUIRE(door_shm_pool_release(pool, &c) == 0);
    ATF_REQUIRE(door_shm_pool_reserve(pool, 640, &d) == 0 && d.dsc_count == 2);
    ATF_REQUIRE(door_shm_chain_map(door_shm_pool_region(pool), &d, iov, 64) == 0);
    ATF_REQUIRE(iov[0].iov_len + iov[1].iov_len == 640);
    memset(iov[0].iov_base, 'A', iov[0].iov_len);
    memset(iov[1].iov_base, 'B', iov[1].iov_len);
    forged = d;
    forged.dsc_segments[0].dcs_offset = 0;
    ATF_REQUIRE(door_shm_chain_map(door_shm_pool_region(pool), &forged, iov, 64) == -1);
    ATF_REQUIRE(door_shm_pool_release(pool, &forged) == -1 && errno == ESTALE);
    ATF_REQUIRE(door_shm_pool_release(pool, &b) == 0);
    ATF_REQUIRE(door_shm_pool_release(pool, &d) == 0);
    ATF_REQUIRE(door_shm_pool_release(pool, &d) == -1 && errno == ESTALE);
    ATF_REQUIRE(door_shm_pool_reserve(pool, 1024, &a) == 0 && a.dsc_count == 1);
    ATF_REQUIRE(door_shm_chain_map(door_shm_pool_region(pool), &a, iov, 64) == 0);
    for (size_t i = 0; i < iov[0].iov_len; i++)
        ATF_REQUIRE(((unsigned char *)iov[0].iov_base)[i] == 0);

    ATF_REQUIRE(door_shm_pool_release(pool, &a) == 0);
    ATF_REQUIRE(door_shm_pool_destroy(pool) == 0);
    ATF_REQUIRE(door_revoke(fd) == 0);
    ATF_REQUIRE(close(fd) == 0);
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, validation_and_lanes);
    ATF_TP_ADD_TC(tp, publication_wait_race);
    ATF_TP_ADD_TC(tp, destroy_wait_boundary);
    ATF_TP_ADD_TC(tp, revoke_wait_boundary);
    ATF_TP_ADD_TC(tp, guessed_region_denied);
    ATF_TP_ADD_TC(tp, creator_exit_invalidates_pair);
    ATF_TP_ADD_TC(tp, variable_chain_reuse);
    return (atf_no_error());
}
