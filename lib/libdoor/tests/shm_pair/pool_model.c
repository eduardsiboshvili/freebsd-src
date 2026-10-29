/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* Standalone allocator check. Uses the real allocator, an mmap setup double. */
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <door.h>
#include "../../door_shm_pool.c"

int
door_shm_pair_create(int fd, size_t size, door_shm_t *shm)
{
    static uint64_t next_id;
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_SHARED, -1, 0);
    if (p == MAP_FAILED)
        return (-1);

    *shm = (door_shm_t){.dsh_addr = p, .dsh_size = size,
        .dsh_region = ++next_id, .dsh_fd = fd, .dsh_uniquifier = 1,
        .dsh_flags = DOOR_SHM_RW | DOOR_SHM_PAIR};
    return (0);
}

int
door_shm_destroy_handle(door_shm_t *shm)
{
    shm->dsh_region = 0;
    return (0);
}

int
door_shm_unmap(door_shm_t *shm)
{
    return (munmap(shm->dsh_addr, shm->dsh_size));
}

struct stress { door_shm_pool_t *pool; unsigned int index; };
static void *
stress(void *arg)
{
    struct stress *s = arg;
    for (unsigned int n = 0; n < 10000; n++) {
        door_shm_chain_t chain;
        struct iovec v[64];
        size_t bytes = 1 + ((n * 137 + s->index * 59) % 4096);
        while (door_shm_pool_reserve(s->pool, bytes, &chain) == -1) {
            assert(errno == EAGAIN);
            sched_yield();
        }

        assert(door_shm_chain_map(door_shm_pool_region(s->pool), &chain, v, 64) == 0);
        for (unsigned int i = 0; i < chain.dsc_count; i++) {
            memset(v[i].iov_base, (int)(s->index + 1), v[i].iov_len);
        }

        for (unsigned int i = 0; i < chain.dsc_count; i++) {
            const unsigned char *p = v[i].iov_base;
            for (size_t j = 0; j < v[i].iov_len; j++)
                assert(p[j] == s->index + 1);
        }

        assert(door_shm_pool_release(s->pool, &chain) == 0);
    }

    return (NULL);
}

int
main(void)
{
    door_shm_pool_t *pool;
    door_shm_chain_t a, b, c, d, bad;
    struct iovec v[64];

    assert(door_shm_pool_create(1, 1024, 8, &pool) == 0);
    assert(door_shm_pool_reserve(pool, SIZE_MAX, &a) == -1 && errno == EOVERFLOW);
    assert(door_shm_pool_reserve(pool, 256, &a) == 0);
    assert(door_shm_pool_reserve(pool, 256, &b) == 0);
    assert(door_shm_pool_reserve(pool, 256, &c) == 0);
    assert(door_shm_pool_destroy(pool) == -1 && errno == EBUSY);
    assert(door_shm_pool_release(pool, &a) == 0);
    assert(door_shm_pool_release(pool, &c) == 0);
    assert(door_shm_pool_reserve(pool, 640, &d) == 0 && d.dsc_count == 2);
    assert(door_shm_chain_map(door_shm_pool_region(pool), &d, v, 64) == 0);
    assert(v[0].iov_len + v[1].iov_len == 640);
    bad = d;
    bad.dsc_segments[0].dcs_offset = 0;
    assert(door_shm_chain_map(door_shm_pool_region(pool), &bad, v, 64) == -1);
    bad = d;
    bad.dsc_segments[1].dcs_offset = bad.dsc_segments[0].dcs_offset;
    assert(door_shm_chain_map(door_shm_pool_region(pool), &bad, v, 64) == -1);
    assert(door_shm_pool_release(pool, &bad) == -1 && errno == ESTALE);
    assert(door_shm_pool_release(pool, &b) == 0);
    assert(door_shm_pool_release(pool, &d) == 0);
    assert(door_shm_pool_release(pool, &d) == -1 && errno == ESTALE);
    assert(door_shm_pool_reserve(pool, 1024, &a) == 0 && a.dsc_count == 1);
    assert(door_shm_chain_map(door_shm_pool_region(pool), &a, v, 64) == 0);
    for (size_t i = 0; i < 1024; i++)
        assert(((unsigned char *)v[0].iov_base)[i] == 0);

    assert(door_shm_pool_release(pool, &a) == 0);
    bad = a;
    assert(door_shm_pool_reserve(pool, 64, &a) == 0);
    assert((bad.dsc_lease & 4095U) == (a.dsc_lease & 4095U));
    assert(bad.dsc_lease != a.dsc_lease);
    assert(door_shm_pool_release(pool, &bad) == -1 && errno == ESTALE);
    bad = a;
    bad.dsc_segments[63].dcs_length = 1;
    assert(door_shm_pool_release(pool, &bad) == -1 && errno == ESTALE);
    assert(door_shm_pool_release(pool, &a) == 0);
    pool->next_lease = (UINT64_MAX >> 12) + 1;
    assert(door_shm_pool_reserve(pool, 64, &a) == -1 && errno == EOVERFLOW);
    assert(door_shm_pool_destroy(pool) == 0);
    puts("PASS: indexed generations, stale reuse, unused descriptor tampering, exhaustion");
    puts("PASS: fragmentation, coalescing, stale/forged leases, bounds, zero on release");

    assert(door_shm_pool_create(1, 130 * 64, 140, &pool) == 0);
    door_shm_chain_t blocks[130];
    for (unsigned int i = 0; i < 130; i++)
        assert(door_shm_pool_reserve(pool, 64, &blocks[i]) == 0);

    for (unsigned int i = 0; i < 130; i += 2)
        assert(door_shm_pool_release(pool, &blocks[i]) == 0);

    assert(door_shm_pool_reserve(pool, 65 * 64, &a) == -1 && errno == EAGAIN);
    assert(door_shm_pool_reserve(pool, 64 * 64, &a) == 0 && a.dsc_count == 64);
    assert(door_shm_pool_release(pool, &a) == 0);
    for (unsigned int i = 1; i < 130; i += 2)
        assert(door_shm_pool_release(pool, &blocks[i]) == 0);

    assert(door_shm_pool_destroy(pool) == 0);
    puts("PASS: 64-segment boundary and transactional allocation failure");

    assert(door_shm_pool_create(1, 65536, 64, &pool) == 0);
    pthread_t threads[4];
    struct stress states[4];
    for (unsigned int i = 0; i < 4; i++) {
        states[i] = (struct stress){pool, i};
        assert(pthread_create(&threads[i], NULL, stress, &states[i]) == 0);
    }

    for (unsigned int i = 0; i < 4; i++)
        assert(pthread_join(threads[i], NULL) == 0);

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0)
        _exit(door_shm_pool_reserve(pool, 1, &a) == -1 && errno == EPERM ? 0 : 1);

    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(door_shm_pool_reserve(pool, 65536, &a) == 0 && a.dsc_count == 1);
    assert(door_shm_pool_release(pool, &a) == 0);
    assert(door_shm_pool_destroy(pool) == 0);
    puts("PASS: concurrent variable-size reuse, fork ownership, full-capacity recovery");
    return (0);
}
