/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/uio.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <door.h>

#define POOL_ALIGN 64U
#define POOL_MAX_LEASES 4096U
struct extent { uint64_t offset, size; };
struct lease { door_shm_chain_t chain; uint_t next_free; };
struct door_shm_pool {
    door_shm_t shm;
    pthread_mutex_t lock;
    pid_t owner;
    uint_t max_leases, active, free_lease;
    uint64_t next_lease;
    size_t free_count, free_capacity;
    struct extent *free;
    struct lease *leases;
};

_Static_assert(sizeof(door_shm_chain_t) == 1064, "chain wire layout");
_Static_assert(offsetof(door_shm_chain_t, dsc_segments) == 40, "chain wire offset");

static int
pool_error(int error)
{
    errno = error;
    return (-1);
}

static int
pool_owner(const door_shm_pool_t *pool)
{
    if (pool == NULL)
        return (pool_error(EINVAL));

    /* A copied pthread mutex or duplicated allocator after fork is unusable. */
    if (pool->owner != getpid())
        return (pool_error(EPERM));

    return (0);
}

int
door_shm_pool_create(int fd, size_t bytes, uint_t max_leases,
    door_shm_pool_t **result)
{
    door_shm_pool_t *pool;
    long page;
    size_t capacity;
    int error;

    if (result == NULL || bytes == 0 || max_leases == 0 ||
        max_leases > POOL_MAX_LEASES)
        return (pool_error(EINVAL));

    *result = NULL;
    page = sysconf(_SC_PAGESIZE);
    if (page < (long)DOOR_SHM_PAIR_CONTROL_SIZE)
        return (pool_error(EINVAL));

    if (bytes > SIZE_MAX - (POOL_ALIGN - 1) ||
        (capacity = (bytes + POOL_ALIGN - 1) & ~(size_t)(POOL_ALIGN - 1)) >
        SIZE_MAX - (size_t)page)
        return (pool_error(EOVERFLOW));

    pool = calloc(1, sizeof(*pool));
    if (pool == NULL)
        return (-1);

    pool->free_capacity = (size_t)max_leases * DOOR_SHM_CHAIN_MAX_SEGMENTS + 1;
    pool->free = calloc(pool->free_capacity, sizeof(*pool->free));
    pool->leases = calloc(max_leases, sizeof(*pool->leases));
    if (pool->free == NULL || pool->leases == NULL) {
        free(pool->free);
        free(pool->leases);
        free(pool);
        return (pool_error(ENOMEM));
    }

    error = pthread_mutex_init(&pool->lock, NULL);
    if (error != 0)
        goto fail;

    if (door_shm_pair_create(fd, capacity + (size_t)page, &pool->shm) == -1) {
        error = errno;
        pthread_mutex_destroy(&pool->lock);
        goto fail;
    }

    pool->owner = getpid();
    pool->max_leases = max_leases;
    pool->next_lease = 1;
    for (uint_t i = 0; i < max_leases; i++)
        pool->leases[i].next_free = i + 1;
    pool->free_count = 1;
    pool->free[0].offset = (uint64_t)page;
    pool->free[0].size = capacity;
    *result = pool;
    return (0);

fail:
    free(pool->free);
    free(pool->leases);
    free(pool);
    return (pool_error(error));
}

const door_shm_t *
door_shm_pool_region(const door_shm_pool_t *pool)
{
    if (pool_owner(pool) == -1)
        return (NULL);

    return (&pool->shm);
}

int
door_shm_pool_reserve(door_shm_pool_t *pool, size_t bytes, door_shm_chain_t *out)
{
    door_shm_chain_t chain = {0};
    size_t rounded, remaining, logical, count, index;
    struct lease *lease;
    int error;

    if (out == NULL || bytes == 0)
        return (pool_error(EINVAL));

    if (pool_owner(pool) == -1)
        return (-1);

    if (bytes > SIZE_MAX - (POOL_ALIGN - 1))
        return (pool_error(EOVERFLOW));

    rounded = (bytes + POOL_ALIGN - 1) & ~(size_t)(POOL_ALIGN - 1);
    pthread_mutex_lock(&pool->lock);
    error = EAGAIN;
    if (pool->active == pool->max_leases)
        goto fail;

    if (pool->next_lease > (UINT64_MAX >> 12)) {
        error = EOVERFLOW;
        goto fail;
    }

    remaining = rounded;
    logical = bytes;
    count = 0;
    /* Plan first; a fragmented/too-large request must not consume extents. */
    for (index = 0; index < pool->free_count && remaining != 0; index++) {
        size_t take = remaining < pool->free[index].size ?
            remaining : (size_t)pool->free[index].size;
        if (count == DOOR_SHM_CHAIN_MAX_SEGMENTS)
            goto fail;

        chain.dsc_segments[count].dcs_offset = pool->free[index].offset;
        chain.dsc_segments[count].dcs_length = logical < take ? logical : take;
        logical -= (size_t)chain.dsc_segments[count].dcs_length;
        remaining -= take;
        count++;
    }

    if (remaining != 0)
        goto fail;

    index = pool->free_lease;
    lease = &pool->leases[index];
    pool->free_lease = lease->next_free;
    chain.dsc_region = pool->shm.dsh_region;
    chain.dsc_uniquifier = pool->shm.dsh_uniquifier;
    chain.dsc_lease = (pool->next_lease++ << 12) | index;
    chain.dsc_length = bytes;
    chain.dsc_count = (uint32_t)count;
    size_t last_take = (size_t)((chain.dsc_segments[count-1].dcs_length +
        POOL_ALIGN - 1) & ~(uint64_t)(POOL_ALIGN - 1));
    pool->free[count-1].offset += last_take;
    pool->free[count-1].size -= last_take;
    size_t removed = pool->free[count-1].size == 0 ? count : count-1;
    memmove(pool->free, pool->free + removed,
        (pool->free_count - removed) * sizeof(*pool->free));
    pool->free_count -= removed;
    lease->chain = chain;
    pool->active++;
    *out = chain;
    pthread_mutex_unlock(&pool->lock);
    return (0);

fail:
    pthread_mutex_unlock(&pool->lock);
    return (pool_error(error));
}

/* Local allocator metadata is never stored in peer-writable SHM. */
static void
pool_insert(door_shm_pool_t *pool, uint64_t offset, uint64_t size)
{
    size_t i;

    for (i = 0; i < pool->free_count && pool->free[i].offset < offset; i++)
        ;

    memmove(pool->free + i + 1, pool->free + i,
        (pool->free_count - i) * sizeof(*pool->free));
    pool->free[i] = (struct extent){offset, size};
    pool->free_count++;
    if (i > 0 && pool->free[i-1].offset + pool->free[i-1].size == offset) {
        pool->free[i-1].size += size;
        memmove(pool->free + i, pool->free + i + 1,
            (pool->free_count - i - 1) * sizeof(*pool->free));
        pool->free_count--;
        i--;
    }

    if (i + 1 < pool->free_count &&
        pool->free[i].offset + pool->free[i].size == pool->free[i+1].offset) {
        pool->free[i].size += pool->free[i+1].size;
        memmove(pool->free + i + 1, pool->free + i + 2,
            (pool->free_count - i - 2) * sizeof(*pool->free));
        pool->free_count--;
    }
}

int
door_shm_pool_release(door_shm_pool_t *pool, const door_shm_chain_t *input)
{
    door_shm_chain_t chain;
    struct lease *lease = NULL;
    uint_t i;

    if (input == NULL)
        return (pool_error(EINVAL));

    if (pool_owner(pool) == -1)
        return (-1);

    chain = *input;
    pthread_mutex_lock(&pool->lock);
    uint_t index = (uint_t)(chain.dsc_lease & 4095U);
    if (chain.dsc_lease != 0 && index < pool->max_leases &&
        pool->leases[index].chain.dsc_lease == chain.dsc_lease)
        lease = &pool->leases[index];

    if (lease == NULL || memcmp(&chain, &lease->chain, sizeof(chain)) != 0) {
        pthread_mutex_unlock(&pool->lock);
        return (pool_error(ESTALE));
    }

    /* Caller must have obtained the consumer's final-access acknowledgement. */
    for (i = 0; i < chain.dsc_count; i++) {
        uint64_t offset = chain.dsc_segments[i].dcs_offset;
        uint64_t size = (chain.dsc_segments[i].dcs_length + POOL_ALIGN - 1) &
            ~(uint64_t)(POOL_ALIGN - 1);
        memset((char *)pool->shm.dsh_addr + offset, 0, (size_t)size);
        pool_insert(pool, offset, size);
    }

    lease->chain.dsc_lease = 0;
    lease->next_free = pool->free_lease;
    pool->free_lease = index;
    pool->active--;
    pthread_mutex_unlock(&pool->lock);
    return (0);
}

int
door_shm_chain_map(const door_shm_t *shm, const door_shm_chain_t *input,
    struct iovec *iov, uint_t capacity)
{
    door_shm_chain_t chain;
    uint64_t total = 0;
    long page;
    uint_t i, j;

    if (shm == NULL || input == NULL || iov == NULL || shm->dsh_addr == NULL ||
        (shm->dsh_flags & DOOR_SHM_PAIR) == 0)
        return (pool_error(EINVAL));

    /* Snapshot the header first and bound the following descriptor copy. */
    memcpy(&chain, input, offsetof(door_shm_chain_t, dsc_segments));
    if (chain.dsc_count == 0 || chain.dsc_count > DOOR_SHM_CHAIN_MAX_SEGMENTS)
        return (pool_error(EINVAL));

    memcpy(chain.dsc_segments, input->dsc_segments,
        chain.dsc_count * sizeof(chain.dsc_segments[0]));
    page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || chain.dsc_reserved != 0 || chain.dsc_lease == 0 ||
        chain.dsc_region != shm->dsh_region ||
        chain.dsc_uniquifier != shm->dsh_uniquifier || chain.dsc_count == 0 ||
        chain.dsc_count > DOOR_SHM_CHAIN_MAX_SEGMENTS || chain.dsc_count > capacity)
        return (pool_error(EINVAL));

    for (i = 0; i < chain.dsc_count; i++) {
        uint64_t offset = chain.dsc_segments[i].dcs_offset;
        uint64_t size = chain.dsc_segments[i].dcs_length;
        if (offset < (uint64_t)page || (offset & (POOL_ALIGN-1)) != 0 ||
            size == 0 || offset > shm->dsh_size || size > shm->dsh_size-offset ||
            total > UINT64_MAX-size)
            return (pool_error(EINVAL));

        for (j = 0; j < i; j++) {
            uint64_t other = chain.dsc_segments[j].dcs_offset;
            if (offset < other + chain.dsc_segments[j].dcs_length &&
                other < offset + size)
                return (pool_error(EINVAL));
        }

        total += size;
    }

    if (total != chain.dsc_length)
        return (pool_error(EINVAL));

    for (i = 0; i < chain.dsc_count; i++) {
        iov[i].iov_base = (char *)shm->dsh_addr + chain.dsc_segments[i].dcs_offset;
        iov[i].iov_len = (size_t)chain.dsc_segments[i].dcs_length;
    }

    return (0);
}

int
door_shm_pool_destroy(door_shm_pool_t *pool)
{
    int error;

    if (pool_owner(pool) == -1)
        return (-1);

    pthread_mutex_lock(&pool->lock);
    if (pool->active != 0) {
        pthread_mutex_unlock(&pool->lock);
        return (pool_error(EBUSY));
    }

    if (door_shm_destroy_handle(&pool->shm) == -1 && errno != ENOENT && errno != EBADF) {
        error = errno;
        pthread_mutex_unlock(&pool->lock);
        return (pool_error(error));
    }

    pthread_mutex_unlock(&pool->lock);
    if (door_shm_unmap(&pool->shm) == -1)
        return (-1);

    pthread_mutex_destroy(&pool->lock);
    free(pool->leases);
    free(pool->free);
    free(pool);
    return (0);
}
