/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include "libdoor_impl.h"

_Static_assert(__atomic_always_lock_free(4, 0),
    "pair event words require process-shared lock-free 32-bit atomics");

static int
pair_word(const door_shm_t *shm, uint_t lane, uint32_t **word)
{
    if (shm == NULL || shm->dsh_addr == NULL || shm->dsh_fd < 0 ||
        shm->dsh_region == 0 || shm->dsh_uniquifier == 0 ||
        lane >= DOOR_SHM_PAIR_LANES ||
        (shm->dsh_flags & DOOR_SHM_PAIR) == 0 ||
        shm->dsh_size < DOOR_SHM_PAIR_CONTROL_SIZE ||
        ((uintptr_t)shm->dsh_addr & 3) != 0) {
        errno = EINVAL;
        return (-1);
    }

    *word = (uint32_t *)((uintptr_t)shm->dsh_addr +
        (uintptr_t)lane * DOOR_SHM_PAIR_STRIDE);
    return (0);
}

int
door_shm_pair_create(int fd, size_t size, door_shm_t *shm)
{
    return (door_shm_create(fd, size, DOOR_SHM_RW | DOOR_SHM_PAIR, shm));
}

int
door_shm_pair_attach(int fd, door_shm_id_t region, door_shm_t *shm)
{
    return (door_shm_attach(fd, region, DOOR_SHM_RW | DOOR_SHM_PAIR, shm));
}

int
door_shm_pair_load(const door_shm_t *shm, uint_t lane, uint32_t *value)
{
    uint32_t *word;

    if (value == NULL) {
        errno = EINVAL;
        return (-1);
    }

    if (pair_word(shm, lane, &word) == -1)
        return (-1);

    *value = __atomic_load_n(word, __ATOMIC_ACQUIRE);
    return (0);
}

int
door_shm_pair_notify(const door_shm_t *shm, uint_t lane)
{
    struct door_ioc_shm_pair arg = {0};
    uint32_t *word;

    if (pair_word(shm, lane, &word) == -1)
        return (-1);

    if ((shm->dsh_flags & DOOR_SHM_WRITE) == 0) {
        errno = EACCES;
        return (-1);
    }

    /* Publication precedes the kernel wake. Do not reset or undo this on error. */
    (void)__atomic_fetch_add(word, 1, __ATOMIC_RELEASE);
    arg.disp_version = DOOR_ABI_VERSION;
    arg.disp_region = shm->dsh_region;
    arg.disp_lane = lane;
    return (__door_syscall(DOOR_SC_SHM_PAIR_WAKE, shm->dsh_fd,
        (long)(uintptr_t)&arg, 0, 0, 0));
}

int
door_shm_pair_wait(const door_shm_t *shm, uint_t lane, uint32_t expected,
    uint64_t timeout_ns)
{
    struct door_ioc_shm_pair arg = {0};
    uint32_t *word;

    if (pair_word(shm, lane, &word) == -1)
        return (-1);

    if (timeout_ns != DOOR_SHM_PAIR_FOREVER &&
        timeout_ns > DOOR_SHM_PAIR_TIMEOUT_MAX_NS) {
        errno = EINVAL;
        return (-1);
    }

    /* Memory-only mismatch succeeds even after revoke; no kernel state read. */
    if (__atomic_load_n(word, __ATOMIC_ACQUIRE) != expected)
        return (0);

    arg.disp_version = DOOR_ABI_VERSION;
    arg.disp_region = shm->dsh_region;
    arg.disp_lane = lane;
    arg.disp_expected = expected;
    arg.disp_timeout_ns = timeout_ns;
    return (__door_syscall(DOOR_SC_SHM_PAIR_WAIT, shm->dsh_fd,
        (long)(uintptr_t)&arg, 0, 0, 0));
}
