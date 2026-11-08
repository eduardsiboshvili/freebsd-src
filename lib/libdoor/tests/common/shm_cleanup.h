/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef DOOR_TEST_SHM_CLEANUP_H
#define DOOR_TEST_SHM_CLEANUP_H
#include <atf-c.h>
#include <door.h>
#include <unistd.h>

static inline void
test_shm_unmap_pair(door_shm_t *a, door_shm_t *b)
{
    /* Writable same-vmspace ATTACH may alias the creator's VA range.
     * Each handle still owns its own private descriptor. */
    if (a->dsh_addr == b->dsh_addr && a->dsh_size == b->dsh_size) {
        ATF_REQUIRE(a->dsh_fd != b->dsh_fd);
        ATF_REQUIRE(door_shm_unmap(a) == 0);
        if (b->dsh_fd >= 0)
            ATF_REQUIRE(close(b->dsh_fd) == 0);
        b->dsh_fd = -1;
        b->dsh_addr = NULL;
        b->dsh_size = 0;
    } else {
        ATF_REQUIRE(door_shm_unmap(a) == 0);
        ATF_REQUIRE(door_shm_unmap(b) == 0);
    }
}
#endif
