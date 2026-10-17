/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/syscall.h>

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include "libdoor_impl.h"

int
door_oneway(int fd, const void *data, size_t size)
{
    if (fd < 0 || (size != 0 && data == NULL)) {
        errno = EINVAL;
        return (-1);
    }

    return ((int)__door_syscall(
        DOOR_SC_ONEWAY, fd, (long)(uintptr_t)data, (long)size, 0, 0));
}
