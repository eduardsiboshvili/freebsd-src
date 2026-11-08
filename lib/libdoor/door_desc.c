/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include "libdoor_impl.h"

int
__door_desc_export(const door_desc_t *src, uint_t count,
    struct door_kdesc **outp, uint32_t *countp)
{
    struct door_kdesc *out;
    door_desc_t *copy;
    size_t bytes;
    uint_t i;

    if (outp == NULL || countp == NULL) {
        errno = EINVAL;
        return (-1);
    }

    *outp = NULL;
    *countp = 0;
    if (count == 0)
        return (0);

    if (src == NULL || count > UINT32_MAX) {
        errno = EINVAL;
        return (-1);
    }

    if ((size_t)count > SIZE_MAX / sizeof(*copy)) {
        errno = EOVERFLOW;
        return (-1);
    }

    bytes = (size_t)count * sizeof(*copy);
    copy = malloc(bytes);
    if (copy == NULL)
        return (-1);

    if (__door_safe_copyin(copy, src, bytes) == -1) {
        free(copy);
        return (-1);
    }

    out = calloc(count, sizeof(*out));
    if (out == NULL) {
        free(copy);
        return (-1);
    }

    for (i = 0; i < count; i++) {
        if ((copy[i].d_attributes & DOOR_DESCRIPTOR) == 0 ||
            copy[i].d_descriptor < 0) {
            free(copy);
            free(out);
            errno = EINVAL;
            return (-1);
        }

        out[i].dd_fd = copy[i].d_descriptor;
        out[i].dd_flags =
            (copy[i].d_attributes & DOOR_RELEASE) != 0 ?
            DOOR_DESC_F_MOVE : 0;
    }

    free(copy);
    *outp = out;
    *countp = (uint32_t)count;
    return (0);
}

void
__door_desc_import(door_desc_t *dst, const struct door_kdesc *src,
    uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        /* DOOR_RELEASE is an instruction to the sender, not a property
         * of the descriptor installed in the receiving process.
         */
        dst[i].d_attributes = DOOR_DESCRIPTOR;
        dst[i].d_descriptor = src[i].dd_fd;
        dst[i].d_id = 0;
    }
}
