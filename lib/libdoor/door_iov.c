/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/uio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "libdoor_impl.h"

int
__door_iov_add(struct iovec **iovp, int *iovlenp, const char *name,
    const void *value, size_t len)
{
    struct iovec *iov;
    char *name_copy;
    void *value_copy;
    int n;

    if (iovp == NULL || iovlenp == NULL || name == NULL ||
        value == NULL || len == 0) {
        errno = EINVAL;
        return (-1);
    }

    n = *iovlenp;
    name_copy = strdup(name);
    if (name_copy == NULL)
        return (-1);

    value_copy = malloc(len);
    if (value_copy == NULL)
        goto fail;

    memcpy(value_copy, value, len);
    iov = realloc(*iovp, (size_t)(n + 2) * sizeof(*iov));
    if (iov == NULL)
        goto fail;

    iov[n].iov_base = name_copy;
    iov[n].iov_len = strlen(name_copy) + 1;
    iov[n + 1].iov_base = value_copy;
    iov[n + 1].iov_len = len;
    *iovp = iov;
    *iovlenp = n + 2;
    return (0);

fail:
    free(name_copy);
    free(value_copy);
    return (-1);
}

void
__door_iov_free(struct iovec *iov, int iovlen)
{
    int i;

    for (i = 0; i < iovlen; i++)
        free(iov[i].iov_base);

    free(iov);
}
