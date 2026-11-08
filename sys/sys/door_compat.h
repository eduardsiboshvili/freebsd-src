/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SYS_DOOR_COMPAT_H_
#define _SYS_DOOR_COMPAT_H_
#include <sys/door_core.h>
#include <sys/errno.h>
#include <sys/stdint.h>

struct door_compat_args {
    uint32_t op;
    int64_t arg[5];
};

/* maxuser is the exclusive upper boundary of the caller's vm_map. */
static __inline int
door_compat_range(uint64_t ptr, uint64_t size, uint64_t maxuser)
{
    if (size > UINT32_MAX)
        return (EOVERFLOW);
    if (ptr > UINT32_MAX)
        return (EFAULT);
    if (size == 0)
        return (0);
    if (ptr == 0 || ptr >= maxuser || size > maxuser - ptr ||
        size > (1ULL << 32) - ptr)
        return (EFAULT);
    return (0);
}

/* Signed fds and unsigned addresses/flags must not share sign extension. */
static __inline int
door_compat_decode(uint32_t op, const uint32_t words[5],
    struct door_compat_args *out)
{
    unsigned int i;

    out->op = op;
    for (i = 0; i < 5; i++)
        out->arg[i] = 0;
    switch (op) {
    case DOOR_SC_FAST_CALL:
    case DOOR_SC_FAST_RETURN:
    case DOOR_SC_EMPTY_CALL:
    case DOOR_SC_EMPTY_RETURN:
    case DOOR_SC_FAST_CALL_MAPPED:
    case DOOR_SC_EMPTY_CALL_MAPPED:
        /* register results and scalar RETURN IDs require 64-bit registers. */
        return (ENOSYS);
    case DOOR_SC_CREATE:
        out->arg[0] = words[0];
        out->arg[1] = words[1];
        out->arg[2] = words[2];
        break;
    case DOOR_SC_ONEWAY:
    case DOOR_SC_ASYNC_CANCEL:
        out->arg[0] = (int32_t)words[0];
        out->arg[1] = op == DOOR_SC_ASYNC_CANCEL ?
            (int64_t)(int32_t)words[1] : (int64_t)words[1];
        out->arg[2] = words[2];
        break;
    case DOOR_SC_RETURN:
    case DOOR_SC_CRED:
        out->arg[0] = words[0];
        break;
    case DOOR_SC_CALL:
    case DOOR_SC_INFO:
    case DOOR_SC_CANCEL:
    case DOOR_SC_GETPARAM:
    case DOOR_SC_SETPARAM:
    case DOOR_SC_SHM_CREATE:
    case DOOR_SC_SHM_ATTACH:
    case DOOR_SC_CALL_SHM:
    case DOOR_SC_SHM_DESTROY:
    case DOOR_SC_ASYNC_CALL:
    case DOOR_SC_ASYNC_CANCEL_FULL:
    case DOOR_SC_SHM_VIEW_PUBLISH:
    case DOOR_SC_SHM_VIEW_ATTACH:
    case DOOR_SC_SHM_VIEW_QUERY:
    case DOOR_SC_SHM_VIEW_RELEASE:
    case DOOR_SC_SHM_PAIR_WAIT:
    case DOOR_SC_SHM_PAIR_WAKE:
    case DOOR_SC_SHM_VIEW_DESTROY:
        out->arg[0] = (int32_t)words[0];
        out->arg[1] = words[1];
        break;
    case DOOR_SC_REVOKE:
    case DOOR_SC_BIND:
        out->arg[0] = (int32_t)words[0];
        break;
    case DOOR_SC_UNBIND:
    case DOOR_SC_WORKER_EXIT:
        break;
    default:
        return (EINVAL);
    }
    return (0);
}
#endif
