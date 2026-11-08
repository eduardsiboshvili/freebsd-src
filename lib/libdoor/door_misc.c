/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "libdoor_impl.h"

static int
door_param_to_kernel(int param, int32_t *kernel_param)
{
    if (kernel_param == NULL) {
        errno = EINVAL;
        return (-1);
    }

    switch (param) {
    case DOOR_PARAM_DESC_MAX:
        *kernel_param = DOOR_PARAM_DESC_MAX;
        return (0);
    case DOOR_PARAM_DATA_MAX:
        *kernel_param = DOOR_PARAM_DATA_MAX;
        return (0);
    case DOOR_PARAM_DATA_MIN:
        *kernel_param = DOOR_PARAM_DATA_MIN;
        return (0);
    default:
        errno = EINVAL;
        return (-1);
    }
}

int
door_revoke(int fd)
{
    struct door_entry *entry;
    int rc, error;

    /*
     * Publish teardown intent before entering the kernel.  Door revoke
     * wakes blocked server workers immediately, so they may observe
     * EBADF/ENXIO before the syscall returns to the revoking thread.
     *
     * Do NOT wait for managed workers here.  door_revoke() is a revoke/cancel
     * operation, not a thread-join barrier: an active server callback may
     * remain in userspace after the client call has already been aborted.
     * Several valid users also release such callbacks only after revoke()
     * returns, so waiting here creates a deadlock.
     */
    entry = __door_entry_begin_revoke(fd);

    rc = (int)__door_syscall(DOOR_SC_REVOKE, fd,
        0, 0, 0, 0);
    error = errno;
    __door_entry_finish_revoke(entry, rc == 0);

    errno = error;
    return (rc);
}

int
door_info(int fd, door_info_t *out)
{
    struct door_ioc_info info;
    struct door_entry *entry;
    struct door_tls *tls;

    if (out == NULL) {
        errno = EINVAL;
        return (-1);
    }

    tls = NULL;
    if (fd == DOOR_QUERY) {
        tls = __door_tls_get(false);
        if (tls == NULL || tls->dt_entry == NULL) {
            errno = EBADF;
            return (-1);
        }

        fd = tls->dt_entry->de_fd;
    }

    memset(&info, 0, sizeof(info));
    if (__door_syscall(DOOR_SC_INFO, fd,
        (long)(uintptr_t)&info, 0, 0, 0) == -1)
        return (-1);

    memset(out, 0, sizeof(*out));
    out->di_target = info.di_target;
    out->di_data = (door_ptr_t)info.di_cookie;
    out->di_attributes = info.di_attributes;
    if ((info.di_flags & DOOR_INFO_LOCAL) != 0)
        out->di_attributes |= DOOR_LOCAL;

    if ((info.di_flags & DOOR_INFO_REVOKED) != 0)
        out->di_attributes |= DOOR_REVOKED;

    if (tls != NULL && tls->dt_is_unref)
        out->di_attributes |= DOOR_IS_UNREF;

    out->di_uniquifier = info.di_uniquifier;
    entry = __door_entry_lookup(fd);
    if (entry != NULL)
        out->di_proc = (door_ptr_t)(uintptr_t)entry->de_proc;

    return (0);
}

int
door_getparam(int fd, int param, size_t *value)
{
    struct door_ioc_param p;

    if (value == NULL) {
        errno = EINVAL;
        return (-1);
    }

    memset(&p, 0, sizeof(p));
    p.dip_version = DOOR_ABI_VERSION;
    if (door_param_to_kernel(param, &p.dip_type) == -1)
        return (-1);

    if (__door_syscall(DOOR_SC_GETPARAM, fd,
        (long)(uintptr_t)&p, 0, 0, 0) == -1)
        return (-1);
#if SIZE_MAX < UINT64_MAX
    if (p.dip_value > SIZE_MAX) {
        errno = EOVERFLOW;
        return (-1);
    }
#endif
    *value = (size_t)p.dip_value;
    return (0);
}

int
door_setparam(int fd, int param, size_t value)
{
    struct door_ioc_param p;

    memset(&p, 0, sizeof(p));
    p.dip_version = DOOR_ABI_VERSION;
    if (door_param_to_kernel(param, &p.dip_type) == -1)
        return (-1);

    p.dip_value = (uint64_t)value;
    return ((int)__door_syscall(DOOR_SC_SETPARAM, fd,
        (long)(uintptr_t)&p, 0, 0, 0));
}

static int
door_load_cred(struct door_tls *tls)
{
    struct door_ioc_cred arg;

    if (tls->dt_cred_valid)
        return (0);

    memset(&arg, 0, sizeof(arg));
    arg.dicr_version = DOOR_ABI_VERSION;
    arg.dicr_call_id = tls->dt_call_id;
    if (__door_syscall(DOOR_SC_CRED, (long)(uintptr_t)&arg,
        0, 0, 0, 0) == -1)
        return (-1);

    tls->dt_cred = arg.dicr_cred;
    tls->dt_cred_valid = true;
    return (0);
}

int
door_cred(door_cred_t *out)
{
    struct door_tls *tls;

    tls = __door_tls_get(false);
    if (out == NULL || tls == NULL || tls->dt_entry == NULL ||
        tls->dt_call_id == 0 || tls->dt_is_unref) {
        errno = EINVAL;
        return (-1);
    }

    if (door_load_cred(tls) == -1)
        return (-1);

    memset(out, 0, sizeof(*out));
    out->dc_euid = tls->dt_cred.dc_euid;
    out->dc_egid = tls->dt_cred.dc_egid;
    out->dc_ruid = tls->dt_cred.dc_ruid;
    out->dc_rgid = tls->dt_cred.dc_rgid;
    out->dc_pid = tls->dt_cred.dc_pid;
    return (0);
}

int
door_ucred(ucred_t **out)
{
    struct door_tls *tls;

    tls = __door_tls_get(false);
    if (out == NULL || tls == NULL || tls->dt_entry == NULL ||
        tls->dt_call_id == 0 || tls->dt_is_unref) {
        errno = EINVAL;
        return (-1);
    }

    if (door_load_cred(tls) == -1)
        return (-1);

    memset(&tls->dt_ucred, 0, sizeof(tls->dt_ucred));
    tls->dt_ucred.du_euid = tls->dt_cred.dc_euid;
    tls->dt_ucred.du_ruid = tls->dt_cred.dc_ruid;
    tls->dt_ucred.du_suid = tls->dt_cred.dc_suid;
    tls->dt_ucred.du_egid = tls->dt_cred.dc_egid;
    tls->dt_ucred.du_rgid = tls->dt_cred.dc_rgid;
    tls->dt_ucred.du_sgid = tls->dt_cred.dc_sgid;
    tls->dt_ucred.du_pid = tls->dt_cred.dc_pid;
    tls->dt_ucred.du_jid = tls->dt_cred.dc_jid;
    tls->dt_ucred.du_ngroups = tls->dt_cred.dc_ngroups;
    if (tls->dt_ucred.du_ngroups > DOOR_UCRED_MAX_GROUPS)
        tls->dt_ucred.du_ngroups = DOOR_UCRED_MAX_GROUPS;

    memcpy(tls->dt_ucred.du_groups, tls->dt_cred.dc_groups,
        tls->dt_ucred.du_ngroups * sizeof(gid_t));
    *out = &tls->dt_ucred;
    return (0);
}

int
door_bind(int fd)
{
    struct door_entry *entry;
    struct door_tls *tls;

    entry = __door_entry_lookup(fd);
    if (entry == NULL) {
        errno = EBADF;
        return (-1);
    }

    tls = __door_tls_get(true);
    if (tls == NULL)
        return (-1);

    if (tls->dt_entry != NULL || tls->dt_bound ||
        tls->dt_worker_fd >= 0) {
        errno = EINVAL;
        return (-1);
    }

    if (__door_syscall(DOOR_SC_BIND, fd,
        0, 0, 0, 0) == -1)
        return (-1);

    tls->dt_entry = entry;
    tls->dt_worker_fd = -1;
    tls->dt_pid = getpid();
    tls->dt_bound = true;
    tls->dt_call_id = 0;
    tls->dt_is_unref = false;
    return (0);
}

int
door_unbind(void)
{
    struct door_tls *tls;

    tls = __door_tls_get(false);
    if (tls == NULL || tls->dt_entry == NULL || !tls->dt_bound ||
        tls->dt_pid != getpid()) {
        errno = EINVAL;
        return (-1);
    }

    if (__door_syscall(DOOR_SC_UNBIND, 0, 0, 0, 0, 0) == -1)
        return (-1);

    tls->dt_worker_fd = -1;
    tls->dt_entry = NULL;
    tls->dt_call_id = 0;
    tls->dt_is_unref = false;
    tls->dt_bound = false;
    return (0);
}
