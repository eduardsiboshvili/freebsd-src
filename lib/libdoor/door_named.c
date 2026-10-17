/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/ioctl.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <door.h>

#include "libdoor_impl.h"

#define DOORCTL_PATH "/dev/doorctl"

static int
door_named_openctl(void)
{
    return (open(DOORCTL_PATH, O_RDWR | O_CLOEXEC));
}

static int
door_named_copy_name(char dst[DOOR_NAME_MAX], const char *name)
{
    size_t len;

    if (name == NULL || name[0] == '\0') {
        errno = EINVAL;
        return (-1);
    }

    len = strlen(name);
    if (len >= DOOR_NAME_MAX) {
        errno = ENAMETOOLONG;
        return (-1);
    }

    memcpy(dst, name, len + 1);
    return (0);
}

static int
door_named_flags(uint_t flags)
{
    if ((flags & ~DOOR_NAMED_GLOBAL) != 0) {
        errno = EINVAL;
        return (-1);
    }

    return ((flags & DOOR_NAMED_GLOBAL) != 0 ? DOOR_NAMED_F_GLOBAL : 0);
}

/* A successful ioctl still reports failure if its control fd cannot close. */
static int
door_named_ioctl(unsigned long command, void *arg)
{
    int ctl, error;

    ctl = door_named_openctl();
    if (ctl == -1)
        return (-1);

    if (ioctl(ctl, command, arg) != -1)
        return (close(ctl));

    error = errno;
    (void)close(ctl);
    errno = error;
    return (-1);
}

int
door_named_register(int door_fd, const char *name, uint_t flags)
{
    struct door_ctl_register arg;
    int kflags;

    if (door_fd < 0) {
        errno = EINVAL;
        return (-1);
    }

    kflags = door_named_flags(flags);
    if (kflags == -1)
        return (-1);

    memset(&arg, 0, sizeof(arg));
    arg.dcr_version = DOOR_CTL_ABI_VERSION;
    arg.dcr_flags = (uint32_t)kflags;
    arg.dcr_door_fd = door_fd;
    if (door_named_copy_name(arg.dcr_name, name) == -1)
        return (-1);

    return (door_named_ioctl(DOORCTL_IOC_REGISTER, &arg));
}

int
door_named_unregister(int door_fd, const char *name, uint_t flags)
{
    struct door_ctl_unregister arg;
    int kflags;

    if (door_fd < 0) {
        errno = EINVAL;
        return (-1);
    }

    kflags = door_named_flags(flags);
    if (kflags == -1)
        return (-1);

    memset(&arg, 0, sizeof(arg));
    arg.dcu_version = DOOR_CTL_ABI_VERSION;
    arg.dcu_flags = (uint32_t)kflags;
    arg.dcu_door_fd = door_fd;
    if (door_named_copy_name(arg.dcu_name, name) == -1)
        return (-1);

    return (door_named_ioctl(DOORCTL_IOC_UNREGISTER, &arg));
}

int
door_named_lookup(const char *name, uint_t flags, door_named_info_t *info)
{
    struct door_ctl_lookup arg;

    /* Discovery selects local scope, then global; no explicit scope flag. */
    if (flags != 0) {
        errno = EINVAL;
        return (-1);
    }

    memset(&arg, 0, sizeof(arg));
    arg.dcl_version = DOOR_CTL_ABI_VERSION;
    arg.dcl_flags = 0;
    if (door_named_copy_name(arg.dcl_name, name) == -1)
        return (-1);

    if (door_named_ioctl(DOORCTL_IOC_LOOKUP, &arg) == -1)
        return (-1);

    if (info != NULL) {
        info->dni_target_jid = arg.dcl_target_jid;
        info->dni_attributes = arg.dcl_attributes;
        info->dni_uniquifier = arg.dcl_uniquifier;
    }

    return (0);
}

int
door_named_connect(const char *name, uint_t flags, door_named_info_t *info)
{
    struct door_ctl_connect arg;
    int ctl, error;

    /* Discovery selects local scope, then global; no explicit scope flag. */
    if (flags != 0) {
        errno = EINVAL;
        return (-1);
    }

    memset(&arg, 0, sizeof(arg));
    arg.dcc_version = DOOR_CTL_ABI_VERSION;
    arg.dcc_flags = 0;
    arg.dcc_fd = -1;
    if (door_named_copy_name(arg.dcc_name, name) == -1)
        return (-1);

    ctl = door_named_openctl();
    if (ctl == -1)
        return (-1);

    if (ioctl(ctl, DOORCTL_IOC_CONNECT, &arg) == -1) {
        error = errno;
        close(ctl);
        errno = error;
        return (-1);
    }

    if (close(ctl) == -1) {
        error = errno;
        close(arg.dcc_fd);
        errno = error;
        return (-1);
    }

    if (info != NULL) {
        info->dni_target_jid = arg.dcc_target_jid;
        /* CONNECT returns identity, not LOOKUP attribute metadata. */
        info->dni_attributes = 0;
        info->dni_uniquifier = arg.dcc_uniquifier;
    }

    return (arg.dcc_fd);
}
