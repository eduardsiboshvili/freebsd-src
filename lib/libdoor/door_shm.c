/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "libdoor_impl.h"

static int
door_shm_validate_create_flags(uint_t flags)
{
    if ((flags & ~DOOR_SHM_FLAG_MASK) != 0 ||
        (flags & DOOR_SHM_RW) == 0) {
        errno = EINVAL;
        return (-1);
    }

    return (0);
}

static int
door_shm_validate_attach_flags(uint_t flags)
{
    if ((flags & ~DOOR_SHM_RW) != 0 || (flags & DOOR_SHM_RW) == 0) {
        errno = EINVAL;
        return (-1);
    }

    return (0);
}

static size_t
door_shm_round_size(size_t size)
{
    long pagesize;
    size_t ps;

    pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 0)
        return (size);

    ps = (size_t)pagesize;
    if (size > SIZE_MAX - (ps - 1))
        return (0);

    return ((size + ps - 1) / ps * ps);
}

static int
door_shm_dupfd(int fd)
{
    int newfd;

    newfd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    return (newfd);
}

int
door_shm_create(int fd, size_t size, uint_t flags, door_shm_t *shm)
{
    struct door_ioc_shm_create arg;
    int pinned_fd, error;

    if (fd < 0 || size == 0 || shm == NULL) {
        errno = EINVAL;
        return (-1);
    }

    if (door_shm_validate_create_flags(flags) == -1)
        return (-1);

    if (door_shm_round_size(size) == 0) {
        errno = EOVERFLOW;
        return (-1);
    }

    pinned_fd = door_shm_dupfd(fd);
    if (pinned_fd == -1)
        return (-1);

    memset(&arg, 0, sizeof(arg));
    arg.disc_version = DOOR_ABI_VERSION;
    arg.disc_flags = flags;
    arg.disc_size = size;
    /* Use the pinned capability for the operation as well as its handle;
     * concurrent reuse of the original fd must not split generations. */
    if (__door_syscall(DOOR_SC_SHM_CREATE, pinned_fd,
        (long)(uintptr_t)&arg, 0, 0, 0) == -1) {
        error = errno;
        close(pinned_fd);
        errno = error;
        return (-1);
    }

    memset(shm, 0, sizeof(*shm));
    shm->dsh_region = arg.disc_region;
    shm->dsh_addr = (void *)(uintptr_t)arg.disc_addr;
    shm->dsh_size = size;
    shm->dsh_flags = flags;
    shm->dsh_uniquifier = arg.disc_uniquifier;
    shm->dsh_fd = pinned_fd;
    return (0);
}

int
door_shm_attach(int fd, door_shm_id_t region, uint_t flags,
    door_shm_t *shm)
{
    struct door_ioc_shm_attach arg;
    int pinned_fd, error;

    if (fd < 0 || region == 0 || shm == NULL) {
        errno = EINVAL;
        return (-1);
    }

    if (door_shm_validate_attach_flags(flags) == -1)
        return (-1);

    pinned_fd = door_shm_dupfd(fd);
    if (pinned_fd == -1)
        return (-1);

    memset(&arg, 0, sizeof(arg));
    arg.disa_version = DOOR_ABI_VERSION;
    arg.disa_flags = flags;
    arg.disa_region = region;
    /* Match returned metadata to the capability kept in dsh_fd. */
    if (__door_syscall(DOOR_SC_SHM_ATTACH, pinned_fd,
        (long)(uintptr_t)&arg, 0, 0, 0) == -1) {
        error = errno;
        close(pinned_fd);
        errno = error;
        return (-1);
    }

    memset(shm, 0, sizeof(*shm));
    shm->dsh_region = region;
    shm->dsh_addr = (void *)(uintptr_t)arg.disa_addr;
    shm->dsh_size = (size_t)arg.disa_size;
    shm->dsh_flags = flags;
    shm->dsh_uniquifier = arg.disa_uniquifier;
    shm->dsh_fd = pinned_fd;
    return (0);
}

int
door_shm_unmap(door_shm_t *shm)
{
    int error, saved;

    if (shm == NULL || shm->dsh_addr == NULL || shm->dsh_size == 0) {
        errno = EINVAL;
        return (-1);
    }

    error = munmap(shm->dsh_addr, door_shm_round_size(shm->dsh_size));
    saved = errno;
    if (shm->dsh_fd >= 0) {
        (void)close(shm->dsh_fd);
        shm->dsh_fd = -1;
    }

    if (error == -1) {
        errno = saved;
        return (-1);
    }

    shm->dsh_addr = NULL;
    shm->dsh_size = 0;
    return (0);
}

int
door_shm_destroy(int fd, door_shm_id_t region)
{
    struct door_ioc_shm_destroy arg;

    if (fd < 0 || region == 0) {
        errno = EINVAL;
        return (-1);
    }

    memset(&arg, 0, sizeof(arg));
    arg.disd_version = DOOR_ABI_VERSION;
    arg.disd_region = region;
    return ((int)__door_syscall(DOOR_SC_SHM_DESTROY, fd,
        (long)(uintptr_t)&arg, 0, 0, 0));
}

static int
door_call_shm_impl(int fd, const door_shm_ref_t *ref, bool trusted_fd)
{
    struct door_ioc_call_shm call;

    if (fd < 0 || ref == NULL || ref->dsr_region == 0 ||
        (uint64_t)ref->dsr_size >
        UINT64_MAX - (uint64_t)ref->dsr_offset) {
        errno = EINVAL;
        return (-1);
    }

    /*
     * Strong refs carry the generation identity.  Legacy refs with zero
     * identity retain the historical raw-region behavior.
     */
    memset(&call, 0, sizeof(call));
    call.dics_call.dic_version = DOOR_ABI_VERSION;
    call.dics_call.dic_send_fd = -1;
    call.dics_call.dic_recv_fd = -1;
    call.dics_shm.disr_region = ref->dsr_region;
    call.dics_shm.disr_offset = ref->dsr_offset;
    call.dics_shm.disr_size = ref->dsr_size;
    call.dics_uniquifier = trusted_fd ? 0 : ref->dsr_uniquifier;

    if (__door_syscall(DOOR_SC_CALL_SHM, fd,
        (long)(uintptr_t)&call, 0, 0, 0) == -1)
        return (-1);

    if ((call.dics_call.dic_flags & DOOR_CALL_F_ONEWAY) == 0 &&
        (call.dics_call.dic_reply_size != 0 ||
        call.dics_call.dic_recv_desc_count != 0)) {
        if ((call.dics_call.dic_flags & DOOR_CALL_F_AUTO_MAP) != 0)
            (void)munmap(
                (void *)(uintptr_t)call.dics_call.dic_reply_ptr,
                door_shm_round_size(
                    (size_t)call.dics_call.dic_reply_size));

        errno = EPROTO;
        return (-1);
    }

    return (0);
}

int
door_call_shm(int fd, const door_shm_ref_t *ref)
{
    return (door_call_shm_impl(fd, ref, false));
}

int
door_shm_ref_init(const door_shm_t *shm, size_t offset, size_t size,
    door_shm_ref_t *ref)
{
    if (shm == NULL || ref == NULL || shm->dsh_region == 0 ||
        shm->dsh_uniquifier == 0 || offset > shm->dsh_size ||
        size > shm->dsh_size - offset) {
        errno = EINVAL;
        return (-1);
    }

    memset(ref, 0, sizeof(*ref));
    ref->dsr_region = shm->dsh_region;
    ref->dsr_offset = offset;
    ref->dsr_size = size;
    ref->dsr_uniquifier = shm->dsh_uniquifier;
    return (0);
}

int
door_call_shm_region(const door_shm_t *shm, size_t offset, size_t size)
{
    door_shm_ref_t ref;

    if (shm == NULL || shm->dsh_fd < 0) {
        errno = EINVAL;
        return (-1);
    }

    if (door_shm_ref_init(shm, offset, size, &ref) == -1)
        return (-1);

    /*
     * dsh_fd is a private duplicate made at CREATE/ATTACH time and therefore
     * cannot be recycled to a different Door generation behind our back.
     */
    return (door_call_shm_impl(shm->dsh_fd, &ref, true));
}

int
door_shm_destroy_handle(door_shm_t *shm)
{
    int rc;

    if (shm == NULL || shm->dsh_region == 0 || shm->dsh_fd < 0 ||
        shm->dsh_uniquifier == 0) {
        errno = EINVAL;
        return (-1);
    }

    rc = door_shm_destroy(shm->dsh_fd, shm->dsh_region);
    if (rc == 0)
        shm->dsh_region = 0;

    return (rc);
}
