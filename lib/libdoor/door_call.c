/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libdoor_impl.h"

static __inline int
door_call_kernel(int fd, struct door_ioc_call *call)
{
    return ((int)__door_syscall(
        DOOR_SC_CALL, fd, (long)(uintptr_t)call,
        0, 0, 0));
}

static __inline int
door_fast_call_kernel(int fd, struct door_ioc_call *call)
{
    uint64_t packed;
    struct door_sys_fast_call_mapped_io io;
    int64_t rc;

#if ULONG_MAX < UINT64_MAX
    return (door_call_kernel(fd, call));
#endif
    if (call->dic_recv_desc_count != DOOR_FAST_CALL_DESC_CAP)
        return (door_call_kernel(fd, call));

    /*
     * FreeBSD syscall() has an int return type.  FAST_CALL deliberately
     * packs descriptor count above bit 32, so use the quad-return entrypoint
     * and preserve the complete register_t value.
     */
    memset(&io, 0, sizeof(io));
    io.dsfcmi_version = DOOR_ABI_VERSION;
    io.dsfcmi_reply_capacity = call->dic_reply_size;
    io.dsfcmi_recv_desc_ptr = call->dic_recv_desc_ptr;
    io.dsfcmi_reply_ptr = call->dic_reply_ptr;
    if (call->dic_request_size == 0) {
        rc = __door_syscall(
            DOOR_SC_EMPTY_CALL_MAPPED, fd,
            call->dic_reply_ptr, call->dic_reply_size,
            call->dic_recv_desc_ptr, (long)(uintptr_t)&io);
    } else {
        rc = __door_syscall(
            DOOR_SC_FAST_CALL_MAPPED, fd,
            call->dic_request_ptr, call->dic_request_size,
            (long)call->dic_reply_ptr, (long)(uintptr_t)&io);
    }

    if (rc == -1) {
        /* Never retry an RPC after an ambiguous fast-path error. */
        return (-1);
    }

    packed = (uint64_t)(unsigned long)rc;
    call->dic_reply_size = packed & DOOR_FAST_CALL_REPLY_MASK;
    call->dic_recv_desc_count = (uint32_t)((packed >>
        DOOR_FAST_CALL_DESC_SHIFT) & DOOR_FAST_CALL_DESC_MASK);
    call->dic_flags = io.dsfcmi_flags;
    call->dic_reply_ptr = io.dsfcmi_reply_ptr;
    call->dic_call_id = 0;
    return (0);
}

int
door_call(int fd, door_arg_t *arg)
{
    door_arg_t empty_arg;
    struct door_ioc_call call;
    struct door_kdesc recv_stack[LIBDOOR_CALL_DESC_CAP];
    struct door_kdesc *send_desc, *recv_desc, *recv_heap;
    door_desc_t *public_desc;
    uint32_t send_count, recv_capacity, i;
    int error;

    /*
     * Solaris/illumos permit door_call(fd, NULL) for a data-less call whose
     * result is intentionally ignored.  Run it through the ordinary CALL
     * implementation so that validation, cancellation, and callback
     * semantics remain identical.  A server is still allowed to return data
     * or descriptors; because the caller supplied no result container, drop
     * those capabilities here without leaking the replacement mapping or
     * installed descriptors.
     */
    if (arg == NULL) {
        memset(&empty_arg, 0, sizeof(empty_arg));
        if (door_call(fd, &empty_arg) == -1)
            return (-1);

        for (i = 0; i < empty_arg.desc_num; i++) {
            if ((empty_arg.desc_ptr[i].d_attributes & DOOR_DESCRIPTOR) != 0 &&
                empty_arg.desc_ptr[i].d_descriptor >= 0)
                (void)close(empty_arg.desc_ptr[i].d_descriptor);
        }

        free(empty_arg.desc_ptr);
        if (empty_arg.rbuf != NULL && empty_arg.rsize != 0)
            (void)munmap(empty_arg.rbuf, empty_arg.rsize);

        return (0);
    }

    if (fd < 0 ||
        (arg->data_size != 0 && arg->data_ptr == NULL) ||
        (arg->desc_num != 0 && arg->desc_ptr == NULL) ||
        (arg->rsize != 0 && arg->rbuf == NULL)) {
        errno = EINVAL;
        return (-1);
    }

    send_desc = NULL;
    recv_desc = recv_stack;
    recv_heap = NULL;
    public_desc = NULL;
    send_count = 0;
    if (__door_desc_export(arg->desc_ptr, arg->desc_num,
        &send_desc, &send_count) == -1)
        return (-1);

    recv_capacity = arg->desc_num;
    if (recv_capacity < LIBDOOR_CALL_DESC_CAP)
        recv_capacity = LIBDOOR_CALL_DESC_CAP;

    if (recv_capacity > LIBDOOR_CALL_DESC_CAP) {
        recv_heap = calloc(recv_capacity, sizeof(*recv_heap));
        if (recv_heap == NULL)
            goto fail;

        recv_desc = recv_heap;
    } else {
        memset(recv_stack, 0, sizeof(recv_stack));
    }

    memset(&call, 0, sizeof(call));
    call.dic_version = DOOR_ABI_VERSION;
    call.dic_request_ptr = (uint64_t)(uintptr_t)arg->data_ptr;
    call.dic_request_size = arg->data_size;
    call.dic_reply_ptr = (uint64_t)(uintptr_t)arg->rbuf;
    call.dic_reply_size = arg->rsize;
    call.dic_send_fd = -1;
    call.dic_recv_fd = -1;
    call.dic_send_desc_ptr = (uint64_t)(uintptr_t)send_desc;
    call.dic_send_desc_count = send_count;
    call.dic_recv_desc_ptr = (uint64_t)(uintptr_t)recv_desc;
    call.dic_recv_desc_count = recv_capacity;

    if ((send_count == 0 ? door_fast_call_kernel(fd, &call) :
        door_call_kernel(fd, &call)) == -1)
        goto fail;

    if ((call.dic_flags & DOOR_CALL_F_ONEWAY) != 0) {
        /*
         * Asynchronous success publishes no synthetic reply buffer.  The
         * request is already snapshotted/owned by the kernel at this point.
         */
        arg->data_ptr = NULL;
        arg->data_size = 0;
        arg->desc_ptr = NULL;
        arg->desc_num = 0;
        free(send_desc);
        free(recv_heap);
        return (0);
    }

    if (call.dic_recv_desc_count != 0) {
        public_desc = calloc(call.dic_recv_desc_count, sizeof(*public_desc));
        if (public_desc == NULL) {
            error = errno;
            goto fail_after_call;
        }

        __door_desc_import(public_desc, recv_desc,
            call.dic_recv_desc_count);
    }

    if ((call.dic_flags & DOOR_CALL_F_AUTO_MAP) != 0) {
        arg->rbuf = (char *)(uintptr_t)call.dic_reply_ptr;
        arg->rsize = roundup2((size_t)call.dic_reply_size,
            (size_t)getpagesize());
    }

    arg->data_ptr = (char *)(uintptr_t)call.dic_reply_ptr;
    arg->data_size = (size_t)call.dic_reply_size;
    arg->desc_ptr = public_desc;
    arg->desc_num = call.dic_recv_desc_count;
    free(send_desc);
    free(recv_heap);
    return (0);

fail_after_call:
    /*
     * The kernel has already installed reply descriptors.  If allocation of
     * the public descriptor array fails, close those descriptors before
     * reporting ENOMEM so this optimization cannot leak them. Server effects
     * and MOVE are already committed; unchanged public fields do not make
     * retry safe. AUTO_MAP ownership is also cleaned below.
     */
    for (i = 0; i < call.dic_recv_desc_count; i++) {
        if (recv_desc[i].dd_fd >= 0)
            (void)close(recv_desc[i].dd_fd);
    }

    if ((call.dic_flags & DOOR_CALL_F_AUTO_MAP) != 0)
        (void)munmap((void *)(uintptr_t)call.dic_reply_ptr,
            roundup2((size_t)call.dic_reply_size,
                (size_t)getpagesize()));

    errno = error;

fail:
    free(send_desc);
    free(recv_heap);
    return (-1);
}
