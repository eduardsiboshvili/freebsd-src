/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libdoor_impl.h"

static __inline int
door_return_kernel(struct door_ioc_return_shm *ret)
{
    return ((int)__door_syscall(
        DOOR_SC_RETURN, (long)(uintptr_t)ret, 0, 0, 0, 0));
}

static __inline int
door_bind_kernel(int fd)
{
    return ((int)__door_syscall(DOOR_SC_BIND, fd,
        0, 0, 0, 0));
}

static __inline int
door_fast_return_kernel(struct door_ioc_return_shm *ret)
{
    struct door_sys_fast_return_out out;
    struct door_sys_fast_return_io io;
    struct door_ioc_return *base;
    uint64_t packed;
    int64_t rc;

#if ULONG_MAX < UINT64_MAX
    return (door_return_kernel(ret));
#endif
    base = &ret->dirs_return;
    if (base->dir_reply_size == 0) {
        rc = __door_syscall(
            DOOR_SC_EMPTY_RETURN, base->dir_call_id,
            base->dir_request_ptr, base->dir_request_size,
            (long)(uintptr_t)&out, 0);
    } else {
        io.dsfri_request_capacity = base->dir_request_size;
        io.dsfri_out_ptr = (uint64_t)(uintptr_t)&out;
        rc = __door_syscall(
            DOOR_SC_FAST_RETURN, base->dir_call_id,
            base->dir_reply_ptr, base->dir_reply_size,
            (long)base->dir_request_ptr, (long)(uintptr_t)&io);
    }

    if (rc == -1)
        return (-1);

    packed = (uint64_t)rc;
    if ((packed & DOOR_FAST_RETURN_F_REGISTER) != 0) {
        base->dir_call_id = packed & DOOR_FAST_RETURN_CALL_MASK;
        base->dir_flags = DOOR_RETURN_F_CRED_LAZY;
        base->dir_request_size = 0;
        base->dir_request_desc_count = 0;
        base->dir_request_fd = -1;
        return (0);
    }

    base->dir_call_id = out.dsfro_call_id;
    base->dir_request_size = out.dsfro_request_size;
    base->dir_request_desc_count = out.dsfro_request_desc_count;
    base->dir_flags = out.dsfro_flags;
    ret->dirs_shm = out.dsfro_shm;
    ret->dirs_shm_ptr = out.dsfro_shm_ptr;
    return (0);
}


static void
door_xcreate_default_setup(void)
{
    (void)pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
}

/* Keep retry policy separate from the public RETURN error result. */
static bool
door_server_recover(struct door_entry *entry, struct door_tls *tls,
    int error, bool reset_call)
{
    switch (error) {
    case EINTR:
        tls->dt_bound = false;
        if (door_bind_kernel(entry->de_fd) == -1)
            return (false);

        tls->dt_bound = true;
        if (!reset_call)
            return (true);

        break;
    case EMSGSIZE:
    case ENOBUFS:
    case ENOTSUP:
    case ENFILE:
        break;
    default:
        errno = error;
        return (false);
    }

    tls->dt_call_id = 0;
    tls->dt_is_unref = false;
    return (true);
}

static void
door_pool_worker_bound(struct door_entry *entry, struct door_tls *tls)
{
    pthread_mutex_lock(&entry->de_pool_lock);
    if (entry->de_workers_starting != 0)
        entry->de_workers_starting--;

    entry->de_workers_ready++;
    entry->de_workers_live++;
    entry->de_workers_idle++;
    entry->de_depletion_in_progress = false;
    entry->de_depletion_armed = true;
    tls->dt_pool_idle = true;
    tls->dt_pool_active = false;
    pthread_cond_broadcast(&entry->de_pool_cv);
    pthread_mutex_unlock(&entry->de_pool_lock);
}

static bool
door_pool_dispatch_begin(struct door_entry *entry, struct door_tls *tls)
{
    bool trigger;

    trigger = false;
    /*
     * Dynamic depletion is a per-door private-pool policy.  A normal
     * door_create() door still uses the stable single per-door worker path;
     * automatically growing those workers changes pending-call semantics
     * and is not a true process-wide shared pool.
     */
    if (entry->de_pool_type != DOOR_POOL_XCREATE_PRIVATE &&
        entry->de_pool_type != DOOR_POOL_LEGACY_PRIVATE)
        return (false);

    pthread_mutex_lock(&entry->de_pool_lock);
    if (tls->dt_pool_idle && entry->de_workers_idle != 0) {
        entry->de_workers_idle--;
        entry->de_workers_active++;
        tls->dt_pool_idle = false;
        tls->dt_pool_active = true;
    }

    if (!entry->de_pool_stopping &&
        (entry->de_attributes & DOOR_NO_DEPLETION_CB) == 0 &&
        entry->de_workers_idle == 0 && entry->de_depletion_armed &&
        !entry->de_depletion_in_progress) {
        entry->de_depletion_in_progress = true;
        entry->de_depletion_armed = false;
        trigger = true;
    }

    pthread_mutex_unlock(&entry->de_pool_lock);
    return (trigger);
}

static void
door_pool_callback_end(struct door_entry *entry, struct door_tls *tls)
{
    if (entry->de_pool_type != DOOR_POOL_XCREATE_PRIVATE &&
        entry->de_pool_type != DOOR_POOL_LEGACY_PRIVATE)
        return;

    pthread_mutex_lock(&entry->de_pool_lock);
    if (tls->dt_pool_active && entry->de_workers_active != 0) {
        entry->de_workers_active--;
        entry->de_workers_idle++;
        tls->dt_pool_active = false;
        tls->dt_pool_idle = true;
        entry->de_depletion_armed = true;
        entry->de_depletion_in_progress = false;
    }

    pthread_cond_broadcast(&entry->de_pool_cv);
    pthread_mutex_unlock(&entry->de_pool_lock);
}

static void
door_pool_worker_exited(struct door_entry *entry, struct door_tls *tls)
{
    pthread_mutex_lock(&entry->de_pool_lock);
    if (tls->dt_pool_active && entry->de_workers_active != 0)
        entry->de_workers_active--;

    if (tls->dt_pool_idle && entry->de_workers_idle != 0)
        entry->de_workers_idle--;

    if (entry->de_workers_live != 0)
        entry->de_workers_live--;

    tls->dt_pool_active = false;
    tls->dt_pool_idle = false;
    entry->de_workers_exited++;
    entry->de_depletion_in_progress = false;
    pthread_cond_broadcast(&entry->de_pool_cv);
    pthread_mutex_unlock(&entry->de_pool_lock);
}

static int
door_server_wait(struct door_tls *tls, char *reply_data, size_t reply_size,
    door_desc_t *reply_desc, uint_t reply_count, char *request_data,
    size_t request_capacity, struct door_kdesc *request_desc,
    uint32_t request_desc_capacity, bool force_full,
    struct door_ioc_return_shm *result)
{
    struct door_ioc_return *ret;
    struct door_kdesc *kernel_reply;
    uint32_t kernel_reply_count;
    int rc;

    kernel_reply = NULL;
    kernel_reply_count = 0;
    if (reply_count != 0 &&
        __door_desc_export(reply_desc, reply_count, &kernel_reply,
        &kernel_reply_count) == -1)
        return (-1);

    ret = &result->dirs_return;
    ret->dir_call_id = tls->dt_call_id;
    ret->dir_reply_ptr = (uint64_t)(uintptr_t)reply_data;
    ret->dir_reply_size = reply_size;
    ret->dir_request_ptr = (uint64_t)(uintptr_t)request_data;
    ret->dir_request_size = request_capacity;

    /*
     * The extended DOOR_SC_RETURN payload adds SHM receive fields. Ordinary
     * requests still use the preallocated buffer; SHM returns a validated
     * server-local pointer in dirs_shm_ptr. It is not a separate selector.
     */
#if ULONG_MAX < UINT64_MAX
    /* The generic RETURN needs initialized descriptor capacities and flags. */
    force_full = true;
#endif
    if (kernel_reply_count == 0 && !force_full &&
        ret->dir_call_id <= DOOR_FAST_RETURN_CALL_MASK)
        rc = door_fast_return_kernel(result);
    else {
        ret->dir_version = DOOR_ABI_VERSION;
        ret->dir_flags = DOOR_RETURN_F_RESIZABLE;
        ret->dir_reply_fd = -1;
        ret->dir_reply_desc_ptr = (uint64_t)(uintptr_t)kernel_reply;
        ret->dir_reply_desc_count = kernel_reply_count;
        ret->dir_request_fd = -1;
        ret->dir_request_desc_ptr = (uint64_t)(uintptr_t)request_desc;
        ret->dir_request_desc_count = request_desc_capacity;
        rc = door_return_kernel(result);
    }

    free(kernel_reply);

    return (rc);
}


static int
door_server_resize_receive(struct door_tls *tls, size_t data_need,
    uint32_t desc_need)
{
    char *new_data;
    struct door_kdesc *new_kernel;
    door_desc_t *new_public;
    size_t new_data_cap;
    uint32_t new_desc_cap;

    if (data_need > tls->dt_request_capacity) {
        new_data_cap = tls->dt_request_capacity;
        if (new_data_cap == 0)
            new_data_cap = LIBDOOR_SERVER_DATA_CAP;

        while (new_data_cap < data_need) {
            if (new_data_cap > SIZE_MAX / 2) {
                new_data_cap = data_need;
                break;
            }

            new_data_cap *= 2;
        }

        new_data = realloc(tls->dt_request_data, new_data_cap);
        if (new_data == NULL)
            return (-1);

        tls->dt_request_data = new_data;
        tls->dt_request_capacity = new_data_cap;
    }

    if (desc_need > tls->dt_request_desc_capacity) {
        new_desc_cap = tls->dt_request_desc_capacity;
        if (new_desc_cap == 0)
            new_desc_cap = LIBDOOR_SERVER_DESC_CAP;

        while (new_desc_cap < desc_need) {
            if (new_desc_cap > UINT32_MAX / 2) {
                new_desc_cap = desc_need;
                break;
            }

            new_desc_cap *= 2;
        }

        new_kernel = reallocarray(tls->dt_request_desc, new_desc_cap,
            sizeof(*new_kernel));
        if (new_kernel == NULL)
            return (-1);

        tls->dt_request_desc = new_kernel;

        new_public = reallocarray(tls->dt_public_desc, new_desc_cap,
            sizeof(*new_public));
        if (new_public == NULL)
            return (-1);

        tls->dt_public_desc = new_public;
        tls->dt_request_desc_capacity = new_desc_cap;
        tls->dt_public_desc_capacity = new_desc_cap;
    }

    return (0);
}

/*
 * Only successful RETURN outputs are authoritative. Preserve COMPLETED and
 * clear call_id before resizing on NEED_BUFS, so retry receives without
 * replaying the reply. EMSGSIZE compatibility retry is limited to pure wait
 * and never reads error outputs.
 */
static int
door_server_wait_resizable(struct door_tls *tls, char *reply_data,
    size_t reply_size, door_desc_t *reply_desc, uint_t reply_count,
    struct door_ioc_return_shm *result)
{
    bool completed, force_full;

    completed = false;
    force_full = false;
    for (;;) {
        if (door_server_wait(tls,
            completed ? NULL : reply_data,
            completed ? 0 : reply_size,
            completed ? NULL : reply_desc,
            completed ? 0 : reply_count,
            tls->dt_request_data, tls->dt_request_capacity,
            tls->dt_request_desc, tls->dt_request_desc_capacity,
            force_full, result) == 0) {
            if ((result->dirs_return.dir_flags &
                DOOR_RETURN_F_COMPLETED) != 0) {
                completed = true;
                tls->dt_call_id = 0;
            }

            if ((result->dirs_return.dir_flags &
                DOOR_RETURN_F_NEED_BUFS) == 0)
                return (0);

#if SIZE_MAX < UINT64_MAX
            if (result->dirs_return.dir_request_size > SIZE_MAX) {
                errno = EOVERFLOW;
                return (-1);
            }
#endif
            /* Scalar FAST_RETURN has no descriptor-buffer arguments. */
            if (result->dirs_return.dir_request_desc_count != 0)
                force_full = true;

            if (door_server_resize_receive(tls,
                (size_t)result->dirs_return.dir_request_size,
                result->dirs_return.dir_request_desc_count) == -1)
                return (-1);

            continue;
        }

        /*
         * Compatibility fallback for older kernels.  On a syscall error we do
         * not trust output flags/sizes.  Only a pure wait can safely retry.
         */
        if (errno == EMSGSIZE && tls->dt_call_id == 0)
            continue;

        return (-1);
    }
}

void *
__door_server_main(void *arg)
{
    struct door_server_context *context;
    struct door_entry *entry;
    struct door_tls *tls;
    struct door_ioc_return_shm ret;
    struct door_kdesc *kernel_desc;
    door_desc_t *public_desc;
    char *request_data;
    bool have_request;
    int error;

    request_data = NULL;
    kernel_desc = NULL;
    public_desc = NULL;
    have_request = false;

    context = arg;
    entry = context->dsc_entry;
    tls = __door_tls_get(true);
    if (tls == NULL) {
        error = errno != 0 ? errno : ENOMEM;
        (void)close(context->dsc_worker_fd);
        pthread_mutex_lock(&entry->de_pool_lock);
        if (entry->de_workers_starting != 0)
            entry->de_workers_starting--;

        if (entry->de_start_error == 0)
            entry->de_start_error = error;

        entry->de_workers_exited++;
        pthread_cond_broadcast(&entry->de_pool_cv);
        pthread_mutex_unlock(&entry->de_pool_lock);
        free(context);
        errno = error;
        return (NULL);
    }

    tls->dt_entry = entry;
    tls->dt_worker_fd = context->dsc_worker_fd;
    tls->dt_pid = getpid();
    tls->dt_is_unref = false;
    tls->dt_return_error = 0;
    tls->dt_next_ready = false;
    tls->dt_exit_after_return = false;
    tls->dt_in_callback = false;
    tls->dt_reply_submitted = false;
    if (context->dsc_xcreate) {
        if (entry->de_thrsetup != NULL)
            entry->de_thrsetup(entry->de_setup_cookie);
        else
            door_xcreate_default_setup();
    }

    free(context);

    request_data = malloc(LIBDOOR_SERVER_DATA_CAP);
    kernel_desc = calloc(LIBDOOR_SERVER_DESC_CAP, sizeof(*kernel_desc));
    public_desc = calloc(LIBDOOR_SERVER_DESC_CAP, sizeof(*public_desc));
    tls->dt_request_data = request_data;
    tls->dt_request_capacity = LIBDOOR_SERVER_DATA_CAP;
    tls->dt_request_desc = kernel_desc;
    tls->dt_request_desc_capacity = LIBDOOR_SERVER_DESC_CAP;
    tls->dt_public_desc = public_desc;
    tls->dt_public_desc_capacity = LIBDOOR_SERVER_DESC_CAP;
    if (request_data == NULL || kernel_desc == NULL || public_desc == NULL) {
        error = errno != 0 ? errno : ENOMEM;
        pthread_mutex_lock(&entry->de_pool_lock);
        if (entry->de_workers_starting != 0)
            entry->de_workers_starting--;

        if (entry->de_start_error == 0)
            entry->de_start_error = error;

        pthread_cond_broadcast(&entry->de_pool_cv);
        pthread_mutex_unlock(&entry->de_pool_lock);
        errno = error;
        goto out;
    }

    /* door_return() uses the TLS-owned receive buffers directly. */

    if (door_bind_kernel(tls->dt_worker_fd) == -1) {
        error = errno;
        pthread_mutex_lock(&entry->de_pool_lock);
        if (entry->de_workers_starting != 0)
            entry->de_workers_starting--;

        if (entry->de_start_error == 0)
            entry->de_start_error = error;

        pthread_cond_broadcast(&entry->de_pool_cv);
        pthread_mutex_unlock(&entry->de_pool_lock);
        errno = error;
        goto out;
    }

    tls->dt_bound = true;
    (void)close(tls->dt_worker_fd);
    tls->dt_worker_fd = -1;
    door_pool_worker_bound(entry, tls);

    for (;;) {
        if (!have_request) {
            /* Initial wait, callback-return fallback, or recovery wait. */
            if (door_server_wait_resizable(tls, NULL, 0, NULL, 0,
                &ret) == -1) {
                if (door_server_recover(entry, tls, errno, false))
                    continue;

                break;
            }
        }

        have_request = false;

        tls->dt_call_id = ret.dirs_return.dir_call_id;
        tls->dt_is_unref = (ret.dirs_return.dir_flags & DOOR_RETURN_F_UNREF) != 0;
        tls->dt_cred_valid =
            (ret.dirs_return.dir_flags & DOOR_RETURN_F_CRED_LAZY) == 0;
        ret.dirs_return.dir_flags &= ~DOOR_RETURN_F_CRED_LAZY;
        if (tls->dt_cred_valid)
            tls->dt_cred = ret.dirs_return.dir_cred;

        if (door_pool_dispatch_begin(entry, tls)) {
            if (entry->de_pool_type == DOOR_POOL_XCREATE_PRIVATE)
                (void)__door_xcreate_launch(entry, true, NULL);
            else {
                __door_notify_factory(entry, true);
                (void)__door_launch_managed_worker(entry, true);
            }
        }

        if (!tls->dt_is_unref)
            __door_desc_import(tls->dt_public_desc, tls->dt_request_desc,
                ret.dirs_return.dir_request_desc_count);

        tls->dt_return_error = 0;
        tls->dt_next_ready = false;
        tls->dt_reply_submitted = false;
        tls->dt_in_callback = true;
        if (tls->dt_is_unref) {
            entry->de_proc(entry->de_cookie, DOOR_UNREF_DATA, 0, NULL, 0);
        } else if ((ret.dirs_return.dir_flags & DOOR_RETURN_F_SHM) != 0) {
            /*
             * The pointer is valid only in this server process and was
             * bounds/ownership validated by doorfs.  Preserve the normal
             * callback ABI: SHM request data simply arrives as data/size.
             */
            entry->de_proc(entry->de_cookie,
                (char *)(uintptr_t)ret.dirs_shm_ptr,
                (size_t)ret.dirs_shm.disr_size, NULL, 0);
        } else {
            entry->de_proc(entry->de_cookie, tls->dt_request_data,
                (size_t)ret.dirs_return.dir_request_size,
                ret.dirs_return.dir_request_desc_count == 0 ? NULL :
                tls->dt_public_desc,
                ret.dirs_return.dir_request_desc_count);
        }

        tls->dt_in_callback = false;

        if (!tls->dt_reply_submitted) {
            /*
             * Compatibility fallback: a callback that returns without
             * door_return() gets an empty reply on the next server wait.
             */
            door_pool_callback_end(entry, tls);
            continue;
        }


        /* door_return() ended callback accounting before entering the kernel. */
        if (tls->dt_exit_after_return) {
            tls->dt_exit_after_return = false;
            break;
        }

        if (tls->dt_return_error != 0) {
            error = tls->dt_return_error;
            tls->dt_return_error = 0;
            tls->dt_next_ready = false;
            if (door_server_recover(entry, tls, error, true))
                continue;

            break;
        }

        if (!tls->dt_next_ready) {
            if ((tls->dt_next_return.dirs_return.dir_flags &
                DOOR_RETURN_F_REWAIT) != 0) {
                tls->dt_call_id = 0;
                tls->dt_is_unref = false;
                continue;
            }

            errno = EPROTO;
            break;
        }

        ret.dirs_return.dir_call_id =
            tls->dt_next_return.dirs_return.dir_call_id;
        ret.dirs_return.dir_flags =
            tls->dt_next_return.dirs_return.dir_flags;
        ret.dirs_return.dir_request_size =
            tls->dt_next_return.dirs_return.dir_request_size;
        ret.dirs_return.dir_request_desc_count =
            tls->dt_next_return.dirs_return.dir_request_desc_count;
        if ((ret.dirs_return.dir_flags & DOOR_RETURN_F_CRED_LAZY) == 0)
            ret.dirs_return.dir_cred =
                tls->dt_next_return.dirs_return.dir_cred;

        if ((ret.dirs_return.dir_flags & DOOR_RETURN_F_SHM) != 0) {
            ret.dirs_shm = tls->dt_next_return.dirs_shm;
            ret.dirs_shm_ptr = tls->dt_next_return.dirs_shm_ptr;
        }

        tls->dt_next_ready = false;
        have_request = true;
        continue;
    }

out:
    free(tls->dt_public_desc);
    free(tls->dt_request_desc);
    free(tls->dt_request_data);
    tls->dt_public_desc = NULL;
    tls->dt_public_desc_capacity = 0;
    tls->dt_request_data = NULL;
    tls->dt_request_capacity = 0;
    tls->dt_request_desc = NULL;
    tls->dt_request_desc_capacity = 0;
    if (tls->dt_bound)
        (void)__door_syscall(tls->dt_call_id != 0 ?
            DOOR_SC_WORKER_EXIT : DOOR_SC_UNBIND, 0, 0, 0, 0, 0);

    tls->dt_bound = false;
    if (tls->dt_worker_fd >= 0)
        (void)close(tls->dt_worker_fd);

    tls->dt_worker_fd = -1;
    tls->dt_entry = NULL;
    tls->dt_call_id = 0;
    tls->dt_is_unref = false;
    tls->dt_exit_after_return = false;
    door_pool_worker_exited(entry, tls);
    return (NULL);
}

void
__door_notify_factory(struct door_entry *entry, bool depletion)
{
    door_server_func_t *factory;
    door_info_t info;

    pthread_mutex_lock(&__door_lock);
    factory = __door_server_factory;
    pthread_mutex_unlock(&__door_lock);
    if (factory == NULL)
        return;

    if (entry->de_pool_type == DOOR_POOL_SHARED) {
        factory(NULL);
        return;
    }

    memset(&info, 0, sizeof(info));
    info.di_target = getpid();
    info.di_proc = (door_ptr_t)(uintptr_t)entry->de_proc;
    info.di_data = (door_ptr_t)(uintptr_t)entry->de_cookie;
    info.di_attributes = entry->de_attributes | DOOR_LOCAL;
    if (depletion)
        info.di_attributes |= DOOR_DEPLETION_CB;

    factory(&info);
}

int
__door_launch_managed_worker(struct door_entry *entry, bool depletion)
{
    struct door_server_context *context;
    pthread_t thread;
    int error, worker_fd;

    worker_fd = dup(entry->de_fd);
    if (worker_fd == -1)
        return (-1);

    context = calloc(1, sizeof(*context));
    if (context == NULL) {
        error = errno;
        (void)close(worker_fd);
        errno = error;
        return (-1);
    }

    context->dsc_entry = entry;
    context->dsc_worker_fd = worker_fd;
    context->dsc_xcreate = false;

    pthread_mutex_lock(&entry->de_pool_lock);
    if (entry->de_pool_stopping) {
        pthread_mutex_unlock(&entry->de_pool_lock);
        free(context);
        (void)close(worker_fd);
        errno = EBADF;
        return (-1);
    }

    entry->de_workers_starting++;
    pthread_mutex_unlock(&entry->de_pool_lock);

    error = pthread_create(&thread, NULL, __door_server_main, context);
    if (error != 0) {
        pthread_mutex_lock(&entry->de_pool_lock);
        if (entry->de_workers_starting != 0)
            entry->de_workers_starting--;

        entry->de_depletion_in_progress = false;
        pthread_cond_broadcast(&entry->de_pool_cv);
        pthread_mutex_unlock(&entry->de_pool_lock);
        free(context);
        (void)close(worker_fd);
        errno = error;
        return (-1);
    }

    (void)pthread_detach(thread);
    (void)depletion;
    return (0);
}

int
__door_spawn_server(struct door_entry *entry)
{
    __door_notify_factory(entry, false);
    return (__door_launch_managed_worker(entry, false));
}

int
door_return(char *data_ptr, size_t data_size, door_desc_t *desc,
    uint_t desc_count)
{
    struct door_tls *tls;
    struct door_entry *entry;

    tls = __door_tls_get(false);
    if (tls == NULL || tls->dt_entry == NULL || !tls->dt_in_callback ||
        tls->dt_reply_submitted ||
        (data_size != 0 && data_ptr == NULL) ||
        (desc_count != 0 && desc == NULL) ||
        (tls->dt_is_unref && (data_size != 0 || desc_count != 0))) {
        errno = EINVAL;
        return (-1);
    }

    entry = tls->dt_entry;
    tls->dt_reply_submitted = true;

    /*
     * ONEWAY has no reply channel.  Keep existing callbacks reusable by
     * treating any door_return() payload as intentionally discarded and send
     * only the server-completion token to the kernel.
     */
    if ((entry->de_attributes & DOOR_ONEWAY) != 0) {
        data_ptr = NULL;
        data_size = 0;
        desc = NULL;
        desc_count = 0;
    }

    /*
     * Keep the callback frame alive until RETURN consumes its reply pointers.
     * Success may stage the next request, or report EXIT/REWAIT without one.
     */
    door_pool_callback_end(entry, tls);
    if (door_server_wait_resizable(tls, data_ptr, data_size, desc,
        desc_count, &tls->dt_next_return) == -1) {
        tls->dt_return_error = errno;
        tls->dt_next_ready = false;
    } else if ((tls->dt_next_return.dirs_return.dir_flags &
        DOOR_RETURN_F_EXIT) != 0) {
        /*
         * The current ONEWAY completion was accepted, but revoke removed
         * this worker binding instead of entering another wait.  This is a
         * successful door_return() for the callback and a graceful worker
         * termination condition for the pool.
         */
        tls->dt_return_error = 0;
        tls->dt_next_ready = false;
        tls->dt_exit_after_return = true;
        tls->dt_bound = false;
    } else if ((tls->dt_next_return.dirs_return.dir_flags &
        DOOR_RETURN_F_REWAIT) != 0) {
        tls->dt_return_error = 0;
        tls->dt_next_ready = false;
    } else {
        tls->dt_return_error = 0;
        tls->dt_next_ready = true;
    }

    /*
     * The callback can unwind after its reply was consumed. Only dt_next_ready
     * means a request is staged; EXIT/REWAIT follow the worker's separate paths.
     */
    if (tls->dt_return_error != 0)
        return (-1);

    return (0);
}

door_server_func_t *
door_server_create(door_server_func_t *new_func)
{
    door_server_func_t *old_func;

    pthread_mutex_lock(&__door_lock);
    old_func = __door_server_factory;
    __door_server_factory = new_func;
    pthread_mutex_unlock(&__door_lock);
    return (old_func);
}


int
__door_xcreate_launch(struct door_entry *entry, bool depletion, int *errorp)
{
    struct door_server_context *context;
    door_info_t info;
    int rc, worker_fd, error;

    if (errorp != NULL)
        *errorp = 0;

    worker_fd = dup(entry->de_fd);
    if (worker_fd == -1) {
        if (errorp != NULL)
            *errorp = errno;

        return (-1);
    }

    context = calloc(1, sizeof(*context));
    if (context == NULL) {
        error = errno;
        (void)close(worker_fd);
        if (errorp != NULL)
            *errorp = error;

        errno = error;
        return (-1);
    }

    context->dsc_entry = entry;
    context->dsc_worker_fd = worker_fd;
    context->dsc_xcreate = true;

    memset(&info, 0, sizeof(info));
    info.di_target = getpid();
    info.di_proc = (door_ptr_t)(uintptr_t)entry->de_proc;
    info.di_data = (door_ptr_t)(uintptr_t)entry->de_cookie;
    info.di_attributes = entry->de_attributes | DOOR_LOCAL;
    if (depletion)
        info.di_attributes |= DOOR_DEPLETION_CB;

    pthread_mutex_lock(&entry->de_pool_lock);
    if (entry->de_pool_stopping) {
        pthread_mutex_unlock(&entry->de_pool_lock);
        free(context);
        (void)close(worker_fd);
        if (errorp != NULL)
            *errorp = EBADF;

        errno = EBADF;
        return (-1);
    }

    entry->de_workers_starting++;
    pthread_mutex_unlock(&entry->de_pool_lock);

    errno = 0;
    rc = entry->de_xcreate_server(&info, __door_server_main, context,
        entry->de_setup_cookie);
    if (rc == 1)
        return (1);

    error = depletion ?
        (rc == 0 ? 0 : (errno != 0 ? errno : EPIPE)) :
        (rc == 0 ? EINVAL : EPIPE);
    pthread_mutex_lock(&entry->de_pool_lock);
    if (entry->de_workers_starting != 0)
        entry->de_workers_starting--;

    if (!depletion && entry->de_start_error == 0)
        entry->de_start_error = error;

    if (depletion) {
        entry->de_depletion_in_progress = false;
        entry->de_depletion_armed = false;
    }

    pthread_cond_broadcast(&entry->de_pool_cv);
    pthread_mutex_unlock(&entry->de_pool_lock);
    free(context);
    (void)close(worker_fd);

    if (errorp != NULL)
        *errorp = error;

    if (error != 0)
        errno = error;

    return (rc == 0 ? 0 : -1);
}

int
door_xcreate(door_server_procedure_t *proc, void *cookie, uint_t attributes,
    door_xcreate_server_func_t *server_create,
    door_xcreate_thrsetup_func_t *thread_setup, void *setup_cookie,
    int nthreads)
{
    struct door_entry *entry;
    unsigned int launched;
    int fd, error, i, rc;

    if (proc == NULL || server_create == NULL || nthreads < 1 ||
        (attributes & ~DOOR_CREATE_MASK) != 0 ||
        (attributes & DOOR_PRIVCREATE) != 0) {
        errno = EINVAL;
        return (-1);
    }

    attributes |= DOOR_PRIVATE;
    fd = __door_create_common(proc, cookie, attributes,
        DOOR_CREATE_F_XCREATE, &entry);
    if (fd == -1)
        return (-1);

    entry->de_xcreate_server = server_create;
    entry->de_thrsetup = thread_setup;
    entry->de_setup_cookie = setup_cookie;
    entry->de_initial_threads = nthreads;
    entry->de_attributes |= DOOR_PRIVATE | DOOR_PRIVCREATE;

    error = 0;
    launched = 0;
    for (i = 0; i < nthreads; i++) {
        rc = __door_xcreate_launch(entry, false, &error);
        if (rc == 1) {
            launched++;
            continue;
        }

        if (error == 0)
            error = rc == 0 ? EINVAL : EPIPE;

        break;
    }

    pthread_mutex_lock(&entry->de_pool_lock);
    while (error == 0 && entry->de_start_error == 0 &&
        entry->de_workers_ready < (unsigned int)nthreads)
        pthread_cond_wait(&entry->de_pool_cv, &entry->de_pool_lock);

    if (error == 0)
        error = entry->de_start_error;

    pthread_mutex_unlock(&entry->de_pool_lock);

    if (error == 0)
        return (fd);

    (void)door_revoke(fd);
    pthread_mutex_lock(&entry->de_pool_lock);
    while (entry->de_workers_exited < launched)
        pthread_cond_wait(&entry->de_pool_cv, &entry->de_pool_lock);

    pthread_mutex_unlock(&entry->de_pool_lock);
    (void)close(fd);
    errno = error;
    return (-1);
}
