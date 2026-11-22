/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/queue.h>

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <door.h>

#include "libdoor_impl.h"

#define DOOR_ASYNC_MAGIC 0x44415359U
#define DOOR_ASYNC_VERSION 1U
#define DOOR_ASYNC_REQUEST 1U
#define DOOR_ASYNC_RESPONSE 2U
#define DOOR_ASYNC_PROCESS_LIMIT 4096U

static pthread_once_t door_async_once = PTHREAD_ONCE_INIT;
static atomic_size_t door_async_process_count;
static int door_async_atfork_error;
static void
door_async_atfork_child(void)
{
    atomic_store_explicit(&door_async_process_count, 0,
        memory_order_relaxed);
}

static void
door_async_initialize(void)
{
    door_async_atfork_error = pthread_atfork(NULL, NULL,
        door_async_atfork_child);
}

static int
door_async_reserve_process_slot(void)
{
    size_t count;

    count = atomic_load_explicit(&door_async_process_count,
        memory_order_relaxed);
    for (;;) {
        if (count >= DOOR_ASYNC_PROCESS_LIMIT) {
            errno = EAGAIN;
            return (-1);
        }

        if (atomic_compare_exchange_weak_explicit(&door_async_process_count,
            &count, count + 1, memory_order_relaxed,
            memory_order_relaxed))
            return (0);
    }
}

static void
door_async_release_process_slot(void)
{
    atomic_fetch_sub_explicit(&door_async_process_count, 1,
        memory_order_relaxed);
}

struct door_async_wire {
    uint32_t daw_magic;
    uint16_t daw_version;
    uint16_t daw_type;
    uint64_t daw_id;
    uint64_t daw_token;
    int32_t daw_status;
    uint32_t daw_reserved;
};
_Static_assert(sizeof(struct door_async_wire) == 32,
    "async wire header must have a stable size");

/* Copied legacy async protocol header, shared across process data models. */
_Static_assert(offsetof(struct door_async_wire, daw_magic) == 0,
    "door_async_wire.daw_magic wire offset");
_Static_assert(offsetof(struct door_async_wire, daw_version) == 4,
    "door_async_wire.daw_version wire offset");
_Static_assert(offsetof(struct door_async_wire, daw_type) == 6,
    "door_async_wire.daw_type wire offset");
_Static_assert(offsetof(struct door_async_wire, daw_id) == 8,
    "door_async_wire.daw_id wire offset");
_Static_assert(offsetof(struct door_async_wire, daw_token) == 16,
    "door_async_wire.daw_token wire offset");
_Static_assert(offsetof(struct door_async_wire, daw_status) == 24,
    "door_async_wire.daw_status wire offset");
_Static_assert(offsetof(struct door_async_wire, daw_reserved) == 28,
    "door_async_wire.daw_reserved wire offset");

struct door_async_pending {
    TAILQ_ENTRY(door_async_pending) dap_link;
    uint64_t dap_id;
    door_async_completion_t *dap_completion;
    door_async_completion_desc_t *dap_completion_desc;
    void *dap_cookie;
};
TAILQ_HEAD(door_async_pending_head, door_async_pending);

struct door_async {
    pthread_mutex_t da_lock;
    pthread_cond_t da_cv;
    struct door_async_pending_head da_pending;
    struct door_entry *da_reply_entry;
    uint64_t da_token;
    uint64_t da_next_id;
    size_t da_limit;
    size_t da_count;
    unsigned int da_submitting;
    unsigned int da_callbacks;
    pid_t da_pid;
    int da_request_fd;
    int da_reply_fd;
    void *da_dispatch_buffer;
    bool da_manual;
    bool da_dispatching;
    bool da_kernel;
    bool da_closing;
    bool da_draining;
};

struct door_async_frame {
    struct door_async *context;
    struct door_async_frame *previous;
};
static _Thread_local struct door_async_frame *door_async_frames;

static bool
door_async_in_callback(struct door_async *ctx)
{
    struct door_async_frame *frame;

    for (frame = door_async_frames; frame != NULL; frame = frame->previous)
        if (frame->context == ctx)
            return (true);

    return (false);
}

static int
door_async_unpack(const void *data, size_t size, uint16_t type,
    struct door_async_wire *wire)
{
    if (data == NULL || size < sizeof(*wire)) {
        errno = EPROTO;
        return (-1);
    }

    memcpy(wire, data, sizeof(*wire));
    if (wire->daw_magic != DOOR_ASYNC_MAGIC ||
        wire->daw_version != DOOR_ASYNC_VERSION ||
        wire->daw_type != type || wire->daw_id == 0 ||
        wire->daw_token == 0 || wire->daw_reserved != 0 ||
        (type == DOOR_ASYNC_REQUEST && wire->daw_status != 0)) {
        errno = EPROTO;
        return (-1);
    }

    return (0);
}

/* Keep descriptor arrays off the ordinary data-only completion stack. */
static void
door_async_receive_descriptors(struct door_async *ctx,
    struct door_async_pending *pending, uint64_t id,
    const char *body, size_t body_size)
{
    struct door_ioc_async_recv_desc receive;
    struct door_kdesc kdesc[DOOR_ASYNC_DESC_MAX];
    door_desc_t public_desc[DOOR_ASYNC_DESC_MAX];
    uint_t received;
    int rc, status;

    received = 0;
    status = 0;
    memset(&receive, 0, sizeof(receive));
    receive.diard_version = DOOR_ABI_VERSION;
    receive.diard_capacity = DOOR_ASYNC_DESC_MAX;
    receive.diard_call_id = id;
    receive.diard_desc_ptr = (uint64_t)(uintptr_t)kdesc;
    receive.diard_completion_fd = ctx->da_reply_fd;
    rc = (int)__door_syscall(DOOR_SC_ASYNC_RECV_DESC,
        ctx->da_request_fd, (long)(uintptr_t)&receive, 0, 0, 0);
    if (rc == -1)
        status = errno;
    else {
        received = (uint_t)rc;
        __door_desc_import(public_desc, kdesc, received);
    }

    if (pending->dap_completion_desc != NULL) {
        pending->dap_completion_desc(id, status,
            status == 0 ? body : NULL, status == 0 ? body_size : 0,
            received != 0 ? public_desc : NULL, received,
            pending->dap_cookie);
    } else {
        /* A data-only submission cannot legitimately receive descriptors. */
        for (uint_t i = 0; i < received; i++)
            (void)close(public_desc[i].d_descriptor);
        pending->dap_completion(id, received != 0 ? EPROTO : status,
            status == 0 && received == 0 ? body : NULL,
            status == 0 && received == 0 ? body_size : 0,
            pending->dap_cookie);
    }
}

static void
door_async_receive(void *cookie, char *data, size_t size,
    door_desc_t *desc, uint_t ndesc)
{
    struct door_async *ctx;
    struct door_async_pending *pending;
    struct door_async_wire wire;
    struct door_async_completion kresult;
    struct door_async_frame frame;
    bool has_desc;
    const char *body;
    size_t body_size;
    uint64_t id;
    int status;

    ctx = cookie;
    has_desc = false;
    if (ndesc != 0 || desc != NULL)
        return;

    if (ctx->da_kernel) {
        if (data == NULL || size < sizeof(kresult))
            return;

        memcpy(&kresult, data, sizeof(kresult));
        if (kresult.dac_version != DOOR_ABI_VERSION ||
            (kresult.dac_flags & ~DOOR_ASYNC_C_FLAG_MASK) != 0 ||
            kresult.dac_reserved != 0 ||
            kresult.dac_call_id == 0 || kresult.dac_status < 0 ||
            kresult.dac_data_size != size - sizeof(kresult) ||
            (kresult.dac_status != 0 && kresult.dac_data_size != 0))
            return;

        id = kresult.dac_call_id;
        status = kresult.dac_status;
        has_desc = (kresult.dac_flags & DOOR_ASYNC_C_REPLY_DESC) != 0;
        if (has_desc && status != 0)
            return;
        body = data + sizeof(kresult);
        body_size = (size_t)kresult.dac_data_size;
    } else {
        if (door_async_unpack(data, size, DOOR_ASYNC_RESPONSE,
            &wire) == -1 || wire.daw_token != ctx->da_token ||
            wire.daw_status < 0)
            return;

        id = wire.daw_id;
        status = wire.daw_status;
        body = data + sizeof(wire);
        body_size = size - sizeof(wire);
    }

    pthread_mutex_lock(&ctx->da_lock);
    /* After successful revoke, only close may claim remaining records. */
    if (ctx->da_draining) {
        pthread_mutex_unlock(&ctx->da_lock);
        return;
    }

    TAILQ_FOREACH(pending, &ctx->da_pending, dap_link) {
        if (pending->dap_id == id)
            break;
    }

    if (pending != NULL) {
        TAILQ_REMOVE(&ctx->da_pending, pending, dap_link);
        ctx->da_count--;
        ctx->da_callbacks++;
        door_async_release_process_slot();
    }

    pthread_mutex_unlock(&ctx->da_lock);
    if (pending == NULL)
        return;

    frame.context = ctx;
    frame.previous = door_async_frames;
    door_async_frames = &frame;
    /* The callback may submit again; never call user code under da_lock. */
    if (has_desc) {
        door_async_receive_descriptors(ctx, pending, id, body, body_size);
    } else if (pending->dap_completion_desc != NULL) {
        pending->dap_completion_desc(id, status,
            status == 0 ? body : NULL, status == 0 ? body_size : 0,
            NULL, 0, pending->dap_cookie);
    } else {
        pending->dap_completion(id, status,
            status == 0 ? body : NULL, status == 0 ? body_size : 0,
            pending->dap_cookie);
    }
    door_async_frames = frame.previous;
    free(pending);
    /* This is the final ctx access: close may free it after the unlock. */
    pthread_mutex_lock(&ctx->da_lock);
    ctx->da_callbacks--;
    pthread_cond_broadcast(&ctx->da_cv);
    pthread_mutex_unlock(&ctx->da_lock);
}

static int
door_async_open_common(int request_fd, size_t max_pending, door_async_t **out,
    bool manual)
{
    struct door_async *ctx;
    door_info_t info;
    int error;

    if (out == NULL || request_fd < 0 || max_pending == 0) {
        errno = EINVAL;
        return (-1);
    }

    *out = NULL;
    error = pthread_once(&door_async_once, door_async_initialize);
    if (error == 0)
        error = door_async_atfork_error;

    if (error != 0) {
        errno = error;
        return (-1);
    }

    if (door_info(request_fd, &info) == -1)
        return (-1);
    if (manual && (info.di_attributes & DOOR_ONEWAY) != 0) {
        errno = ENOTSUP;
        return (-1);
    }

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
        return (-1);

    ctx->da_request_fd = -1;
    ctx->da_reply_fd = -1;
    ctx->da_pid = getpid();
    ctx->da_kernel = (info.di_attributes & DOOR_ONEWAY) == 0;
    ctx->da_limit = max_pending;
    ctx->da_manual = manual;
    TAILQ_INIT(&ctx->da_pending);
    error = pthread_mutex_init(&ctx->da_lock, NULL);
    if (error != 0) {
        free(ctx);
        errno = error;
        return (-1);
    }

    error = pthread_cond_init(&ctx->da_cv, NULL);
    if (error != 0)
        goto fail_mutex;

    ctx->da_request_fd = dup(request_fd);
    if (ctx->da_request_fd == -1) {
        error = errno;
        goto fail_cond;
    }

    do {
        arc4random_buf(&ctx->da_token, sizeof(ctx->da_token));
    } while (ctx->da_token == 0 || ctx->da_token == UINT64_MAX);

    ctx->da_next_id = ctx->da_token;
    if (manual) {
        ctx->da_dispatch_buffer = malloc(sizeof(struct door_async_completion) +
            64U * 1024U);
        if (ctx->da_dispatch_buffer == NULL) {
            error = errno;
            goto fail_fd;
        }

        ctx->da_reply_fd = (int)__door_syscall(DOOR_SC_CREATE,
            DOOR_ONEWAY | DOOR_PRIVATE | DOOR_NO_DEPLETION_CB, 0,
            DOOR_CREATE_F_COMPLETION, 0, 0);
    } else {
        ctx->da_reply_fd = door_create(door_async_receive, ctx,
            DOOR_ONEWAY | DOOR_PRIVATE | DOOR_NO_DEPLETION_CB);
    }
    if (ctx->da_reply_fd == -1) {
        error = errno;
        free(ctx->da_dispatch_buffer);
        goto fail_fd;
    }

    if (!manual)
        ctx->da_reply_entry = __door_entry_lookup(ctx->da_reply_fd);
    *out = ctx;
    return (0);

fail_fd:
    close(ctx->da_request_fd);
fail_cond:
    pthread_cond_destroy(&ctx->da_cv);
fail_mutex:
    pthread_mutex_destroy(&ctx->da_lock);
    free(ctx);
    errno = error;
    return (-1);
}

int
door_async_open(int request_fd, size_t max_pending, door_async_t **out)
{
    return (door_async_open_common(request_fd, max_pending, out, false));
}

int
door_async_open_poll(int request_fd, size_t max_pending, door_async_t **out)
{
    return (door_async_open_common(request_fd, max_pending, out, true));
}

int
door_async_poll_fd(const door_async_t *ctx)
{
    if (ctx == NULL || ctx->da_pid != getpid()) {
        errno = EINVAL;
        return (-1);
    }
    if (!ctx->da_manual) {
        errno = ENOTSUP;
        return (-1);
    }

    return (ctx->da_reply_fd);
}

/* No receive wait. User callbacks and descriptor acknowledgement can block. */
int
door_async_dispatch(door_async_t *ctx, unsigned int budget)
{
    ssize_t received;
    unsigned int count;
    int error;

    if (ctx == NULL || ctx->da_pid != getpid() || budget == 0 ||
        budget > INT_MAX) {
        errno = EINVAL;
        return (-1);
    }

    pthread_mutex_lock(&ctx->da_lock);
    error = !ctx->da_manual ? ENOTSUP : ctx->da_closing ? EBADF :
        ctx->da_dispatching ? EBUSY : 0;
    if (error != 0) {
        pthread_mutex_unlock(&ctx->da_lock);
        errno = error;
        return (-1);
    }

    ctx->da_dispatching = true;
    pthread_mutex_unlock(&ctx->da_lock);
    count = 0;
    error = 0;
    while (count < budget) {
        received = read(ctx->da_reply_fd, ctx->da_dispatch_buffer,
            sizeof(struct door_async_completion) + 64U * 1024U);
        if (received == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                error = errno;
            break;
        }
        if (received == 0) {
            error = EPIPE;
            break;
        }

        door_async_receive(ctx, ctx->da_dispatch_buffer, (size_t)received,
            NULL, 0);
        count++;
    }

    pthread_mutex_lock(&ctx->da_lock);
    ctx->da_dispatching = false;
    pthread_cond_broadcast(&ctx->da_cv);
    pthread_mutex_unlock(&ctx->da_lock);
    if (count == 0 && error != 0) {
        errno = error;
        return (-1);
    }

    return ((int)count);
}

int
door_async_reply_fd(const door_async_t *ctx)
{
    if (ctx == NULL || ctx->da_pid != getpid()) {
        errno = EINVAL;
        return (-1);
    }

    if (ctx->da_kernel) {
        errno = ENOTSUP;
        return (-1);
    }

    return (ctx->da_reply_fd);
}

int
door_async_token(const door_async_t *ctx, uint64_t *out)
{
    if (ctx == NULL || out == NULL || ctx->da_pid != getpid()) {
        errno = EINVAL;
        return (-1);
    }

    if (ctx->da_kernel) {
        errno = ENOTSUP;
        return (-1);
    }

    *out = ctx->da_token;
    return (0);
}

static int
door_async_submit_impl(door_async_t *ctx, const void *data, size_t size,
    door_async_completion_t *completion,
    door_async_completion_desc_t *completion_desc, void *cookie,
    uint64_t *id_out)
{
    struct door_async_pending *pending;
    struct door_async_wire *wire;
    struct door_ioc_async_call kernel_call;
    uint64_t id;
    size_t length;
    int error, rc;

    if (ctx == NULL || ctx->da_pid != getpid() ||
        (completion == NULL && completion_desc == NULL) ||
        (size != 0 && data == NULL) ||
        size > SIZE_MAX - sizeof(*wire)) {
        errno = EINVAL;
        return (-1);
    }

    if (completion_desc != NULL && !ctx->da_kernel) {
        errno = ENOTSUP;
        return (-1);
    }

    pending = calloc(1, sizeof(*pending));
    if (pending == NULL)
        return (-1);

    wire = NULL;
    length = sizeof(*wire) + size;
    if (!ctx->da_kernel) {
        wire = malloc(length);
        if (wire == NULL) {
            error = errno;
            goto fail_alloc;
        }
    }

    pthread_mutex_lock(&ctx->da_lock);
    if (ctx->da_closing || ctx->da_count >= ctx->da_limit ||
        ctx->da_next_id == UINT64_MAX) {
        error = ctx->da_closing ? EBADF :
            ctx->da_next_id == UINT64_MAX ? EOVERFLOW : EAGAIN;
        pthread_mutex_unlock(&ctx->da_lock);
        goto fail_alloc;
    }

    if (door_async_reserve_process_slot() == -1) {
        error = errno;
        pthread_mutex_unlock(&ctx->da_lock);
        goto fail_alloc;
    }

    pending->dap_id = ++ctx->da_next_id;
    id = pending->dap_id;
    pending->dap_completion = completion;
    pending->dap_completion_desc = completion_desc;
    pending->dap_cookie = cookie;
    /* Completion may beat syscall return; publish its lookup first. */
    TAILQ_INSERT_TAIL(&ctx->da_pending, pending, dap_link);
    ctx->da_count++;
    /* close must not free ctx while submit still uses it after the syscall. */
    ctx->da_submitting++;
    if (id_out != NULL)
        *id_out = id;

    pthread_mutex_unlock(&ctx->da_lock);

    if (ctx->da_kernel) {
        memset(&kernel_call, 0, sizeof(kernel_call));
        kernel_call.diac_version = DOOR_ABI_VERSION;
        if (completion_desc != NULL)
            kernel_call.diac_flags = DOOR_ASYNC_F_REPLY_DESC;
        kernel_call.diac_call_id = id;
        kernel_call.diac_request_ptr = (uint64_t)(uintptr_t)data;
        kernel_call.diac_request_size = size;
        kernel_call.diac_completion_fd = ctx->da_reply_fd;

        rc = (int)__door_syscall(DOOR_SC_ASYNC_CALL, ctx->da_request_fd,
            (long)(uintptr_t)&kernel_call, 0, 0, 0);
    } else {
        memset(wire, 0, sizeof(*wire));
        wire->daw_magic = DOOR_ASYNC_MAGIC;
        wire->daw_version = DOOR_ASYNC_VERSION;
        wire->daw_type = DOOR_ASYNC_REQUEST;
        wire->daw_id = id;
        wire->daw_token = ctx->da_token;
        if (size != 0)
            memcpy(wire + 1, data, size);

        rc = door_oneway(ctx->da_request_fd, wire, length);
    }

    error = errno;

    free(wire);
    pthread_mutex_lock(&ctx->da_lock);
    /* Failed submission owns its record; success may already have freed it. */
    if (rc == -1) {
        TAILQ_REMOVE(&ctx->da_pending, pending, dap_link);
        ctx->da_count--;
        door_async_release_process_slot();
        if (id_out != NULL)
            *id_out = 0;
    }

    ctx->da_submitting--;
    pthread_cond_broadcast(&ctx->da_cv);
    pthread_mutex_unlock(&ctx->da_lock);
    if (rc == -1) {
        free(pending);
        errno = error;
    }

    return (rc);

fail_alloc:
    free(wire);
    free(pending);
    errno = error;
    return (-1);
}

int
door_async_submit(door_async_t *ctx, const void *data, size_t size,
    door_async_completion_t *completion, void *cookie, uint64_t *id_out)
{
    if (completion == NULL) {
        errno = EINVAL;
        return (-1);
    }

    return (door_async_submit_impl(ctx, data, size, completion, NULL,
        cookie, id_out));
}

int
door_async_submit_desc(door_async_t *ctx, const void *data, size_t size,
    door_async_completion_desc_t *completion, void *cookie, uint64_t *id_out)
{
    if (completion == NULL) {
        errno = EINVAL;
        return (-1);
    }

    return (door_async_submit_impl(ctx, data, size, NULL, completion,
        cookie, id_out));
}

int
door_async_request_parse(const void *data, size_t size,
    door_async_request_t *out)
{
    struct door_async_wire wire;
    ucred_t *cred;

    if (out == NULL) {
        errno = EINVAL;
        return (-1);
    }

    if (door_async_unpack(data, size, DOOR_ASYNC_REQUEST, &wire) == -1)
        return (-1);

    /* A shared request Door must authenticate the session before replying. */
    if (door_ucred(&cred) == -1)
        return (-1);

    out->dar_id = wire.daw_id;
    out->dar_token = wire.daw_token;
    out->dar_pid = cred->du_pid;
    out->dar_jid = cred->du_jid;
    out->dar_data = (const char *)data + sizeof(wire);
    out->dar_size = size - sizeof(wire);
    return (0);
}

int
door_async_cancel(door_async_t *ctx, uint64_t id)
{
#if ULONG_MAX < UINT64_MAX
    struct door_ioc_async_cancel arg;
#endif
    if (ctx == NULL || ctx->da_pid != getpid() || id == 0) {
        errno = EINVAL;
        return (-1);
    }

    if (!ctx->da_kernel) {
        errno = ENOTSUP;
        return (-1);
    }
#if ULONG_MAX < UINT64_MAX
    memset(&arg, 0, sizeof(arg));
    arg.diacc_version = DOOR_ABI_VERSION;
    arg.diacc_completion_fd = ctx->da_reply_fd;
    arg.diacc_call_id = id;
    return ((int)__door_syscall(DOOR_SC_ASYNC_CANCEL_FULL,
        ctx->da_request_fd, (long)(uintptr_t)&arg, 0, 0, 0));
#else
    return ((int)__door_syscall(DOOR_SC_ASYNC_CANCEL,
        ctx->da_request_fd, ctx->da_reply_fd, (long)id, 0, 0));
#endif
}

int
door_async_respond(int reply_fd, const door_async_request_t *request,
    int status, const void *data, size_t size)
{
    struct door_async_wire *wire;
    int rc;

    if (reply_fd < 0 || request == NULL || request->dar_id == 0 ||
        request->dar_token == 0 || status < 0 ||
        (status != 0 && size != 0) || (size != 0 && data == NULL) ||
        size > SIZE_MAX - sizeof(*wire)) {
        errno = EINVAL;
        return (-1);
    }

    wire = calloc(1, sizeof(*wire) + size);
    if (wire == NULL)
        return (-1);

    wire->daw_magic = DOOR_ASYNC_MAGIC;
    wire->daw_version = DOOR_ASYNC_VERSION;
    wire->daw_type = DOOR_ASYNC_RESPONSE;
    wire->daw_id = request->dar_id;
    wire->daw_token = request->dar_token;
    wire->daw_status = status;
    if (size != 0)
        memcpy(wire + 1, data, size);

    rc = door_oneway(reply_fd, wire, sizeof(*wire) + size);
    free(wire);
    return (rc);
}

int
door_async_close(door_async_t *ctx)
{
    struct door_async_pending *pending;
    struct door_entry *entry;
    int error;

    /* Closing here would wait for the callback worker executing this call. */
    if (ctx == NULL || ctx->da_pid != getpid() ||
        door_async_in_callback(ctx)) {
        errno = EINVAL;
        return (-1);
    }

    pthread_mutex_lock(&ctx->da_lock);
    if (ctx->da_closing) {
        pthread_mutex_unlock(&ctx->da_lock);
        errno = EALREADY;
        return (-1);
    }

    ctx->da_closing = true;
    while (ctx->da_submitting != 0)
        pthread_cond_wait(&ctx->da_cv, &ctx->da_lock);

    pthread_mutex_unlock(&ctx->da_lock);

    if (door_revoke(ctx->da_reply_fd) == -1 &&
        !(ctx->da_manual && errno == EBADF)) {
        error = errno;
        pthread_mutex_lock(&ctx->da_lock);
        ctx->da_closing = false;
        pthread_mutex_unlock(&ctx->da_lock);
        errno = error;
        return (-1);
    }

    pthread_mutex_lock(&ctx->da_lock);
    ctx->da_draining = true;
    pthread_mutex_unlock(&ctx->da_lock);
    entry = ctx->da_reply_entry;
    if (entry != NULL) {
        pthread_mutex_lock(&entry->de_pool_lock);
        /* Compatibility callback mode only; manual mode has no worker entry. */
        while (entry->de_workers_live != 0 || entry->de_workers_starting != 0)
            pthread_cond_wait(&entry->de_pool_cv, &entry->de_pool_lock);

        pthread_mutex_unlock(&entry->de_pool_lock);
    }

    /* A claimed completion owns ctx until its user callback has unwound. */
    pthread_mutex_lock(&ctx->da_lock);
    while (ctx->da_callbacks != 0 || ctx->da_dispatching)
        pthread_cond_wait(&ctx->da_cv, &ctx->da_lock);

    pthread_mutex_unlock(&ctx->da_lock);

    close(ctx->da_reply_fd);
    close(ctx->da_request_fd);
    /* Local close drain runs here, on the caller, not a reply worker.
     * This does not join callbacks executing at the request peer. */
    while ((pending = TAILQ_FIRST(&ctx->da_pending)) != NULL) {
        TAILQ_REMOVE(&ctx->da_pending, pending, dap_link);
        door_async_release_process_slot();
        if (pending->dap_completion_desc != NULL)
            pending->dap_completion_desc(pending->dap_id, ECANCELED,
                NULL, 0, NULL, 0, pending->dap_cookie);
        else
            pending->dap_completion(pending->dap_id, ECANCELED, NULL, 0,
                pending->dap_cookie);
        free(pending);
    }

    free(ctx->da_dispatch_buffer);
    pthread_cond_destroy(&ctx->da_cv);
    pthread_mutex_destroy(&ctx->da_lock);
    free(ctx);
    return (0);
}
