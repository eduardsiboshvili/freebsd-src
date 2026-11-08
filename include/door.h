/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*-
 * Public libdoor interface for FreeBSD.
 *
 * This header preserves the public illumos Doors source interface while the
 * implementation uses the FreeBSD doorfs kernel transport.  Public structure
 * layouts and exported symbols form libdoor ABI 1 and must not be changed
 * incompatibly without a new shared-library major or symbol version.
 */
#ifndef _DOOR_H_
#define _DOOR_H_

#include <sys/door_core.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _UINT_T_DECLARED
typedef unsigned int uint_t;
#define _UINT_T_DECLARED
#endif

/*
 * ABI values used by door_info_t.  They are fixed-width handles rather than
 * native C pointers so the public layout is stable across data models.
 * di_proc and di_data may be converted back to process-local pointers only
 * when DOOR_LOCAL is present in di_attributes.
 */
typedef uint64_t door_ptr_t;
typedef uint64_t door_id_t;
typedef uint32_t door_attr_t;

#define DOOR_INVAL             (-1)    /* Invalid door descriptor. */
#define DOOR_QUERY             (-2)    /* Query the current worker binding. */

/*
 * data_ptr value delivered to a DOOR_UNREF callback.  It is a sentinel and
 * must not be dereferenced.  The callback receives data_size == 0 and no
 * descriptors.
 */
#define DOOR_UNREF_DATA        ((void *)(uintptr_t)1)

/* State attributes returned by door_info() or a creation callback. */
#define DOOR_LOCAL             DOOR_INFO_LOCAL
#define DOOR_REVOKED           DOOR_INFO_REVOKED
#define DOOR_IS_UNREF          0x00000020U /* Current callback is unref. */
#define DOOR_DEPLETION_CB      0x00000400U /* Transient depletion callback. */

/*
 * DOOR_UNREF_MULTI implies DOOR_UNREF and is normalized by libdoor.
 * DOOR_PRIVCREATE is included for illumos mask compatibility but is
 * output-only: applications must not pass it to either creation function.
 */
#define DOOR_CREATE_MASK (DOOR_UNREF | DOOR_PRIVATE | DOOR_UNREF_MULTI | \
    DOOR_REFUSE_DESC | DOOR_NO_CANCEL | DOOR_NO_DEPLETION_CB | \
    DOOR_PRIVCREATE | DOOR_ONEWAY | DOOR_NO_RETURN | DOOR_CROSS_JAIL | \
    DOOR_NO_CRED)
#define DOOR_ATTR_MASK (DOOR_CREATE_MASK | DOOR_LOCAL | DOOR_REVOKED | \
    DOOR_IS_UNREF)

/* door_desc_t attributes. */
#define DOOR_DESCRIPTOR        0x00010000U /* d_descriptor contains an fd. */
#define DOOR_RELEASE           0x00040000U /* Transactionally move source fd. */

/*
 * The 4-byte packing of door_desc_t and door_info_t is part of ABI 1 and
 * matches the illumos x86 layout on amd64.
 */
#if defined(__GNUC__) || defined(__clang__)
#pragma pack(push, 4)
#endif

/* Descriptor metadata passed with an invocation or reply. */
typedef struct door_desc {
    door_attr_t d_attributes;
    union {
        struct {
            int d_descriptor;
            door_id_t d_id;
        } d_desc;
        int d_resv[5];
    } d_data;
} door_desc_t;

#define d_descriptor d_data.d_desc.d_descriptor
#define d_id         d_data.d_desc.d_id

/* Information returned by door_info().  di_resv must remain zero. */
typedef struct door_info {
    pid_t di_target;             /* Owner/server process, or -1 if dead. */
    door_ptr_t di_proc;          /* Local server procedure handle. */
    door_ptr_t di_data;          /* Creation cookie handle. */
    door_attr_t di_attributes;   /* Creation and current-state flags. */
    door_id_t di_uniquifier;     /* Stable identity of this door object. */
    int di_resv[4];              /* Reserved; applications must ignore. */
} door_info_t;

#if defined(__GNUC__) || defined(__clang__)
#pragma pack(pop)
#endif

/* Credentials of the client for the current server invocation. */
typedef struct door_cred {
    uid_t dc_euid;
    gid_t dc_egid;
    uid_t dc_ruid;
    gid_t dc_rgid;
    pid_t dc_pid;
    int dc_resv[4];              /* Reserved; applications must ignore. */
} door_cred_t;

/*
 * On input, data/descriptor fields describe the request and rbuf/rsize the
 * reply storage. Success points data_ptr at rbuf and returns a caller-owned
 * descriptor array (free after retaining/closing its fds). AUTO_MAP may replace
 * rbuf/rsize with a page-rounded mapping which the caller must munmap.
 * ONEWAY success clears data_ptr/data_size and desc_ptr/desc_num. Failure preserves visible fields, but
 * server effects and MOVE may already have committed; retry can repeat work.
 * A NULL argument invokes with an empty request and discards the result.
 */
typedef struct door_arg {
    char *data_ptr;
    size_t data_size;
    door_desc_t *desc_ptr;
    uint_t desc_num;
    char *rbuf;
    size_t rsize;
} door_arg_t;

/*
 * FreeBSD DoorFS persistent shared-memory extension.  A region is created and
 * mapped once, then hot-path calls pass only a region id plus offset/length.
 * Addresses are process-local and must never be sent to the peer.
 */
typedef uint64_t door_shm_id_t;

#define DOOR_SHM_READ          0x00000001U
#define DOOR_SHM_WRITE         0x00000002U
#define DOOR_SHM_RW            (DOOR_SHM_READ | DOOR_SHM_WRITE)
#define DOOR_SHM_CONSUMER_RO   0x00000004U
#define DOOR_SHM_PAIR          0x00000008U
#define DOOR_SHM_FLAG_MASK     (DOOR_SHM_RW | DOOR_SHM_CONSUMER_RO | DOOR_SHM_PAIR)

/* Region ids, held objects and VM mappings have separate lifetimes. Destroy
 * invalidates future export, even after capture, but leaves existing mappings.
 * Delivered callbacks can use those mappings. SHM is shared, not a snapshot;
 * applications synchronize edits and unmap each local mapping explicitly. */
typedef struct door_shm {
    door_shm_id_t dsh_region;
    void *dsh_addr;
    size_t dsh_size;
    uint_t dsh_flags;

    /*
     * Generation metadata filled by libdoor.  Applications should treat
     * these fields as read-only.  dsh_fd is a private duplicate pinned to
     * the Door generation which created/attached this mapping.
     */
    door_id_t dsh_uniquifier;
    int dsh_fd;
    uint32_t dsh_resv;
} door_shm_t;

typedef struct door_shm_ref {
    door_shm_id_t dsr_region;
    size_t dsr_offset;
    size_t dsr_size;

    /*
     * Optional strong generation identity.  door_shm_ref_init() always fills
     * this field.  A zero value denotes the legacy raw region-id form.
     */
    door_id_t dsr_uniquifier;
} door_shm_ref_t;

/*
 * Checked single-producer/single-consumer ring over a persistent region.
 * The control words and slot links are offsets and sequence numbers; no
 * process-local pointer is stored in shared memory.  Applications must use
 * the accessors below instead of modifying this structure.
 */
typedef struct door_shm_ring {
    door_shm_t dsr_shm;
    uint64_t dsr_slot_size;
    uint64_t dsr_slot_stride;
    uint64_t dsr_slot_count;
    uint64_t dsr_local_producer;
    uint64_t dsr_local_consumer;
    uint32_t dsr_role;
    uint32_t dsr_resv;
    uint64_t dsr_local_reservation;
} door_shm_ring_t;

/* Mutable producer slot.  It is valid only until commit() or abort(). */
typedef struct door_shm_ring_writer {
    void *drw_data;
    size_t drw_capacity;
    size_t drw_offset;
    uint64_t drw_sequence;
    uint64_t drw_reservation;
} door_shm_ring_writer_t;

/* Logical read view until consume; SPSC discipline, not VM immutability. */
typedef struct door_shm_ring_view {
    const void *drv_data;
    size_t drv_size;
    size_t drv_offset;
    uint64_t drv_sequence;
} door_shm_ring_view_t;

#define DOOR_SHM_RING_PRODUCER 0x00000001U
#define DOOR_SHM_RING_CONSUMER 0x00000002U

/*
 * FreeBSD named Door control plane.  CONNECT returns an ordinary Door
 * capability fd pinned to the generation current at connect time.
 */
#define DOOR_NAMED_GLOBAL      0x00000001U

typedef struct door_named_info {
    int32_t dni_target_jid;
    uint32_t dni_attributes;
    uint64_t dni_uniquifier;
} door_named_info_t;

/* FreeBSD credential extension returned by door_ucred(). */
#define DOOR_UCRED_MAX_GROUPS 16
struct door_ucred {
    uid_t du_euid;
    uid_t du_ruid;
    uid_t du_suid;
    gid_t du_egid;
    gid_t du_rgid;
    gid_t du_sgid;
    pid_t du_pid;
    int32_t du_jid;
    uint32_t du_ngroups;
    gid_t du_groups[DOOR_UCRED_MAX_GROUPS];
};
typedef struct door_ucred door_ucred_t;
typedef struct door_ucred ucred_t;

/*
 * Server procedure invoked by a libdoor-managed worker.
 * The procedure must normally finish by calling door_return().
 */
typedef void door_server_procedure_t(void *, char *, size_t,
    door_desc_t *, uint_t);

/* Process-wide legacy server-pool notification callback. */
typedef void door_server_func_t(door_info_t *);

/*
 * door_xcreate() worker factory.  start_func(start_arg) is the complete
 * libdoor worker entry point and must be run by the newly created thread.
 * Return 1 when a thread was created, 0 when no thread was created, and -1
 * on failure with errno set.
 */
typedef int door_xcreate_server_func_t(door_info_t *,
    void *(*start_func)(void *), void *start_arg, void *cookie);

/* Optional setup hook run in each xcreate worker before kernel binding. */
typedef void door_xcreate_thrsetup_func_t(void *);

/* Create a door and synchronously establish its initial managed worker. */
int door_create(door_server_procedure_t *, void *, uint_t);

/* Revoke a door owned by the current process.  Existing calls are aborted. */
int door_revoke(int);

/* Query a door descriptor or use DOOR_QUERY inside a server callback. */
int door_info(int, door_info_t *);

/*
 * Invoke a door.
 * Ordinary doors are synchronous.  DOOR_ONEWAY returns after the kernel has
 * snapshotted and queued/dispatched the request; on success it publishes an
 * empty result (data_ptr == NULL, data_size == 0, no descriptors).
 */
int door_call(int, door_arg_t *);

/*
 * FreeBSD DoorFS extension: compact data-only submit for a DOOR_ONEWAY
 * endpoint.  The request is fully snapshotted by the kernel before return.
 * No descriptor or reply state is constructed.
 */
int door_oneway(int, const void *, size_t);

/*
 * Ordinary Doors use kernel ASYNC_CALL and normal server callbacks/RETURN;
 * legacy DOOR_ONEWAY uses the registered reply protocol. Replies are data-only,
 * up to 64 KiB. Received completions run on reply workers; close drains remaining
 * records with ECANCELED on the closing thread. Thread-affine runtimes must
 * marshal both cases. Completion bytes are borrowed only for the callback.
 * Close drains the reply endpoint, not callbacks executing at the peer.
 */
typedef struct door_async door_async_t;
typedef struct door_async_server door_async_server_t;
typedef struct door_async_request {
    uint64_t dar_id;
    uint64_t dar_token;
    pid_t dar_pid;
    int32_t dar_jid;
    const void *dar_data;
    size_t dar_size;
} door_async_request_t;
typedef void door_async_completion_t(uint64_t, int, const void *, size_t,
    void *);
int door_async_open(int, size_t, door_async_t **);
int door_async_reply_fd(const door_async_t *);
int door_async_token(const door_async_t *, uint64_t *);
int door_async_submit(door_async_t *, const void *, size_t,
    door_async_completion_t *, void *, uint64_t *);
int door_async_cancel(door_async_t *, uint64_t);
int door_async_request_parse(const void *, size_t, door_async_request_t *);
int door_async_respond(int, const door_async_request_t *, int,
    const void *, size_t);
int door_async_server_open(size_t, door_async_server_t **);
int door_async_server_register(door_async_server_t *, uint64_t, int);
int door_async_server_respond(door_async_server_t *,
    const door_async_request_t *, int, const void *, size_t);
int door_async_server_unregister(door_async_server_t *, uint64_t);
int door_async_server_close(door_async_server_t *);
int door_async_close(door_async_t *);

/*
 * Persistent DoorFS shared-memory extension.  CREATE maps a new region in the
 * caller.  ATTACH maps an existing region into the door owner/server process.
 * dsh_size is the exact requested/usable size; page rounding is private to
 * the VM implementation.  DOOR_SHM_CONSUMER_RO permanently caps the server
 * mapping at read-only and must be paired with a DOOR_SHM_READ attach.
 * UNMAP only removes the local mapping; DESTROY invalidates the creator-owned
 * region handle but deliberately does not unmap either participant.
 */
/* Pair regions reserve their first VM page for two 32-bit event words.
 * No field in that page authorizes access to another region or allocation. */
int door_shm_pair_create(int, size_t, door_shm_t *);
int door_shm_pair_attach(int, door_shm_id_t, door_shm_t *);
int door_shm_pair_load(const door_shm_t *, uint_t, uint32_t *);
int door_shm_pair_notify(const door_shm_t *, uint_t);
int door_shm_pair_wait(const door_shm_t *, uint_t, uint32_t, uint64_t);

#define DOOR_SHM_CHAIN_MAX_SEGMENTS 64U
struct door_shm_chain_segment {
    uint64_t dcs_offset;
    uint64_t dcs_length;
};
typedef struct door_shm_chain {
    uint64_t dsc_region;
    uint64_t dsc_uniquifier;
    uint64_t dsc_lease;
    uint64_t dsc_length;
    uint32_t dsc_count;
    uint32_t dsc_reserved;
    struct door_shm_chain_segment dsc_segments[DOOR_SHM_CHAIN_MAX_SEGMENTS];
} door_shm_chain_t;
struct door_shm_pool;
typedef struct door_shm_pool door_shm_pool_t;
struct iovec;
int door_shm_pool_create(int, size_t, uint_t, door_shm_pool_t **);
const door_shm_t *door_shm_pool_region(const door_shm_pool_t *);
int door_shm_pool_reserve(door_shm_pool_t *, size_t, door_shm_chain_t *);
int door_shm_pool_release(door_shm_pool_t *, const door_shm_chain_t *);
int door_shm_pool_destroy(door_shm_pool_t *);
int door_shm_chain_map(const door_shm_t *, const door_shm_chain_t *,
    struct iovec *, uint_t);

int door_shm_create(int, size_t, uint_t, door_shm_t *);
int door_shm_attach(int, door_shm_id_t, uint_t, door_shm_t *);
int door_shm_unmap(door_shm_t *);
int door_shm_destroy(int, door_shm_id_t);

/*
 * Strong-handle helpers.  These avoid exposing the per-Door numeric region
 * namespace to normal application code.
 */
int door_shm_ref_init(const door_shm_t *, size_t, size_t, door_shm_ref_t *);
int door_call_shm_region(const door_shm_t *, size_t, size_t);
int door_shm_destroy_handle(door_shm_t *);

/*
 * A page view borrows disjoint, page-aligned source ranges from one Door.
 * Publish is creator-owned; attach/release are owner/server-owned. The
 * receiver mapping is read-only, initially non-inheritable, and removed by
 * RELEASE. Do not create aliases, change inheritance, or use vfork/RFMEM with
 * a live view. Stop every reader before release.
 * No writable source alias or DMA buffer may change until RELEASED.
 * Cancellation/revoke is not a release barrier for an attached view.
 */
typedef struct door_shm_view {
    uint64_t dsv_id;
    uint64_t dsv_token;
    void *dsv_addr;
    size_t dsv_size;
    int dsv_fd; /* private duplicate, do not close while the view is live */
    uint32_t dsv_state;
    uint32_t dsv_role; /* producer or consumer; maintained by libdoor */
} door_shm_view_t;

#define DOOR_SHM_VIEW_PRODUCER 1
#define DOOR_SHM_VIEW_CONSUMER 2

int door_shm_view_publish(int, const door_shm_ref_t *, uint_t,
    door_shm_view_t *);
int door_shm_view_attach(int, uint64_t, uint64_t, door_shm_view_t *);
int door_shm_view_query(door_shm_view_t *, uint_t *);
int door_shm_view_release(door_shm_view_t *);
int door_shm_view_destroy(door_shm_view_t *);
int door_shm_view_close(door_shm_view_t *);

/*
 * Checked SPSC ring construction and data movement.  reserve() returns the
 * complete writable capacity of the next producer slot.  The producer may
 * append fragments directly to that memory and commit() publishes only the
 * final length.  abort() discards an unpublished reservation.  Only one
 * outstanding writer is permitted per producer handle; stale or modified
 * writers are rejected.  push() is the compatible copying wrapper.
 *
 * acquire() verifies and pins the next logical consumer slot in the local
 * ring handle; its view remains valid until the matching consume().
 * consume() revalidates the exact offset, generation, and length before
 * advancing the tail.  Only one outstanding view is permitted per consumer
 * handle.
 */
int door_shm_ring_create(int, size_t, size_t, door_shm_ring_t *);
int door_shm_ring_attach(int, door_shm_id_t, uint_t, door_shm_ring_t *);
int door_shm_ring_reserve(door_shm_ring_t *, door_shm_ring_writer_t *);
int door_shm_ring_commit(door_shm_ring_t *, const door_shm_ring_writer_t *,
    size_t, door_shm_ref_t *);
int door_shm_ring_abort(door_shm_ring_t *, const door_shm_ring_writer_t *);
int door_shm_ring_push(door_shm_ring_t *, const void *, size_t,
    door_shm_ref_t *);
int door_shm_ring_acquire(door_shm_ring_t *, door_shm_ring_view_t *);
int door_shm_ring_consume(door_shm_ring_t *, const door_shm_ring_view_t *);
int door_shm_ring_pop(door_shm_ring_t *, void *, size_t, size_t *);
int door_shm_ring_unmap(door_shm_ring_t *);

/*
 * This libdoor wrapper sends a persistent SHM request and supports only an
 * empty reply (ONEWAY or synchronous acknowledgement). Nonempty replies need
 * another interface; this is not a restriction of the kernel RETURN machinery.
 */
int door_call_shm(int, const door_shm_ref_t *);


/* GLOBAL applies only to register/unregister. Lookup/connect require flags 0
 * and select local scope before global. Lookup is a snapshot, not a reservation
 * for connect; connect reports generation/jail and sets attributes to 0. */
int door_named_register(int, const char *, uint_t);
int door_named_unregister(int, const char *, uint_t);
int door_named_lookup(const char *, uint_t, door_named_info_t *);
int door_named_connect(const char *, uint_t, door_named_info_t *);

/*
 * Complete the current invocation.  libdoor passes the caller's reply buffers
 * directly to the kernel while the callback frame is still alive.  On success
 * it returns 0; the server procedure must then return normally.  It returns -1
 * on invalid context/arguments or if the Door RETURN syscall fails.
 */
int door_return(char *, size_t, door_desc_t *, uint_t);

/*
 * Obtain credentials for the current non-UNREF server invocation.
 * DOOR_NO_CRED endpoints return ENOTSUP.
 */
int door_cred(door_cred_t *);
int door_ucred(ucred_t **);

/* Explicitly bind or unbind the calling thread as a worker for one door. */
int door_bind(int);
int door_unbind(void);

/* Get or set a supported per-door limit. */
int door_getparam(int, int, size_t *);
int door_setparam(int, int, size_t);

/* Install a process-local legacy pool notification callback. */
door_server_func_t *door_server_create(door_server_func_t *);

/* Create a private door with an application-provided worker factory. */
int door_xcreate(door_server_procedure_t *, void *, uint_t,
    door_xcreate_server_func_t *, door_xcreate_thrsetup_func_t *, void *, int);

/* Attach/detach a door descriptor to/from a filesystem pathname. */
int fattach(int, const char *);
int fdetach(const char *);

#ifdef __cplusplus
}
#endif
#endif /* _DOOR_H_ */
