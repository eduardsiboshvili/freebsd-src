/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SYS_DOOR_IMPL_H_
#define _SYS_DOOR_IMPL_H_

#ifdef _KERNEL

#include <sys/capsicum.h>
#include <sys/types.h>
#include <sys/condvar.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/taskqueue.h>
#include <sys/ucred.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/uma.h>

#include <sys/door_core.h>

/*
 * DoorFS requires the shuttle scheduler API provided by the DOORFS kernel.
 * There is no separate module-local scheduler feature switch.
 */
#define DOOR_SHUTTLE_F_INTERRUPTIBLE SCHED_SHUTTLE_F_INTERRUPTIBLE
#define DOOR_SHUTTLE_F_DISPATCH SCHED_SHUTTLE_F_DISPATCH
#define DOOR_SHUTTLE_F_REPLY SCHED_SHUTTLE_F_REPLY
#define DOOR_SHUTTLE_F_IDLE_WAIT SCHED_SHUTTLE_F_IDLE_WAIT
#define DOOR_SHUTTLE_F_ASYNC_WAKE SCHED_SHUTTLE_F_ASYNC_WAKE

MALLOC_DECLARE(M_DOORFS);

enum door_xfer_mode {
	DOOR_XFER_NONE = 0,
	DOOR_XFER_BUFFER,
	DOOR_XFER_PAGES,
};

/*
 * Per-worker reusable reply storage.
 *
 * A binding holds one reference.  A BUFFER reply can atomically claim the
 * cache and hold another reference until the client has completed copyout.
 * Busy cache => ordinary malloc fallback; a worker never waits for storage.
 */

struct door_reply_cache {
	u_int drc_refs;
	volatile u_int drc_busy;
	size_t drc_capacity;
	uint8_t drc_data[];
};

struct door_xfer {
	enum door_xfer_mode dx_mode;
	size_t dx_size;
	uint8_t *dx_buffer;
	vm_page_t *dx_pages;
	int dx_npages;
	vm_offset_t dx_page_offset;

	bool dx_buffer_owned;
	struct door_reply_cache *dx_reply_cache;
};

struct door_shm_region;

struct door_fd_bundle {
	struct file **df_files;
	struct filecaps *df_caps;
	int *df_source_fds;
	uint32_t *df_flags;
	uint32_t df_count;
};

enum door_call_state {
	DOOR_CALL_PENDING = 0,
	DOOR_CALL_ACTIVE,
	DOOR_CALL_DONE,
	DOOR_CALL_CANCELLED,
	DOOR_CALL_REVOKED,
};

enum door_call_type {
	DOOR_CALL_RPC = 0,
	DOOR_CALL_UNREF,
};

struct door_call {
	TAILQ_ENTRY(door_call) dc_link;
	struct cv dc_cv;
	u_int dc_refs;
	enum door_call_state dc_state;
	enum door_call_type dc_type;
	uint64_t dc_id;
	uint64_t dc_unref_generation;
	int dc_error;
	struct ucred *dc_cred;
	struct proc *dc_client;
	struct thread *dc_client_td;
	struct thread *dc_server_td;
	bool dc_client_shuttle_armed;
	/*
	 * Allocation class.  Every normal RPC call object comes from
	 * one of the UMA zones below; the class selects the matching zfree path.
	 */
	uint8_t dc_alloc_class;
#define DOOR_CALL_ALLOC_FIXED 1
#define DOOR_CALL_ALLOC_INLINE_256 2
#define DOOR_CALL_ALLOC_INLINE_1K 3
#define DOOR_CALL_ALLOC_INLINE_4K 4
#define DOOR_CALL_ALLOC_INLINE_8K 5
#define DOOR_CALL_ALLOC_MALLOC 6
	struct door_fd_bundle dc_request_fds;
	struct door_fd_bundle dc_reply_fds;
	pid_t dc_pid;
	struct door_xfer dc_request;
	struct door_xfer dc_reply;

	/* Kernel-managed persistent SHM reference for this invocation. */
	struct door_shm_region *dc_shm_region;
	size_t dc_shm_offset;
	size_t dc_shm_size;

	/*
	 * Descriptor-only early-dispatch state.
	 * dc_early_dispatch is immutable after call publication.
	 */
	volatile u_int dc_request_ready;
	bool dc_early_dispatch;
	bool dc_oneway;
	/* Kernel async: one terminal schedule; endpoint loss can prevent delivery. */
	bool dc_async;
	bool dc_async_scheduled; /* protected by the request Door's d_lock */
	bool dc_async_reserved;
	struct door *dc_async_target; /* held through completion task */
	struct task dc_async_task;
	struct door_call *dc_async_enqueue_next; /* temporary post-unlock batch */
	uint8_t *dc_async_result;
	size_t dc_async_result_size;
	int dc_async_status;
	/* Lockless release/acquire publication for bounded client spinning. */
	volatile u_int dc_client_ready;

	/*
	 * Protected by d_lock.  Distinguishes an ONEWAY request merely assigned
	 * to a worker from one already committed for export to server userspace.
	 */
	bool dc_server_delivered;

	bool dc_reply_install_done;
	int dc_reply_install_error;

	/*
	 * A successful reply descriptor MOVE is not complete until the server
	 * thread has removed the source descriptor from its own file table.
	 * install_done first authorizes the sender to close its source fd;
	 * move_done then acknowledges that close to the client before CALL returns.
	 */
	bool dc_reply_move_required;
	bool dc_reply_move_done;
};

struct door_server_binding {
	LIST_ENTRY(door_server_binding) ds_link;
	LIST_ENTRY(door_server_binding) ds_global_link;
	struct door *ds_door;
	struct thread *ds_td;
	struct proc *ds_proc;
	struct door_call *ds_call;
	struct door_reply_cache *ds_reply_cache;
	struct cv ds_cv;
	u_int ds_refs;
	bool ds_waiting;
	bool ds_door_ref;
	bool ds_linked;
	bool ds_global_linked;
};

TAILQ_HEAD(door_call_head, door_call);
LIST_HEAD(door_server_head, door_server_binding);
TAILQ_HEAD(door_shm_region_head, door_shm_region);

struct door {
	struct mtx d_lock;
	u_int d_refs;
	u_int d_file_count;
	uint64_t d_unref_generation;
	bool d_unref_once_fired;

	struct proc *d_owner;
	pid_t d_owner_pid;
	struct ucred *d_owner_cred;
	TAILQ_ENTRY(door) d_owner_link;
	bool d_owner_linked;

	/*
	 * Every allocated Door remains on the all-object list until its final
	 * reference is released.  Unlike d_owner_link this membership survives
	 * owner exit/orphaning and is used to prevent module unload while an
	 * unlinked Door is still referenced by a file, client, publication or
	 * server binding.
	 */
	TAILQ_ENTRY(door) d_all_link;
	bool d_all_linked;

	/*
	 * doorctl LIVE entries own a publication count and a Door ref. namefs
	 * instead holds its target struct file; each open clones an independent
	 * native Door capability pinned to that generation.
	 */
	u_int d_publications;
	u_int d_client_count;
	u_int d_async_reserved; /* accepted completions not yet enqueued */
	/*
	 * Set while the owner-list anchor is being removed.  This closes the
	 * small lifetime window between unlinking the Door from door_list and
	 * the later revoke pass: no new client/publication may attach there.
	 */
	bool d_orphaning;
	bool d_revoked;

	/*
	 * Lockless CALL precheck state.
	 *
	 * d_revoked remains the authoritative value under d_lock.  These bits
	 * only allow the overwhelmingly common default-policy path to reject
	 * cheaply or skip the first d_lock acquisition.  The post-capture check
	 * under d_lock remains authoritative for races with SETPARAM/REVOKE.
	 */
	volatile u_int d_hot_flags;
#define DOOR_HOT_REVOKED 0x00000001u
#define DOOR_HOT_CUSTOM_LIMITS 0x00000002u

	struct door_call_head d_pending;
	struct door_call_head d_active;
	struct door_server_head d_servers;
	struct door_shm_region_head d_shm_regions;
	uint64_t d_next_shm_region;
	u_int d_shm_region_count;
	vm_size_t d_shm_bytes;

	/*
	 * The idle-server hint is protected by d_lock and extends no lifetime.
	 * A miss falls back to d_servers; td_door_server is the separate worker binding.
	 */
	struct door_server_binding *d_idle_server_hint;

	uint64_t d_next_call_id;
	u_int d_pending_count;
	u_int d_active_count;
	u_int d_server_count;

	uint64_t d_cookie;
	uint64_t d_uniquifier;
	uint32_t d_attributes;

	/* Per-door invocation limits, matching illumos door_node_t. */
	size_t d_data_min;
	size_t d_data_max;
	u_int d_desc_max;
};

int door_core_init(void);
int door_core_fini(void);
extern u_int door_max_servers_per_door;
extern u_int door_max_shm_regions_per_door;
extern u_long door_max_shm_bytes_per_door;
int kern_door(struct thread *, long, long, long, long, long, long);
int door_rpc_cache_init(void);
void door_rpc_cache_fini(void);
bool door_rpc_calls_busy(void);
int door_alloc(struct proc *, uint64_t, uint32_t, uint32_t, struct door **);
void door_hold(struct door *);
void door_drop(struct door *);
int door_revoke(struct door *);
void door_thread_cleanup_all(struct thread *);
void door_thread_exit(struct thread *);
void door_process_exit(struct proc *);
bool door_rpc_bindings_busy(void);
bool door_is_owner(struct door *, struct proc *);
void door_owner_remove(struct door *);
void door_file_installed(struct door *);
void door_last_file_closed(struct door *);
int door_client_open(struct door *);
void door_client_closed(struct door *);
void door_maybe_orphan(struct door *);
void door_owner_snapshot(struct door *, struct proc *, pid_t *, bool *);
void door_unref_enqueue(struct door *, uint64_t);
void door_unref_drop(struct door_call *);
void door_oneway_drop(struct door_call *);
void door_oneway_server_drop(struct door_call *);
void door_call_wake_client_locked(struct door_call *, int);
void door_server_wake_locked(struct door_server_binding *);
void door_server_wake_async_locked(struct door_server_binding *);

/* Persistent kernel-managed SHM regions. */
int door_shm_create(
    struct door *, struct door_ioc_shm_create *, struct thread *);
int door_shm_attach(
    struct door *, struct door_ioc_shm_attach *, struct thread *);
int door_shm_destroy_handle(
    struct door *, struct door_ioc_shm_destroy *, struct thread *);
int door_shm_call_capture_locked(struct door *, struct thread *,
    const struct door_ioc_shm_ref *, struct door_call *);
int door_shm_server_export_locked(
    struct door_call *, struct thread *, struct door_ioc_shm_ref *, uint64_t *);
void door_shm_region_drop(struct door_shm_region *);
void door_shm_revoke_all(struct door *);
int door_shm_pair_op(struct door *, const struct door_ioc_shm_pair *,
    unsigned int, struct thread *);
int door_shm_view_op(struct door *, struct door_ioc_shm_view *,
    const struct door_ioc_shm_view_segment *, unsigned int, struct thread *);
bool door_shm_view_exit_pending(struct door *, pid_t);
void door_shm_view_process_exit(struct door *, pid_t);

int door_check_jail(struct door *, struct ucred *);
int door_publication_hold(struct door *);
int door_owner_publication_hold(struct door *, struct proc *);
void door_publication_drop(struct door *);
int door_owner_lock(struct door *, struct proc *);

int door_call_full(struct door *, struct door_ioc_call *, struct thread *);
int door_async_call(struct door *, struct door *,
    const struct door_ioc_async_call *, struct thread *);
int door_async_cancel(struct door *, struct door *, uint64_t);
/*
 * Collect under the request Door's d_lock; flush after unlocking, before
 * releasing any caller-owned call references.  Each queued call has its own
 * task reference, including when revoke removes it from the Door queues.
 */
struct door_async_batch {
	struct door_call *head;
	struct door_call **tail;
};
void door_async_batch_init(struct door_async_batch *);
void door_async_batch_flush(struct door_async_batch *);
void door_async_schedule_locked(struct door *, struct door_call *, int,
    uint8_t *, size_t, struct door_async_batch *);
int door_call_shm(struct door *, struct door_ioc_call_shm *, struct thread *);
int door_server_bind(struct door *, struct thread *);
int door_cancel(struct door *, struct door_ioc_cancel *, struct thread *);
int door_getparam(struct door *, struct door_ioc_param *);
int door_setparam(struct door *, struct door_ioc_param *, struct thread *);
int door_info(struct door *, struct door_ioc_info *, struct thread *);
int door_xfer_capture_request(
    struct door_xfer *, struct thread *, uint64_t, size_t);
int door_xfer_capture_request_snapshot(
    struct door_xfer *, struct thread *, uint64_t, size_t);
int door_xfer_capture_request_prealloc(
    struct door_xfer *, struct thread *, uint64_t, size_t, void *, size_t);
int door_xfer_capture_reply(
    struct door_xfer *, struct thread *, uint64_t, size_t);
int door_xfer_capture_reply_cached(struct door_xfer *, struct thread *,
    uint64_t, size_t, struct door_reply_cache *);
int door_xfer_copyout(struct door_xfer *, struct thread *, uint64_t);
void door_xfer_destroy(struct door_xfer *);

struct door_reply_cache *door_reply_cache_alloc(size_t);
void door_reply_cache_hold(struct door_reply_cache *);
void door_reply_cache_drop(struct door_reply_cache *);
int door_file_install(struct thread *, struct door *, int *);
int door_file_get(struct thread *, int, struct door **);
int door_file_get_ref(struct thread *, int, const cap_rights_t *,
    struct file **, struct door **);
int door_server_cred(struct door *, struct thread *, struct door_ioc_cred *);
int door_server_unbind_bound(struct thread *);
int door_server_worker_exit_bound(struct thread *);
int door_server_cred_bound(struct thread *, struct door_ioc_cred *);

int door_client_file_install(struct thread *, struct door *, int *);
bool door_file_is_door(const struct file *);
bool door_file_is_live(const struct file *);
int door_file_clone(struct file *, struct file *, int, struct ucred *);
int door_oneway_submit(struct door *, struct thread *, uint64_t, size_t);
int door_call_scalar(struct door *, struct thread *, uint64_t, size_t, uint64_t,
    size_t, uint64_t, bool, uint64_t *, uint32_t *, uint64_t *);
int door_return_bound_direct(struct door *, struct thread *,
    struct door_server_binding *, struct door_ioc_return_shm *, uint64_t *);
int doorctl_init(void);
int doorctl_fini(void);
void doorctl_generation_revoked(struct door *);
void doorctl_purge_dead(void);

#endif /* _KERNEL */

#endif /* _SYS_DOOR_IMPL_H_ */
