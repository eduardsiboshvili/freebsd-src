/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "opt_doorfs.h"

#include <sys/param.h>
#include <machine/atomic.h>
#include <sys/systm.h>
#include <sys/jail.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/refcount.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>
#include <sys/syslimits.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>
#include <vm/uma.h>

#include <sys/door_impl.h>
#ifdef DOORFS_TEST
#include <sys/door_test.h>
#endif

/*
 * Descriptor-only early dispatch.
 *
 * Buffer and page payloads both keep capture-before-dispatch
 * ordering.  Early dispatch is retained only for descriptor/fd capture so
 * page-transport setup cost can be measured independently.
 */
#define DOOR_REQUEST_READY_SPINS 128

static uma_zone_t door_call_zone;
static uma_zone_t door_call_inline_256_zone;
static uma_zone_t door_call_inline_1k_zone;
static uma_zone_t door_call_inline_4k_zone;
static uma_zone_t door_call_inline_8k_zone;

static int door_return(struct door *, struct door_ioc_return *, struct thread *,
    struct door_ioc_shm_ref *, uint64_t *, struct door_server_binding *, bool,
    uint64_t *);

static int
door_reply_map(struct thread *td, size_t reply_size, uint64_t *addrp,
    vm_size_t *map_sizep)
{
	vm_object_t object;
	vm_offset_t addr;
	vm_size_t map_size;
	int error;

	if ((td->td_proc->p_sysent->sv_flags & SV_ILP32) != 0 &&
	    reply_size > UINT32_MAX)
		return (EOVERFLOW);
	if (reply_size == 0)
		return (EINVAL);
	map_size = round_page((vm_size_t)reply_size);
	if (map_size == 0 || map_size < reply_size)
		return (EOVERFLOW);

	object = vm_object_allocate(OBJT_DEFAULT, atop(map_size));
	if (object == NULL)
		return (ENOMEM);
	addr = 0;
	vm_object_reference(object); /* mapping reference */
	error = vm_mmap_object(&td->td_proc->p_vmspace->vm_map, &addr,
	    map_size, VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE, MAP_PRIVATE, object, 0, FALSE, td);
	if (error != 0)
		vm_object_deallocate(object); /* failed mapping reference */
	vm_object_deallocate(object); /* local reference */
	if (error != 0)
		return (error);

	*addrp = (uint64_t)addr;
	*map_sizep = map_size;
	return (0);
}

static int
door_call_zone_init(void *mem, int size __unused, int flags __unused)
{
	struct door_call *call;

	call = mem;
	bzero(call, sizeof(*call));
	cv_init(&call->dc_cv, "doorcall");
	return (0);
}

static void
door_call_zone_fini(void *mem, int size __unused)
{
	struct door_call *call;

	call = mem;
	cv_destroy(&call->dc_cv);
}

/* Reset per-invocation state while preserving the UMA-lifetime CV. */
static __inline void
door_call_reset(struct door_call *call)
{
	size_t cv_end;

	cv_end = offsetof(struct door_call, dc_cv) + sizeof(call->dc_cv);
	bzero(call, offsetof(struct door_call, dc_cv));
	bzero((char *)call + cv_end, sizeof(*call) - cv_end);
}

/*
 * Linked bindings are counted here for busy/unload checks. Thread cleanup
 * uses td_door_server with a temporary ds_refs pin, not a registry lookup.
 * Never acquire d_lock while holding door_binding_registry_lock; removal may link
 * or unlink registry state while already holding d_lock.
 */
static LIST_HEAD(, door_server_binding)
    door_binding_registry = LIST_HEAD_INITIALIZER(door_binding_registry);
static struct mtx door_binding_registry_lock;

/*
 * Minimal production lifetime accounting.
 *
 * This one counter is retained because module unload must never destroy the
 * door_call UMA zones while a detached call object is still alive.  Cost:
 * one atomic increment per call allocation and one atomic decrement on final
 * free.
 */
static volatile u_int door_call_live;

/*
 * Bounded reply spinning can avoid a park for short handoffs on 4BSD.
 * Default 0 avoids consuming CPU on ULE; tuning depends on placement/load.
 */
static u_int door_client_spins = 0;

SYSCTL_NODE(_kern, OID_AUTO, doorfs, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "DoorFS runtime state");
SYSCTL_UINT(_kern_doorfs, OID_AUTO, call_outstanding, CTLFLAG_RD,
    __DEVOLATILE(u_int *, &door_call_live), 0, "Live door_call objects");
SYSCTL_UINT(_kern_doorfs, OID_AUTO, client_spins, CTLFLAG_RWTUN,
    &door_client_spins, 0, "Remote synchronous reply spin iterations");

#define DOOR_CALL_INLINE_256_CAP 256
#define DOOR_CALL_INLINE_1K_CAP 1024
#define DOOR_CALL_INLINE_4K_CAP 4096
#define DOOR_CALL_INLINE_8K_CAP (8 * 1024)
/* Bound undelivered ONEWAY snapshots even for raw syscall callers. */
#define DOOR_ONEWAY_PENDING_MAX 4096U
#define DOOR_ASYNC_REQUEST_MAX (1024U * 1024U)
#define DOOR_ASYNC_REPLY_MAX (64U * 1024U)
#define DOOR_ASYNC_OUTSTANDING_MAX 256U

static __inline void
door_call_allocated(struct door_call *call)
{
	atomic_add_int(&door_call_live, 1);
#ifdef DOORFS_TEST
	door_test_object_add(DOOR_TEST_OBJ_CALL);
#endif

	(void)call;
}

static __inline void
door_call_freed(struct door_call *call)
{
	(void)call;

	KASSERT(atomic_load_acq_int(&door_call_live) != 0,
	    ("door_call live count underflow"));
	atomic_subtract_int(&door_call_live, 1);
#ifdef DOORFS_TEST
	door_test_object_drop(DOOR_TEST_OBJ_CALL);
#endif
}

int
door_rpc_cache_init(void)
{
	/* The loader zero-initializes this static lifetime count. */
	door_call_live = 0;

	mtx_init(&door_binding_registry_lock, "door binding registry", NULL,
	    MTX_DEF);

	door_call_zone =
	    uma_zcreate("door_call", sizeof(struct door_call), NULL, NULL,
		door_call_zone_init, door_call_zone_fini, UMA_ALIGN_PTR, 0);
	if (door_call_zone == NULL)
		goto fail;

	door_call_inline_256_zone = uma_zcreate("door_call_256",
	    sizeof(struct door_call) + DOOR_CALL_INLINE_256_CAP, NULL, NULL,
	    door_call_zone_init, door_call_zone_fini, UMA_ALIGN_PTR, 0);
	if (door_call_inline_256_zone == NULL)
		goto fail;

	door_call_inline_1k_zone = uma_zcreate("door_call_1k",
	    sizeof(struct door_call) + DOOR_CALL_INLINE_1K_CAP, NULL, NULL,
	    door_call_zone_init, door_call_zone_fini, UMA_ALIGN_PTR, 0);
	if (door_call_inline_1k_zone == NULL)
		goto fail;

	door_call_inline_4k_zone = uma_zcreate("door_call_4k",
	    sizeof(struct door_call) + DOOR_CALL_INLINE_4K_CAP, NULL, NULL,
	    door_call_zone_init, door_call_zone_fini, UMA_ALIGN_PTR, 0);
	if (door_call_inline_4k_zone == NULL)
		goto fail;

	door_call_inline_8k_zone = uma_zcreate("door_call_8k",
	    sizeof(struct door_call) + DOOR_CALL_INLINE_8K_CAP, NULL, NULL,
	    door_call_zone_init, door_call_zone_fini, UMA_ALIGN_PTR, 0);
	if (door_call_inline_8k_zone == NULL)
		goto fail;

	return (0);

fail:
	if (door_call_inline_8k_zone != NULL) {
		uma_zdestroy(door_call_inline_8k_zone);
		door_call_inline_8k_zone = NULL;
	}
	if (door_call_inline_4k_zone != NULL) {
		uma_zdestroy(door_call_inline_4k_zone);
		door_call_inline_4k_zone = NULL;
	}
	if (door_call_inline_1k_zone != NULL) {
		uma_zdestroy(door_call_inline_1k_zone);
		door_call_inline_1k_zone = NULL;
	}
	if (door_call_inline_256_zone != NULL) {
		uma_zdestroy(door_call_inline_256_zone);
		door_call_inline_256_zone = NULL;
	}
	if (door_call_zone != NULL) {
		uma_zdestroy(door_call_zone);
		door_call_zone = NULL;
	}
	mtx_destroy(&door_binding_registry_lock);
	return (ENOMEM);
}

void
door_rpc_cache_fini(void)
{
	KASSERT(atomic_load_acq_int(&door_call_live) == 0,
	    ("door RPC cache fini with %u live calls",
		atomic_load_acq_int(&door_call_live)));

	mtx_lock(&door_binding_registry_lock);
	KASSERT(LIST_EMPTY(&door_binding_registry),
	    ("door RPC cache fini with live server bindings"));
	mtx_unlock(&door_binding_registry_lock);

	if (door_call_inline_8k_zone != NULL) {
		uma_zdestroy(door_call_inline_8k_zone);
		door_call_inline_8k_zone = NULL;
	}
	if (door_call_inline_4k_zone != NULL) {
		uma_zdestroy(door_call_inline_4k_zone);
		door_call_inline_4k_zone = NULL;
	}
	if (door_call_inline_1k_zone != NULL) {
		uma_zdestroy(door_call_inline_1k_zone);
		door_call_inline_1k_zone = NULL;
	}
	if (door_call_inline_256_zone != NULL) {
		uma_zdestroy(door_call_inline_256_zone);
		door_call_inline_256_zone = NULL;
	}
	if (door_call_zone != NULL) {
		uma_zdestroy(door_call_zone);
		door_call_zone = NULL;
	}
	mtx_destroy(&door_binding_registry_lock);
}

bool
door_rpc_calls_busy(void)
{
	return (atomic_load_acq_int(&door_call_live) != 0);
}

bool
door_rpc_bindings_busy(void)
{
	bool busy;

	mtx_lock(&door_binding_registry_lock);
	busy = !LIST_EMPTY(&door_binding_registry);
	mtx_unlock(&door_binding_registry_lock);
	return (busy);
}

static struct door_call *
door_call_alloc_fixed(void)
{
	struct door_call *call;

	call = uma_zalloc(door_call_zone, M_WAITOK);
	door_call_reset(call);
	call->dc_alloc_class = DOOR_CALL_ALLOC_FIXED;
	door_call_allocated(call);
	return (call);
}

static void door_fd_bundle_drop(struct door_fd_bundle *, struct thread *);

static struct door_call *
door_call_alloc_inline(
    size_t request_size, uint8_t **storage, size_t *storage_capacity)
{
	struct door_call *call;
	uma_zone_t zone;
	size_t capacity;
	uint8_t alloc_class;

	KASSERT(request_size != 0 && request_size < DOOR_REQUEST_PAGE_THRESHOLD,
	    ("invalid inline door request size"));

	if (request_size <= DOOR_CALL_INLINE_256_CAP) {
		zone = door_call_inline_256_zone;
		capacity = DOOR_CALL_INLINE_256_CAP;
		alloc_class = DOOR_CALL_ALLOC_INLINE_256;
	} else if (request_size <= DOOR_CALL_INLINE_1K_CAP) {
		zone = door_call_inline_1k_zone;
		capacity = DOOR_CALL_INLINE_1K_CAP;
		alloc_class = DOOR_CALL_ALLOC_INLINE_1K;
	} else if (request_size <= DOOR_CALL_INLINE_4K_CAP) {
		zone = door_call_inline_4k_zone;
		capacity = DOOR_CALL_INLINE_4K_CAP;
		alloc_class = DOOR_CALL_ALLOC_INLINE_4K;
	} else {
		zone = door_call_inline_8k_zone;
		capacity = DOOR_CALL_INLINE_8K_CAP;
		alloc_class = DOOR_CALL_ALLOC_INLINE_8K;
	}

	call = uma_zalloc(zone, M_WAITOK);
	door_call_reset(call);
	call->dc_alloc_class = alloc_class;
	door_call_allocated(call);
	*storage = (uint8_t *)(call + 1);
	*storage_capacity = capacity;

	return (call);
}

static void door_call_drop(struct door_call *);

static void
door_call_local_drop(struct door_call *call)
{
	door_call_drop(call);
}

static void
door_call_detached_drop_locked(struct door *door, struct door_call *call)
{
	mtx_assert(&door->d_lock, MA_OWNED);
	/* Client release can race: atomically drop only a non-final reference
	 * under d_lock. Final SHM/fd destruction may reacquire this mutex. */
	if (refcount_release_if_not_last(&call->dc_refs))
		return;
	mtx_unlock(&door->d_lock);
	door_call_drop(call);
	mtx_lock(&door->d_lock);
}

static void
door_call_hold(struct door_call *call)
{
	refcount_acquire(&call->dc_refs);
}

static void
door_call_drop(struct door_call *call)
{
	if (!refcount_release(&call->dc_refs))
		return;
	KASSERT(!call->dc_async_reserved,
	    ("destroying async call with reserved completion slot"));
	if (call->dc_async_target != NULL)
		door_drop(call->dc_async_target);
	if (call->dc_async_result != NULL)
		free(call->dc_async_result, M_DOORFS);
	if (call->dc_request.dx_mode != DOOR_XFER_NONE)
		door_xfer_destroy(&call->dc_request);
	if (call->dc_reply.dx_mode != DOOR_XFER_NONE)
		door_xfer_destroy(&call->dc_reply);
	if (call->dc_shm_region != NULL) {
		door_shm_region_drop(call->dc_shm_region);
		call->dc_shm_region = NULL;
	}
	if (call->dc_request_fds.df_files != NULL)
		door_fd_bundle_drop(&call->dc_request_fds, curthread);
	if (call->dc_reply_fds.df_files != NULL)
		door_fd_bundle_drop(&call->dc_reply_fds, curthread);
	if (call->dc_cred != NULL) {
		crfree(call->dc_cred);
	}
	KASSERT(!call->dc_client_shuttle_armed,
	    ("destroying call with armed client shuttle"));

	/*
	 * From this point no code may dereference call after the class-specific
	 * free.  Decrement outstanding before releasing class-specific storage.
	 */
	door_call_freed(call);

	switch (call->dc_alloc_class) {
	case DOOR_CALL_ALLOC_FIXED:
		uma_zfree(door_call_zone, call);
		break;
	case DOOR_CALL_ALLOC_INLINE_256:
		uma_zfree(door_call_inline_256_zone, call);
		break;
	case DOOR_CALL_ALLOC_INLINE_1K:
		uma_zfree(door_call_inline_1k_zone, call);
		break;
	case DOOR_CALL_ALLOC_INLINE_4K:
		uma_zfree(door_call_inline_4k_zone, call);
		break;
	case DOOR_CALL_ALLOC_INLINE_8K:
		uma_zfree(door_call_inline_8k_zone, call);
		break;
	case DOOR_CALL_ALLOC_MALLOC:
		free(call, M_DOORFS);
		break;
	default:
		panic("door_call_drop: invalid allocation class %u",
		    call->dc_alloc_class);
	}
}

/*
 * Cancel scheduler wait intent before reusing the call. Private shuttle
 * waits bypass sleepqueues; CV is the fallback for unsupported waits.
 */
static void
door_call_shuttle_disarm_locked(struct door_call *call, struct thread *td)
{
	if (call->dc_client_shuttle_armed) {
		thread_lock(td);
		sched_shuttle_abort(td);
		thread_unlock(td);
		call->dc_client_shuttle_armed = false;
	}
}

/*
 * Private Door wait (the v6.2 hot path) bypasses CV/sleepqueue.
 * ULE and 4BSD publish PREPARED under d_lock, then park only after unlock:
 * a mutex owner must remain RUNNING for turnstile priority propagation.
 * Unsupported waits return EOPNOTSUPP for CV fallback. A pre-existing AST
 * returns neutrally without arming; the caller rechecks state and ASTs.
 */
static int
door_shuttle_wait_locked(struct door *door, struct thread *td,
    struct thread *peer, const void *wchan, int flags,
    struct door_server_binding *dispatch_ds, bool *usedp)
{
	enum sched_shuttle_result sr;
	int error;

	mtx_assert(&door->d_lock, MA_OWNED);
	*usedp = false;
#ifdef DOORFS_TEST
	if (door_test_cv_requested())
		return (EOPNOTSUPP);
#endif

	if ((flags & DOOR_SHUTTLE_F_INTERRUPTIBLE) != 0 &&
	    ((td->td_pflags & TDP_WAKEUP) != 0 || td_ast_pending(td, TDA_SIG) ||
		td_ast_pending(td, TDA_SUSPEND)))
		return (0);

	thread_lock(td);
	sr = sched_shuttle_sleep(td, peer, wchan, flags);
	thread_unlock(td);
	if (sr != SCHED_SHUTTLE_OK)
		return (EOPNOTSUPP);

	*usedp = true;

	/*
	 * Initial CALL dispatch is done while d_lock is still held, exactly like
	 * illumos shuttle_resume(..., &door_knob).  door_server_wake_locked()
	 * first attempts a same-CPU exact successor and then performs a normal
	 * scheduler wake for a remote/non-direct target.
	 */
	if (dispatch_ds != NULL)
		door_server_wake_locked(dispatch_ds);

	mtx_unlock(&door->d_lock);
#ifdef DOORFS_TEST
	if ((flags & DOOR_SHUTTLE_F_IDLE_WAIT) == 0)
		door_test_gate(DOOR_TEST_PREPARK);
#endif

	/*
	 * sched_shuttle_sleep() only published a private PREPARED intent while
	 * d_lock was held.  The scheduler may turn it into SHUTTLE_WAIT only
	 * after this unlock.  This avoids exposing a non-running Door mutex owner
	 * to FreeBSD turnstile priority propagation on remote-CPU handoffs.
	 *
	 * A signal/suspend which becomes pending in this window does not need to
	 * manufacture a wakeup: abort the intent and let the existing Door
	 * post-wake AST code process it after d_lock is reacquired.
	 */
	if ((flags & DOOR_SHUTTLE_F_INTERRUPTIBLE) != 0 &&
	    (td_ast_pending(td, TDA_SIG) || td_ast_pending(td, TDA_SUSPEND))) {
		thread_lock(td);
		sched_shuttle_abort(td);
		thread_unlock(td);
		sr = SCHED_SHUTTLE_ABORTED;
	} else {
		thread_lock(td);
		sr = sched_shuttle_swtch(td, flags);
		if (sr != SCHED_SHUTTLE_OK)
			thread_unlock(td);
		KASSERT(sr == SCHED_SHUTTLE_OK || sr == SCHED_SHUTTLE_ABORTED,
		    ("Door private shuttle switch failed: %d", sr));
	}

	thread_lock(td);
	error =
	    ((flags & DOOR_SHUTTLE_F_INTERRUPTIBLE) != 0) ? td->td_intrval : 0;
	td->td_intrval = 0;
	td->td_flags &= ~TDF_SINTR;
	thread_unlock(td);

	mtx_lock(&door->d_lock);
	return (error);
}

static int
door_call_spin_client_locked(struct door *door, struct door_call *call,
    struct thread *peer, struct door_server_binding *dispatch_ds)
{
	u_int i, spins;
	int client_cpu, peer_cpu;

	mtx_assert(&door->d_lock, MA_OWNED);
	spins = door_client_spins;
	if (spins == 0 || peer == NULL || dispatch_ds == NULL)
		return (0);

	/*
	 * td_lastcpu is advisory here.  A migration can only turn this bounded
	 * optimization into a miss; the d_lock interlock below preserves the
	 * ordinary wait path.  Never spin deliberately when both partners are
	 * known to share a CPU, because the worker could not run.
	 */
	client_cpu = PCPU_GET(cpuid);
	peer_cpu = peer->td_lastcpu;
	if (peer_cpu == NOCPU || peer_cpu == client_cpu)
		return (0);

	door_server_wake_locked(dispatch_ds);
	mtx_unlock(&door->d_lock);
	for (i = 0; i < spins; i++) {
		if (atomic_load_acq_int(&call->dc_client_ready) != 0)
			break;
		cpu_spinwait();
	}
	mtx_lock(&door->d_lock);

	/* The assigned worker was already woken; the caller must not repeat it. */
	return (1);
}

static int
door_call_wait_client_locked(struct door *door, struct door_call *call,
    struct thread *td, bool interruptible,
    struct door_server_binding *dispatch_ds)
{
	struct thread *peer;
	int flags, error;
	bool used;

	flags = DOOR_SHUTTLE_F_REPLY;
	if (interruptible)
		flags |= DOOR_SHUTTLE_F_INTERRUPTIBLE;

	peer = NULL;
	if (call->dc_server_td != NULL && call->dc_server_td != td)
		peer = call->dc_server_td;
	if (door_call_spin_client_locked(door, call, peer, dispatch_ds)) {
		dispatch_ds = NULL;
		if (atomic_load_acq_int(&call->dc_client_ready) != 0)
			return (0);
	}

	/*
	 * Arm client wakeup independently of whether a concrete server is
	 * already known.  A pending caller with peer == NULL is still a private
	 * shuttle waiter and revoke/cancel must wake it through scheduler state,
	 * not merely broadcast dc_cv.
	 */
	call->dc_client_shuttle_armed = true;

	error = door_shuttle_wait_locked(
	    door, td, peer, &call->dc_cv, flags, dispatch_ds, &used);
	if (used) {
		call->dc_client_shuttle_armed = false;
		return (error);
	}

	call->dc_client_shuttle_armed = false;
	if (error != EOPNOTSUPP)
		return (error);

	/*
	 * Only an unsupported private wait reaches the CV fallback.
	 * Neutral AST returns are handled by the caller's state/AST recheck.
	 */
	if (peer != NULL)
		call->dc_client_shuttle_armed = true;

	if (call->dc_client_shuttle_armed) {
		if (interruptible)
			error = cv_wait_sig_shuttle(&call->dc_cv, &door->d_lock,
			    peer,
			    dispatch_ds != NULL ? dispatch_ds->ds_td : NULL,
			    dispatch_ds != NULL ? &dispatch_ds->ds_cv : NULL,
			    flags);
		else {
			cv_wait_shuttle(&call->dc_cv, &door->d_lock, peer,
			    dispatch_ds != NULL ? dispatch_ds->ds_td : NULL,
			    dispatch_ds != NULL ? &dispatch_ds->ds_cv : NULL,
			    flags);
			error = 0;
		}
	} else if (interruptible) {
		error = cv_wait_sig(&call->dc_cv, &door->d_lock);
	} else {
		cv_wait(&call->dc_cv, &door->d_lock);
		error = 0;
	}

	door_call_shuttle_disarm_locked(call, td);
	return (error);
}

/*
 * Stop/ptrace is handled with resource-safe deferred suspension. Drop d_lock
 * for the suspend check, then recheck dc_state: completion may have raced it.
 * CALL enters with SIGDEFERSTOP_SILENT in door_syscall.c; this check does not
 * suspend the live kernel stack. A required unwind or interrupting signal
 * returns to the normal syscall/AST path with existing cancellation rules.
 */
static int
door_call_postwake_ast_locked(struct door *door, struct door_call *call,
    struct thread *td, bool interruptible)
{
	struct proc *p;
	int error;

	mtx_assert(&door->d_lock, MA_OWNED);

	if (!interruptible)
		return (0);

	if (call->dc_state == DOOR_CALL_DONE ||
	    call->dc_state == DOOR_CALL_CANCELLED ||
	    call->dc_state == DOOR_CALL_REVOKED)
		return (0);

	/*
	 * Do not suspend while owning RPC resources. return_instead=1 checks for
	 * required unwind; ordinary deferred stops are handled at the syscall boundary.
	 */
	if (td_ast_pending(td, TDA_SUSPEND)) {
		p = td->td_proc;

		mtx_unlock(&door->d_lock);
		PROC_LOCK(p);
		/*
		 * CALL syscall entry defers ordinary stops with TDF_SBDRY.  Use the
		 * resource-safe form: it never suspends or exits this kernel stack.
		 * SIGSTOP/ptrace therefore returns 0 while deferred; SINGLE_EXIT
		 * returns EINTR and forces a normal syscall unwind.
		 */
		error = thread_suspend_check(1);
		PROC_UNLOCK(p);
		mtx_lock(&door->d_lock);

		if (call->dc_state == DOOR_CALL_DONE ||
		    call->dc_state == DOOR_CALL_CANCELLED ||
		    call->dc_state == DOOR_CALL_REVOKED)
			return (0);
		if (error != 0)
			return (error);
	}

	/*
	 * A deferred stop need not have been consumed. Process remaining signal
	 * ASTs through the ordinary interruptible-call path after the state recheck.
	 */
	if (!td_ast_pending(td, TDA_SIG))
		return (0);

	mtx_unlock(&door->d_lock);
	error = sig_intr();
	mtx_lock(&door->d_lock);

	if (call->dc_state == DOOR_CALL_DONE ||
	    call->dc_state == DOOR_CALL_CANCELLED ||
	    call->dc_state == DOOR_CALL_REVOKED)
		return (0);

	return (error);
}

void
door_call_wake_client_locked(struct door_call *call, int flags)
{
	enum sched_shuttle_result result;
	struct thread *client;

	if (__predict_false(call->dc_oneway))
		return;
	if (call->dc_state == DOOR_CALL_DONE ||
	    call->dc_state == DOOR_CALL_CANCELLED ||
	    call->dc_state == DOOR_CALL_REVOKED)
		atomic_store_rel_int(&call->dc_client_ready, 1);

	client = call->dc_client_td;
	if (call->dc_client_shuttle_armed && client != NULL) {
		/*
		 * Only the assigned server owns a direct client continuation.  A
		 * cancel, revoke, process-exit, or other third-party wake returns to
		 * its own caller and therefore cannot consume a scheduler shuttle
		 * reservation.  Publish those clients through the ordinary runnable
		 * path instead.
		 */
		if (call->dc_server_td == curthread) {
			result =
			    sched_shuttle_resume_to(client, curthread, flags);
			if (result != SCHED_SHUTTLE_OK)
				result = sched_shuttle_resume(client, flags);
		} else {
			result = sched_shuttle_resume(
			    client, flags | DOOR_SHUTTLE_F_ASYNC_WAKE);
		}
		if (result == SCHED_SHUTTLE_OK || result == SCHED_SHUTTLE_RETRY)
			return;
		call->dc_client_shuttle_armed = false;
	}
	cv_broadcast(&call->dc_cv);
}

/*
 * Wake private ULE/4BSD waiters through sched_shuttle_resume(). Unsupported
 * or generic CV waits use cv_signal(); d_lock serializes assignment and wake.
 */
static void
door_server_wake_flags_locked(struct door_server_binding *ds, int flags)
{
	enum sched_shuttle_result result;

	result = sched_shuttle_resume_to(ds->ds_td, curthread, flags);

	if (result != SCHED_SHUTTLE_OK) {
		result = sched_shuttle_resume(ds->ds_td, flags);
	}
	if (result == SCHED_SHUTTLE_OK || result == SCHED_SHUTTLE_RETRY)
		return;
	cv_signal(&ds->ds_cv);
}

void
door_server_wake_locked(struct door_server_binding *ds)
{
	door_server_wake_flags_locked(ds, DOOR_SHUTTLE_F_DISPATCH);
}

/*
 * Wake a worker when the current thread will return instead of consuming a
 * direct-successor reservation with mi_switch_shuttle().  ONEWAY, UNREF and
 * revoke all have this asynchronous ownership model.
 */
void
door_server_wake_async_locked(struct door_server_binding *ds)
{
	door_server_wake_flags_locked(
	    ds, DOOR_SHUTTLE_F_DISPATCH | DOOR_SHUTTLE_F_ASYNC_WAKE);
}

/*
 * d_lock must be held.
 *
 * Normal Door servers spend most of their life with the same one/few workers
 * cycling through RETURN.  Remember an already-published idle worker so CALL
 * does not linearly scan d_servers on every RPC.  The list remains
 * authoritative; the hint never owns a reference.
 */
static struct door_server_binding *
door_idle_server_find_locked(struct door *door)
{
	struct door_server_binding *ds;

	mtx_assert(&door->d_lock, MA_OWNED);

	ds = door->d_idle_server_hint;
	if (__predict_true(ds != NULL && ds->ds_waiting && ds->ds_call == NULL))
		return (ds);

	door->d_idle_server_hint = NULL;
	LIST_FOREACH(ds, &door->d_servers, ds_link)
	{
		if (ds->ds_waiting && ds->ds_call == NULL) {
			door->d_idle_server_hint = ds;
			return (ds);
		}
	}
	return (NULL);
}

/* d_lock must be held. */
static void
door_server_set_waiting_locked(
    struct door *door, struct door_server_binding *ds, bool waiting)
{
	mtx_assert(&door->d_lock, MA_OWNED);

	ds->ds_waiting = waiting;
	if (waiting) {
		if (door->d_idle_server_hint == NULL)
			door->d_idle_server_hint = ds;
	} else if (door->d_idle_server_hint == ds) {
		/*
		 * Do not scan for a replacement here.  The next dispatch miss will
		 * find and cache another idle worker if one exists.
		 */
		door->d_idle_server_hint = NULL;
	}
}

/* d_lock must be held; call must not be linked on either call queue. */
static void
door_call_activate_locked(
    struct door *door, struct door_call *call, struct door_server_binding *ds)
{
	KASSERT(ds->ds_call == NULL, ("dispatching to busy server"));
	KASSERT(call->dc_state == DOOR_CALL_PENDING,
	    ("dispatching call in state %d", call->dc_state));

	door_server_set_waiting_locked(door, ds, false);
	if (call->dc_type == DOOR_CALL_RPC) {
		door_call_hold(call); /* server reference */
	}
	call->dc_state = DOOR_CALL_ACTIVE;
	TAILQ_INSERT_TAIL(&door->d_active, call, dc_link);
	door->d_active_count++;
	ds->ds_call = call;
	call->dc_server_td = ds->ds_td;

	/*
	 * A pending ONEWAY call owns one asynchronous queue reference after the
	 * submitting thread returns.  Once a server owns the call, transfer that
	 * lifetime to the server reference.
	 */
	if (__predict_false(call->dc_oneway)) {
		door_call_drop(call);
	}
}

/*
 * Assign or queue only; waking is a separate step. A waiting RPC client
 * prepares its own wait before door_server_wake_locked() tries resume_to/resume.
 * Producers and UNREF have no reply waiter and use the async wake helper.
 */
static struct door_server_binding *
door_call_dispatch_locked(struct door *door, struct door_call *call)
{
	struct door_server_binding *ds;

	ds = door_idle_server_find_locked(door);
	if (ds != NULL) {
		door_call_activate_locked(door, call, ds);
		return (ds);
	}

	TAILQ_INSERT_TAIL(&door->d_pending, call, dc_link);
	door->d_pending_count++;
	return (NULL);
}

void
door_unref_drop(struct door_call *call)
{
	KASSERT(call->dc_type == DOOR_CALL_UNREF,
	    ("dropping non-UNREF call as UNREF"));
	door_call_drop(call);
}

void
door_oneway_drop(struct door_call *call)
{
	KASSERT(call->dc_type == DOOR_CALL_RPC && call->dc_oneway,
	    ("dropping non-ONEWAY call as ONEWAY"));
	door_call_drop(call);
}

/*
 * Drop an ONEWAY call whose lifetime is currently owned by an assigned server
 * binding.  Revoke uses this after detaching ds_call under d_lock.
 */
void
door_oneway_server_drop(struct door_call *call)
{
	KASSERT(call->dc_type == DOOR_CALL_RPC && call->dc_oneway,
	    ("dropping non-ONEWAY server call as ONEWAY"));
	door_call_drop(call);
}

void
door_unref_enqueue(struct door *door, uint64_t generation)
{
	struct door_server_binding *dispatch_ds;
	struct door_call *call;

	call = door_call_alloc_fixed();
	refcount_init(&call->dc_refs, 1);
	call->dc_type = DOOR_CALL_UNREF;
	call->dc_state = DOOR_CALL_PENDING;
	atomic_store_rel_int(&call->dc_request_ready, 1);
	call->dc_unref_generation = generation;

	mtx_lock(&door->d_lock);
	if (door->d_revoked) {
		mtx_unlock(&door->d_lock);
		door_call_drop(call);
		return;
	}
	call->dc_id = door->d_next_call_id++;
	if (door->d_next_call_id == 0)
		door->d_next_call_id = 1;
	dispatch_ds = door_call_dispatch_locked(door, call);
	if (dispatch_ds != NULL)
		door_server_wake_async_locked(dispatch_ds);
	mtx_unlock(&door->d_lock);
}

static int
door_capture_fd(struct thread *td, int fd, struct file **fpp,
    struct filecaps *fcaps)
{
	struct file *fp;
	int error;

	*fpp = NULL;
	if (fd < 0)
		return (0);
	error = fget_cap(td, fd, &cap_no_rights, NULL, &fp, fcaps);
	if (error != 0)
		return (error);
	if ((fp->f_ops->fo_flags & DFLAG_PASSABLE) == 0) {
		fdrop(fp, td);
		filecaps_free(fcaps);
		return (EOPNOTSUPP);
	}
	*fpp = fp;
	return (0);
}

/*
 * Remove fd from the current process only if it still names fp.  fdclose()
 * is specifically designed to handle a concurrent close/reuse race.
 */
static void
door_move_source_fd(struct thread *td, struct door *door __unused,
    struct door_call *call __unused, struct file *fp, int fd)
{
	if (fp != NULL && fd >= 0)
		fdclose(td, fp, fd);
}

static void
door_fd_bundle_drop(struct door_fd_bundle *bundle, struct thread *td)
{
	uint32_t i;
	if (bundle->df_files != NULL) {
		for (i = 0; i < bundle->df_count; i++) {
			if (bundle->df_files[i] != NULL) {
				fdrop(bundle->df_files[i], td);
			}
		}
		free(bundle->df_files, M_DOORFS);
	}
	if (bundle->df_caps != NULL) {
		for (i = 0; i < bundle->df_count; i++)
			filecaps_free(&bundle->df_caps[i]);
		free(bundle->df_caps, M_DOORFS);
	}
	free(bundle->df_source_fds, M_DOORFS);
	free(bundle->df_flags, M_DOORFS);
	bzero(bundle, sizeof(*bundle));
}

static int
door_fd_bundle_capture(struct thread *td, uint64_t desc_ptr,
    uint32_t desc_count, int legacy_fd, struct door_fd_bundle *bundle)
{
	struct door_kdesc *descs;
	uint32_t i, count;
	int error;

	bzero(bundle, sizeof(*bundle));
	if (desc_count > DOOR_MAX_DESC)
		return (E2BIG);
	if (desc_count != 0 && desc_ptr == 0)
		return (EINVAL);
	if (desc_count != 0 && legacy_fd >= 0)
		return (EINVAL);
	count = desc_count != 0 ? desc_count : (legacy_fd >= 0 ? 1 : 0);
	if (count == 0)
		return (0);

	descs = mallocarray(count, sizeof(*descs), M_DOORFS, M_WAITOK | M_ZERO);
	if (desc_count != 0) {
		error = copyin((const void *)(uintptr_t)desc_ptr, descs,
		    count * sizeof(*descs));
		if (error != 0) {
			free(descs, M_DOORFS);
			return (error);
		}
	} else {
		descs[0].dd_fd = legacy_fd;
		descs[0].dd_flags = DOOR_DESC_F_MOVE;
	}

	bundle->df_files = mallocarray(
	    count, sizeof(*bundle->df_files), M_DOORFS, M_WAITOK | M_ZERO);
	bundle->df_caps = mallocarray(
	    count, sizeof(*bundle->df_caps), M_DOORFS, M_WAITOK | M_ZERO);
	bundle->df_source_fds = mallocarray(
	    count, sizeof(*bundle->df_source_fds), M_DOORFS, M_WAITOK | M_ZERO);
	bundle->df_flags = mallocarray(
	    count, sizeof(*bundle->df_flags), M_DOORFS, M_WAITOK | M_ZERO);
	bundle->df_count = count;
	for (i = 0; i < count; i++)
		filecaps_init(&bundle->df_caps[i]);
	for (i = 0; i < count; i++) {
		if (descs[i].dd_fd < 0 ||
		    (descs[i].dd_flags & ~DOOR_DESC_F_MOVE) != 0) {
			error = EINVAL;
			goto fail;
		}
		bundle->df_source_fds[i] = descs[i].dd_fd;
		bundle->df_flags[i] = descs[i].dd_flags;
		error = door_capture_fd(td, descs[i].dd_fd,
		    &bundle->df_files[i], &bundle->df_caps[i]);
		if (error != 0)
			goto fail;
	}
	free(descs, M_DOORFS);
	return (0);
fail:
	free(descs, M_DOORFS);
	door_fd_bundle_drop(bundle, td);
	return (error);
}

static int
door_fd_bundle_install(struct thread *td, struct door_fd_bundle *bundle,
    uint64_t out_ptr, uint32_t capacity, int *legacy_out)
{
	struct door_kdesc *out;
	uint32_t i;
	int error;

	if (legacy_out != NULL)
		*legacy_out = -1;
	if (bundle->df_count == 0)
		return (0);
	if (bundle->df_count > capacity && out_ptr != 0)
		return (EMSGSIZE);
	if (out_ptr == 0 && bundle->df_count > 1)
		return (EMSGSIZE);

	out = mallocarray(
	    bundle->df_count, sizeof(*out), M_DOORFS, M_WAITOK | M_ZERO);
	for (i = 0; i < bundle->df_count; i++) {
		error = finstall(td, bundle->df_files[i], &out[i].dd_fd, 0,
		    &bundle->df_caps[i]);
		if (error != 0)
			goto rollback;
		/* MOVE is a sender-side transfer instruction, not receiver state. */
		out[i].dd_flags = 0;
	}
	if (out_ptr != 0) {
		error = copyout(out, (void *)(uintptr_t)out_ptr,
		    bundle->df_count * sizeof(*out));
		if (error != 0)
			goto rollback;
	}
	if (legacy_out != NULL)
		*legacy_out = out[0].dd_fd;
	free(out, M_DOORFS);
	return (0);
rollback:
	while (i-- != 0)
		fdclose(td, bundle->df_files[i], out[i].dd_fd);
	free(out, M_DOORFS);
	return (error);
}

static bool
door_fd_bundle_has_move(const struct door_fd_bundle *bundle)
{
	uint32_t i;

	for (i = 0; i < bundle->df_count; i++) {
		if ((bundle->df_flags[i] & DOOR_DESC_F_MOVE) != 0)
			return (true);
	}
	return (false);
}

static void
door_fd_bundle_move_sources(struct thread *td, struct door *door,
    struct door_call *call, struct door_fd_bundle *bundle)
{
	uint32_t i;

	for (i = 0; i < bundle->df_count; i++) {
		if ((bundle->df_flags[i] & DOOR_DESC_F_MOVE) == 0)
			continue;
		door_move_source_fd(td, door, call, bundle->df_files[i],
		    bundle->df_source_fds[i]);
	}
}

static void
door_server_binding_hold(struct door_server_binding *ds)
{
	refcount_acquire(&ds->ds_refs);
}

static void
door_server_binding_drop(struct door_server_binding *ds)
{
	struct door *door;

	if (!refcount_release(&ds->ds_refs))
		return;

	KASSERT(!ds->ds_linked, ("freeing linked door server binding"));
	KASSERT(!ds->ds_global_linked,
	    ("freeing globally linked door server binding"));
	KASSERT(ds->ds_call == NULL,
	    ("freeing door server binding with assigned call"));
	KASSERT(ds->ds_td == NULL || ds->ds_td->td_door_server != ds,
	    ("freeing published door server binding"));

	door = ds->ds_door;
	ds->ds_door = NULL;

	cv_destroy(&ds->ds_cv);
	door_reply_cache_drop(ds->ds_reply_cache);
	ds->ds_reply_cache = NULL;

	if (ds->ds_door_ref) {
		ds->ds_door_ref = false;
		door_drop(door);
	}
#ifdef DOORFS_TEST
	door_test_object_drop(DOOR_TEST_OBJ_BINDING);
#endif
	free(ds, M_DOORFS);
}

static struct door_server_binding *
door_server_find_locked(struct door *door, struct thread *td)
{
	struct door_server_binding *ds;

	mtx_assert(&door->d_lock, MA_OWNED);

	ds = td->td_door_server;
	if (__predict_true(ds != NULL && ds->ds_td == td &&
			   ds->ds_door == door && ds->ds_linked))
		return (ds);
	return (NULL);
}

int
door_server_bind(struct door *door, struct thread *td)
{
	struct door_server_binding *ds;
	int error;

	if (__predict_false(td->td_door_server != NULL))
		return (EBUSY);

	ds = malloc(sizeof(*ds), M_DOORFS, M_WAITOK | M_ZERO);
#ifdef DOORFS_TEST
	door_test_object_add(DOOR_TEST_OBJ_BINDING);
#endif
	ds->ds_reply_cache = door_reply_cache_alloc(DOOR_REPLY_PAGE_THRESHOLD);
	cv_init(&ds->ds_cv, "doorsrv");
	refcount_init(&ds->ds_refs, 1); /* structural binding reference */
	ds->ds_door = door;
	ds->ds_td = td;
	ds->ds_proc = td->td_proc;

	error = door_owner_lock(door, td->td_proc);
	if (error != 0) {
		cv_destroy(&ds->ds_cv);
		door_reply_cache_drop(ds->ds_reply_cache);
		ds->ds_reply_cache = NULL;
#ifdef DOORFS_TEST
		door_test_object_drop(DOOR_TEST_OBJ_BINDING);
#endif
		free(ds, M_DOORFS);
		return (error);
	}

	if (door_server_find_locked(door, td) != NULL)
		error = EINVAL;
	else if (door->d_server_count >= door_max_servers_per_door)
		error = EAGAIN;
	else {
		/*
		 * A binding is a first-class reference to the door object.  The
		 * descriptor used to bind is only a lookup handle; closing
		 * or duplicating that descriptor does not affect the binding.
		 */
		door_hold(door);
		ds->ds_door_ref = true;
		LIST_INSERT_HEAD(&door->d_servers, ds, ds_link);
		ds->ds_linked = true;
		door->d_server_count++;

		mtx_lock(&door_binding_registry_lock);
		LIST_INSERT_HEAD(&door_binding_registry, ds, ds_global_link);
		ds->ds_global_linked = true;
		mtx_unlock(&door_binding_registry_lock);

		/* Publish last: a non-NULL thread slot always names a live binding. */
		td->td_door_server = ds;

		ds = NULL;
	}
	mtx_unlock(&door->d_lock);

	if (ds != NULL) {
		cv_destroy(&ds->ds_cv);
		door_reply_cache_drop(ds->ds_reply_cache);
		ds->ds_reply_cache = NULL;
#ifdef DOORFS_TEST
		door_test_object_drop(DOOR_TEST_OBJ_BINDING);
#endif
		free(ds, M_DOORFS);
	}
	return (error);
}

/*
 * Remove a binding while d_lock is held.  The caller MUST drop the binding's
 * door reference after releasing d_lock.
 */
static bool
door_server_remove_locked(struct door *door, struct door_server_binding *ds)
{
	bool drop_ref;

	KASSERT(ds->ds_call == NULL, ("removing bound door server"));

	/*
	 * Removal is idempotent from the binding owner's point of view.  Owner
	 * process teardown only revokes/wakes; nevertheless this also makes
	 * RETURN robust against a second owner-side cleanup path.
	 */
	if (!ds->ds_linked)
		return (false);

	door_server_set_waiting_locked(door, ds, false);
	if (ds->ds_td != NULL && ds->ds_td->td_door_server == ds)
		ds->ds_td->td_door_server = NULL;
	LIST_REMOVE(ds, ds_link);
	ds->ds_linked = false;
	door->d_server_count--;

	/*
	 * Removal holds d_lock before the registry lock. No registry user acquires
	 * d_lock while holding that lock; thread cleanup pins the direct thread slot.
	 */
	mtx_lock(&door_binding_registry_lock);
	if (ds->ds_global_linked) {
		LIST_REMOVE(ds, ds_global_link);
		ds->ds_global_linked = false;
	}
	mtx_unlock(&door_binding_registry_lock);

	/*
	 * Return true when the structural binding reference must be dropped
	 * after d_lock is released.  The Door reference is released only when the
	 * final ds reference disappears, so a temporary thread-dtor lookup keeps
	 * both binding and Door alive.
	 */
	drop_ref = true;
	return (drop_ref);
}

static int
door_server_unbind(struct door *door, struct thread *td)
{
	struct door_server_binding *ds;
	bool drop_ref;
	int error;

	drop_ref = false;
	error = 0;
	mtx_lock(&door->d_lock);
	ds = door_server_find_locked(door, td);
	if (ds == NULL)
		error = EINVAL;
	else if (ds->ds_call != NULL)
		error = EBUSY;
	else
		drop_ref = door_server_remove_locked(door, ds);
	mtx_unlock(&door->d_lock);

	if (drop_ref)
		door_server_binding_drop(ds);
	return (error);
}

/*
 * Tear down the binding owned by td.  This is the synchronous counterpart
 * to thread_dtor cleanup and is used when libdoor observes pthread_exit() in
 * a server callback.  The active client is released immediately instead of
 * waiting for the kernel thread object to be reaped.
 */
static int
door_server_worker_exit(struct door *door, struct thread *td)
{
	struct door_async_batch batch;
	struct door_server_binding *ds;
	struct door_call *call;
	bool drop_ref;

	call = NULL;
	drop_ref = false;
	door_async_batch_init(&batch);

	mtx_lock(&door->d_lock);
	ds = door_server_find_locked(door, td);
	if (ds == NULL) {
		mtx_unlock(&door->d_lock);
		return (EINVAL);
	}

	call = ds->ds_call;
	if (call != NULL) {
		ds->ds_call = NULL;
		if (call->dc_state == DOOR_CALL_ACTIVE ||
		    call->dc_state == DOOR_CALL_CANCELLED) {
			TAILQ_REMOVE(&door->d_active, call, dc_link);
			door->d_active_count--;
		}
		if (call->dc_state == DOOR_CALL_ACTIVE) {
			call->dc_error = ECONNRESET;
			call->dc_state = DOOR_CALL_DONE;
			if (call->dc_async)
				door_async_schedule_locked(
				    door, call, ECONNRESET, NULL, 0, &batch);
			if (call->dc_type != DOOR_CALL_UNREF)
				door_call_wake_client_locked(
				    call, DOOR_SHUTTLE_F_REPLY);
		}
		call->dc_server_td = NULL;
	}

	drop_ref = door_server_remove_locked(door, ds);
	mtx_unlock(&door->d_lock);
	door_async_batch_flush(&batch);

	if (call != NULL) {
		door_call_drop(call);
	}
	if (drop_ref)
		door_server_binding_drop(ds);
	return (0);
}

int
door_server_unbind_bound(struct thread *td)
{
	struct door_server_binding *ds;

	ds = td->td_door_server;
	if (ds == NULL || ds->ds_td != td || ds->ds_door == NULL)
		return (EINVAL);
	return (door_server_unbind(ds->ds_door, td));
}

int
door_server_worker_exit_bound(struct thread *td)
{
	struct door_server_binding *ds;

	ds = td->td_door_server;
	if (ds == NULL || ds->ds_td != td || ds->ds_door == NULL)
		return (EINVAL);
	return (door_server_worker_exit(ds->ds_door, td));
}

int
door_return_bound_direct(struct door *door, struct thread *td,
    struct door_server_binding *ds, struct door_ioc_return_shm *ret,
    uint64_t *fast_result)
{
	/* A vfork child has a new thread and cannot inherit td_door_server. */
	return (door_return(door, &ret->dirs_return, td, &ret->dirs_shm,
	    &ret->dirs_shm_ptr, ds, true, fast_result));
}

static void
door_export_cred(struct door_call *call, struct door_kcred *out)
{
	struct ucred *cr;
	u_int i, n;

	bzero(out, sizeof(*out));
	cr = call->dc_cred;
	out->dc_euid = cr->cr_uid;
	out->dc_ruid = cr->cr_ruid;
	out->dc_suid = cr->cr_svuid;
	out->dc_egid = cr->cr_gid;
	out->dc_rgid = cr->cr_rgid;
	out->dc_sgid = cr->cr_svgid;
	out->dc_pid = call->dc_pid;
	out->dc_jid = cr->cr_prison->pr_id;
	n = MIN((u_int)cr->cr_ngroups, (u_int)DOOR_CRED_MAX_GROUPS);
	out->dc_ngroups = n;
	for (i = 0; i < n; i++)
		out->dc_groups[i] = cr->cr_groups[i];
}

int
door_server_cred(
    struct door *door, struct thread *td, struct door_ioc_cred *arg)
{
	struct door_server_binding *ds;
	struct door_call *call;
	int error;

	if (arg->dicr_version != DOOR_ABI_VERSION || arg->dicr_reserved != 0 ||
	    arg->dicr_call_id == 0)
		return (EINVAL);
	if ((door->d_attributes & DOOR_NO_CRED) != 0)
		return (ENOTSUP);

	error = 0;
	mtx_lock(&door->d_lock);
	ds = door_server_find_locked(door, td);
	if (ds == NULL || (call = ds->ds_call) == NULL ||
	    call->dc_id != arg->dicr_call_id ||
	    call->dc_type == DOOR_CALL_UNREF)
		error = EINVAL;
	else {
		door_export_cred(call, &arg->dicr_cred);
		arg->dicr_padding = 0;
	}
	mtx_unlock(&door->d_lock);
	return (error);
}

int
door_server_cred_bound(struct thread *td, struct door_ioc_cred *arg)
{
	struct door_server_binding *ds;

	ds = td->td_door_server;
	if (ds == NULL || ds->ds_td != td || ds->ds_door == NULL)
		return (EINVAL);
	return (door_server_cred(ds->ds_door, td, arg));
}

/* Caller-supplied IDs must be unique among live queued/active calls. */
static int
door_call_check_id_locked(struct door *door, uint64_t id)
{
 struct door_call *iter;
 mtx_assert(&door->d_lock, MA_OWNED);
 TAILQ_FOREACH(iter, &door->d_pending, dc_link)
  if (iter->dc_id == id)
   return (EEXIST);
 TAILQ_FOREACH(iter, &door->d_active, dc_link)
  if (iter->dc_id == id)
   return (EEXIST);
 return (0);
}

static __inline int
door_call_assign_id_locked(struct door *door, struct door_call *call,
    uint64_t *idp, bool supplied)
{
 int error;
 if (supplied) {
  error = door_call_check_id_locked(door, *idp);
  if (error != 0)
   return (error);
  call->dc_id = *idp;
 } else {
  call->dc_id = door->d_next_call_id++;
  if (door->d_next_call_id == 0)
   door->d_next_call_id = 1;
  *idp = call->dc_id;
 }
 return (0);
}

/* Cancel a call while d_lock is held. */
static int
door_cancel_call_locked(struct door *door, struct door_call *call, int error,
    struct door_async_batch *batch)
{
	bool active;

	active = call->dc_state == DOOR_CALL_ACTIVE;
	switch (call->dc_state) {
	case DOOR_CALL_PENDING:
		TAILQ_REMOVE(&door->d_pending, call, dc_link);
		door->d_pending_count--;
		break;
	case DOOR_CALL_ACTIVE:
		break;
	case DOOR_CALL_DONE:
	case DOOR_CALL_CANCELLED:
	case DOOR_CALL_REVOKED:
		return (EALREADY);
	default:
		return (EINVAL);
	}
	call->dc_error = error;
	call->dc_state = DOOR_CALL_CANCELLED;
	if (call->dc_async)
		door_async_schedule_locked(door, call, error, NULL, 0, batch);
	if (active)
		cv_broadcast(&call->dc_cv);
	door_call_wake_client_locked(call, DOOR_SHUTTLE_F_REPLY);
	return (0);
}

int
door_cancel(struct door *door, struct door_ioc_cancel *arg, struct thread *td)
{
	struct door_async_batch batch;
	struct door_call *call;
	int error;

	if (arg->dican_version != DOOR_ABI_VERSION || arg->dican_call_id == 0)
		return (EINVAL);

	error = ESRCH;
	door_async_batch_init(&batch);
	mtx_lock(&door->d_lock);
	if ((door->d_attributes & DOOR_NO_CANCEL) != 0) {
		mtx_unlock(&door->d_lock);
		return (ENOTSUP);
	}
	TAILQ_FOREACH(call, &door->d_pending, dc_link)
	{
		if (call->dc_id == arg->dican_call_id &&
		    call->dc_client == td->td_proc) {
			error = door_cancel_call_locked(door, call, ECANCELED, &batch);
			goto out;
		}
	}
	TAILQ_FOREACH(call, &door->d_active, dc_link)
	{
		if (call->dc_id == arg->dican_call_id &&
		    call->dc_client == td->td_proc) {
			error = door_cancel_call_locked(door, call, ECANCELED, &batch);
			goto out;
		}
	}
out:
	mtx_unlock(&door->d_lock);
	door_async_batch_flush(&batch);
	return (error);
}

int
door_async_cancel(struct door *door, struct door *target, uint64_t id)
{
	struct door_async_batch batch;
	struct door_call *call, *drop;
	int error;

	if (id == 0)
		return (EINVAL);
	drop = NULL;
	error = ESRCH;
	door_async_batch_init(&batch);
	mtx_lock(&door->d_lock);
	if ((door->d_attributes & DOOR_NO_CANCEL) != 0) {
		mtx_unlock(&door->d_lock);
		return (ENOTSUP);
	}
	TAILQ_FOREACH(call, &door->d_pending, dc_link) {
		if (call->dc_async && call->dc_id == id &&
		    call->dc_async_target == target) {
			error = door_cancel_call_locked(door, call, ECANCELED, &batch);
			if (error == 0)
				drop = call; /* queue reference */
			goto out;
		}
	}
	TAILQ_FOREACH(call, &door->d_active, dc_link) {
		if (call->dc_async && call->dc_id == id &&
		    call->dc_async_target == target) {
			error = door_cancel_call_locked(door, call, ECANCELED, &batch);
			goto out;
		}
	}
out:
	mtx_unlock(&door->d_lock);
	door_async_batch_flush(&batch);
	if (drop != NULL)
		door_call_drop(drop);
	return (error);
}

static uint32_t
door_input_desc_count(uint32_t desc_count, int legacy_fd)
{
	return (desc_count != 0 ? desc_count : (legacy_fd >= 0 ? 1 : 0));
}

/* d_lock must be held.  This mirrors illumos door_check_limits(). */
static int
door_check_limits_locked(
    struct door *door, size_t data_size, uint32_t desc_count)
{
	if (data_size < door->d_data_min || data_size > door->d_data_max)
		return (ENOBUFS);
	if (desc_count != 0 && (door->d_attributes & DOOR_REFUSE_DESC) != 0)
		return (ENOTSUP);
	if (desc_count > door->d_desc_max)
		return (ENFILE);
	return (0);
}

/*
 * Default limits are immutable until the first successful SETPARAM:
 *
 *   DATA_MIN = 0
 *   DATA_MAX = SIZE_MAX
 *   DESC_MAX = INT_MAX (or zero with DOOR_REFUSE_DESC)
 *
 * This check therefore needs no d_lock.  Once SETPARAM succeeds,
 * DOOR_HOT_CUSTOM_LIMITS permanently disables this shortcut.
 */
static int
door_check_default_limits(struct door *door, uint32_t desc_count)
{
	if (desc_count != 0 && (door->d_attributes & DOOR_REFUSE_DESC) != 0)
		return (ENOTSUP);
	if (desc_count > INT_MAX)
		return (ENFILE);
	return (0);
}

int
door_getparam(struct door *door, struct door_ioc_param *arg)
{
	int error;

	if (arg->dip_version != DOOR_ABI_VERSION)
		return (EINVAL);

	error = 0;
	mtx_lock(&door->d_lock);
	if (door->d_revoked) {
		error = EBADF;
		goto out;
	}
	switch (arg->dip_type) {
	case DOOR_PARAM_DESC_MAX:
		arg->dip_value = door->d_desc_max;
		break;
	case DOOR_PARAM_DATA_MIN:
		arg->dip_value = door->d_data_min;
		break;
	case DOOR_PARAM_DATA_MAX:
		arg->dip_value = door->d_data_max;
		break;
	default:
		error = EINVAL;
		break;
	}
out:
	mtx_unlock(&door->d_lock);
	return (error);
}

int
door_setparam(struct door *door, struct door_ioc_param *arg, struct thread *td)
{
	size_t value;
	int error;

	if (arg->dip_version != DOOR_ABI_VERSION)
		return (EINVAL);
	if (arg->dip_value > SIZE_MAX)
		return (ERANGE);
	if (!door_is_owner(door, td->td_proc))
		return (EPERM);

	value = (size_t)arg->dip_value;
	error = 0;
	mtx_lock(&door->d_lock);
	if (door->d_revoked) {
		error = EBADF;
		goto out;
	}
	switch (arg->dip_type) {
	case DOOR_PARAM_DESC_MAX:
		if (value > INT_MAX)
			error = ERANGE;
		else if ((door->d_attributes & DOOR_REFUSE_DESC) != 0 &&
			 value != 0)
			error = ENOTSUP;
		else
			door->d_desc_max = (u_int)value;
		break;
	case DOOR_PARAM_DATA_MIN:
		if (value > door->d_data_max)
			error = EINVAL;
		else
			door->d_data_min = value;
		break;
	case DOOR_PARAM_DATA_MAX:
		if (value < door->d_data_min)
			error = EINVAL;
		else
			door->d_data_max = value;
		break;
	default:
		error = EINVAL;
		break;
	}
	if (error == 0)
		atomic_set_int(&door->d_hot_flags, DOOR_HOT_CUSTOM_LIMITS);
out:
	mtx_unlock(&door->d_lock);
	return (error);
}

/*
 * A completion is an ordinary ONEWAY request on the client's private Door.
 * Work is dispatched outside the request Door's lock: taking two Door locks
 * in either order would make reciprocal async calls deadlock.
 */
static void
door_async_task(void *context, int pending __unused)
{
	struct door_async_completion header;
	struct door_server_binding *ds;
	struct door_call *origin, *event;
	struct door *target;
	size_t size;

	origin = context;

	target = origin->dc_async_target;
	size = sizeof(header) + origin->dc_async_result_size;
	event = door_call_alloc_fixed();
	refcount_init(&event->dc_refs, 1);
	event->dc_state = DOOR_CALL_PENDING;
	event->dc_type = DOOR_CALL_RPC;
	event->dc_oneway = true;
	event->dc_client = NULL;
	event->dc_client_td = NULL;
	event->dc_cred = origin->dc_cred != NULL ?
	    crhold(origin->dc_cred) : NULL;
	event->dc_pid = origin->dc_pid;
	event->dc_request.dx_buffer = malloc(size, M_DOORFS, M_WAITOK);
	event->dc_request.dx_size = size;
	event->dc_request.dx_mode = DOOR_XFER_BUFFER;
	event->dc_request.dx_buffer_owned = true;
	bzero(&header, sizeof(header));
	header.dac_version = DOOR_ABI_VERSION;
	header.dac_call_id = origin->dc_id;
	header.dac_status = origin->dc_async_status;
	switch (header.dac_status) {
	case EBADF:
		header.dac_flags = DOOR_ASYNC_C_REVOKED;
		break;
	case ECONNRESET:
		header.dac_flags = DOOR_ASYNC_C_WORKER_EXIT;
		break;
	case ECANCELED:
		header.dac_flags = DOOR_ASYNC_C_CANCELLED;
		break;
	default:
		break;
	}
	header.dac_data_size = origin->dc_async_result_size;
	bcopy(&header, event->dc_request.dx_buffer, sizeof(header));
	if (origin->dc_async_result_size != 0)
		bcopy(origin->dc_async_result,
		    event->dc_request.dx_buffer + sizeof(header),
		    origin->dc_async_result_size);
	atomic_store_rel_int(&event->dc_request_ready, 1);

	mtx_lock(&target->d_lock);
	KASSERT(target->d_async_reserved != 0,
	    ("async completion reservation underflow"));
	/* Convert admission to delivery even if revoke now forces a discard. */
	target->d_async_reserved--;
	origin->dc_async_reserved = false;
	if (!target->d_revoked) {
		event->dc_id = target->d_next_call_id++;
		if (target->d_next_call_id == 0)
			target->d_next_call_id = 1;
		/* The queue or assigned server now owns this reference. */
		door_call_hold(event);
		ds = door_call_dispatch_locked(target, event);
		if (ds != NULL)
			door_server_wake_async_locked(ds);
	}
	mtx_unlock(&target->d_lock);

	door_call_local_drop(event);
	door_call_drop(origin); /* task reference */
#ifdef DOORFS_TEST
	/* No publication or resource release remains after this notification. */
	door_test_async_end();
#endif
}

void
door_async_batch_init(struct door_async_batch *batch)
{
	batch->head = NULL;
	batch->tail = &batch->head;
}

void
door_async_batch_flush(struct door_async_batch *batch)
{
	struct door_call *call, *next;

	for (call = batch->head; call != NULL; call = next) {
		next = call->dc_async_enqueue_next;
		call->dc_async_enqueue_next = NULL;

		/* Queue only after unlock: reciprocal RPCs must not nest Door locks. */
		taskqueue_enqueue(taskqueue_thread, &call->dc_async_task);
	}
	door_async_batch_init(batch);
}

void
door_async_schedule_locked(struct door *door, struct door_call *call,
    int status, uint8_t *result, size_t size, struct door_async_batch *batch)
{
	mtx_assert(&door->d_lock, MA_OWNED);
	KASSERT(call->dc_async, ("scheduling ordinary Door call"));
	KASSERT(batch != NULL, ("async completion without enqueue batch"));
	if (call->dc_async_scheduled) {
		if (result != NULL)
			free(result, M_DOORFS);
		return;
	}
	/* Reply, cancel and revoke race here; only the winner owns a completion. */
	/* This selects one terminal schedule, not guaranteed userspace delivery:
	 * the completion endpoint may be closed/revoked before receive. */
	call->dc_async_scheduled = true;
#ifdef DOORFS_TEST
	/* Count before post-unlock enqueue, so drain includes unpublished jobs. */
	door_test_async_begin();
#endif
	call->dc_async_status = status;
	call->dc_async_result = result;
	call->dc_async_result_size = size;

	door_call_hold(call); /* held until completion task exits */
	call->dc_async_enqueue_next = NULL;
	*batch->tail = call;
	batch->tail = &call->dc_async_enqueue_next;
}

int
door_async_call(struct door *door, struct door *target,
    const struct door_ioc_async_call *arg, struct thread *td)
{
	struct door_server_binding *ds;
	struct door_call *call;
	uint8_t *storage;
	size_t capacity, size;
	int error;

	if (arg->diac_version != DOOR_ABI_VERSION || arg->diac_flags != 0 ||
	    arg->diac_reserved != 0 || arg->diac_call_id == 0 ||
	    arg->diac_request_size > SIZE_MAX ||
	    (arg->diac_request_size != 0 && arg->diac_request_ptr == 0)) {
		return (EINVAL);
	}
	if ((door->d_attributes & DOOR_ONEWAY) != 0 ||
	    (target->d_attributes & DOOR_ONEWAY) == 0) {
		return (EINVAL);
	}
	size = (size_t)arg->diac_request_size;
	if (size > DOOR_ASYNC_REQUEST_MAX) {
		return (EMSGSIZE);
	}

	/* Reserve a queue slot before the request becomes visible. */

	mtx_lock(&target->d_lock);

	if (target->d_revoked)
		error = EBADF;
	else if (target->d_async_reserved >= DOOR_ASYNC_OUTSTANDING_MAX)
		error = EAGAIN;
	else if (target->d_pending_count + target->d_async_reserved >=
	    DOOR_ONEWAY_PENDING_MAX)
		error = EAGAIN;
	else {
		target->d_async_reserved++;
		error = 0;
	}
	mtx_unlock(&target->d_lock);

	if (error != 0) {
		return (error);
	}


#ifdef DOORFS_TEST
	door_test_gate(DOOR_TEST_ASYNC_RESERVED);
#endif
	storage = NULL;
	capacity = 0;
	if (size != 0 && size < DOOR_REQUEST_PAGE_THRESHOLD)
		call = door_call_alloc_inline(size, &storage, &capacity);
	else
		call = door_call_alloc_fixed();
	refcount_init(&call->dc_refs, 1);
	call->dc_state = DOOR_CALL_PENDING;
	call->dc_type = DOOR_CALL_RPC;
	call->dc_oneway = true; /* independent of the submitting thread */
	call->dc_async = true;

	call->dc_async_reserved = true;
	call->dc_async_target = target;
	door_hold(target);
	TASK_INIT(&call->dc_async_task, 0, door_async_task, call);
	/* The private completion Door may request credentials independently. */
	call->dc_cred = crhold(td->td_ucred);
	call->dc_pid = td->td_proc->p_pid;

	if (size == 0)
		error = 0;
	else if (size >= DOOR_REQUEST_PAGE_THRESHOLD)
		error = door_xfer_capture_request_snapshot(
		    &call->dc_request, td, arg->diac_request_ptr, size);
	else
		error = door_xfer_capture_request_prealloc(&call->dc_request,
		    td, arg->diac_request_ptr, size, storage, capacity);

	if (error != 0)
		goto fail;
	atomic_store_rel_int(&call->dc_request_ready, 1);


	mtx_lock(&door->d_lock);

	if (door->d_revoked)
		error = EBADF;
	else
		error = door_check_limits_locked(door, size, 0);
	if (error == 0 && door->d_pending_count >= DOOR_ONEWAY_PENDING_MAX)
		error = EAGAIN;

	if (error == 0)
		error = door_call_check_id_locked(door, arg->diac_call_id);

	if (error == 0) {
		call->dc_id = arg->diac_call_id;
		door_call_hold(call); /* pending or server ownership */
		ds = door_call_dispatch_locked(door, call);

		if (ds != NULL) {
			door_server_wake_async_locked(ds);
		}
	}
	mtx_unlock(&door->d_lock);

	if (error != 0)
		goto fail;

	sched_door_producer(td);

	door_call_local_drop(call);

	return (0);

fail:

	mtx_lock(&target->d_lock);
	target->d_async_reserved--;
	mtx_unlock(&target->d_lock);
	call->dc_async_reserved = false;
	door_call_local_drop(call);

	return (error);
}

/*
 * Compact data-only ONEWAY submit path.
 *
 * The public DOOR_ONEWAY policy already implies DOOR_REFUSE_DESC at create
 * time.  This entry therefore needs no reply state, descriptor bundles,
 * call-id copyout, cancellation waiter, or client shuttle setup.
 */
int
door_oneway_submit(
    struct door *door, struct thread *td, uint64_t uptr, size_t size)
{
	struct door_server_binding *dispatch_ds;
	struct door_call *call;
	uint8_t *request_storage;
	size_t request_storage_capacity;
	u_int hot_flags;
	int error;

	if (size != 0 && uptr == 0)
		return (EINVAL);

	if (__predict_false((door->d_attributes & DOOR_ONEWAY) == 0))
		return (EINVAL);

	hot_flags = atomic_load_acq_int(&door->d_hot_flags);
	if (__predict_false((hot_flags & DOOR_HOT_REVOKED) != 0))
		return (EBADF);

	if (__predict_false((hot_flags & DOOR_HOT_CUSTOM_LIMITS) != 0)) {
		mtx_lock(&door->d_lock);
		if (door->d_revoked)
			error = EBADF;
		else
			error = door_check_limits_locked(door, size, 0);
		mtx_unlock(&door->d_lock);
		if (error != 0)
			return (error);
	}

	request_storage = NULL;
	request_storage_capacity = 0;
	if (size != 0 && size < DOOR_REQUEST_PAGE_THRESHOLD) {
		call = door_call_alloc_inline(
		    size, &request_storage, &request_storage_capacity);
	} else {
		call = door_call_alloc_fixed();
	}

	refcount_init(&call->dc_refs, 1);
	call->dc_state = DOOR_CALL_PENDING;
	call->dc_type = DOOR_CALL_RPC;
	if ((door->d_attributes & DOOR_NO_CRED) == 0) {
		call->dc_cred = crhold(td->td_ucred);
		call->dc_pid = td->td_proc->p_pid;
	}
	call->dc_client = NULL;
	call->dc_client_td = NULL;
	call->dc_early_dispatch = false;
	call->dc_oneway = true;
	atomic_store_rel_int(&call->dc_request_ready, 0);

	/*
	 * ONEWAY must be completely detached from caller userspace before this
	 * syscall returns.  Small requests use inline copy storage; large
	 * requests use the existing snapshot path rather than held pages.
	 */
	if (size == 0)
		error = 0;
	else if (size >= DOOR_REQUEST_PAGE_THRESHOLD)
		error = door_xfer_capture_request_snapshot(
		    &call->dc_request, td, uptr, size);
	else
		error = door_xfer_capture_request_prealloc(&call->dc_request,
		    td, uptr, size, request_storage, request_storage_capacity);
	if (error != 0)
		goto drop_local;

	atomic_store_rel_int(&call->dc_request_ready, 1);

	mtx_lock(&door->d_lock);
	if (door->d_revoked) {
		error = EBADF;
		mtx_unlock(&door->d_lock);
		goto drop_local;
	}

	/*
	 * Always perform the authoritative limit check after capture so a racing
	 * SETPARAM has the same semantics as ordinary door_call().
	 */
	error = door_check_limits_locked(door, size, 0);
	if (error != 0) {
		mtx_unlock(&door->d_lock);
		goto drop_local;
	}
	if (door->d_pending_count + door->d_async_reserved >=
	    DOOR_ONEWAY_PENDING_MAX) {
		error = EAGAIN;
		mtx_unlock(&door->d_lock);
		goto drop_local;
	}

	call->dc_id = door->d_next_call_id++;
	if (door->d_next_call_id == 0)
		door->d_next_call_id = 1;

	door_call_hold(call); /* asynchronous ownership */
	dispatch_ds = door_call_dispatch_locked(door, call);
	if (dispatch_ds != NULL)
		door_server_wake_async_locked(dispatch_ds);
	mtx_unlock(&door->d_lock);
	sched_door_producer(td);

	door_call_local_drop(call); /* submitter ownership */
	return (0);

drop_local:
	door_call_local_drop(call);
	return (error);
}

static int
door_call(struct door *door, struct door_ioc_call *arg, struct thread *td,
    const struct door_ioc_shm_ref *shm_ref, bool scalar_fast, bool auto_map)
{
	struct door_server_binding *dispatch_ds;
	struct door_call *call;
	uint8_t *request_storage;
	size_t capacity, request_storage_capacity;
	vm_size_t reply_map_size;
	uint64_t reply_map_addr;
	uint32_t desc_capacity;
	bool early_dispatch, oneway, reply_mapped, simple_reply;
	int error, wait_error, install_error;

	if (arg->dic_version != DOOR_ABI_VERSION ||
	    (arg->dic_request_size != 0 && arg->dic_request_ptr == 0) ||
	    (arg->dic_reply_size != 0 && arg->dic_reply_ptr == 0) ||
	    arg->dic_send_fd < -1)
		return (EINVAL);
	if (arg->dic_request_size > SIZE_MAX || arg->dic_reply_size > SIZE_MAX)
		return (EOVERFLOW);

	arg->dic_flags = 0;
	reply_mapped = false;
	reply_map_addr = 0;
	reply_map_size = 0;
	oneway = (door->d_attributes & DOOR_ONEWAY) != 0;
	if (shm_ref != NULL && shm_ref->disr_region != 0 &&
	    (arg->dic_send_desc_count != 0 || arg->dic_send_fd >= 0))
		return (ENOTSUP);

	/*
	 * Dispatch policy:
	 *
	 * Keep both buffer and page payloads on capture-before-dispatch ordering
	 * so page-transport fixed cost can be measured without early-wake effects.
	 * Only descriptor/fd capture uses early dispatch.
	 */
	early_dispatch =
	    !oneway && (arg->dic_send_desc_count != 0 || arg->dic_send_fd >= 0);

	dispatch_ds = NULL;
	{
		u_int hot_flags;
		uint32_t input_desc_count;

		input_desc_count = door_input_desc_count(
		    arg->dic_send_desc_count, arg->dic_send_fd);
		hot_flags = atomic_load_acq_int(&door->d_hot_flags);

		if (__predict_false(oneway && input_desc_count != 0))
			return (ENOTSUP);
		if (__predict_false((hot_flags & DOOR_HOT_REVOKED) != 0))
			return (EBADF);

		if (__predict_false(
			(hot_flags & DOOR_HOT_CUSTOM_LIMITS) != 0)) {
			mtx_lock(&door->d_lock);
			if (door->d_revoked)
				error = EBADF;
			else
				error = door_check_limits_locked(door,
				    (size_t)arg->dic_request_size,
				    input_desc_count);
			mtx_unlock(&door->d_lock);
		} else {
			error =
			    door_check_default_limits(door, input_desc_count);
		}
	}
	if (error != 0)
		return (error);

	/*
	 * For BUFFER requests, struct door_call and request bytes share one
	 * allocation.  Only the fixed object is zeroed; copyin overwrites payload.
	 */
	request_storage = NULL;
	request_storage_capacity = 0;

	if (arg->dic_request_size != 0 &&
	    arg->dic_request_size < DOOR_REQUEST_PAGE_THRESHOLD) {
		call = door_call_alloc_inline((size_t)arg->dic_request_size,
		    &request_storage, &request_storage_capacity);
	} else {
		call = door_call_alloc_fixed();
	}

	refcount_init(&call->dc_refs, 1);
	call->dc_state = DOOR_CALL_PENDING;
	call->dc_type = DOOR_CALL_RPC;
	if ((door->d_attributes & DOOR_NO_CRED) == 0) {
		call->dc_cred = crhold(td->td_ucred);
		call->dc_pid = td->td_proc->p_pid;
	}
	call->dc_client = oneway ? NULL : td->td_proc;
	call->dc_client_td = oneway ? NULL : td;
	call->dc_early_dispatch = early_dispatch;
	call->dc_oneway = oneway;
	atomic_store_rel_int(&call->dc_request_ready, 0);
	arg->dic_recv_fd = -1;

	capacity = arg->dic_reply_size;
	desc_capacity = arg->dic_recv_desc_count;

	if (!early_dispatch) {
		/* Capture-before-dispatch path for small descriptor-free RPCs. */
		if (!scalar_fast &&
		    (arg->dic_send_desc_count != 0 || arg->dic_send_fd >= 0)) {
			error = door_fd_bundle_capture(td,
			    arg->dic_send_desc_ptr, arg->dic_send_desc_count,
			    arg->dic_send_fd, &call->dc_request_fds);
			if (error != 0)
				goto early_drop;
		}
		if (arg->dic_request_size == 0) {
			error = 0;
		} else if (__predict_false(
			       oneway && arg->dic_request_size >=
					     DOOR_REQUEST_PAGE_THRESHOLD))
			error = door_xfer_capture_request_snapshot(
			    &call->dc_request, td, arg->dic_request_ptr,
			    (size_t)arg->dic_request_size);
		else
			error = door_xfer_capture_request_prealloc(
			    &call->dc_request, td, arg->dic_request_ptr,
			    (size_t)arg->dic_request_size, request_storage,
			    request_storage_capacity);
		if (error != 0)
			goto early_drop;
		atomic_store_rel_int(&call->dc_request_ready, 1);

		mtx_lock(&door->d_lock);
		if (door->d_revoked) {
			error = EBADF;
			goto unlock_drop;
		}
		error = door_check_limits_locked(door,
		    (size_t)arg->dic_request_size,
		    call->dc_request_fds.df_count);
		if (error != 0)
			goto unlock_drop;
		if (oneway &&
		    door->d_pending_count + door->d_async_reserved >=
		    DOOR_ONEWAY_PENDING_MAX) {
			error = EAGAIN;
			goto unlock_drop;
		}
		if (shm_ref != NULL) {
			error = door_shm_call_capture_locked(
			    door, td, shm_ref, call);
			if (error != 0)
				goto unlock_drop;
		}

		error = door_call_assign_id_locked(door, call,
		    &arg->dic_call_id, !scalar_fast && arg->dic_call_id != 0);
		if (error != 0)
			goto unlock_drop;

		if (__predict_false(oneway)) {
			door_call_hold(
			    call); /* async pending/server ownership */
		}
		dispatch_ds = door_call_dispatch_locked(door, call);

		if (__predict_false(oneway)) {
			/*
			 * Request capture is complete and lifetime is detached from the
			 * submitting thread.  Wake an assigned worker now; queued calls
			 * need no client sleeper at all.
			 */
			if (dispatch_ds != NULL)
				door_server_wake_async_locked(dispatch_ds);
			arg->dic_flags = DOOR_CALL_F_ONEWAY;
			arg->dic_reply_size = 0;
			arg->dic_recv_desc_count = 0;
			arg->dic_recv_fd = -1;
			mtx_unlock(&door->d_lock);
			sched_door_producer(td);
			door_call_local_drop(
			    call); /* submitting-thread local reference */
			return (0);
		}
	} else {
		/*
		 * Expensive path: assign/wake first, then capture without d_lock.
		 * If there is no idle server, the call remains pending and this is
		 * equivalent to an ordinary queued request except for publication.
		 */
		mtx_lock(&door->d_lock);
		if (door->d_revoked) {
			error = EBADF;
			goto unlock_drop;
		}
		error = door_call_assign_id_locked(door, call,
		    &arg->dic_call_id, arg->dic_call_id != 0);
		if (error != 0)
			goto unlock_drop;
		dispatch_ds = door_call_dispatch_locked(door, call);
		if (dispatch_ds != NULL)
			door_server_wake_locked(dispatch_ds);
		mtx_unlock(&door->d_lock);

		error = door_fd_bundle_capture(td, arg->dic_send_desc_ptr,
		    arg->dic_send_desc_count, arg->dic_send_fd,
		    &call->dc_request_fds);
		if (error == 0 && arg->dic_request_size != 0)
			error = door_xfer_capture_request_prealloc(
			    &call->dc_request, td, arg->dic_request_ptr,
			    (size_t)arg->dic_request_size, request_storage,
			    request_storage_capacity);

		mtx_lock(&door->d_lock);
		if (call->dc_state != DOOR_CALL_PENDING &&
		    call->dc_state != DOOR_CALL_ACTIVE) {
			cv_broadcast(&call->dc_cv);
			if (call->dc_state == DOOR_CALL_REVOKED)
				error = EBADF;
			else if (error == 0)
				error = call->dc_error != 0 ? call->dc_error
							    : ECANCELED;
			goto unlock_drop;
		}
		if (error == 0 && door->d_revoked)
			error = EBADF;
		if (error == 0)
			error = door_check_limits_locked(door,
			    (size_t)arg->dic_request_size,
			    call->dc_request_fds.df_count);
		if (error != 0) {
			(void)door_cancel_call_locked(door, call, error, NULL);
			cv_broadcast(&call->dc_cv);
			goto unlock_drop;
		}
		/* Assignment may already be ACTIVE. Publish captured state separately;
		 * the worker acquires ready before reading it. Failure/revoke wakes
		 * the state-checked wait instead of exporting partial capture. */
		atomic_store_rel_int(&call->dc_request_ready, 1);
		cv_broadcast(&call->dc_cv);
		dispatch_ds = NULL;
	}

	for (;;) {
		if (call->dc_state == DOOR_CALL_DONE ||
		    call->dc_state == DOOR_CALL_CANCELLED ||
		    call->dc_state == DOOR_CALL_REVOKED)
			break;
		wait_error = door_call_wait_client_locked(door, call, td,
		    (door->d_attributes & DOOR_NO_CANCEL) == 0, dispatch_ds);
		dispatch_ds = NULL;
		if (wait_error == 0) {
			wait_error = door_call_postwake_ast_locked(door, call,
			    td, (door->d_attributes & DOOR_NO_CANCEL) == 0);
			if (wait_error == 0)
				continue;
		}
		error = EINTR;
		(void)door_cancel_call_locked(door, call, EINTR, NULL);
		goto unlock_drop;
	}

	error = call->dc_error;
	if (call->dc_state == DOOR_CALL_REVOKED)
		error = EBADF;
	arg->dic_reply_size = call->dc_reply.dx_size;
	arg->dic_recv_desc_count = call->dc_reply_fds.df_count;
	if (error == 0 && call->dc_reply.dx_size > capacity && !auto_map)
		error = EMSGSIZE;
	if (error == 0 && call->dc_reply_fds.df_count != 0 &&
	    arg->dic_recv_desc_ptr != 0 &&
	    call->dc_reply_fds.df_count > desc_capacity)
		error = EMSGSIZE;

	simple_reply = call->dc_reply_fds.df_count == 0 &&
		       call->dc_reply.dx_mode != DOOR_XFER_PAGES;
	mtx_unlock(&door->d_lock);

#ifdef DOORFS_TEST
	if (error == 0 && call->dc_reply.dx_mode == DOOR_XFER_PAGES)
		door_test_gate(DOOR_TEST_CLIENT_COPY);
#endif
	if (error == 0 && call->dc_reply.dx_size > capacity) {
		error = door_reply_map(td, call->dc_reply.dx_size,
		    &reply_map_addr, &reply_map_size);
		if (error == 0) {
			reply_mapped = true;
			arg->dic_reply_ptr = reply_map_addr;
			arg->dic_flags |= DOOR_CALL_F_AUTO_MAP;
		}
	}

	if (error == 0 && call->dc_reply.dx_size != 0)
		error =
		    door_xfer_copyout(&call->dc_reply, td, arg->dic_reply_ptr);
	install_error = error;
	if (install_error == 0 && call->dc_reply_fds.df_count != 0)
		install_error = door_fd_bundle_install(td, &call->dc_reply_fds,
		    arg->dic_recv_desc_ptr, desc_capacity, &arg->dic_recv_fd);

	/*
	 * BUFFER/NONE replies without descriptors have no server-side install
	 * barrier: door_return() already released the worker immediately after
	 * publishing the private kernel reply.  Do not reacquire d_lock merely
	 * to set fields that no thread will read.
	 */
	if (__predict_true(simple_reply)) {
		if (install_error == 0 && call->dc_request_fds.df_count != 0)
			door_fd_bundle_move_sources(
			    td, door, call, &call->dc_request_fds);
		if (install_error != 0 && reply_mapped)
			(void)kern_munmap(td, (vm_offset_t)reply_map_addr,
			    reply_map_size);
		door_call_local_drop(call);
		return (install_error);
	}

#ifdef DOORFS_TEST
	if (install_error == 0 && call->dc_reply_move_required)
		door_test_gate(DOOR_TEST_REPLY_MOVE_INSTALL);
#endif
	mtx_lock(&door->d_lock);
	call->dc_reply_install_error = install_error;
	call->dc_reply_install_done = true;
	cv_broadcast(&call->dc_cv);
	/* Successful receiver installation commits reply MOVE. Revoke cannot
	 * turn that installed transfer into an error while hiding receiver fds.
	 * SERVER retains the call until source close and acknowledgement. */
	if (install_error == 0 && call->dc_reply_move_required) {
		while (!call->dc_reply_move_done)
			(void)door_call_wait_client_locked(
			    door, call, td, false, NULL);
	}
	mtx_unlock(&door->d_lock);

	if (install_error == 0)
		door_fd_bundle_move_sources(
		    td, door, call, &call->dc_request_fds);
	if (install_error != 0 && reply_mapped)
		(void)kern_munmap(td, (vm_offset_t)reply_map_addr,
		    reply_map_size);
	door_call_local_drop(call);
	return (install_error);

unlock_drop:
	mtx_unlock(&door->d_lock);
early_drop:
	door_call_local_drop(call);
	return (error);
}

int
door_call_scalar(struct door *door, struct thread *td, uint64_t request_ptr,
    size_t request_size, uint64_t reply_ptr, size_t reply_capacity,
    uint64_t recv_desc_ptr, bool auto_map, uint64_t *reply_result_ptr,
    uint32_t *call_flagsp, uint64_t *packedp)
{
	struct door_ioc_call call;
	uint64_t packed;
	int error;

	call.dic_version = DOOR_ABI_VERSION;
	call.dic_flags = 0;
	call.dic_request_ptr = request_ptr;
	call.dic_request_size = request_size;
	call.dic_reply_ptr = reply_ptr;
	call.dic_reply_size = reply_capacity;
	call.dic_call_id = 0;
	call.dic_send_fd = -1;
	call.dic_recv_fd = -1;
	call.dic_send_desc_ptr = 0;
	call.dic_send_desc_count = 0;
	call.dic_recv_desc_ptr = recv_desc_ptr;
	call.dic_recv_desc_count = DOOR_FAST_CALL_DESC_CAP;

	error = door_call(door, &call, td, NULL, true, auto_map);
	if (error != 0)
		return (error);
	if (call.dic_reply_size > DOOR_FAST_CALL_REPLY_MASK ||
	    call.dic_recv_desc_count > DOOR_FAST_CALL_DESC_MASK) {
		if ((call.dic_flags & DOOR_CALL_F_AUTO_MAP) != 0)
			(void)kern_munmap(td, (vm_offset_t)call.dic_reply_ptr,
			    round_page((vm_size_t)call.dic_reply_size));
		return (EOVERFLOW);
	}
	packed = call.dic_reply_size | ((uint64_t)call.dic_recv_desc_count
					   << DOOR_FAST_CALL_DESC_SHIFT);
	if ((call.dic_flags & DOOR_CALL_F_ONEWAY) != 0)
		packed |= DOOR_FAST_CALL_F_ONEWAY;
	if (reply_result_ptr != NULL)
		*reply_result_ptr = call.dic_reply_ptr;
	if (call_flagsp != NULL)
		*call_flagsp = call.dic_flags;
	*packedp = packed;
	return (0);
}

static int
door_server_wait_locked(struct door *door, struct door_server_binding *ds)
{
	int error;
	bool used;

	error = door_shuttle_wait_locked(door, curthread, NULL, &ds->ds_cv,
	    DOOR_SHUTTLE_F_INTERRUPTIBLE | DOOR_SHUTTLE_F_IDLE_WAIT, NULL,
	    &used);
	if (used || error != EOPNOTSUPP)
		return (error);

	return (cv_wait_sig_shuttle(&ds->ds_cv, &door->d_lock, NULL, NULL, NULL,
	    DOOR_SHUTTLE_F_INTERRUPTIBLE | DOOR_SHUTTLE_F_IDLE_WAIT));
}

/*
 * Idle RETURN uses SIGDEFERSTOP_EINTR, unlike CALL's SILENT policy.
 * Check suspend without d_lock and recheck assignment/revoke afterwards.
 * If still idle, EINTR may unwind RETURN and remove the binding; the worker
 * can subsequently bind again. This helper does not suspend the kernel stack.
 */
static int
door_server_postwake_ast_locked(
    struct door *door, struct door_server_binding *ds, struct thread *td)
{
	struct proc *p;
	int error;

	mtx_assert(&door->d_lock, MA_OWNED);

	if (ds->ds_call != NULL || door->d_revoked) {
		return (0);
	}

	if (td_ast_pending(td, TDA_SUSPEND)) {
		p = td->td_proc;
		mtx_unlock(&door->d_lock);
		PROC_LOCK(p);
		/*
		 * Bound RETURN defers stops with SIGDEFERSTOP_EINTR at syscall entry.
		 * return_instead=1 permits safe EINTR/unwind without exiting this stack;
		 * an assignment or revoke that wins the recheck takes precedence.
		 */
		error = thread_suspend_check(1);
		PROC_UNLOCK(p);
		mtx_lock(&door->d_lock);

		if (ds->ds_call != NULL || door->d_revoked) {
			return (0);
		}
		if (error != 0) {
			return (error);
		}
	}

	if (!td_ast_pending(td, TDA_SIG)) {
		return (0);
	}

	mtx_unlock(&door->d_lock);
	error = sig_intr();
	mtx_lock(&door->d_lock);

	if (ds->ds_call != NULL || door->d_revoked) {
		return (0);
	}
	return (error);
}

/* d_lock is held on entry and return. */
static void
door_server_wait_request_ready_locked(struct door *door, struct door_call *call)
{
	u_int i;

	mtx_assert(&door->d_lock, MA_OWNED);
	/* ACTIVE alone is not capture publication; acquire pairs with ready release. */
	if (atomic_load_acq_int(&call->dc_request_ready) != 0)
		return;

	mtx_unlock(&door->d_lock);
	for (i = 0; i < DOOR_REQUEST_READY_SPINS; i++) {
		if (atomic_load_acq_int(&call->dc_request_ready) != 0)
			break;
		cpu_spinwait();
	}
	mtx_lock(&door->d_lock);

	while (atomic_load_acq_int(&call->dc_request_ready) == 0 &&
	       call->dc_state == DOOR_CALL_ACTIVE && !door->d_revoked)
		cv_wait(&call->dc_cv, &door->d_lock);
}

static bool
door_server_discard_cancelled_locked(
    struct door *door, struct door_server_binding *ds, struct door_call *call)
{
	if (call->dc_state != DOOR_CALL_CANCELLED &&
	    call->dc_state != DOOR_CALL_REVOKED)
		return (false);
	KASSERT(ds->ds_call == call, ("cancelled server call mismatch"));
	if (call->dc_state == DOOR_CALL_CANCELLED) {
		TAILQ_REMOVE(&door->d_active, call, dc_link);
		door->d_active_count--;
	}
	ds->ds_call = NULL;
	call->dc_server_td = NULL;
	door_call_detached_drop_locked(door, call);
	return (true);
}

/*
 * Requeue an undelivered request for an undersized receive buffer. Later
 * export/copyout/descriptor-install errors retain the assignment for the
 * error/teardown path; this helper does not promise replay after EFAULT.
 * Activation owns SERVER. Internal one-way calls restore PENDING before
 * releasing SERVER; UNREF keeps its single queue/server lifetime reference.
 */
static void
door_server_requeue_undelivered_locked(
    struct door *door, struct door_server_binding *ds, struct door_call *call)
{
	mtx_assert(&door->d_lock, MA_OWNED);
	KASSERT(ds->ds_call == call, ("requeue server call mismatch"));
	KASSERT(call->dc_state == DOOR_CALL_ACTIVE,
	    ("requeue call in state %d", call->dc_state));

	TAILQ_REMOVE(&door->d_active, call, dc_link);
	door->d_active_count--;
	ds->ds_call = NULL;
	call->dc_server_td = NULL;
	call->dc_state = DOOR_CALL_PENDING;

	if (call->dc_type == DOOR_CALL_RPC && call->dc_oneway) {
		door_call_hold(call); /* restore async pending ownership */
	}

	TAILQ_INSERT_HEAD(&door->d_pending, call, dc_link);
	door->d_pending_count++;

	if (call->dc_type == DOOR_CALL_RPC) {
		door_call_drop(call); /* server reference */
	}
}

/* Clear only the exported request; the caller owns dir_flags. */
static __inline void
door_return_clear_request(struct door_ioc_return *arg)
{
	arg->dir_call_id = 0;
	arg->dir_request_size = 0;
	arg->dir_request_desc_count = 0;
	arg->dir_request_fd = -1;
	bzero(&arg->dir_cred, sizeof(arg->dir_cred));
}

/*
 * Complete a deferred RPC.  Enter with d_lock held and return unlocked,
 * including errors.  Keep copyin, taskqueue state and their stack frame out
 * of the synchronous RETURN path.  The server reference pins the call and
 * the owner thread keeps its binding alive while d_lock is dropped.
 */
static __noinline int
door_return_async_locked(struct door *door, struct door_server_binding *ds,
    struct door_ioc_return *arg)
{
	struct door_async_batch batch;
	struct door_call *call;
	uint8_t *data;
	size_t size;
	int status;

	mtx_assert(&door->d_lock, MA_OWNED);
	door_async_batch_init(&batch);
	call = ds->ds_call;
	door_call_hold(call); /* across copyin and server-reference drop */
	size = (size_t)arg->dir_reply_size;
	status = 0;
	data = NULL;
	if (arg->dir_reply_desc_count != 0 || arg->dir_reply_fd >= 0)
		status = ENOTSUP;
	else if (size > DOOR_ASYNC_REPLY_MAX)
		status = EMSGSIZE;
	mtx_unlock(&door->d_lock);
	if (status == 0 && size != 0) {
		data = malloc(size, M_DOORFS, M_WAITOK);
		if (copyin((const void *)(uintptr_t)arg->dir_reply_ptr,
		    data, size) != 0) {
			free(data, M_DOORFS);
			data = NULL;
			status = EFAULT;
		}
	}
	mtx_lock(&door->d_lock);
	/* copyin dropped d_lock; teardown may have detached this assignment. */
	if (ds->ds_call != call) {
		mtx_unlock(&door->d_lock);
		if (data != NULL)
			free(data, M_DOORFS);
		door_call_drop(call);
		return (EBADF);
	}
	if (call->dc_state == DOOR_CALL_ACTIVE) {
		TAILQ_REMOVE(&door->d_active, call, dc_link);
		door->d_active_count--;
		call->dc_state = DOOR_CALL_DONE;
		call->dc_error = status;
		door_async_schedule_locked(door, call, status,
		    data, status == 0 ? size : 0, &batch);
		data = NULL;
	}
	if (call->dc_state == DOOR_CALL_CANCELLED) {
		TAILQ_REMOVE(&door->d_active, call, dc_link);
		door->d_active_count--;
	}
	ds->ds_call = NULL;
	call->dc_server_td = NULL;
	door_server_set_waiting_locked(door, ds, false);
	arg->dir_flags = DOOR_RETURN_F_COMPLETED |
	    DOOR_RETURN_F_REWAIT;
	door_return_clear_request(arg);
	mtx_unlock(&door->d_lock);
	door_async_batch_flush(&batch);
	if (data != NULL)
		free(data, M_DOORFS);
	door_call_drop(call); /* server */
	door_call_drop(call); /* local */
	return (0);
}

static int
door_return(struct door *door, struct door_ioc_return *arg, struct thread *td,
    struct door_ioc_shm_ref *shm_ref, uint64_t *shm_ptr,
    struct door_server_binding *bound_ds, bool scalar_fast,
    uint64_t *fast_result)
{
	struct door_server_binding *ds;
	struct door_call *call, *completed;
	struct door_reply_cache *reply_cache;
	struct door_xfer reply;
	struct door_fd_bundle reply_fds;
	size_t capacity, request_size;
	uint32_t desc_capacity, input_flags;
	bool binding_drop, completed_cancelled, reply_initialized, reply_unref;
	bool resizable, completed_oneway;
	int error;

	/* Old amd64 callers supplied unnamed padding; never validate it. */
	arg->dir_padding = 0;
	if (!scalar_fast &&
	    (arg->dir_version != DOOR_ABI_VERSION ||
		(arg->dir_reply_size != 0 && arg->dir_reply_ptr == 0) ||
		(arg->dir_request_size != 0 && arg->dir_request_ptr == 0) ||
		arg->dir_reply_fd < -1))
		return (EINVAL);
	if (!scalar_fast && (arg->dir_reply_size > SIZE_MAX ||
				arg->dir_request_size > SIZE_MAX))
		return (EOVERFLOW);
	/*
	 * RETURN authorization is the server binding itself.  BIND is owner-only
	 * and binds a concrete struct thread; checking door_list ownership again
	 * here would take the global door_list_lock on every RPC.
	 */
	reply_initialized = false;
	if (!scalar_fast) {
		bzero(&reply, sizeof(reply));
		bzero(&reply_fds, sizeof(reply_fds));
		reply_initialized = true;
	}
	if (!scalar_fast && shm_ref != NULL)
		bzero(shm_ref, sizeof(*shm_ref));
	if (!scalar_fast && shm_ptr != NULL)
		*shm_ptr = 0;
	reply_cache = NULL;
	reply_unref = false;
	binding_drop = false;
	completed = NULL;

	input_flags = arg->dir_flags;
	resizable = (input_flags & DOOR_RETURN_F_RESIZABLE) != 0;
	capacity = arg->dir_request_size;
	desc_capacity = arg->dir_request_desc_count;
	arg->dir_flags = 0;

	mtx_lock(&door->d_lock);
	if (__predict_true(bound_ds != NULL)) {
		ds = bound_ds;
	} else {
		ds = door_server_find_locked(door, td);
	}
	if (ds == NULL) {
		mtx_unlock(&door->d_lock);
		return (EPERM);
	}

	/*
	 * Revoke/cancel may race with direct dispatch to a worker which was
	 * already sleeping in RETURN.
	 *
	 * In that case ds->ds_call is assigned (typically call id 1), but this
	 * invocation of RETURN still has dir_call_id == 0 because the request has
	 * never been exported to userspace.  The normal completion fast path
	 * therefore cannot match the call id.  Previously the later
	 * `door->d_revoked` check returned EBADF immediately and left the server
	 * reference attached to ds_call.  Worker teardown usually cleaned it, but
	 * the rapid doorctl ONEWAY generation-replacement race can remove the
	 * generation before that cleanup, leaking exactly one server reference.
	 *
	 * Consume an already CANCELLED/REVOKED assigned request here, before any
	 * call-id/reply handling.  This is the same owner-side operation used
	 * later in next_request, but it must also cover a worker waking from its
	 * original dir_call_id == 0 wait.
	 */
	if (arg->dir_call_id == 0 && ds->ds_call != NULL &&
	    (ds->ds_call->dc_state == DOOR_CALL_CANCELLED ||
		ds->ds_call->dc_state == DOOR_CALL_REVOKED)) {
		call = ds->ds_call;
		KASSERT(door_server_discard_cancelled_locked(door, ds, call),
		    ("failed to discard cancelled/revoked assigned call"));
		call = NULL;
	}

	if (__predict_false(ds->ds_call != NULL && ds->ds_call->dc_async &&
	    ds->ds_call->dc_id == arg->dir_call_id))
		return (door_return_async_locked(door, ds, arg));

	/*
	 * Completion fast paths.
	 *
	 * ONEWAY never has a client reply and therefore only accepts an empty
	 * server completion.  DOOR_NO_RETURN keeps ordinary synchronous CALL
	 * semantics, but an empty reply can complete directly under this first
	 * d_lock acquisition without constructing reply transport state.
	 */
	if (ds->ds_call != NULL && ds->ds_call->dc_id == arg->dir_call_id &&
	    ds->ds_call->dc_type == DOOR_CALL_RPC) {
		bool empty_reply, fast_empty;

		call = ds->ds_call;
		empty_reply = arg->dir_reply_size == 0 &&
			      arg->dir_reply_fd < 0 &&
			      arg->dir_reply_desc_count == 0;

		if (call->dc_oneway && !empty_reply) {
			mtx_unlock(&door->d_lock);
			return (EINVAL);
		}

		/*
		 * An explicit empty descriptor-free reply has no transport or
		 * install barrier regardless of endpoint attributes.  Complete it
		 * under this first lock acquisition; DOOR_NO_RETURN remains an API
		 * policy hint, not a requirement for the safe empty completion.
		 */
		fast_empty = empty_reply;
		if (__predict_true(fast_empty)) {
			completed_cancelled =
			    call->dc_state == DOOR_CALL_CANCELLED ||
			    call->dc_state == DOOR_CALL_REVOKED;
			if (call->dc_state == DOOR_CALL_ACTIVE ||
			    call->dc_state == DOOR_CALL_CANCELLED) {
				TAILQ_REMOVE(&door->d_active, call, dc_link);
				door->d_active_count--;
			}
			ds->ds_call = NULL;

			if (!completed_cancelled) {
				call->dc_error = 0;
				call->dc_state = DOOR_CALL_DONE;
				if (!call->dc_oneway) {
					door_call_wake_client_locked(
					    call, DOOR_SHUTTLE_F_REPLY);
				}
			}

			call->dc_server_td = NULL;
			completed_oneway = call->dc_oneway;
			completed = call;
			arg->dir_flags |= DOOR_RETURN_F_COMPLETED;

			/* Release detached SERVER before waiting for unrelated work. The
			 * final-drop interlock also covers a concurrent client release. */
			if (!completed_cancelled && !completed_oneway) {
				door_call_detached_drop_locked(door, call);
				completed = NULL;
			}

			/*
			 * Do not retain a cancelled transaction across the fused
			 * wait-for-next operation.  Its client may already have left
			 * the kernel and the only remaining reference belongs to this
			 * server completion.  Return a re-wait token so libdoor unwinds
			 * the callback and enters a fresh RETURN with call_id == 0.
			 */
			if (completed_cancelled && !completed_oneway) {
				door_server_set_waiting_locked(door, ds, false);
				door_return_clear_request(arg);
				arg->dir_flags |= DOOR_RETURN_F_REWAIT;
				call = NULL;
				error = 0;
				goto unlock;
			}

			KASSERT(ds->ds_call == NULL,
			    ("fast empty completion left server busy"));

			/*
			 * ONEWAY completion is independent of the original caller.  When a
			 * successor is already queued, retain the fused RETURN policy:
			 * release the old server reference and consume the next request
			 * without an extra userspace/kernel round trip.  An empty queue must
			 * still unwind this door_return() to preserve the public callback
			 * completion contract.
			 *
			 * The old REWAIT policy imposed one extra userspace/kernel round
			 * trip per queued ONEWAY request.  More importantly, an unbound
			 * worker lost its scheduler locality on every item, reducing a
			 * full pending queue to repeated cold worker rediscovery.
			 *
			 * A revoked or cancelled transaction remains conservative.  Its
			 * final server reference may be the only lifetime reference, and
			 * revoke also makes an implicit wait-for-next invalid.
			 */
			if (completed_oneway) {
				if (door->d_revoked || completed_cancelled) {
					door_server_set_waiting_locked(door, ds, false);
					door_return_clear_request(arg);

					if (door->d_revoked) {
						binding_drop =
						    door_server_remove_locked(door, ds);
						arg->dir_flags |= DOOR_RETURN_F_EXIT;
					} else {
						arg->dir_flags |= DOOR_RETURN_F_REWAIT;
					}

					mtx_unlock(&door->d_lock);
					if (binding_drop)
						door_server_binding_drop(ds);
					door_call_drop(completed);
					return (0);
				}

				KASSERT(completed == call,
				    ("ONEWAY completion reference mismatch"));

				/*
				 * Preserve the public ONEWAY completion contract when this
				 * worker drained the last queued request.  door_return() must
				 * return to the callback in that case; libdoor will issue a
				 * fresh wait after the callback unwinds.
				 *
				 * Fuse only an already queued successor.  Keeping ds_waiting
				 * clear while dropping the completed reference also prevents
				 * a racing newer submitter from bypassing an older pending
				 * request through direct dispatch.
				 */
				if (TAILQ_EMPTY(&door->d_pending)) {
					door_server_set_waiting_locked(door, ds, false);
					door_return_clear_request(arg);
					arg->dir_flags |= DOOR_RETURN_F_REWAIT;
					door_call_detached_drop_locked(door, completed);
					completed = NULL;
					call = NULL;
					error = 0;
					goto unlock;
				}

				door_call_detached_drop_locked(door, completed);
				completed = NULL;
				call = NULL;
				goto next_request;
			}

			door_server_set_waiting_locked(door, ds, true);

			call = NULL;
			goto next_request;
		}
		call = NULL;
	}

	if (!reply_initialized) {
		bzero(&reply, sizeof(reply));
		bzero(&reply_fds, sizeof(reply_fds));
		reply_initialized = true;
	}
	if (arg->dir_reply_size != 0) {
		reply_cache = ds->ds_reply_cache;
		door_reply_cache_hold(reply_cache);
	}

	if (ds->ds_call != NULL && ds->ds_call->dc_id == arg->dir_call_id &&
	    ds->ds_call->dc_type == DOOR_CALL_UNREF)
		reply_unref = true;

	if (door->d_revoked)
		error = EBADF;
	else if (reply_unref) {
		if (arg->dir_reply_size != 0 || arg->dir_reply_fd >= 0 ||
		    arg->dir_reply_desc_count != 0)
			error = EINVAL;
		else
			error = 0;
	} else if (arg->dir_call_id != 0 || arg->dir_reply_size != 0 ||
		   arg->dir_reply_fd >= 0 || arg->dir_reply_desc_count != 0) {
		error =
		    door_check_limits_locked(door, (size_t)arg->dir_reply_size,
			door_input_desc_count(
			    arg->dir_reply_desc_count, arg->dir_reply_fd));
	} else {
		error = 0;
	}
	/*
	 * A reply-policy failure belongs to the current RPC, not to the server
	 * binding.  Complete the client with the same error and leave the worker
	 * bound so libdoor can discard this reply and wait for another call.
	 */
	if (error != 0 && ds != NULL && ds->ds_call != NULL &&
	    ds->ds_call->dc_id == arg->dir_call_id &&
	    ds->ds_call->dc_type == DOOR_CALL_RPC &&
	    (error == ENOTSUP || error == ENFILE || error == ENOBUFS)) {
		call = ds->ds_call;
		if (call->dc_state == DOOR_CALL_ACTIVE ||
		    call->dc_state == DOOR_CALL_CANCELLED) {
			TAILQ_REMOVE(&door->d_active, call, dc_link);
			door->d_active_count--;
		}
		ds->ds_call = NULL;
		call->dc_server_td = NULL;
		if (call->dc_state == DOOR_CALL_ACTIVE) {
			call->dc_error = error;
			call->dc_state = DOOR_CALL_DONE;
			door_call_wake_client_locked(
			    call, DOOR_SHUTTLE_F_REPLY);
		}
		mtx_unlock(&door->d_lock);
		door_reply_cache_drop(reply_cache);
		reply_cache = NULL;
		door_call_drop(call); /* server reference */
		return (error);
	}
	mtx_unlock(&door->d_lock);
	if (error != 0) {
		door_reply_cache_drop(reply_cache);
		return (error);
	}

	if (__predict_false(arg->dir_reply_size != 0))
		error = door_xfer_capture_reply_cached(&reply, td,
		    arg->dir_reply_ptr, (size_t)arg->dir_reply_size,
		    reply_cache);
	else
		error = 0;
	door_reply_cache_drop(reply_cache); /* temporary lookup reference */
	reply_cache = NULL;
	if (error != 0)
		return (error);
	if (__predict_false(
		arg->dir_reply_desc_count != 0 || arg->dir_reply_fd >= 0))
		error = door_fd_bundle_capture(td, arg->dir_reply_desc_ptr,
		    arg->dir_reply_desc_count, arg->dir_reply_fd, &reply_fds);
	else
		error = 0;
	if (error != 0) {
		door_xfer_destroy(&reply);
		return (error);
	}

	request_size = 0;
	/* Preserve DOOR_RETURN_F_COMPLETED from a fused prior completion. */
	arg->dir_request_fd = -1;
	completed_cancelled = false;
	call = NULL;

	mtx_lock(&door->d_lock);
	ds = door_server_find_locked(door, td);
	if (ds == NULL) {
		error = EPERM;
		goto unlock;
	}

	if (ds->ds_call != NULL) {
		call = ds->ds_call;
		if (arg->dir_call_id != call->dc_id) {
			error = EINVAL;
			goto unlock;
		}
		if (call->dc_type == DOOR_CALL_UNREF &&
		    (arg->dir_reply_size != 0 || arg->dir_reply_fd >= 0 ||
			arg->dir_reply_desc_count != 0)) {
			error = EINVAL;
			goto unlock;
		}
		completed_cancelled = (call->dc_state == DOOR_CALL_CANCELLED ||
				       call->dc_state == DOOR_CALL_REVOKED);
		if (call->dc_state == DOOR_CALL_ACTIVE ||
		    call->dc_state == DOOR_CALL_CANCELLED) {
			TAILQ_REMOVE(&door->d_active, call, dc_link);
			door->d_active_count--;
		}
		ds->ds_call = NULL;

		if (call->dc_type == DOOR_CALL_UNREF) {
			if (!completed_cancelled) {
				call->dc_state = DOOR_CALL_DONE;
				call->dc_error = 0;
			}
		} else if (!completed_cancelled) {
			call->dc_reply = reply;
			bzero(&reply, sizeof(reply));
			call->dc_reply_fds = reply_fds;
			bzero(&reply_fds, sizeof(reply_fds));
			call->dc_reply_move_required =
			    door_fd_bundle_has_move(&call->dc_reply_fds);
			call->dc_reply_move_done = false;
			call->dc_error = 0;
			call->dc_state = DOOR_CALL_DONE;

			/*
			 * Publish this worker as reservable before handing execution
			 * back to the client.  The completed call is no longer attached
			 * to ds->ds_call; the local call pointer and server reference keep
			 * it alive through reply_install_done.
			 *
			 * A following client may reserve ds->ds_call immediately.
			 * door_call_activate_locked() clears ds_waiting atomically, and
			 * this server consumes that next call only after finishing the
			 * old reply-install barrier below.
			 *
			 * Keep MOVE replies conservative: sender-side fdclose() and the
			 * move acknowledgement still belong to the completed call.
			 */
			if (!call->dc_reply_move_required) {
				KASSERT(ds->ds_call == NULL,
				    ("early-available server already has a "
				     "call"));
				door_server_set_waiting_locked(door, ds, true);
			}

			door_call_wake_client_locked(
			    call, DOOR_SHUTTLE_F_REPLY);

			/*
			 * Fast completion is safe only when the published reply no
			 * longer aliases mutable server userspace.  BUFFER replies are
			 * private kernel copies and NONE has no payload, so the client's
			 * reference is sufficient to keep their contents alive while the
			 * server immediately re-enters the worker dispatch path.
			 *
			 * PAGES replies merely hold the server's userspace pages.  A
			 * reused worker can overwrite those pages in its next callback
			 * before the previous client finishes door_xfer_copyout(), so
			 * page-backed replies must retain the v13 install barrier.
			 * Descriptor-bearing replies also retain the barrier, preserving
			 * ordinary descriptor delivery and the stricter MOVE protocol.
			 */
			if (call->dc_reply_fds.df_count != 0 ||
			    call->dc_reply.dx_mode == DOOR_XFER_PAGES) {
				/* A published MOVE reply must receive install success/failure
				 * even after revoke. The client may be installing receiver fds
				 * outside d_lock; leaving here could strand its commit. */
				while (!call->dc_reply_install_done &&
				       (call->dc_reply_move_required || !door->d_revoked))
					cv_wait(&call->dc_cv, &door->d_lock);
				if (call->dc_reply_install_done) {
					if (call->dc_reply_install_error == 0 &&
					    call->dc_reply_move_required) {
						/*
						 * fdclose() acquires the process filedesc lock, so
						 * drop d_lock first.  The server call reference keeps
						 * the descriptor bundle alive while the source is
						 * removed.
						 */
						mtx_unlock(&door->d_lock);
#ifdef DOORFS_TEST
						door_test_gate(DOOR_TEST_REPLY_MOVE_CLOSE);
#endif
						door_fd_bundle_move_sources(td,
						    door, call,
						    &call->dc_reply_fds);
						mtx_lock(&door->d_lock);
					}
					/* After source close, acknowledge MOVE to the client. */
					call->dc_reply_move_done = true;
					door_call_wake_client_locked(
					    call, DOOR_SHUTTLE_F_REPLY);
				}
			}
		}
		call->dc_server_td = NULL;

		/*
		 * The local SERVER ref protects the detached call through install/MOVE.
		 * The client may already have dropped its ref. Release SERVER through the
		 * final-drop interlock, never retain it across the next receive.
		 */
		if (call->dc_type == DOOR_CALL_RPC && !completed_cancelled) {
			door_call_detached_drop_locked(door, call);
			call = NULL;
			completed = NULL;
		} else {
			completed = call;
		}
		arg->dir_flags |= DOOR_RETURN_F_COMPLETED;

		/*
		 * A cancelled completion has no reply-install barrier and must not
		 * keep its final server reference across the next worker wait.
		 * Finish this transaction now; libdoor will issue a clean re-wait.
		 */
		if (completed_cancelled && completed != NULL &&
		    completed->dc_type == DOOR_CALL_RPC && !completed->dc_oneway) {
			door_server_set_waiting_locked(door, ds, false);
			door_return_clear_request(arg);
			arg->dir_flags |= DOOR_RETURN_F_REWAIT;
			call = NULL;
			error = 0;
			goto unlock;
		}
	} else if (arg->dir_call_id != 0 || arg->dir_reply_size != 0 ||
		   arg->dir_reply_fd >= 0 || arg->dir_reply_desc_count != 0) {
		error = EINVAL;
		goto unlock;
	}

next_request:
	while (ds->ds_call == NULL && TAILQ_EMPTY(&door->d_pending) &&
	       !door->d_revoked) {
		/*
		 * Idempotent for the early-available path.  If a client reserved
		 * this worker during reply_install_done, ds_call is already non-NULL
		 * and this loop is skipped.
		 */
		door_server_set_waiting_locked(door, ds, true);
		error = door_server_wait_locked(door, ds);

		if (error == 0 && ds->ds_call == NULL && !door->d_revoked)
			error = door_server_postwake_ast_locked(door, ds, td);

		if (error != 0) {
			/*
			 * Assignment/revoke may win after the interruptible wait has
			 * selected an error but before d_lock is reacquired.  A binding
			 * which owns ds_call must never be removed.  Prioritize the
			 * committed Door state, exactly as postwake AST handling does,
			 * and let the loop exit through the normal assigned/revoked
			 * path on its next condition check.
			 */
			if (ds->ds_call != NULL || door->d_revoked) {
				error = 0;
				continue;
			}
			door_server_set_waiting_locked(door, ds, false);
			binding_drop = door_server_remove_locked(door, ds);
			error = EINTR;
			goto unlock;
		}
		/* Direct dispatch clears ds_waiting before signalling ds_cv. */
		if (ds->ds_call == NULL)
			door_server_set_waiting_locked(door, ds, false);
	}
	if (door->d_revoked) {
		/*
		 * The worker may have entered this RETURN before the ONEWAY request
		 * existed, slept in next_request with dir_call_id == 0, then raced:
		 *
		 *   direct dispatch -> ds_call = call
		 *   revoke          -> call state = REVOKED, removed from d_active
		 *   wake worker
		 *
		 * We are therefore already past the function-entry discard added in
		 * v10.17.  Do not remove/free the binding while it still owns the
		 * assigned server reference.  Consume that undelivered revoked call
		 * first, then tear down the binding.
		 */
		if (ds->ds_call != NULL) {
			call = ds->ds_call;
			KASSERT(call->dc_state == DOOR_CALL_REVOKED ||
				    call->dc_state == DOOR_CALL_CANCELLED,
			    ("revoked Door has assigned call in state %d",
				call->dc_state));
			KASSERT(door_server_discard_cancelled_locked(
				    door, ds, call),
			    ("failed to discard revoked assigned call after "
			     "wait"));
			call = NULL;
		}

		door_server_set_waiting_locked(door, ds, false);
		binding_drop = door_server_remove_locked(door, ds);
		error = EBADF;
		goto unlock;
	}

	if (ds->ds_call != NULL) {
		call = ds->ds_call;
		KASSERT(call->dc_server_td == td,
		    ("direct dispatch server mismatch"));
	} else {
		call = TAILQ_FIRST(&door->d_pending);
		KASSERT(call != NULL, ("worker woke without assigned call"));
		TAILQ_REMOVE(&door->d_pending, call, dc_link);
		door->d_pending_count--;
		door_call_activate_locked(door, call, ds);

		/*
		 * This client slept before a concrete server was known.  Wake it so
		 * any subsequent wait can arm a precise client/server relationship.
		 */
		door_call_wake_client_locked(call, DOOR_SHUTTLE_F_DISPATCH);
	}

#ifdef DOORFS_TEST
	if (call->dc_type == DOOR_CALL_RPC) {
		bool still_assigned;
		door_call_hold(call);
		mtx_unlock(&door->d_lock);
		door_test_gate(DOOR_TEST_EXPORT);
		mtx_lock(&door->d_lock);
		still_assigned = ds->ds_call == call;
		door_call_detached_drop_locked(door, call); /* TEMP, not SERVER */
		if (!still_assigned) {
			call = NULL;
			goto next_request;
		}
	}
#endif
	if (call->dc_type == DOOR_CALL_RPC &&
	    __predict_false(call->dc_early_dispatch))
		door_server_wait_request_ready_locked(door, call);
	if (door_server_discard_cancelled_locked(door, ds, call)) {
		call = NULL;
		goto next_request;
	}
	if (door->d_revoked) {
		if (ds->ds_call != NULL) {
			call = ds->ds_call;
			ds->ds_call = NULL;
			call->dc_server_td = NULL;
			door_call_detached_drop_locked(door, call);
			call = NULL;
		}
		door_server_set_waiting_locked(door, ds, false);
		binding_drop = door_server_remove_locked(door, ds);
		error = EBADF;
		goto unlock;
	}

	if (call->dc_shm_region != NULL && shm_ref != NULL && shm_ptr != NULL) {
		error =
		    door_shm_server_export_locked(call, td, shm_ref, shm_ptr);
		if (error != 0)
			goto unlock;
		arg->dir_flags |= DOOR_RETURN_F_SHM;
	} else if (call->dc_shm_region != NULL) {
		error = ENOTSUP;
		goto unlock;
	}

	request_size = call->dc_request.dx_size;
	arg->dir_request_size = request_size;
	arg->dir_request_desc_count = call->dc_request_fds.df_count;
	arg->dir_call_id = call->dc_id;
	if (call->dc_type == DOOR_CALL_UNREF) {
		arg->dir_flags |= DOOR_RETURN_F_UNREF;
		bzero(&arg->dir_cred, sizeof(arg->dir_cred));
	} else if ((door->d_attributes & DOOR_NO_CRED) != 0) {
		bzero(&arg->dir_cred, sizeof(arg->dir_cred));
	} else if ((input_flags & DOOR_RETURN_F_CRED_LAZY) == 0) {
		door_export_cred(call, &arg->dir_cred);
	}
	if (request_size > capacity ||
	    (call->dc_request_fds.df_count != 0 &&
	    ((arg->dir_request_desc_ptr != 0 &&
		 call->dc_request_fds.df_count > desc_capacity) ||
		(arg->dir_request_desc_ptr == 0 &&
		    call->dc_request_fds.df_count > 1)))) {
		door_server_requeue_undelivered_locked(door, ds, call);
		call = NULL;
		if (resizable) {
			arg->dir_flags &= DOOR_RETURN_F_COMPLETED;
			arg->dir_flags |= DOOR_RETURN_F_NEED_BUFS;
			arg->dir_call_id = 0;
			arg->dir_request_fd = -1;
			bzero(&arg->dir_cred, sizeof(arg->dir_cred));
			if (shm_ref != NULL)
				bzero(shm_ref, sizeof(*shm_ref));
			if (shm_ptr != NULL)
				*shm_ptr = 0;
			error = 0;
		} else {
			error = EMSGSIZE;
		}
		goto unlock;
	}

	/*
	 * Commit ONEWAY server delivery before releasing d_lock for request
	 * copyout/install.  Revoke must preserve the SERVER reference from this
	 * point onward because the callback may already be entering userspace.
	 *
	 * Marking here is deliberately conservative: if copyout/install later
	 * fails, worker/RETURN teardown still owns and releases the call.
	 */
	if (call != NULL && call->dc_type == DOOR_CALL_RPC && call->dc_oneway)
		call->dc_server_delivered = true;

	error = 0;

unlock:
	mtx_unlock(&door->d_lock);

	/*
	 * The scalar empty-reply path has neither userspace transport to finish
	 * nor detached ownership to release.  Once the next empty request has
	 * been exported under d_lock, its call id is the complete result.  Keep
	 * that overwhelmingly common ping-pong case out of the generic cleanup,
	 * copyout and descriptor-install tail.
	 *
	 * reply_initialized being false proves that this invocation never
	 * entered the general reply-capture path.  The remaining predicates
	 * deliberately exclude revoke/cancel teardown, SHM and descriptor work.
	 */
	if (__predict_true(scalar_fast && !reply_initialized && error == 0 &&
			   call != NULL && completed == NULL && !binding_drop &&
			   call->dc_request.dx_size == 0 &&
			   call->dc_request_fds.df_count == 0 &&
			   call->dc_shm_region == NULL)) {
		if (__predict_true(
			fast_result != NULL && call->dc_type == DOOR_CALL_RPC &&
			arg->dir_call_id != 0 &&
			arg->dir_call_id < DOOR_FAST_RETURN_CALL_MASK &&
			(arg->dir_flags & ~DOOR_RETURN_F_COMPLETED) == 0))
			*fast_result =
			    DOOR_FAST_RETURN_F_REGISTER | arg->dir_call_id;
		return (0);
	}

	if (binding_drop)
		door_server_binding_drop(ds);
	if (completed != NULL) {
		door_call_drop(completed);
	}
	if (error == 0 && call != NULL && call->dc_request.dx_size != 0) {
		error = door_xfer_copyout(
		    &call->dc_request, td, arg->dir_request_ptr);
	}
	if (error == 0 && call != NULL && call->dc_request_fds.df_count != 0) {
		error = door_fd_bundle_install(td, &call->dc_request_fds,
		    arg->dir_request_desc_ptr, desc_capacity,
		    &arg->dir_request_fd);
	}
	if (reply_initialized && reply.dx_mode != DOOR_XFER_NONE)
		door_xfer_destroy(&reply);
	if (reply_initialized && reply_fds.df_files != NULL)
		door_fd_bundle_drop(&reply_fds, td);
	return (error);
}

static void
door_thread_cleanup_binding(struct door_server_binding *ds, struct thread *td)
{
	struct door_async_batch batch;
	struct door *door;
	struct door_call *call;
	bool drop_ref;

	door = ds->ds_door;
	if (door == NULL)
		return;

	call = NULL;
	drop_ref = false;
	door_async_batch_init(&batch);
	mtx_lock(&door->d_lock);

	/*
	 * Thread cleanup uses the direct thread slot. Its temporary ds_refs pin
	 * survives structural removal; retain the linked check for idempotence.
	 */
	if (!ds->ds_linked || ds->ds_td != td) {
		mtx_unlock(&door->d_lock);
		return;
	}

	call = ds->ds_call;
	if (call != NULL) {
		ds->ds_call = NULL;
		if (call->dc_state == DOOR_CALL_ACTIVE ||
		    call->dc_state == DOOR_CALL_CANCELLED) {
			TAILQ_REMOVE(&door->d_active, call, dc_link);
			door->d_active_count--;
		}
		if (call->dc_state == DOOR_CALL_ACTIVE) {
			/*
			 * Isolated thread disappearance keeps ECONNRESET semantics.
			 * Owner-process exit has already run door_revoke(), so those
			 * calls arrive here as DOOR_CALL_REVOKED with EBADF published.
			 */
			call->dc_error = ECONNRESET;
			call->dc_state = DOOR_CALL_DONE;
			if (call->dc_async)
				door_async_schedule_locked(
				    door, call, ECONNRESET, NULL, 0, &batch);
			if (call->dc_type != DOOR_CALL_UNREF)
				door_call_wake_client_locked(
				    call, DOOR_SHUTTLE_F_REPLY);
		}
		call->dc_server_td = NULL;
	}

	drop_ref = door_server_remove_locked(door, ds);
	mtx_unlock(&door->d_lock);
	door_async_batch_flush(&batch);

	if (call != NULL) {
		door_call_drop(call); /* server call reference */
	}
	if (drop_ref)
		door_server_binding_drop(ds); /* structural binding reference */
}

void
door_thread_cleanup_all(struct thread *td)
{
	struct door_server_binding *ds;

	/*
	 * A Door worker has at most one binding.  thread_dtor runs after td has
	 * stopped executing, while the binding's structural reference keeps ds
	 * and its Door alive.  Pin it across removal so cleanup remains robust if
	 * the structural reference is dropped by door_server_remove_locked().
	 */
	ds = td->td_door_server;
	if (ds == NULL)
		return;

	door_server_binding_hold(ds);
	door_thread_cleanup_binding(ds, td);
	door_server_binding_drop(ds);

	KASSERT(td->td_door_server == NULL,
	    ("Door thread cleanup left binding installed"));
}

/*
 * Process exit intentionally does not tear down bindings.
 *
 * door_revoke() wakes every server and marks assigned calls revoked.  A
 * RETURN worker removes its own binding after observing revoke; if it never
 * resumes, thread_dtor reaches the same object directly through
 * td_door_server.
 * This prevents a different process thread from freeing ds while RETURN still
 * has that pointer live after door_server_wait_locked().
 */

int
door_call_full(struct door *door, struct door_ioc_call *arg, struct thread *td)
{
	return (door_call(door, arg, td, NULL, false, true));
}

int
door_call_shm(
    struct door *door, struct door_ioc_call_shm *arg, struct thread *td)
{
	if (arg->dics_uniquifier != 0 &&
	    arg->dics_uniquifier != door->d_uniquifier)
		return (EXDEV);
	return (door_call(
	    door, &arg->dics_call, td, &arg->dics_shm, false, true));
}

int
door_info(struct door *door, struct door_ioc_info *info, struct thread *td)
{
	bool local;
	pid_t target;

	bzero(info, sizeof(*info));
	info->di_version = DOOR_ABI_VERSION;
	door_owner_snapshot(door, td->td_proc, &target, &local);
	info->di_target = target;
	if (local)
		info->di_flags |= DOOR_INFO_LOCAL;
	info->di_proc = 0;

	mtx_lock(&door->d_lock);
	if (door->d_revoked)
		info->di_flags |= DOOR_INFO_REVOKED;
	info->di_cookie = door->d_cookie;
	info->di_uniquifier = door->d_uniquifier;
	info->di_attributes = door->d_attributes;
	info->di_pending_calls = door->d_pending_count;
	info->di_active_calls = door->d_active_count;
	info->di_server_threads = door->d_server_count;
	info->di_jid = door->d_owner_cred != NULL
			   ? door->d_owner_cred->cr_prison->pr_id
			   : -1;
	mtx_unlock(&door->d_lock);
	return (0);
}
