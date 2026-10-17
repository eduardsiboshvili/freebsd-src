/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "opt_doorfs.h"
#include "opt_doorctl.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/eventhandler.h>
#include <sys/imgact.h>
#include <sys/jail.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/taskqueue.h>
#include <sys/sysctl.h>
#include <sys/ucred.h>

#include <sys/door_impl.h>
#ifdef DOORFS_TEST
#include <sys/door_test.h>
#endif

MALLOC_DEFINE(M_DOORFS, "doorfs", "doorfs objects");

static TAILQ_HEAD(, door) door_list = TAILQ_HEAD_INITIALIZER(door_list);
static TAILQ_HEAD(, door) door_all = TAILQ_HEAD_INITIALIZER(door_all);
static struct mtx door_list_lock;
static uint64_t door_next_uniquifier = 1;
static volatile u_int door_core_ready;
static eventhandler_tag door_view_exit_tag, door_view_exec_tag;

/* Late events: revoke alone must not invalidate a live userspace reader. */
static void
door_shm_view_process_event(void *arg __unused, struct proc *p)
{
    struct door *door;

    if (atomic_load_acq_int(&door_core_ready) == 0)
        return;

    for (;;) {
        mtx_lock(&door_list_lock);
        TAILQ_FOREACH(door, &door_all, d_all_link) {
            if (door_shm_view_exit_pending(door, p->p_pid) &&
                refcount_acquire_if_not_zero(&door->d_refs)) {
                break;
            }
        }

        mtx_unlock(&door_list_lock);
        if (door == NULL)
            return;

        door_shm_view_process_exit(door, p->p_pid);
        door_drop(door);
    }
}

static void
door_shm_view_exec_event(void *arg, struct proc *p,
    struct image_params *imgp __unused)
{
    door_shm_view_process_event(arg, p);
}


static u_int door_max_doors_per_proc = 1024;
u_int door_max_servers_per_door = 256;
u_int door_max_shm_regions_per_door = 1024;
u_long door_max_shm_bytes_per_door = 1024UL * 1024 * 1024;

TUNABLE_INT("kern.doorfs.max_doors_per_proc", &door_max_doors_per_proc);
TUNABLE_INT("kern.doorfs.max_servers_per_door",
    &door_max_servers_per_door);
TUNABLE_INT("kern.doorfs.max_shm_regions_per_door",
    &door_max_shm_regions_per_door);
TUNABLE_ULONG("kern.doorfs.max_shm_bytes_per_door",
    &door_max_shm_bytes_per_door);

SYSCTL_DECL(_kern_doorfs);
SYSCTL_UINT(_kern_doorfs, OID_AUTO, max_doors_per_proc, CTLFLAG_RD,
    &door_max_doors_per_proc, 0, "Maximum owned Doors per process");
SYSCTL_UINT(_kern_doorfs, OID_AUTO, max_servers_per_door, CTLFLAG_RD,
    &door_max_servers_per_door, 0, "Maximum server bindings per Door");
SYSCTL_UINT(_kern_doorfs, OID_AUTO, max_shm_regions_per_door, CTLFLAG_RD,
    &door_max_shm_regions_per_door, 0, "Maximum SHM regions per Door");
SYSCTL_ULONG(_kern_doorfs, OID_AUTO, max_shm_bytes_per_door, CTLFLAG_RD,
    &door_max_shm_bytes_per_door, 0, "Maximum SHM bytes per Door");

void
door_hold(struct door *door)
{
	refcount_acquire(&door->d_refs);
}

static void
door_destroy(struct door *door)
{
	KASSERT(!door->d_owner_linked, ("destroying linked door"));

	/*
	 * d_all_link carries no reference of its own; the final d_refs release
	 * guarantees that this object cannot disappear while we unlink it.
	 */
	mtx_lock(&door_list_lock);
	KASSERT(door->d_all_linked, ("destroying untracked door"));
	TAILQ_REMOVE(&door_all, door, d_all_link);
	door->d_all_linked = false;
	mtx_unlock(&door_list_lock);
	KASSERT(door->d_async_reserved == 0,
	    ("destroying door with async reservations"));
	KASSERT(door->d_publications == 0, ("destroying published door"));
	KASSERT(
	    door->d_client_count == 0, ("destroying door with open clients"));
	KASSERT(TAILQ_EMPTY(&door->d_pending),
	    ("destroying door with pending calls"));
	KASSERT(TAILQ_EMPTY(&door->d_active),
	    ("destroying door with active calls"));
	KASSERT(LIST_EMPTY(&door->d_servers),
	    ("destroying door with server bindings"));
	KASSERT(TAILQ_EMPTY(&door->d_shm_regions),
	    ("destroying door with SHM regions"));
	KASSERT(door->d_pending_count == 0,
	    ("destroying door with pending_count=%u", door->d_pending_count));
	KASSERT(door->d_active_count == 0,
	    ("destroying door with active_count=%u", door->d_active_count));
	KASSERT(door->d_server_count == 0,
	    ("destroying door with server_count=%u", door->d_server_count));
	KASSERT(door->d_shm_region_count == 0,
	    ("destroying door with SHM region reservations"));
	KASSERT(door->d_shm_bytes == 0,
	    ("destroying door with SHM byte reservations"));
	if (door->d_owner_cred != NULL) {
		crfree(door->d_owner_cred);
		door->d_owner_cred = NULL;
	}
	mtx_destroy(&door->d_lock);
#ifdef DOORFS_TEST
	door_test_object_drop(DOOR_TEST_OBJ_DOOR);
#endif
	free(door, M_DOORFS);
}

void
door_drop(struct door *door)
{
	if (refcount_release(&door->d_refs))
		door_destroy(door);
}

int
door_alloc(struct proc *owner, uint64_t cookie, uint32_t attributes,
    uint32_t flags, struct door **doorp)
{
	struct door *door, *iter;
	u_int owned;
	int error;

	*doorp = NULL;
	if ((attributes & ~DOOR_CREATE_ALLOWED) != 0 ||
	    (attributes & DOOR_PRIVCREATE) != 0)
		return (EINVAL);
	/*
	 * Cross-prison visibility is an endpoint policy fixed at creation.
	 * Export such endpoints only from prison0.
	 * There is no per-call prison check after open(2) succeeds.
	 */
	if ((attributes & DOOR_CROSS_JAIL) != 0 &&
	    owner->p_ucred->cr_prison != &prison0)
		return (EPERM);
	if (flags == DOOR_CREATE_F_XCREATE) {
		if ((attributes & DOOR_PRIVATE) == 0)
			return (EINVAL);
		attributes |= DOOR_PRIVCREATE;
	} else if (flags != DOOR_CREATE_F_NORMAL) {
		return (EINVAL);
	}
	if ((attributes & DOOR_UNREF_MULTI) != 0)
		attributes |= DOOR_UNREF;
	/*
	 * ONEWAY is a data-only asynchronous primitive.  Descriptor delivery,
	 * especially transactional MOVE, has completion semantics that cannot be
	 * reported to a caller which has already returned.
	 */
	if ((attributes & DOOR_ONEWAY) != 0)
		attributes |= DOOR_REFUSE_DESC;

	door = malloc(sizeof(*door), M_DOORFS, M_WAITOK | M_ZERO);
#ifdef DOORFS_TEST
	door_test_object_add(DOOR_TEST_OBJ_DOOR);
#endif
	mtx_init(&door->d_lock, "door", NULL, MTX_DEF);
	TAILQ_INIT(&door->d_pending);
	TAILQ_INIT(&door->d_active);
	LIST_INIT(&door->d_servers);
	TAILQ_INIT(&door->d_shm_regions);
	door->d_next_call_id = 1;
	door->d_next_shm_region = 1;

	/* One owner-list reference and one reference returned to the caller. */
	refcount_init(&door->d_refs, 2);
	door->d_owner = owner;
	door->d_owner_pid = owner->p_pid;
	door->d_owner_cred = crhold(owner->p_ucred);
	door->d_cookie = cookie;
	door->d_attributes = attributes;
	door->d_data_min = 0;
	door->d_data_max = SIZE_MAX;
	door->d_hot_flags = 0;
	door->d_desc_max =
	    (door->d_attributes & DOOR_REFUSE_DESC) != 0 ? 0 : INT_MAX;

	/*
	 * Interlock publication with exit1().  exit1() sets P2_WEXIT while
	 * holding PROC_LOCK, then removes all owner endpoints.  Holding the same
	 * lock through insertion gives a strict order: either this Door is on the
	 * list before the exit pass, or creation fails and nothing is published.
	 */
	error = 0;
	PROC_LOCK(owner);
	if ((owner->p_flag2 & P2_WEXIT) != 0)
		error = ESRCH;
	if (error == 0)
		mtx_lock(&door_list_lock);
	if (error != 0) {
		PROC_UNLOCK(owner);
		crfree(door->d_owner_cred);
		door->d_owner_cred = NULL;
		mtx_destroy(&door->d_lock);
#ifdef DOORFS_TEST
		door_test_object_drop(DOOR_TEST_OBJ_DOOR);
#endif
		free(door, M_DOORFS);
		return (error);
	}
	owned = 0;
	TAILQ_FOREACH(iter, &door_list, d_owner_link) {
		if (iter->d_owner == owner)
			owned++;
	}
	if (owned >= door_max_doors_per_proc) {
		mtx_unlock(&door_list_lock);
		PROC_UNLOCK(owner);
		crfree(door->d_owner_cred);
		door->d_owner_cred = NULL;
		mtx_destroy(&door->d_lock);
#ifdef DOORFS_TEST
		door_test_object_drop(DOOR_TEST_OBJ_DOOR);
#endif
		free(door, M_DOORFS);
		return (EMFILE);
	}
	door->d_uniquifier = door_next_uniquifier++;
	if (door_next_uniquifier == 0)
		door_next_uniquifier = 1;
	TAILQ_INSERT_TAIL(&door_list, door, d_owner_link);
	door->d_owner_linked = true;
	TAILQ_INSERT_TAIL(&door_all, door, d_all_link);
	door->d_all_linked = true;
	mtx_unlock(&door_list_lock);
	PROC_UNLOCK(owner);
	*doorp = door;
	return (0);
}

/*
 * Atomically validate owner identity and acquire d_lock.
 *
 * Lock order is door_list_lock -> d_lock, which is the same order used by
 * door_maybe_orphan() and thread teardown.  On success d_lock is held and
 * door_list_lock has been released.  This prevents owner exit from slipping
 * between a standalone door_is_owner() check and publication of new state
 * protected by d_lock (notably a server binding).
 */
int
door_owner_lock(struct door *door, struct proc *p)
{
	int error;

	error = 0;
	mtx_lock(&door_list_lock);
	if (!door->d_owner_linked || door->d_owner != p) {
		mtx_unlock(&door_list_lock);
		return (EPERM);
	}

	mtx_lock(&door->d_lock);
	if (door->d_revoked || door->d_orphaning)
		error = EBADF;
	mtx_unlock(&door_list_lock);

	if (error != 0)
		mtx_unlock(&door->d_lock);
	return (error);
}

bool
door_is_owner(struct door *door, struct proc *p)
{
	bool result;

	mtx_lock(&door_list_lock);
	result = door->d_owner_linked && door->d_owner == p;
	mtx_unlock(&door_list_lock);
	return (result);
}

void
door_owner_snapshot(
    struct door *door, struct proc *p, pid_t *pidp, bool *localp)
{
	mtx_lock(&door_list_lock);
	*pidp = door->d_owner_linked ? door->d_owner_pid : -1;
	*localp = door->d_owner_linked && door->d_owner == p;
	mtx_unlock(&door_list_lock);
}

void
door_owner_remove(struct door *door)
{
	bool drop;

	drop = false;
	mtx_lock(&door_list_lock);
	if (door->d_owner_linked) {
		mtx_lock(&door->d_lock);
		door->d_orphaning = true;
		TAILQ_REMOVE(&door_list, door, d_owner_link);
		door->d_owner_linked = false;
		door->d_owner = NULL;
		mtx_unlock(&door->d_lock);
		drop = true;
	}
	mtx_unlock(&door_list_lock);

	if (drop)
		door_drop(door); /* owner-list reference */
}

/*
 * d_file_count counts door file objects, not numeric descriptors.  dup(2)
 * references the same struct file, so fo_close() decrements the count only
 * when the final reference to that file object disappears.
 */
void
door_file_installed(struct door *door)
{
	mtx_lock(&door->d_lock);
	door->d_file_count++;
	mtx_unlock(&door->d_lock);
}

/*
 * Remove the owner-list anchor once neither a private Door file object nor a
 * namefs publication can make this generation reachable from userland.
 *
 * Lock order is door_list_lock -> d_lock.
 */
void
door_maybe_orphan(struct door *door)
{
	bool orphaned;

	orphaned = false;
	mtx_lock(&door_list_lock);
	mtx_lock(&door->d_lock);
	if (door->d_owner_linked && door->d_file_count == 0 &&
	    door->d_publications == 0) {
		/*
		 * Block new client/publication acquisition before dropping the
		 * namespace anchor.  door_revoke() runs after the locks are released
		 * and would otherwise leave a race window in which a new reference
		 * can be published onto an already-unlinked generation.
		 */
		door->d_orphaning = true;
		TAILQ_REMOVE(&door_list, door, d_owner_link);
		door->d_owner_linked = false;
		door->d_owner = NULL;
		orphaned = true;
	}
	mtx_unlock(&door->d_lock);
	mtx_unlock(&door_list_lock);

	if (!orphaned)
		return;

	(void)door_revoke(door);
	door_drop(door); /* owner-list reference */
}

void
door_last_file_closed(struct door *door)
{
	mtx_lock(&door->d_lock);
	KASSERT(door->d_file_count != 0, ("door file count underflow"));
	door->d_file_count--;
	mtx_unlock(&door->d_lock);

	door_maybe_orphan(door);
}

int
door_client_open(struct door *door)
{
	int error;

	mtx_lock(&door->d_lock);
	if (door->d_revoked || door->d_orphaning) {
		error = EBADF;
	} else {
		door->d_client_count++;
		error = 0;
	}
	mtx_unlock(&door->d_lock);
	return (error);
}

void
door_client_closed(struct door *door)
{
	uint64_t generation;
	bool enqueue;

	generation = 0;
	enqueue = false;

	mtx_lock(&door->d_lock);
	KASSERT(door->d_client_count != 0, ("door client count underflow"));
	door->d_client_count--;

	if (door->d_client_count == 0 && !door->d_revoked &&
	    (door->d_attributes & DOOR_UNREF) != 0 &&
	    (((door->d_attributes & DOOR_UNREF_MULTI) != 0) ||
		!door->d_unref_once_fired)) {
		/* Historical zero-client notification; MULTI ignores the once latch.
		 * Generation labels events, not current client liveness: reopening
		 * must not erase an already owed zero-transition notification. */
		door->d_unref_once_fired = true;
		generation = ++door->d_unref_generation;
		if (door->d_unref_generation == 0)
			generation = ++door->d_unref_generation;
		enqueue = true;
	}
	mtx_unlock(&door->d_lock);

	if (enqueue)
		door_unref_enqueue(door, generation);
}

int
door_publication_hold(struct door *door)
{
	int error;

	mtx_lock(&door->d_lock);
	if (door->d_revoked || door->d_orphaning) {
		error = EBADF;
	} else {
		door->d_publications++;
		error = 0;
	}
	mtx_unlock(&door->d_lock);
	return (error);
}

/*
 * Owner-authorized publication acquisition.  The owner test and publication
 * increment are one transaction with respect to process exit/orphaning.
 */
int
door_owner_publication_hold(struct door *door, struct proc *p)
{
	int error;

	error = door_owner_lock(door, p);
	if (error != 0)
		return (error);

	door->d_publications++;
	mtx_unlock(&door->d_lock);
	return (0);
}

void
door_publication_drop(struct door *door)
{
	mtx_lock(&door->d_lock);
	KASSERT(
	    door->d_publications != 0, ("door publication count underflow"));
	door->d_publications--;
	mtx_unlock(&door->d_lock);

	door_maybe_orphan(door);
}

int
door_revoke(struct door *door)
{
	struct door_async_batch batch;
	struct door_call_head dropped_async, dropped_server_oneway;
	struct door_server_binding *ds, *assigned_ds;
	struct door_call *call, *tmp;

	TAILQ_INIT(&dropped_async);
	TAILQ_INIT(&dropped_server_oneway);
	door_async_batch_init(&batch);
	mtx_lock(&door->d_lock);
	if (door->d_revoked) {
		mtx_unlock(&door->d_lock);
		return (EBADF);
	}
	door->d_revoked = true;
	atomic_set_int(&door->d_hot_flags, DOOR_HOT_REVOKED);

	TAILQ_FOREACH_SAFE(call, &door->d_pending, dc_link, tmp)
	{
		TAILQ_REMOVE(&door->d_pending, call, dc_link);
		door->d_pending_count--;
		call->dc_error = EBADF;
		call->dc_state = DOOR_CALL_REVOKED;
		if (call->dc_async)
			door_async_schedule_locked(door, call, EBADF, NULL, 0,
			    &batch);
		if (call->dc_type == DOOR_CALL_UNREF || call->dc_oneway)
			TAILQ_INSERT_TAIL(&dropped_async, call, dc_link);
		else
			door_call_wake_client_locked(
			    call, DOOR_SHUTTLE_F_REPLY);
	}

	/*
	 * Revoke chooses the terminal outcome independently of SERVER lifetime.
	 * Sync retains SERVER until RETURN/teardown. Internal dc_oneway also covers
	 * kernel async: schedule its completion, then decide whether to detach.
	 * For an assigned but undelivered one-way call, detach under d_lock and
	 * drop SERVER after unlock; waiting for teardown here leaked replacement
	 * generations. A delivered callback still needs the call through RETURN
	 * or worker teardown, even after its async completion has been scheduled.
	 */
	TAILQ_FOREACH_SAFE(call, &door->d_active, dc_link, tmp)
	{
		TAILQ_REMOVE(&door->d_active, call, dc_link);
		door->d_active_count--;
		call->dc_error = EBADF;
		call->dc_state = DOOR_CALL_REVOKED;
		if (call->dc_async)
			door_async_schedule_locked(door, call, EBADF, NULL, 0,
			    &batch);

		if (call->dc_type == DOOR_CALL_RPC && call->dc_oneway &&
		    !call->dc_server_delivered) {
			/*
			 * Assigned but not yet committed to server userspace: no
			 * callback can legitimately RETURN this request, so revoke may
			 * detach and drop SERVER immediately.
			 */
			assigned_ds = NULL;
			LIST_FOREACH(ds, &door->d_servers, ds_link)
			{
				if (ds->ds_call == call) {
					assigned_ds = ds;
					break;
				}
			}
			KASSERT(assigned_ds != NULL,
			    ("active undelivered ONEWAY call %p has no server "
			     "binding",
				call));
			if (assigned_ds != NULL) {
				assigned_ds->ds_call = NULL;
				call->dc_server_td = NULL;
				TAILQ_INSERT_TAIL(
				    &dropped_server_oneway, call, dc_link);
			}
		} else if (call->dc_type == DOOR_CALL_RPC) {
			/*
			 * Synchronous RPCs and delivered ONEWAY callbacks keep SERVER.
			 * Delivered ONEWAY completion after revoke is accepted by the
			 * existing fast-empty path, which returns DOOR_RETURN_F_EXIT and
			 * releases SERVER normally.
			 */
			cv_broadcast(&call->dc_cv);
			door_call_wake_client_locked(
			    call, DOOR_SHUTTLE_F_REPLY);
		}
	}

	/* Sleeping server threads remove their own local bindings on wakeup. */
	LIST_FOREACH(ds, &door->d_servers, ds_link)
	{
		if (ds->ds_waiting)
			door_server_wake_async_locked(ds);
	}
	mtx_unlock(&door->d_lock);
	door_async_batch_flush(&batch);

	TAILQ_FOREACH_SAFE(call, &dropped_async, dc_link, tmp)
	{
		TAILQ_REMOVE(&dropped_async, call, dc_link);
		if (call->dc_type == DOOR_CALL_UNREF)
			door_unref_drop(call);
		else
			door_oneway_drop(call);
	}

	TAILQ_FOREACH_SAFE(call, &dropped_server_oneway, dc_link, tmp)
	{
		TAILQ_REMOVE(&dropped_server_oneway, call, dc_link);
		door_oneway_server_drop(call);
	}

	door_shm_revoke_all(door);

	/*
	 * Discovery identity may outlive this generation, but the registry must
	 * not pin the revoked Door itself.  LIVE named entries become detached
	 * DEAD identities here for both explicit REVOKE and owner exit.
	 */
#ifdef DOORCTL
	doorctl_generation_revoked(door);
#endif
	return (0);
}

int
door_check_jail(struct door *door, struct ucred *cred)
{
	struct prison *owner_prison, *caller_prison;
	uint32_t attributes;

	/*
	 * This check is used by doorfs_open().  A successful open grants the
	 * descriptor capability; CALL/CALL_SHM do not re-check prison identity.
	 */
	mtx_lock(&door->d_lock);
	if (door->d_owner_cred == NULL || cred == NULL) {
		mtx_unlock(&door->d_lock);
		return (ENXIO);
	}
	owner_prison = door->d_owner_cred->cr_prison;
	caller_prison = cred->cr_prison;
	attributes = door->d_attributes;
	mtx_unlock(&door->d_lock);

	if (owner_prison == caller_prison)
		return (0);
	if ((attributes & DOOR_CROSS_JAIL) != 0)
		return (0);
	return (EACCES);
}

void
door_thread_exit(struct thread *td)
{
	if (__predict_false(atomic_load_acq_int(&door_core_ready) == 0))
		return;
	/*
	 * Owner exit removes door_list before workers necessarily unwind RETURN.
	 * Thread cleanup therefore uses td_door_server, pinned by ds_refs, rather
	 * than searching the owner list. A foreign live binding is released by
	 * its own RETURN or thread destructor, not by the owner's list removal.
	 */
	door_thread_cleanup_all(td);
}

void
door_process_exit(struct proc *p)
{
	struct door *door;

	if (__predict_false(atomic_load_acq_int(&door_core_ready) == 0))
		return;
	for (;;) {
		door = NULL;
		mtx_lock(&door_list_lock);
		TAILQ_FOREACH(door, &door_list, d_owner_link)
		{
			if (door->d_owner == p)
				break;
		}
		if (door == NULL) {
			mtx_unlock(&door_list_lock);
			break;
		}
		/*
		 * Close the owner-exit publication window before removing the global
		 * anchor.  Other processes may still hold inherited/client fds and
		 * can otherwise acquire fresh client/publication state before the
		 * revoke below reaches d_lock. The owner-list ref is separate from
		 * live bindings: door_thread_cleanup_all() releases their thread slots.
		 */
		mtx_lock(&door->d_lock);
		door->d_orphaning = true;
		TAILQ_REMOVE(&door_list, door, d_owner_link);
		door->d_owner_linked = false;
		door->d_owner = NULL;
		door_hold(
		    door); /* temporary reference outside door_list_lock */
		mtx_unlock(&door->d_lock);
		mtx_unlock(&door_list_lock);

		/*
		 * Revoke is the owner-exit linearization point.
		 *
		 * Owner exit never frees a server binding belonging to another
		 * thread.  A worker can be returning from its shuttle/CV wait with a
		 * local ds pointer at exactly this point.  Revoke marks the Door dead,
		 * detaches/wakes calls and wakes sleeping workers; the binding owner
		 * removes its own binding from RETURN, or thread_dtor does so if the
		 * worker never resumes.
		 *
		 * Each binding owns an independent Door reference, so dropping the
		 * owner-list anchor below cannot destroy the Door before that cleanup.
		 */
		(void)door_revoke(door);

		door_drop(door); /* owner-list reference */
		door_drop(door); /* temporary reference */
	}
}

int
door_core_init(void)
{
	int error;

	error = door_rpc_cache_init();
	if (error != 0)
		return (error);

	mtx_init(&door_list_lock, "door list", NULL, MTX_DEF);
#ifdef DOORCTL
	error = doorctl_init();
	if (error != 0) {
		mtx_destroy(&door_list_lock);
		door_rpc_cache_fini();
		return (error);
	}
#endif

#ifdef DOORFS_TEST
	door_test_init();
#endif
    door_view_exit_tag = EVENTHANDLER_REGISTER(process_exit,
        door_shm_view_process_event, NULL, EVENTHANDLER_PRI_ANY);
    door_view_exec_tag = EVENTHANDLER_REGISTER(process_exec,
        door_shm_view_exec_event, NULL, EVENTHANDLER_PRI_ANY);
	atomic_store_rel_int(&door_core_ready, 1);
	return (0);
}

int
door_core_fini(void)
{
#ifdef DOORCTL
	int error;
#endif

	/*
	 * DEAD doorctl entries contain only service identity metadata.  They are
	 * safe to discard on an unload attempt and must never make an otherwise
	 * idle module report EBUSY.
	 */
#ifdef DOORCTL
	doorctl_purge_dead();
#endif

	/*
	 * door_list contains only Doors which still have a live owner anchor.
	 * It is not a complete lifetime registry: owner-exited Doors may remain
	 * referenced by transferred descriptors, clients, publications or
	 * bindings.  Unloading while such an object exists frees M_DOORFS and
	 * module text underneath live callbacks.
	 *
	 * Refuse unload until every allocated Door has reached door_destroy().
	 */
	mtx_lock(&door_list_lock);
	if (!TAILQ_EMPTY(&door_all)) {
		mtx_unlock(&door_list_lock);
		return (EBUSY);
	}
	KASSERT(TAILQ_EMPTY(&door_list),
	    ("owner list nonempty with empty all-door list"));
	mtx_unlock(&door_list_lock);

	/*
	 * Never destroy UMA zones while any door_call object is still alive.
	 * uma_zdestroy() on a nonempty zone loses wired pages and hides the real
	 * reference leak.  Keep the module loaded until all calls are gone.
	 */
	if (door_rpc_calls_busy())
		return (EBUSY);

	if (door_rpc_bindings_busy())
		return (EBUSY);
#ifdef DOORFS_TEST
	if (door_test_busy())
		return (EBUSY);
#endif

#ifdef DOORCTL
	error = doorctl_fini();
	if (error != 0)
		return (error);
#endif

#ifdef DOORFS_TEST
	door_test_fini();
#endif
	atomic_store_rel_int(&door_core_ready, 0);
    EVENTHANDLER_DEREGISTER(process_exit, door_view_exit_tag);
    EVENTHANDLER_DEREGISTER(process_exec, door_view_exec_tag);
	mtx_destroy(&door_list_lock);
	door_rpc_cache_fini();
	return (0);
}

static int
door_modevent(module_t mod __unused, int type, void *data __unused)
{
	switch (type) {
	case MOD_LOAD:
		return (door_core_init());
	case MOD_UNLOAD:
		return (door_core_fini());
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t door_mod = {"doorfs", door_modevent, NULL};

DECLARE_MODULE(doorfs, door_mod, SI_SUB_VFS, SI_ORDER_ANY);
MODULE_VERSION(doorfs, 1);
