/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/time.h>
#include <sys/ucred.h>

#include <sys/door_impl.h>

enum door_named_state {
	DOOR_NAMED_LIVE = 0,
	DOOR_NAMED_DEAD,
};

struct door_named_entry {
	LIST_ENTRY(door_named_entry) dne_link;
	TAILQ_ENTRY(door_named_entry) dne_dead_link;

	/*
	 * Service identity outlives one Door generation.  DEAD entries have no
	 * Door pointer and therefore cannot pin a revoked generation in memory.
	 */
	struct door *dne_door;
	struct ucred *dne_scope_cred;
	uint64_t dne_uniquifier;
	time_t dne_dead_since;
	enum door_named_state dne_state;
	bool dne_global;
	bool dne_dead_linked;
	char dne_name[DOOR_NAME_MAX];
};

static LIST_HEAD(, door_named_entry) door_named = LIST_HEAD_INITIALIZER(
    door_named);
static TAILQ_HEAD(, door_named_entry) door_named_dead = TAILQ_HEAD_INITIALIZER(
    door_named_dead);

static struct mtx door_named_lock;
static struct timeout_task door_named_gc_task;
static struct cdev *doorctl_dev;

static u_int door_named_count;
static u_int door_named_dead_count;
static bool door_named_gc_queued;
static bool door_named_gc_stopping;

/*
 * Hard bound prevents a buggy or hostile application from turning the
 * persistent discovery namespace into unbounded wired-kernel memory.
 *
 * DEAD entries exist only as service identities for restart/replacement and
 * are garbage-collected after a grace period.  Future contractfs/SMF policy
 * can replace this timeout without changing Door generation lifetime.
 */
static int door_named_max_entries = 4096;
static int door_named_dead_grace = 60;

SYSCTL_NODE(_kern, OID_AUTO, doorctl, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Door named-service registry");
SYSCTL_INT(_kern_doorctl, OID_AUTO, max_entries, CTLFLAG_RWTUN,
    &door_named_max_entries, 0, "Maximum named Door service identities");
SYSCTL_INT(_kern_doorctl, OID_AUTO, dead_grace, CTLFLAG_RWTUN,
    &door_named_dead_grace, 0,
    "Seconds to retain a DEAD service identity for replacement");
SYSCTL_UINT(_kern_doorctl, OID_AUTO, entries, CTLFLAG_RD, &door_named_count, 0,
    "Current named service identities");
SYSCTL_UINT(_kern_doorctl, OID_AUTO, dead_entries, CTLFLAG_RD,
    &door_named_dead_count, 0, "Current DEAD service identities");

static void door_named_gc(void *, int);

static d_ioctl_t doorctl_ioctl;

static struct cdevsw doorctl_cdevsw = {
    .d_version = D_VERSION,
    .d_ioctl = doorctl_ioctl,
    .d_name = "doorctl",
};

static int
door_name_validate(const char name[DOOR_NAME_MAX])
{
	size_t i;

	if (name[0] == '\0')
		return (EINVAL);

	for (i = 0; i < DOOR_NAME_MAX; i++) {
		unsigned char c;

		c = (unsigned char)name[i];
		if (c == '\0')
			return (0);
		/*
		 * Keep logical names single-component and log-safe.  Dot, colon,
		 * dash and underscore remain available for hierarchical naming.
		 */
		if (c <= 0x20 || c == 0x7f || c == '/' || c == '\\')
			return (EINVAL);
	}
	return (ENAMETOOLONG);
}

static bool
door_named_same_scope(
    struct door_named_entry *e, bool global, struct ucred *cred)
{
	if (e->dne_global != global)
		return (false);
	if (global)
		return (true);
	return (e->dne_scope_cred != NULL && cred != NULL &&
		e->dne_scope_cred->cr_prison == cred->cr_prison);
}

static void
door_named_entry_free(struct door_named_entry *e)
{
	KASSERT(e->dne_door == NULL, ("freeing LIVE named Door entry"));
	KASSERT(!e->dne_dead_linked, ("freeing linked DEAD named Door entry"));

	if (e->dne_scope_cred != NULL) {
		crfree(e->dne_scope_cred);
		e->dne_scope_cred = NULL;
	}
	free(e, M_DOORFS);
}

static int
door_named_gc_delay(void)
{
	int seconds;

	seconds = door_named_dead_grace;
	if (seconds <= 0)
		return (1);
	if (seconds > INT_MAX / hz)
		seconds = INT_MAX / hz;
	return (MAX(1, seconds * hz));
}

static void
door_named_gc_arm_locked(void)
{
	mtx_assert(&door_named_lock, MA_OWNED);

	if (door_named_gc_stopping || door_named_gc_queued ||
	    TAILQ_EMPTY(&door_named_dead))
		return;

	door_named_gc_queued = true;
	taskqueue_enqueue_timeout(
	    taskqueue_thread, &door_named_gc_task, door_named_gc_delay());
}

/*
 * Remove eligible DEAD service identities.  No Door references are involved:
 * the generation was detached at LIVE -> DEAD transition.
 */
static void
door_named_gc(void *context __unused, int pending __unused)
{
	TAILQ_HEAD(, door_named_entry) expired;
	struct door_named_entry *e, *tmp;
	time_t now;
	int grace;

	TAILQ_INIT(&expired);
	now = time_uptime;
	grace = MAX(0, door_named_dead_grace);

	mtx_lock(&door_named_lock);
	door_named_gc_queued = false;
	TAILQ_FOREACH_SAFE(e, &door_named_dead, dne_dead_link, tmp)
	{
		if (grace != 0 && now - e->dne_dead_since < grace)
			continue;

		TAILQ_REMOVE(&door_named_dead, e, dne_dead_link);
		e->dne_dead_linked = false;
		LIST_REMOVE(e, dne_link);
		KASSERT(door_named_count != 0, ("named entry count underflow"));
		KASSERT(
		    door_named_dead_count != 0, ("named DEAD count underflow"));
		door_named_count--;
		door_named_dead_count--;
		TAILQ_INSERT_TAIL(&expired, e, dne_dead_link);
	}
	door_named_gc_arm_locked();
	mtx_unlock(&door_named_lock);

	while ((e = TAILQ_FIRST(&expired)) != NULL) {
		TAILQ_REMOVE(&expired, e, dne_dead_link);
		door_named_entry_free(e);
	}
}

/*
 * Purge only DEAD identities.  Used before an unload-busy decision so stale
 * restart metadata can never keep an otherwise idle module loaded.
 */
void
doorctl_purge_dead(void)
{
	TAILQ_HEAD(, door_named_entry) dead;
	struct door_named_entry *e;

	TAILQ_INIT(&dead);
	mtx_lock(&door_named_lock);
	while ((e = TAILQ_FIRST(&door_named_dead)) != NULL) {
		TAILQ_REMOVE(&door_named_dead, e, dne_dead_link);
		e->dne_dead_linked = false;
		LIST_REMOVE(e, dne_link);
		KASSERT(door_named_count != 0, ("named entry count underflow"));
		KASSERT(
		    door_named_dead_count != 0, ("named DEAD count underflow"));
		door_named_count--;
		door_named_dead_count--;
		TAILQ_INSERT_TAIL(&dead, e, dne_dead_link);
	}
	mtx_unlock(&door_named_lock);

	while ((e = TAILQ_FIRST(&dead)) != NULL) {
		TAILQ_REMOVE(&dead, e, dne_dead_link);
		door_named_entry_free(e);
	}
}

static int
door_named_register(struct door_ctl_register *arg, struct thread *td)
{
	struct door_named_entry *e, *newent;
	struct door *door, *old;
	bool global, revoked;
	int error;

	if (arg->dcr_version != DOOR_CTL_ABI_VERSION ||
	    (arg->dcr_flags & ~DOOR_NAMED_F_GLOBAL) != 0 ||
	    arg->dcr_reserved != 0)
		return (EINVAL);
	error = door_name_validate(arg->dcr_name);
	if (error != 0)
		return (error);

	error = door_file_get(td, arg->dcr_door_fd, &door);
	if (error != 0)
		return (error);

	global = (arg->dcr_flags & DOOR_NAMED_F_GLOBAL) != 0;
	if (global && td->td_ucred->cr_prison != &prison0) {
		door_drop(door);
		return (EPERM);
	}

	newent = malloc(sizeof(*newent), M_DOORFS, M_WAITOK | M_ZERO);
	strlcpy(newent->dne_name, arg->dcr_name, sizeof(newent->dne_name));
	newent->dne_global = global;
	newent->dne_state = DOOR_NAMED_LIVE;
	newent->dne_scope_cred = crhold(td->td_ucred);

	/*
	 * A LIVE entry owns one publication count and one Door reference.  DEAD
	 * entries own neither; they retain only service identity/scope metadata.
	 */
	door_hold(door);
	error = door_owner_publication_hold(door, td->td_proc);
	if (error != 0) {
		door_drop(door);
		door_drop(door); /* door_file_get */
		door_named_entry_free(newent);
		return (error);
	}
	newent->dne_door = door;
	newent->dne_uniquifier = door->d_uniquifier;

	old = NULL;
	/* Acquisition above does not freeze registry identity. Recheck under
	 * registry lock; nested order is registry -> Door. Revoke drops d_lock
	 * before notifying this registry; displaced refs are dropped outside it. */
	mtx_lock(&door_named_lock);
	LIST_FOREACH(e, &door_named, dne_link)
	{
		if (strcmp(e->dne_name, arg->dcr_name) != 0 ||
		    !door_named_same_scope(e, global, td->td_ucred))
			continue;

		if (e->dne_state == DOOR_NAMED_DEAD) {
			if (e->dne_dead_linked) {
				TAILQ_REMOVE(
				    &door_named_dead, e, dne_dead_link);
				e->dne_dead_linked = false;
				KASSERT(door_named_dead_count != 0,
				    ("named DEAD count underflow"));
				door_named_dead_count--;
			}
			e->dne_door = door;
			e->dne_uniquifier = door->d_uniquifier;
			e->dne_dead_since = 0;
			e->dne_state = DOOR_NAMED_LIVE;
			mtx_unlock(&door_named_lock);

			door_drop(door); /* door_file_get */
			newent->dne_door = NULL;
			door_named_entry_free(newent);
			return (0);
		}

		KASSERT(e->dne_door != NULL, ("LIVE named entry without Door"));
		mtx_lock(&e->dne_door->d_lock);
		revoked = e->dne_door->d_revoked;
		mtx_unlock(&e->dne_door->d_lock);
		if (!revoked) {
			mtx_unlock(&door_named_lock);
			door_publication_drop(door);
			door_drop(door);
			door_drop(door); /* door_file_get */
			newent->dne_door = NULL;
			door_named_entry_free(newent);
			return (EEXIST);
		}

		/*
		 * Defensive replacement of a revoked LIVE entry.  Normally
		 * doorctl_generation_revoked() has already converted it to DEAD.
		 */
		old = e->dne_door;
		e->dne_door = door;
		e->dne_uniquifier = door->d_uniquifier;
		e->dne_state = DOOR_NAMED_LIVE;
		mtx_unlock(&door_named_lock);

		door_publication_drop(old);
		door_drop(old);
		door_drop(door); /* door_file_get */
		newent->dne_door = NULL;
		door_named_entry_free(newent);
		return (0);
	}

	if (door_named_max_entries <= 0 ||
	    door_named_count >= (u_int)door_named_max_entries) {
		mtx_unlock(&door_named_lock);
		door_publication_drop(door);
		door_drop(door);
		door_drop(door); /* door_file_get */
		newent->dne_door = NULL;
		door_named_entry_free(newent);
		return (ENOSPC);
	}

	LIST_INSERT_HEAD(&door_named, newent, dne_link);
	door_named_count++;
	mtx_unlock(&door_named_lock);
	door_drop(door); /* door_file_get */
	return (0);
}

static int
door_named_unregister(struct door_ctl_unregister *arg, struct thread *td)
{
	struct door_named_entry *e;
	struct door *door, *published;
	bool global, live;
	int error;

	if (arg->dcu_version != DOOR_CTL_ABI_VERSION ||
	    (arg->dcu_flags & ~DOOR_NAMED_F_GLOBAL) != 0 ||
	    arg->dcu_reserved != 0)
		return (EINVAL);
	error = door_name_validate(arg->dcu_name);
	if (error != 0)
		return (error);

	error = door_file_get(td, arg->dcu_door_fd, &door);
	if (error != 0)
		return (error);
	global = (arg->dcu_flags & DOOR_NAMED_F_GLOBAL) != 0;

	published = NULL;
	live = false;
	mtx_lock(&door_named_lock);
	LIST_FOREACH(e, &door_named, dne_link)
	{
		if (strcmp(e->dne_name, arg->dcu_name) != 0 ||
		    !door_named_same_scope(e, global, td->td_ucred))
			continue;

		if (e->dne_state == DOOR_NAMED_LIVE) {
			if (e->dne_door != door)
				continue;
			live = true;
			published = e->dne_door;
		} else {
			/*
			 * Explicit REVOKE followed by UNREGISTER remains supported after
			 * LIVE -> DEAD detached the generation pointer.
			 */
			if (e->dne_uniquifier != door->d_uniquifier)
				continue;
		}
		break;
	}
	if (e == NULL) {
		mtx_unlock(&door_named_lock);
		door_drop(door);
		return (ENOENT);
	}
	if (!door_is_owner(door, td->td_proc)) {
		mtx_unlock(&door_named_lock);
		door_drop(door);
		return (EPERM);
	}

	if (e->dne_dead_linked) {
		TAILQ_REMOVE(&door_named_dead, e, dne_dead_link);
		e->dne_dead_linked = false;
		KASSERT(
		    door_named_dead_count != 0, ("named DEAD count underflow"));
		door_named_dead_count--;
	}
	LIST_REMOVE(e, dne_link);
	KASSERT(door_named_count != 0, ("named entry count underflow"));
	door_named_count--;
	if (live)
		e->dne_door = NULL;
	mtx_unlock(&door_named_lock);

	if (published != NULL) {
		door_publication_drop(published);
		door_drop(published);
	}
	door_named_entry_free(e);
	door_drop(door);
	return (0);
}

/*
 * Lookup order is local jail namespace first, then a host-global service.
 * The returned Door reference belongs to the caller. This selection is a
 * snapshot, not a reservation of the generation for a later connect.
 */
static struct door *
door_named_lookup_hold(const char *name, struct ucred *cred)
{
	struct door_named_entry *e;
	struct door *door;

	door = NULL;
	mtx_lock(&door_named_lock);

	LIST_FOREACH(e, &door_named, dne_link)
	{
		if (e->dne_state != DOOR_NAMED_LIVE || e->dne_global ||
		    strcmp(e->dne_name, name) != 0 ||
		    !door_named_same_scope(e, false, cred))
			continue;
		KASSERT(e->dne_door != NULL, ("LIVE named entry without Door"));
		door = e->dne_door;
		door_hold(door);
		break;
	}

	if (door == NULL) {
		LIST_FOREACH(e, &door_named, dne_link)
		{
			if (e->dne_state != DOOR_NAMED_LIVE || !e->dne_global ||
			    strcmp(e->dne_name, name) != 0)
				continue;
			KASSERT(e->dne_door != NULL,
			    ("LIVE global named entry without Door"));
			door = e->dne_door;
			door_hold(door);
			break;
		}
	}

	mtx_unlock(&door_named_lock);
	return (door);
}

static int
door_named_connect(struct door_ctl_connect *arg, struct thread *td)
{
	struct door *door;
	int error, fd, jid;
	uint64_t id;

	if (arg->dcc_version != DOOR_CTL_ABI_VERSION || arg->dcc_flags != 0)
		return (EINVAL);
	error = door_name_validate(arg->dcc_name);
	if (error != 0)
		return (error);

	door = door_named_lookup_hold(arg->dcc_name, td->td_ucred);
	if (door == NULL)
		return (ENOENT);

	/*
	 * Same-jail access is implicit; host-global cross-jail
	 * access requires DOOR_CROSS_JAIL.  This call site is deliberately the
	 * future policy-manager hook: successful authorization produces a file
	 * capability. CALL does not repeat jail/discovery selection, but still
	 * enforces operation-specific Capsicum rights and per-Door limits.
	 */
	error = door_check_jail(door, td->td_ucred);
	if (error != 0) {
		door_drop(door);
		return (error);
	}

	mtx_lock(&door->d_lock);
	if (door->d_revoked) {
		mtx_unlock(&door->d_lock);
		door_drop(door);
		return (EBADF);
	}
	jid = door->d_owner_cred != NULL ? door->d_owner_cred->cr_prison->pr_id
					 : -1;
	id = door->d_uniquifier;
	mtx_unlock(&door->d_lock);

	fd = -1;
	error = door_client_file_install(td, door, &fd);
	door_drop(door);
	if (error != 0)
		return (error);

	arg->dcc_fd = fd;
	arg->dcc_target_jid = jid;
	arg->dcc_uniquifier = id;
	return (0);
}

static int
door_named_lookup(struct door_ctl_lookup *arg, struct thread *td)
{
	struct door *door;
	int error;

	if (arg->dcl_version != DOOR_CTL_ABI_VERSION || arg->dcl_flags != 0)
		return (EINVAL);
	error = door_name_validate(arg->dcl_name);
	if (error != 0)
		return (error);

	door = door_named_lookup_hold(arg->dcl_name, td->td_ucred);
	if (door == NULL)
		return (ENOENT);

	error = door_check_jail(door, td->td_ucred);
	if (error == 0) {
		mtx_lock(&door->d_lock);
		if (door->d_revoked)
			error = EBADF;
		else {
			arg->dcl_target_jid =
			    door->d_owner_cred != NULL
				? door->d_owner_cred->cr_prison->pr_id
				: -1;
			arg->dcl_attributes = door->d_attributes;
			arg->dcl_uniquifier = door->d_uniquifier;
		}
		mtx_unlock(&door->d_lock);
	}

	door_drop(door);
	return (error);
}

/*
 * Convert every publication of this generation into a detached DEAD service
 * identity.  The old Door is released immediately; only bounded metadata is
 * retained for daemon restart/replacement.
 */
void
doorctl_generation_revoked(struct door *door)
{
	struct door_named_entry *e;
	u_int detached;

	detached = 0;
	mtx_lock(&door_named_lock);
	LIST_FOREACH(e, &door_named, dne_link)
	{
		if (e->dne_state != DOOR_NAMED_LIVE || e->dne_door != door)
			continue;

		e->dne_door = NULL;
		e->dne_uniquifier = door->d_uniquifier;
		e->dne_dead_since = time_uptime;
		e->dne_state = DOOR_NAMED_DEAD;
		if (!e->dne_dead_linked) {
			TAILQ_INSERT_TAIL(&door_named_dead, e, dne_dead_link);
			e->dne_dead_linked = true;
			door_named_dead_count++;
		}
		detached++;
	}
	door_named_gc_arm_locked();
	mtx_unlock(&door_named_lock);

	/* DEAD entries no longer own publications. Drops may run Door teardown,
	 * so none may run while door_named_lock is held. */
	while (detached-- != 0) {
		door_publication_drop(door);
		door_drop(door);
	}
}

static int
doorctl_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td)
{
	switch (cmd) {
	case DOORCTL_IOC_REGISTER:
		return (
		    door_named_register((struct door_ctl_register *)data, td));
	case DOORCTL_IOC_UNREGISTER:
		return (door_named_unregister(
		    (struct door_ctl_unregister *)data, td));
	case DOORCTL_IOC_CONNECT:
		return (
		    door_named_connect((struct door_ctl_connect *)data, td));
	case DOORCTL_IOC_LOOKUP:
		return (door_named_lookup((struct door_ctl_lookup *)data, td));
	default:
		return (ENOTTY);
	}
}

int
doorctl_init(void)
{
	mtx_init(&door_named_lock, "door named registry", NULL, MTX_DEF);
	TAILQ_INIT(&door_named_dead);
	door_named_count = 0;
	door_named_dead_count = 0;
	door_named_gc_queued = false;
	door_named_gc_stopping = false;
	TIMEOUT_TASK_INIT(
	    taskqueue_thread, &door_named_gc_task, 0, door_named_gc, NULL);

	/*
	 * Operations are owner/jail checked in-kernel.  devfs rules still decide
	 * whether a jail sees this global control device at all.
	 */
	doorctl_dev =
	    make_dev(&doorctl_cdevsw, 0, UID_ROOT, GID_WHEEL, 0666, "doorctl");
	if (doorctl_dev == NULL) {
		mtx_destroy(&door_named_lock);
		return (ENOMEM);
	}
	return (0);
}

int
doorctl_fini(void)
{
	u_int pending;

	/*
	 * door_core_fini() has already purged DEAD identities and verified that
	 * no Door objects/bindings remain.  Stop the deferred GC before destroying
	 * registry state so it cannot re-enqueue after the module unload begins.
	 */
	mtx_lock(&door_named_lock);
	door_named_gc_stopping = true;
	mtx_unlock(&door_named_lock);

	pending = 0;
	(void)taskqueue_cancel_timeout(
	    taskqueue_thread, &door_named_gc_task, &pending);
	taskqueue_drain_timeout(taskqueue_thread, &door_named_gc_task);

	doorctl_purge_dead();

	mtx_lock(&door_named_lock);
	if (!LIST_EMPTY(&door_named)) {
		/*
		 * Any remaining entry is LIVE and therefore indicates a real active
		 * Door lifetime bug.  Do not silently destroy a live service.
		 */
		door_named_gc_stopping = false;
		mtx_unlock(&door_named_lock);
		return (EBUSY);
	}
	KASSERT(door_named_count == 0, ("named entry count nonzero at fini"));
	KASSERT(
	    door_named_dead_count == 0, ("named DEAD count nonzero at fini"));
	mtx_unlock(&door_named_lock);

	if (doorctl_dev != NULL) {
		destroy_dev(doorctl_dev);
		doorctl_dev = NULL;
	}
	mtx_destroy(&door_named_lock);
	return (0);
}
