/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "opt_doorfs.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/caprights.h>
#include <sys/eventhandler.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/stat.h>
#include <sys/vnode.h>

#include <sys/door_impl.h>
#ifdef DOORFS_TEST
#include <sys/door_test.h>
#endif

#include "namefs_impl.h"

MALLOC_DEFINE(M_NAMEFS, "namefs", "namefs objects");

static LIST_HEAD(, namefs_mount) namefs_endpoints = LIST_HEAD_INITIALIZER(
    namefs_endpoints);
static struct mtx namefs_endpoints_lock;
static eventhandler_tag namefs_process_exit_tag;
static eventhandler_tag namefs_vfs_unmounted_tag;

/* Prevent module unload while a detached GC task still owns its object. */
static volatile u_int namefs_gc_objects;

static void namefs_gc_task(void *, int);

static int
namefs_get_doorfd(struct mount *mp, int *fdp)
{
	void *value;
	int error, len;

	value = NULL;
	len = 0;
	error = vfs_getopt(mp->mnt_optnew, "doorfd", &value, &len);
	if (error != 0 || len != sizeof(*fdp))
		return (EINVAL);
	memcpy(fdp, value, sizeof(*fdp));
	return (*fdp >= 0 ? 0 : EINVAL);
}

static int
namefs_get_path(struct mount *mp, char **pathp)
{
	void *value;
	size_t len;
	int error, ilen;

	*pathp = NULL;
	value = NULL;
	ilen = 0;
	error = vfs_getopt(mp->mnt_optnew, "fspath", &value, &ilen);
	if (error != 0 || value == NULL || ilen <= 1)
		return (EINVAL);
	len = strnlen(value, (size_t)ilen);
	if (len == 0 || len >= (size_t)ilen)
		return (EINVAL);
	*pathp = strdup(value, M_NAMEFS);
	return (*pathp != NULL ? 0 : ENOMEM);
}

static struct namefs_gc *
namefs_gc_alloc(void)
{
	struct namefs_gc *gc;

	gc = malloc(sizeof(*gc), M_NAMEFS, M_WAITOK | M_ZERO);
	TIMEOUT_TASK_INIT(
	    taskqueue_thread, &gc->ng_task, 0, namefs_gc_task, gc);
	atomic_add_int(&namefs_gc_objects, 1);
#ifdef DOORFS_TEST
	door_test_object_add(DOOR_TEST_OBJ_GC);
#endif
	return (gc);
}

static void
namefs_gc_free(struct namefs_gc *gc)
{
	if (gc == NULL)
		return;
	atomic_subtract_int(&namefs_gc_objects, 1);
#ifdef DOORFS_TEST
	door_test_object_drop(DOOR_TEST_OBJ_GC);
#endif
	free(gc, M_NAMEFS);
}

static bool
namefs_target_orphaned_locked(struct namefs_mount *nm)
{
	struct file *fp;
	u_int refs;

	mtx_assert(&nm->nm_lock, MA_OWNED);
	fp = nm->nm_target;
	if (fp == NULL)
		return (true);
	/* namefs owns one file ref. dup/inherited target refs postpone orphaning;
	 * external vnode refs instead decide whether the mount can be removed. */
	refs = atomic_load_acq_int(&fp->f_count);
	return (refs <= 1);
}

void
namefs_gc_kick(struct namefs_mount *nm, u_int probe_budget)
{
	struct namefs_gc *gc;

	if (nm == NULL)
		return;
	mtx_lock(&nm->nm_lock);
	gc = nm->nm_gc;
	if (gc == NULL || gc->ng_queued || nm->nm_state == NAMEFS_UNMOUNTING ||
	    nm->nm_rootvp == NULL) {
		mtx_unlock(&nm->nm_lock);
		return;
	}
	if (probe_budget > gc->ng_probe_budget)
		gc->ng_probe_budget = probe_budget;
	gc->ng_mp = nm->nm_rootvp->v_mount;
	/* Pin the mount across delayed/bounded probes; finish releases this ref. */
	vfs_ref(gc->ng_mp);
#ifdef DOORFS_TEST
	door_test_object_add(DOOR_TEST_OBJ_GC_PIN);
#endif
	gc->ng_queued = true;
	mtx_unlock(&nm->nm_lock);
	taskqueue_enqueue_timeout(
	    taskqueue_thread, &gc->ng_task, MAX(1, hz / 4));
}

static u_int
namefs_external_vrefs_locked(struct namefs_mount *nm)
{
	u_int refs;

	refs = vrefcnt(nm->nm_rootvp);
	return (
	    refs > nm->nm_internal_vrefs ? refs - nm->nm_internal_vrefs : 0);
}

static void
namefs_gc_task(void *context, int pending __unused)
{
	struct namefs_gc *gc;
	struct namefs_mount *nm;
	struct mount *mp;
	u_int budget, external;
	bool free_gc, orphaned, retry_probe, try_unmount;
	int error;
#ifdef DOORFS_TEST
	uint64_t test_object = 0;
#endif

	gc = context;
	mp = gc->ng_mp;
	try_unmount = false;
	retry_probe = false;
	free_gc = false;
	if (mp == NULL) {
		free_gc = true;
		goto finish;
	}
#ifdef DOORFS_TEST
	test_object = ((uint64_t)(uint32_t)mp->mnt_stat.f_fsid.val[0] << 32) |
	    (uint32_t)mp->mnt_stat.f_fsid.val[1];
	door_test_gc_gate(test_object);
#endif
	nm = mp->mnt_data;
	if (nm == NULL) {
		free_gc = true;
		goto finish;
	}
	mtx_lock(&nm->nm_lock);
	if (nm->nm_gc != gc || nm->nm_state == NAMEFS_UNMOUNTING) {
		mtx_unlock(&nm->nm_lock);
		goto finish;
	}
	orphaned = namefs_target_orphaned_locked(nm);
	if (!orphaned) {
		/* Exit can precede final fd drops; probe again only within this budget. */
		budget = gc->ng_probe_budget;
		if (budget != 0) {
			gc->ng_probe_budget = budget - 1;
			retry_probe = true;
		}
		mtx_unlock(&nm->nm_lock);
		goto out;
	}
	if (nm->nm_state == NAMEFS_LIVE)
		nm->nm_state = NAMEFS_RECOVERY;
	external = namefs_external_vrefs_locked(nm);
	if (external == 0) {
		nm->nm_state = NAMEFS_UNMOUNTING;
		try_unmount = true;
	}
	gc->ng_probe_budget = 0;
	mtx_unlock(&nm->nm_lock);
	if (try_unmount) {
		error = dounmount(mp, 0, curthread);
		if (error == 0) {
			free_gc = true;
		} else {
			nm = mp->mnt_data;
			if (nm != NULL) {
				mtx_lock(&nm->nm_lock);
				/* Failed unmount must permit recovery/rebind again. */
				if (nm->nm_gc == gc &&
				    nm->nm_state == NAMEFS_UNMOUNTING)
					nm->nm_state = NAMEFS_RECOVERY;
				mtx_unlock(&nm->nm_lock);
			}
		}
	}
out:
	if (retry_probe) {
		taskqueue_enqueue_timeout(
		    taskqueue_thread, &gc->ng_task, MAX(1, hz / 4));
#ifdef DOORFS_TEST
		door_test_gc_done(test_object);
#endif
		return;
	}
finish:
	gc->ng_mp = NULL;
	gc->ng_queued = false;
	if (mp != NULL) {
		vfs_rel(mp);
#ifdef DOORFS_TEST
		door_test_object_drop(DOOR_TEST_OBJ_GC_PIN);
#endif
	}
	if (free_gc)
		namefs_gc_free(gc);
#ifdef DOORFS_TEST
	if (test_object != 0)
		door_test_gc_done(test_object);
#endif
}

static int
namefs_alloc_root(struct mount *mp, struct namefs_mount *nm, struct vnode **vpp)
{
	struct vnode *vp;
	int error;

	*vpp = NULL;
	error = getnewvnode("namefs", mp, &namefs_vnodeops, &vp);
	if (error != 0)
		return (error);
	error = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	if (error != 0) {
		vrele(vp);
		return (error);
	}
	vp->v_type = VREG;
	vp->v_data = nm;
	vp->v_vflag |= VV_ROOT;
	error = insmntque1(vp, mp);
	if (error != 0) {
		vgone(vp);
		vput(vp);
		return (error);
	}
	vn_set_state(vp, VSTATE_CONSTRUCTED);
	VOP_UNLOCK(vp);
	*vpp = vp;
	return (0);
}

static void
namefs_register(struct namefs_mount *nm)
{
	mtx_lock(&namefs_endpoints_lock);
	LIST_INSERT_HEAD(&namefs_endpoints, nm, nm_registry_link);
	nm->nm_registry_linked = true;
	mtx_unlock(&namefs_endpoints_lock);
}

static void
namefs_unregister(struct namefs_mount *nm)
{
	mtx_lock(&namefs_endpoints_lock);
	if (nm->nm_registry_linked) {
		LIST_REMOVE(nm, nm_registry_link);
		nm->nm_registry_linked = false;
	}
	mtx_unlock(&namefs_endpoints_lock);
}

static int
namefs_mount(struct mount *mp)
{
	struct namefs_mount *nm;
	struct file *old, *target;
	struct vattr va;
	struct vnode *coveredvp;
	char *path;
	int error, fd;

	path = NULL;
	error = namefs_get_doorfd(mp, &fd);
	if (error != 0)
		return (error);
	error = fget(curthread, fd, &cap_no_rights, &target);
	if (error != 0)
		return (error);
	if (!door_file_is_door(target)) {
		fdrop(target, curthread);
		return (EINVAL);
	}
	if (!door_file_is_live(target)) {
		fdrop(target, curthread);
		return (EBADF);
	}
	if ((mp->mnt_flag & MNT_UPDATE) != 0) {
		nm = mp->mnt_data;
		if (nm == NULL) {
			fdrop(target, curthread);
			return (EINVAL);
		}
		mtx_lock(&nm->nm_lock);
		old = nm->nm_target;
		nm->nm_target = target;
		nm->nm_state = NAMEFS_LIVE;
		/* Rebind cancels further orphan probes; queued work sees the new target. */
		nm->nm_gc->ng_probe_budget = 0;
		mtx_unlock(&nm->nm_lock);
		if (old != NULL)
			fdrop(old, curthread);
		return (0);
	}
	error = namefs_get_path(mp, &path);
	if (error != 0) {
		fdrop(target, curthread);
		return (error);
	}
	coveredvp = mp->mnt_vnodecovered;
	if (coveredvp == NULL) {
		free(path, M_NAMEFS);
		fdrop(target, curthread);
		return (EINVAL);
	}
	error = vn_lock(coveredvp, LK_SHARED | LK_RETRY);
	if (error == 0) {
		error = VOP_GETATTR(coveredvp, &va, curthread->td_ucred);
		VOP_UNLOCK(coveredvp);
	}
	if (error != 0) {
		free(path, M_NAMEFS);
		fdrop(target, curthread);
		return (error);
	}
	nm = malloc(sizeof(*nm), M_NAMEFS, M_WAITOK | M_ZERO);
#ifdef DOORFS_TEST
	door_test_object_add(DOOR_TEST_OBJ_MOUNT);
#endif
	mtx_init(&nm->nm_lock, "namefs endpoint", NULL, MTX_DEF);
	nm->nm_target = target;
	nm->nm_attach_cred = crhold(curthread->td_ucred);
	nm->nm_attach_path = path;
	nm->nm_attr = va;
	nm->nm_state = NAMEFS_LIVE;
	nm->nm_gc = namefs_gc_alloc();
	mp->mnt_data = nm;
	error = namefs_alloc_root(mp, nm, &nm->nm_rootvp);
	if (error != 0) {
		mp->mnt_data = NULL;
		fdrop(target, curthread);
		namefs_gc_free(nm->nm_gc);
		free(path, M_NAMEFS);
		crfree(nm->nm_attach_cred);
		mtx_destroy(&nm->nm_lock);
#ifdef DOORFS_TEST
		door_test_object_drop(DOOR_TEST_OBJ_MOUNT);
#endif
		free(nm, M_NAMEFS);
		return (error);
	}
	namefs_register(nm);
	vfs_getnewfsid(mp);
	vfs_mountedfrom(mp, "namefs");
	nm->nm_internal_vrefs = vrefcnt(nm->nm_rootvp);
	return (0);
}

static int
namefs_unmount(struct mount *mp, int mntflags)
{
	struct namefs_mount *nm;
	struct namefs_gc *gc;
	struct file *target;
	enum namefs_state old;
	bool claimed;
	int error, flags;

	nm = mp->mnt_data;
	if (nm == NULL)
		return (EINVAL);
	mtx_lock(&nm->nm_lock);
	old = nm->nm_state;
	claimed = old != NAMEFS_UNMOUNTING;
	if (claimed)
		nm->nm_state = NAMEFS_UNMOUNTING;
	mtx_unlock(&nm->nm_lock);
	flags = (mntflags & MNT_FORCE) != 0 ? FORCECLOSE : 0;
	error = vflush(mp, 1, flags, curthread);
	if (error != 0) {
		if (claimed) {
			mtx_lock(&nm->nm_lock);
			if (nm->nm_state == NAMEFS_UNMOUNTING)
				nm->nm_state = old;
			mtx_unlock(&nm->nm_lock);
		}
		return (error);
	}
	namefs_unregister(nm);
	mtx_lock(&nm->nm_lock);
	target = nm->nm_target;
	nm->nm_target = NULL;
	gc = nm->nm_gc;
	nm->nm_gc = NULL;
	mtx_unlock(&nm->nm_lock);
	mp->mnt_data = NULL;
	if (target != NULL)
		fdrop(target, curthread);
	if (nm->nm_attach_cred != NULL)
		crfree(nm->nm_attach_cred);
	free(nm->nm_attach_path, M_NAMEFS);
	if (gc != NULL && !gc->ng_queued)
		namefs_gc_free(gc);
	mtx_destroy(&nm->nm_lock);
#ifdef DOORFS_TEST
	door_test_object_drop(DOOR_TEST_OBJ_MOUNT);
#endif
	free(nm, M_NAMEFS);
	return (0);
}

static int
namefs_root(struct mount *mp, int flags, struct vnode **vpp)
{
	struct namefs_mount *nm;
	int error;

	nm = mp->mnt_data;
	if (nm == NULL || nm->nm_rootvp == NULL)
		return (ENOENT);
	error = vget(nm->nm_rootvp, flags | LK_RETRY);
	if (error == 0)
		*vpp = nm->nm_rootvp;
	return (error);
}

static int
namefs_statfs(struct mount *mp __unused, struct statfs *sbp)
{
	sbp->f_bsize = PAGE_SIZE;
	sbp->f_iosize = PAGE_SIZE;
	sbp->f_blocks = 1;
	sbp->f_files = 1;
	return (0);
}

static void
namefs_process_exit(void *arg __unused, struct proc *p __unused)
{
	struct namefs_mount *nm;

	mtx_lock(&namefs_endpoints_lock);
	/* An exit kicks all publications; it does not synchronously mark recovery. */
	LIST_FOREACH(nm, &namefs_endpoints, nm_registry_link)
	namefs_gc_kick(nm, 4);
	mtx_unlock(&namefs_endpoints_lock);
}

static void
namefs_vfs_unmounted(
    void *arg __unused, struct mount *ump __unused, struct thread *td __unused)
{
	struct namefs_mount *nm;

	mtx_lock(&namefs_endpoints_lock);
	LIST_FOREACH(nm, &namefs_endpoints, nm_registry_link)
	namefs_gc_kick(nm, 0);
	mtx_unlock(&namefs_endpoints_lock);
}

static int
namefs_init(struct vfsconf *vfsp __unused)
{
	mtx_init(&namefs_endpoints_lock, "namefs endpoints", NULL, MTX_DEF);
	namefs_process_exit_tag = EVENTHANDLER_REGISTER(
	    process_exit, namefs_process_exit, NULL, EVENTHANDLER_PRI_ANY);
	if (namefs_process_exit_tag == NULL) {
		mtx_destroy(&namefs_endpoints_lock);
		return (ENOMEM);
	}
	namefs_vfs_unmounted_tag = EVENTHANDLER_REGISTER(
	    vfs_unmounted, namefs_vfs_unmounted, NULL, EVENTHANDLER_PRI_ANY);
	if (namefs_vfs_unmounted_tag == NULL) {
		EVENTHANDLER_DEREGISTER(process_exit, namefs_process_exit_tag);
		namefs_process_exit_tag = NULL;
		mtx_destroy(&namefs_endpoints_lock);
		return (ENOMEM);
	}
	return (0);
}

static int
namefs_uninit(struct vfsconf *vfsp __unused)
{
	if (atomic_load_acq_int(&namefs_gc_objects) != 0)
		return (EBUSY);
	mtx_lock(&namefs_endpoints_lock);
	if (!LIST_EMPTY(&namefs_endpoints)) {
		mtx_unlock(&namefs_endpoints_lock);
		return (EBUSY);
	}
	mtx_unlock(&namefs_endpoints_lock);
	if (namefs_process_exit_tag != NULL)
		EVENTHANDLER_DEREGISTER(process_exit, namefs_process_exit_tag);
	if (namefs_vfs_unmounted_tag != NULL)
		EVENTHANDLER_DEREGISTER(
		    vfs_unmounted, namefs_vfs_unmounted_tag);
	mtx_destroy(&namefs_endpoints_lock);
	return (0);
}

static struct vfsops namefs_vfsops = {
    .vfs_init = namefs_init,
    .vfs_uninit = namefs_uninit,
    .vfs_mount = namefs_mount,
    .vfs_unmount = namefs_unmount,
    .vfs_root = namefs_root,
    .vfs_statfs = namefs_statfs,
};

VFS_SET(namefs_vfsops, namefs, VFCF_FILEMOUNT);
MODULE_DEPEND(namefs, doorfs, 1, 1, 1);
