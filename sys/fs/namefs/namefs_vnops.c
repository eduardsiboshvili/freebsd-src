/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/vnode.h>

#include <sys/door_impl.h>

#include "namefs_impl.h"

static vop_open_t namefs_open;
static vop_getattr_t namefs_getattr;
static vop_access_t namefs_access;
static vop_inactive_t namefs_inactive;
static vop_reclaim_t namefs_reclaim;

struct vop_vector namefs_vnodeops = {
    .vop_default = &default_vnodeops,
    .vop_open = namefs_open,
    .vop_getattr = namefs_getattr,
    .vop_access = namefs_access,
    .vop_inactive = namefs_inactive,
    .vop_reclaim = namefs_reclaim,
};
VFS_VOP_VECTOR_REGISTER(namefs_vnodeops);

/*
 * A namefs pathname is a publication point, not a proxy file.  Pin the
 * generation selected under nm_lock and replace the file allocated by
 * openatfp() with native doorfs fileops.  Existing descriptors therefore
 * remain attached to their generation across MNT_UPDATE, while every new
 * open observes the currently published Door.
 */
static int
namefs_open(struct vop_open_args *ap)
{
	struct namefs_mount *nm;
	struct file *target;
	int error;

	if (ap->a_fp == NULL)
		return (ENXIO);
	nm = ap->a_vp->v_mount->mnt_data;
	if (nm == NULL)
		return (ENXIO);

	mtx_lock(&nm->nm_lock);
	if (nm->nm_state != NAMEFS_LIVE || nm->nm_target == NULL) {
		mtx_unlock(&nm->nm_lock);
		return (ENXIO);
	}
	target = nm->nm_target;
	if (!fhold(target)) {
		mtx_unlock(&nm->nm_lock);
		return (EBADF);
	}
	mtx_unlock(&nm->nm_lock);

	error = door_file_clone(target, ap->a_fp, ap->a_mode, ap->a_cred);
	fdrop(target, curthread);
	if (error != 0)
		return (error);

	/* openatfp() recognizes ENXIO with replaced fileops as success. With no
	 * target above, the same errno is a real failure: keep that distinction. */
	return (ENXIO);
}

static int
namefs_getattr(struct vop_getattr_args *ap)
{
	struct namefs_mount *nm;

	nm = ap->a_vp->v_mount->mnt_data;
	if (nm == NULL)
		return (ENXIO);
	*ap->a_vap = nm->nm_attr;
	ap->a_vap->va_type = VREG;
	ap->a_vap->va_fsid = ap->a_vp->v_mount->mnt_stat.f_fsid.val[0];
	return (0);
}

static int
namefs_access(struct vop_access_args *ap)
{
	struct namefs_mount *nm;

	nm = ap->a_vp->v_mount->mnt_data;
	if (nm == NULL)
		return (ENXIO);
	return (vaccess(VREG, nm->nm_attr.va_mode, nm->nm_attr.va_uid,
	    nm->nm_attr.va_gid, ap->a_accmode, ap->a_cred));
}

static int
namefs_inactive(struct vop_inactive_args *ap)
{
	struct namefs_mount *nm;

	nm = ap->a_vp->v_mount->mnt_data;
	if (nm != NULL)
		namefs_gc_kick(nm, 0);
	return (0);
}

static int
namefs_reclaim(struct vop_reclaim_args *ap)
{
	ap->a_vp->v_data = NULL;
	return (0);
}
