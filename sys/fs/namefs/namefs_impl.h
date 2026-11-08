/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _NAMEFS_IMPL_H_
#define _NAMEFS_IMPL_H_

#include <sys/types.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

MALLOC_DECLARE(M_NAMEFS);

enum namefs_state {
	NAMEFS_LIVE = 0,
	NAMEFS_RECOVERY,
	NAMEFS_UNMOUNTING,
};

struct namefs_gc {
	struct timeout_task ng_task;
	struct mount *ng_mp;
	bool ng_queued;
	u_int ng_probe_budget;
};

struct namefs_mount {
	struct mtx nm_lock;
	struct file *nm_target;
	struct vnode *nm_rootvp;
	struct ucred *nm_attach_cred;
	struct vattr nm_attr;

	LIST_ENTRY(namefs_mount) nm_registry_link;
	char *nm_attach_path;
	bool nm_registry_linked;

	enum namefs_state nm_state;
	u_int nm_internal_vrefs;
	struct namefs_gc *nm_gc;
};

extern struct vop_vector namefs_vnodeops;

void namefs_gc_kick(struct namefs_mount *, u_int);

#endif /* !_NAMEFS_IMPL_H_ */
