/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "opt_doorfs.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/refcount.h>
#include <sys/syscallsubr.h>
#include <sys/time.h>
#include <machine/atomic.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>

#include <sys/door_impl.h>
#ifdef DOORFS_TEST
#include <sys/door_test.h>
#endif

/*
 * Persistent SHM objects are setup objects, not per-call transports.  Each
 * object keeps one private vm_object reference.  vm_map entries own their own
 * references, so invalidating the Door handle does not tear mappings out from
 * under either participant.  Userland munmaps the returned addresses during
 * channel teardown.
 */
/* Bound non-pageable control memory globally as well as ordinary Door quotas.
 * Setup-only CAS; no global allocator lock is taken on the data/event path. */
#define DOOR_SHM_PAIR_MAX_LIVE 1024U
static volatile u_int door_shm_pair_live;

static bool
door_shm_pair_reserve(void)
{
	u_int count;

	for (;;) {
		count = atomic_load_acq_int(&door_shm_pair_live);
		if (count >= DOOR_SHM_PAIR_MAX_LIVE)
			return (false);

		if (atomic_cmpset_int(&door_shm_pair_live, count, count + 1))
			return (true);
	}
}

struct door_shm_view_part {
	struct door_shm_region *source;
	vm_ooffset_t offset;
	vm_size_t size;
};

struct door_shm_region {
	TAILQ_ENTRY(door_shm_region) dr_link;
	u_int dr_refs;
	bool dr_dead;
	uint64_t dr_id;
	vm_size_t dr_size;       /* Page-rounded VM object and mapping size. */
	vm_size_t dr_usable_size; /* Exact caller-visible bounds. */
	uint32_t dr_flags;
	vm_object_t dr_object;

	struct vmspace *dr_creator_vm;
	vm_offset_t dr_creator_addr;

	struct vmspace *dr_consumer_vm;
	vm_offset_t dr_consumer_addr;
	uint32_t dr_consumer_flags;

	/* Non-NULL parts distinguish a borrowed page view from an owning region. */
	struct door_shm_view_part *dr_view_parts;
	struct door *dr_view_door;
	struct door *dr_view_budget_door; /* dead source still charged while lent */
	unsigned int dr_view_count, dr_view_state, dr_view_loans;
	unsigned int dr_attach_pending; /* legacy mapping outside d_lock */
	uint64_t dr_view_token;
	pid_t dr_view_creator_pid, dr_view_consumer_pid;
	bool dr_view_creator_gone, dr_view_used;
	pid_t dr_creator_pid;

	/* Wired alias: checking an event under d_lock must never page fault. */
	vm_offset_t dr_pair_kva;
	struct cv dr_pair_cv[DOOR_SHM_PAIR_LANES];
	pid_t dr_pair_consumer_pid;
};

static void
door_shm_unreserve_locked(struct door *door, vm_size_t size)
{
	mtx_assert(&door->d_lock, MA_OWNED);
	KASSERT(door->d_shm_region_count != 0,
	    ("Door SHM region reservation underflow"));
	KASSERT(door->d_shm_bytes >= size,
	    ("Door SHM byte reservation underflow"));
	door->d_shm_region_count--;
	door->d_shm_bytes -= size;
}

static void
door_shm_remove_locked(struct door *door, struct door_shm_region *r)
{
	TAILQ_REMOVE(&door->d_shm_regions, r, dr_link);
	r->dr_dead = true;
	if ((r->dr_flags & DOOR_SHM_F_PAIR) != 0) {
		for (unsigned int lane = 0; lane < DOOR_SHM_PAIR_LANES; lane++)
			cv_broadcast(&r->dr_pair_cv[lane]);
	}

	if (r->dr_view_parts == NULL && r->dr_view_loans != 0) {
		door_shm_unreserve_locked(door, 0);
		r->dr_view_budget_door = door;
	} else
		door_shm_unreserve_locked(door, r->dr_view_parts == NULL ? r->dr_size : 0);
}

static void
door_shm_view_unloan_locked(struct door *door, struct door_shm_region *source)
{
	KASSERT(source->dr_view_loans != 0, ("page loan underflow"));
	source->dr_view_loans--;
	if (source->dr_view_loans == 0 && source->dr_view_budget_door != NULL) {
		KASSERT(source->dr_view_budget_door == door, ("wrong loan budget"));
		KASSERT(door->d_shm_bytes >= source->dr_size, ("loan budget underflow"));
		door->d_shm_bytes -= source->dr_size;
		source->dr_view_budget_door = NULL;
	}
}

static void
door_shm_region_hold(struct door_shm_region *r)
{
	refcount_acquire(&r->dr_refs);
}

void
door_shm_region_drop(struct door_shm_region *r)
{
	struct door *held_door;

	if (!refcount_release(&r->dr_refs))
		return;

	if (r->dr_view_parts != NULL) {
		KASSERT(r->dr_view_state != DOOR_SHM_VIEW_ATTACHED &&
			r->dr_view_state != DOOR_SHM_VIEW_MAPPING &&
			r->dr_view_state != DOOR_SHM_VIEW_RELEASING,
			("destroying active page view"));
		for (unsigned int i = 0; i < r->dr_view_count; i++) {
			struct door_shm_region *source = r->dr_view_parts[i].source;
			if (source == NULL)
				continue;

			mtx_lock(&r->dr_view_door->d_lock);
			door_shm_view_unloan_locked(r->dr_view_door, source);
			mtx_unlock(&r->dr_view_door->d_lock);
			door_shm_region_drop(source);
		}
		free(r->dr_view_parts, M_DOORFS);
	}

	if ((r->dr_flags & DOOR_SHM_F_PAIR) != 0) {
		if (r->dr_pair_kva != 0) {
			(void)vm_map_unwire(kernel_map, r->dr_pair_kva,
				r->dr_pair_kva + PAGE_SIZE, VM_MAP_WIRE_SYSTEM);
			(void)vm_map_remove(kernel_map, r->dr_pair_kva,
				r->dr_pair_kva + PAGE_SIZE);
		}

		for (unsigned int lane = 0; lane < DOOR_SHM_PAIR_LANES; lane++)
			cv_destroy(&r->dr_pair_cv[lane]);

		atomic_subtract_int(&door_shm_pair_live, 1);
	}

	if (r->dr_consumer_vm != NULL &&
	    (r->dr_consumer_vm != r->dr_creator_vm ||
	    r->dr_consumer_addr != r->dr_creator_addr))
		vmspace_free(r->dr_consumer_vm);
	if (r->dr_creator_vm != NULL)
		vmspace_free(r->dr_creator_vm);
	if (r->dr_object != NULL)
		vm_object_deallocate(r->dr_object);
#ifdef DOORFS_TEST
	door_test_object_drop(DOOR_TEST_OBJ_SHM);
#endif
	held_door = r->dr_view_door;
	free(r, M_DOORFS);
	if (held_door != NULL)
		door_drop(held_door);
}

static struct door_shm_region *
door_shm_find_locked(struct door *door, uint64_t id)
{
	struct door_shm_region *r;

	mtx_assert(&door->d_lock, MA_OWNED);
	TAILQ_FOREACH(r, &door->d_shm_regions, dr_link)
	{
		if (r->dr_id == id && !r->dr_dead)
			return (r);
	}
	return (NULL);
}

static int
door_shm_map_current(struct door_shm_region *r, struct thread *td,
	vm_prot_t prot, struct vmspace **vmp, vm_offset_t *addrp)
{
	struct vmspace *vm;
	vm_offset_t addr;
	int error;

	if ((td->td_proc->p_sysent->sv_flags & SV_ILP32) != 0 &&
	    r->dr_size > UINT32_MAX)
		return (EOVERFLOW);
	vm = vmspace_acquire_ref(td->td_proc);
	if (vm == NULL)
		return (ESRCH);

	addr = 0;
	vm_object_reference(r->dr_object); /* mapping reference */
	error = vm_mmap_object(&vm->vm_map, &addr, r->dr_size, prot, prot,
	    MAP_SHARED, r->dr_object, 0, FALSE, td);
	if (error != 0) {
		vm_object_deallocate(r->dr_object);
		vmspace_free(vm);
		return (error);
	}

	*vmp = vm;
	*addrp = addr;
	return (0);
}

static __inline vm_prot_t
door_shm_prot(uint32_t flags)
{
 return (((flags & DOOR_SHM_F_READ) != 0 ? VM_PROT_READ : 0) |
	 ((flags & DOOR_SHM_F_WRITE) != 0 ? VM_PROT_WRITE : 0));
}

static int
door_shm_pair_map(struct door_shm_region *r)
{
	vm_offset_t address;
	int error;

	address = vm_map_min(kernel_map);
	vm_object_reference(r->dr_object);
	error = vm_map_find(kernel_map, r->dr_object, 0, &address, PAGE_SIZE, 0,
		VMFS_ANY_SPACE, VM_PROT_READ | VM_PROT_WRITE,
		VM_PROT_READ | VM_PROT_WRITE, 0);
	if (error != 0) {
		vm_object_deallocate(r->dr_object);
		return (ENOMEM);
	}

	error = vm_map_wire(kernel_map, address, address + PAGE_SIZE,
		VM_MAP_WIRE_SYSTEM | VM_MAP_WIRE_NOHOLES);
	if (error != 0) {
		(void)vm_map_remove(kernel_map, address, address + PAGE_SIZE);
		return (ENOMEM);
	}

	r->dr_pair_kva = address;
	return (0);
}

int
door_shm_create(
	struct door *door, struct door_ioc_shm_create *arg, struct thread *td)
{
	struct door_shm_region *r;
	vm_size_t size;
	vm_prot_t prot;
	int error;

	if (arg->disc_version != DOOR_ABI_VERSION || arg->disc_size == 0 ||
	    (arg->disc_flags & ~DOOR_SHM_F_MASK) != 0 ||
	    (arg->disc_flags & DOOR_SHM_F_RW) == 0)
		return (EINVAL);
	if ((arg->disc_flags & DOOR_SHM_F_PAIR) != 0 &&
		(arg->disc_size < PAGE_SIZE ||
		(arg->disc_flags & DOOR_SHM_F_RW) != DOOR_SHM_F_RW ||
		(arg->disc_flags & DOOR_SHM_F_CONSUMER_RO) != 0))
		return (EINVAL);

	if ((td->td_proc->p_sysent->sv_flags & SV_ILP32) != 0 &&
	    arg->disc_size > UINT32_MAX)
		return (EOVERFLOW);
	if (arg->disc_size > SIZE_MAX)
		return (EOVERFLOW);

	size = round_page((vm_size_t)arg->disc_size);
	if (size == 0 || size < arg->disc_size)
		return (EOVERFLOW);

	mtx_lock(&door->d_lock);
	if (door->d_revoked || door->d_next_shm_region == 0) {
		error = door->d_revoked ? EBADF : EOVERFLOW;
		mtx_unlock(&door->d_lock);
		return (error);
	}
	if (door->d_shm_region_count >= door_max_shm_regions_per_door) {
		mtx_unlock(&door->d_lock);
		return (ENOSPC);
	}
	if (size > door_max_shm_bytes_per_door ||
	    door->d_shm_bytes > door_max_shm_bytes_per_door - size) {
		mtx_unlock(&door->d_lock);
		return (ENOMEM);
	}
	door->d_shm_region_count++;
	door->d_shm_bytes += size;
	mtx_unlock(&door->d_lock);

	if ((arg->disc_flags & DOOR_SHM_F_PAIR) != 0 &&
		!door_shm_pair_reserve()) {
		mtx_lock(&door->d_lock);
		door_shm_unreserve_locked(door, size);
		mtx_unlock(&door->d_lock);
		return (ENOSPC);
	}

	r = malloc(sizeof(*r), M_DOORFS, M_WAITOK | M_ZERO);
#ifdef DOORFS_TEST
	door_test_object_add(DOOR_TEST_OBJ_SHM);
#endif
	refcount_init(&r->dr_refs, 1); /* door-list reference */
	r->dr_creator_pid = td->td_proc->p_pid;
	r->dr_size = size;
	r->dr_usable_size = (vm_size_t)arg->disc_size;
	r->dr_flags = arg->disc_flags;
	if ((r->dr_flags & DOOR_SHM_F_PAIR) != 0) {
		for (unsigned int lane = 0; lane < DOOR_SHM_PAIR_LANES; lane++)
			cv_init(&r->dr_pair_cv[lane], "doorpair");
	}

	r->dr_object = vm_object_allocate(OBJT_DEFAULT, atop(size));
	if (r->dr_object == NULL) {
		if ((r->dr_flags & DOOR_SHM_F_PAIR) != 0) {
			for (unsigned int lane = 0; lane < DOOR_SHM_PAIR_LANES; lane++)
				cv_destroy(&r->dr_pair_cv[lane]);
			atomic_subtract_int(&door_shm_pair_live, 1);
		}

#ifdef DOORFS_TEST
		door_test_object_drop(DOOR_TEST_OBJ_SHM);
#endif
		free(r, M_DOORFS);
		mtx_lock(&door->d_lock);
		door_shm_unreserve_locked(door, size);
		mtx_unlock(&door->d_lock);
		return (ENOMEM);
	}

	prot = door_shm_prot(arg->disc_flags);
	error = 0;
	if ((r->dr_flags & DOOR_SHM_F_PAIR) != 0)
		error = door_shm_pair_map(r);
	if (error == 0)
		error = door_shm_map_current(r, td, prot, &r->dr_creator_vm,
			&r->dr_creator_addr);
	if (error != 0) {
		door_shm_region_drop(r);
		mtx_lock(&door->d_lock);
		door_shm_unreserve_locked(door, size);
		mtx_unlock(&door->d_lock);
		return (error);
	}

	mtx_lock(&door->d_lock);
	if (door->d_revoked || door->d_next_shm_region == 0) {
		error = door->d_revoked ? EBADF : EOVERFLOW;
		door_shm_unreserve_locked(door, size);
		mtx_unlock(&door->d_lock);
		(void)kern_munmap(td, r->dr_creator_addr, r->dr_size);
		door_shm_region_drop(r);
		return (error);
	}
	r->dr_id = door->d_next_shm_region++;
	TAILQ_INSERT_TAIL(&door->d_shm_regions, r, dr_link);
	mtx_unlock(&door->d_lock);

	arg->disc_region = r->dr_id;
	arg->disc_addr = r->dr_creator_addr;
	arg->disc_uniquifier = door->d_uniquifier;
	return (0);
}

int
door_shm_attach(
	struct door *door, struct door_ioc_shm_attach *arg, struct thread *td)
{
	struct door_shm_region *r;
	struct vmspace *vm;
	vm_offset_t addr;
	vm_prot_t prot;
	int error;

	if (arg->disa_version != DOOR_ABI_VERSION ||
	    (arg->disa_flags & ~(DOOR_SHM_F_RW | DOOR_SHM_F_PAIR)) != 0 || arg->disa_region == 0)
		return (EINVAL);
	if (!door_is_owner(door, td->td_proc))
		return (EPERM);

	mtx_lock(&door->d_lock);
	r = door_shm_find_locked(door, arg->disa_region);
	if (r == NULL) {
		mtx_unlock(&door->d_lock);
		return (ENOENT);
	}
	if ((arg->disa_flags & DOOR_SHM_F_PAIR) != 0 &&
		(r->dr_flags & DOOR_SHM_F_PAIR) == 0) {
		mtx_unlock(&door->d_lock);
		return (EINVAL);
	}

	arg->disa_flags &= ~DOOR_SHM_F_PAIR;
	if ((r->dr_flags & DOOR_SHM_F_PAIR) != 0 &&
		arg->disa_flags != DOOR_SHM_F_RW) {
		mtx_unlock(&door->d_lock);
		return (EACCES);
	}

	if (r->dr_view_parts != NULL || r->dr_view_loans != 0) {
		mtx_unlock(&door->d_lock);
		return (EBUSY);
	}

	if ((arg->disa_flags & DOOR_SHM_F_RW) == 0 ||
	    ((r->dr_flags & DOOR_SHM_F_CONSUMER_RO) != 0 &&
	    (arg->disa_flags & DOOR_SHM_F_WRITE) != 0)) {
		mtx_unlock(&door->d_lock);
		return (EACCES);
	}
	if (r->dr_consumer_vm != NULL) {
		if (r->dr_consumer_vm != td->td_proc->p_vmspace) {
			mtx_unlock(&door->d_lock);
			return (EBUSY);
		}
		if ((arg->disa_flags & ~r->dr_consumer_flags) != 0) {
			mtx_unlock(&door->d_lock);
			return (EACCES);
		}
		arg->disa_addr = r->dr_consumer_addr;
		arg->disa_size = r->dr_usable_size;
		arg->disa_uniquifier = door->d_uniquifier;
		mtx_unlock(&door->d_lock);
		return (0);
	}
	if (r->dr_creator_vm == td->td_proc->p_vmspace &&
	    (r->dr_flags & DOOR_SHM_F_CONSUMER_RO) == 0) {
		if ((arg->disa_flags & ~(r->dr_flags & DOOR_SHM_F_RW)) != 0) {
			mtx_unlock(&door->d_lock);
			return (EACCES);
		}
		r->dr_pair_consumer_pid = td->td_proc->p_pid;
		r->dr_consumer_vm = r->dr_creator_vm;
		r->dr_consumer_addr = r->dr_creator_addr;
		r->dr_consumer_flags = r->dr_flags & DOOR_SHM_F_RW;
		arg->disa_addr = r->dr_consumer_addr;
		arg->disa_size = r->dr_usable_size;
		arg->disa_uniquifier = door->d_uniquifier;
		mtx_unlock(&door->d_lock);
		return (0);
	}
	r->dr_attach_pending++;
	door_shm_region_hold(r);
	mtx_unlock(&door->d_lock);

	prot = door_shm_prot(arg->disa_flags);
	error = door_shm_map_current(r, td, prot, &vm, &addr);
	if (error != 0) {
		mtx_lock(&door->d_lock);
		r->dr_attach_pending--;
		mtx_unlock(&door->d_lock);
		door_shm_region_drop(r);
		return (error);
	}

	mtx_lock(&door->d_lock);
	r->dr_attach_pending--;
	if (r->dr_dead || door->d_revoked || r->dr_consumer_vm != NULL) {
		/* Snapshot before the final drop: concurrent destroy may own no ref. */
		error = r->dr_dead ? ENOENT : (door->d_revoked ? EBADF : EBUSY);
		mtx_unlock(&door->d_lock);
		(void)kern_munmap(td, addr, r->dr_size);
		vmspace_free(vm);
		door_shm_region_drop(r);
		return (error);
	}
	r->dr_pair_consumer_pid = td->td_proc->p_pid;
	r->dr_consumer_vm = vm;
	r->dr_consumer_addr = addr;
	r->dr_consumer_flags = arg->disa_flags;
	arg->disa_addr = addr;
	arg->disa_size = r->dr_usable_size;
	arg->disa_uniquifier = door->d_uniquifier;
	mtx_unlock(&door->d_lock);
	door_shm_region_drop(r); /* temporary lookup reference */
	return (0);
}

int
door_shm_destroy_handle(
	struct door *door, struct door_ioc_shm_destroy *arg, struct thread *td)
{
	struct door_shm_region *r;

	if (arg->disd_version != DOOR_ABI_VERSION || arg->disd_flags != 0 ||
	    arg->disd_region == 0)
		return (EINVAL);

	mtx_lock(&door->d_lock);
	r = door_shm_find_locked(door, arg->disd_region);
	if (r == NULL || r->dr_creator_vm != td->td_proc->p_vmspace) {
		mtx_unlock(&door->d_lock);
		return (r == NULL ? ENOENT : EPERM);
	}
	if (r->dr_view_parts != NULL || r->dr_view_loans != 0) {
		mtx_unlock(&door->d_lock);
		return (EBUSY);
	}

	door_shm_remove_locked(door, r);
	mtx_unlock(&door->d_lock);

	door_shm_region_drop(r); /* door-list reference */
	return (0);
}

int
door_shm_call_capture_locked(struct door *door, struct thread *td,
	const struct door_ioc_shm_ref *ref, struct door_call *call)
{
	struct door_shm_region *r;

	mtx_assert(&door->d_lock, MA_OWNED);
	if (ref == NULL || ref->disr_region == 0) {
		if (ref != NULL &&
		    (ref->disr_offset != 0 || ref->disr_size != 0))
			return (EINVAL);
		return (0);
	}

	r = door_shm_find_locked(door, ref->disr_region);
	if (r == NULL)
		return (ENOENT);
	if (r->dr_view_parts != NULL || r->dr_view_loans != 0) {
		return (EBUSY);
	}

	if (r->dr_creator_vm != td->td_proc->p_vmspace)
		return (EPERM);
	if (r->dr_consumer_vm == NULL)
		return (ENXIO);
	if (ref->disr_offset > r->dr_usable_size ||
	    ref->disr_size > r->dr_usable_size - ref->disr_offset)
		return (EOVERFLOW);
	if (ref->disr_offset > SIZE_MAX || ref->disr_size > SIZE_MAX)
		return (EOVERFLOW);

	door_shm_region_hold(r);
	call->dc_shm_region = r;
	call->dc_shm_offset = ref->disr_offset;
	call->dc_shm_size = ref->disr_size;
	return (0);
}

int
door_shm_server_export_locked(struct door_call *call, struct thread *td,
	struct door_ioc_shm_ref *ref, uint64_t *local_ptr)
{
	struct door_shm_region *r;

	r = call->dc_shm_region;
	bzero(ref, sizeof(*ref));
	*local_ptr = 0;
	if (r == NULL)
		return (0);
	/* Capture pins the object, not export permission: destroy can invalidate
	 * it before delivery. Existing VM mappings are independent of this id. */
	if (r->dr_dead || r->dr_consumer_vm != td->td_proc->p_vmspace)
		return (ENXIO);

	ref->disr_region = r->dr_id;
	ref->disr_offset = call->dc_shm_offset;
	ref->disr_size = call->dc_shm_size;
	*local_ptr = r->dr_consumer_addr + call->dc_shm_offset;
	return (0);
}

void
door_shm_revoke_all(struct door *door)
{
	struct door_shm_region_head list;
	struct door_shm_region *r, *next;

	TAILQ_INIT(&list);
	mtx_lock(&door->d_lock);
	TAILQ_FOREACH_SAFE(r, &door->d_shm_regions, dr_link, next) {
		if (r->dr_view_parts != NULL &&
			r->dr_view_state != DOOR_SHM_VIEW_PUBLISHED &&
			r->dr_view_state != DOOR_SHM_VIEW_RELEASED)
			continue;

		door_shm_remove_locked(door, r);
		TAILQ_INSERT_TAIL(&list, r, dr_link);
	}
	mtx_unlock(&door->d_lock);

	while ((r = TAILQ_FIRST(&list)) != NULL) {
		TAILQ_REMOVE(&list, r, dr_link);
		door_shm_region_drop(r);
	}
}

static bool
door_shm_view_overlap(struct door *door, struct door_shm_region *source,
	uint64_t offset, uint64_t size)
{
	struct door_shm_region *view;

	TAILQ_FOREACH(view, &door->d_shm_regions, dr_link) {
		if (view->dr_view_parts == NULL)
			continue;

		for (unsigned int i = 0; i < view->dr_view_count; i++) {
			struct door_shm_view_part *p = &view->dr_view_parts[i];
			if (p->source == source && offset < p->offset + p->size &&
				p->offset < offset + size)
				return (true);
		}
	}

	return (false);
}

static void
door_shm_view_result(struct door_shm_region *view, struct door_ioc_shm_view *arg)
{
	arg->disv_id = view->dr_id;
	arg->disv_token = view->dr_view_token;
	arg->disv_size = view->dr_size;
	arg->disv_addr = view->dr_consumer_addr;
	arg->disv_state = view->dr_view_state;
	arg->disv_segment_count = view->dr_view_count;
	arg->disv_segments_ptr = 0;
}

static int
door_shm_view_publish(struct door *door, struct door_ioc_shm_view *arg,
	const struct door_ioc_shm_view_segment *segments, struct thread *td)
{
	struct door_shm_region *view, *source;
	struct door_shm_view_part *parts;
	uint64_t size, total;
	unsigned int i, j, count;
	int error;

	count = arg->disv_segment_count;
	if (count == 0 || count > DOOR_SHM_VIEW_MAX_SEGMENTS ||
		arg->disv_id != 0 || arg->disv_token != 0)
		return (EINVAL);

	view = malloc(sizeof(*view), M_DOORFS, M_WAITOK | M_ZERO);
	parts = malloc(count * sizeof(*parts), M_DOORFS, M_WAITOK | M_ZERO);
	view->dr_creator_vm = vmspace_acquire_ref(td->td_proc);
	if (view->dr_creator_vm == NULL) {
		free(parts, M_DOORFS);
		free(view, M_DOORFS);
		return (ESRCH);
	}

	total = 0;
	error = 0;
	mtx_lock(&door->d_lock);
	if (door->d_revoked || door->d_next_shm_region == 0) {
		error = door->d_revoked ? EBADF : EOVERFLOW;
		goto fail;
	}

	for (i = 0; i < count; i++) {
		const struct door_ioc_shm_view_segment *segment = &segments[i];
		size = segment->disvs_size;
		if (size == 0 || (size & PAGE_MASK) != 0 ||
			(segment->disvs_offset & PAGE_MASK) != 0) {
			error = EINVAL;
			goto fail;
		}

		if (segment->disvs_uniquifier != door->d_uniquifier) {
			error = ESTALE;
			goto fail;
		}

		source = door_shm_find_locked(door, segment->disvs_region);
		if (source == NULL) {
			error = ENOENT;
			goto fail;
		}

		if (source->dr_view_parts != NULL || source->dr_consumer_vm != NULL ||
			source->dr_attach_pending != 0) {
			error = EBUSY;
			goto fail;
		}

		if (source->dr_creator_vm != td->td_proc->p_vmspace) {
			error = EPERM;
			goto fail;
		}

		if (segment->disvs_offset > source->dr_usable_size ||
			size > source->dr_usable_size - segment->disvs_offset ||
			size > SIZE_MAX - total) {
			error = EOVERFLOW;
			goto fail;
		}

		if (door_shm_view_overlap(door, source, segment->disvs_offset, size)) {
			error = EBUSY;
			goto fail;
		}

		for (j = 0; j < i; j++) {
			if (parts[j].source == source &&
				segment->disvs_offset < parts[j].offset + parts[j].size &&
				parts[j].offset < segment->disvs_offset + size) {
				error = EINVAL;
				goto fail;
			}
		}

		if ((source->dr_flags & DOOR_SHM_F_PAIR) != 0) {
			error = EBUSY;
			goto fail;
		}

		parts[i].source = source;
		parts[i].offset = segment->disvs_offset;
		parts[i].size = size;
		total += size;
	}

	if ((td->td_proc->p_sysent->sv_flags & SV_ILP32) != 0 && total > UINT32_MAX) {
		error = EOVERFLOW;
		goto fail;
	}

	if (door->d_shm_region_count >= door_max_shm_regions_per_door) {
		error = ENOSPC;
		goto fail;
	}

	if (total > door_max_shm_bytes_per_door) {
		error = ENOMEM;
		goto fail;
	}

	refcount_init(&view->dr_refs, 1);
	view->dr_view_parts = parts;
	view->dr_view_count = count;
	view->dr_view_state = DOOR_SHM_VIEW_PUBLISHED;
	view->dr_size = view->dr_usable_size = total;
	view->dr_view_creator_pid = td->td_proc->p_pid;

	do {
		arc4random_buf(&view->dr_view_token, sizeof(view->dr_view_token));
	} while (view->dr_view_token == 0);
	view->dr_id = door->d_next_shm_region++;

	for (i = 0; i < count; i++) {
		door_shm_region_hold(parts[i].source);
		parts[i].source->dr_view_loans++;
		parts[i].source->dr_view_used = true;
	}

	door_hold(door);
	view->dr_view_door = door;
	door->d_shm_region_count++;
	TAILQ_INSERT_TAIL(&door->d_shm_regions, view, dr_link);
#ifdef DOORFS_TEST
	door_test_object_add(DOOR_TEST_OBJ_SHM);
#endif
	door_shm_view_result(view, arg);
	mtx_unlock(&door->d_lock);
	return (0);

fail:
	mtx_unlock(&door->d_lock);
	vmspace_free(view->dr_creator_vm);
	free(parts, M_DOORFS);
	free(view, M_DOORFS);
	return (error);
}

static int
door_shm_view_map(struct door_shm_region *view, struct thread *td,
	struct vmspace **vmp, vm_offset_t *addrp)
{
	struct vmspace *vm;
	vm_offset_t addr, part_addr;
	struct door_shm_view_part *part;
	int error;

	if ((td->td_proc->p_sysent->sv_flags & SV_ILP32) != 0 &&
		view->dr_size > UINT32_MAX)
		return (EOVERFLOW);

	vm = vmspace_acquire_ref(td->td_proc);
	if (vm == NULL)
		return (ESRCH);

	addr = vm_map_min(&vm->vm_map);
	error = vm_map_find(&vm->vm_map, NULL, 0, &addr, view->dr_size, 0,
		VMFS_ANY_SPACE, VM_PROT_NONE, VM_PROT_NONE, 0);
	if (error != KERN_SUCCESS) {
		vmspace_free(vm);
		return (ENOMEM);
	}

	part_addr = addr;
	for (unsigned int i = 0; i < view->dr_view_count; i++) {
		part = &view->dr_view_parts[i];
		vm_object_reference(part->source->dr_object);
		error = vm_mmap_object(&vm->vm_map, &part_addr, part->size,
			VM_PROT_READ, VM_PROT_READ, MAP_SHARED | MAP_FIXED,
			part->source->dr_object, part->offset, FALSE, td);
		if (error != 0) {
			vm_object_deallocate(part->source->dr_object);
			goto fail;
		}

		/* A child must not keep a source alias after its parent's release. */
		error = vm_map_inherit(&vm->vm_map, part_addr,
			part_addr + part->size, VM_INHERIT_NONE);
		if (error != KERN_SUCCESS) {
			error = EINVAL;
			goto fail;
		}

		part_addr += part->size;
	}

	*vmp = vm;
	*addrp = addr;
	return (0);

fail:
	(void)vm_map_remove(&vm->vm_map, addr, addr + view->dr_size);
	vmspace_free(vm);
	return (error);
}

/* Caller has selected RELEASING under d_lock and owns a temporary view ref. */
static int
door_shm_view_finish_release(struct door *door, struct door_shm_region *view)
{
	struct door_shm_region *drop[DOOR_SHM_VIEW_MAX_SEGMENTS];
	struct vmspace *vm;
	unsigned int count;
	int error;

	vm = view->dr_consumer_vm;
	error = vm_map_remove(&vm->vm_map, view->dr_consumer_addr,
		view->dr_consumer_addr + view->dr_size);
	mtx_lock(&door->d_lock);
	if (error != KERN_SUCCESS) {
		view->dr_view_state = DOOR_SHM_VIEW_ATTACHED;
		mtx_unlock(&door->d_lock);
		return (EBUSY);
	}

	count = view->dr_view_count;
	for (unsigned int i = 0; i < count; i++) {
		drop[i] = view->dr_view_parts[i].source;
		door_shm_view_unloan_locked(door, drop[i]);
		view->dr_view_parts[i].source = NULL;
	}

	view->dr_consumer_vm = NULL;
	view->dr_consumer_addr = 0;
	view->dr_view_state = DOOR_SHM_VIEW_RELEASED;
	mtx_unlock(&door->d_lock);
	vmspace_free(vm);
	for (unsigned int i = 0; i < count; i++)
		door_shm_region_drop(drop[i]);

	return (0);
}

int
door_shm_view_op(struct door *door, struct door_ioc_shm_view *arg,
	const struct door_ioc_shm_view_segment *segments, unsigned int op,
	struct thread *td)
{
	struct door_shm_region *view;
	struct vmspace *vm;
	vm_offset_t addr;
	bool removed;
	int error;

	error = door_check_jail(door, td->td_ucred);
	if (error != 0)
		return (error);

	if (op == DOOR_SC_SHM_VIEW_PUBLISH)
		return (door_shm_view_publish(door, arg, segments, td));

	if (arg->disv_id == 0 || arg->disv_token == 0)
		return (EINVAL);

	removed = false;
	error = 0;
	if (op == DOOR_SC_SHM_VIEW_ATTACH) {
		/* Owner validation and acquisition of d_lock are one transaction.
		 * Never take door_list_lock from door_is_owner() under d_lock.
		 * Cleanup operations below retain their post-revoke permissions. */
		error = door_owner_lock(door, td->td_proc);
		if (error != 0)
			return (error);
	} else {
		mtx_lock(&door->d_lock);
	}
	view = door_shm_find_locked(door, arg->disv_id);
	if (view == NULL || view->dr_view_parts == NULL) {
		error = ENOENT;
		goto unlock;
	}

	if (view->dr_view_token != arg->disv_token) {
		error = ESTALE;
		goto unlock;
	}

	switch (op) {
	case DOOR_SC_SHM_VIEW_QUERY:
		if (view->dr_creator_vm != td->td_proc->p_vmspace &&
			view->dr_view_consumer_pid != td->td_proc->p_pid) {
			error = EPERM;
			goto unlock;
		}

		door_shm_view_result(view, arg);
		if (view->dr_consumer_vm != td->td_proc->p_vmspace)
			arg->disv_addr = 0;
		goto unlock;
	case DOOR_SC_SHM_VIEW_ATTACH:
		if (door->d_revoked) {
			error = EBADF;
			goto unlock;
		}

		if (view->dr_view_state != DOOR_SHM_VIEW_PUBLISHED) {
			error = EBUSY;
			goto unlock;
		}

		view->dr_view_state = DOOR_SHM_VIEW_MAPPING;
		view->dr_view_consumer_pid = td->td_proc->p_pid;
		door_shm_region_hold(view);
		mtx_unlock(&door->d_lock);
		error = door_shm_view_map(view, td, &vm, &addr);
		mtx_lock(&door->d_lock);
		if (error == 0) {
			view->dr_consumer_vm = vm;
			view->dr_consumer_addr = addr;
			view->dr_view_state = DOOR_SHM_VIEW_ATTACHED;
			door_shm_view_result(view, arg);
		} else {
			view->dr_view_state = DOOR_SHM_VIEW_PUBLISHED;
			view->dr_view_consumer_pid = 0;
			if (door->d_revoked) {
				door_shm_remove_locked(door, view);
				removed = true;
			}
		}

		/* Revoke during mapping is not a release: a successful attach stays live. */
		mtx_unlock(&door->d_lock);
		if (removed)
			door_shm_region_drop(view); /* list */
		door_shm_region_drop(view); /* operation */
		return (error);
	case DOOR_SC_SHM_VIEW_RELEASE:
		if (view->dr_view_consumer_pid != td->td_proc->p_pid ||
			(view->dr_consumer_vm != NULL &&
			view->dr_consumer_vm != td->td_proc->p_vmspace)) {
			error = EPERM;
			goto unlock;
		}

		if (view->dr_view_state == DOOR_SHM_VIEW_RELEASED) {
			door_shm_view_result(view, arg);
			goto unlock;
		}

		if (view->dr_view_state != DOOR_SHM_VIEW_ATTACHED) {
			error = EBUSY;
			goto unlock;
		}

		view->dr_view_state = DOOR_SHM_VIEW_RELEASING;
		door_shm_region_hold(view);
		mtx_unlock(&door->d_lock);
		error = door_shm_view_finish_release(door, view);
		mtx_lock(&door->d_lock);
		if (error == 0) {
			door_shm_view_result(view, arg);
			if (view->dr_view_creator_gone && !view->dr_dead) {
				door_shm_remove_locked(door, view);
				removed = true;
			}
		}

		mtx_unlock(&door->d_lock);
		if (removed)
			door_shm_region_drop(view); /* list */
		door_shm_region_drop(view); /* operation */
		return (error);
	case DOOR_SC_SHM_VIEW_DESTROY:
		if (view->dr_creator_vm != td->td_proc->p_vmspace) {
			error = EPERM;
			goto unlock;
		}

		if (view->dr_view_state != DOOR_SHM_VIEW_PUBLISHED &&
			view->dr_view_state != DOOR_SHM_VIEW_RELEASED) {
			error = EBUSY;
			goto unlock;
		}

		door_shm_remove_locked(door, view);
		removed = true;
		break;
	default:
		error = EINVAL;
	}

unlock:
	mtx_unlock(&door->d_lock);
	if (removed)
		door_shm_region_drop(view);
	return (error);
}

/* Called by core's late exit/exec event, after other readers have stopped. */
bool
door_shm_view_exit_pending(struct door *door, pid_t pid)
{
	struct door_shm_region *view;
	bool pending;

	pending = false;
	mtx_lock(&door->d_lock);
	TAILQ_FOREACH(view, &door->d_shm_regions, dr_link) {
		if ((view->dr_view_parts == NULL &&
			((view->dr_view_used && view->dr_creator_pid == pid) ||
			((view->dr_flags & DOOR_SHM_F_PAIR) != 0 &&
			(view->dr_creator_pid == pid || view->dr_pair_consumer_pid == pid)))) ||
			(view->dr_view_parts != NULL &&
			((!view->dr_view_creator_gone && view->dr_view_creator_pid == pid) ||
			view->dr_view_consumer_pid == pid))) {
			pending = true;
			break;
		}
	}

	mtx_unlock(&door->d_lock);
	return (pending);
}

void
door_shm_view_process_exit(struct door *door, pid_t pid)
{
	struct door_shm_region *view;
	bool remove, release;

	for (;;) {
		remove = release = false;
		mtx_lock(&door->d_lock);
		TAILQ_FOREACH(view, &door->d_shm_regions, dr_link) {
			if (view->dr_view_parts == NULL) {
				if ((view->dr_view_used && view->dr_creator_pid == pid) ||
					((view->dr_flags & DOOR_SHM_F_PAIR) != 0 &&
					(view->dr_creator_pid == pid || view->dr_pair_consumer_pid == pid))) {
					door_shm_remove_locked(door, view);
					remove = true;
					break;
				}

				continue;
			}

			if (view->dr_view_consumer_pid == pid) {
				if (view->dr_view_state == DOOR_SHM_VIEW_ATTACHED) {
					view->dr_view_state = DOOR_SHM_VIEW_RELEASING;
					release = true;
				}

				view->dr_view_consumer_pid = 0;
				break;
			}

			if (!view->dr_view_creator_gone && view->dr_view_creator_pid == pid) {
				view->dr_view_creator_gone = true;
				break;
			}
		}

		if (view == NULL) {
			mtx_unlock(&door->d_lock);
			return;
		}

		if (view->dr_view_parts != NULL && view->dr_view_creator_gone &&
			(view->dr_view_state == DOOR_SHM_VIEW_PUBLISHED ||
			view->dr_view_state == DOOR_SHM_VIEW_RELEASED)) {
			door_shm_remove_locked(door, view);
			remove = true;
		}

		door_shm_region_hold(view);
		mtx_unlock(&door->d_lock);
		if (release && door_shm_view_finish_release(door, view) == 0) {
			mtx_lock(&door->d_lock);
			if (view->dr_view_creator_gone && !view->dr_dead) {
				door_shm_remove_locked(door, view);
				remove = true;
			}

			mtx_unlock(&door->d_lock);
		}

		if (remove)
			door_shm_region_drop(view);
		door_shm_region_drop(view);
	}
}

/*
 * Shared sequence modification happens before WAKE takes d_lock. WAIT checks
 * that same wired VM-object word while holding d_lock, then atomically drops
 * d_lock in cv_wait. Thus a notification either changes the checked sequence
 * before registration or broadcasts after the waiter is registered.
 * Shared words never select an object, pointer, allocation, or CV in kernel.
 */
int
door_shm_pair_op(struct door *door, const struct door_ioc_shm_pair *arg,
	unsigned int op, struct thread *td)
{
	struct door_shm_region *r;
	volatile uint32_t *word;
	sbintime_t deadline;
	int error;

	if (arg->disp_version != DOOR_ABI_VERSION || arg->disp_reserved != 0 ||
		arg->disp_region == 0 || arg->disp_lane >= DOOR_SHM_PAIR_LANES ||
		(op != DOOR_SC_SHM_PAIR_WAIT && op != DOOR_SC_SHM_PAIR_WAKE) ||
		(arg->disp_timeout_ns != DOOR_SHM_PAIR_FOREVER &&
		arg->disp_timeout_ns > DOOR_SHM_PAIR_TIMEOUT_MAX_NS))
		return (EINVAL);

	if (op == DOOR_SC_SHM_PAIR_WAKE &&
		(arg->disp_expected != 0 || arg->disp_timeout_ns != 0))
		return (EINVAL);

	deadline = 0;
	if (arg->disp_timeout_ns != 0 &&
		arg->disp_timeout_ns != DOOR_SHM_PAIR_FOREVER)
		deadline = sbinuptime() + nstosbt(arg->disp_timeout_ns);

	mtx_lock(&door->d_lock);
	r = door_shm_find_locked(door, arg->disp_region);
	if (door->d_revoked || r == NULL) {
		error = door->d_revoked ? EBADF : ENOENT;
		mtx_unlock(&door->d_lock);
		return (error);
	}

	if ((r->dr_flags & DOOR_SHM_F_PAIR) == 0 || r->dr_pair_kva == 0) {
		mtx_unlock(&door->d_lock);
		return (EINVAL);
	}

	/* A held Door fd plus a guessed region id never grants peer access. */
	if (td->td_proc->p_vmspace != r->dr_creator_vm &&
		td->td_proc->p_vmspace != r->dr_consumer_vm) {
		mtx_unlock(&door->d_lock);
		return (EPERM);
	}

	if (op == DOOR_SC_SHM_PAIR_WAKE) {
		cv_broadcast(&r->dr_pair_cv[arg->disp_lane]);
		mtx_unlock(&door->d_lock);
		return (0);
	}

	door_shm_region_hold(r);
	word = (volatile uint32_t *)(r->dr_pair_kva +
		arg->disp_lane * DOOR_SHM_PAIR_STRIDE);
	error = 0;
	for (;;) {
		if (r->dr_dead || door->d_revoked) {
			error = door->d_revoked ? EBADF : ENOENT;
			break;
		}

		if (atomic_load_acq_32(word) != arg->disp_expected)
			break;

		if (arg->disp_timeout_ns == 0) {
			error = ETIMEDOUT;
			break;
		}

		if (arg->disp_timeout_ns == DOOR_SHM_PAIR_FOREVER)
			error = cv_wait_sig(&r->dr_pair_cv[arg->disp_lane], &door->d_lock);
		else
			error = cv_timedwait_sig_sbt(&r->dr_pair_cv[arg->disp_lane],
				&door->d_lock, deadline, 0, C_ABSOLUTE);

		if (error != 0) {
			if (r->dr_dead || door->d_revoked)
				error = door->d_revoked ? EBADF : ENOENT;
			else if (error == EWOULDBLOCK)
				error = atomic_load_acq_32(word) != arg->disp_expected ?
					0 : ETIMEDOUT;
			if (error == ERESTART)
				error = EINTR;
			break;
		}
	}

	mtx_unlock(&door->d_lock);
	door_shm_region_drop(r);
	return (error);
}
