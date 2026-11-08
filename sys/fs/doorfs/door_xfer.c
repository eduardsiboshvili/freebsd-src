/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>

#include <sys/door_impl.h>

struct door_reply_cache *
door_reply_cache_alloc(size_t capacity)
{
	struct door_reply_cache *cache;

	if (capacity > SIZE_MAX - sizeof(*cache))
		return (NULL);
	cache = malloc(sizeof(*cache) + capacity, M_DOORFS, M_WAITOK);
	refcount_init(&cache->drc_refs, 1);
	cache->drc_busy = 0;
	cache->drc_capacity = capacity;
	return (cache);
}

void
door_reply_cache_hold(struct door_reply_cache *cache)
{
	if (cache != NULL)
		refcount_acquire(&cache->drc_refs);
}

void
door_reply_cache_drop(struct door_reply_cache *cache)
{
	if (cache != NULL && refcount_release(&cache->drc_refs))
		free(cache, M_DOORFS);
}

/*
 * Fresh-transfer invariant:
 * request xfers live in freshly zeroed door_call objects and RETURN uses a
 * freshly zeroed local reply xfer.  BUFFER paths therefore write only fields
 * which actually become non-zero.  PAGES lives in a separate cold helper.
 */
static __inline void
door_xfer_set_buffer(struct door_xfer *xfer, void *buffer, size_t size,
    bool owned, struct door_reply_cache *cache)
{
	xfer->dx_size = size;
	xfer->dx_buffer = buffer;
	xfer->dx_buffer_owned = owned;
	xfer->dx_reply_cache = cache;
	xfer->dx_mode = DOOR_XFER_BUFFER;
}

static int
door_xfer_capture_pages(
    struct door_xfer *xfer, struct thread *td, uint64_t uptr, size_t size)
{
	vm_offset_t addr, base, end;
	int held, npages;
	vm_size_t span;

	if (size == 0) {
		xfer->dx_size = 0;
		xfer->dx_mode = DOOR_XFER_NONE;
		return (0);
	}
	if (uptr == 0)
		return (EINVAL);

	addr = (vm_offset_t)(uintptr_t)uptr;
	if (addr + size < addr)
		return (EOVERFLOW);
	base = trunc_page(addr);
	end = round_page(addr + size);
	if (end < base)
		return (EOVERFLOW);
	span = end - base;
	if (atop(span) > INT_MAX)
		return (E2BIG);
	npages = (int)atop(span);

	xfer->dx_pages =
	    mallocarray(npages, sizeof(vm_page_t), M_DOORFS, M_WAITOK);
	held = vm_fault_quick_hold_pages(&td->td_proc->p_vmspace->vm_map, addr,
	    size, VM_PROT_READ, xfer->dx_pages, npages);
	if (held != npages) {
		if (held > 0)
			vm_page_unhold_pages(xfer->dx_pages, held);
		free(xfer->dx_pages, M_DOORFS);
		xfer->dx_pages = NULL;
		xfer->dx_size = 0;
		return (EFAULT);
	}

	xfer->dx_size = size;
	xfer->dx_npages = npages;
	xfer->dx_page_offset = addr - base;
	xfer->dx_mode = DOOR_XFER_PAGES;
	return (0);
}

static int
door_xfer_capture_buffer_alloc(
    struct door_xfer *xfer, uint64_t uptr, size_t size)
{
	uint8_t *buffer;

	if (size == 0) {
		xfer->dx_size = 0;
		xfer->dx_mode = DOOR_XFER_NONE;
		return (0);
	}
	if (uptr == 0)
		return (EINVAL);

	buffer = malloc(size, M_DOORFS, M_WAITOK);
	if (copyin((const void *)(uintptr_t)uptr, buffer, size) != 0) {
		free(buffer, M_DOORFS);
		return (EFAULT);
	}

	door_xfer_set_buffer(xfer, buffer, size, true, NULL);
	return (0);
}

int
door_xfer_capture_request(
    struct door_xfer *xfer, struct thread *td, uint64_t uptr, size_t size)
{
	int error;

	if (__predict_true(size < DOOR_REQUEST_PAGE_THRESHOLD))
		error = door_xfer_capture_buffer_alloc(xfer, uptr, size);
	else
		error = door_xfer_capture_pages(xfer, td, uptr, size);

	return (error);
}

int
door_xfer_capture_request_snapshot(
    struct door_xfer *xfer, struct thread *td, uint64_t uptr, size_t size)
{
	int error;

	(void)td;
	/*
	 * ONEWAY must detach request lifetime from caller userspace before the
	 * syscall returns.  Never use held pages here: the caller is free to
	 * modify or unmap its buffer immediately after the asynchronous submit.
	 */
	error = door_xfer_capture_buffer_alloc(xfer, uptr, size);
	return (error);
}

int
door_xfer_capture_reply(
    struct door_xfer *xfer, struct thread *td, uint64_t uptr, size_t size)
{
	int error;

	if (__predict_true(size < DOOR_REPLY_PAGE_THRESHOLD))
		error = door_xfer_capture_buffer_alloc(xfer, uptr, size);
	else
		error = door_xfer_capture_pages(xfer, td, uptr, size);

	return (error);
}

int
door_xfer_capture_request_prealloc(struct door_xfer *xfer, struct thread *td,
    uint64_t uptr, size_t size, void *storage, size_t storage_capacity)
{
	int error;

	if (__predict_false(size >= DOOR_REQUEST_PAGE_THRESHOLD ||
			    size > storage_capacity ||
			    (size != 0 && storage == NULL)))
		return (door_xfer_capture_request(xfer, td, uptr, size));

	if (size == 0) {
		xfer->dx_size = 0;
		xfer->dx_mode = DOOR_XFER_NONE;
		return (0);
	}
	if (__predict_false(uptr == 0))
		return (EINVAL);

	error = copyin((const void *)(uintptr_t)uptr, storage, size);
	if (__predict_false(error != 0))
		return (EFAULT);

	door_xfer_set_buffer(xfer, storage, size, false, NULL);
	return (0);
}

int
door_xfer_capture_reply_cached(struct door_xfer *xfer, struct thread *td,
    uint64_t uptr, size_t size, struct door_reply_cache *cache)
{
	bool eligible;

	eligible = size != 0 && size < DOOR_REPLY_PAGE_THRESHOLD &&
		   cache != NULL && size <= cache->drc_capacity;

	if (!eligible) {
		return (door_xfer_capture_reply(xfer, td, uptr, size));
	}

	if (!atomic_cmpset_acq_int(&cache->drc_busy, 0, 1)) {
		return (door_xfer_capture_reply(xfer, td, uptr, size));
	}

	/*
	 * The caller holds a temporary lookup reference while this function
	 * runs.  Take a distinct xfer reference before publishing the cache
	 * pointer into the transfer object.
	 */
	door_reply_cache_hold(cache);

	if (__predict_false(uptr == 0 || copyin((const void *)(uintptr_t)uptr,
					     cache->drc_data, size) != 0)) {
		atomic_store_rel_int(&cache->drc_busy, 0);
		door_reply_cache_drop(cache);
		return (uptr == 0 ? EINVAL : EFAULT);
	}

	door_xfer_set_buffer(xfer, cache->drc_data, size, false, cache);
	return (0);
}

int
door_xfer_copyout(struct door_xfer *xfer, struct thread *td, uint64_t uptr)
{
	struct iovec iov;
	struct uio uio;

	if (__predict_false(xfer->dx_size == 0))
		return (0);
	if (__predict_false(uptr == 0))
		return (EINVAL);
	if (__predict_true(xfer->dx_mode == DOOR_XFER_BUFFER))
		return (copyout(
		    xfer->dx_buffer, (void *)(uintptr_t)uptr, xfer->dx_size));
	if (__predict_false(xfer->dx_mode != DOOR_XFER_PAGES))
		return (EINVAL);

	iov.iov_base = (void *)(uintptr_t)uptr;
	iov.iov_len = xfer->dx_size;
	uio = (struct uio){
	    .uio_iov = &iov,
	    .uio_iovcnt = 1,
	    .uio_offset = 0,
	    .uio_resid = xfer->dx_size,
	    .uio_segflg = UIO_USERSPACE,
	    .uio_rw = UIO_READ,
	    .uio_td = td,
	};
	return (uiomove_fromphys(
	    xfer->dx_pages, xfer->dx_page_offset, xfer->dx_size, &uio));
}

void
door_xfer_destroy(struct door_xfer *xfer)
{
	struct door_reply_cache *cache;

	cache = xfer->dx_reply_cache;

	if (__predict_true(
		xfer->dx_mode == DOOR_XFER_BUFFER && xfer->dx_buffer != NULL)) {
		if (cache != NULL) {
			/*
			 * The cache cannot be claimed by a subsequent reply until the
			 * previous client is completely done consuming this xfer.
			 */
			atomic_store_rel_int(&cache->drc_busy, 0);
			door_reply_cache_drop(cache);
		} else if (xfer->dx_buffer_owned) {
			free(xfer->dx_buffer, M_DOORFS);
		}
	}

	if (__predict_false(
		xfer->dx_mode == DOOR_XFER_PAGES && xfer->dx_pages != NULL)) {
		vm_page_unhold_pages(xfer->dx_pages, xfer->dx_npages);
		free(xfer->dx_pages, M_DOORFS);
	}

	xfer->dx_mode = DOOR_XFER_NONE;
	xfer->dx_size = 0;
	xfer->dx_buffer = NULL;
	xfer->dx_pages = NULL;
	xfer->dx_npages = 0;
	xfer->dx_page_offset = 0;
	xfer->dx_buffer_owned = false;
	xfer->dx_reply_cache = NULL;
}
