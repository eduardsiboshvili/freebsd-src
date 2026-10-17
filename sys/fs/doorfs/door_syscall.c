/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "opt_doorfs.h"

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/limits.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/door_core.h>
#ifdef COMPAT_FREEBSD32
#include <compat/freebsd32/freebsd32_proto.h>
#endif

#ifdef DOORFS
#include <sys/door_impl.h>
#include <sys/door_compat.h>

static const cap_rights_t door_call_rights =
    CAP_RIGHTS_INITIALIZER(CAP_DOOR_CALL);
static const cap_rights_t door_service_rights =
    CAP_RIGHTS_INITIALIZER(CAP_DOOR_SERVICE);
static const cap_rights_t door_admin_rights =
    CAP_RIGHTS_INITIALIZER(CAP_DOOR_ADMIN);
static const cap_rights_t door_info_rights =
    CAP_RIGHTS_INITIALIZER(CAP_DOOR_INFO);
static const cap_rights_t door_shm_rights =
    CAP_RIGHTS_INITIALIZER(CAP_DOOR_SHM);
static const cap_rights_t door_call_shm_rights =
    CAP_RIGHTS_INITIALIZER(CAP_DOOR_CALL | CAP_DOOR_SHM);

/* SIZE_MAX is the kernel data model, not the caller's data model. */
static __inline bool
door_sys_ilp32(struct thread *td)
{
    return ((td->td_proc->p_sysent->sv_flags & SV_ILP32) != 0);
}

static int
door_sys_range(struct thread *td, uint64_t ptr, uint64_t size)
{
    if (!door_sys_ilp32(td))
        return (0);
    return (door_compat_range(ptr, size,
        vm_map_max(&td->td_proc->p_vmspace->vm_map)));
}

static int
door_sys_copyin(struct thread *td, const void *user, void *data, size_t size)
{
    int error;

    error = door_sys_range(td, (uintptr_t)user, size);
    if (error != 0)
        return (error);
    return (copyin(user, data, size));
}

static int
door_sys_copyout(struct thread *td, const void *data, void *user, size_t size)
{
    int error;

    error = door_sys_range(td, (uintptr_t)user, size);
    if (error != 0)
        return (error);
    return (copyout(data, user, size));
}

static int
door_sys_check_call(struct thread *td, const struct door_ioc_call *arg)
{
    int error;

    error = door_sys_range(td, arg->dic_request_ptr, arg->dic_request_size);
    if (error == 0)
        error = door_sys_range(td, arg->dic_reply_ptr, arg->dic_reply_size);
    if (error == 0)
        error = door_sys_range(td, arg->dic_send_desc_ptr,
            (uint64_t)arg->dic_send_desc_count * sizeof(struct door_kdesc));
    if (error == 0)
        error = door_sys_range(td, arg->dic_recv_desc_ptr,
            (uint64_t)arg->dic_recv_desc_count * sizeof(struct door_kdesc));
    return (error);
}

static int
door_sys_check_return(struct thread *td, const struct door_ioc_return *arg)
{
    int error;

    error = door_sys_range(td, arg->dir_reply_ptr, arg->dir_reply_size);
    if (error == 0)
        error = door_sys_range(td, arg->dir_request_ptr, arg->dir_request_size);
    if (error == 0)
        error = door_sys_range(td, arg->dir_reply_desc_ptr,
            (uint64_t)arg->dir_reply_desc_count * sizeof(struct door_kdesc));
    if (error == 0)
        error = door_sys_range(td, arg->dir_request_desc_ptr,
            (uint64_t)arg->dir_request_desc_count * sizeof(struct door_kdesc));
    return (error);
}

static int
door_sys_decode_fd(long value, int *fdp)
{
	if (value < INT_MIN || value > INT_MAX)
		return (EINVAL);
	*fdp = (int)value;
	return (0);
}

static int
door_sys_enter(struct thread *td, int fd, const cap_rights_t *rights,
    bool vfork_safe, int deferstop, struct file **fpp, struct door **doorp,
    int *stop_prevp)
{
	struct proc *p;
	bool vfork_child;
	int error;

	error = door_file_get_ref(td, fd, rights, fpp, doorp);

	if (error != 0) {
		return (error);
	}
	*stop_prevp = sigdeferstop_impl(deferstop);

	if (!vfork_safe) {
		p = td->td_proc;
		vfork_child = false;
		if (__predict_false((p->p_flag & P_PPWAIT) != 0)) {
			PROC_LOCK(p);
			vfork_child = (p->p_flag & P_PPWAIT) != 0;
			PROC_UNLOCK(p);
		}
		if (__predict_false(vfork_child)) {
			if (*stop_prevp != SIGDEFERSTOP_VAL_NCHG)
				sigallowstop_impl(*stop_prevp);
			fdrop(*fpp, td);
			return (EBUSY);
		}
	}

	return (0);
}

static void
door_sys_leave(struct thread *td, struct file *fp, int stop_prev)
{
	if (stop_prev != SIGDEFERSTOP_VAL_NCHG)
		sigallowstop_impl(stop_prev);

	fdrop(fp, td);
}

static int
door_sys_call_scalar_direct(struct thread *td, int fd, uint64_t request_ptr,
    size_t request_size, uint64_t reply_ptr, size_t reply_capacity,
    uint64_t recv_desc_ptr, bool auto_map, uint64_t *reply_result_ptr,
    uint32_t *call_flagsp, uint64_t *packedp)
{
	struct door *door;
	struct file *fp;
	uint64_t packed;
	int error, stop_prev;

	packed = 0;
	error = door_sys_enter(td, fd, &door_call_rights, false,
	    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error != 0)
		return (error);
	error = door_call_scalar(door, td, request_ptr, request_size, reply_ptr,
	    reply_capacity, recv_desc_ptr, auto_map, reply_result_ptr,
	    call_flagsp, &packed);
	door_sys_leave(td, fp, stop_prev);
	if (error == 0)
		*packedp = packed;
	return (error);
}

/* RETURN is authorized by the current thread's live server binding. */
static int
door_sys_return_bound(
    struct thread *td, struct door_ioc_return_shm *ret, uint64_t *fast_result)
{
	struct door_server_binding *ds;
	struct door *door;
	int error, stop_prev;

	ds = td->td_door_server;
	if (__predict_false(ds == NULL || ds->ds_td != td || !ds->ds_linked ||
			    !ds->ds_door_ref || ds->ds_door == NULL))
		return (EINVAL);
	door = ds->ds_door;
	stop_prev = sigdeferstop_impl(SIGDEFERSTOP_EINTR);
	error = door_return_bound_direct(door, td, ds, ret, fast_result);
	if (stop_prev != SIGDEFERSTOP_VAL_NCHG)
		sigallowstop_impl(stop_prev);
	return (error);
}

static int
door_sys_create(struct thread *td, unsigned long value, unsigned long cookie,
    unsigned long flags)
{
	struct door *door;
	int error, fd;

	if (value > UINT32_MAX || flags > UINT32_MAX)
		return (EINVAL);
	error = door_alloc(
	    td->td_proc, cookie, (uint32_t)value, (uint32_t)flags, &door);
	if (error != 0)
		return (error);

	error = door_file_install(td, door, &fd);
	if (error != 0) {
		(void)door_revoke(door);
		door_owner_remove(door);
		door_drop(door);
		return (error);
	}

	door_drop(door);
	td->td_retval[0] = fd;
	return (0);
}

static int
door_sys_call(struct thread *td, long value, unsigned long arg)
{
	struct door_ioc_call call;
	struct door *door;
	struct file *fp;
	void *uptr;
	int error, fd, stop_prev;

	if (arg == 0)
		return (EINVAL);
	error = door_sys_decode_fd(value, &fd);
	if (error != 0)
		return (error);
	uptr = (void *)(uintptr_t)arg;
	error = door_sys_copyin(td, uptr, &call, sizeof(call));
	if (error != 0)
		return (error);
	error = door_sys_check_call(td, &call);
	if (error != 0)
		return (error);
	error = door_sys_enter(td, fd, &door_call_rights, false,
	    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error == 0) {
		error = door_call_full(door, &call, td);
		door_sys_leave(td, fp, stop_prev);
	}
	if (error == 0) {
		error = door_sys_copyout(td, &call, uptr, sizeof(call));
		if (error != 0 &&
		    (call.dic_flags & DOOR_CALL_F_AUTO_MAP) != 0)
			(void)kern_munmap(td, (vm_offset_t)call.dic_reply_ptr,
			    round_page((vm_size_t)call.dic_reply_size));
	}
	return (error);
}

static int
door_sys_return(struct thread *td, unsigned long arg)
{
	struct door_ioc_return_shm ret;
	void *uptr;
	int error;

	if (arg == 0)
		return (EINVAL);
	uptr = (void *)(uintptr_t)arg;
	error = door_sys_copyin(td, uptr, &ret, sizeof(ret));
	if (error != 0)
		return (error);
	error = door_sys_check_return(td, &ret.dirs_return);
	if (error != 0)
		return (error);
	error = door_sys_return_bound(td, &ret, NULL);
	if (error == 0)
		error = door_sys_copyout(td, &ret, uptr, sizeof(ret));
	return (error);
}

static int
door_sys_fast_call(struct thread *td, long value, unsigned long request_ptr,
    unsigned long request_size, unsigned long reply_ptr, unsigned long io_ptr)
{
	struct door_sys_fast_call_io io;
	uint64_t packed;
	int error, fd;

#if ULONG_MAX < UINT64_MAX
	return (ENOSYS);
#endif
	if (request_size > SIZE_MAX || io_ptr == 0 ||
	    (request_size != 0 && request_ptr == 0))
		return (EINVAL);
	error = door_sys_decode_fd(value, &fd);
	if (error != 0)
		return (error);
	error = door_sys_copyin(td, (void *)(uintptr_t)io_ptr, &io, sizeof(io));
	if (error != 0)
		return (error);
	if (io.dsfci_reply_capacity > SIZE_MAX ||
	    (io.dsfci_reply_capacity != 0 && reply_ptr == 0) ||
	    io.dsfci_recv_desc_ptr == 0)
		return (EINVAL);
	error = door_sys_call_scalar_direct(td, fd, request_ptr,
	    (size_t)request_size, reply_ptr, (size_t)io.dsfci_reply_capacity,
	    io.dsfci_recv_desc_ptr, false, NULL, NULL, &packed);
	if (error != 0)
		return (error);
	td->td_retval[0] = (register_t)packed;
	return (0);
}

static int
door_sys_empty_call(struct thread *td, long value, unsigned long reply_ptr,
    unsigned long reply_capacity, unsigned long recv_desc_ptr)
{
	uint64_t packed;
	int error, fd;

#if ULONG_MAX < UINT64_MAX
	return (ENOSYS);
#endif
	if (reply_capacity > SIZE_MAX ||
	    (reply_capacity != 0 && reply_ptr == 0) || recv_desc_ptr == 0)
		return (EINVAL);
	error = door_sys_decode_fd(value, &fd);
	if (error != 0)
		return (error);
	error = door_sys_call_scalar_direct(td, fd, 0, 0, reply_ptr,
	    (size_t)reply_capacity, recv_desc_ptr, false, NULL, NULL, &packed);
	if (error != 0)
		return (error);
	td->td_retval[0] = (register_t)packed;
	return (0);
}

static int
door_sys_fast_call_mapped(struct thread *td, long value,
    unsigned long request_ptr, unsigned long request_size,
    unsigned long reply_ptr, unsigned long io_ptr)
{
	struct door_sys_fast_call_mapped_io io;
	uint64_t packed, result_ptr;
	uint32_t call_flags;
	int error, fd;

#if ULONG_MAX < UINT64_MAX
	return (ENOSYS);
#endif
	if (request_size > SIZE_MAX || io_ptr == 0 ||
	    (request_size != 0 && request_ptr == 0))
		return (EINVAL);
	error = door_sys_decode_fd(value, &fd);
	if (error != 0)
		return (error);
	error = door_sys_copyin(td, (void *)(uintptr_t)io_ptr, &io, sizeof(io));
	if (error != 0)
		return (error);
	if (io.dsfcmi_version != DOOR_ABI_VERSION ||
	    io.dsfcmi_reply_capacity > SIZE_MAX ||
	    (io.dsfcmi_reply_capacity != 0 && reply_ptr == 0) ||
	    io.dsfcmi_recv_desc_ptr == 0)
		return (EINVAL);

	result_ptr = reply_ptr;
	call_flags = 0;
	error = door_sys_call_scalar_direct(td, fd, request_ptr,
	    (size_t)request_size, reply_ptr,
	    (size_t)io.dsfcmi_reply_capacity, io.dsfcmi_recv_desc_ptr, true,
	    &result_ptr, &call_flags, &packed);
	if (error != 0)
		return (error);
	io.dsfcmi_flags = call_flags;
	io.dsfcmi_reply_ptr = result_ptr;
	error = door_sys_copyout(td, &io, (void *)(uintptr_t)io_ptr, sizeof(io));
	if (error != 0) {
		if ((call_flags & DOOR_CALL_F_AUTO_MAP) != 0)
			(void)kern_munmap(td, (vm_offset_t)result_ptr,
			    round_page((vm_size_t)(packed &
			    DOOR_FAST_CALL_REPLY_MASK)));
		return (error);
	}
	td->td_retval[0] = (register_t)packed;
	return (0);
}

static int
door_sys_empty_call_mapped(struct thread *td, long value,
    unsigned long reply_ptr, unsigned long reply_capacity,
    unsigned long recv_desc_ptr, unsigned long io_ptr)
{
	struct door_sys_fast_call_mapped_io io;
	uint64_t packed, result_ptr;
	uint32_t call_flags;
	int error, fd;

#if ULONG_MAX < UINT64_MAX
	return (ENOSYS);
#endif
	if (reply_capacity > SIZE_MAX || io_ptr == 0 ||
	    (reply_capacity != 0 && reply_ptr == 0) || recv_desc_ptr == 0)
		return (EINVAL);
	error = door_sys_decode_fd(value, &fd);
	if (error != 0)
		return (error);
	error = door_sys_copyin(td, (void *)(uintptr_t)io_ptr, &io, sizeof(io));
	if (error != 0)
		return (error);
	if (io.dsfcmi_version != DOOR_ABI_VERSION ||
	    io.dsfcmi_reply_capacity != reply_capacity ||
	    io.dsfcmi_recv_desc_ptr != recv_desc_ptr)
		return (EINVAL);

	result_ptr = reply_ptr;
	call_flags = 0;
	error = door_sys_call_scalar_direct(td, fd, 0, 0, reply_ptr,
	    (size_t)reply_capacity, recv_desc_ptr, true, &result_ptr,
	    &call_flags, &packed);
	if (error != 0)
		return (error);
	io.dsfcmi_flags = call_flags;
	io.dsfcmi_reply_ptr = result_ptr;
	error = door_sys_copyout(td, &io, (void *)(uintptr_t)io_ptr, sizeof(io));
	if (error != 0) {
		if ((call_flags & DOOR_CALL_F_AUTO_MAP) != 0)
			(void)kern_munmap(td, (vm_offset_t)result_ptr,
			    round_page((vm_size_t)(packed &
			    DOOR_FAST_CALL_REPLY_MASK)));
		return (error);
	}
	td->td_retval[0] = (register_t)packed;
	return (0);
}

static int
door_sys_fast_return(struct thread *td, unsigned long call_id,
    unsigned long reply_ptr, unsigned long reply_size,
    unsigned long request_ptr, unsigned long io_ptr)
{
	struct door_sys_fast_return_io io;
	struct door_sys_fast_return_out out;
	struct door_ioc_return_shm ret;
	uint64_t fast_result;
	int error;

#if ULONG_MAX < UINT64_MAX
	return (ENOSYS);
#endif
	if (io_ptr == 0 || reply_size > SIZE_MAX ||
	    (reply_size != 0 && reply_ptr == 0))
		return (EINVAL);
	error = door_sys_copyin(td, (void *)(uintptr_t)io_ptr, &io, sizeof(io));
	if (error != 0)
		return (error);
	if (io.dsfri_request_capacity > SIZE_MAX ||
	    (io.dsfri_request_capacity != 0 && request_ptr == 0) ||
	    io.dsfri_out_ptr == 0)
		return (EINVAL);

	bzero(&ret, sizeof(ret));
	fast_result = 0;
	ret.dirs_return.dir_flags =
	    DOOR_RETURN_F_RESIZABLE | DOOR_RETURN_F_CRED_LAZY;
	ret.dirs_return.dir_call_id = call_id;
	ret.dirs_return.dir_reply_ptr = reply_ptr;
	ret.dirs_return.dir_reply_size = (size_t)reply_size;
	ret.dirs_return.dir_request_ptr = request_ptr;
	ret.dirs_return.dir_request_size = (size_t)io.dsfri_request_capacity;
	ret.dirs_return.dir_reply_fd = -1;
	ret.dirs_return.dir_request_fd = -1;
	ret.dirs_return.dir_request_desc_ptr = 1;

	error = door_sys_return_bound(td, &ret, &fast_result);
	if (error != 0)
		return (error);
	if (__predict_true(fast_result != 0)) {
		td->td_retval[0] = (register_t)fast_result;
		return (0);
	}

	bzero(&out, sizeof(out));
	out.dsfro_call_id = ret.dirs_return.dir_call_id;
	out.dsfro_request_size = ret.dirs_return.dir_request_size;
	out.dsfro_request_desc_count = ret.dirs_return.dir_request_desc_count;
	out.dsfro_flags = ret.dirs_return.dir_flags | DOOR_RETURN_F_CRED_LAZY;
	if ((ret.dirs_return.dir_flags & DOOR_RETURN_F_SHM) != 0) {
		out.dsfro_shm = ret.dirs_shm;
		out.dsfro_shm_ptr = ret.dirs_shm_ptr;
	}
	return (
	    door_sys_copyout(td, &out, (void *)(uintptr_t)io.dsfri_out_ptr, sizeof(out)));
}

static int
door_sys_empty_return(struct thread *td, unsigned long call_id,
    unsigned long request_ptr, unsigned long request_capacity,
    unsigned long out_ptr)
{
	struct door_sys_fast_return_out out;
	struct door_ioc_return_shm ret;
	uint64_t fast_result;
	int error;

#if ULONG_MAX < UINT64_MAX
	return (ENOSYS);
#endif
	if (request_capacity > SIZE_MAX || out_ptr == 0 ||
	    (request_capacity != 0 && request_ptr == 0))
		return (EINVAL);
	fast_result = 0;
	ret.dirs_return.dir_flags =
	    DOOR_RETURN_F_RESIZABLE | DOOR_RETURN_F_CRED_LAZY;
	ret.dirs_return.dir_call_id = call_id;
	ret.dirs_return.dir_reply_ptr = 0;
	ret.dirs_return.dir_reply_size = 0;
	ret.dirs_return.dir_request_ptr = request_ptr;
	ret.dirs_return.dir_request_size = (size_t)request_capacity;
	ret.dirs_return.dir_reply_fd = -1;
	ret.dirs_return.dir_reply_desc_count = 0;
	ret.dirs_return.dir_request_fd = -1;
	ret.dirs_return.dir_request_desc_ptr = 1;
	ret.dirs_return.dir_request_desc_count = 0;

	error = door_sys_return_bound(td, &ret, &fast_result);
	if (error != 0)
		return (error);
	if (__predict_true(fast_result != 0)) {
		td->td_retval[0] = (register_t)fast_result;
		return (0);
	}

	bzero(&out, sizeof(out));
	out.dsfro_call_id = ret.dirs_return.dir_call_id;
	out.dsfro_request_size = ret.dirs_return.dir_request_size;
	out.dsfro_request_desc_count = ret.dirs_return.dir_request_desc_count;
	out.dsfro_flags = ret.dirs_return.dir_flags | DOOR_RETURN_F_CRED_LAZY;
	if ((ret.dirs_return.dir_flags & DOOR_RETURN_F_SHM) != 0) {
		out.dsfro_shm = ret.dirs_shm;
		out.dsfro_shm_ptr = ret.dirs_shm_ptr;
	}
	return (door_sys_copyout(td, &out, (void *)(uintptr_t)out_ptr, sizeof(out)));
}

static int
door_sys_revoke(struct thread *td, long fd)
{
	struct door *door;
	struct file *fp;
	int decoded, error, stop_prev;

	error = door_sys_decode_fd(fd, &decoded);
	if (error != 0)
		return (error);
	error = door_sys_enter(td, decoded, &door_admin_rights, false,
	    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error != 0)
		return (error);
	if (!door_is_owner(door, td->td_proc))
		error = EPERM;
	else
		error = door_revoke(door);
	door_sys_leave(td, fp, stop_prev);
	return (error);
}

static int
door_sys_bind(struct thread *td, long fd)
{
	struct door *door;
	struct file *fp;
	int decoded, error, stop_prev;

	error = door_sys_decode_fd(fd, &decoded);
	if (error != 0)
		return (error);
	error = door_sys_enter(td, decoded, &door_service_rights, false,
	    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error != 0)
		return (error);
	error = door_server_bind(door, td);
	door_sys_leave(td, fp, stop_prev);
	return (error);
}

static int
door_sys_info(struct thread *td, long fd, unsigned long uptr)
{
	struct door_ioc_info arg;
	struct door *door;
	struct file *fp;
	int decoded, error, stop_prev;

	if (uptr == 0)
		return (EINVAL);
	error = door_sys_decode_fd(fd, &decoded);
	if (error != 0)
		return (error);
	error = door_sys_enter(td, decoded, &door_info_rights, true,
	    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error == 0) {
		error = door_info(door, &arg, td);
		door_sys_leave(td, fp, stop_prev);
	}
	if (error == 0)
		error = door_sys_copyout(td, &arg, (void *)(uintptr_t)uptr, sizeof(arg));
	return (error);
}

static int
door_sys_param(struct thread *td, long fd, unsigned long uptr, bool set)
{
	struct door_ioc_param arg;
	struct door *door;
	struct file *fp;
	int decoded, error, stop_prev;

	if (uptr == 0)
		return (EINVAL);
	error = door_sys_decode_fd(fd, &decoded);
	if (error != 0)
		return (error);
	error = door_sys_copyin(td, (void *)(uintptr_t)uptr, &arg, sizeof(arg));
	if (error != 0)
		return (error);
	error = door_sys_enter(td, decoded,
	    set ? &door_admin_rights : &door_info_rights, !set,
	    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error == 0) {
		error = set ? door_setparam(door, &arg, td)
			    : door_getparam(door, &arg);
		door_sys_leave(td, fp, stop_prev);
	}
	if (error == 0 && !set)
		error = door_sys_copyout(td, &arg, (void *)(uintptr_t)uptr, sizeof(arg));
	return (error);
}

static int
door_sys_cancel(struct thread *td, long fd, unsigned long uptr)
{
	struct door_ioc_cancel arg;
	struct door *door;
	struct file *fp;
	int decoded, error, stop_prev;

	if (uptr == 0)
		return (EINVAL);
	error = door_sys_decode_fd(fd, &decoded);
	if (error != 0)
		return (error);
	error = door_sys_copyin(td, (void *)(uintptr_t)uptr, &arg, sizeof(arg));
	if (error == 0)
		error = door_sys_enter(td, decoded, &door_call_rights, false,
		    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error == 0) {
		error = door_cancel(door, &arg, td);
		door_sys_leave(td, fp, stop_prev);
	}
	return (error);
}

static int
door_sys_cred(struct thread *td, unsigned long uptr)
{
	struct door_ioc_cred arg;
	int error;

	if (uptr == 0)
		return (EINVAL);
	error = door_sys_copyin(td, (void *)(uintptr_t)uptr, &arg, sizeof(arg));
	if (error == 0)
		error = door_server_cred_bound(td, &arg);
	if (error == 0)
		error = door_sys_copyout(td, &arg, (void *)(uintptr_t)uptr, sizeof(arg));
	return (error);
}

static int
door_sys_shm_create(struct thread *td, long fd, unsigned long uptr)
{
	struct door_ioc_shm_create arg;
	struct door *door;
	struct file *fp;
	int decoded, error, stop_prev;

	if (uptr == 0)
		return (EINVAL);
	error = door_sys_decode_fd(fd, &decoded);
	if (error != 0)
		return (error);
	error = door_sys_copyin(td, (void *)(uintptr_t)uptr, &arg, sizeof(arg));
	if (error == 0)
		error = door_sys_enter(td, decoded, &door_shm_rights, false,
		    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error == 0) {
		error = door_shm_create(door, &arg, td);
		door_sys_leave(td, fp, stop_prev);
	}
	if (error == 0)
		error = door_sys_copyout(td, &arg, (void *)(uintptr_t)uptr, sizeof(arg));
	return (error);
}

static int
door_sys_shm_attach(struct thread *td, long fd, unsigned long uptr)
{
	struct door_ioc_shm_attach arg;
	struct door *door;
	struct file *fp;
	int decoded, error, stop_prev;

	if (uptr == 0)
		return (EINVAL);
	error = door_sys_decode_fd(fd, &decoded);
	if (error != 0)
		return (error);
	error = door_sys_copyin(td, (void *)(uintptr_t)uptr, &arg, sizeof(arg));
	if (error == 0)
		error = door_sys_enter(td, decoded, &door_shm_rights, false,
		    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error == 0) {
		error = door_shm_attach(door, &arg, td);
		door_sys_leave(td, fp, stop_prev);
	}
	if (error == 0)
		error = door_sys_copyout(td, &arg, (void *)(uintptr_t)uptr, sizeof(arg));
	return (error);
}

static int
door_sys_shm_destroy(struct thread *td, long fd, unsigned long uptr)
{
	struct door_ioc_shm_destroy arg;
	struct door *door;
	struct file *fp;
	int decoded, error, stop_prev;

	if (uptr == 0)
		return (EINVAL);
	error = door_sys_decode_fd(fd, &decoded);
	if (error != 0)
		return (error);
	error = door_sys_copyin(td, (void *)(uintptr_t)uptr, &arg, sizeof(arg));
	if (error == 0)
		error = door_sys_enter(td, decoded, &door_shm_rights, false,
		    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error == 0) {
		error = door_shm_destroy_handle(door, &arg, td);
		door_sys_leave(td, fp, stop_prev);
	}
	return (error);
}

static int
door_sys_call_shm(struct thread *td, long fd, unsigned long uptr)
{
	struct door_ioc_call_shm arg;
	struct door *door;
	struct file *fp;
	int decoded, error, stop_prev;

	if (uptr == 0)
		return (EINVAL);
	error = door_sys_decode_fd(fd, &decoded);
	if (error != 0)
		return (error);
	error = door_sys_copyin(td, (void *)(uintptr_t)uptr, &arg, sizeof(arg));
	if (error == 0)
		error = door_sys_check_call(td, &arg.dics_call);
	if (error == 0)
		error = door_sys_enter(td, decoded, &door_call_shm_rights, false,
		    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error == 0) {
		error = door_call_shm(door, &arg, td);
		door_sys_leave(td, fp, stop_prev);
	}
	if (error == 0) {
		error = door_sys_copyout(td, &arg, (void *)(uintptr_t)uptr, sizeof(arg));
		if (error != 0 &&
		    (arg.dics_call.dic_flags & DOOR_CALL_F_AUTO_MAP) != 0)
			(void)kern_munmap(td,
			    (vm_offset_t)arg.dics_call.dic_reply_ptr,
			    round_page((vm_size_t)arg.dics_call.dic_reply_size));
	}
	return (error);
}

static int
door_sys_oneway(struct thread *td, long value, unsigned long data,
    unsigned long size)
{
	struct door *door;
	struct file *fp;
	int error, fd;

	if (size > SIZE_MAX || (size != 0 && data == 0))
		return (EINVAL);
	error = door_sys_range(td, data, size);
	if (error != 0)
		return (error);
	error = door_sys_decode_fd(value, &fd);
	if (error != 0)
		return (error);
	error = door_file_get_ref(td, fd, &door_call_rights, &fp, &door);
	if (error != 0)
		return (error);
	error = door_oneway_submit(door, td, data, (size_t)size);
	fdrop(fp, td);
	return (error);
}

static int
door_sys_async_call(struct thread *td, long value, unsigned long uptr)
{
	struct door_ioc_async_call arg;
	struct door *door, *target;
	struct file *fp, *target_fp;
	int error, fd, stop_prev;

	if (uptr == 0) {
		return (EINVAL);
	}
	error = door_sys_decode_fd(value, &fd);
	if (error != 0) {
		return (error);
	}
	error = door_sys_copyin(td, (void *)(uintptr_t)uptr, &arg, sizeof(arg));
	if (error != 0) {
		return (error);
	}
	if (arg.diac_version != DOOR_ABI_VERSION || arg.diac_flags != 0 ||
	    arg.diac_reserved != 0 || arg.diac_call_id == 0) {
		return (EINVAL);
	}

	error = door_sys_range(td, arg.diac_request_ptr, arg.diac_request_size);
	if (error != 0)
		return (error);
	error = door_sys_enter(td, fd, &door_call_rights, false,
	    SIGDEFERSTOP_NOP, &fp, &door, &stop_prev);

	if (error != 0) {
		return (error);
	}
	error = door_file_get_ref(td, arg.diac_completion_fd,
	    &door_service_rights, &target_fp, &target);

	if (error == 0) {
		/* An untrusted caller cannot redirect replies to another process. */
		if (!door_is_owner(target, td->td_proc))
			error = EPERM;

		if (error == 0) {
			error = door_async_call(door, target, &arg, td);
		}

		fdrop(target_fp, td);
	}
	door_sys_leave(td, fp, stop_prev);

	return (error);
}

static int
door_sys_async_cancel(struct thread *td, long value, long completion_fd,
    uint64_t id)
{
	struct door *door, *target;
	struct file *fp, *target_fp;
	int error, fd, target_fd, stop_prev;

	if (id == 0)
		return (EINVAL);
	error = door_sys_decode_fd(value, &fd);
	if (error != 0)
		return (error);
	error = door_sys_decode_fd(completion_fd, &target_fd);
	if (error != 0)
		return (error);
	error = door_sys_enter(td, fd, &door_call_rights, false,
	    SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
	if (error != 0)
		return (error);
	error = door_file_get_ref(td, target_fd, &door_service_rights,
	    &target_fp, &target);
	if (error == 0) {
		if (!door_is_owner(target, td->td_proc))
			error = EPERM;
		else
			error = door_async_cancel(door, target, (uint64_t)id);
		fdrop(target_fp, td);
	}
	door_sys_leave(td, fp, stop_prev);
	return (error);
}
static int
door_sys_async_cancel_full(struct thread *td, long value, unsigned long uptr)
{
    struct door_ioc_async_cancel arg;
    int error;

    if (uptr == 0)
        return (EINVAL);
    error = door_sys_copyin(td, (void *)(uintptr_t)uptr, &arg, sizeof(arg));
    if (error != 0)
        return (error);
    if (arg.diacc_version != DOOR_ABI_VERSION || arg.diacc_flags != 0 ||
        arg.diacc_reserved != 0 || arg.diacc_call_id == 0)
        return (EINVAL);
    return (door_sys_async_cancel(td, value, arg.diacc_completion_fd,
        arg.diacc_call_id));
}

static int
door_sys_shm_view(struct thread *td, long value, unsigned long uptr,
    unsigned int op)
{
    struct door_ioc_shm_view arg;
    struct door_ioc_shm_view_segment segments[DOOR_SHM_VIEW_MAX_SEGMENTS];
    struct door *door;
    struct file *fp;
    int error, fd, stop_prev;

    error = door_sys_decode_fd(value, &fd);
    if (error != 0)
        return (error);

    error = door_sys_copyin(td, (void *)(uintptr_t)uptr, &arg, sizeof(arg));
    if (error != 0)
        return (error);

    if (arg.disv_version != DOOR_ABI_VERSION || arg.disv_flags != 0)
        return (EINVAL);

    if (op == DOOR_SC_SHM_VIEW_PUBLISH) {
        if (arg.disv_segment_count == 0 ||
            arg.disv_segment_count > DOOR_SHM_VIEW_MAX_SEGMENTS)
            return (EINVAL);

        error = door_sys_range(td, arg.disv_segments_ptr,
            arg.disv_segment_count * sizeof(segments[0]));
        if (error != 0)
            return (error);

        error = door_sys_copyin(td, (void *)(uintptr_t)arg.disv_segments_ptr,
            segments, arg.disv_segment_count * sizeof(segments[0]));
        if (error != 0)
            return (error);
    }

    error = door_sys_enter(td, fd, &door_shm_rights, false,
        SIGDEFERSTOP_SILENT, &fp, &door, &stop_prev);
    if (error != 0)
        return (error);

    error = door_shm_view_op(door, &arg, segments, op, td);
    if (error == 0) {
        error = door_sys_copyout(td, &arg, (void *)(uintptr_t)uptr, sizeof(arg));
        /* Roll back only a committed operation whose output was not delivered. */
        if (error != 0) {
            if (op == DOOR_SC_SHM_VIEW_PUBLISH)
                (void)door_shm_view_op(door, &arg, NULL,
                    DOOR_SC_SHM_VIEW_DESTROY, td);
            else if (op == DOOR_SC_SHM_VIEW_ATTACH)
                (void)door_shm_view_op(door, &arg, NULL,
                    DOOR_SC_SHM_VIEW_RELEASE, td);
        }
    }

    door_sys_leave(td, fp, stop_prev);
    return (error);
}

#endif

int kern_door(struct thread *, long, long, long, long, long, long);

int
kern_door(struct thread *td, long op, long arg1, long arg2, long arg3,
    long arg4, long arg5)
{
#ifdef DOORFS
	switch (op) {
    case DOOR_SC_SHM_VIEW_PUBLISH:
    case DOOR_SC_SHM_VIEW_ATTACH:
    case DOOR_SC_SHM_VIEW_QUERY:
    case DOOR_SC_SHM_VIEW_RELEASE:
    case DOOR_SC_SHM_VIEW_DESTROY:
        return (door_sys_shm_view(td, arg1, arg2, (unsigned int)op));
	case DOOR_SC_CALL:
		return (door_sys_call(td, arg1, arg2));
	case DOOR_SC_RETURN:
		return (door_sys_return(td, arg1));
	case DOOR_SC_FAST_CALL:
		return (door_sys_fast_call(td, arg1, arg2, arg3, arg4, arg5));
	case DOOR_SC_FAST_RETURN:
		return (door_sys_fast_return(td, arg1, arg2, arg3, arg4, arg5));
	case DOOR_SC_EMPTY_CALL:
		return (door_sys_empty_call(td, arg1, arg2, arg3, arg4));
	case DOOR_SC_EMPTY_RETURN:
		return (door_sys_empty_return(td, arg1, arg2, arg3, arg4));
	case DOOR_SC_FAST_CALL_MAPPED:
		return (door_sys_fast_call_mapped(
		    td, arg1, arg2, arg3, arg4, arg5));
	case DOOR_SC_EMPTY_CALL_MAPPED:
		return (door_sys_empty_call_mapped(
		    td, arg1, arg2, arg3, arg4, arg5));
	case DOOR_SC_ONEWAY:
		return (door_sys_oneway(td, arg1, arg2, arg3));
	case DOOR_SC_ASYNC_CALL:
		return (door_sys_async_call(td, arg1, arg2));
	case DOOR_SC_ASYNC_CANCEL:
		return (door_sys_async_cancel(td, arg1, arg2, (unsigned long)arg3));
	case DOOR_SC_ASYNC_CANCEL_FULL:
		return (door_sys_async_cancel_full(td, arg1, arg2));
	case DOOR_SC_CREATE:
		return (door_sys_create(td, arg1, arg2, arg3));
	case DOOR_SC_REVOKE:
		return (door_sys_revoke(td, arg1));
	case DOOR_SC_INFO:
		return (door_sys_info(td, arg1, arg2));
	case DOOR_SC_CANCEL:
		return (door_sys_cancel(td, arg1, arg2));
	case DOOR_SC_GETPARAM:
		return (door_sys_param(td, arg1, arg2, false));
	case DOOR_SC_SETPARAM:
		return (door_sys_param(td, arg1, arg2, true));
	case DOOR_SC_BIND:
		return (door_sys_bind(td, arg1));
	case DOOR_SC_UNBIND:
		return (door_server_unbind_bound(td));
	case DOOR_SC_WORKER_EXIT:
		return (door_server_worker_exit_bound(td));
	case DOOR_SC_CRED:
		return (door_sys_cred(td, arg1));
	case DOOR_SC_SHM_CREATE:
		return (door_sys_shm_create(td, arg1, arg2));
	case DOOR_SC_SHM_ATTACH:
		return (door_sys_shm_attach(td, arg1, arg2));
	case DOOR_SC_CALL_SHM:
		return (door_sys_call_shm(td, arg1, arg2));
	case DOOR_SC_SHM_DESTROY:
		return (door_sys_shm_destroy(td, arg1, arg2));
	default:
		return (EINVAL);
	}
#else
	(void)td;
	(void)op;
	(void)arg1;
	(void)arg2;
	(void)arg3;
	(void)arg4;
	(void)arg5;
	return (ENOSYS);
#endif
}

int
sys_door(struct thread *td, struct door_args *uap)
{
	return (kern_door(td, uap->op, uap->arg1, uap->arg2, uap->arg3,
	    uap->arg4, uap->arg5));
}

#ifdef COMPAT_FREEBSD32
/* Generated from the native long operands by freebsd32/syscalls.conf. */
int
freebsd32_door(struct thread *td, struct freebsd32_door_args *uap)
{
#ifdef DOORFS
    struct door_compat_args args;
    uint32_t words[5];
    int error;

    /* __syscall() observes both i386 result registers, including for int ops. */
    td->td_retval[0] = 0;
    td->td_retval[1] = 0;
    words[0] = (uint32_t)uap->arg1;
    words[1] = (uint32_t)uap->arg2;
    words[2] = (uint32_t)uap->arg3;
    words[3] = (uint32_t)uap->arg4;
    words[4] = (uint32_t)uap->arg5;
    error = door_compat_decode((uint32_t)uap->op, words, &args);
    if (error != 0)
        return (error);
    return (kern_door(td, args.op, (long)args.arg[0], (long)args.arg[1],
        (long)args.arg[2], (long)args.arg[3], (long)args.arg[4]));
#else
    (void)td;
    (void)uap;
    return (ENOSYS);
#endif
}
#endif
