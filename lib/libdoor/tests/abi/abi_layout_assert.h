/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Freeze the observed ABI 13 layouts, with common amd64/i386 wire sizes
 * and offsets. Public native layouts differ; this is not runtime qualification.
 * DOOR_ABI_REQUIRE_LP64_WIRE_LAYOUT additionally requires kernel wire sizes
 * and field offsets to match amd64; it must pass on both x86 data models.
 * Public pointer-bearing libdoor types remain native to each data model.
 */
#ifndef LIBDOOR_ABI_LAYOUT_ASSERT_H
#define LIBDOOR_ABI_LAYOUT_ASSERT_H

#include <stddef.h>
#include <door.h>
#ifdef DOOR_ABI_CHECK_TEST_INTERFACE
#include <sys/door_test.h>
#endif

#define DOOR_ABI_SIZE(t, n) _Static_assert(sizeof(t) == (n), #t " size")
#define DOOR_ABI_ALIGN(t, n) _Static_assert(_Alignof(t) == (n), #t " alignment")
#define DOOR_ABI_OFFSET(t, f, n) \
    _Static_assert(offsetof(t, f) == (n), #t "." #f " offset")

#if defined(__i386__)
#define DOOR_ABI_NATIVE(a64, a32) (a32)
#elif defined(__LP64__)
#define DOOR_ABI_NATIVE(a64, a32) (a64)
#else
#error "Layout baseline covers LP64 and i386; qualify other ILP32 ABIs separately"
#endif
#ifdef DOOR_ABI_REQUIRE_LP64_WIRE_LAYOUT
#define DOOR_ABI_WIRE(a64, a32) (a64)
#else
#define DOOR_ABI_WIRE(a64, a32) DOOR_ABI_NATIVE(a64, a32)
#endif

_Static_assert(sizeof(uint64_t) == 8, "uint64_t stays 64-bit in both ABIs");
_Static_assert(sizeof(uid_t) == 4 && sizeof(gid_t) == 4 && sizeof(pid_t) == 4,
    "FreeBSD credential scalar widths");

/* struct door_kdesc */
DOOR_ABI_SIZE(struct door_kdesc, 8);
DOOR_ABI_ALIGN(struct door_kdesc, 4);
DOOR_ABI_OFFSET(struct door_kdesc, dd_fd, 0);
DOOR_ABI_OFFSET(struct door_kdesc, dd_flags, 4);

/* struct door_ioc_async_call */
DOOR_ABI_SIZE(struct door_ioc_async_call, 40);
DOOR_ABI_ALIGN(struct door_ioc_async_call, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_async_call, diac_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_async_call, diac_flags, 4);
DOOR_ABI_OFFSET(struct door_ioc_async_call, diac_call_id, 8);
DOOR_ABI_OFFSET(struct door_ioc_async_call, diac_request_ptr, 16);
DOOR_ABI_OFFSET(struct door_ioc_async_call, diac_request_size, 24);
DOOR_ABI_OFFSET(struct door_ioc_async_call, diac_completion_fd, 32);
DOOR_ABI_OFFSET(struct door_ioc_async_call, diac_reserved, 36);

/* Full-width cancel is a fixed wire record, including on i386. */
DOOR_ABI_SIZE(door_shm_view_t, DOOR_ABI_NATIVE(48, 36));
DOOR_ABI_ALIGN(door_shm_view_t, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_shm_view_t, dsv_id, 0);
DOOR_ABI_OFFSET(door_shm_view_t, dsv_token, 8);
DOOR_ABI_OFFSET(door_shm_view_t, dsv_addr, 16);
DOOR_ABI_OFFSET(door_shm_view_t, dsv_size, DOOR_ABI_NATIVE(24, 20));
DOOR_ABI_OFFSET(door_shm_view_t, dsv_fd, DOOR_ABI_NATIVE(32, 24));
DOOR_ABI_OFFSET(door_shm_view_t, dsv_state, DOOR_ABI_NATIVE(36, 28));
DOOR_ABI_OFFSET(door_shm_view_t, dsv_role, DOOR_ABI_NATIVE(40, 32));

DOOR_ABI_SIZE(struct door_ioc_shm_view, 56);
DOOR_ABI_ALIGN(struct door_ioc_shm_view, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_shm_view, disv_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_shm_view, disv_flags, 4);
DOOR_ABI_OFFSET(struct door_ioc_shm_view, disv_id, 8);
DOOR_ABI_OFFSET(struct door_ioc_shm_view, disv_token, 16);
DOOR_ABI_OFFSET(struct door_ioc_shm_view, disv_addr, 24);
DOOR_ABI_OFFSET(struct door_ioc_shm_view, disv_size, 32);
DOOR_ABI_OFFSET(struct door_ioc_shm_view, disv_segments_ptr, 40);
DOOR_ABI_OFFSET(struct door_ioc_shm_view, disv_segment_count, 48);
DOOR_ABI_OFFSET(struct door_ioc_shm_view, disv_state, 52);
DOOR_ABI_SIZE(struct door_ioc_shm_view_segment, 32);
DOOR_ABI_ALIGN(struct door_ioc_shm_view_segment, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_shm_view_segment, disvs_region, 0);
DOOR_ABI_OFFSET(struct door_ioc_shm_view_segment, disvs_offset, 8);
DOOR_ABI_OFFSET(struct door_ioc_shm_view_segment, disvs_size, 16);
DOOR_ABI_OFFSET(struct door_ioc_shm_view_segment, disvs_uniquifier, 24);

DOOR_ABI_SIZE(struct door_ioc_async_cancel, 24);
DOOR_ABI_ALIGN(struct door_ioc_async_cancel, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_async_cancel, diacc_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_async_cancel, diacc_flags, 4);
DOOR_ABI_OFFSET(struct door_ioc_async_cancel, diacc_completion_fd, 8);
DOOR_ABI_OFFSET(struct door_ioc_async_cancel, diacc_reserved, 12);
DOOR_ABI_OFFSET(struct door_ioc_async_cancel, diacc_call_id, 16);

/* struct door_async_completion */
DOOR_ABI_SIZE(struct door_async_completion, 32);
DOOR_ABI_ALIGN(struct door_async_completion, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_async_completion, dac_version, 0);
DOOR_ABI_OFFSET(struct door_async_completion, dac_flags, 4);
DOOR_ABI_OFFSET(struct door_async_completion, dac_call_id, 8);
DOOR_ABI_OFFSET(struct door_async_completion, dac_status, 16);
DOOR_ABI_OFFSET(struct door_async_completion, dac_reserved, 20);
DOOR_ABI_OFFSET(struct door_async_completion, dac_data_size, 24);

/* struct door_kcred */
DOOR_ABI_SIZE(struct door_kcred, 100);
DOOR_ABI_ALIGN(struct door_kcred, 4);
DOOR_ABI_OFFSET(struct door_kcred, dc_euid, 0);
DOOR_ABI_OFFSET(struct door_kcred, dc_ruid, 4);
DOOR_ABI_OFFSET(struct door_kcred, dc_suid, 8);
DOOR_ABI_OFFSET(struct door_kcred, dc_egid, 12);
DOOR_ABI_OFFSET(struct door_kcred, dc_rgid, 16);
DOOR_ABI_OFFSET(struct door_kcred, dc_sgid, 20);
DOOR_ABI_OFFSET(struct door_kcred, dc_pid, 24);
DOOR_ABI_OFFSET(struct door_kcred, dc_jid, 28);
DOOR_ABI_OFFSET(struct door_kcred, dc_ngroups, 32);
DOOR_ABI_OFFSET(struct door_kcred, dc_groups, 36);

/* struct door_ioc_call */
DOOR_ABI_SIZE(struct door_ioc_call, 88);
DOOR_ABI_ALIGN(struct door_ioc_call, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_call, dic_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_flags, 4);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_request_ptr, 8);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_request_size, 16);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_reply_ptr, 24);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_reply_size, 32);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_call_id, 40);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_send_fd, 48);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_recv_fd, 52);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_send_desc_ptr, 56);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_send_desc_count, 64);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_reserved2, 68);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_recv_desc_ptr, 72);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_recv_desc_count, 80);
DOOR_ABI_OFFSET(struct door_ioc_call, dic_reserved3, 84);

/* struct door_ioc_return */
DOOR_ABI_SIZE(struct door_ioc_return, 192);
DOOR_ABI_ALIGN(struct door_ioc_return, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_return, dir_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_flags, 4);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_call_id, 8);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_reply_ptr, 16);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_reply_size, 24);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_request_ptr, 32);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_request_size, 40);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_cred, 48);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_reply_fd, 148);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_request_fd, 152);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_padding, 156);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_reply_desc_ptr, 160);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_reply_desc_count, 168);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_reserved2, 172);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_request_desc_ptr, 176);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_request_desc_count, 184);
DOOR_ABI_OFFSET(struct door_ioc_return, dir_reserved3, 188);

/* struct door_ioc_cancel */
DOOR_ABI_SIZE(struct door_ioc_cancel, 16);
DOOR_ABI_ALIGN(struct door_ioc_cancel, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_cancel, dican_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_cancel, dican_flags, 4);
DOOR_ABI_OFFSET(struct door_ioc_cancel, dican_call_id, 8);

/* struct door_ioc_param */
DOOR_ABI_SIZE(struct door_ioc_param, 16);
DOOR_ABI_ALIGN(struct door_ioc_param, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_param, dip_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_param, dip_type, 4);
DOOR_ABI_OFFSET(struct door_ioc_param, dip_value, 8);

/* struct door_ioc_info */
DOOR_ABI_SIZE(struct door_ioc_info, 56);
DOOR_ABI_ALIGN(struct door_ioc_info, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_info, di_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_info, di_flags, 4);
DOOR_ABI_OFFSET(struct door_ioc_info, di_target, 8);
DOOR_ABI_OFFSET(struct door_ioc_info, di_jid, 12);
DOOR_ABI_OFFSET(struct door_ioc_info, di_proc, 16);
DOOR_ABI_OFFSET(struct door_ioc_info, di_cookie, 24);
DOOR_ABI_OFFSET(struct door_ioc_info, di_uniquifier, 32);
DOOR_ABI_OFFSET(struct door_ioc_info, di_attributes, 40);
DOOR_ABI_OFFSET(struct door_ioc_info, di_pending_calls, 44);
DOOR_ABI_OFFSET(struct door_ioc_info, di_active_calls, 48);
DOOR_ABI_OFFSET(struct door_ioc_info, di_server_threads, 52);

/* struct door_ioc_shm_ref */
DOOR_ABI_SIZE(struct door_ioc_shm_ref, 24);
DOOR_ABI_ALIGN(struct door_ioc_shm_ref, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_shm_ref, disr_region, 0);
DOOR_ABI_OFFSET(struct door_ioc_shm_ref, disr_offset, 8);
DOOR_ABI_OFFSET(struct door_ioc_shm_ref, disr_size, 16);

/* struct door_ioc_shm_create */
DOOR_ABI_SIZE(struct door_ioc_shm_create, 40);
DOOR_ABI_ALIGN(struct door_ioc_shm_create, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_shm_create, disc_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_shm_create, disc_flags, 4);
DOOR_ABI_OFFSET(struct door_ioc_shm_create, disc_size, 8);
DOOR_ABI_OFFSET(struct door_ioc_shm_create, disc_region, 16);
DOOR_ABI_OFFSET(struct door_ioc_shm_create, disc_addr, 24);
DOOR_ABI_OFFSET(struct door_ioc_shm_create, disc_uniquifier, 32);

/* struct door_ioc_shm_attach */
DOOR_ABI_SIZE(struct door_ioc_shm_attach, 40);
DOOR_ABI_ALIGN(struct door_ioc_shm_attach, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_shm_attach, disa_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_shm_attach, disa_flags, 4);
DOOR_ABI_OFFSET(struct door_ioc_shm_attach, disa_region, 8);
DOOR_ABI_OFFSET(struct door_ioc_shm_attach, disa_size, 16);
DOOR_ABI_OFFSET(struct door_ioc_shm_attach, disa_addr, 24);
DOOR_ABI_OFFSET(struct door_ioc_shm_attach, disa_uniquifier, 32);

/* struct door_ioc_shm_destroy */
DOOR_ABI_SIZE(struct door_ioc_shm_destroy, 16);
DOOR_ABI_ALIGN(struct door_ioc_shm_destroy, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_shm_destroy, disd_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_shm_destroy, disd_flags, 4);
DOOR_ABI_OFFSET(struct door_ioc_shm_destroy, disd_region, 8);

/* struct door_ioc_call_shm */
DOOR_ABI_SIZE(struct door_ioc_call_shm, 120);
DOOR_ABI_ALIGN(struct door_ioc_call_shm, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_call_shm, dics_call, 0);
DOOR_ABI_OFFSET(struct door_ioc_call_shm, dics_shm, 88);
DOOR_ABI_OFFSET(struct door_ioc_call_shm, dics_uniquifier, 112);

/* struct door_ioc_return_shm */
DOOR_ABI_SIZE(struct door_ioc_return_shm, 224);
DOOR_ABI_ALIGN(struct door_ioc_return_shm, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_return_shm, dirs_return, 0);
DOOR_ABI_OFFSET(struct door_ioc_return_shm, dirs_shm, 192);
DOOR_ABI_OFFSET(struct door_ioc_return_shm, dirs_shm_ptr, 216);

/* struct door_ioc_cred */
DOOR_ABI_SIZE(struct door_ioc_cred, 120);
DOOR_ABI_ALIGN(struct door_ioc_cred, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ioc_cred, dicr_version, 0);
DOOR_ABI_OFFSET(struct door_ioc_cred, dicr_reserved, 4);
DOOR_ABI_OFFSET(struct door_ioc_cred, dicr_call_id, 8);
DOOR_ABI_OFFSET(struct door_ioc_cred, dicr_cred, 16);
DOOR_ABI_OFFSET(struct door_ioc_cred, dicr_padding, 116);

/* struct door_sys_fast_call_io */
DOOR_ABI_SIZE(struct door_sys_fast_call_io, 16);
DOOR_ABI_ALIGN(struct door_sys_fast_call_io, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_sys_fast_call_io, dsfci_reply_capacity, 0);
DOOR_ABI_OFFSET(struct door_sys_fast_call_io, dsfci_recv_desc_ptr, 8);

/* struct door_sys_fast_call_mapped_io */
DOOR_ABI_SIZE(struct door_sys_fast_call_mapped_io, 32);
DOOR_ABI_ALIGN(struct door_sys_fast_call_mapped_io, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_sys_fast_call_mapped_io, dsfcmi_version, 0);
DOOR_ABI_OFFSET(struct door_sys_fast_call_mapped_io, dsfcmi_flags, 4);
DOOR_ABI_OFFSET(struct door_sys_fast_call_mapped_io, dsfcmi_reply_capacity, 8);
DOOR_ABI_OFFSET(struct door_sys_fast_call_mapped_io, dsfcmi_recv_desc_ptr, 16);
DOOR_ABI_OFFSET(struct door_sys_fast_call_mapped_io, dsfcmi_reply_ptr, 24);

/* struct door_sys_fast_return_out */
DOOR_ABI_SIZE(struct door_sys_fast_return_out, 56);
DOOR_ABI_ALIGN(struct door_sys_fast_return_out, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_sys_fast_return_out, dsfro_call_id, 0);
DOOR_ABI_OFFSET(struct door_sys_fast_return_out, dsfro_request_size, 8);
DOOR_ABI_OFFSET(struct door_sys_fast_return_out, dsfro_request_desc_count, 16);
DOOR_ABI_OFFSET(struct door_sys_fast_return_out, dsfro_flags, 20);
DOOR_ABI_OFFSET(struct door_sys_fast_return_out, dsfro_shm, 24);
DOOR_ABI_OFFSET(struct door_sys_fast_return_out, dsfro_shm_ptr, 48);

/* struct door_sys_fast_return_io */
DOOR_ABI_SIZE(struct door_sys_fast_return_io, 16);
DOOR_ABI_ALIGN(struct door_sys_fast_return_io, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_sys_fast_return_io, dsfri_request_capacity, 0);
DOOR_ABI_OFFSET(struct door_sys_fast_return_io, dsfri_out_ptr, 8);

/* struct door_ctl_register */
DOOR_ABI_SIZE(struct door_ctl_register, 144);
DOOR_ABI_ALIGN(struct door_ctl_register, 4);
DOOR_ABI_OFFSET(struct door_ctl_register, dcr_version, 0);
DOOR_ABI_OFFSET(struct door_ctl_register, dcr_flags, 4);
DOOR_ABI_OFFSET(struct door_ctl_register, dcr_door_fd, 8);
DOOR_ABI_OFFSET(struct door_ctl_register, dcr_reserved, 12);
DOOR_ABI_OFFSET(struct door_ctl_register, dcr_name, 16);

/* struct door_ctl_unregister */
DOOR_ABI_SIZE(struct door_ctl_unregister, 144);
DOOR_ABI_ALIGN(struct door_ctl_unregister, 4);
DOOR_ABI_OFFSET(struct door_ctl_unregister, dcu_version, 0);
DOOR_ABI_OFFSET(struct door_ctl_unregister, dcu_flags, 4);
DOOR_ABI_OFFSET(struct door_ctl_unregister, dcu_door_fd, 8);
DOOR_ABI_OFFSET(struct door_ctl_unregister, dcu_reserved, 12);
DOOR_ABI_OFFSET(struct door_ctl_unregister, dcu_name, 16);

/* struct door_ctl_connect */
DOOR_ABI_SIZE(struct door_ctl_connect, 152);
DOOR_ABI_ALIGN(struct door_ctl_connect, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ctl_connect, dcc_version, 0);
DOOR_ABI_OFFSET(struct door_ctl_connect, dcc_flags, 4);
DOOR_ABI_OFFSET(struct door_ctl_connect, dcc_fd, 8);
DOOR_ABI_OFFSET(struct door_ctl_connect, dcc_target_jid, 12);
DOOR_ABI_OFFSET(struct door_ctl_connect, dcc_uniquifier, 16);
DOOR_ABI_OFFSET(struct door_ctl_connect, dcc_name, 24);

/* struct door_ctl_lookup */
DOOR_ABI_SIZE(struct door_ctl_lookup, 152);
DOOR_ABI_ALIGN(struct door_ctl_lookup, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_ctl_lookup, dcl_version, 0);
DOOR_ABI_OFFSET(struct door_ctl_lookup, dcl_flags, 4);
DOOR_ABI_OFFSET(struct door_ctl_lookup, dcl_target_jid, 8);
DOOR_ABI_OFFSET(struct door_ctl_lookup, dcl_attributes, 12);
DOOR_ABI_OFFSET(struct door_ctl_lookup, dcl_uniquifier, 16);
DOOR_ABI_OFFSET(struct door_ctl_lookup, dcl_name, 24);

#ifdef DOOR_ABI_CHECK_TEST_INTERFACE

/* struct door_test_control */
DOOR_ABI_SIZE(struct door_test_control, 48);
DOOR_ABI_ALIGN(struct door_test_control, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(struct door_test_control, stage, 0);
DOOR_ABI_OFFSET(struct door_test_control, pid, 4);
DOOR_ABI_OFFSET(struct door_test_control, tid, 8);
DOOR_ABI_OFFSET(struct door_test_control, entered, 16);
DOOR_ABI_OFFSET(struct door_test_control, expired, 20);
DOOR_ABI_OFFSET(struct door_test_control, active, 24);
DOOR_ABI_OFFSET(struct door_test_control, reserved, 28);
DOOR_ABI_OFFSET(struct door_test_control, finished, 32);
DOOR_ABI_OFFSET(struct door_test_control, padding, 36);
DOOR_ABI_OFFSET(struct door_test_control, object, 40);

#endif

#ifdef DOOR_ABI_CHECK_TEST_INTERFACE

/* struct door_test_inspect */
DOOR_ABI_SIZE(struct door_test_inspect, 28);
DOOR_ABI_ALIGN(struct door_test_inspect, 4);
DOOR_ABI_OFFSET(struct door_test_inspect, fd, 0);
DOOR_ABI_OFFSET(struct door_test_inspect, pending, 4);
DOOR_ABI_OFFSET(struct door_test_inspect, active, 8);
DOOR_ABI_OFFSET(struct door_test_inspect, reserved, 12);
DOOR_ABI_OFFSET(struct door_test_inspect, assigned, 16);
DOOR_ABI_OFFSET(struct door_test_inspect, delivered, 20);
DOOR_ABI_OFFSET(struct door_test_inspect, waiting, 24);

#endif

#ifdef DOOR_ABI_CHECK_TEST_INTERFACE

/* struct door_test_objects */
DOOR_ABI_SIZE(struct door_test_objects, 32);
DOOR_ABI_ALIGN(struct door_test_objects, 4);
DOOR_ABI_OFFSET(struct door_test_objects, live, 0);
DOOR_ABI_OFFSET(struct door_test_objects, async_jobs, 28);

#endif

/* door_desc_t */
DOOR_ABI_SIZE(door_desc_t, 24);
DOOR_ABI_ALIGN(door_desc_t, 4);
DOOR_ABI_OFFSET(door_desc_t, d_attributes, 0);
DOOR_ABI_OFFSET(door_desc_t, d_descriptor, 4);
DOOR_ABI_OFFSET(door_desc_t, d_id, 8);

/* door_info_t */
DOOR_ABI_SIZE(door_info_t, 48);
DOOR_ABI_ALIGN(door_info_t, 4);
DOOR_ABI_OFFSET(door_info_t, di_target, 0);
DOOR_ABI_OFFSET(door_info_t, di_proc, 4);
DOOR_ABI_OFFSET(door_info_t, di_data, 12);
DOOR_ABI_OFFSET(door_info_t, di_attributes, 20);
DOOR_ABI_OFFSET(door_info_t, di_uniquifier, 24);
DOOR_ABI_OFFSET(door_info_t, di_resv, 32);

/* door_cred_t */
DOOR_ABI_SIZE(door_cred_t, 36);
DOOR_ABI_ALIGN(door_cred_t, 4);
DOOR_ABI_OFFSET(door_cred_t, dc_euid, 0);
DOOR_ABI_OFFSET(door_cred_t, dc_egid, 4);
DOOR_ABI_OFFSET(door_cred_t, dc_ruid, 8);
DOOR_ABI_OFFSET(door_cred_t, dc_rgid, 12);
DOOR_ABI_OFFSET(door_cred_t, dc_pid, 16);
DOOR_ABI_OFFSET(door_cred_t, dc_resv, 20);

/* door_arg_t */
DOOR_ABI_SIZE(door_arg_t, DOOR_ABI_NATIVE(48, 24));
DOOR_ABI_ALIGN(door_arg_t, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_arg_t, data_ptr, 0);
DOOR_ABI_OFFSET(door_arg_t, data_size, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_arg_t, desc_ptr, DOOR_ABI_NATIVE(16, 8));
DOOR_ABI_OFFSET(door_arg_t, desc_num, DOOR_ABI_NATIVE(24, 12));
DOOR_ABI_OFFSET(door_arg_t, rbuf, DOOR_ABI_NATIVE(32, 16));
DOOR_ABI_OFFSET(door_arg_t, rsize, DOOR_ABI_NATIVE(40, 20));

/* door_shm_t */
DOOR_ABI_SIZE(door_shm_t, DOOR_ABI_NATIVE(48, 36));
DOOR_ABI_ALIGN(door_shm_t, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_shm_t, dsh_region, 0);
DOOR_ABI_OFFSET(door_shm_t, dsh_addr, 8);
DOOR_ABI_OFFSET(door_shm_t, dsh_size, DOOR_ABI_NATIVE(16, 12));
DOOR_ABI_OFFSET(door_shm_t, dsh_flags, DOOR_ABI_NATIVE(24, 16));
DOOR_ABI_OFFSET(door_shm_t, dsh_uniquifier, DOOR_ABI_NATIVE(32, 20));
DOOR_ABI_OFFSET(door_shm_t, dsh_fd, DOOR_ABI_NATIVE(40, 28));
DOOR_ABI_OFFSET(door_shm_t, dsh_resv, DOOR_ABI_NATIVE(44, 32));

/* door_shm_ref_t */
DOOR_ABI_SIZE(door_shm_ref_t, DOOR_ABI_NATIVE(32, 24));
DOOR_ABI_ALIGN(door_shm_ref_t, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_shm_ref_t, dsr_region, 0);
DOOR_ABI_OFFSET(door_shm_ref_t, dsr_offset, 8);
DOOR_ABI_OFFSET(door_shm_ref_t, dsr_size, DOOR_ABI_NATIVE(16, 12));
DOOR_ABI_OFFSET(door_shm_ref_t, dsr_uniquifier, DOOR_ABI_NATIVE(24, 16));

/* door_shm_ring_t */
DOOR_ABI_SIZE(door_shm_ring_t, DOOR_ABI_NATIVE(104, 92));
DOOR_ABI_ALIGN(door_shm_ring_t, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_shm_ring_t, dsr_shm, 0);
DOOR_ABI_OFFSET(door_shm_ring_t, dsr_slot_size, DOOR_ABI_NATIVE(48, 36));
DOOR_ABI_OFFSET(door_shm_ring_t, dsr_slot_stride, DOOR_ABI_NATIVE(56, 44));
DOOR_ABI_OFFSET(door_shm_ring_t, dsr_slot_count, DOOR_ABI_NATIVE(64, 52));
DOOR_ABI_OFFSET(door_shm_ring_t, dsr_local_producer, DOOR_ABI_NATIVE(72, 60));
DOOR_ABI_OFFSET(door_shm_ring_t, dsr_local_consumer, DOOR_ABI_NATIVE(80, 68));
DOOR_ABI_OFFSET(door_shm_ring_t, dsr_role, DOOR_ABI_NATIVE(88, 76));
DOOR_ABI_OFFSET(door_shm_ring_t, dsr_resv, DOOR_ABI_NATIVE(92, 80));
DOOR_ABI_OFFSET(door_shm_ring_t, dsr_local_reservation, DOOR_ABI_NATIVE(96, 84));

/* door_shm_ring_writer_t */
DOOR_ABI_SIZE(door_shm_ring_writer_t, DOOR_ABI_NATIVE(40, 28));
DOOR_ABI_ALIGN(door_shm_ring_writer_t, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_shm_ring_writer_t, drw_data, 0);
DOOR_ABI_OFFSET(door_shm_ring_writer_t, drw_capacity, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_shm_ring_writer_t, drw_offset, DOOR_ABI_NATIVE(16, 8));
DOOR_ABI_OFFSET(door_shm_ring_writer_t, drw_sequence, DOOR_ABI_NATIVE(24, 12));
DOOR_ABI_OFFSET(door_shm_ring_writer_t, drw_reservation, DOOR_ABI_NATIVE(32, 20));

/* door_shm_ring_view_t */
DOOR_ABI_SIZE(door_shm_ring_view_t, DOOR_ABI_NATIVE(32, 20));
DOOR_ABI_ALIGN(door_shm_ring_view_t, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_shm_ring_view_t, drv_data, 0);
DOOR_ABI_OFFSET(door_shm_ring_view_t, drv_size, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_shm_ring_view_t, drv_offset, DOOR_ABI_NATIVE(16, 8));
DOOR_ABI_OFFSET(door_shm_ring_view_t, drv_sequence, DOOR_ABI_NATIVE(24, 12));

/* door_named_info_t */
DOOR_ABI_SIZE(door_named_info_t, 16);
DOOR_ABI_ALIGN(door_named_info_t, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_named_info_t, dni_target_jid, 0);
DOOR_ABI_OFFSET(door_named_info_t, dni_attributes, 4);
DOOR_ABI_OFFSET(door_named_info_t, dni_uniquifier, 8);

/* door_ucred_t */
DOOR_ABI_SIZE(door_ucred_t, 100);
DOOR_ABI_ALIGN(door_ucred_t, 4);
DOOR_ABI_OFFSET(door_ucred_t, du_euid, 0);
DOOR_ABI_OFFSET(door_ucred_t, du_ruid, 4);
DOOR_ABI_OFFSET(door_ucred_t, du_suid, 8);
DOOR_ABI_OFFSET(door_ucred_t, du_egid, 12);
DOOR_ABI_OFFSET(door_ucred_t, du_rgid, 16);
DOOR_ABI_OFFSET(door_ucred_t, du_sgid, 20);
DOOR_ABI_OFFSET(door_ucred_t, du_pid, 24);
DOOR_ABI_OFFSET(door_ucred_t, du_jid, 28);
DOOR_ABI_OFFSET(door_ucred_t, du_ngroups, 32);
DOOR_ABI_OFFSET(door_ucred_t, du_groups, 36);

/* door_async_request_t */
DOOR_ABI_SIZE(door_async_request_t, DOOR_ABI_NATIVE(40, 32));
DOOR_ABI_ALIGN(door_async_request_t, DOOR_ABI_NATIVE(8, 4));
DOOR_ABI_OFFSET(door_async_request_t, dar_id, 0);
DOOR_ABI_OFFSET(door_async_request_t, dar_token, 8);
DOOR_ABI_OFFSET(door_async_request_t, dar_pid, 16);
DOOR_ABI_OFFSET(door_async_request_t, dar_jid, 20);
DOOR_ABI_OFFSET(door_async_request_t, dar_data, 24);
DOOR_ABI_OFFSET(door_async_request_t, dar_size, DOOR_ABI_NATIVE(32, 28));
_Static_assert(DOORCTL_IOC_REGISTER == 0x80904e01U, "DOORCTL_IOC_REGISTER encoding");
_Static_assert(DOORCTL_IOC_UNREGISTER == 0x80904e02U, "DOORCTL_IOC_UNREGISTER encoding");
_Static_assert(DOORCTL_IOC_CONNECT == 0xc0984e03U, "DOORCTL_IOC_CONNECT encoding");
_Static_assert(DOORCTL_IOC_LOOKUP == 0xc0984e04U, "DOORCTL_IOC_LOOKUP encoding");

#ifdef DOOR_ABI_CHECK_TEST_INTERFACE
_Static_assert(DOOR_TEST_ARM == 0x80305401U, "DOOR_TEST_ARM encoding");
#endif

#ifdef DOOR_ABI_CHECK_TEST_INTERFACE
_Static_assert(DOOR_TEST_STATE == 0x40305402U, "DOOR_TEST_STATE encoding");
#endif

#ifdef DOOR_ABI_CHECK_TEST_INTERFACE
_Static_assert(DOOR_TEST_RELEASE == 0x20005403U, "DOOR_TEST_RELEASE encoding");
#endif

#ifdef DOOR_ABI_CHECK_TEST_INTERFACE
_Static_assert(DOOR_TEST_INSPECT == 0xc01c5404U, "DOOR_TEST_INSPECT encoding");
#endif

#ifdef DOOR_ABI_CHECK_TEST_INTERFACE
_Static_assert(DOOR_TEST_DRAIN == 0x20005405U, "DOOR_TEST_DRAIN encoding");
#endif

#ifdef DOOR_ABI_CHECK_TEST_INTERFACE
_Static_assert(DOOR_TEST_OBJECTS == 0x40205406U, "DOOR_TEST_OBJECTS encoding");
#endif

#undef DOOR_ABI_WIRE
#undef DOOR_ABI_NATIVE
#undef DOOR_ABI_OFFSET
#undef DOOR_ABI_ALIGN
#undef DOOR_ABI_SIZE
#endif
