/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SYS_DOOR_CORE_H_
#define _SYS_DOOR_CORE_H_

#include <sys/ioccom.h>
#include <sys/types.h>



#define DOOR_ABI_VERSION 13

#ifdef _KERNEL
/*
 * Data payloads have no small global ceiling.  As in illumos, each door
 * carries DATA_MIN/DATA_MAX policy values; allocation and VM resource
 * failures provide the effective implementation limit.
 */
#define DOOR_MAX_DESC 1024
/*
 * Request and reply thresholds are independent, currently both 8 KiB.
 * Transfers at or above their direction's threshold use held pages.
 */
#define DOOR_REQUEST_PAGE_THRESHOLD (8 * 1024)
#define DOOR_REPLY_PAGE_THRESHOLD (8 * 1024)

/* Compatibility/internal default for code that is not direction-specific. */
#define DOOR_PAGE_THRESHOLD DOOR_REQUEST_PAGE_THRESHOLD
#endif /* _KERNEL */

/* illumos-compatible door creation attributes. */
#define DOOR_UNREF 0x00000001U
#define DOOR_PRIVATE 0x00000002U
#define DOOR_UNREF_MULTI 0x00000010U
#define DOOR_REFUSE_DESC 0x00000040U
#define DOOR_NO_CANCEL 0x00000080U
#define DOOR_NO_DEPLETION_CB 0x00000100U
#define DOOR_PRIVCREATE 0x00000200U
#define DOOR_ONEWAY 0x00000800U
#define DOOR_NO_RETURN 0x00001000U
#define DOOR_CROSS_JAIL 0x00002000U
#define DOOR_NO_CRED 0x00004000U

#ifdef _KERNEL
#define DOOR_CREATE_ALLOWED                                                    \
	(DOOR_UNREF | DOOR_PRIVATE | DOOR_UNREF_MULTI | DOOR_REFUSE_DESC |     \
	    DOOR_NO_CANCEL | DOOR_NO_DEPLETION_CB | DOOR_ONEWAY |              \
	    DOOR_NO_RETURN | DOOR_CROSS_JAIL | DOOR_NO_CRED)
#endif /* _KERNEL */

#define DOOR_PARAM_DESC_MAX 1
#define DOOR_PARAM_DATA_MAX 2
#define DOOR_PARAM_DATA_MIN 3

#define DOOR_DESC_F_MOVE 0x00000001U

struct door_kdesc {
	int32_t dd_fd;
	uint32_t dd_flags;
};
#define DOOR_CRED_MAX_GROUPS 16

#define DOOR_CREATE_F_NORMAL 0x00000001U
#define DOOR_CREATE_F_XCREATE 0x00000002U

/* One six-register native syscall: one selector and five operands. */
#define DOOR_SC_CALL 1U
#define DOOR_SC_RETURN 2U
#define DOOR_SC_FAST_CALL 3U
#define DOOR_SC_FAST_RETURN 4U
#define DOOR_SC_ONEWAY 5U
#define DOOR_SC_CREATE 6U
#define DOOR_SC_REVOKE 7U
#define DOOR_SC_INFO 8U
#define DOOR_SC_CANCEL 9U
#define DOOR_SC_GETPARAM 10U
#define DOOR_SC_SETPARAM 11U
#define DOOR_SC_BIND 12U
#define DOOR_SC_UNBIND 13U
#define DOOR_SC_WORKER_EXIT 14U
#define DOOR_SC_CRED 15U
#define DOOR_SC_SHM_CREATE 16U
#define DOOR_SC_SHM_ATTACH 17U
#define DOOR_SC_CALL_SHM 18U
#define DOOR_SC_SHM_DESTROY 19U
#define DOOR_SC_EMPTY_CALL 20U
#define DOOR_SC_EMPTY_RETURN 21U
#define DOOR_SC_FAST_CALL_MAPPED 22U
#define DOOR_SC_EMPTY_CALL_MAPPED 23U
#define DOOR_SC_ASYNC_CALL 24U
#define DOOR_SC_ASYNC_CANCEL 25U
/* Pointer payload preserves the ID across ILP32 and LP64. */
#define DOOR_SC_ASYNC_CANCEL_FULL 26U
#define DOOR_SC_SHM_VIEW_PUBLISH 27U
#define DOOR_SC_SHM_VIEW_ATTACH 28U
#define DOOR_SC_SHM_VIEW_QUERY 29U
#define DOOR_SC_SHM_VIEW_RELEASE 30U
#define DOOR_SC_SHM_VIEW_DESTROY 31U
#define DOOR_SC_SHM_PAIR_WAIT 32U
#define DOOR_SC_SHM_PAIR_WAKE 33U

/* Two independent event words, in separate cache lines of the first page. */
#define DOOR_SHM_PAIR_LANES 2U
#define DOOR_SHM_PAIR_STRIDE 64U
#define DOOR_SHM_PAIR_CONTROL_SIZE 128U
#define DOOR_SHM_PAIR_TIMEOUT_MAX_NS 86400000000000ULL
#define DOOR_SHM_PAIR_FOREVER (~(uint64_t)0)

struct door_ioc_shm_pair {
    uint32_t disp_version;
    uint32_t disp_lane;
    uint64_t disp_region;
    uint64_t disp_timeout_ns; /* relative duration, UINT64_MAX = infinite */
    uint32_t disp_expected;
    uint32_t disp_reserved;
};

#define DOOR_SHM_VIEW_MAX_SEGMENTS 64
#define DOOR_SHM_VIEW_PUBLISHED 1
#define DOOR_SHM_VIEW_MAPPING 2
#define DOOR_SHM_VIEW_ATTACHED 3
#define DOOR_SHM_VIEW_RELEASING 4
#define DOOR_SHM_VIEW_RELEASED 5

/* Shared fixed-width request/result for the page-view operations. */
struct door_ioc_shm_view {
    uint32_t disv_version;
    uint32_t disv_flags;
    uint64_t disv_id;
    uint64_t disv_token;
    uint64_t disv_addr;
    uint64_t disv_size;
    uint64_t disv_segments_ptr; /* door_shm_ref_t-compatible 32-byte records */
    uint32_t disv_segment_count;
    uint32_t disv_state;
};

struct door_ioc_shm_view_segment {
    uint64_t disvs_region;
    uint64_t disvs_offset;
    uint64_t disvs_size;
    uint64_t disvs_uniquifier;
};


/* A data-only RPC.  The reply is delivered as a request to completion_fd. */
struct door_ioc_async_call {
	uint32_t diac_version;
	uint32_t diac_flags; /* must be zero */
	uint64_t diac_call_id; /* nonzero, chosen before submission */
	uint64_t diac_request_ptr;
	uint64_t diac_request_size;
	int32_t diac_completion_fd;
	uint32_t diac_reserved; /* must be zero */
};

struct door_ioc_async_cancel {
	uint32_t diacc_version;
	uint32_t diacc_flags; /* must be zero */
	int32_t diacc_completion_fd;
	uint32_t diacc_reserved; /* must be zero */
	uint64_t diacc_call_id;
};

#define DOOR_ASYNC_C_REVOKED 0x00000001U
#define DOOR_ASYNC_C_WORKER_EXIT 0x00000002U
#define DOOR_ASYNC_C_CANCELLED 0x00000004U
#define DOOR_ASYNC_C_FLAG_MASK 0x00000007U

/* The request body delivered to the completion Door follows this header. */
struct door_async_completion {
	uint32_t dac_version;
	uint32_t dac_flags; /* DOOR_ASYNC_C_* */
	uint64_t dac_call_id;
	/* 0 or positive errno from lifecycle/reply validation or copy failure.
	 * A nonzero status carries no result bytes. */
	int32_t dac_status;
	uint32_t dac_reserved;
	uint64_t dac_data_size;
};

#define DOOR_INFO_LOCAL 0x00000004U
#define DOOR_INFO_REVOKED 0x00000008U

struct door_kcred {
	uid_t dc_euid;
	uid_t dc_ruid;
	uid_t dc_suid;
	gid_t dc_egid;
	gid_t dc_rgid;
	gid_t dc_sgid;
	pid_t dc_pid;
	int32_t dc_jid;
	uint32_t dc_ngroups;
	gid_t dc_groups[DOOR_CRED_MAX_GROUPS];
};

/*
 * Door call output flags.
 * ONEWAY means the request was accepted by the asynchronous door and there is
 * deliberately no reply payload or descriptor set.
 */
#define DOOR_CALL_F_ONEWAY 0x00000001U
#define DOOR_CALL_F_AUTO_MAP 0x00000002U

struct door_ioc_call {
	uint32_t dic_version;
	uint32_t dic_flags;
	uint64_t dic_request_ptr;
	uint64_t dic_request_size;
	uint64_t dic_reply_ptr;
	uint64_t dic_reply_size;
	uint64_t
	    dic_call_id; /* input 0=allocate, otherwise requested id; output */
	int32_t dic_send_fd;	    /* input, -1 for none */
	int32_t dic_recv_fd;	    /* output, -1 for none */
	uint64_t dic_send_desc_ptr; /* struct door_kdesc[] input */
	uint32_t dic_send_desc_count;
	uint32_t dic_reserved2;
	uint64_t dic_recv_desc_ptr;   /* struct door_kdesc[] output */
	uint32_t dic_recv_desc_count; /* capacity on input, actual on output */
	uint32_t dic_reserved3;
};

/*
 * call_id == 0 with no reply is a pure receive. Normally RETURN completes
 * that call and receives the next, but success may instead report NEED_BUFS,
 * REWAIT or EXIT. COMPLETED alone does not imply a next request; kernel async
 * completion returns COMPLETED|REWAIT and receives again separately.
 */
#define DOOR_RETURN_F_UNREF 0x00000001U

struct door_ioc_return {
	uint32_t dir_version;
	uint32_t dir_flags;   /* input: RESIZABLE/CRED_LAZY; output: DOOR_RETURN_F_* */
	uint64_t dir_call_id; /* previous call on entry, next call out */
	uint64_t dir_reply_ptr;
	uint64_t dir_reply_size;
	uint64_t dir_request_ptr;
	uint64_t dir_request_size;
	struct door_kcred dir_cred;  /* client credential snapshot, output */
	int32_t dir_reply_fd;	     /* input, -1 for none */
	int32_t dir_request_fd;	     /* output, -1 for none */
	/* Explicit amd64 padding: ignored on input, zero on output. */
	uint32_t dir_padding;
	uint64_t dir_reply_desc_ptr; /* struct door_kdesc[] input */
	uint32_t dir_reply_desc_count;
	uint32_t dir_reserved2;
	uint64_t dir_request_desc_ptr; /* struct door_kdesc[] output */
	uint32_t
	    dir_request_desc_count; /* capacity on input, actual on output */
	uint32_t dir_reserved3;
};

struct door_ioc_cancel {
	uint32_t dican_version;
	uint32_t dican_flags;
	uint64_t dican_call_id;
};

struct door_ioc_param {
	uint32_t dip_version;
	int32_t dip_type;
	uint64_t dip_value;
};

struct door_ioc_info {
	uint32_t di_version;
	uint32_t di_flags; /* DOOR_INFO_* */
	int32_t di_target; /* owner/server process, -1 after exit */
	int32_t di_jid;
	uint64_t di_proc; /* kernel: 0; libdoor may resolve a process-local callback */
	uint64_t di_cookie;
	uint64_t di_uniquifier;
	uint32_t di_attributes;	    /* create-time attributes */
	uint32_t di_pending_calls;  /* FreeBSD diagnostic extension */
	uint32_t di_active_calls;   /* FreeBSD diagnostic extension */
	uint32_t di_server_threads; /* FreeBSD diagnostic extension */
};

/*
 * Persistent kernel-managed shared-memory regions.
 *
 * CREATE allocates one anonymous VM object and maps it into the caller.
 * ATTACH is owner/server-only and maps the same object into that process.
 * CALL_SHM carries only a validated region/offset/length reference; the
 * server receives its own local virtual address through the extended RETURN payload.
 *
 * Region setup is intentionally outside the RPC hot path.
 */
#define DOOR_SHM_F_READ 0x00000001U
#define DOOR_SHM_F_WRITE 0x00000002U
#define DOOR_SHM_F_RW (DOOR_SHM_F_READ | DOOR_SHM_F_WRITE)
#define DOOR_SHM_F_CONSUMER_RO 0x00000004U
#define DOOR_SHM_F_PAIR 0x00000008U
#define DOOR_SHM_F_MASK (DOOR_SHM_F_RW | DOOR_SHM_F_CONSUMER_RO | DOOR_SHM_F_PAIR)

struct door_ioc_shm_ref {
	uint64_t disr_region;
	uint64_t disr_offset;
	uint64_t disr_size;
};

struct door_ioc_shm_create {
	uint32_t disc_version;
	uint32_t disc_flags;
	uint64_t disc_size;
	uint64_t disc_region; /* output */
	uint64_t disc_addr;   /* output: caller-local mapping */
	uint64_t disc_uniquifier; /* output: Door generation */
};

struct door_ioc_shm_attach {
	uint32_t disa_version;
	uint32_t disa_flags;
	uint64_t disa_region;
	uint64_t disa_size; /* output */
	uint64_t disa_addr; /* output: current-process mapping */
	uint64_t disa_uniquifier; /* output: Door generation */
};

struct door_ioc_shm_destroy {
	uint32_t disd_version;
	uint32_t disd_flags;
	uint64_t disd_region;
};

struct door_ioc_call_shm {
	struct door_ioc_call dics_call;
	struct door_ioc_shm_ref dics_shm;
	uint64_t dics_uniquifier; /* input: expected Door generation */
};

#define DOOR_RETURN_F_SHM 0x00000002U
#define DOOR_RETURN_F_COMPLETED 0x00000004U
#define DOOR_RETURN_F_EXIT 0x00000008U

/*
 * Fused RETURN receive-resize protocol.
 *
 * RESIZABLE is an input capability bit.  If the next request does not fit
 * the supplied receive buffers, a capable kernel requeues that request and
 * returns success with NEED_BUFS plus the required sizes.  Returning a normal
 * syscall error is not sufficient because modified argument data is not
 * a reliable output channel on failure.
 *
 * Callers without RESIZABLE retain the legacy EMSGSIZE receive behavior.
 * This does not imply compatibility with every older binary ABI layout.
 */
#define DOOR_RETURN_F_RESIZABLE 0x00000010U
#define DOOR_RETURN_F_NEED_BUFS 0x00000020U
#define DOOR_RETURN_F_REWAIT 0x00000040U
#define DOOR_RETURN_F_CRED_LAZY 0x80000000U

struct door_ioc_return_shm {
	struct door_ioc_return dirs_return;
	struct door_ioc_shm_ref dirs_shm; /* output */
	uint64_t dirs_shm_ptr;		  /* output: server-local address */
};

struct door_ioc_cred {
	uint32_t dicr_version;
	uint32_t dicr_reserved;
	uint64_t dicr_call_id;
	struct door_kcred dicr_cred;
	/* Explicit amd64 tail padding: ignored on input, zero on output. */
	uint32_t dicr_padding;
};

/* Scalar FAST_CALL result packed into register_t. */
#define DOOR_FAST_CALL_REPLY_MASK ((1ULL << 56) - 1)
#define DOOR_FAST_CALL_DESC_SHIFT 56
#define DOOR_FAST_CALL_DESC_MASK 0x7fULL
#define DOOR_FAST_CALL_F_ONEWAY (1ULL << 63)
#define DOOR_FAST_CALL_DESC_CAP 64U

struct door_sys_fast_call_io {
	uint64_t dsfci_reply_capacity;
	uint64_t dsfci_recv_desc_ptr;
};

/*
 * Replacement-buffer capable scalar CALL.  Separate selectors preserve the
 * layout and behavior of the original register fast paths for old binaries.
 */
struct door_sys_fast_call_mapped_io {
	uint32_t dsfcmi_version;
	uint32_t dsfcmi_flags; /* output: DOOR_CALL_F_* */
	uint64_t dsfcmi_reply_capacity;
	uint64_t dsfcmi_recv_desc_ptr;
	uint64_t dsfcmi_reply_ptr; /* output: original or automatic mapping */
};

/* FAST_RETURN register result for an ordinary empty next request. */
#define DOOR_FAST_RETURN_F_REGISTER (1ULL << 63)
#define DOOR_FAST_RETURN_CALL_MASK (DOOR_FAST_RETURN_F_REGISTER - 1)

struct door_sys_fast_return_out {
	uint64_t dsfro_call_id;
	uint64_t dsfro_request_size;
	uint32_t dsfro_request_desc_count;
	uint32_t dsfro_flags;
	struct door_ioc_shm_ref dsfro_shm;
	uint64_t dsfro_shm_ptr;
};

struct door_sys_fast_return_io {
	uint64_t dsfri_request_capacity;
	uint64_t dsfri_out_ptr;
};

/*
 * Global named Door control plane (/dev/doorctl).
 *
 * Names are logical service identifiers.  Local registrations are scoped to
 * the owner's jail; DOOR_NAMED_F_GLOBAL registrations live in the host-wide
 * namespace and may only be created from prison0.
 *
 * CONNECT returns a client capability fd pinned to the generation current at
 * connect time.  Subsequent RPCs do not re-run discovery/policy.
 */
#define DOOR_CTL_ABI_VERSION 1
#define DOOR_NAME_MAX 128

#define DOOR_NAMED_F_GLOBAL 0x00000001U

struct door_ctl_register {
	uint32_t dcr_version;
	uint32_t dcr_flags;
	int32_t dcr_door_fd;
	uint32_t dcr_reserved;
	char dcr_name[DOOR_NAME_MAX];
};

struct door_ctl_unregister {
	uint32_t dcu_version;
	uint32_t dcu_flags;
	int32_t dcu_door_fd;
	uint32_t dcu_reserved;
	char dcu_name[DOOR_NAME_MAX];
};

struct door_ctl_connect {
	uint32_t dcc_version;
	uint32_t dcc_flags;
	int32_t dcc_fd;		 /* output */
	int32_t dcc_target_jid;	 /* output */
	uint64_t dcc_uniquifier; /* output */
	char dcc_name[DOOR_NAME_MAX];
};

struct door_ctl_lookup {
	uint32_t dcl_version;
	uint32_t dcl_flags;
	int32_t dcl_target_jid;	 /* output */
	uint32_t dcl_attributes; /* output */
	uint64_t dcl_uniquifier; /* output */
	char dcl_name[DOOR_NAME_MAX];
};

#define DOORCTL_IOC_REGISTER _IOW('N', 1, struct door_ctl_register)
#define DOORCTL_IOC_UNREGISTER _IOW('N', 2, struct door_ctl_unregister)
#define DOORCTL_IOC_CONNECT _IOWR('N', 3, struct door_ctl_connect)
#define DOORCTL_IOC_LOOKUP _IOWR('N', 4, struct door_ctl_lookup)

#endif /* _SYS_DOOR_CORE_H_ */
