/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _LIBDOOR_IMPL_H_
#define _LIBDOOR_IMPL_H_

#include <sys/types.h>
#include <sys/door_core.h>
#include <sys/syscall.h>
#include <sys/uio.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <door.h>

#define	DOOR_SYSCALL_NR	SYS_door

static __inline long
__door_syscall(long op, long arg1, long arg2, long arg3, long arg4, long arg5)
{
#if DOOR_SYSCALL_NR >= 0
    return ((long)__syscall((quad_t)DOOR_SYSCALL_NR, op, arg1, arg2,
        arg3, arg4, arg5));
#else
	(void)op;
    (void)arg1;
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;
    errno = ENOSYS;
    return (-1);
#endif
}

#define LIBDOOR_SERVER_DATA_CAP  (1024U * 1024U)
#define LIBDOOR_SERVER_DESC_CAP  64U
#define LIBDOOR_CALL_DESC_CAP    64U

enum door_pool_type {
    DOOR_POOL_SHARED = 0,
    DOOR_POOL_LEGACY_PRIVATE,
    DOOR_POOL_XCREATE_PRIVATE
};

struct door_entry {
    int de_fd;
    door_server_procedure_t *de_proc;
    void *de_cookie;
    uint_t de_attributes;
    bool de_revoked;
    bool de_revoke_pending;
    enum door_pool_type de_pool_type;
    door_xcreate_server_func_t *de_xcreate_server;
    door_xcreate_thrsetup_func_t *de_thrsetup;
    void *de_setup_cookie;
    int de_initial_threads;
    pthread_mutex_t de_pool_lock;
    pthread_cond_t de_pool_cv;
    unsigned int de_workers_starting;
    unsigned int de_workers_ready;
    unsigned int de_workers_exited;
    unsigned int de_workers_live;
    unsigned int de_workers_idle;
    unsigned int de_workers_active;
    bool de_depletion_in_progress;
    bool de_depletion_armed;
    int de_start_error;
    bool de_pool_stopping;
    struct door_entry *de_next;
};

struct door_tls {
    struct door_entry *dt_entry;
    int dt_worker_fd;
    pid_t dt_pid;
    bool dt_bound;
    uint64_t dt_call_id;
    bool dt_is_unref;
    bool dt_pool_idle;
    bool dt_pool_active;
    struct door_kcred dt_cred;
    bool dt_cred_valid;
    ucred_t dt_ucred;
    bool dt_in_callback;
    bool dt_reply_submitted;
    char *dt_request_data;
    size_t dt_request_capacity;
    struct door_kdesc *dt_request_desc;
    uint32_t dt_request_desc_capacity;
    door_desc_t *dt_public_desc;
    uint32_t dt_public_desc_capacity;
    struct door_ioc_return_shm dt_next_return;
    int dt_return_error;
    bool dt_next_ready;
    bool dt_exit_after_return;

};

extern pthread_mutex_t __door_lock;
extern struct door_entry *__door_entries;
extern door_server_func_t *__door_server_factory;

struct door_server_context {
    struct door_entry *dsc_entry;
    int dsc_worker_fd;
    bool dsc_xcreate;
};

struct door_tls *__door_tls_get(bool);
struct door_entry *__door_entry_lookup(int);
int __door_entry_add(struct door_entry *);
struct door_entry *__door_entry_begin_revoke(int);
void __door_entry_finish_revoke(struct door_entry *, bool);
int __door_spawn_server(struct door_entry *);
int __door_launch_managed_worker(struct door_entry *, bool);
void __door_notify_factory(struct door_entry *, bool);
int __door_xcreate_launch(struct door_entry *, bool, int *);
int __door_create_common(door_server_procedure_t *, void *, uint_t,
    uint32_t, struct door_entry **);
void __door_entry_pool_destroy(struct door_entry *);
void *__door_server_main(void *);
int __door_desc_export(const door_desc_t *, uint_t, struct door_kdesc **,
    uint32_t *);
void __door_desc_import(door_desc_t *, const struct door_kdesc *, uint32_t);
int __door_safe_copyin(void *, const void *, size_t);
int __door_iov_add(struct iovec **, int *, const char *, const void *, size_t);
void __door_iov_free(struct iovec *, int);

#endif
