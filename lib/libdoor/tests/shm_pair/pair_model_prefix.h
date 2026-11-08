/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <stdint.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sched.h>
#include <time.h>
#include <door.h>
#ifndef ERESTART
#define ERESTART 512
#endif
#ifndef C_ABSOLUTE
#define C_ABSOLUTE 1
#endif
#define mtx_lock pthread_mutex_lock
#define mtx_unlock pthread_mutex_unlock
#define atomic_load_acq_32(p) __atomic_load_n(p,__ATOMIC_ACQUIRE)
typedef int64_t sbintime_t;
struct cv { pthread_cond_t value; };
struct door { bool d_revoked; pthread_mutex_t d_lock; };
struct door_shm_region {
 bool dr_dead; unsigned dr_flags, refs; uintptr_t dr_pair_kva;
 void *dr_creator_vm,*dr_consumer_vm;
 struct cv dr_pair_cv[2];
};
struct proc { void *p_vmspace; };
struct thread { struct proc *td_proc; };
static struct door fixture={.d_lock=PTHREAD_MUTEX_INITIALIZER};
static struct door_shm_region region;
static struct proc process={.p_vmspace=(void *)1};
static struct thread td={.td_proc=&process};
static unsigned registered;
static uint32_t words[32];
static uint32_t payload,ack;
static sbintime_t sbinuptime(void) {
 struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
 return (int64_t)t.tv_sec*1000000000+t.tv_nsec;
}
static sbintime_t nstosbt(uint64_t ns) { return (sbintime_t)ns; }
static void cv_broadcast(struct cv *cv) { assert(pthread_cond_broadcast(&cv->value)==0); }
static int cv_wait_sig(struct cv *cv,pthread_mutex_t *mtx) {
 __atomic_store_n(&registered,1,__ATOMIC_RELEASE);
 return pthread_cond_wait(&cv->value,mtx);
}
static int cv_timedwait_sig_sbt(struct cv *cv,pthread_mutex_t *mtx,
 sbintime_t deadline,sbintime_t precision,int flags) {
 (void)precision;(void)flags;
 struct timespec t={.tv_sec=deadline/1000000000,.tv_nsec=deadline%1000000000};
 __atomic_store_n(&registered,1,__ATOMIC_RELEASE);
 int error=pthread_cond_timedwait(&cv->value,mtx,&t);
 return error==ETIMEDOUT?EWOULDBLOCK:error;
}
static struct door_shm_region *door_shm_find_locked(struct door *door,uint64_t id) {
 (void)door;return id==1&&!region.dr_dead?&region:NULL;
}
static void door_shm_region_hold(struct door_shm_region *r) { (void)__atomic_fetch_add(&r->refs,1,__ATOMIC_SEQ_CST); }
static void door_shm_region_drop(struct door_shm_region *r) {
 assert(__atomic_fetch_sub(&r->refs,1,__ATOMIC_SEQ_CST)>1);
}
int door_shm_pair_op(struct door *,const struct door_ioc_shm_pair *,unsigned,struct thread *);
