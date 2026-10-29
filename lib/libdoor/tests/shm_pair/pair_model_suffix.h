/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

long __door_syscall(long op,long fd,long arg,long x,long y,long z) {
 (void)fd;(void)x;(void)y;(void)z;
 int error=door_shm_pair_op(&fixture,(const void *)(uintptr_t)arg,(unsigned)op,&td);
 if(error) {errno=error;return -1;}return 0;
}
int door_shm_create(int fd,size_t size,uint_t flags,door_shm_t *shm) {
 (void)fd;(void)size;(void)flags;(void)shm;errno=ENOSYS;return -1;
}
int door_shm_attach(int fd,door_shm_id_t id,uint_t flags,door_shm_t *shm) {
 (void)fd;(void)id;(void)flags;(void)shm;errno=ENOSYS;return -1;
}
static door_shm_t handle={.dsh_addr=words,.dsh_region=1,.dsh_uniquifier=1,.dsh_size=sizeof(words),
 .dsh_flags=DOOR_SHM_PAIR|DOOR_SHM_RW,.dsh_fd=1};
static void await(unsigned lane,uint32_t *p,uint32_t value) {
 while(__atomic_load_n(p,__ATOMIC_ACQUIRE)!=value) {
  uint32_t seq;assert(door_shm_pair_load(&handle,lane,&seq)==0);
  if(__atomic_load_n(p,__ATOMIC_ACQUIRE)==value)break;
  assert(door_shm_pair_wait(&handle,lane,seq,2000000000ULL)==0);
 }
}
static void *receive(void *arg) {
 (void)arg;for(uint32_t i=1;i<=100000;i++) {
  await(0,&payload,i);__atomic_store_n(&ack,i,__ATOMIC_RELEASE);
  assert(door_shm_pair_notify(&handle,1)==0);
 }return NULL;
}
static void *waiting(void *arg) {
 int *error=arg;
 *error=door_shm_pair_wait(&handle,0,words[0],2000000000ULL)==-1?errno:0;
 return NULL;
}
int main(void) {
 pthread_condattr_t attr;assert(pthread_condattr_init(&attr)==0);
 assert(pthread_condattr_setclock(&attr,CLOCK_MONOTONIC)==0);
 for(unsigned i=0;i<2;i++)assert(pthread_cond_init(&region.dr_pair_cv[i].value,&attr)==0);
 region.dr_flags=DOOR_SHM_F_PAIR;region.dr_pair_kva=(uintptr_t)words;
 region.dr_creator_vm=(void *)1;region.refs=1;
 assert(door_shm_pair_wait(&handle,0,0,0)==-1&&errno==ETIMEDOUT);
 assert(door_shm_pair_notify(&handle,1)==0&&words[0]==0&&words[16]==1);
 assert(door_shm_pair_wait(&handle,1,0,0)==0);
 struct door_ioc_shm_pair wire={.disp_version=DOOR_ABI_VERSION,.disp_region=1};
 struct proc outsider={.p_vmspace=(void *)2};struct thread other={.td_proc=&outsider};
 assert(door_shm_pair_op(&fixture,&wire,DOOR_SC_SHM_PAIR_WAKE,&other)==EPERM);
 pthread_t thread;assert(pthread_create(&thread,NULL,receive,NULL)==0);
 for(uint32_t i=1;i<=100000;i++) {
  __atomic_store_n(&payload,i,__ATOMIC_RELEASE);
  assert(door_shm_pair_notify(&handle,0)==0);await(1,&ack,i);
 }
 assert(pthread_join(thread,NULL)==0);assert(region.refs==1);
 puts("PASS: real kernel wait body + real library atomics, 100000 paired handshakes");
 for(unsigned revoke=0;revoke<2;revoke++) {
  region.dr_dead=false;fixture.d_revoked=false;registered=0;
  int error=0;assert(pthread_create(&thread,NULL,waiting,&error)==0);
  while(!__atomic_load_n(&registered,__ATOMIC_ACQUIRE))sched_yield();
  pthread_mutex_lock(&fixture.d_lock);region.dr_dead=true;fixture.d_revoked=revoke;
  for(unsigned i=0;i<2;i++)cv_broadcast(&region.dr_pair_cv[i]);
  pthread_mutex_unlock(&fixture.d_lock);assert(pthread_join(thread,NULL)==0);
  assert(error==(revoke?EBADF:ENOENT));assert(region.refs==1);
 }
 puts("PASS: registered waiters wake on invalidation, references balanced, outsider denied");
 return 0;
}
