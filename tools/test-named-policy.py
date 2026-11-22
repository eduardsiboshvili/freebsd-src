#!/usr/bin/env python3
"""Actual policy/install/clone helpers with modeled kernel services; not native ATF."""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ctl = (ROOT / 'sys/fs/doorfs/door_ctl.c').read_text()
file = (ROOT / 'sys/fs/doorfs/door_file.c').read_text()
core = (ROOT / 'sys/sys/door_core.h').read_text()
public = (ROOT / 'include/door.h').read_text()


def extract(source, name):
    match = re.search(r'(?m)^(?:static int|static void|int|bool)\n' + name +
                      r'\(.*?^\}', source, re.M | re.S)
    assert match, name
    return match[0]


for name in ('NO_PASS', 'CONNECT_ONCE'):
    assert re.search(r'DOOR_NAMED_F_' + name + r'\s+(0x[0-9a-fA-F]+)U', core)[1] == \
        re.search(r'DOOR_NAMED_' + name + r'\s+(0x[0-9a-fA-F]+)U', public)[1]
assert ctl.count('newent->dne_policy = policy;') == 2
assert ctl.count('refcount_acquire(&e->dne_policy->dnp_refs);') == 2
assert 'door_named_policy_drop(e->dne_policy);' in ctl
rpc = (ROOT / 'sys/fs/doorfs/door_rpc.c').read_text()
assert 'fp->f_ops->fo_flags & DFLAG_PASSABLE' in rpc
assert file.count('static const struct fileops door_client_nopass_fileops') == 1
assert re.search(r'door_client_nopass_fileops = \{.*?\.fo_fork = door_client_nopass_fork,\s*\.fo_flags = DFLAG_FORK,', file, re.S)

prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
typedef unsigned int u_int;
#define DOOR_NAMED_F_NO_PASS 2u
#define DOOR_NAMED_F_CONNECT_ONCE 4u
#define DOOR_CTL_ABI_VERSION 1u
#define DOOR_NAME_MAX 128
#define M_DOORFS 0
#define FREAD 1
#define FWRITE 2
#define DTYPE_DOOR 99
#define DFLAG_PASSABLE 1
#define DFLAG_FORK 4
#define __unused __attribute__((unused))
struct filedesc;
struct proc;
struct ucred { int jid; };
struct prison { int pr_id; };
struct owner_cred { struct prison *cr_prison; };
struct thread { struct ucred *td_ucred; };
struct door { int d_lock; bool d_revoked; struct owner_cred *d_owner_cred;
    uint64_t d_uniquifier; int refs, clients; };
struct fileops { int fo_flags; };
struct file { const struct fileops *f_ops; void *f_data; int f_type; int holds; };
static bool fhold(struct file *fp) { if(fp->holds<0)return false; fp->holds++;return true; }
struct door_ctl_connect { uint32_t dcc_version, dcc_flags;
    int dcc_fd, dcc_target_jid; uint64_t dcc_uniquifier; char dcc_name[128]; };
static const struct fileops door_fileops={1},door_client_fileops={1},
    door_client_nopass_fileops={DFLAG_FORK};
struct door_named_policy { u_int dnp_refs; uint32_t dnp_flags; volatile u_int dnp_claimed; };
static int freed;
static void policy_free(void *p) { freed++; free(p); }
#define free(p,type) policy_free(p)
static bool refcount_release(u_int *v) { return __atomic_sub_fetch(v,1,__ATOMIC_ACQ_REL)==0; }
static void refcount_acquire(u_int *v) { __atomic_add_fetch(v,1,__ATOMIC_RELAXED); }
static bool atomic_cmpset_int(volatile u_int *v,u_int old,u_int value) {
    return __atomic_compare_exchange_n(v,&old,value,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
static void atomic_store_rel_int(volatile u_int *v,u_int value) { __atomic_store_n(v,value,__ATOMIC_RELEASE); }
static void mtx_lock(int *p) { (void)p; }
static void mtx_unlock(int *p) { (void)p; }
static void door_hold(struct door *d) { __atomic_add_fetch(&d->refs,1,__ATOMIC_RELAXED); }
static void door_drop(struct door *d) { assert(__atomic_sub_fetch(&d->refs,1,__ATOMIC_RELAXED)>=0); }
static void door_client_closed(struct door *d) { assert(--d->clients>=0); }
static int door_client_open(struct door *d) { if(d->d_revoked)return EBADF; d->clients++; return 0; }
static int door_check_jail(struct door *d,struct ucred *cred) { (void)d; return cred->jid?EPERM:0; }
static struct file *installed;
static int install_error;
static void (*install_hook)(void);
static int falloc(struct thread *td,struct file **fp,int *fd,int flags) {
    (void)td;(void)flags;
    if(install_hook)install_hook();
    if(install_error)return install_error;
    assert(installed==NULL);installed=calloc(1,sizeof(*installed));assert(installed);
    *fp=installed;*fd=7;return 0;
}
static void finit(struct file *fp,int flags,int type,void *data,const struct fileops *ops) {
    (void)flags;fp->f_type=type;fp->f_data=data;fp->f_ops=ops;
}
static void fdrop(struct file *fp,struct thread *td) { (void)fp;(void)td; }
static void close_installed(void) {
    assert(installed);struct door *d=installed->f_data;door_client_closed(d);door_drop(d);
    /* Not a policy allocation. */
    void *p=installed;installed=NULL;
    #undef free
    free(p);
    #define free(p,type) policy_free(p)
}
static struct door endpoint={.d_uniquifier=123,.refs=1};
static struct door_named_policy *current_policy;
static int door_name_validate(const char *name) { return name[0]?0:EINVAL; }
static struct door *door_named_lookup_hold(const char *name,struct ucred *cred,
    struct door_named_policy **p) {
    (void)name;(void)cred;door_hold(&endpoint);*p=current_policy;
    refcount_acquire(&(*p)->dnp_refs);return &endpoint;
}
'''
helpers = '\n\n'.join([
    extract(ctl, 'door_named_policy_drop'),
    extract(ctl, 'door_named_policy_claim'),
    extract(ctl, 'door_named_policy_rollback'),
    extract(file, 'door_client_nopass_fork'),
    extract(file, 'door_file_is_door'),
    extract(file, 'door_client_file_install_policy'),
    extract(file, 'door_client_file_install'),
    extract(file, 'door_file_clone'),
    extract(ctl, 'door_named_connect'),
])
body = r'''
static struct door_named_policy *policy(uint32_t flags) {
    struct door_named_policy *p=calloc(1,sizeof(*p));assert(p);p->dnp_refs=1;p->dnp_flags=flags;return p;
}
struct race { struct door_named_policy *policy; bool won; };
static void *claim(void *arg) { struct race *r=arg;r->won=door_named_policy_claim(r->policy)==0;return NULL; }
static void replace_during_install(void) {
    install_hook=NULL;
    struct door_named_policy *old=current_policy;
    current_policy=policy(DOOR_NAMED_F_CONNECT_ONCE);
    /* Registry drops its reference while CONNECT still owns the old policy. */
    door_named_policy_drop(old);
}
int main(void) {
    struct ucred cred={0};struct thread td={&cred};
    struct door_ctl_connect arg={.dcc_version=1,.dcc_name="service"};
    current_policy=policy(DOOR_NAMED_F_CONNECT_ONCE|DOOR_NAMED_F_NO_PASS);
    install_error=EMFILE;
    assert(door_named_connect(&arg,&td)==EMFILE);
    assert(current_policy->dnp_claimed==0&&endpoint.clients==0&&endpoint.refs==1);
    install_error=0;
    assert(door_named_connect(&arg,&td)==0&&arg.dcc_fd==7);
    assert(installed->f_ops==&door_client_nopass_fileops);
    assert(door_file_is_door(installed));
    struct file *inherited=NULL;
    assert((installed->f_ops->fo_flags&DFLAG_PASSABLE)==0);
    assert((installed->f_ops->fo_flags&DFLAG_FORK)!=0);
    assert(door_client_nopass_fork(NULL,installed,&inherited,NULL,&td)==0);
    assert(inherited==installed&&installed->holds==1);
    assert(door_client_nopass_fork(NULL,NULL,&inherited,NULL,&td)==0);
    assert(inherited==installed&&installed->holds==1);
    inherited->holds--; /* inherited reference dropped */
    struct file dead={.holds=-1};inherited=NULL;
    assert(door_client_nopass_fork(NULL,&dead,&inherited,NULL,&td)==EBADF);
    assert(inherited==NULL);
    assert(door_named_connect(&arg,&td)==EACCES);
    struct file clone={0};
    assert(door_file_clone(installed,&clone,FREAD|FWRITE,&cred)==0);
    assert(clone.f_ops==&door_client_nopass_fileops);
    door_client_closed(&endpoint);door_drop(&endpoint);
    close_installed();
    assert(current_policy->dnp_claimed==1); /* close does not refund issuance */
    door_named_policy_drop(current_policy);

    current_policy=policy(DOOR_NAMED_F_CONNECT_ONCE);
    cred.jid=1;assert(door_named_connect(&arg,&td)==EPERM);
    assert(current_policy->dnp_claimed==0);cred.jid=0;
    endpoint.d_revoked=true;assert(door_named_connect(&arg,&td)==EBADF);
    assert(current_policy->dnp_claimed==0);endpoint.d_revoked=false;
    assert(door_named_connect(&arg,&td)==0);
    assert(installed->f_ops==&door_client_fileops);close_installed();
    door_named_policy_drop(current_policy);

    /* Independent generation replacement while installation fails. */
    current_policy=policy(DOOR_NAMED_F_CONNECT_ONCE);
    int before=freed;install_hook=replace_during_install;install_error=EMFILE;
    assert(door_named_connect(&arg,&td)==EMFILE);
    assert(freed==before+1&&current_policy->dnp_claimed==0);
    install_error=0;assert(door_named_connect(&arg,&td)==0);close_installed();
    door_named_policy_drop(current_policy);

    for(unsigned round=0;round<100;round++) {
        struct door_named_policy *p=policy(DOOR_NAMED_F_CONNECT_ONCE);
        pthread_t threads[8];struct race races[8];unsigned wins=0;
        for(unsigned i=0;i<8;i++) {
            races[i]=(struct race){p,false};assert(pthread_create(&threads[i],NULL,claim,&races[i])==0);
        }
        for(unsigned i=0;i<8;i++) { assert(pthread_join(threads[i],NULL)==0);wins+=races[i].won; }
        assert(wins==1);door_named_policy_drop(p);
    }
    current_policy=policy(0);
    for(unsigned i=0;i<2;i++) { assert(door_named_connect(&arg,&td)==0);close_installed(); }
    door_named_policy_drop(current_policy);
    int fd;
    assert(door_client_file_install(&td,&endpoint,&fd)==0);
    assert(installed->f_ops==&door_client_fileops);close_installed();
    assert(endpoint.refs==1&&endpoint.clients==0);
    puts("PASS: actual policy/connect/install/clone helpers: atomic issuance, rollback, generation lifetime and immutable passability");
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='door-policy-model-') as tmp:
    path = Path(tmp) / 'model.c'
    binary = Path(tmp) / 'model'
    path.write_text(prefix + helpers + body)
    cmd = shlex.split(os.environ.get('CC', 'cc'))
    cmd += ['-std=gnu17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread']
    cmd += shlex.split(os.environ.get('MODEL_CFLAGS', ''))
    subprocess.run(cmd + [str(path), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print('PASS: public/kernel flags, generation swaps and existing Door transfer gate')
