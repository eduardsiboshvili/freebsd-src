/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/types.h>
#include <sys/cpuset.h>
#include <sys/ioctl.h>
#include <sys/thr.h>
#include <sys/door_test.h>
#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "door_raw.h"
#include "shm_cleanup.h"

static int probe, subject_cpu, controller_cpu, worker_cpu, second_client_cpu;
static void
pin(int cpu)
{
    cpuset_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    ATF_REQUIRE(cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
        sizeof(set), &set) == 0);
}
static void
phase_open(void)
{
    cpuset_t set;
    int i;
    ATF_REQUIRE(cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
        sizeof(set), &set) == 0);
    int cpus[4], count = 0;
    for (i = 0; i < CPU_SETSIZE && count < 4; i++)
        if (CPU_ISSET(i, &set))
            cpus[count++] = i;
    ATF_REQUIRE_MSG(count == 4, "Phase tests require four available CPUs");
    subject_cpu = cpus[0]; controller_cpu = cpus[1];
    worker_cpu = cpus[2]; second_client_cpu = cpus[3];
    pin(controller_cpu);
    probe = open("/dev/door_test", O_RDWR | O_CLOEXEC);
    ATF_REQUIRE_MSG(probe >= 0, "Build DOORFS_TEST kernel before running this suite");
}
static void
arm(unsigned stage, long tid)
{
    struct door_test_control c;
    memset(&c, 0, sizeof(c));
    c.stage = stage;
    c.pid = getpid();
    c.tid = tid;
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_ARM, &c) == 0);
}
static void
phase_entered(void)
{
    struct door_test_control c;
    int n;
    for (n = 0; n < 10000; n++) {
        ATF_REQUIRE(ioctl(probe, DOOR_TEST_STATE, &c) == 0);
        ATF_REQUIRE(!c.expired);
        if (c.entered)
            return;
        usleep(1000);
    }
    atf_tc_fail("Requested kernel phase was not reached");
}
static void
phase_release(void)
{
    struct door_test_control c;
    int n;
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_RELEASE) == 0);
    for (n = 0; n < 10000; n++) {
        ATF_REQUIRE(ioctl(probe, DOOR_TEST_STATE, &c) == 0);
        ATF_REQUIRE_MSG(!c.expired, "Kernel gate expired instead of being released");
        if (!c.active)
            return;
        usleep(1000);
    }
    atf_tc_fail("Kernel phase did not leave the gate");
}
static struct door_test_inspect
inspect(int fd)
{
    struct door_test_inspect i;
    memset(&i, 0, sizeof(i));
    i.fd = fd;
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_INSPECT, &i) == 0);
    return (i);
}
static void
wait_flag(atomic_int *flag)
{
    int n;
    for (n = 0; n < 10000; n++) {
        if (atomic_load(flag))
            return;
        usleep(1000);
    }
    atf_tc_fail("Fixture did not reach the expected state");
}

struct client {
    int fd, result, error, shm_call, cpu;
    long tid;
    atomic_int ready, go;
    door_shm_ref_t ref;
    char reply[16384];
    size_t reply_size;
};
static void *
client_run(void *arg)
{
    struct client *c = arg;
    door_arg_t a;
    pin(c->cpu);
    ATF_REQUIRE(thr_self(&c->tid) == 0);
    atomic_store(&c->ready, 1);
    wait_flag(&c->go);
    memset(&a, 0, sizeof(a));
    a.rbuf = c->reply;
    a.rsize = sizeof(c->reply);
    c->result = c->shm_call ? door_call_shm(c->fd, &c->ref) :
        door_call(c->fd, &a);
    c->error = errno;
    c->reply_size = a.data_size;
    return (NULL);
}
static void
client_start(struct client *c, pthread_t *t, int fd, int cpu)
{
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->cpu = cpu;
    ATF_REQUIRE(pthread_create(t, NULL, client_run, c) == 0);
    wait_flag(&c->ready);
}

struct worker {
    int fd, mode, result, error;
    atomic_int bound, received, finish, second, done;
    uint32_t flags;
    char *pages;
};
#define WORK_EMPTY 0
#define WORK_SHM_FAIL 1
#define WORK_PAGES 2
static void *
worker_run(void *arg)
{
    struct worker *w = arg;
    struct door_ioc_return_shm r;
    char input[64];
    uint64_t id;
    pin(worker_cpu);
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, w->fd, 0, 0, 0, 0) == 0);
    atomic_store(&w->bound, 1);
    raw_receive_init(&r, input, sizeof(input));
    w->result = (int)raw_return_shm(&r);
    w->error = errno;
    if (w->result == -1) {
        if (w->mode == WORK_SHM_FAIL)
            ATF_REQUIRE(raw_op(DOOR_SC_WORKER_EXIT, 0, 0, 0, 0, 0) == 0);
        atomic_store(&w->done, 1);
        return (NULL);
    }
    atomic_store(&w->received, 1);
    wait_flag(&w->finish);
    id = r.dirs_return.dir_call_id;
    raw_receive_init(&r, input, sizeof(input));
    r.dirs_return.dir_call_id = id;
    if (w->mode == WORK_PAGES) {
        memset(w->pages, 'A', 16384);
        r.dirs_return.dir_reply_ptr = (uintptr_t)w->pages;
        r.dirs_return.dir_reply_size = 16384;
    }
    w->result = (int)raw_return_shm(&r);
    w->error = errno;
    w->flags = r.dirs_return.dir_flags;
    if (w->mode == WORK_PAGES && w->result == 0 && r.dirs_return.dir_call_id) {
        /* The same backing buffer is reused only after fused RETURN installs
         * reply A. A queued second request must not bypass that barrier. */
        atomic_store(&w->second, 1);
        memset(w->pages, 'B', 16384);
        id = r.dirs_return.dir_call_id;
        raw_receive_init(&r, input, sizeof(input));
        r.dirs_return.dir_call_id = id;
        r.dirs_return.dir_reply_ptr = (uintptr_t)w->pages;
        r.dirs_return.dir_reply_size = 16384;
        w->result = (int)raw_return_shm(&r);
        w->error = errno;
    }
    atomic_store(&w->done, 1);
    return (NULL);
}
static void
worker_start(struct worker *w, pthread_t *t, int fd, int mode)
{
    memset(w, 0, sizeof(*w));
    w->fd = fd;
    w->mode = mode;
    if (mode == WORK_PAGES)
        ATF_REQUIRE(posix_memalign((void **)&w->pages, 4096, 16384) == 0);
    ATF_REQUIRE(pthread_create(t, NULL, worker_run, w) == 0);
    wait_flag(&w->bound);
}

static void
prepark(unsigned stage, bool revoke)
{
    struct client c;
    struct worker w;
    struct door_ioc_info info;
    pthread_t ct, wt;
    int fd, n;
    fd = raw_create(DOOR_NO_CANCEL);
    worker_start(&w, &wt, fd, WORK_EMPTY);
    /* Establish a concrete idle peer; BIND alone is insufficient for the old
     * private CV path, which requires a non-NULL peer for client waits. */
    for (n = 0; n < 10000; n++) {
        memset(&info, 0, sizeof(info));
        info.di_version = DOOR_ABI_VERSION;
        ATF_REQUIRE(raw_op(DOOR_SC_INFO, fd, (long)(uintptr_t)&info, 0, 0, 0) == 0);
        if (inspect(fd).waiting)
            break;
        usleep(1000);
    }
    ATF_REQUIRE(n != 10000);
    client_start(&c, &ct, fd, subject_cpu);
    arm(stage, c.tid);
    atomic_store(&c.go, 1);
    phase_entered();
    wait_flag(&w.received);
    if (revoke)
        ATF_REQUIRE(door_revoke(fd) == 0);
    atomic_store(&w.finish, 1);
    for (n = 0; n < 10000 && inspect(fd).active != 0; n++)
        usleep(1000);
    ATF_REQUIRE_EQ(inspect(fd).active, 0);
    phase_release();
    ATF_REQUIRE(pthread_join(ct, NULL) == 0);
    ATF_REQUIRE_EQ(c.result, revoke ? -1 : 0);
    if (revoke)
        ATF_REQUIRE_EQ(c.error, EBADF);
    else
        ATF_REQUIRE(door_revoke(fd) == 0);
    ATF_REQUIRE(pthread_join(wt, NULL) == 0);
    ATF_REQUIRE_EQ(inspect(fd).assigned, 0);
    ATF_REQUIRE(close(fd) == 0);
}
ATF_TC(prepark_completion_and_revoke);
ATF_TC_HEAD(prepark_completion_and_revoke, tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "90");
}
ATF_TC_BODY(prepark_completion_and_revoke, tc)
{
    (void)tc;
    phase_open();
    prepark(DOOR_TEST_PREPARK, false);
    prepark(DOOR_TEST_PREPARK, true);
    prepark(DOOR_TEST_CV_PREPARK, false);
    prepark(DOOR_TEST_CV_PREPARK, true);
    ATF_REQUIRE(close(probe) == 0);
}

ATF_TC(oneway_revoke_delivery_boundary);
ATF_TC_HEAD(oneway_revoke_delivery_boundary, tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "45");
}
ATF_TC_BODY(oneway_revoke_delivery_boundary, tc)
{
    struct worker w;
    struct door_test_inspect i;
    door_arg_t a;
    pthread_t wt;
    int fd, pass;
    (void)tc;
    phase_open();
    for (pass = 0; pass < 3; pass++) {
        fd = raw_create(DOOR_ONEWAY);
        memset(&a, 0, sizeof(a));
        if (pass == 0)
            arm(DOOR_TEST_EXPORT, 0);
        worker_start(&w, &wt, fd, WORK_EMPTY);
        ATF_REQUIRE(door_call(fd, &a) == 0);
        if (pass == 0) {
            phase_entered();
            i = inspect(fd);
            ATF_REQUIRE_EQ(i.assigned, 1);
            ATF_REQUIRE_EQ(i.delivered, 0);
            ATF_REQUIRE(door_revoke(fd) == 0);
            ATF_REQUIRE_EQ(inspect(fd).assigned, 0);
            phase_release();
        } else {
            wait_flag(&w.received);
            ATF_REQUIRE_EQ(inspect(fd).delivered, 1);
            ATF_REQUIRE(door_revoke(fd) == 0);
            atomic_store(&w.finish, 1);
        }
        ATF_REQUIRE(pthread_join(wt, NULL) == 0);
        if (pass == 0) {
            ATF_REQUIRE_EQ(atomic_load(&w.received), 0);
            ATF_REQUIRE(w.result == -1 && w.error == EBADF);
        } else {
            ATF_REQUIRE_EQ(w.result, 0);
            ATF_REQUIRE((w.flags & (DOOR_RETURN_F_COMPLETED | DOOR_RETURN_F_EXIT)) ==
                (DOOR_RETURN_F_COMPLETED | DOOR_RETURN_F_EXIT));
        }
        ATF_REQUIRE_EQ(inspect(fd).assigned, 0);
        ATF_REQUIRE_EQ(inspect(fd).active, 0);
        ATF_REQUIRE(close(fd) == 0);
    }
    ATF_REQUIRE(close(probe) == 0);
}

ATF_TC(shm_destroy_before_export);
ATF_TC_HEAD(shm_destroy_before_export, tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(shm_destroy_before_export, tc)
{
    struct worker w;
    struct client c;
    pthread_t wt, ct;
    door_shm_t shm, mapping;
    int fd;
    (void)tc;
    phase_open();
    fd = raw_create(0);
    ATF_REQUIRE(door_shm_create(fd, 4096, DOOR_SHM_RW, &shm) == 0);
    ATF_REQUIRE(door_shm_attach(fd, shm.dsh_region, DOOR_SHM_RW, &mapping) == 0);
    arm(DOOR_TEST_EXPORT, 0);
    worker_start(&w, &wt, fd, WORK_SHM_FAIL);
    client_start(&c, &ct, fd, subject_cpu);
    c.shm_call = 1;
    ATF_REQUIRE(door_shm_ref_init(&shm, 0, 64, &c.ref) == 0);
    atomic_store(&c.go, 1);
    phase_entered();
    ATF_REQUIRE_EQ(inspect(fd).assigned, 1);
    ATF_REQUIRE(door_shm_destroy_handle(&shm) == 0);
    memset(shm.dsh_addr, 0x5a, 64);
    ATF_REQUIRE(memcmp(shm.dsh_addr, mapping.dsh_addr, 64) == 0);
    phase_release();
    ATF_REQUIRE(pthread_join(wt, NULL) == 0);
    ATF_REQUIRE(w.result == -1 && w.error == ENXIO);
    ATF_REQUIRE_EQ(atomic_load(&w.received), 0);
    ATF_REQUIRE(pthread_join(ct, NULL) == 0);
    ATF_REQUIRE(c.result == -1 && c.error == ECONNRESET);
    ATF_REQUIRE_EQ(inspect(fd).assigned, 0);
    ATF_REQUIRE_EQ(inspect(fd).active, 0);
    ATF_REQUIRE(memcmp(shm.dsh_addr, mapping.dsh_addr, 64) == 0);
    test_shm_unmap_pair(&mapping, &shm);
    ATF_REQUIRE(door_revoke(fd) == 0);
    ATF_REQUIRE(close(fd) == 0);
    ATF_REQUIRE(close(probe) == 0);
}

ATF_TC(page_reply_install_before_reuse);
ATF_TC_HEAD(page_reply_install_before_reuse, tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(page_reply_install_before_reuse, tc)
{
    struct worker w;
    struct client first, second;
    pthread_t wt, ft, st;
    int fd, n;
    (void)tc;
    phase_open();
    fd = raw_create(0);
    worker_start(&w, &wt, fd, WORK_PAGES);
    client_start(&first, &ft, fd, subject_cpu);
    arm(DOOR_TEST_CLIENT_COPY, first.tid);
    atomic_store(&first.go, 1);
    wait_flag(&w.received);
    atomic_store(&w.finish, 1);
    phase_entered();
    client_start(&second, &st, fd, second_client_cpu);
    /* Only the first client's copy phase is gated. Queue request 2 while the
     * first reply still owns pages from the server's reusable buffer. */
    atomic_store(&second.go, 1);
    for (n = 0; n < 10000; n++) {
        struct door_test_inspect i = inspect(fd);
        if (i.pending + i.assigned != 0)
            break;
        usleep(1000);
    }
    ATF_REQUIRE(n != 10000);
    usleep(100000);
    ATF_REQUIRE_EQ(atomic_load(&w.second), 0);
    phase_release();
    ATF_REQUIRE(pthread_join(ft, NULL) == 0);
    ATF_REQUIRE_EQ(first.result, 0);
    ATF_REQUIRE_EQ(first.reply_size, sizeof(first.reply));
    for (n = 0; n < (int)sizeof(first.reply); n++)
        ATF_REQUIRE_EQ(first.reply[n], 'A');
    ATF_REQUIRE(pthread_join(st, NULL) == 0);
    ATF_REQUIRE_EQ(second.result, 0);
    for (n = 0; n < (int)sizeof(second.reply); n++)
        ATF_REQUIRE_EQ(second.reply[n], 'B');
    ATF_REQUIRE_EQ(atomic_load(&w.second), 1);
    ATF_REQUIRE(door_revoke(fd) == 0);
    ATF_REQUIRE(pthread_join(wt, NULL) == 0);
    ATF_REQUIRE_EQ(inspect(fd).assigned, 0);
    free(w.pages);
    ATF_REQUIRE(close(fd) == 0);
    ATF_REQUIRE(close(probe) == 0);
}


struct submit_close {
    door_async_t *ctx;
    long tid;
    pthread_t closer, callback_thread;
    atomic_int ready, go, close_started, close_done;
    int submit_result, close_result, status;
    unsigned callbacks;
    uint64_t submitted_id, completed_id;
};
static void
submit_close_completed(uint64_t id, int status, const void *data,
    size_t size, void *cookie)
{
    struct submit_close *f = cookie;
    ATF_REQUIRE(data == NULL && size == 0);
    f->callback_thread = pthread_self();
    f->completed_id = id;
    f->status = status;
    f->callbacks++;
}
static void *
paused_submit(void *cookie)
{
    struct submit_close *f = cookie;
    pin(subject_cpu);
    ATF_REQUIRE(thr_self(&f->tid) == 0);
    atomic_store(&f->ready, 1);
    wait_flag(&f->go);
    f->submit_result = door_async_submit(f->ctx, NULL, 0,
        submit_close_completed, f, &f->submitted_id);
    return (NULL);
}
static void *
close_during_submit(void *cookie)
{
    struct submit_close *f = cookie;
    atomic_store(&f->close_started, 1);
    f->close_result = door_async_close(f->ctx);
    atomic_store(&f->close_done, 1);
    return (NULL);
}
ATF_TC(async_close_during_reserved_submit);
ATF_TC_HEAD(async_close_during_reserved_submit, tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(async_close_during_reserved_submit, tc)
{
    struct submit_close f;
    pthread_t submitter;
    int fd;
    (void)tc;
    phase_open();
    memset(&f, 0, sizeof(f));
    atomic_init(&f.ready, 0); atomic_init(&f.go, 0);
    atomic_init(&f.close_started, 0); atomic_init(&f.close_done, 0);
    /* No request worker: completion cannot win the local close drain. */
    fd = raw_create(0);
    ATF_REQUIRE(door_async_open(fd, 1, &f.ctx) == 0);
    ATF_REQUIRE(pthread_create(&submitter, NULL, paused_submit, &f) == 0);
    wait_flag(&f.ready);
    arm(DOOR_TEST_ASYNC_RESERVED, f.tid);
    atomic_store(&f.go, 1);
    phase_entered();
    ATF_REQUIRE(pthread_create(&f.closer, NULL, close_during_submit, &f) == 0);
    wait_flag(&f.close_started);
    usleep(100000);
    ATF_REQUIRE_EQ(atomic_load(&f.close_done), 0);
    phase_release();
    ATF_REQUIRE(pthread_join(submitter, NULL) == 0);
    ATF_REQUIRE(pthread_join(f.closer, NULL) == 0);
    ATF_REQUIRE_EQ(f.submit_result, 0);
    ATF_REQUIRE_EQ(f.close_result, 0);
    ATF_REQUIRE_EQ(f.callbacks, 1);
    ATF_REQUIRE_EQ(f.status, ECANCELED);
    ATF_REQUIRE_EQ(f.completed_id, f.submitted_id);
    ATF_REQUIRE(pthread_equal(f.callback_thread, f.closer));
    ATF_REQUIRE(door_revoke(fd) == 0);
    ATF_REQUIRE_EQ(inspect(fd).pending, 0);
    ATF_REQUIRE(close(fd) == 0);
    ATF_REQUIRE(close(probe) == 0);
}

ATF_TC(async_revoke_before_delivery);
ATF_TC_HEAD(async_revoke_before_delivery, tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(async_revoke_before_delivery, tc)
{
    struct worker w;
    struct door_ioc_return_shm r;
    struct door_async_completion h;
    pthread_t wt;
    int fd, completion;
    (void)tc;
    phase_open();
    fd = raw_create(0);
    completion = raw_create(DOOR_ONEWAY);
    arm(DOOR_TEST_EXPORT, 0);
    worker_start(&w, &wt, fd, WORK_EMPTY);
    ATF_REQUIRE(raw_submit(fd, completion, 77, NULL, 0) == 0);
    phase_entered();
    ATF_REQUIRE_EQ(inspect(fd).assigned, 1);
    ATF_REQUIRE_EQ(atomic_load(&w.received), 0);
    ATF_REQUIRE(door_revoke(fd) == 0);
    phase_release();
    ATF_REQUIRE(pthread_join(wt, NULL) == 0);
    ATF_REQUIRE_EQ(atomic_load(&w.received), 0);
    ATF_REQUIRE(w.result == -1 && w.error == EBADF);
    ATF_REQUIRE_EQ(inspect(fd).assigned, 0);
    ATF_REQUIRE_EQ(inspect(fd).active, 0);
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_DRAIN) == 0);
    ATF_REQUIRE_EQ(inspect(completion).reserved, 0);
    ATF_REQUIRE_EQ(inspect(completion).pending, 1);
    raw_wait_pending(completion, 1);
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, completion, 0, 0, 0, 0) == 0);
    raw_receive_init(&r, &h, sizeof(h));
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    ATF_REQUIRE_EQ(r.dirs_return.dir_request_size, sizeof(h));
    ATF_REQUIRE(h.dac_call_id == 77 && h.dac_status == EBADF);
    ATF_REQUIRE_EQ(h.dac_data_size, 0);
    r.dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
    r.dirs_return.dir_request_size = sizeof(h);
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    ATF_REQUIRE((r.dirs_return.dir_flags & DOOR_RETURN_F_REWAIT) != 0);
    ATF_REQUIRE(raw_op(DOOR_SC_UNBIND, 0, 0, 0, 0, 0) == 0);
    ATF_REQUIRE(door_revoke(completion) == 0);
    ATF_REQUIRE(close(completion) == 0);
    ATF_REQUIRE(close(fd) == 0);
    ATF_REQUIRE(close(probe) == 0);
}

/* Revoke after receiver installation must not hide an installed MOVE fd. */
struct move_fixture {
    int fd, source, received, result, error, worker_result, worker_error;
    atomic_int bound, go, done;
};

static void *
move_worker(void *arg)
{
    struct move_fixture *f = arg;
    struct door_ioc_return_shm r;
    struct door_kdesc desc;
    char input[1];
    uint64_t id;

    pin(worker_cpu);
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, f->fd, 0, 0, 0, 0) == 0);
    atomic_store(&f->bound, 1);
    raw_receive_init(&r, input, sizeof(input));
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    id = r.dirs_return.dir_call_id;
    desc.dd_fd = f->source;
    desc.dd_flags = DOOR_DESC_F_MOVE;
    raw_receive_init(&r, input, sizeof(input));
    r.dirs_return.dir_call_id = id;
    r.dirs_return.dir_reply_desc_ptr = (uintptr_t)&desc;
    r.dirs_return.dir_reply_desc_count = 1;
    f->worker_result = (int)raw_return_shm(&r);
    f->worker_error = errno;
    return (NULL);
}

static void *
move_client(void *arg)
{
    struct move_fixture *f = arg;
    struct door_ioc_call c;

    pin(subject_cpu);
    wait_flag(&f->go);
    memset(&c, 0, sizeof(c));
    c.dic_version = DOOR_ABI_VERSION;
    c.dic_send_fd = -1;
    c.dic_recv_fd = -1;
    c.dic_recv_desc_count = 1;
    f->result = (int)raw_op(DOOR_SC_CALL, f->fd,
        (long)(uintptr_t)&c, 0, 0, 0);
    f->error = errno;
    f->received = c.dic_recv_fd;
    /* No operation capable of reusing the source fd precedes this check. */
    if (f->result == 0)
        ATF_REQUIRE_ERRNO(EBADF, fcntl(f->source, F_GETFD) == -1);
    atomic_store(&f->done, 1);
    return (NULL);
}

static void
reply_move_revoke(unsigned stage)
{
    struct move_fixture f;
    pthread_t worker, client;
    int pipefd[2];
    char byte;

    phase_open();
    memset(&f, 0, sizeof(f));
    f.received = -1;
    f.fd = raw_create(0);
    ATF_REQUIRE(pipe(pipefd) == 0);
    f.source = pipefd[0];
    ATF_REQUIRE(write(pipefd[1], "M", 1) == 1);
    ATF_REQUIRE(pthread_create(&worker, NULL, move_worker, &f) == 0);
    wait_flag(&f.bound);
    arm(stage, 0);
    ATF_REQUIRE(pthread_create(&client, NULL, move_client, &f) == 0);
    atomic_store(&f.go, 1);
    phase_entered();
    ATF_REQUIRE(fcntl(f.source, F_GETFD) != -1);
    ATF_REQUIRE(door_revoke(f.fd) == 0);
    ATF_REQUIRE_EQ(atomic_load(&f.done), 0);
    phase_release();
    ATF_REQUIRE(pthread_join(client, NULL) == 0);
    ATF_REQUIRE(pthread_join(worker, NULL) == 0);
    ATF_REQUIRE_MSG(f.result == 0, "CALL failed after MOVE installation: %d",
        f.error);
    ATF_REQUIRE(f.received >= 0 && f.received != f.source);
    ATF_REQUIRE(read(f.received, &byte, 1) == 1 && byte == 'M');
    ATF_REQUIRE(f.worker_result == -1 && f.worker_error == EBADF);
    ATF_REQUIRE(close(f.received) == 0);
    ATF_REQUIRE(close(pipefd[1]) == 0);
    ATF_REQUIRE(close(f.fd) == 0);
    ATF_REQUIRE(close(probe) == 0);
}

ATF_TC(reply_move_revoke_before_install_ack);
ATF_TC_HEAD(reply_move_revoke_before_install_ack, tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(reply_move_revoke_before_install_ack, tc)
{
    (void)tc;
    reply_move_revoke(DOOR_TEST_REPLY_MOVE_INSTALL);
}

ATF_TC(reply_move_revoke_before_source_close);
ATF_TC_HEAD(reply_move_revoke_before_source_close, tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(reply_move_revoke_before_source_close, tc)
{
    (void)tc;
    reply_move_revoke(DOOR_TEST_REPLY_MOVE_CLOSE);
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, async_close_during_reserved_submit);
    ATF_TP_ADD_TC(tp, async_revoke_before_delivery);
    ATF_TP_ADD_TC(tp, prepark_completion_and_revoke);
    ATF_TP_ADD_TC(tp, oneway_revoke_delivery_boundary);
    ATF_TP_ADD_TC(tp, shm_destroy_before_export);
    ATF_TP_ADD_TC(tp, page_reply_install_before_reuse);
    ATF_TP_ADD_TC(tp, reply_move_revoke_before_install_ack);
    ATF_TP_ADD_TC(tp, reply_move_revoke_before_source_close);
    return (atf_no_error());
}
