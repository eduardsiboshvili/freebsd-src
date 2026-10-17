/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/door_test.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "door_raw.h"
#include "shm_cleanup.h"

static int probe;
static void
metadata(atf_tc_t *tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "120");
}
static void
probe_open(void)
{
    probe = open("/dev/door_test", O_RDWR | O_CLOEXEC);
    ATF_REQUIRE_MSG(probe >= 0, "Build DOORFS_TEST kernel before running this suite");
}
static void
drain(void)
{
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_DRAIN) == 0);
}
static struct door_test_objects
objects(void)
{
    struct door_test_objects o;
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_OBJECTS, &o) == 0);
    return (o);
}
static void
live_increased(const struct door_test_objects *base, unsigned type,
    unsigned count)
{
    struct door_test_objects o = objects();
    ATF_REQUIRE_MSG(o.live[type] == base->live[type] + count,
        "Counter %u did not observe live resources: baseline %u, current %u",
        type, base->live[type], o.live[type]);
}
static void
baseline_restored(const struct door_test_objects *base)
{
    struct door_test_objects o;
    unsigned n;
    for (n = 0; n < 10000; n++) {
        o = objects();
        if (memcmp(&o, base, sizeof(o)) == 0)
            return;
        usleep(1000);
    }
    for (n = 0; n < DOOR_TEST_NOBJECTS; n++)
        ATF_CHECK_MSG(o.live[n] == base->live[n],
            "live object type %u: baseline %u, remaining %u", n,
            base->live[n], o.live[n]);
    ATF_REQUIRE_EQ(o.async_jobs, base->async_jobs);
    atf_tc_fail("Live objects did not return to baseline after teardown");
}
static void
empty_endpoint(int fd)
{
    struct door_test_inspect i;
    memset(&i, 0, sizeof(i));
    i.fd = fd;
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_INSPECT, &i) == 0);
    ATF_REQUIRE_EQ(i.pending, 0);
    ATF_REQUIRE_EQ(i.active, 0);
    ATF_REQUIRE_EQ(i.reserved, 0);
    ATF_REQUIRE_EQ(i.assigned, 0);
}
static void
completion_once(int fd, uint64_t id, int status)
{
    struct door_test_inspect i;
    struct door_ioc_return_shm r;
    struct door_async_completion h;
    memset(&i, 0, sizeof(i));
    i.fd = fd;
    /* A drained publisher must have exactly one event, not merely one
     * user callback after libdoor's pending-ID deduplication. */
    drain();
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_INSPECT, &i) == 0);
    ATF_REQUIRE_EQ(i.pending, 1);
    ATF_REQUIRE_EQ(i.reserved, 0);
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, fd, 0, 0, 0, 0) == 0);
    raw_receive_init(&r, &h, sizeof(h));
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    ATF_REQUIRE_EQ(r.dirs_return.dir_request_size, sizeof(h));
    ATF_REQUIRE_EQ(h.dac_version, DOOR_ABI_VERSION);
    ATF_REQUIRE_EQ(h.dac_call_id, id);
    ATF_REQUIRE_EQ(h.dac_data_size, 0);
    ATF_REQUIRE_EQ(h.dac_status, status);
    ATF_REQUIRE_EQ(h.dac_flags, status == ECANCELED ? DOOR_ASYNC_C_CANCELLED :
        status == EBADF ? DOOR_ASYNC_C_REVOKED :
        status == ECONNRESET ? DOOR_ASYNC_C_WORKER_EXIT : 0);
    r.dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
    r.dirs_return.dir_request_size = sizeof(h);
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    ATF_REQUIRE((r.dirs_return.dir_flags & DOOR_RETURN_F_REWAIT) != 0);
    ATF_REQUIRE(raw_op(DOOR_SC_UNBIND, 0, 0, 0, 0, 0) == 0);
    drain();
    empty_endpoint(fd);
}
struct ordered_worker {
    int fd, return_error;
    long return_result;
    uint32_t return_flags;
    atomic_int delivered, return_now;
};
static void
wait_flag(atomic_int *flag)
{
    for (unsigned n = 0; n < 10000; n++) {
        if (atomic_load(flag))
            return;
        usleep(1000);
    }
    atf_tc_fail("Worker did not reach the requested state");
}
static void *
ordered_return(void *cookie)
{
    struct ordered_worker *w = cookie;
    struct door_ioc_return_shm r;
    uint64_t id;
    ATF_REQUIRE(raw_op(DOOR_SC_BIND, w->fd, 0, 0, 0, 0) == 0);
    raw_receive_init(&r, NULL, 0);
    ATF_REQUIRE(raw_return_shm(&r) == 0);
    id = r.dirs_return.dir_call_id;
    ATF_REQUIRE(id != 0);
    atomic_store(&w->delivered, 1);
    wait_flag(&w->return_now);
    raw_receive_init(&r, NULL, 0);
    r.dirs_return.dir_call_id = id;
    /* Delivered async calls retain SERVER across cancel/revoke. RETURN
     * consumes that reference even when another operation won completion. */
    w->return_result = raw_return_shm(&r);
    w->return_error = w->return_result == -1 ? errno : 0;
    w->return_flags = r.dirs_return.dir_flags;
    (void)raw_op(DOOR_SC_WORKER_EXIT, 0, 0, 0, 0, 0);
    return (NULL);
}
/* Each syscall has returned before the next operation starts. These six
 * permutations guarantee all winners, unlike a repeated barrier race. */
static void
ordered_cases(unsigned winner)
{
    static const unsigned order[6][3] = {
        {0, 1, 2}, {0, 2, 1}, {1, 0, 2},
        {1, 2, 0}, {2, 0, 1}, {2, 1, 0}
    };
    static const int status[3] = {0, ECANCELED, EBADF};
    for (unsigned n = 2 * winner; n < 2 * winner + 2; n++) {
        struct ordered_worker w;
        pthread_t worker;
        int fd = raw_create(0), completion = raw_create(DOOR_ONEWAY);
        uint64_t id = n + 1;
        memset(&w, 0, sizeof(w));
        w.fd = fd;
        ATF_REQUIRE(raw_submit(fd, completion, id, NULL, 0) == 0);
        ATF_REQUIRE(pthread_create(&worker, NULL, ordered_return, &w) == 0);
        wait_flag(&w.delivered);
        for (unsigned step = 0; step < 3; step++) {
            switch (order[n][step]) {
            case 0:
                atomic_store(&w.return_now, 1);
                ATF_REQUIRE(pthread_join(worker, NULL) == 0);
                ATF_REQUIRE_MSG(w.return_result == 0,
                    "Order %u step %u: RETURN result %ld, errno %d",
                    n, step, w.return_result, w.return_error);
                ATF_REQUIRE_MSG((w.return_flags &
                    (DOOR_RETURN_F_COMPLETED | DOOR_RETURN_F_REWAIT)) ==
                    (DOOR_RETURN_F_COMPLETED | DOOR_RETURN_F_REWAIT),
                    "Order %u step %u: RETURN flags %#x", n, step,
                    w.return_flags);
                break;
            case 1: {
                long result = raw_op(DOOR_SC_ASYNC_CANCEL, fd, completion,
                    id, 0, 0);
                if (step == 0)
                    ATF_REQUIRE_EQ(result, 0);
                else
                    ATF_REQUIRE(result == -1 && (errno == ESRCH ||
                        errno == EALREADY || errno == EBADF));
                break;
            }
            case 2:
                ATF_REQUIRE(door_revoke(fd) == 0);
                break;
            }
        }
        completion_once(completion, id, status[winner]);
        empty_endpoint(fd);
        ATF_REQUIRE(door_revoke(completion) == 0);
        ATF_REQUIRE(close(fd) == 0);
        ATF_REQUIRE(close(completion) == 0);
    }
}
ATF_TC(async_return_first);
ATF_TC_HEAD(async_return_first, tc) { metadata(tc); }
ATF_TC_BODY(async_return_first, tc)
{
    (void)tc; probe_open(); ordered_cases(0); ATF_REQUIRE(close(probe) == 0);
}
ATF_TC(async_cancel_first);
ATF_TC_HEAD(async_cancel_first, tc) { metadata(tc); }
ATF_TC_BODY(async_cancel_first, tc)
{
    (void)tc; probe_open(); ordered_cases(1); ATF_REQUIRE(close(probe) == 0);
}
ATF_TC(async_revoke_first);
ATF_TC_HEAD(async_revoke_first, tc) { metadata(tc); }
ATF_TC_BODY(async_revoke_first, tc)
{
    (void)tc; probe_open(); ordered_cases(2); ATF_REQUIRE(close(probe) == 0);
}
ATF_TC(ipc_live_objects_after_cycles);
ATF_TC_HEAD(ipc_live_objects_after_cycles, tc) { metadata(tc); }
ATF_TC_BODY(ipc_live_objects_after_cycles, tc)
{
    struct door_test_objects base;
    (void)tc;
    probe_open(); drain(); base = objects();
    ATF_REQUIRE_EQ(base.async_jobs, 0);
    for (unsigned n = 0; n < 100; n++) {
        int fd = raw_create(0), completion = raw_create(DOOR_ONEWAY);
        struct door_ioc_return_shm r;
        door_shm_t a, b;
        int status;
        live_increased(&base, DOOR_TEST_OBJ_DOOR, 2);
        ATF_REQUIRE(door_shm_create(fd, 4096, DOOR_SHM_RW, &a) == 0);
        ATF_REQUIRE(door_shm_attach(fd, a.dsh_region, DOOR_SHM_RW, &b) == 0);
        live_increased(&base, DOOR_TEST_OBJ_SHM, 1);
        ATF_REQUIRE(door_shm_destroy_handle(&a) == 0);
        test_shm_unmap_pair(&a, &b);
        ATF_REQUIRE(raw_submit(fd, completion, n + 1, NULL, 0) == 0);
        live_increased(&base, DOOR_TEST_OBJ_CALL, 1);
        if (n % 5 == 0) {
            ATF_REQUIRE(raw_op(DOOR_SC_ASYNC_CANCEL, fd, completion,
                n + 1, 0, 0) == 0);
            status = ECANCELED;
        } else if (n % 5 == 1) {
            ATF_REQUIRE(door_revoke(fd) == 0);
            status = EBADF;
        } else if (n % 5 == 4) {
            /* Publication must also release reservations/origin refs when
             * the client has revoked its completion endpoint. */
            ATF_REQUIRE(door_revoke(completion) == 0);
            ATF_REQUIRE(door_revoke(fd) == 0);
            status = EBADF;
        } else {
            ATF_REQUIRE(raw_op(DOOR_SC_BIND, fd, 0, 0, 0, 0) == 0);
            live_increased(&base, DOOR_TEST_OBJ_BINDING, 1);
            raw_receive_init(&r, NULL, 0);
            ATF_REQUIRE(raw_return_shm(&r) == 0);
            ATF_REQUIRE(r.dirs_return.dir_call_id != 0);
            if (n % 5 == 3) {
                r.dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
                ATF_REQUIRE(raw_return_shm(&r) == 0);
                ATF_REQUIRE((r.dirs_return.dir_flags & DOOR_RETURN_F_REWAIT) != 0);
            }
            ATF_REQUIRE(raw_op(DOOR_SC_WORKER_EXIT, 0, 0, 0, 0, 0) == 0);
            status = n % 5 == 3 ? 0 : ECONNRESET;
        }
        if (n % 5 == 4) {
            drain(); empty_endpoint(fd); empty_endpoint(completion);
        } else
            completion_once(completion, n + 1, status);
        if (n % 5 != 1 && n % 5 != 4)
            ATF_REQUIRE(door_revoke(fd) == 0);
        if (n % 5 != 4)
            ATF_REQUIRE(door_revoke(completion) == 0);
        ATF_REQUIRE(close(fd) == 0);
        ATF_REQUIRE(close(completion) == 0);
        drain();
        /* Check every cycle, so compensating changes cannot mask growth. */
        baseline_restored(&base);
    }
    ATF_REQUIRE(close(probe) == 0);
}

static void
publication_create(const char *path, int fd)
{
    int file = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    ATF_REQUIRE(file >= 0);
    ATF_REQUIRE(close(file) == 0);
    ATF_REQUIRE(fattach(fd, path) == 0);
}
static uint64_t
publication_id(const char *path)
{
    struct statfs st;
    ATF_REQUIRE(statfs(path, &st) == 0);
    ATF_REQUIRE(strcmp(st.f_fstypename, "namefs") == 0);
    return (((uint64_t)(uint32_t)st.f_fsid.val[0] << 32) |
        (uint32_t)st.f_fsid.val[1]);
}
static void
gc_arm(const char *path)
{
    struct door_test_control c;
    memset(&c, 0, sizeof(c));
    c.stage = DOOR_TEST_NAMEFS_GC;
    c.object = publication_id(path);
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_ARM, &c) == 0);
}
static void
gc_wait(int finished)
{
    struct door_test_control c;
    for (unsigned n = 0; n < 10000; n++) {
        ATF_REQUIRE(ioctl(probe, DOOR_TEST_STATE, &c) == 0);
        ATF_REQUIRE_MSG(!c.expired, "Namefs GC gate expired");
        if (finished ? c.finished : c.entered)
            return;
        usleep(1000);
    }
    atf_tc_fail("Namefs GC did not %s", finished ? "finish evaluation" : "enter gate");
}
static void
wait_child(pid_t pid)
{
    int status;
    ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
    ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static void
kick_gc(void)
{
    /* namefs_process_exit() kicks all publications. No guessed sleep is
     * used to decide when the GC has begun examining the selected mount. */
    pid_t pid = fork();
    ATF_REQUIRE(pid >= 0);
    if (pid == 0)
        _exit(0);
    wait_child(pid);
}
static void
publication_gone(const char *path, const struct door_test_objects *base)
{
    struct statfs st;
    struct door_test_objects o;
    /* Repeated statfs takes VFS references/busy state on the very mount the
     * GC is trying to unmount. Observe teardown without touching that mount. */
    for (unsigned n = 0; n < 10000; n++) {
        o = objects();
        if (o.live[DOOR_TEST_OBJ_MOUNT] == base->live[DOOR_TEST_OBJ_MOUNT] &&
            o.live[DOOR_TEST_OBJ_GC] == base->live[DOOR_TEST_OBJ_GC] &&
            o.live[DOOR_TEST_OBJ_GC_PIN] == base->live[DOOR_TEST_OBJ_GC_PIN]) {
            ATF_REQUIRE(statfs(path, &st) == 0);
            ATF_REQUIRE_MSG(strcmp(st.f_fstypename, "namefs") != 0,
                "Namefs objects disappeared but publication remains mounted");
            return;
        }
        usleep(1000);
    }
    atf_tc_fail("Orphaned Namefs publication was not automatically unmounted: "
        "mounts %u/%u, GC %u/%u, GC pins %u/%u (current/baseline)",
        o.live[DOOR_TEST_OBJ_MOUNT], base->live[DOOR_TEST_OBJ_MOUNT],
        o.live[DOOR_TEST_OBJ_GC], base->live[DOOR_TEST_OBJ_GC],
        o.live[DOOR_TEST_OBJ_GC_PIN], base->live[DOOR_TEST_OBJ_GC_PIN]);
}
static void
publication_cleanup(const char *path)
{
    /* This only runs in the ATF case's private work directory. */
    (void)fdetach(path);
    (void)unlink(path);
}
static void
rebind_while_gc_paused(const char *path)
{
    door_info_t info, old_info, new_info;
    struct door_test_objects base = objects();
    uint64_t fsid;
    int old = raw_create(0), replacement, anchor, client;
    publication_create(path, old);
    live_increased(&base, DOOR_TEST_OBJ_MOUNT, 1);
    live_increased(&base, DOOR_TEST_OBJ_GC, 1);
    fsid = publication_id(path);
    ATF_REQUIRE(door_info(old, &old_info) == 0);
    anchor = open(path, O_PATH | O_CLOEXEC);
    ATF_REQUIRE(anchor >= 0);
    gc_arm(path);
    /* Leave only the mount's reference to the original target file. The
     * O_PATH vnode anchor keeps the recovery publication available. */
    ATF_REQUIRE(door_revoke(old) == 0);
    ATF_REQUIRE(close(old) == 0);
    kick_gc(); gc_wait(0);
    live_increased(&base, DOOR_TEST_OBJ_GC_PIN, 1);
    replacement = raw_create(0);
    ATF_REQUIRE(door_info(replacement, &new_info) == 0);
    ATF_REQUIRE(new_info.di_uniquifier != old_info.di_uniquifier);
    ATF_REQUIRE(fattach(replacement, path) == 0);
    ATF_REQUIRE_EQ(publication_id(path), fsid);
    /* Remove the recovery anchor before GC evaluates. Otherwise an erroneous
     * stale-target orphan decision could be hidden by this vnode reference. */
    ATF_REQUIRE(close(anchor) == 0);
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_RELEASE) == 0);
    gc_wait(1);
    /* Confirmation follows orphan evaluation, not just release of the gate. */
    ATF_REQUIRE_EQ(publication_id(path), fsid);
    client = open(path, O_RDWR | O_CLOEXEC);
    ATF_REQUIRE(client >= 0);
    ATF_REQUIRE(door_info(client, &info) == 0);
    ATF_REQUIRE_EQ(info.di_uniquifier, new_info.di_uniquifier);
    ATF_REQUIRE(close(client) == 0);
    ATF_REQUIRE(fdetach(path) == 0);
    ATF_REQUIRE(door_revoke(replacement) == 0);
    ATF_REQUIRE(close(replacement) == 0);
    ATF_REQUIRE(unlink(path) == 0);
}
ATF_TC_WITH_CLEANUP(namefs_gc_rebind);
ATF_TC_HEAD(namefs_gc_rebind, tc) { metadata(tc); }
ATF_TC_BODY(namefs_gc_rebind, tc)
{
    struct door_test_objects base;
    (void)tc;
    probe_open(); drain(); base = objects();
    rebind_while_gc_paused("gc-rebind");
    baseline_restored(&base);
    ATF_REQUIRE(close(probe) == 0);
}
ATF_TC_CLEANUP(namefs_gc_rebind, tc)
{
    (void)tc; publication_cleanup("gc-rebind");
}
/* A dup or inherited descriptor references the exact struct file owned by
 * the mount. It must defer orphaning even with no external vnode anchor. */
static void
held_target_defers_gc(const char *path, int inherited)
{
    struct door_test_objects base;
    int fd, held, command[2], ready[2];
    pid_t child = -1;
    char byte = 'x';
    drain(); base = objects();
    fd = raw_create(0);
    publication_create(path, fd);
    live_increased(&base, DOOR_TEST_OBJ_MOUNT, 1);
    live_increased(&base, DOOR_TEST_OBJ_GC, 1);
    held = dup(fd);
    ATF_REQUIRE(held >= 0);
    if (inherited) {
        ATF_REQUIRE(pipe(command) == 0 && pipe(ready) == 0);
        child = fork();
        ATF_REQUIRE(child >= 0);
        if (child == 0) {
            close(command[1]); close(ready[0]); close(fd);
            if (write(ready[1], &byte, 1) != 1)
                _exit(1);
            close(ready[1]);
            /* EOF also exits if an assertion kills the ATF parent. */
            (void)read(command[0], &byte, 1);
            close(held); close(command[0]);
            _exit(0);
        }
        close(command[0]); close(ready[1]);
        ATF_REQUIRE(read(ready[0], &byte, 1) == 1);
        ATF_REQUIRE(close(ready[0]) == 0);
        ATF_REQUIRE(close(held) == 0);
    }
    gc_arm(path);
    ATF_REQUIRE(door_revoke(fd) == 0);
    ATF_REQUIRE(close(fd) == 0);
    kick_gc(); gc_wait(0);
    live_increased(&base, DOOR_TEST_OBJ_GC_PIN, 1);
    ATF_REQUIRE(ioctl(probe, DOOR_TEST_RELEASE) == 0);
    gc_wait(1);
    (void)publication_id(path);
    /* No O_PATH or reopened client hides an orphan by pinning the vnode. */
    if (inherited) {
        ATF_REQUIRE(write(command[1], &byte, 1) == 1);
        ATF_REQUIRE(close(command[1]) == 0);
        wait_child(child);
    } else {
        ATF_REQUIRE(close(held) == 0);
        kick_gc();
    }
    publication_gone(path, &base);
    ATF_REQUIRE(unlink(path) == 0);
    baseline_restored(&base);
}
ATF_TC_WITH_CLEANUP(namefs_gc_waits_dup_target);
ATF_TC_HEAD(namefs_gc_waits_dup_target, tc) { metadata(tc); }
ATF_TC_BODY(namefs_gc_waits_dup_target, tc)
{
    (void)tc; probe_open(); held_target_defers_gc("gc-dup", 0);
    ATF_REQUIRE(close(probe) == 0);
}
ATF_TC_CLEANUP(namefs_gc_waits_dup_target, tc)
{
    (void)tc; publication_cleanup("gc-dup");
}
ATF_TC_WITH_CLEANUP(namefs_gc_waits_inherited_target);
ATF_TC_HEAD(namefs_gc_waits_inherited_target, tc) { metadata(tc); }
ATF_TC_BODY(namefs_gc_waits_inherited_target, tc)
{
    (void)tc; probe_open(); held_target_defers_gc("gc-inherited", 1);
    ATF_REQUIRE(close(probe) == 0);
}
ATF_TC_CLEANUP(namefs_gc_waits_inherited_target, tc)
{
    (void)tc; publication_cleanup("gc-inherited");
}
ATF_TC_WITH_CLEANUP(namefs_live_objects_after_cycles);
ATF_TC_HEAD(namefs_live_objects_after_cycles, tc) { metadata(tc); }
ATF_TC_BODY(namefs_live_objects_after_cycles, tc)
{
    struct door_test_objects base;
    (void)tc;
    probe_open(); drain(); base = objects();
    for (unsigned n = 0; n < 30; n++) {
        if (n % 2 == 0)
            rebind_while_gc_paused("gc-cycles");
        else
            held_target_defers_gc("gc-cycles", 0);
        baseline_restored(&base);
    }
    ATF_REQUIRE(close(probe) == 0);
}
ATF_TC_CLEANUP(namefs_live_objects_after_cycles, tc)
{
    (void)tc; publication_cleanup("gc-cycles");
}
ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, async_return_first);
    ATF_TP_ADD_TC(tp, async_cancel_first);
    ATF_TP_ADD_TC(tp, async_revoke_first);
    ATF_TP_ADD_TC(tp, ipc_live_objects_after_cycles);
    ATF_TP_ADD_TC(tp, namefs_gc_rebind);
    ATF_TP_ADD_TC(tp, namefs_gc_waits_dup_target);
    ATF_TP_ADD_TC(tp, namefs_gc_waits_inherited_target);
    ATF_TP_ADD_TC(tp, namefs_live_objects_after_cycles);
    return (atf_no_error());
}
