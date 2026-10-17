/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "opt_global.h"
#include "opt_doorfs.h"
#ifdef DOORFS_TEST
#if !defined(INVARIANTS) || !defined(DOORFS)
#error "DOORFS_TEST requires INVARIANTS and built-in DOORFS"
#endif
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/condvar.h>
#include <sys/door_impl.h>
#include <sys/door_test.h>

static struct cdev *door_test_dev;
static struct mtx door_test_lock;
static struct cv door_test_cv;
static volatile u_int live[DOOR_TEST_NOBJECTS], async_jobs;
static struct door_test_control control;
static volatile u_int opened, state, released, entered, expired;

void
door_test_object_add(unsigned int type)
{
    KASSERT(type < DOOR_TEST_NOBJECTS, ("invalid test object type"));
    atomic_add_int(&live[type], 1);
}
void
door_test_object_drop(unsigned int type)
{
    KASSERT(type < DOOR_TEST_NOBJECTS &&
        atomic_load_acq_int(&live[type]) != 0, ("test object underflow"));
    atomic_subtract_int(&live[type], 1);
}
void
door_test_async_begin(void)
{
    atomic_add_int(&async_jobs, 1);
}
void
door_test_async_end(void)
{
    mtx_lock(&door_test_lock);
    KASSERT(atomic_load_acq_int(&async_jobs) != 0,
        ("test async job underflow"));
    atomic_subtract_int(&async_jobs, 1);
    cv_broadcast(&door_test_cv);
    mtx_unlock(&door_test_lock);
}
void
door_test_gc_gate(uint64_t object)
{
    int error;
    u_int start, elapsed;
    mtx_lock(&door_test_lock);
    if (atomic_load_acq_int(&state) != 1 ||
        control.stage != DOOR_TEST_NAMEFS_GC || control.object != object) {
        mtx_unlock(&door_test_lock);
        return;
    }
    atomic_store_rel_int(&state, 2);
    atomic_store_rel_int(&entered, 1);
    /* GC has no PREPARED intent: sleeping avoids monopolising a taskq CPU. */
    start = ticks;
    while (atomic_load_acq_int(&released) == 0) {
        elapsed = (u_int)(ticks - start);
        if (elapsed >= 15 * hz) {
            atomic_store_rel_int(&expired, 1);
            break;
        }
        error = cv_timedwait(&door_test_cv, &door_test_lock,
            15 * hz - elapsed);
        if (error == EWOULDBLOCK) {
            atomic_store_rel_int(&expired, 1);
            break;
        }
    }
    atomic_store_rel_int(&state, 0);
    mtx_unlock(&door_test_lock);
}

void
door_test_gc_done(uint64_t object)
{
    mtx_lock(&door_test_lock);
    if (control.stage == DOOR_TEST_NAMEFS_GC && control.object == object &&
        atomic_load_acq_int(&entered) != 0)
        control.finished = 1;
    mtx_unlock(&door_test_lock);
}

static bool
match(void)
{
    return (control.pid == curproc->p_pid &&
        (control.tid == 0 || control.tid == curthread->td_tid));
}

bool
door_test_cv_requested(void)
{
    bool requested;
    mtx_lock(&door_test_lock);
    requested = atomic_load_acq_int(&state) == 1 &&
        control.stage == DOOR_TEST_CV_PREPARK && match();
    mtx_unlock(&door_test_lock);
    return (requested);
}

void
door_test_gate(unsigned int stage)
{
    u_int start;

    mtx_lock(&door_test_lock);
    if (atomic_load_acq_int(&state) != 1 || control.stage != stage || !match()) {
        mtx_unlock(&door_test_lock);
        return;
    }
    atomic_store_rel_int(&state, 2);
    mtx_unlock(&door_test_lock);
    /* A normal CV sleep here could consume the PREPARED intent being tested.
     * Spin with interrupts enabled and no Door/thread/scheduler lock held.
     * Tests pin controller and subject to different CPUs. */
    start = ticks;
    atomic_store_rel_int(&entered, 1);
    while (atomic_load_acq_int(&released) == 0) {
        if ((u_int)(ticks - start) > 15 * hz) {
            atomic_store_rel_int(&expired, 1);
            break;
        }
        cpu_spinwait();
    }
    atomic_store_rel_int(&state, 0);
}

static void
door_test_close(void *unused __unused)
{
    mtx_lock(&door_test_lock);
    atomic_store_rel_int(&released, 1);
    (void)atomic_cmpset_rel_int(&state, 1, 0);
    atomic_store_rel_int(&opened, 0);
    cv_broadcast(&door_test_cv);
    mtx_unlock(&door_test_lock);
}

static int
door_test_open(struct cdev *dev __unused, int flags __unused,
    int type __unused, struct thread *td __unused)
{
    int error;

    if (!atomic_cmpset_acq_int(&opened, 0, 1))
        return (EBUSY);
    error = devfs_set_cdevpriv((void *)1, door_test_close);
    if (error != 0)
        atomic_store_rel_int(&opened, 0);
    return (error);
}

static int
door_test_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int flags __unused, struct thread *td)
{
    struct door_test_control *c;
    struct door_test_inspect *i;
    struct door_server_binding *ds;
    struct door *door;
    int error;

    if (cmd == DOOR_TEST_OBJECTS) {
        struct door_test_objects *o = (void *)data;
        for (unsigned int n = 0; n < DOOR_TEST_NOBJECTS; n++)
            o->live[n] = atomic_load_acq_int(&live[n]);
        o->async_jobs = atomic_load_acq_int(&async_jobs);
        return (0);
    }
    if (cmd == DOOR_TEST_DRAIN) {
        u_int start = ticks, elapsed;
        mtx_lock(&door_test_lock);
        error = 0;
        while (atomic_load_acq_int(&async_jobs) != 0 && error == 0) {
            elapsed = (u_int)(ticks - start);
            if (elapsed >= 10 * hz) {
                error = EWOULDBLOCK;
                break;
            }
            error = cv_timedwait_sig(&door_test_cv, &door_test_lock,
                10 * hz - elapsed);
        }
        mtx_unlock(&door_test_lock);
        return (error);
    }
    if (cmd == DOOR_TEST_INSPECT) {
        i = (void *)data;
        error = door_file_get(td, i->fd, &door);
        if (error != 0)
            return (error);
        mtx_lock(&door->d_lock);
        i->pending = door->d_pending_count;
        i->active = door->d_active_count;
        i->reserved = door->d_async_reserved;
        i->assigned = i->delivered = i->waiting = 0;
        LIST_FOREACH(ds, &door->d_servers, ds_link) {
            if (ds->ds_waiting)
                i->waiting++;
            if (ds->ds_call == NULL)
                continue;
            i->assigned++;
            if (ds->ds_call->dc_server_delivered)
                i->delivered++;
        }
        mtx_unlock(&door->d_lock);
        door_drop(door);
        return (0);
    }
    error = 0;
    mtx_lock(&door_test_lock);
    switch (cmd) {
    case DOOR_TEST_ARM:
        c = (void *)data;
        if (atomic_load_acq_int(&state) != 0) {
            error = EBUSY;
            break;
        }
        if (c->stage < DOOR_TEST_PREPARK ||
            c->stage > DOOR_TEST_REPLY_MOVE_CLOSE ||
            (c->stage != DOOR_TEST_NAMEFS_GC && c->pid <= 0) ||
            c->tid < 0 || c->reserved != 0) {
            error = EINVAL;
            break;
        }
        control = *c;
        control.padding = 0;
        control.finished = 0;
        atomic_store_rel_int(&entered, 0);
        atomic_store_rel_int(&expired, 0);
        atomic_store_rel_int(&released, 0);
        atomic_store_rel_int(&state, 1);
        break;
    case DOOR_TEST_STATE:
        c = (void *)data;
        *c = control;
        c->active = atomic_load_acq_int(&state) != 0;
        c->entered = atomic_load_acq_int(&entered);
        c->expired = atomic_load_acq_int(&expired);
        break;
    case DOOR_TEST_RELEASE:
        atomic_store_rel_int(&released, 1);
        cv_broadcast(&door_test_cv);
        (void)atomic_cmpset_rel_int(&state, 1, 0);
        break;
    default:
        error = ENOTTY;
    }
    mtx_unlock(&door_test_lock);
    return (error);
}

static struct cdevsw door_test_cdevsw = {
    .d_version = D_VERSION,
    .d_open = door_test_open,
    .d_ioctl = door_test_ioctl,
    .d_name = "door_test",
};
void
door_test_init(void)
{
    mtx_init(&door_test_lock, "door test", NULL, MTX_DEF);
    cv_init(&door_test_cv, "door test drain");
    door_test_dev = make_dev(&door_test_cdevsw, 0, UID_ROOT, GID_WHEEL,
        0600, "door_test");
}
bool
door_test_busy(void)
{
    return (atomic_load_acq_int(&opened) != 0 ||
        atomic_load_acq_int(&state) != 0 ||
        atomic_load_acq_int(&async_jobs) != 0);
}
void
door_test_fini(void)
{
    destroy_dev(door_test_dev);
    cv_destroy(&door_test_cv);
    mtx_destroy(&door_test_lock);
}
#endif
