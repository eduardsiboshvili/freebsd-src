/*-
 * Copyright (c) 2026 Eduard Siboshvili
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct state {
    door_async_t *ctx;
    pthread_t dispatcher;
    unsigned count, mask;
    int status, fd;
    bool reenter;
};

static atomic_int entered, release_service, finished, move_source;

static void
service(void *cookie, char *data, size_t size, door_desc_t *desc, uint_t count)
{
    (void)cookie;
    (void)desc;
    (void)count;
    if (size != 0 && data[0] == 'B') {
        struct timespec pause = {0, 1000000};
        atomic_store(&entered, 1);
        while (!atomic_load(&release_service))
            nanosleep(&pause, NULL);
    }

    if (size != 0 && data[0] == 'F') {
        door_desc_t result;
        int fd = open("/dev/null", O_RDWR);
        if (fd == -1)
            _exit(41);

        atomic_store(&move_source, fd);
        memset(&result, 0, sizeof(result));
        result.d_attributes = DOOR_DESCRIPTOR | DOOR_RELEASE;
        result.d_descriptor = fd;
        (void)door_return(data, size, &result, 1);
    } else {
        (void)door_return(data, size, NULL, 0);
    }

    atomic_store(&finished, 1);
}

static int
threads(void)
{
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc kp;
    size_t size = sizeof(kp);
    ATF_REQUIRE_EQ(sysctl(mib, 4, &kp, &size, NULL, 0), 0);
    ATF_REQUIRE_EQ(size, sizeof(kp));
    return (kp.ki_numthreads);
}

static void
complete(uint64_t id, int status, const void *data, size_t size, void *cookie)
{
    struct state *s = cookie;
    ATF_REQUIRE(id != 0);
    ATF_REQUIRE(pthread_equal(s->dispatcher, pthread_self()));
    s->count++;
    s->status = status;
    if (status == 0 && size == 16) {
        const unsigned char *bytes = data;
        unsigned sequence = bytes[1];
        ATF_REQUIRE(sequence < 16);
        ATF_REQUIRE((s->mask & (1U << sequence)) == 0);
        for (size_t i = 2; i < size; i++)
            ATF_REQUIRE_EQ(bytes[i], (unsigned char)(sequence + i));
        s->mask |= 1U << sequence;
    }

    if (s->reenter) {
        s->reenter = false;
        errno = 0;
        ATF_REQUIRE_EQ(door_async_dispatch(s->ctx, 1), -1);
        ATF_REQUIRE_EQ(errno, EBUSY);
        ATF_REQUIRE_EQ(door_async_close(s->ctx), -1);
        ATF_REQUIRE_EQ(errno, EINVAL);
        uint64_t next;
        char request = 'R';
        ATF_REQUIRE_EQ(door_async_submit(s->ctx, &request, 1, complete, s, &next), 0);
    }
}

static void
complete_fd(uint64_t id, int status, const void *data, size_t size,
    door_desc_t *descriptors, uint_t count, void *cookie)
{
    struct state *s = cookie;
    ATF_REQUIRE_EQ(status, 0);
    ATF_REQUIRE_EQ(count, 1);
    s->fd = descriptors[0].d_descriptor;
    ATF_REQUIRE(fcntl(s->fd, F_GETFD) != -1);
    ATF_REQUIRE_EQ(fcntl(atomic_load(&move_source), F_GETFD), -1);
    ATF_REQUIRE_EQ(errno, EBADF);
    complete(id, status, data, size, cookie);
}

static int
setup(struct state *s, int *server)
{
    memset(s, 0, sizeof(*s));
    s->dispatcher = pthread_self();
    s->fd = -1;
    *server = door_create(service, NULL, DOOR_PRIVATE | DOOR_NO_DEPLETION_CB);
    ATF_REQUIRE(*server != -1);
    int before = threads();
    ATF_REQUIRE_EQ(door_async_open_poll(*server, 16, &s->ctx), 0);
    ATF_REQUIRE_EQ(threads(), before);
    int queue = kqueue();
    ATF_REQUIRE(queue != -1);
    struct kevent event;
    EV_SET(&event, door_async_poll_fd(s->ctx), EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
    ATF_REQUIRE_EQ(kevent(queue, &event, 1, NULL, 0, NULL), 0);
    return (queue);
}

static void
ready(int queue)
{
    struct kevent event;
    struct timespec deadline = {10, 0};
    ATF_REQUIRE_EQ(kevent(queue, NULL, 0, &event, 1, &deadline), 1);
    ATF_REQUIRE_EQ(event.filter, EVFILT_READ);
    ATF_REQUIRE((event.flags & EV_ERROR) == 0);
}

static void
pump(struct state *s, int queue, unsigned target)
{
    while (s->count < target) {
        int count = door_async_dispatch(s->ctx, 4);
        ATF_REQUIRE(count >= 0);
        if (count == 0)
            ready(queue);
    }
}

static void
cleanup(struct state *s, int queue, int server)
{
    ATF_REQUIRE_EQ(door_async_close(s->ctx), 0);
    ATF_REQUIRE_EQ(close(queue), 0);
    ATF_REQUIRE_EQ(door_revoke(server), 0);
    ATF_REQUIRE_EQ(close(server), 0);
}

ATF_TC(poll_snapshot_budget_no_workers);
ATF_TC_HEAD(poll_snapshot_budget_no_workers, tc)
{
    atf_tc_set_md_var(tc, "descr", "kqueue readiness, caller callbacks, snapshots and bounded dispatch");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(poll_snapshot_budget_no_workers, tc)
{
    (void)tc;
    struct state s;
    int server, queue = setup(&s, &server);
    int before = threads();
    int inherited = door_async_poll_fd(s.ctx);
    pid_t child = fork();
    ATF_REQUIRE(child != -1);
    if (child == 0) {
        char buffer[128];
        if (read(inherited, buffer, sizeof(buffer)) != -1 || errno != EPERM)
            _exit(50);
        errno = 0;
        int fd = door_async_poll_fd(s.ctx); /* Inherited context is rejected. */
        if (fd != -1 || errno != EINVAL)
            _exit(51);
        _exit(0);
    }
    int status;
    ATF_REQUIRE_EQ(waitpid(child, &status, 0), child);
    ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    ATF_REQUIRE_EQ(door_oneway(inherited, NULL, 0), -1);
    ATF_REQUIRE_EQ(errno, EOPNOTSUPP);
    unsigned char bytes[16];
    uint64_t id;
    for (unsigned sequence = 0; sequence < 16; sequence++) {
        bytes[0] = 'D';
        bytes[1] = sequence;
        for (size_t i = 2; i < sizeof(bytes); i++)
            bytes[i] = sequence + i;
        ATF_REQUIRE_EQ(door_async_submit(s.ctx, bytes, sizeof(bytes), complete, &s, &id), 0);
        memset(bytes, 0xee, sizeof(bytes));
    }

    ATF_REQUIRE_EQ(door_async_submit(s.ctx, bytes, sizeof(bytes), complete, &s, &id), -1);
    ATF_REQUIRE_EQ(errno, EAGAIN);
    ready(queue);
    ATF_REQUIRE_EQ(s.count, 0);
    ATF_REQUIRE_EQ(threads(), before);
    ATF_REQUIRE_EQ(door_async_dispatch(s.ctx, 1), 1);
    ATF_REQUIRE_EQ(s.count, 1);
    pump(&s, queue, 16);
    ATF_REQUIRE_EQ(s.mask, 0xffffU);
    ATF_REQUIRE_EQ(door_async_dispatch(s.ctx, 16), 0);
    ATF_REQUIRE_EQ(threads(), before);
    char request = 'R';
    ATF_REQUIRE_EQ(door_async_submit(s.ctx, &request, 1, complete, &s, &id), 0);
    pump(&s, queue, 17);
    cleanup(&s, queue, server);
}

ATF_TC(poll_read_fault_preserves_completion);
ATF_TC_HEAD(poll_read_fault_preserves_completion, tc)
{
    atf_tc_set_md_var(tc, "descr", "short/faulting raw completion reads do not consume the record");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(poll_read_fault_preserves_completion, tc)
{
    (void)tc;
    struct state s;
    int server, queue = setup(&s, &server);
    char request = 'R', small;
    uint64_t id;
    ATF_REQUIRE_EQ(door_async_submit(s.ctx, &request, 1, complete, &s, &id), 0);
    ready(queue);
    int fd = door_async_poll_fd(s.ctx);
    ATF_REQUIRE_EQ(read(fd, &small, 1), -1);
    ATF_REQUIRE_EQ(errno, EMSGSIZE);
    volatile uintptr_t bad = 1;
    ATF_REQUIRE_EQ(read(fd, (void *)bad, 65568), -1);
    ATF_REQUIRE_EQ(errno, EFAULT);
    ATF_REQUIRE_EQ(door_async_dispatch(s.ctx, 1), 1);
    ATF_REQUIRE_EQ(s.count, 1);
    cleanup(&s, queue, server);
}

static door_async_t *outer_context, *inner_context;

static void
nested_inner(uint64_t id, int status, const void *data, size_t size, void *cookie)
{
    ATF_REQUIRE_EQ(door_async_close(outer_context), -1);
    ATF_REQUIRE_EQ(errno, EINVAL);
    complete(id, status, data, size, cookie);
}

static void
nested_outer(uint64_t id, int status, const void *data, size_t size, void *cookie)
{
    ATF_REQUIRE_EQ(door_async_dispatch(inner_context, 1), 1);
    complete(id, status, data, size, cookie);
}

ATF_TC(poll_callback_resubmit);
ATF_TC_HEAD(poll_callback_resubmit, tc)
{
    atf_tc_set_md_var(tc, "descr", "callback can resubmit; recursive dispatch/close are rejected");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(poll_callback_resubmit, tc)
{
    (void)tc;
    struct state s;
    int server, queue = setup(&s, &server);
    uint64_t id;
    char request = 'R';
    s.reenter = true;
    ATF_REQUIRE_EQ(door_async_submit(s.ctx, &request, 1, complete, &s, &id), 0);
    pump(&s, queue, 2);
    struct state inner;
    int inner_server, inner_queue = setup(&inner, &inner_server);
    outer_context = s.ctx;
    inner_context = inner.ctx;
    ATF_REQUIRE_EQ(door_async_submit(inner.ctx, &request, 1,
        nested_inner, &inner, &id), 0);
    ready(inner_queue);
    ATF_REQUIRE_EQ(door_async_submit(s.ctx, &request, 1, nested_outer, &s, &id), 0);
    pump(&s, queue, 3);
    ATF_REQUIRE_EQ(inner.count, 1);
    cleanup(&inner, inner_queue, inner_server);
    cleanup(&s, queue, server);
}

ATF_TC(poll_descriptor_move);
ATF_TC_HEAD(poll_descriptor_move, tc)
{
    atf_tc_set_md_var(tc, "descr", "manual dispatch preserves receiver install before MOVE acknowledgement");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(poll_descriptor_move, tc)
{
    (void)tc;
    struct state s;
    int server, queue = setup(&s, &server);
    uint64_t id;
    char request = 'F';
    ATF_REQUIRE_EQ(door_async_submit_desc(s.ctx, &request, 1, complete_fd, &s, &id), 0);
    pump(&s, queue, 1);
    ATF_REQUIRE_EQ(close(s.fd), 0);
    cleanup(&s, queue, server);
}

ATF_TC(poll_cancel_and_close);
ATF_TC_HEAD(poll_cancel_and_close, tc)
{
    atf_tc_set_md_var(tc, "descr", "cancel completion and close drain execute on the existing caller");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(poll_cancel_and_close, tc)
{
    (void)tc;
    struct state s;
    int server, queue = setup(&s, &server);
    uint64_t id;
    char request = 'B';
    ATF_REQUIRE_EQ(door_async_submit(s.ctx, &request, 1, complete, &s, &id), 0);
    struct timespec pause = {0, 1000000};
    while (!atomic_load(&entered))
        nanosleep(&pause, NULL);
    ATF_REQUIRE_EQ(door_async_cancel(s.ctx, id), 0);
    pump(&s, queue, 1);
    ATF_REQUIRE_EQ(s.status, ECANCELED);
    ATF_REQUIRE_EQ(door_async_submit(s.ctx, &request, 1, complete, &s, &id), 0);
    ATF_REQUIRE_EQ(door_async_close(s.ctx), 0);
    ATF_REQUIRE_EQ(s.count, 2);
    ATF_REQUIRE_EQ(s.status, ECANCELED);
    atomic_store(&release_service, 1);
    while (!atomic_load(&finished))
        nanosleep(&pause, NULL);
    close(queue);
    door_revoke(server);
    close(server);
}

ATF_TC(poll_revoke_eof);
ATF_TC_HEAD(poll_revoke_eof, tc)
{
    atf_tc_set_md_var(tc, "descr", "revoked completion endpoint wakes kqueue with EOF");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(poll_revoke_eof, tc)
{
    (void)tc;
    struct state s;
    int server, queue = setup(&s, &server);
    ATF_REQUIRE_EQ(door_revoke(door_async_poll_fd(s.ctx)), 0);
    struct kevent event;
    struct timespec deadline = {10, 0};
    ATF_REQUIRE_EQ(kevent(queue, NULL, 0, &event, 1, &deadline), 1);
    ATF_REQUIRE((event.flags & EV_EOF) != 0);
    ATF_REQUIRE_EQ(door_async_dispatch(s.ctx, 1), -1);
    ATF_REQUIRE_EQ(errno, EBADF);
    cleanup(&s, queue, server);
}

static void
discard_fd(uint64_t id, int status, const void *data, size_t size,
    door_desc_t *descriptors, uint_t count, void *cookie)
{
    (void)descriptors;
    ATF_REQUIRE_EQ(status, ECANCELED);
    ATF_REQUIRE_EQ(count, 0);
    complete(id, status, data, size, cookie);
}

ATF_TC(poll_discard_retained_move);
ATF_TC_HEAD(poll_discard_retained_move, tc)
{
    atf_tc_set_md_var(tc, "descr", "revoke after raw read cancels uncollected MOVE without closing source");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(poll_discard_retained_move, tc)
{
    (void)tc;
    struct state s;
    int server, queue = setup(&s, &server);
    uint64_t id;
    char request = 'F';
    ATF_REQUIRE_EQ(door_async_submit_desc(s.ctx, &request, 1, discard_fd, &s, &id), 0);
    ready(queue);
    char wire[128];
    ATF_REQUIRE(read(door_async_poll_fd(s.ctx), wire, sizeof(wire)) > 0);
    /* Close must deliver cancellation to a callback that accepts an error. */
    ATF_REQUIRE_EQ(door_revoke(door_async_poll_fd(s.ctx)), 0);
    struct timespec pause = {0, 1000000};
    while (!atomic_load(&finished))
        nanosleep(&pause, NULL);
    ATF_REQUIRE(fcntl(atomic_load(&move_source), F_GETFD) != -1);
    close(atomic_load(&move_source));
    cleanup(&s, queue, server);
    ATF_REQUIRE_EQ(s.count, 1);
    ATF_REQUIRE_EQ(s.status, ECANCELED);
}

static atomic_int callback_entered, callback_release, close_started, close_finished;

static void
blocking_complete(uint64_t id, int status, const void *data, size_t size, void *cookie)
{
    struct timespec pause = {0, 1000000};
    atomic_store(&callback_entered, 1);
    while (!atomic_load(&callback_release))
        nanosleep(&pause, NULL);
    complete(id, status, data, size, cookie);
}

static void *
dispatch_thread(void *cookie)
{
    struct state *s = cookie;
    s->dispatcher = pthread_self();
    ATF_REQUIRE_EQ(door_async_dispatch(s->ctx, 1), 1);
    return (NULL);
}

static void *
close_thread(void *cookie)
{
    struct state *s = cookie;
    atomic_store(&close_started, 1);
    ATF_REQUIRE_EQ(door_async_close(s->ctx), 0);
    atomic_store(&close_finished, 1);
    return (NULL);
}

ATF_TC(poll_close_waits_dispatch);
ATF_TC_HEAD(poll_close_waits_dispatch, tc)
{
    atf_tc_set_md_var(tc, "descr", "close waits for the application dispatcher and executing callback");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(poll_close_waits_dispatch, tc)
{
    (void)tc;
    struct state s;
    int server, queue = setup(&s, &server);
    char request = 'R';
    uint64_t id;
    ATF_REQUIRE_EQ(door_async_submit(s.ctx, &request, 1, blocking_complete, &s, &id), 0);
    ready(queue);
    pthread_t dispatch, closer;
    ATF_REQUIRE_EQ(pthread_create(&dispatch, NULL, dispatch_thread, &s), 0);
    struct timespec pause = {0, 1000000};
    while (!atomic_load(&callback_entered))
        nanosleep(&pause, NULL);
    ATF_REQUIRE_EQ(pthread_create(&closer, NULL, close_thread, &s), 0);
    while (!atomic_load(&close_started))
        nanosleep(&pause, NULL);
    struct timespec interval = {0, 10000000};
    nanosleep(&interval, NULL);
    ATF_REQUIRE_EQ(atomic_load(&close_finished), 0);
    atomic_store(&callback_release, 1);
    ATF_REQUIRE_EQ(pthread_join(dispatch, NULL), 0);
    ATF_REQUIRE_EQ(pthread_join(closer, NULL), 0);
    ATF_REQUIRE_EQ(s.count, 1);
    close(queue);
    door_revoke(server);
    close(server);
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, poll_snapshot_budget_no_workers);
    ATF_TP_ADD_TC(tp, poll_read_fault_preserves_completion);
    ATF_TP_ADD_TC(tp, poll_callback_resubmit);
    ATF_TP_ADD_TC(tp, poll_descriptor_move);
    ATF_TP_ADD_TC(tp, poll_cancel_and_close);
    ATF_TP_ADD_TC(tp, poll_revoke_eof);
    ATF_TP_ADD_TC(tp, poll_discard_retained_move);
    ATF_TP_ADD_TC(tp, poll_close_waits_dispatch);
    return (atf_no_error());
}
