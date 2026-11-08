/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "test_common.h"

static void
unused_server(void *cookie, char *data, size_t size, door_desc_t *desc, uint_t n)
{
    (void)cookie; (void)data; (void)size; (void)desc; (void)n;
    (void)door_return(NULL, 0, NULL, 0);
}

static void
source(int fd, door_shm_t *shm)
{
    size_t page = (size_t)getpagesize();
    ATF_REQUIRE(door_shm_create(fd, 4 * page, DOOR_SHM_RW, shm) == 0);
    for (unsigned int i = 0; i < 4; i++)
        memset((char *)shm->dsh_addr + i * page, 'A' + (int)i, page);
}

static void
cleanup_source(door_shm_t *shm, bool revoked)
{
    if (!revoked)
        ATF_REQUIRE(door_shm_destroy_handle(shm) == 0);
    ATF_REQUIRE(door_shm_unmap(shm) == 0);
}

static void
fill_refs(door_shm_t *shm, door_shm_ref_t refs[2])
{
    size_t page = (size_t)getpagesize();
    ATF_REQUIRE(door_shm_ref_init(shm, 3 * page, page, &refs[0]) == 0);
    ATF_REQUIRE(door_shm_ref_init(shm, page, page, &refs[1]) == 0);
}

static void
check_view(door_shm_view_t *view)
{
    size_t page = (size_t)getpagesize();
    const unsigned char *p = view->dsv_addr;
    ATF_REQUIRE(view->dsv_size == 2 * page);
    for (size_t i = 0; i < page; i++) {
        ATF_REQUIRE(p[i] == 'D');
        ATF_REQUIRE(p[page + i] == 'B');
    }

    errno = 0;
    ATF_REQUIRE(mprotect(view->dsv_addr, view->dsv_size,
        PROT_READ | PROT_WRITE) == -1);
    ATF_REQUIRE(errno == EACCES || errno == EPERM);
}

static void
release_view(door_shm_view_t *producer, door_shm_view_t *consumer)
{
    uint_t state;
    ATF_REQUIRE(door_shm_view_release(consumer) == 0);
    ATF_REQUIRE(door_shm_view_release(consumer) == 0); /* idempotent */
    ATF_REQUIRE(door_shm_view_query(producer, &state) == 0);
    ATF_REQUIRE(state == DOOR_SHM_VIEW_RELEASED);
    ATF_REQUIRE(door_shm_view_close(consumer) == 0);
    ATF_REQUIRE(door_shm_view_destroy(producer) == 0);
}

ATF_TC_WITHOUT_HEAD(page_order_readonly_and_release);
ATF_TC_BODY(page_order_readonly_and_release, tc)
{
    door_shm_t shm;
    door_shm_ref_t refs[2];
    door_shm_view_t publisher, receiver;
    int fd = test_create_door(unused_server);
    (void)tc;
    source(fd, &shm);
    fill_refs(&shm, refs);
    ATF_REQUIRE(door_shm_view_publish(fd, refs, 2, &publisher) == 0);
    ATF_REQUIRE_ERRNO(EBUSY, door_shm_destroy_handle(&shm) == -1);
    ATF_REQUIRE(door_shm_view_attach(fd, publisher.dsv_id,
        publisher.dsv_token, &receiver) == 0);
    check_view(&receiver);
    ATF_REQUIRE_ERRNO(EBUSY, door_shm_view_destroy(&publisher) == -1);
    ATF_REQUIRE_ERRNO(EBUSY, door_shm_view_close(&receiver) == -1);
    release_view(&publisher, &receiver);
    /* A released range can be issued again with a fresh token. */
    ATF_REQUIRE(door_shm_view_publish(fd, refs, 2, &publisher) == 0);
    ATF_REQUIRE(door_shm_view_destroy(&publisher) == 0);
    cleanup_source(&shm, false);
    test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(validation_and_pending_cancel);
ATF_TC_BODY(validation_and_pending_cancel, tc)
{
    door_shm_t shm;
    door_shm_ref_t refs[2], bad[2];
    door_shm_view_t publisher, receiver;
    int fd = test_create_door(unused_server);
    (void)tc;
    source(fd, &shm);
    fill_refs(&shm, refs);
    memcpy(bad, refs, sizeof(bad));
    bad[0].dsr_offset++;
    ATF_REQUIRE_ERRNO(EINVAL, door_shm_view_publish(fd, bad, 2, &publisher) == -1);
    memcpy(bad, refs, sizeof(bad));
    bad[0].dsr_uniquifier++;
    ATF_REQUIRE_ERRNO(ESTALE, door_shm_view_publish(fd, bad, 2, &publisher) == -1);
    bad[0] = refs[0]; bad[1] = refs[0];
    ATF_REQUIRE_ERRNO(EINVAL, door_shm_view_publish(fd, bad, 2, &publisher) == -1);
    bad[0] = refs[0]; bad[0].dsr_offset = shm.dsh_size;
    ATF_REQUIRE_ERRNO(EOVERFLOW, door_shm_view_publish(fd, bad, 1, &publisher) == -1);
    ATF_REQUIRE_ERRNO(EINVAL, door_shm_view_publish(fd, refs, 0, &publisher) == -1);
    ATF_REQUIRE(door_shm_view_publish(fd, refs, 2, &publisher) == 0);
    ATF_REQUIRE_ERRNO(ESTALE, door_shm_view_attach(fd, publisher.dsv_id,
        publisher.dsv_token == UINT64_MAX ? publisher.dsv_token - 1 : publisher.dsv_token + 1, &receiver) == -1);
    ATF_REQUIRE(door_shm_view_destroy(&publisher) == 0);
    cleanup_source(&shm, false);
    test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(disjoint_and_overlapping_leases);
ATF_TC_BODY(disjoint_and_overlapping_leases, tc)
{
    door_shm_t shm;
    door_shm_ref_t refs[2];
    door_shm_view_t a, b, again, reader;
    int fd = test_create_door(unused_server);
    (void)tc;
    source(fd, &shm);
    fill_refs(&shm, refs);
    ATF_REQUIRE(door_shm_view_publish(fd, refs, 1, &a) == 0);
    ATF_REQUIRE(door_shm_view_publish(fd, refs + 1, 1, &b) == 0);
    ATF_REQUIRE_ERRNO(EBUSY, door_shm_view_publish(fd, refs, 1, &again) == -1);
    ATF_REQUIRE(door_shm_view_attach(fd, a.dsv_id, a.dsv_token, &reader) == 0);
    release_view(&a, &reader);
    ATF_REQUIRE_ERRNO(EBUSY, door_shm_destroy_handle(&shm) == -1);
    ATF_REQUIRE(door_shm_view_publish(fd, refs, 1, &again) == 0);
    ATF_REQUIRE(door_shm_view_destroy(&again) == 0);
    ATF_REQUIRE(door_shm_view_destroy(&b) == 0);
    cleanup_source(&shm, false);
    test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(revoke_preserves_live_view);
ATF_TC_BODY(revoke_preserves_live_view, tc)
{
    door_shm_t shm;
    door_shm_ref_t refs[2];
    door_shm_view_t publisher, receiver;
    int fd = test_create_door(unused_server);
    (void)tc;
    source(fd, &shm); fill_refs(&shm, refs);
    ATF_REQUIRE(door_shm_view_publish(fd, refs, 2, &publisher) == 0);
    ATF_REQUIRE(door_shm_view_attach(fd, publisher.dsv_id, publisher.dsv_token,
        &receiver) == 0);
    ATF_REQUIRE(door_revoke(fd) == 0);
    check_view(&receiver);
    release_view(&publisher, &receiver);
    cleanup_source(&shm, true);
    test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(mapping_not_inherited_by_fork);
ATF_TC_BODY(mapping_not_inherited_by_fork, tc)
{
    door_shm_t shm;
    door_shm_ref_t refs[2];
    door_shm_view_t publisher, receiver;
    pid_t child;
    int status, fd = test_create_door(unused_server);
    (void)tc;
    source(fd, &shm); fill_refs(&shm, refs);
    ATF_REQUIRE(door_shm_view_publish(fd, refs, 2, &publisher) == 0);
    ATF_REQUIRE(door_shm_view_attach(fd, publisher.dsv_id, publisher.dsv_token,
        &receiver) == 0);
    child = fork();
    ATF_REQUIRE(child != -1);
    if (child == 0) {
        volatile unsigned char byte = *(volatile unsigned char *)receiver.dsv_addr;
        (void)byte;
        _exit(0);
    }

    ATF_REQUIRE(waitpid(child, &status, 0) == child);
    ATF_REQUIRE(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
    release_view(&publisher, &receiver);
    cleanup_source(&shm, false);
    test_close_door(fd);
}

struct offer { uint64_t id, token; };

ATF_TC_WITHOUT_HEAD(producer_exit_keeps_attached_pages);
ATF_TC_BODY(producer_exit_keeps_attached_pages, tc)
{
    int pipes[2][2], status, fd = test_create_door(unused_server);
    struct offer offer;
    door_shm_view_t receiver;
    pid_t child;
    char byte;
    (void)tc;
    ATF_REQUIRE(pipe(pipes[0]) == 0 && pipe(pipes[1]) == 0);
    child = fork();
    ATF_REQUIRE(child != -1);
    if (child == 0) {
        close(pipes[0][0]); close(pipes[1][1]);
        door_shm_t shm;
        door_shm_ref_t refs[2];
        door_shm_view_t publisher;
        (void)alarm(30);
        source(fd, &shm); fill_refs(&shm, refs);
        ATF_REQUIRE(door_shm_view_publish(fd, refs, 2, &publisher) == 0);
        offer.id = publisher.dsv_id; offer.token = publisher.dsv_token;
        ATF_REQUIRE(write(pipes[0][1], &offer, sizeof(offer)) == sizeof(offer));
        ATF_REQUIRE(read(pipes[1][0], &byte, 1) == 1);
        _exit(0);
    }

    close(pipes[0][1]); close(pipes[1][0]);
    ATF_REQUIRE(read(pipes[0][0], &offer, sizeof(offer)) == sizeof(offer));
    ATF_REQUIRE(door_shm_view_attach(fd, offer.id, offer.token, &receiver) == 0);
    ATF_REQUIRE(write(pipes[1][1], "X", 1) == 1);
    ATF_REQUIRE(waitpid(child, &status, 0) == child);
    ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    check_view(&receiver);
    ATF_REQUIRE(door_shm_view_release(&receiver) == 0);
    ATF_REQUIRE(door_shm_view_close(&receiver) == 0);
    close(pipes[0][0]); close(pipes[1][1]);
    test_close_door(fd);
}

static long
raw_view(int fd, unsigned int op, struct door_ioc_shm_view *arg)
{
    return ((long)__syscall((quad_t)SYS_door, (long)op, (long)fd,
        (long)(uintptr_t)arg, 0L, 0L, 0L));
}

ATF_TC_WITHOUT_HEAD(copyout_rollback);
ATF_TC_BODY(copyout_rollback, tc)
{
    size_t page = (size_t)getpagesize();
    struct door_ioc_shm_view *arg;
    struct door_ioc_shm_view_segment segments[2];
    door_shm_t shm;
    door_shm_ref_t refs[2];
    door_shm_view_t publisher;
    uint_t state;
    int fd = test_create_door(unused_server);
    (void)tc;
    source(fd, &shm); fill_refs(&shm, refs);
    for (unsigned int i = 0; i < 2; i++) {
        segments[i].disvs_region = refs[i].dsr_region;
        segments[i].disvs_offset = refs[i].dsr_offset;
        segments[i].disvs_size = refs[i].dsr_size;
        segments[i].disvs_uniquifier = refs[i].dsr_uniquifier;
    }

    arg = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    ATF_REQUIRE(arg != MAP_FAILED);
    memset(arg, 0, sizeof(*arg));
    arg->disv_version = DOOR_ABI_VERSION;
    arg->disv_segments_ptr = (uintptr_t)segments;
    arg->disv_segment_count = 2;
    ATF_REQUIRE(mprotect(arg, page, PROT_READ) == 0);
    ATF_REQUIRE_ERRNO(EFAULT, raw_view(fd, DOOR_SC_SHM_VIEW_PUBLISH, arg) == -1);
    /* If publish leaked its reservation, the same ranges would be EBUSY. */
    ATF_REQUIRE(door_shm_view_publish(fd, refs, 2, &publisher) == 0);
    ATF_REQUIRE(mprotect(arg, page, PROT_READ | PROT_WRITE) == 0);
    memset(arg, 0, sizeof(*arg));
    arg->disv_version = DOOR_ABI_VERSION;
    arg->disv_id = publisher.dsv_id; arg->disv_token = publisher.dsv_token;
    ATF_REQUIRE(mprotect(arg, page, PROT_READ) == 0);
    ATF_REQUIRE_ERRNO(EFAULT, raw_view(fd, DOOR_SC_SHM_VIEW_ATTACH, arg) == -1);
    ATF_REQUIRE(door_shm_view_query(&publisher, &state) == 0);
    ATF_REQUIRE(state == DOOR_SHM_VIEW_RELEASED);
    ATF_REQUIRE(door_shm_view_destroy(&publisher) == 0);
    ATF_REQUIRE(munmap(arg, page) == 0);
    cleanup_source(&shm, false);
    test_close_door(fd);
}

static void
send_fd(int sock, int fd)
{
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *cmsg;
    char byte = 'F';

    memset(&msg, 0, sizeof(msg));
    memset(&control, 0, sizeof(control));
    iov.iov_base = &byte; iov.iov_len = 1;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control.bytes; msg.msg_controllen = sizeof(control);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    ATF_REQUIRE(sendmsg(sock, &msg, 0) == 1);
}

static int
receive_fd(int sock)
{
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
    struct msghdr msg;
    struct iovec iov;
    struct cmsghdr *cmsg;
    char byte;
    int fd;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = &byte; iov.iov_len = 1;
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control.bytes; msg.msg_controllen = sizeof(control);
    ATF_REQUIRE(recvmsg(sock, &msg, 0) == 1 && byte == 'F');
    ATF_REQUIRE((msg.msg_flags & MSG_CTRUNC) == 0);
    cmsg = CMSG_FIRSTHDR(&msg);
    ATF_REQUIRE(cmsg != NULL && cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_len == CMSG_LEN(sizeof(fd)));
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
    return (fd);
}

static void
receiver_finish(bool exec_mode)
{
    int sockets[2], fd, status;
    pid_t child;
    struct offer offer;
    door_shm_t shm;
    door_shm_ref_t refs[2];
    door_shm_view_t publisher;
    uint_t state;

    ATF_REQUIRE(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) == 0);
    child = fork();
    ATF_REQUIRE(child != -1);
    if (child == 0) {
        door_shm_view_t receiver;
        close(sockets[0]);
        (void)alarm(30);
        fd = test_create_door(unused_server);
        send_fd(sockets[1], fd);
        ATF_REQUIRE(read(sockets[1], &offer, sizeof(offer)) == sizeof(offer));
        ATF_REQUIRE(door_shm_view_attach(fd, offer.id, offer.token, &receiver) == 0);
        check_view(&receiver);
        if (exec_mode) {
            ATF_REQUIRE(dup2(sockets[1], 9) == 9);
            ATF_REQUIRE(fcntl(9, F_SETFD, 0) == 0);
            execl("/bin/sh", "sh", "-c",
                "printf E >&9; read token <&9; exit 0", (char *)NULL);
            _exit(127);
        }

        _exit(0); /* no explicit release */
    }

    close(sockets[1]);
    fd = receive_fd(sockets[0]);
    source(fd, &shm); fill_refs(&shm, refs);
    ATF_REQUIRE(door_shm_view_publish(fd, refs, 2, &publisher) == 0);
    offer.id = publisher.dsv_id; offer.token = publisher.dsv_token;
    ATF_REQUIRE(write(sockets[0], &offer, sizeof(offer)) == sizeof(offer));
    if (exec_mode) {
        char byte;
        ATF_REQUIRE(read(sockets[0], &byte, 1) == 1 && byte == 'E');
        /* The exec'ed child remains blocked: exit cleanup cannot mask exec. */
        ATF_REQUIRE(door_shm_view_query(&publisher, &state) == 0);
        ATF_REQUIRE(state == DOOR_SHM_VIEW_RELEASED);
        ATF_REQUIRE(write(sockets[0], "\n", 1) == 1);
    }

    ATF_REQUIRE(waitpid(child, &status, 0) == child);
    ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (!exec_mode) {
        ATF_REQUIRE(door_shm_view_query(&publisher, &state) == 0);
        ATF_REQUIRE(state == DOOR_SHM_VIEW_RELEASED);
    }

    ATF_REQUIRE(door_shm_view_destroy(&publisher) == 0);
    cleanup_source(&shm, true); /* owner exit revoked the endpoint */
    close(sockets[0]);
    test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(receiver_exit_releases_pages);
ATF_TC_BODY(receiver_exit_releases_pages, tc)
{
    (void)tc;
    receiver_finish(false);
}

ATF_TC_WITHOUT_HEAD(receiver_exec_releases_before_exit);
ATF_TC_BODY(receiver_exec_releases_before_exit, tc)
{
    (void)tc;
    receiver_finish(true);
}

struct publish_racer {
    pthread_barrier_t *barrier;
    int fd, result, error;
    const door_shm_ref_t *ref;
    door_shm_view_t view;
};

static void *
publish_race(void *cookie)
{
    struct publish_racer *racer = cookie;
    int error = pthread_barrier_wait(racer->barrier);
    ATF_REQUIRE(error == 0 || error == PTHREAD_BARRIER_SERIAL_THREAD);
    racer->result = door_shm_view_publish(racer->fd, racer->ref, 1, &racer->view);
    racer->error = errno;
    return (NULL);
}

ATF_TC_WITHOUT_HEAD(concurrent_publish_has_one_winner);
ATF_TC_BODY(concurrent_publish_has_one_winner, tc)
{
    int fd = test_create_door(unused_server), winners = 0;
    door_shm_t shm;
    door_shm_ref_t refs[2];
    pthread_barrier_t barrier;
    pthread_t threads[2];
    struct publish_racer racers[2];
    (void)tc;

    source(fd, &shm); fill_refs(&shm, refs);
    ATF_REQUIRE(pthread_barrier_init(&barrier, NULL, 2) == 0);
    for (unsigned int i = 0; i < 2; i++) {
        memset(&racers[i], 0, sizeof(racers[i]));
        racers[i].barrier = &barrier; racers[i].fd = fd; racers[i].ref = refs;
        ATF_REQUIRE(pthread_create(&threads[i], NULL, publish_race, &racers[i]) == 0);
    }

    for (unsigned int i = 0; i < 2; i++)
        ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);

    for (unsigned int i = 0; i < 2; i++) {
        if (racers[i].result == 0) {
            winners++;
            ATF_REQUIRE(door_shm_view_destroy(&racers[i].view) == 0);
        } else
            ATF_REQUIRE(racers[i].result == -1 && racers[i].error == EBUSY);
    }

    ATF_REQUIRE(winners == 1);
    ATF_REQUIRE(pthread_barrier_destroy(&barrier) == 0);
    cleanup_source(&shm, false);
    test_close_door(fd);
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, page_order_readonly_and_release);
    ATF_TP_ADD_TC(tp, validation_and_pending_cancel);
    ATF_TP_ADD_TC(tp, disjoint_and_overlapping_leases);
    ATF_TP_ADD_TC(tp, revoke_preserves_live_view);
    ATF_TP_ADD_TC(tp, mapping_not_inherited_by_fork);
    ATF_TP_ADD_TC(tp, producer_exit_keeps_attached_pages);
    ATF_TP_ADD_TC(tp, copyout_rollback);
    ATF_TP_ADD_TC(tp, receiver_exit_releases_pages);
    ATF_TP_ADD_TC(tp, receiver_exec_releases_before_exit);
    ATF_TP_ADD_TC(tp, concurrent_publish_has_one_winner);
    return (atf_no_error());
}
