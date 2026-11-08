/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/types.h>
#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "shm_cleanup.h"

static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cv = PTHREAD_COND_INITIALIZER;
static bool armed, entered, release_gate;
static int subject_fd;

static int
reuse_fcntl(int fd, int command, ...)
{
    va_list ap;
    int minimum, result;
    va_start(ap, command);
    minimum = va_arg(ap, int);
    va_end(ap);
    result = fcntl(fd, command, minimum);
    pthread_mutex_lock(&gate_lock);
    if (armed && fd == subject_fd && command == F_DUPFD_CLOEXEC && result >= 0) {
        armed = false;
        entered = true;
        pthread_cond_broadcast(&gate_cv);
        while (!release_gate)
            pthread_cond_wait(&gate_cv, &gate_lock);
    }
    pthread_mutex_unlock(&gate_lock);
    return (result);
}
/* Compile the real wrappers into this executable. Only the post-dup fcntl
 * boundary is interposed; all Door/SHM syscalls still execute in the kernel. */
#define fcntl reuse_fcntl
#include "../../door_shm.c"
#undef fcntl

struct operation { int fd, attach, result; door_shm_id_t region; door_shm_t shm; };
static void *
run_operation(void *cookie)
{
    struct operation *o = cookie;
    o->result = o->attach ? door_shm_attach(o->fd, o->region, DOOR_SHM_RW, &o->shm) :
        door_shm_create(o->fd, 4096, DOOR_SHM_RW, &o->shm);
    return (NULL);
}
static void
empty_server(void *cookie, char *data, size_t size, door_desc_t *d, uint_t n)
{
    (void)cookie; (void)data; (void)size; (void)d; (void)n;
    (void)door_return(NULL, 0, NULL, 0);
}
static void
reuse_test(bool attach)
{
    struct operation o;
    struct timespec deadline;
    door_info_t a_info, info;
    door_shm_t original;
    pthread_t thread;
    int a, a_guard, b, e;
    memset(&o, 0, sizeof(o));
    a = door_create(empty_server, NULL, DOOR_PRIVATE);
    b = door_create(empty_server, NULL, DOOR_PRIVATE);
    ATF_REQUIRE(a >= 0 && b >= 0);
    a_guard = dup(a);
    ATF_REQUIRE(a_guard >= 0);
    ATF_REQUIRE(door_info(a_guard, &a_info) == 0);
    ATF_REQUIRE(door_shm_create(a_guard, 4096, DOOR_SHM_RW, &original) == 0);
    o.fd = a; o.attach = attach; o.region = original.dsh_region;
    pthread_mutex_lock(&gate_lock);
    subject_fd = a; entered = release_gate = false; armed = true;
    pthread_mutex_unlock(&gate_lock);
    ATF_REQUIRE(pthread_create(&thread, NULL, run_operation, &o) == 0);
    clock_gettime(CLOCK_REALTIME, &deadline); deadline.tv_sec += 10;
    pthread_mutex_lock(&gate_lock);
    while (!entered) {
        e = pthread_cond_timedwait(&gate_cv, &gate_lock, &deadline);
        ATF_REQUIRE_EQ(e, 0);
    }
    ATF_REQUIRE(close(a) == 0);
    ATF_REQUIRE(dup2(b, a) == a);
    ATF_REQUIRE(door_info(a, &info) == 0);
    ATF_REQUIRE(info.di_uniquifier != a_info.di_uniquifier);
    release_gate = true; pthread_cond_broadcast(&gate_cv);
    pthread_mutex_unlock(&gate_lock);
    ATF_REQUIRE(pthread_join(thread, NULL) == 0);
    ATF_REQUIRE_EQ(o.result, 0);
    ATF_REQUIRE_EQ(o.shm.dsh_uniquifier, a_info.di_uniquifier);
    ATF_REQUIRE(door_info(o.shm.dsh_fd, &info) == 0);
    ATF_REQUIRE_EQ(info.di_uniquifier, a_info.di_uniquifier);
    if (!attach) {
        door_shm_t consumer;
        ATF_REQUIRE(door_shm_attach(a_guard, o.shm.dsh_region, DOOR_SHM_RW, &consumer) == 0);
        *(uint32_t *)o.shm.dsh_addr = UINT32_C(0x12345678);
        ATF_REQUIRE_EQ(*(uint32_t *)consumer.dsh_addr, UINT32_C(0x12345678));
        ATF_REQUIRE(door_shm_destroy_handle(&o.shm) == 0);
        test_shm_unmap_pair(&o.shm, &consumer);
    } else {
        *(uint32_t *)original.dsh_addr = UINT32_C(0x87654321);
        ATF_REQUIRE_EQ(*(uint32_t *)o.shm.dsh_addr, UINT32_C(0x87654321));
    }
    ATF_REQUIRE(door_shm_destroy_handle(&original) == 0);
    if (attach)
        test_shm_unmap_pair(&original, &o.shm);
    else
        ATF_REQUIRE(door_shm_unmap(&original) == 0);
    ATF_REQUIRE(door_revoke(a_guard) == 0);
    ATF_REQUIRE(door_revoke(b) == 0);
    close(a); close(b); close(a_guard);
}
ATF_TC_WITHOUT_HEAD(create_original_fd_reused);
ATF_TC_BODY(create_original_fd_reused, tc) { (void)tc; reuse_test(false); }
ATF_TC_WITHOUT_HEAD(attach_original_fd_reused);
ATF_TC_BODY(attach_original_fd_reused, tc) { (void)tc; reuse_test(true); }
ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, create_original_fd_reused);
    ATF_TP_ADD_TC(tp, attach_original_fd_reused);
    return (atf_no_error());
}
