/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cpuset.h>
#include <sys/ptrace.h>
#include <sys/rtprio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_common.h"

struct gate {
  int entered[2];
  int release[2];
};

static void gated(void *cookie, char *d, size_t n, door_desc_t *x, uint_t nx) {
  struct gate *g = cookie;
  char b = 'E';
  (void)d;
  (void)n;
  (void)x;
  (void)nx;
  (void)write(g->entered[1], &b, 1);
  if (read(g->release[0], &b, 1) != 1)
    pthread_exit(NULL);
  door_return(__DECONST(char *, "ok"), 3, NULL, 0);
}

static void echo(void *c, char *d, size_t n, door_desc_t *x, uint_t nx) {
  (void)c;
  (void)x;
  (void)nx;
  door_return(d, n, NULL, 0);
}

static int child_call(int fd) {
  door_arg_t a;
  char r[8];
  test_init_call(&a, r, sizeof(r));
  return door_call(fd, &a) == 0 ? 0 : 1;
}

static void gate_init(struct gate *g) {
  ATF_REQUIRE(pipe(g->entered) == 0);
  ATF_REQUIRE(pipe(g->release) == 0);
}

static void gate_fini(struct gate *g) {
  close(g->entered[0]);
  close(g->entered[1]);
  close(g->release[0]);
  close(g->release[1]);
}

ATF_TC_WITHOUT_HEAD(sigstop_sigcont_client);

ATF_TC_BODY(sigstop_sigcont_client, tc) {
  struct gate g;
  int fd, status;
  pid_t p;
  char b = 'R';
  (void)tc;
  gate_init(&g);
  fd = door_create(gated, &g, 0);
  ATF_REQUIRE(fd != -1);
  p = fork();
  ATF_REQUIRE(p != -1);
  if (p == 0) {
    alarm(10);
    _exit(child_call(fd));
  }
  ATF_REQUIRE(read(g.entered[0], &b, 1) == 1);
  ATF_REQUIRE(kill(p, SIGSTOP) == 0);
  usleep(20000);
  ATF_REQUIRE(kill(p, SIGCONT) == 0);
  ATF_REQUIRE(write(g.release[1], &b, 1) == 1);
  ATF_REQUIRE(waitpid(p, &status, 0) == p);
  ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  test_close_door(fd);
  gate_fini(&g);
}

ATF_TC_WITHOUT_HEAD(sigkill_pending_client_cleanup);

ATF_TC_BODY(sigkill_pending_client_cleanup, tc) {
  struct gate g;
  int fd, status;
  pid_t p1, p2;
  char b = 'R';
  (void)tc;
  gate_init(&g);
  fd = door_create(gated, &g, DOOR_NO_DEPLETION_CB);
  ATF_REQUIRE(fd != -1);
  p1 = fork();
  ATF_REQUIRE(p1 != -1);
  if (p1 == 0) {
    alarm(10);
    _exit(child_call(fd));
  }
  ATF_REQUIRE(read(g.entered[0], &b, 1) == 1);
  p2 = fork();
  ATF_REQUIRE(p2 != -1);
  if (p2 == 0) {
    alarm(10);
    _exit(child_call(fd));
  }
  usleep(20000);
  ATF_REQUIRE(kill(p2, SIGKILL) == 0);
  ATF_REQUIRE(waitpid(p2, &status, 0) == p2);
  ATF_REQUIRE(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
  ATF_REQUIRE(write(g.release[1], &b, 1) == 1);
  ATF_REQUIRE(waitpid(p1, &status, 0) == p1);
  ATF_REQUIRE(WIFEXITED(status));
  ATF_REQUIRE(door_revoke(fd) == 0);
  close(fd);
  gate_fini(&g);
}

ATF_TC_WITHOUT_HEAD(ptrace_stopped_client_resumes);

ATF_TC_BODY(ptrace_stopped_client_resumes, tc) {
  struct gate g;
  int fd, status;
  pid_t p;
  char b = 'R';
  (void)tc;
  gate_init(&g);
  fd = door_create(gated, &g, 0);
  ATF_REQUIRE(fd != -1);
  p = fork();
  ATF_REQUIRE(p != -1);
  if (p == 0) {
    alarm(10);
    _exit(child_call(fd));
  }
  ATF_REQUIRE(read(g.entered[0], &b, 1) == 1);
  if (ptrace(PT_ATTACH, p, NULL, 0) == -1) {
    int e = errno;
    kill(p, SIGKILL);
    waitpid(p, &status, 0);
    test_close_door(fd);
    gate_fini(&g);
    atf_tc_skip("ptrace attach unavailable: %s", strerror(e));
  }

  /*
   * Door CALL deliberately defers the ptrace stop while the kernel owns
   * its temporary file reference.  Complete the in-flight RPC so the
   * child can reach the normal syscall/AST boundary and stop there.
   * Waiting for the stop before releasing the server creates a circular
   * wait that is broken only by the child's 10-second alarm.
   */
  ATF_REQUIRE(write(g.release[1], &b, 1) == 1);
  ATF_REQUIRE(waitpid(p, &status, 0) == p);
  ATF_REQUIRE(WIFSTOPPED(status));
  ATF_REQUIRE(ptrace(PT_DETACH, p, (caddr_t)1, 0) == 0);
  ATF_REQUIRE(waitpid(p, &status, 0) == p);
  ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  test_close_door(fd);
  gate_fini(&g);
}

static atomic_int setup_ok;

static void scheduler_setup(void *cookie) {
  cpuset_t set;
  struct rtprio rtp;
  (void)cookie;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(set),
                         &set) == 0)
    atomic_fetch_add(&setup_ok, 1);
  rtp.type = RTP_PRIO_NORMAL;
  rtp.prio = 0;
  (void)rtprio_thread(RTP_SET, 0, &rtp);
}

static int xfactory(door_info_t *i, void *(*start)(void *), void *arg,
                    void *c) {
  pthread_t t;
  (void)i;
  (void)c;
  int e = pthread_create(&t, NULL, start, arg);
  if (e) {
    errno = e;
    return -1;
  }
  return 1;
}

ATF_TC_WITHOUT_HEAD(worker_affinity_and_rtprio);

ATF_TC_BODY(worker_affinity_and_rtprio, tc) {
  int fd;
  door_arg_t a;
  char r[8];
  char request[] = "x";
  (void)tc;
  atomic_store(&setup_ok, 0);
  fd = door_xcreate(echo, NULL, DOOR_NO_DEPLETION_CB, xfactory, scheduler_setup,
                    NULL, 1);
  ATF_REQUIRE(fd != -1);
  test_init_call(&a, r, sizeof(r));
  a.data_ptr = request;
  a.data_size = sizeof(request);
  ATF_REQUIRE(door_call(fd, &a) == 0);
  ATF_REQUIRE(atomic_load(&setup_ok) >= 0);
  ATF_REQUIRE(door_revoke(fd) == 0);
  close(fd);
}

ATF_TP_ADD_TCS(tp) {
  ATF_TP_ADD_TC(tp, sigstop_sigcont_client);
  ATF_TP_ADD_TC(tp, sigkill_pending_client_cleanup);
  ATF_TP_ADD_TC(tp, ptrace_stopped_client_resumes);
  ATF_TP_ADD_TC(tp, worker_affinity_and_rtprio);
  return atf_no_error();
}
