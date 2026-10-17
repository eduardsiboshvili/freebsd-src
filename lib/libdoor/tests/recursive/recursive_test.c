/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"
static int door_a, door_b;

static void echo(void *c, char *d, size_t n, door_desc_t *x, uint_t nx) {
  (void)c;
  (void)x;
  (void)nx;
  door_return(d, n, NULL, 0);
}

static void a_to_b(void *c, char *d, size_t n, door_desc_t *x, uint_t nx) {
  door_arg_t a;
  char r[16];
  char request[] = "nested";
  (void)c;
  (void)d;
  (void)n;
  (void)x;
  (void)nx;
  test_init_call(&a, r, sizeof(r));
  a.data_ptr = request;
  a.data_size = sizeof(request);
  if (door_call(door_b, &a) == -1)
    door_return(__DECONST(char *, "bad"), 4, NULL, 0);
  door_return(a.data_ptr, a.data_size, NULL, 0);
}

static void self_proc(void *c, char *d, size_t n, door_desc_t *x, uint_t nx) {
  door_arg_t a;
  char r[16];
  char request[] = "1";
  (void)c;
  (void)x;
  (void)nx;
  if (n > 0 && d[0] == '1') {
    door_return(__DECONST(char *, "done"), 5, NULL, 0);
  }
  test_init_call(&a, r, sizeof(r));
  a.data_ptr = request;
  a.data_size = sizeof(request);
  if (door_call(door_a, &a) == -1)
    door_return(__DECONST(char *, "bad"), 4, NULL, 0);
  door_return(a.data_ptr, a.data_size, NULL, 0);
}

static int factory(door_info_t *i, void *(*start)(void *), void *arg, void *c) {
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

ATF_TC_WITHOUT_HEAD(cross_door_recursive_call);

ATF_TC_BODY(cross_door_recursive_call, tc) {
  door_arg_t a;
  char r[16];
  (void)tc;
  door_b = test_create_door(echo);
  door_a = test_create_door(a_to_b);
  test_init_call(&a, r, sizeof(r));
  ATF_REQUIRE(door_call(door_a, &a) == 0);
  ATF_REQUIRE(strcmp(a.data_ptr, "nested") == 0);
  test_close_door(door_a);
  test_close_door(door_b);
}

ATF_TC_WITHOUT_HEAD(self_recursive_with_two_workers);

ATF_TC_BODY(self_recursive_with_two_workers, tc) {
  door_arg_t a;
  char r[16];
  char request[] = "0";
  (void)tc;
  door_a = door_xcreate(self_proc, NULL, DOOR_NO_DEPLETION_CB, factory, NULL,
                        NULL, 2);
  ATF_REQUIRE(door_a != -1);
  test_init_call(&a, r, sizeof(r));
  a.data_ptr = request;
  a.data_size = sizeof(request);
  ATF_REQUIRE(door_call(door_a, &a) == 0);
  ATF_REQUIRE(strcmp(a.data_ptr, "done") == 0);
  ATF_REQUIRE(door_revoke(door_a) == 0);
  close(door_a);
}

ATF_TC_WITHOUT_HEAD(recursive_revoke_propagates);

ATF_TC_BODY(recursive_revoke_propagates, tc) {
  door_arg_t a;
  char r[16];
  (void)tc;
  door_b = test_create_door(echo);
  ATF_REQUIRE(door_revoke(door_b) == 0);
  door_a = test_create_door(a_to_b);
  test_init_call(&a, r, sizeof(r));
  ATF_REQUIRE(door_call(door_a, &a) == 0);
  ATF_REQUIRE(strcmp(a.data_ptr, "bad") == 0);
  test_close_door(door_a);
  close(door_b);
}

ATF_TP_ADD_TCS(tp) {
  ATF_TP_ADD_TC(tp, cross_door_recursive_call);
  ATF_TP_ADD_TC(tp, self_recursive_with_two_workers);
  ATF_TP_ADD_TC(tp, recursive_revoke_propagates);
  return atf_no_error();
}
