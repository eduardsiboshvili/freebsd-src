/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_common.h"

static volatile sig_atomic_t dispatch_count;

static void echo_server(void *cookie, char *data, size_t data_size,
                        door_desc_t *descs, uint_t ndescs) {
  (void)cookie;
  (void)descs;
  (void)ndescs;
  dispatch_count++;
  door_return(data, data_size, NULL, 0);
}

static void close_descs_server(void *cookie, char *data, size_t data_size,
                               door_desc_t *descs, uint_t ndescs) {
  uint_t i;
  (void)cookie;
  (void)data;
  (void)data_size;
  dispatch_count++;
  for (i = 0; i < ndescs; i++)
    (void)close(descs[i].d_descriptor);
  door_return(data, data_size, NULL, 0);
}

static int normal_call(int fd) {
  static const char request[] = "recover";
  char reply[sizeof(request)];
  door_arg_t arg;

  test_init_call(&arg, reply, sizeof(reply));
  arg.data_ptr = (char *)(uintptr_t)request;
  arg.data_size = sizeof(request);
  if (door_call(fd, &arg) == -1)
    return (-1);
  if (arg.data_size != sizeof(request) ||
      memcmp(arg.data_ptr, request, sizeof(request)) != 0) {
    errno = EPROTO;
    return (-1);
  }
  return (0);
}

/* Public bad-pointer/flag/fd failures and recovery; no deterministic
 * kernel pause or allocation-injection hooks are used by this suite. */
ATF_TC_WITHOUT_HEAD(unreadable_request_is_atomic);

ATF_TC_BODY(unreadable_request_is_atomic, tc) {
  char reply[16];
  door_arg_t arg;
  int fd;
  (void)tc;
  dispatch_count = 0;
  fd = test_create_door(echo_server);
  test_init_call(&arg, reply, sizeof(reply));
  arg.data_ptr = (char *)(uintptr_t)1;
  arg.data_size = 1;
  ATF_REQUIRE_ERRNO(EFAULT, door_call(fd, &arg) == -1);
  ATF_REQUIRE_MSG(dispatch_count == 0, "server dispatched unreadable request");
  ATF_REQUIRE(normal_call(fd) == 0);
  ATF_REQUIRE(dispatch_count == 1);
  test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(request_crossing_guard_is_atomic);

ATF_TC_BODY(request_crossing_guard_is_atomic, tc) {
  struct test_guarded_region region;
  char reply[64], *request;
  door_arg_t arg;
  int fd;
  (void)tc;
  ATF_REQUIRE(test_guarded_region_create(&region) == 0);
  request = (char *)region.guard - 16;
  memset(request, 0x5a, 16);
  dispatch_count = 0;
  fd = test_create_door(echo_server);
  test_init_call(&arg, reply, sizeof(reply));
  arg.data_ptr = request;
  arg.data_size = 32;
  ATF_REQUIRE_ERRNO(EFAULT, door_call(fd, &arg) == -1);
  ATF_REQUIRE(dispatch_count == 0);
  ATF_REQUIRE(normal_call(fd) == 0);
  test_close_door(fd);
  test_guarded_region_destroy(&region);
}

ATF_TC_WITHOUT_HEAD(unwritable_reply_recovers);

ATF_TC_BODY(unwritable_reply_recovers, tc) {
  static const char request[] = "reply";
  door_arg_t arg;
  void *mapping;
  size_t page_size;
  int fd;
  (void)tc;
  page_size = (size_t)getpagesize();
  mapping = mmap(NULL, page_size, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
  ATF_REQUIRE(mapping != MAP_FAILED);
  dispatch_count = 0;
  fd = test_create_door(echo_server);
  test_init_call(&arg, mapping, page_size);
  arg.data_ptr = (char *)(uintptr_t)request;
  arg.data_size = sizeof(request);
  ATF_REQUIRE_ERRNO(EFAULT, door_call(fd, &arg) == -1);
  ATF_REQUIRE(dispatch_count == 1);
  ATF_REQUIRE(normal_call(fd) == 0);
  ATF_REQUIRE(dispatch_count == 2);
  test_close_door(fd);
  ATF_REQUIRE(munmap(mapping, page_size) == 0);
}

ATF_TC_WITHOUT_HEAD(readonly_reply_recovers);

ATF_TC_BODY(readonly_reply_recovers, tc) {
  static const char request[] = "reply";
  door_arg_t arg;
  void *mapping;
  size_t page_size;
  int fd;
  (void)tc;
  page_size = (size_t)getpagesize();
  mapping = mmap(NULL, page_size, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
  ATF_REQUIRE(mapping != MAP_FAILED);
  dispatch_count = 0;
  fd = test_create_door(echo_server);
  test_init_call(&arg, mapping, page_size);
  arg.data_ptr = (char *)(uintptr_t)request;
  arg.data_size = sizeof(request);
  ATF_REQUIRE_ERRNO(EFAULT, door_call(fd, &arg) == -1);
  ATF_REQUIRE(dispatch_count == 1);
  ATF_REQUIRE(normal_call(fd) == 0);
  test_close_door(fd);
  ATF_REQUIRE(munmap(mapping, page_size) == 0);
}

ATF_TC_WITHOUT_HEAD(unreadable_descriptor_array_preserves_source);

ATF_TC_BODY(unreadable_descriptor_array_preserves_source, tc) {
  char reply[8];
  door_arg_t arg;
  int fd, source;
  (void)tc;
  dispatch_count = 0;
  fd = test_create_door(close_descs_server);
  source = test_make_regular_fd();
  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = (door_desc_t *)(uintptr_t)1;
  arg.desc_num = 1;
  ATF_REQUIRE_ERRNO(EFAULT, door_call(fd, &arg) == -1);
  test_require_fd_valid(source);
  ATF_REQUIRE(dispatch_count == 0);
  ATF_REQUIRE(close(source) == 0);
  test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(partial_descriptor_array_preserves_move);

ATF_TC_BODY(partial_descriptor_array_preserves_move, tc) {
  struct test_guarded_region region;
  char reply[8];
  door_arg_t arg;
  door_desc_t *desc;
  int fd, source;
  (void)tc;
  ATF_REQUIRE(test_guarded_region_create(&region) == 0);
  desc = (door_desc_t *)((uintptr_t)region.guard - sizeof(*desc));
  source = test_make_regular_fd();
  test_init_desc(desc, source, DOOR_RELEASE);
  dispatch_count = 0;
  fd = test_create_door(close_descs_server);
  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = desc;
  arg.desc_num = 2;
  ATF_REQUIRE_ERRNO(EFAULT, door_call(fd, &arg) == -1);
  test_require_fd_valid(source);
  ATF_REQUIRE(dispatch_count == 0);
  ATF_REQUIRE(close(source) == 0);
  test_close_door(fd);
  test_guarded_region_destroy(&region);
}

ATF_TC_WITHOUT_HEAD(bad_descriptor_after_move_is_atomic);

ATF_TC_BODY(bad_descriptor_after_move_is_atomic, tc) {
  char reply[8];
  door_arg_t arg;
  door_desc_t descs[2];
  int fd, source;
  (void)tc;
  source = test_make_regular_fd();
  test_init_desc(&descs[0], source, DOOR_RELEASE);
  test_init_desc(&descs[1], INT_MAX, 0);
  dispatch_count = 0;
  fd = test_create_door(close_descs_server);
  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = descs;
  arg.desc_num = 2;
  ATF_REQUIRE_ERRNO(EBADF, door_call(fd, &arg) == -1);
  test_require_fd_valid(source);
  ATF_REQUIRE(dispatch_count == 0);
  ATF_REQUIRE(close(source) == 0);
  ATF_REQUIRE(normal_call(fd) == 0);
  test_close_door(fd);
}

ATF_TP_ADD_TCS(tp) {
  ATF_TP_ADD_TC(tp, unreadable_request_is_atomic);
  ATF_TP_ADD_TC(tp, request_crossing_guard_is_atomic);
  ATF_TP_ADD_TC(tp, unwritable_reply_recovers);
  ATF_TP_ADD_TC(tp, readonly_reply_recovers);
  ATF_TP_ADD_TC(tp, unreadable_descriptor_array_preserves_source);
  ATF_TP_ADD_TC(tp, partial_descriptor_array_preserves_move);
  ATF_TP_ADD_TC(tp, bad_descriptor_after_move_is_atomic);
  return (atf_no_error());
}
