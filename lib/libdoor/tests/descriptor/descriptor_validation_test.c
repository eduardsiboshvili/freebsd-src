/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

static void close_descriptors_server(void *cookie, char *data, size_t data_size,
                                     door_desc_t *descs, uint_t ndescs) {
  uint_t i;

  (void)cookie;
  (void)data;
  (void)data_size;

  for (i = 0; descs != NULL && i < ndescs; i++)
    (void)close(descs[i].d_descriptor);

  door_return(NULL, 0, NULL, 0);
}

static void null_server(void *cookie, char *data, size_t data_size,
                        door_desc_t *descs, uint_t ndescs) {
  (void)cookie;
  (void)data;
  (void)data_size;
  (void)descs;
  (void)ndescs;

  door_return(NULL, 0, NULL, 0);
}

static void require_descriptor_error(int door_fd, door_desc_t *desc,
                                     int expected_error) {
  char reply[8];
  door_arg_t arg;

  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = desc;
  arg.desc_num = 1;
  ATF_REQUIRE_ERRNO(expected_error, door_call(door_fd, &arg) == -1);
}

ATF_TC_WITHOUT_HEAD(invalid_values);

ATF_TC_BODY(invalid_values, tc) {
  door_desc_t desc;
  int door_fd;

  (void)tc;

  door_fd = test_create_door(close_descriptors_server);

  test_init_desc(&desc, -1, 0);
  require_descriptor_error(door_fd, &desc, EINVAL);

  memset(&desc, 0, sizeof(desc));
  desc.d_descriptor = STDIN_FILENO;
  require_descriptor_error(door_fd, &desc, EINVAL);

  test_init_desc(&desc, INT_MAX, 0);
  require_descriptor_error(door_fd, &desc, EBADF);

  test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(closed_descriptor);

ATF_TC_BODY(closed_descriptor, tc) {
  char reply[8];
  door_arg_t arg;
  door_desc_t desc;
  int closed_fd;
  int door_fd;
  int pipe_fds[2];

  (void)tc;

  door_fd = test_create_door(close_descriptors_server);
  ATF_REQUIRE(pipe(pipe_fds) == 0);
  closed_fd = pipe_fds[1];
  ATF_REQUIRE(close(closed_fd) == 0);

  test_init_desc(&desc, closed_fd, 0);
  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = &desc;
  arg.desc_num = 1;

  ATF_REQUIRE_ERRNO(EBADF, door_call(door_fd, &arg) == -1);
  test_require_fd_valid(pipe_fds[0]);

  ATF_REQUIRE(close(pipe_fds[0]) == 0);
  test_close_door(door_fd);
}

struct bad_array_context {
  int door_fd;
  door_desc_t *descs;
  uint_t ndescs;
};

static int call_with_bad_array(void *argument) {
  struct bad_array_context *context;
  char reply[8];
  door_arg_t arg;

  context = argument;
  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = context->descs;
  arg.desc_num = context->ndescs;

  errno = 0;
  if (door_call(context->door_fd, &arg) == -1 && errno == EFAULT)
    return (0);
  return (1);
}

static void require_bad_array_efault(struct bad_array_context *context) {
  int exit_code;
  int signal_number;

  ATF_REQUIRE(test_run_child(call_with_bad_array, context, &exit_code,
                             &signal_number) == 0);
  ATF_REQUIRE_MSG(signal_number == 0, "child terminated by signal %d",
                  signal_number);
  ATF_REQUIRE_MSG(exit_code == 0, "child returned unexpected exit status %d",
                  exit_code);
}

ATF_TC_WITHOUT_HEAD(unreadable_array);

ATF_TC_BODY(unreadable_array, tc) {
  struct bad_array_context context;
  struct test_guarded_region region;
  int door_fd;

  (void)tc;

  door_fd = test_create_door(null_server);
  context.door_fd = door_fd;
  context.ndescs = 1;
  context.descs = (door_desc_t *)(uintptr_t)1;
  require_bad_array_efault(&context);

  ATF_REQUIRE(test_guarded_region_create(&region) == 0);
  context.descs = region.guard;
  require_bad_array_efault(&context);

  test_guarded_region_destroy(&region);
  test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(null_array);

ATF_TC_BODY(null_array, tc) {
  char reply[8];
  door_arg_t arg;
  int door_fd;

  (void)tc;

  door_fd = test_create_door(null_server);

  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = NULL;
  arg.desc_num = 1;
  ATF_REQUIRE_ERRNO(EINVAL, door_call(door_fd, &arg) == -1);

  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = NULL;
  arg.desc_num = UINT_MAX;
  ATF_REQUIRE_ERRNO(EINVAL, door_call(door_fd, &arg) == -1);

  test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(partially_readable_array);

ATF_TC_BODY(partially_readable_array, tc) {
  struct bad_array_context context;
  struct test_guarded_region region;
  door_desc_t *desc;
  int door_fd;
  int file_fd;

  (void)tc;

  door_fd = test_create_door(null_server);
  file_fd = test_make_regular_fd();
  ATF_REQUIRE(file_fd != -1);
  ATF_REQUIRE(test_guarded_region_create(&region) == 0);

  desc = (door_desc_t *)((uintptr_t)region.guard - sizeof(*desc));
  test_init_desc(desc, file_fd, 0);
  context.door_fd = door_fd;
  context.descs = desc;
  context.ndescs = 2;
  require_bad_array_efault(&context);

  test_require_fd_valid(file_fd);
  test_guarded_region_destroy(&region);
  ATF_REQUIRE(close(file_fd) == 0);
  test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(structural_count);

ATF_TC_BODY(structural_count, tc) {
  char reply[8];
  door_arg_t arg;
  int door_fd;

  (void)tc;

  door_fd = test_create_door(null_server);
  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = NULL;
  arg.desc_num = UINT_MAX;
  ATF_REQUIRE_ERRNO(EINVAL, door_call(door_fd, &arg) == -1);
  test_close_door(door_fd);
}

static void duplicate_receiver(void *cookie, char *data, size_t data_size,
                               door_desc_t *descs, uint_t ndescs) {
  const char byte = 'X';
  uint_t i;

  (void)cookie;
  (void)data;
  (void)data_size;

  if (descs == NULL || ndescs != 4)
    door_return(__DECONST(char *, "BAD"), sizeof("BAD"), NULL, 0);

  for (i = 0; i < ndescs; i++) {
    if (write(descs[i].d_descriptor, &byte, 1) != 1)
      door_return(__DECONST(char *, "BAD"), sizeof("BAD"), NULL, 0);
    (void)close(descs[i].d_descriptor);
  }

  door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

ATF_TC_WITHOUT_HEAD(duplicate_descriptors);

ATF_TC_BODY(duplicate_descriptors, tc) {
  char bytes[4];
  char reply[8];
  door_arg_t arg;
  door_desc_t descs[4];
  int door_fd;
  int pipe_fds[2];
  int i;

  (void)tc;

  door_fd = test_create_door(duplicate_receiver);
  ATF_REQUIRE(pipe(pipe_fds) == 0);

  for (i = 0; i < (int)nitems(descs); i++)
    test_init_desc(&descs[i], pipe_fds[1], 0);

  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = descs;
  arg.desc_num = nitems(descs);
  ATF_REQUIRE(door_call(door_fd, &arg) == 0);
  ATF_REQUIRE(arg.data_size == sizeof("OK"));
  ATF_REQUIRE(memcmp(arg.data_ptr, "OK", sizeof("OK")) == 0);
  ATF_REQUIRE(read(pipe_fds[0], bytes, sizeof(bytes)) ==
              (ssize_t)sizeof(bytes));

  for (i = 0; i < (int)nitems(bytes); i++)
    ATF_REQUIRE(bytes[i] == 'X');

  test_require_fd_valid(pipe_fds[1]);
  ATF_REQUIRE(close(pipe_fds[0]) == 0);
  ATF_REQUIRE(close(pipe_fds[1]) == 0);
  test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(mixed_valid_invalid);

ATF_TC_BODY(mixed_valid_invalid, tc) {
  char reply[8];
  door_arg_t arg;
  door_desc_t descs[3];
  int closed_fd;
  int door_fd;
  int first_fd;
  int third_fd;

  (void)tc;

  door_fd = test_create_door(close_descriptors_server);
  first_fd = test_make_regular_fd();
  third_fd = test_make_regular_fd();
  ATF_REQUIRE(first_fd != -1);
  ATF_REQUIRE(third_fd != -1);

  closed_fd = dup(first_fd);
  ATF_REQUIRE(closed_fd != -1);
  ATF_REQUIRE(close(closed_fd) == 0);

  test_init_desc(&descs[0], first_fd, DOOR_RELEASE);
  test_init_desc(&descs[1], closed_fd, DOOR_RELEASE);
  test_init_desc(&descs[2], third_fd, DOOR_RELEASE);

  test_init_call(&arg, reply, sizeof(reply));
  arg.desc_ptr = descs;
  arg.desc_num = nitems(descs);
  ATF_REQUIRE_ERRNO(EBADF, door_call(door_fd, &arg) == -1);

  test_require_fd_valid(first_fd);
  test_require_fd_valid(third_fd);
  ATF_REQUIRE(close(first_fd) == 0);
  ATF_REQUIRE(close(third_fd) == 0);
  test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp) {
  ATF_TP_ADD_TC(tp, invalid_values);
  ATF_TP_ADD_TC(tp, closed_descriptor);
  ATF_TP_ADD_TC(tp, unreadable_array);
  ATF_TP_ADD_TC(tp, null_array);
  ATF_TP_ADD_TC(tp, partially_readable_array);
  ATF_TP_ADD_TC(tp, structural_count);
  ATF_TP_ADD_TC(tp, duplicate_descriptors);
  ATF_TP_ADD_TC(tp, mixed_valid_invalid);

  return (atf_no_error());
}
