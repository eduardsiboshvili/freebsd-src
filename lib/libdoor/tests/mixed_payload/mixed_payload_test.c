/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define MIXED_DATA_MAX (64U * 1024U)
#define MIXED_DESC_LIMIT 4U
#define MIXED_REPLY_SIZE 512U
#define MIXED_PATTERN_SEED 0x3dU

static const char request_message[] = "mixed request payload";
static const char request_file_data[] = "client descriptor contents";
static const char reply_message[] = "mixed reply payload";
static const char reply_file_data[] = "server descriptor contents";

static char reply_path[PATH_MAX];
static char limit_reply_paths[MIXED_DESC_LIMIT][PATH_MAX];
static atomic_uint dispatch_count;

static uint8_t mixed_pattern_byte(size_t offset) {
  return ((uint8_t)((offset * 197U + MIXED_PATTERN_SEED) & 0xffU));
}

static void fill_mixed_pattern(void *buffer, size_t size) {
  uint8_t *bytes;
  size_t i;

  bytes = buffer;
  for (i = 0; i < size; i++)
    bytes[i] = mixed_pattern_byte(i);
}

static void require_mixed_pattern(const void *buffer, size_t size) {
  const uint8_t *bytes;
  size_t i;

  bytes = buffer;
  for (i = 0; i < size; i++) {
    ATF_REQUIRE_MSG(bytes[i] == mixed_pattern_byte(i),
                    "payload differs at offset %zu: got %#x, expected %#x", i,
                    bytes[i], mixed_pattern_byte(i));
  }
}

static int create_seed_file(char *path, size_t path_size, const char *template,
                            const void *data, size_t data_size) {
  char local_path[PATH_MAX];
  int fd;

  ATF_REQUIRE(strlen(template) + 1 <= sizeof(local_path));
  (void)strlcpy(local_path, template, sizeof(local_path));
  fd = mkstemp(local_path);
  ATF_REQUIRE(fd != -1);
  ATF_REQUIRE(write(fd, data, data_size) == (ssize_t)data_size);
  ATF_REQUIRE(lseek(fd, 0, SEEK_SET) == 0);
  (void)strlcpy(path, local_path, path_size);
  return (fd);
}

static void set_mixed_limits(int door_fd, size_t data_max, size_t desc_max) {
  size_t value;

  ATF_REQUIRE(door_setparam(door_fd, DOOR_PARAM_DATA_MIN, 0) == 0);
  ATF_REQUIRE(door_setparam(door_fd, DOOR_PARAM_DATA_MAX, data_max) == 0);
  ATF_REQUIRE(door_setparam(door_fd, DOOR_PARAM_DESC_MAX, desc_max) == 0);
  ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DATA_MAX, &value) == 0);
  ATF_REQUIRE(value == data_max);
  ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DESC_MAX, &value) == 0);
  ATF_REQUIRE(value == desc_max);
}

static bool read_fd_matches(int fd, const void *expected,
                            size_t expected_size) {
  uint8_t buffer[128];
  ssize_t bytes_read;

  if (expected_size > sizeof(buffer))
    return (false);
  bytes_read = pread(fd, buffer, expected_size, 0);
  if (bytes_read != (ssize_t)expected_size)
    return (false);
  return (memcmp(buffer, expected, expected_size) == 0);
}

static void request_mixed_server(void *cookie, char *data, size_t data_size,
                                 door_desc_t *descs, uint_t ndescs) {
  (void)cookie;

  if (data == NULL || data_size != sizeof(request_message) ||
      memcmp(data, request_message, sizeof(request_message)) != 0)
    door_return(__DECONST(char *, "BAD-DATA"), sizeof("BAD-DATA"), NULL, 0);
  if (descs == NULL || ndescs != 1 || descs[0].d_attributes != DOOR_DESCRIPTOR)
    door_return(__DECONST(char *, "BAD-DESC"), sizeof("BAD-DESC"), NULL, 0);
  if (!read_fd_matches(descs[0].d_descriptor, request_file_data,
                       sizeof(request_file_data))) {
    (void)close(descs[0].d_descriptor);
    door_return(__DECONST(char *, "BAD-FILE"), sizeof("BAD-FILE"), NULL, 0);
  }
  (void)close(descs[0].d_descriptor);
  door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

static void reply_mixed_server(void *cookie, char *data, size_t data_size,
                               door_desc_t *descs, uint_t ndescs) {
  door_desc_t output;
  int fd;

  (void)cookie;
  (void)data;
  (void)data_size;
  (void)descs;
  (void)ndescs;

  fd = open(reply_path, O_RDONLY);
  if (fd == -1)
    door_return(__DECONST(char *, "OPEN-FAIL"), sizeof("OPEN-FAIL"), NULL, 0);
  test_init_desc(&output, fd, DOOR_RELEASE);
  door_return((char *)(uintptr_t)reply_message, sizeof(reply_message), &output,
              1);
}

static void bidirectional_server(void *cookie, char *data, size_t data_size,
                                 door_desc_t *descs, uint_t ndescs) {
  door_desc_t output;
  int fd;

  (void)cookie;

  if (data == NULL || data_size != sizeof(request_message) ||
      memcmp(data, request_message, sizeof(request_message)) != 0)
    door_return(__DECONST(char *, "BAD-DATA"), sizeof("BAD-DATA"), NULL, 0);
  if (descs == NULL || ndescs != 1 ||
      !read_fd_matches(descs[0].d_descriptor, request_file_data,
                       sizeof(request_file_data))) {
    if (descs != NULL && ndescs == 1)
      (void)close(descs[0].d_descriptor);
    door_return(__DECONST(char *, "BAD-DESC"), sizeof("BAD-DESC"), NULL, 0);
  }
  (void)close(descs[0].d_descriptor);

  fd = open(reply_path, O_RDONLY);
  if (fd == -1)
    door_return(__DECONST(char *, "OPEN-FAIL"), sizeof("OPEN-FAIL"), NULL, 0);
  test_init_desc(&output, fd, DOOR_RELEASE);
  door_return((char *)(uintptr_t)reply_message, sizeof(reply_message), &output,
              1);
}

static void counting_server(void *cookie, char *data, size_t data_size,
                            door_desc_t *descs, uint_t ndescs) {
  uint_t i;

  (void)cookie;
  (void)data;
  (void)data_size;

  (void)atomic_fetch_add_explicit(&dispatch_count, 1, memory_order_relaxed);
  for (i = 0; i < ndescs; i++)
    (void)close(descs[i].d_descriptor);
  door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

static void large_mixed_reply_server(void *cookie, char *data, size_t data_size,
                                     door_desc_t *descs, uint_t ndescs) {
  uint8_t reply[MIXED_REPLY_SIZE];
  door_desc_t output;
  int fd;

  (void)cookie;
  (void)data;
  (void)data_size;
  (void)descs;
  (void)ndescs;

  (void)atomic_fetch_add_explicit(&dispatch_count, 1, memory_order_relaxed);

  fd = open(reply_path, O_RDONLY);
  if (fd == -1)
    door_return(__DECONST(char *, "OPEN-FAIL"), sizeof("OPEN-FAIL"), NULL, 0);
  fill_mixed_pattern(reply, sizeof(reply));
  test_init_desc(&output, fd, DOOR_RELEASE);
  door_return((char *)reply, sizeof(reply), &output, 1);
}

static void combined_limit_server(void *cookie, char *data, size_t data_size,
                                  door_desc_t *descs, uint_t ndescs) {
  uint8_t reply[MIXED_DATA_MAX];
  door_desc_t output[MIXED_DESC_LIMIT];
  uint_t i;
  int fd;

  (void)cookie;

  if (data == NULL || data_size != MIXED_DATA_MAX || descs == NULL ||
      ndescs != MIXED_DESC_LIMIT)
    door_return(__DECONST(char *, "BAD-SHAPE"), sizeof("BAD-SHAPE"), NULL, 0);
  for (i = 0; i < MIXED_DESC_LIMIT; i++) {
    if (!read_fd_matches(descs[i].d_descriptor, &i, sizeof(i))) {
      while (i < ndescs) {
        (void)close(descs[i].d_descriptor);
        i++;
      }
      door_return(__DECONST(char *, "BAD-FD"), sizeof("BAD-FD"), NULL, 0);
    }
    (void)close(descs[i].d_descriptor);
  }

  for (i = 0; i < MIXED_DATA_MAX; i++) {
    if ((uint8_t)data[i] != mixed_pattern_byte(i))
      door_return(__DECONST(char *, "BAD-PATTERN"), sizeof("BAD-PATTERN"), NULL,
                  0);
  }
  fill_mixed_pattern(reply, sizeof(reply));
  for (i = 0; i < MIXED_DESC_LIMIT; i++) {
    fd = open(limit_reply_paths[i], O_RDONLY);
    if (fd == -1) {
      while (i > 0) {
        i--;
        (void)close(output[i].d_descriptor);
      }
      door_return(__DECONST(char *, "OPEN-FAIL"), sizeof("OPEN-FAIL"), NULL, 0);
    }
    test_init_desc(&output[i], fd, DOOR_RELEASE);
  }
  door_return((char *)reply, sizeof(reply), output, MIXED_DESC_LIMIT);
}

ATF_TC_WITHOUT_HEAD(client_data_and_descriptor);

ATF_TC_BODY(client_data_and_descriptor, tc) {
  char path[PATH_MAX];
  char reply[32];
  door_arg_t arg;
  door_desc_t desc;
  int door_fd;
  int file_fd;

  (void)tc;

  file_fd =
      create_seed_file(path, sizeof(path), "/tmp/libdoor-mixed-request.XXXXXX",
                       request_file_data, sizeof(request_file_data));
  door_fd = test_create_door(request_mixed_server);
  test_init_desc(&desc, file_fd, 0);
  test_init_call(&arg, reply, sizeof(reply));
  arg.data_ptr = (char *)(uintptr_t)request_message;
  arg.data_size = sizeof(request_message);
  arg.desc_ptr = &desc;
  arg.desc_num = 1;

  ATF_REQUIRE(door_call(door_fd, &arg) == 0);
  ATF_REQUIRE(arg.data_size == sizeof("OK"));
  ATF_REQUIRE(memcmp(arg.data_ptr, "OK", sizeof("OK")) == 0);
  ATF_REQUIRE(arg.desc_num == 0);
  test_require_fd_valid(file_fd);

  ATF_REQUIRE(close(file_fd) == 0);
  test_close_door(door_fd);
  (void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(server_data_and_descriptor);

ATF_TC_BODY(server_data_and_descriptor, tc) {
  char buffer[sizeof(reply_file_data)];
  char reply[64];
  door_arg_t arg;
  ssize_t bytes_read;
  int door_fd;
  int seed_fd;

  (void)tc;

  seed_fd = create_seed_file(reply_path, sizeof(reply_path),
                             "/tmp/libdoor-mixed-reply.XXXXXX", reply_file_data,
                             sizeof(reply_file_data));
  ATF_REQUIRE(close(seed_fd) == 0);
  door_fd = test_create_door(reply_mixed_server);
  test_init_call(&arg, reply, sizeof(reply));

  ATF_REQUIRE(door_call(door_fd, &arg) == 0);
  ATF_REQUIRE(arg.data_ptr == reply);
  ATF_REQUIRE(arg.data_size == sizeof(reply_message));
  ATF_REQUIRE(memcmp(reply, reply_message, sizeof(reply_message)) == 0);
  ATF_REQUIRE(arg.desc_num == 1);
  ATF_REQUIRE(arg.desc_ptr[0].d_attributes == DOOR_DESCRIPTOR);
  bytes_read = read(arg.desc_ptr[0].d_descriptor, buffer, sizeof(buffer));
  ATF_REQUIRE(bytes_read == (ssize_t)sizeof(reply_file_data));
  ATF_REQUIRE(memcmp(buffer, reply_file_data, sizeof(buffer)) == 0);

  test_close_received_descs(&arg);
  test_close_door(door_fd);
  (void)unlink(reply_path);
}

ATF_TC_WITHOUT_HEAD(bidirectional_single_descriptor);

ATF_TC_BODY(bidirectional_single_descriptor, tc) {
  char request_path[PATH_MAX];
  char buffer[sizeof(reply_file_data)];
  char reply[1];
  door_arg_t arg;
  door_desc_t desc;
  ssize_t bytes_read;
  int door_fd;
  int request_fd;
  int seed_fd;

  (void)tc;

  request_fd = create_seed_file(request_path, sizeof(request_path),
                                "/tmp/libdoor-mixed-bidir-in.XXXXXX",
                                request_file_data, sizeof(request_file_data));
  seed_fd = create_seed_file(reply_path, sizeof(reply_path),
                             "/tmp/libdoor-mixed-bidir-out.XXXXXX",
                             reply_file_data, sizeof(reply_file_data));
  ATF_REQUIRE(close(seed_fd) == 0);

  door_fd = test_create_door(bidirectional_server);
  test_init_desc(&desc, request_fd, 0);
  test_init_call(&arg, reply, sizeof(reply));
  arg.data_ptr = (char *)(uintptr_t)request_message;
  arg.data_size = sizeof(request_message);
  arg.desc_ptr = &desc;
  arg.desc_num = 1;

  ATF_REQUIRE(door_call(door_fd, &arg) == 0);
  ATF_REQUIRE(arg.rbuf != reply);
  ATF_REQUIRE(arg.data_ptr == arg.rbuf);
  ATF_REQUIRE(arg.rsize == round_page(sizeof(reply_message)));
  ATF_REQUIRE(arg.data_size == sizeof(reply_message));
  ATF_REQUIRE(memcmp(arg.data_ptr, reply_message, sizeof(reply_message)) == 0);
  ATF_REQUIRE(arg.desc_num == 1);
  ATF_REQUIRE(arg.desc_ptr[0].d_attributes == DOOR_DESCRIPTOR);
  bytes_read = read(arg.desc_ptr[0].d_descriptor, buffer, sizeof(buffer));
  ATF_REQUIRE(bytes_read == (ssize_t)sizeof(reply_file_data));
  ATF_REQUIRE(memcmp(buffer, reply_file_data, sizeof(buffer)) == 0);
  test_require_fd_valid(request_fd);

  test_close_received_descs(&arg);
  ATF_REQUIRE(munmap(arg.rbuf, arg.rsize) == 0);
  ATF_REQUIRE(close(request_fd) == 0);
  test_close_door(door_fd);
  (void)unlink(request_path);
  (void)unlink(reply_path);
}

ATF_TC_WITHOUT_HEAD(request_copy_ownership);

ATF_TC_BODY(request_copy_ownership, tc) {
  char path[PATH_MAX];
  char reply[32];
  door_arg_t arg;
  door_desc_t desc;
  int door_fd;
  int file_fd;

  (void)tc;

  file_fd =
      create_seed_file(path, sizeof(path), "/tmp/libdoor-mixed-copy.XXXXXX",
                       request_file_data, sizeof(request_file_data));
  door_fd = test_create_door(request_mixed_server);
  test_init_desc(&desc, file_fd, 0);
  test_init_call(&arg, reply, sizeof(reply));
  arg.data_ptr = (char *)(uintptr_t)request_message;
  arg.data_size = sizeof(request_message);
  arg.desc_ptr = &desc;
  arg.desc_num = 1;

  ATF_REQUIRE(door_call(door_fd, &arg) == 0);
  test_require_fd_valid(file_fd);
  ATF_REQUIRE(
      read_fd_matches(file_fd, request_file_data, sizeof(request_file_data)));

  ATF_REQUIRE(close(file_fd) == 0);
  test_close_door(door_fd);
  (void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(request_move_ownership);

ATF_TC_BODY(request_move_ownership, tc) {
  char path[PATH_MAX];
  char reply[32];
  door_arg_t arg;
  door_desc_t desc;
  int door_fd;
  int file_fd;

  (void)tc;

  file_fd =
      create_seed_file(path, sizeof(path), "/tmp/libdoor-mixed-move.XXXXXX",
                       request_file_data, sizeof(request_file_data));
  door_fd = test_create_door(request_mixed_server);
  test_init_desc(&desc, file_fd, DOOR_RELEASE);
  test_init_call(&arg, reply, sizeof(reply));
  arg.data_ptr = (char *)(uintptr_t)request_message;
  arg.data_size = sizeof(request_message);
  arg.desc_ptr = &desc;
  arg.desc_num = 1;

  ATF_REQUIRE(door_call(door_fd, &arg) == 0);
  ATF_REQUIRE(!test_fd_valid(file_fd));
  ATF_REQUIRE(arg.data_size == sizeof("OK"));
  ATF_REQUIRE(memcmp(arg.data_ptr, "OK", sizeof("OK")) == 0);

  test_close_door(door_fd);
  (void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(oversize_data_preserves_moved_descriptor);

ATF_TC_BODY(oversize_data_preserves_moved_descriptor, tc) {
  static const int errors[] = {ENOBUFS};
  char path[PATH_MAX];
  char reply[32];
  uint8_t *request;
  door_arg_t arg;
  door_desc_t desc;
  int door_fd;
  int file_fd;

  (void)tc;

  atomic_store_explicit(&dispatch_count, 0, memory_order_relaxed);
  file_fd =
      create_seed_file(path, sizeof(path), "/tmp/libdoor-mixed-oversize.XXXXXX",
                       request_file_data, sizeof(request_file_data));
  door_fd = test_create_door(counting_server);
  set_mixed_limits(door_fd, MIXED_DATA_MAX, 1);
  request = malloc(MIXED_DATA_MAX + 1);
  ATF_REQUIRE(request != NULL);
  fill_mixed_pattern(request, MIXED_DATA_MAX + 1);
  test_init_desc(&desc, file_fd, DOOR_RELEASE);
  test_init_call(&arg, reply, sizeof(reply));
  arg.data_ptr = (char *)request;
  arg.data_size = MIXED_DATA_MAX + 1;
  arg.desc_ptr = &desc;
  arg.desc_num = 1;

  TEST_REQUIRE_ERRNO_ONE_OF(door_call(door_fd, &arg), errors);
  ATF_REQUIRE(arg.data_ptr == (char *)request);
  ATF_REQUIRE(arg.data_size == MIXED_DATA_MAX + 1);
  ATF_REQUIRE(arg.desc_ptr == &desc);
  ATF_REQUIRE(arg.desc_num == 1);
  test_require_fd_valid(file_fd);
  ATF_REQUIRE(atomic_load_explicit(&dispatch_count, memory_order_relaxed) == 0);

  free(request);
  ATF_REQUIRE(close(file_fd) == 0);
  test_close_door(door_fd);
  (void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(invalid_descriptor_does_not_dispatch_data);

ATF_TC_BODY(invalid_descriptor_does_not_dispatch_data, tc) {
  char reply[32];
  door_arg_t arg;
  door_desc_t desc;
  int door_fd;

  (void)tc;

  atomic_store_explicit(&dispatch_count, 0, memory_order_relaxed);
  door_fd = test_create_door(counting_server);
  test_init_desc(&desc, -1, 0);
  test_init_call(&arg, reply, sizeof(reply));
  arg.data_ptr = (char *)(uintptr_t)request_message;
  arg.data_size = sizeof(request_message);
  arg.desc_ptr = &desc;
  arg.desc_num = 1;

  ATF_REQUIRE_ERRNO(EINVAL, door_call(door_fd, &arg) == -1);
  ATF_REQUIRE(arg.data_ptr == (char *)(uintptr_t)request_message);
  ATF_REQUIRE(arg.data_size == sizeof(request_message));
  ATF_REQUIRE(arg.desc_ptr == &desc);
  ATF_REQUIRE(arg.desc_num == 1);
  ATF_REQUIRE(atomic_load_explicit(&dispatch_count, memory_order_relaxed) == 0);

  test_init_call(&arg, reply, sizeof(reply));
  arg.data_ptr = (char *)(uintptr_t)request_message;
  arg.data_size = sizeof(request_message);
  ATF_REQUIRE(door_call(door_fd, &arg) == 0);
  ATF_REQUIRE(atomic_load_explicit(&dispatch_count, memory_order_relaxed) == 1);

  test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(small_reply_buffer_recovers_mixed_call);

ATF_TC_BODY(small_reply_buffer_recovers_mixed_call, tc) {
  char small_reply[32];
  door_arg_t arg;
  int door_fd;
  int seed_fd;

  (void)tc;

  seed_fd = create_seed_file(reply_path, sizeof(reply_path),
                             "/tmp/libdoor-mixed-small-reply.XXXXXX",
                             reply_file_data, sizeof(reply_file_data));
  ATF_REQUIRE(close(seed_fd) == 0);
  door_fd = test_create_door(large_mixed_reply_server);
  set_mixed_limits(door_fd, MIXED_DATA_MAX, 1);
  atomic_store_explicit(&dispatch_count, 0, memory_order_relaxed);

  memset(small_reply, 0xa5, sizeof(small_reply));
  test_init_call(&arg, small_reply, sizeof(small_reply));
  arg.data_ptr = (char *)(uintptr_t)request_message;
  arg.data_size = sizeof(request_message);
  ATF_REQUIRE(door_call(door_fd, &arg) == 0);
  ATF_REQUIRE(arg.rbuf != small_reply);
  ATF_REQUIRE(arg.data_ptr == arg.rbuf);
  ATF_REQUIRE(arg.data_size == MIXED_REPLY_SIZE);
  ATF_REQUIRE(arg.rsize == round_page(MIXED_REPLY_SIZE));
  require_mixed_pattern(arg.data_ptr, arg.data_size);
  ATF_REQUIRE(arg.desc_num == 1);
  ATF_REQUIRE(arg.desc_ptr[0].d_attributes == DOOR_DESCRIPTOR);
  ATF_REQUIRE(read_fd_matches(arg.desc_ptr[0].d_descriptor, reply_file_data,
                              sizeof(reply_file_data)));
  ATF_REQUIRE(atomic_load_explicit(&dispatch_count, memory_order_relaxed) == 1);

  test_close_received_descs(&arg);
  ATF_REQUIRE(munmap(arg.rbuf, arg.rsize) == 0);
  test_close_door(door_fd);
  (void)unlink(reply_path);
}

ATF_TC_WITHOUT_HEAD(combined_exact_limits);

ATF_TC_BODY(combined_exact_limits, tc) {
  char input_paths[MIXED_DESC_LIMIT][PATH_MAX];
  uint8_t *reply;
  uint8_t *request;
  door_arg_t arg;
  door_desc_t descs[MIXED_DESC_LIMIT];
  uint_t marker;
  uint_t i;
  int door_fd;
  int input_fds[MIXED_DESC_LIMIT];
  int seed_fd;

  (void)tc;

  for (i = 0; i < MIXED_DESC_LIMIT; i++) {
    marker = i;
    input_fds[i] = create_seed_file(input_paths[i], sizeof(input_paths[i]),
                                    "/tmp/libdoor-mixed-limit-in.XXXXXX",
                                    &marker, sizeof(marker));
    test_init_desc(&descs[i], input_fds[i], 0);
    seed_fd = create_seed_file(
        limit_reply_paths[i], sizeof(limit_reply_paths[i]),
        "/tmp/libdoor-mixed-limit-out.XXXXXX", &marker, sizeof(marker));
    ATF_REQUIRE(close(seed_fd) == 0);
  }

  request = malloc(MIXED_DATA_MAX);
  reply = malloc(MIXED_DATA_MAX);
  ATF_REQUIRE(request != NULL);
  ATF_REQUIRE(reply != NULL);
  fill_mixed_pattern(request, MIXED_DATA_MAX);
  memset(reply, 0, MIXED_DATA_MAX);

  door_fd = test_create_door(combined_limit_server);
  set_mixed_limits(door_fd, MIXED_DATA_MAX, MIXED_DESC_LIMIT);
  test_init_call(&arg, (char *)reply, MIXED_DATA_MAX);
  arg.data_ptr = (char *)request;
  arg.data_size = MIXED_DATA_MAX;
  arg.desc_ptr = descs;
  arg.desc_num = MIXED_DESC_LIMIT;

  ATF_REQUIRE(door_call(door_fd, &arg) == 0);
  ATF_REQUIRE(arg.data_size == MIXED_DATA_MAX);
  require_mixed_pattern(reply, MIXED_DATA_MAX);
  ATF_REQUIRE(arg.desc_num == MIXED_DESC_LIMIT);
  for (i = 0; i < MIXED_DESC_LIMIT; i++) {
    marker = UINT_MAX;
    ATF_REQUIRE(pread(arg.desc_ptr[i].d_descriptor, &marker, sizeof(marker),
                      0) == (ssize_t)sizeof(marker));
    ATF_REQUIRE(marker == i);
    test_require_fd_valid(input_fds[i]);
  }

  test_close_received_descs(&arg);
  for (i = 0; i < MIXED_DESC_LIMIT; i++) {
    ATF_REQUIRE(close(input_fds[i]) == 0);
    (void)unlink(input_paths[i]);
    (void)unlink(limit_reply_paths[i]);
  }
  test_close_door(door_fd);
  free(reply);
  free(request);
}

ATF_TP_ADD_TCS(tp) {
  ATF_TP_ADD_TC(tp, client_data_and_descriptor);
  ATF_TP_ADD_TC(tp, server_data_and_descriptor);
  ATF_TP_ADD_TC(tp, bidirectional_single_descriptor);
  ATF_TP_ADD_TC(tp, request_copy_ownership);
  ATF_TP_ADD_TC(tp, request_move_ownership);
  ATF_TP_ADD_TC(tp, oversize_data_preserves_moved_descriptor);
  ATF_TP_ADD_TC(tp, invalid_descriptor_does_not_dispatch_data);
  ATF_TP_ADD_TC(tp, small_reply_buffer_recovers_mixed_call);
  ATF_TP_ADD_TC(tp, combined_exact_limits);

  return (atf_no_error());
}
