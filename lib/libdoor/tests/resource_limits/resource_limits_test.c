/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <atf-c.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <door.h>
#include <sys/door_core.h>
#include <sys/syscall.h>

#define MAX_DOOR_TEST_LIMIT 4096U
#define MAX_SHM_REGION_TEST_LIMIT 4096U

static unsigned long read_uint_limit(const char *name) {
  u_int value;
  size_t size;

  value = 0;
  size = sizeof(value);
  ATF_REQUIRE_MSG(sysctlbyname(name, &value, &size, NULL, 0) == 0,
                  "sysctlbyname(%s): %s", name, strerror(errno));
  ATF_REQUIRE(size == sizeof(value));
  return ((unsigned long)value);
}

static unsigned long read_ulong_limit(const char *name) {
  u_long value;
  size_t size;

  value = 0;
  size = sizeof(value);
  ATF_REQUIRE_MSG(sysctlbyname(name, &value, &size, NULL, 0) == 0,
                  "sysctlbyname(%s): %s", name, strerror(errno));
  ATF_REQUIRE(size == sizeof(value));
  return ((unsigned long)value);
}

static int raw_create(void) {
  return ((int)__syscall((quad_t)SYS_door, DOOR_SC_CREATE, 0L, 0L,
                         (long)DOOR_CREATE_F_NORMAL, 0L, 0L));
}

static int raw_shm_create(int fd, size_t size,
                          struct door_ioc_shm_create *arg) {

  memset(arg, 0, sizeof(*arg));
  arg->disc_version = DOOR_ABI_VERSION;
  arg->disc_flags = DOOR_SHM_RW;
  arg->disc_size = size;
  return ((int)__syscall((quad_t)SYS_door, DOOR_SC_SHM_CREATE, (long)fd,
                         (long)(uintptr_t)arg, 0L, 0L, 0L));
}

static int raw_shm_destroy(int fd, uint64_t region) {
  struct door_ioc_shm_destroy arg;

  memset(&arg, 0, sizeof(arg));
  arg.disd_version = DOOR_ABI_VERSION;
  arg.disd_region = region;
  return ((int)__syscall((quad_t)SYS_door, DOOR_SC_SHM_DESTROY, (long)fd,
                         (long)(uintptr_t)&arg, 0L, 0L, 0L));
}

static void destroy_mapping(int fd, const struct door_ioc_shm_create *arg) {

  ATF_REQUIRE(raw_shm_destroy(fd, arg->disc_region) == 0);
  ATF_REQUIRE(
      munmap((void *)(uintptr_t)arg->disc_addr, (size_t)arg->disc_size) == 0);
}

ATF_TC_WITHOUT_HEAD(sysctls_read_only);

ATF_TC_BODY(sysctls_read_only, tc) {
  static const struct {
    const char *name;
    bool is_ulong;
  } limits[] = {
      {"kern.doorfs.max_doors_per_proc", false},
      {"kern.doorfs.max_servers_per_door", false},
      {"kern.doorfs.max_shm_regions_per_door", false},
      {"kern.doorfs.max_shm_bytes_per_door", true},
  };

  u_long ulong_value;
  u_int uint_value;
  size_t i;

  (void)tc;
  for (i = 0; i < nitems(limits); i++) {
    errno = 0;
    if (limits[i].is_ulong) {
      ulong_value = read_ulong_limit(limits[i].name);
      ATF_REQUIRE(sysctlbyname(limits[i].name, NULL, NULL, &ulong_value,
                               sizeof(ulong_value)) == -1);
    } else {
      uint_value = (u_int)read_uint_limit(limits[i].name);
      ATF_REQUIRE(sysctlbyname(limits[i].name, NULL, NULL, &uint_value,
                               sizeof(uint_value)) == -1);
    }
    ATF_REQUIRE(errno == EPERM);
  }
}

ATF_TC_WITHOUT_HEAD(door_limit_and_release);

ATF_TC_BODY(door_limit_and_release, tc) {
  struct rlimit rlim;
  unsigned long limit;
  int *fds;
  unsigned long i;

  (void)tc;
  limit = read_uint_limit("kern.doorfs.max_doors_per_proc");
  if (limit == 0 || limit > MAX_DOOR_TEST_LIMIT)
    atf_tc_skip("use a boot-time Door limit between 1 and %u",
                MAX_DOOR_TEST_LIMIT);
  ATF_REQUIRE(getrlimit(RLIMIT_NOFILE, &rlim) == 0);
  if (rlim.rlim_cur < (rlim_t)(limit + 32))
    atf_tc_skip("RLIMIT_NOFILE is too small for the Door boundary");

  fds = calloc(limit, sizeof(*fds));
  ATF_REQUIRE(fds != NULL);
  for (i = 0; i < limit; i++) {
    fds[i] = raw_create();
    ATF_REQUIRE_MSG(fds[i] >= 0, "CREATE %lu/%lu: %s", i + 1, limit,
                    strerror(errno));
  }
  errno = 0;
  ATF_REQUIRE(raw_create() == -1);
  ATF_REQUIRE_ERRNO(EMFILE, true);

  ATF_REQUIRE(close(fds[0]) == 0);
  fds[0] = raw_create();
  ATF_REQUIRE_MSG(fds[0] >= 0, "released Door slot was not reusable: %s",
                  strerror(errno));
  for (i = 0; i < limit; i++)
    ATF_REQUIRE(close(fds[i]) == 0);
  free(fds);
}

ATF_TC_WITHOUT_HEAD(shm_region_limit_and_release);

ATF_TC_BODY(shm_region_limit_and_release, tc) {
  struct door_ioc_shm_create *regions, replacement;
  unsigned long byte_limit, limit;
  long page_size;
  int fd;
  unsigned long i;

  (void)tc;
  limit = read_uint_limit("kern.doorfs.max_shm_regions_per_door");
  if (limit == 0 || limit > MAX_SHM_REGION_TEST_LIMIT)
    atf_tc_skip("use a boot-time SHM region limit between 1 and %u",
                MAX_SHM_REGION_TEST_LIMIT);
  page_size = sysconf(_SC_PAGESIZE);
  ATF_REQUIRE(page_size > 0);
  byte_limit = read_ulong_limit("kern.doorfs.max_shm_bytes_per_door");
  if (limit > byte_limit / (unsigned long)page_size)
    atf_tc_skip("SHM byte limit is reached before region limit");
  fd = raw_create();
  ATF_REQUIRE(fd >= 0);
  regions = calloc(limit, sizeof(*regions));
  ATF_REQUIRE(regions != NULL);

  for (i = 0; i < limit; i++) {
    ATF_REQUIRE_MSG(raw_shm_create(fd, (size_t)page_size, &regions[i]) == 0,
                    "SHM_CREATE %lu/%lu: %s", i + 1, limit, strerror(errno));
  }
  errno = 0;
  ATF_REQUIRE(raw_shm_create(fd, (size_t)page_size, &replacement) == -1);
  ATF_REQUIRE_ERRNO(ENOSPC, true);

  destroy_mapping(fd, &regions[0]);
  ATF_REQUIRE(raw_shm_create(fd, (size_t)page_size, &replacement) == 0);
  for (i = 1; i < limit; i++)
    destroy_mapping(fd, &regions[i]);
  destroy_mapping(fd, &replacement);
  free(regions);
  ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(shm_byte_limit_and_release);

ATF_TC_BODY(shm_byte_limit_and_release, tc) {
  struct door_ioc_shm_create whole, extra, replacement;
  unsigned long limit;
  long page_size;
  int fd;

  (void)tc;
  limit = read_ulong_limit("kern.doorfs.max_shm_bytes_per_door");
  page_size = sysconf(_SC_PAGESIZE);
  ATF_REQUIRE(page_size > 0);
  if (limit < (unsigned long)page_size)
    atf_tc_skip("SHM byte limit is smaller than one page");
  if (limit % (unsigned long)page_size != 0)
    atf_tc_skip("SHM byte limit must be page aligned for this test");

  fd = raw_create();
  ATF_REQUIRE(fd >= 0);
  ATF_REQUIRE(raw_shm_create(fd, limit, &whole) == 0);
  errno = 0;
  ATF_REQUIRE(raw_shm_create(fd, (size_t)page_size, &extra) == -1);
  ATF_REQUIRE_ERRNO(ENOMEM, true);
  destroy_mapping(fd, &whole);
  ATF_REQUIRE(raw_shm_create(fd, (size_t)page_size, &replacement) == 0);
  destroy_mapping(fd, &replacement);
  ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(shm_revoke_cleanup);

ATF_TC_BODY(shm_revoke_cleanup, tc) {
  struct door_ioc_shm_create region;
  long page_size;
  int fd;

  (void)tc;
  page_size = sysconf(_SC_PAGESIZE);
  ATF_REQUIRE(page_size > 0);
  fd = raw_create();
  ATF_REQUIRE(fd >= 0);
  ATF_REQUIRE(raw_shm_create(fd, (size_t)page_size, &region) == 0);
  ATF_REQUIRE(__syscall((quad_t)SYS_door, DOOR_SC_REVOKE, (long)fd, 0L, 0L, 0L,
                        0L) == 0);
  ATF_REQUIRE(munmap((void *)(uintptr_t)region.disc_addr,
                     (size_t)region.disc_size) == 0);
  ATF_REQUIRE(close(fd) == 0);
}

struct bind_group {
  pthread_mutex_t lock;
  pthread_cond_t cv;
  int fd;
  unsigned int ready;
  bool release;
};

struct bind_result {
  struct bind_group *group;
  int result;
  int error;
};

static void *bind_worker(void *argument) {
  struct bind_result *result;
  struct bind_group *group;

  result = argument;
  group = result->group;
  result->result = (int)__syscall((quad_t)SYS_door, DOOR_SC_BIND,
                                  (long)group->fd, 0L, 0L, 0L, 0L);
  result->error = errno;

  (void)pthread_mutex_lock(&group->lock);
  group->ready++;
  (void)pthread_cond_broadcast(&group->cv);
  while (!group->release)
    (void)pthread_cond_wait(&group->cv, &group->lock);
  (void)pthread_mutex_unlock(&group->lock);

  if (result->result == 0) {
    result->result =
        (int)__syscall((quad_t)SYS_door, DOOR_SC_UNBIND, 0L, 0L, 0L, 0L, 0L);
    result->error = errno;
  }
  return (NULL);
}

ATF_TC_WITHOUT_HEAD(server_limit_and_release);

ATF_TC_BODY(server_limit_and_release, tc) {
  struct bind_group group;
  struct bind_result *results;
  pthread_t *threads;
  u_int limit;
  u_int i;
  unsigned int failed, succeeded;
  int fd;

  (void)tc;
  limit = (u_int)read_uint_limit("kern.doorfs.max_servers_per_door");
  if (limit == 0)
    atf_tc_skip("server bindings are disabled");
  fd = raw_create();
  ATF_REQUIRE(fd >= 0);
  memset(&group, 0, sizeof(group));
  group.fd = fd;
  ATF_REQUIRE(pthread_mutex_init(&group.lock, NULL) == 0);
  ATF_REQUIRE(pthread_cond_init(&group.cv, NULL) == 0);
  threads = calloc(limit + 1, sizeof(*threads));
  results = calloc(limit + 1, sizeof(*results));
  ATF_REQUIRE(threads != NULL && results != NULL);

  for (i = 0; i <= limit; i++) {
    results[i].group = &group;
    ATF_REQUIRE(pthread_create(&threads[i], NULL, bind_worker, &results[i]) ==
                0);
  }
  ATF_REQUIRE(pthread_mutex_lock(&group.lock) == 0);
  while (group.ready != limit + 1)
    ATF_REQUIRE(pthread_cond_wait(&group.cv, &group.lock) == 0);
  group.release = true;
  ATF_REQUIRE(pthread_cond_broadcast(&group.cv) == 0);
  ATF_REQUIRE(pthread_mutex_unlock(&group.lock) == 0);

  for (i = 0; i <= limit; i++)
    ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);
  succeeded = 0;
  failed = 0;
  for (i = 0; i <= limit; i++) {
    if (results[i].result == 0)
      succeeded++;
    else if (results[i].result == -1 && results[i].error == EAGAIN)
      failed++;
  }
  ATF_REQUIRE_MSG(succeeded == limit, "expected %u successful bindings, got %u",
                  limit, succeeded);
  ATF_REQUIRE_MSG(failed == 1, "expected one EAGAIN binding, got %u", failed);

  /* Every successful worker unbound, so the released slot is reusable. */
  group.ready = 0;
  results[0].result = -1;
  results[0].error = 0;
  ATF_REQUIRE(pthread_create(&threads[0], NULL, bind_worker, &results[0]) == 0);
  ATF_REQUIRE(pthread_join(threads[0], NULL) == 0);
  ATF_REQUIRE_MSG(results[0].result == 0,
                  "released server slot was not reusable: %s",
                  strerror(results[0].error));

  free(results);
  free(threads);
  ATF_REQUIRE(pthread_cond_destroy(&group.cv) == 0);
  ATF_REQUIRE(pthread_mutex_destroy(&group.lock) == 0);
  ATF_REQUIRE(close(fd) == 0);
}

ATF_TP_ADD_TCS(tp) {
  ATF_TP_ADD_TC(tp, sysctls_read_only);
  ATF_TP_ADD_TC(tp, door_limit_and_release);
  ATF_TP_ADD_TC(tp, server_limit_and_release);
  ATF_TP_ADD_TC(tp, shm_region_limit_and_release);
  ATF_TP_ADD_TC(tp, shm_byte_limit_and_release);
  ATF_TP_ADD_TC(tp, shm_revoke_cleanup);
  return (atf_no_error());
}
