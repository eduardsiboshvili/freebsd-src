/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBDOOR_TEST_COMMON_H
#define LIBDOOR_TEST_COMMON_H

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>

#include <errno.h>
#include <door.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TEST_TIMEOUT_SECONDS 10

struct test_guarded_region {
	void *mapping;
	size_t mapping_size;
	size_t page_size;
	void *guard;
};

typedef int (*test_child_fn)(void *);

void test_close_received_descs(door_arg_t *);
bool test_fd_valid(int);
void test_require_fd_valid(int);
void test_require_errno_one_of(int, int, const int *, size_t, const char *);
int test_make_regular_fd(void);
int test_make_socket_fd(void);
int test_create_door(door_server_procedure_t *);
void test_close_door(int);
void test_init_desc(door_desc_t *, int, door_attr_t);
void test_init_call(door_arg_t *, char *, size_t);
int test_guarded_region_create(struct test_guarded_region *);
void test_guarded_region_destroy(struct test_guarded_region *);
int test_run_child(test_child_fn, void *, int *, int *);

#define TEST_REQUIRE_ERRNO_ONE_OF(expression, errors)                          \
	do {                                                                   \
		int _error;                                                    \
		int _result;                                                   \
                                                                               \
		errno = 0;                                                     \
		_result = (expression);                                        \
		_error = errno;                                                \
		test_require_errno_one_of(                                     \
		    _result, _error, (errors), nitems(errors), #expression);   \
	} while (0)

#endif /* LIBDOOR_TEST_COMMON_H */
