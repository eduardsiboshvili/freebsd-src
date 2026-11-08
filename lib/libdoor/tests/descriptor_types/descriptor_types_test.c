/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/event.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(__has_include)
#if __has_include(<sys/eventfd.h>)
#include <sys/eventfd.h>
#define HAVE_EVENTFD 1
#endif
#endif
#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

static int expected_kind;

static void
receive_one(void *c, char *d, size_t n, door_desc_t *x, uint_t nx)
{
	struct stat st;
	char b = 'Z', r = 0;
	(void)c;
	(void)d;
	(void)n;
	if (nx != 1 || fstat(x[0].d_descriptor, &st) == -1)
		door_return(__DECONST(char *, "bad"), 4, NULL, 0);
	switch (expected_kind) {
	case 1:
		if (write(x[0].d_descriptor, &b, 1) != 1)
			door_return(__DECONST(char *, "bad"), 4, NULL, 0);
		break;
	case 2:
		if (write(x[0].d_descriptor, &b, 1) != 1 ||
		    read(x[0].d_descriptor, &r, 1) != 1) {
		}
		break;
	case 3:
		if (kqueue() == -1) {
		}
		break;
	case 4:
		if (pwrite(x[0].d_descriptor, &b, 1, 0) != 1)
			door_return(__DECONST(char *, "bad"), 4, NULL, 0);
		break;
	}
	close(x[0].d_descriptor);
	door_return(__DECONST(char *, "ok"), 3, NULL, 0);
}

static void
receive_many(void *c, char *d, size_t n, door_desc_t *x, uint_t nx)
{
	uint_t i;
	(void)c;
	(void)d;
	(void)n;
	for (i = 0; i < nx; i++)
		close(x[i].d_descriptor);
	door_return(__DECONST(char *, "ok"), 3, NULL, 0);
}

static void
send_fd_call(int doorfd, int fd, door_attr_t attr)
{
	door_desc_t desc;
	door_arg_t a;
	char rep[8];
	test_init_desc(&desc, fd, attr);
	test_init_call(&a, rep, sizeof(rep));
	a.desc_ptr = &desc;
	a.desc_num = 1;
	ATF_REQUIRE_MSG(
	    door_call(doorfd, &a) == 0, "door_call: %s", strerror(errno));
	ATF_REQUIRE(strcmp(a.data_ptr, "ok") == 0);
}

ATF_TC_WITHOUT_HEAD(pipe_descriptor);

ATF_TC_BODY(pipe_descriptor, tc)
{
	int p[2], fd;
	char b;
	(void)tc;
	ATF_REQUIRE(pipe(p) == 0);
	expected_kind = 1;
	fd = test_create_door(receive_one);
	send_fd_call(fd, p[1], DOOR_DESCRIPTOR);
	ATF_REQUIRE(read(p[0], &b, 1) == 1 && b == 'Z');
	close(p[0]);
	close(p[1]);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(socketpair_descriptor);

ATF_TC_BODY(socketpair_descriptor, tc)
{
	int s[2], fd;
	char b = 'Q', r;
	(void)tc;
	ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0);
	expected_kind = 2;
	fd = test_create_door(receive_one);
	ATF_REQUIRE(write(s[1], &b, 1) == 1);
	send_fd_call(fd, s[0], DOOR_DESCRIPTOR);
	ATF_REQUIRE(read(s[1], &r, 1) == 1 && r == 'Z');
	close(s[0]);
	close(s[1]);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(kqueue_descriptor);

ATF_TC_BODY(kqueue_descriptor, tc)
{
	int k, fd;
	door_desc_t d;
	door_arg_t a;
	char rep[8];
	(void)tc;
	k = kqueue();
	ATF_REQUIRE(k != -1);
	fd = test_create_door(receive_one);
	test_init_desc(&d, k, DOOR_RELEASE);
	test_init_call(&a, rep, sizeof(rep));
	a.desc_ptr = &d;
	a.desc_num = 1;
	errno = 0;
	ATF_REQUIRE(door_call(fd, &a) == -1);
	ATF_REQUIRE(errno == EOPNOTSUPP || errno == ENOTSUP);
	/* Rejection must be atomic, including MOVE ownership. */
	ATF_REQUIRE(fcntl(k, F_GETFD) != -1);
	close(k);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(shm_descriptor);

ATF_TC_BODY(shm_descriptor, tc)
{
	int s, fd;
	char b = 0;
	(void)tc;
	s = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(s != -1);
	ATF_REQUIRE(ftruncate(s, 4096) == 0);
	expected_kind = 4;
	fd = test_create_door(receive_one);
	send_fd_call(fd, s, DOOR_DESCRIPTOR);
	ATF_REQUIRE(pread(s, &b, 1, 0) == 1 && b == 'Z');
	close(s);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(duplicated_descriptor_independent);

ATF_TC_BODY(duplicated_descriptor_independent, tc)
{
	int p[2], dupfd, fd;
	char b;
	(void)tc;
	ATF_REQUIRE(pipe(p) == 0);
	dupfd = dup(p[1]);
	ATF_REQUIRE(dupfd != -1);
	expected_kind = 1;
	fd = test_create_door(receive_one);
	send_fd_call(fd, dupfd, DOOR_RELEASE);
	ATF_REQUIRE(fcntl(dupfd, F_GETFD) == -1 && errno == EBADF);
	ATF_REQUIRE(write(p[1], "A", 1) == 1);
	ATF_REQUIRE(read(p[0], &b, 1) == 1 && b == 'Z');
	ATF_REQUIRE(read(p[0], &b, 1) == 1 && b == 'A');
	close(p[0]);
	close(p[1]);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(closed_before_call_is_atomic);

ATF_TC_BODY(closed_before_call_is_atomic, tc)
{
	int p[2], fd, closed_fd;
	door_desc_t d;
	door_arg_t a;
	char rep[8];
	(void)tc;
	/* Create the door first so its internal fd cannot reuse closed_fd. */
	fd = test_create_door(receive_one);
	ATF_REQUIRE(pipe(p) == 0);
	closed_fd = p[1];
	test_init_desc(&d, closed_fd, DOOR_RELEASE);
	ATF_REQUIRE(close(closed_fd) == 0);
	test_init_call(&a, rep, sizeof(rep));
	a.desc_ptr = &d;
	a.desc_num = 1;
	errno = 0;
	ATF_REQUIRE(door_call(fd, &a) == -1);
	ATF_REQUIRE(errno == EBADF);
	close(p[0]);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(multiple_move_descriptors);

ATF_TC_BODY(multiple_move_descriptors, tc)
{
	enum { N = 16 };

	int p[N][2], fd, i;
	door_desc_t d[N];
	door_arg_t a;
	char rep[8];
	(void)tc;
	fd = test_create_door(receive_many);
	for (i = 0; i < N; i++) {
		ATF_REQUIRE(pipe(p[i]) == 0);
		test_init_desc(&d[i], p[i][1], DOOR_RELEASE);
	}
	test_init_call(&a, rep, sizeof(rep));
	a.desc_ptr = d;
	a.desc_num = N;
	ATF_REQUIRE_MSG(door_call(fd, &a) == 0,
			"multiple MOVE failed: %s",
			strerror(errno));
	for (i = 0; i < N; i++)
		ATF_REQUIRE(fcntl(p[i][1], F_GETFD) == -1 && errno == EBADF);
	for (i = 0; i < N; i++) {
		if (fcntl(p[i][1], F_GETFD) != -1)
			close(p[i][1]);
		close(p[i][0]);
	}
	test_close_door(fd);
}

#ifdef HAVE_EVENTFD
static void
receive_eventfd(void *c, char *d, size_t n, door_desc_t *x, uint_t nx)
{
	uint64_t v = 1;
	(void)c;
	(void)d;
	(void)n;
	if (nx != 1 ||
	    write(x[0].d_descriptor, &v, sizeof(v)) != (ssize_t)sizeof(v))
		door_return(__DECONST(char *, "bad"), 4, NULL, 0);
	close(x[0].d_descriptor);
	door_return(__DECONST(char *, "ok"), 3, NULL, 0);
}

ATF_TC_WITHOUT_HEAD(eventfd_descriptor);

ATF_TC_BODY(eventfd_descriptor, tc)
{
	int efd, fd;
	uint64_t value;
	(void)tc;
	efd = eventfd(0, 0);
	ATF_REQUIRE_MSG(efd != -1, "eventfd: %s", strerror(errno));
	fd = test_create_door(receive_eventfd);
	send_fd_call(fd, efd, DOOR_DESCRIPTOR);
	ATF_REQUIRE(read(efd, &value, sizeof(value)) == (ssize_t)sizeof(value));
	ATF_REQUIRE(value == 1);
	close(efd);
	test_close_door(fd);
}
#endif

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, pipe_descriptor);
	ATF_TP_ADD_TC(tp, socketpair_descriptor);
	ATF_TP_ADD_TC(tp, kqueue_descriptor);
	ATF_TP_ADD_TC(tp, shm_descriptor);
	ATF_TP_ADD_TC(tp, duplicated_descriptor_independent);
	ATF_TP_ADD_TC(tp, closed_before_call_is_atomic);
	ATF_TP_ADD_TC(tp, multiple_move_descriptors);
#ifdef HAVE_EVENTFD
	ATF_TP_ADD_TC(tp, eventfd_descriptor);
#endif
	return atf_no_error();
}
