/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/mman.h>
#include <sys/stat.h>
#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

static void
accept_one(void *c, char *d, size_t n, door_desc_t *x, uint_t nx)
{
	struct stat st;
	(void)c;
	(void)d;
	(void)n;
	if (nx != 1 || fstat(x[0].d_descriptor, &st) == -1)
		door_return(__DECONST(char *, "bad"), 4, NULL, 0);
	close(x[0].d_descriptor);
	door_return(__DECONST(char *, "ok"), 3, NULL, 0);
}

static void
accept_many(void *c, char *d, size_t n, door_desc_t *x, uint_t nx)
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
sendone(int doorfd, int fd, door_attr_t attr)
{
	door_desc_t x;
	door_arg_t a;
	char r[8];
	test_init_desc(&x, fd, attr);
	test_init_call(&a, r, sizeof(r));
	a.desc_ptr = &x;
	a.desc_num = 1;
	ATF_REQUIRE_MSG(
	    door_call(doorfd, &a) == 0, "door_call: %s", strerror(errno));
	ATF_REQUIRE(strcmp(a.data_ptr, "ok") == 0);
}

ATF_TC_WITHOUT_HEAD(directory_descriptor);

ATF_TC_BODY(directory_descriptor, tc)
{
	int dfd, fd;
	(void)tc;
	dfd = open("/tmp", O_RDONLY | O_DIRECTORY);
	ATF_REQUIRE(dfd != -1);
	fd = test_create_door(accept_one);
	sendone(fd, dfd, DOOR_DESCRIPTOR);
	close(dfd);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(device_descriptor);

ATF_TC_BODY(device_descriptor, tc)
{
	int dfd, fd;
	(void)tc;
	dfd = open("/dev/null", O_RDWR);
	ATF_REQUIRE(dfd != -1);
	fd = test_create_door(accept_one);
	sendone(fd, dfd, DOOR_DESCRIPTOR);
	close(dfd);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(door_descriptor_through_door);

ATF_TC_BODY(door_descriptor_through_door, tc)
{
	int target, carrier;
	(void)tc;
	target = test_create_door(accept_one);
	carrier = test_create_door(accept_one);
	sendone(carrier, target, DOOR_DESCRIPTOR);
	test_close_door(target);
	test_close_door(carrier);
}

ATF_TC_WITHOUT_HEAD(shm_grow_shrink_after_copy);

ATF_TC_BODY(shm_grow_shrink_after_copy, tc)
{
	int s, fd;
	(void)tc;
	s = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE(s != -1);
	ATF_REQUIRE(ftruncate(s, 4096) == 0);
	fd = test_create_door(accept_one);
	sendone(fd, s, DOOR_DESCRIPTOR);
	ATF_REQUIRE(ftruncate(s, 8192) == 0);
	ATF_REQUIRE(ftruncate(s, 1024) == 0);
	close(s);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(descriptor_graph_copy_move_copy);

ATF_TC_BODY(descriptor_graph_copy_move_copy, tc)
{
	int p[2], dup1, dup2, fd;
	char b;
	(void)tc;
	ATF_REQUIRE(pipe(p) == 0);
	dup1 = dup(p[1]);
	dup2 = dup(dup1);
	ATF_REQUIRE(dup1 != -1 && dup2 != -1);
	fd = test_create_door(accept_one);
	sendone(fd, dup1, DOOR_DESCRIPTOR);
	sendone(fd, dup2, DOOR_RELEASE);
	ATF_REQUIRE(fcntl(dup2, F_GETFD) == -1 && errno == EBADF);
	ATF_REQUIRE(write(p[1], "Z", 1) == 1);
	ATF_REQUIRE(read(p[0], &b, 1) == 1 && b == 'Z');
	close(dup1);
	close(p[0]);
	close(p[1]);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(large_mixed_array_atomic_failure);

ATF_TC_BODY(large_mixed_array_atomic_failure, tc)
{
	enum { N = 64 };

	int p[N][2], fd, i;
	door_desc_t x[N];
	door_arg_t a;
	char r[8];
	(void)tc;
	fd = test_create_door(accept_many);
	for (i = 0; i < N; i++) {
		ATF_REQUIRE(pipe(p[i]) == 0);
		test_init_desc(
		    &x[i], p[i][1], (i & 1) ? DOOR_RELEASE : DOOR_DESCRIPTOR);
	}
	close(p[N / 2][1]);
	test_init_call(&a, r, sizeof(r));
	a.desc_ptr = x;
	a.desc_num = N;
	errno = 0;
	ATF_REQUIRE(door_call(fd, &a) == -1);
	ATF_REQUIRE(errno == EBADF);
	for (i = 0; i < N; i++) {
		if (i != N / 2)
			ATF_REQUIRE(fcntl(p[i][1], F_GETFD) != -1);
		close(p[i][0]);
		if (i != N / 2)
			close(p[i][1]);
	}
	test_close_door(fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, directory_descriptor);
	ATF_TP_ADD_TC(tp, device_descriptor);
	ATF_TP_ADD_TC(tp, door_descriptor_through_door);
	ATF_TP_ADD_TC(tp, shm_grow_shrink_after_copy);
	ATF_TP_ADD_TC(tp, descriptor_graph_copy_move_copy);
	ATF_TP_ADD_TC(tp, large_mixed_array_atomic_failure);
	return atf_no_error();
}
