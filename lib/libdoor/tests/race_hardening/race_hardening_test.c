/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define RACE_ITERS 500
#define STRESS_THREADS 12
#define STRESS_LOOPS 100

static void
echo(void *c, char *d, size_t n, door_desc_t *x, uint_t nx)
{
	(void)c;
	(void)x;
	(void)nx;
	door_return(d, n, NULL, 0);
}

struct rc {
	int fd;
	atomic_int go;
	int result;
	int error;
};

static void *
do_revoke(void *p)
{
	struct rc *r = p;
	while (!atomic_load(&r->go))
		sched_yield();
	errno = 0;
	r->result = door_revoke(r->fd);
	r->error = errno;
	return NULL;
}

static void *
do_close(void *p)
{
	struct rc *r = p;
	while (!atomic_load(&r->go))
		sched_yield();
	errno = 0;
	r->result = close(r->fd);
	r->error = errno;
	return NULL;
}

ATF_TC_WITHOUT_HEAD(revoke_close_same_door_race);

ATF_TC_BODY(revoke_close_same_door_race, tc)
{
	int i;
	(void)tc;
	for (i = 0; i < RACE_ITERS; i++) {
		/* Separate dup slots, one generation; this is not numeric fd reuse. */
		int fd = test_create_door(echo), a = dup(fd), b = dup(fd);
		pthread_t t1, t2;
		struct rc r1 = {.fd = a}, r2 = {.fd = b};
		ATF_REQUIRE(a != -1 && b != -1);
		ATF_REQUIRE(pthread_create(&t1, NULL, do_revoke, &r1) == 0);
		ATF_REQUIRE(pthread_create(&t2, NULL, do_close, &r2) == 0);
		atomic_store(&r1.go, 1);
		atomic_store(&r2.go, 1);
		ATF_REQUIRE(pthread_join(t1, NULL) == 0);
		ATF_REQUIRE(pthread_join(t2, NULL) == 0);
		ATF_REQUIRE(r2.result == 0);
		/* Closing b cannot invalidate the distinct live slot a. */
		ATF_REQUIRE(r1.result == 0);
		(void)close(a);
		(void)close(fd);
	}
}

ATF_TC_WITHOUT_HEAD(revoke_fork_race);

ATF_TC_BODY(revoke_fork_race, tc)
{
	int i;
	(void)tc;
	for (i = 0; i < 200; i++) {
		int fd = test_create_door(echo), status;
		pid_t p = fork();
		ATF_REQUIRE(p != -1);
		if (p == 0) {
			char rep[8];
			door_arg_t a;
			alarm(TEST_TIMEOUT_SECONDS);
			test_init_call(&a, rep, sizeof(rep));
			errno = 0;
			if (door_call(fd, &a) == 0 || errno == EBADF ||
			    errno == ENXIO || errno == ECONNRESET)
				_exit(0);
			_exit(1);
		}
		ATF_REQUIRE(door_revoke(fd) == 0);
		ATF_REQUIRE(waitpid(p, &status, 0) == p);
		ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
		ATF_REQUIRE(close(fd) == 0);
	}
}

struct stress_arg {
	atomic_int *fail;
};

static void *
create_revoke_loop(void *p)
{
	struct stress_arg *a = p;
	int i;
	for (i = 0; i < STRESS_LOOPS; i++) {
		int fd = door_create(echo, NULL, 0);
		if (fd == -1) {
			atomic_store(a->fail, 1);
			return NULL;
		}
		if (door_revoke(fd) == -1 && errno != EBADF)
			atomic_store(a->fail, 1);
		if (close(fd) == -1)
			atomic_store(a->fail, 1);
	}
	return NULL;
}

ATF_TC_WITHOUT_HEAD(parallel_create_revoke_stress);

ATF_TC_BODY(parallel_create_revoke_stress, tc)
{
	pthread_t t[STRESS_THREADS];
	struct stress_arg a;
	atomic_int fail = 0;
	int i;
	(void)tc;
	a.fail = &fail;
	for (i = 0; i < STRESS_THREADS; i++)
		ATF_REQUIRE(
		    pthread_create(&t[i], NULL, create_revoke_loop, &a) == 0);
	for (i = 0; i < STRESS_THREADS; i++)
		ATF_REQUIRE(pthread_join(t[i], NULL) == 0);
	ATF_REQUIRE(atomic_load(&fail) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, revoke_close_same_door_race);
	ATF_TP_ADD_TC(tp, revoke_fork_race);
	ATF_TP_ADD_TC(tp, parallel_create_revoke_stress);
	return atf_no_error();
}
