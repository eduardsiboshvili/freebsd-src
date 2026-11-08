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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"
#define CLIENTS 100
#define EXEC_LOOPS 100
static int gatepipe[2];

static void
block(void *c, char *d, size_t n, door_desc_t *x, uint_t nx)
{
	char b;
	(void)c;
	(void)d;
	(void)n;
	(void)x;
	(void)nx;
	if (read(gatepipe[0], &b, 1) != 1)
		pthread_exit(NULL);
	door_return(__DECONST(char *, "ok"), 3, NULL, 0);
}

struct cc {
	int fd, rc, err;
};

static void *
callp(void *p)
{
	struct cc *c = p;
	door_arg_t a;
	char r[8];
	test_init_call(&a, r, sizeof(r));
	errno = 0;
	c->rc = door_call(c->fd, &a);
	c->err = errno;
	return NULL;
}

ATF_TC_WITHOUT_HEAD(mass_parallel_revoke);

ATF_TC_BODY(mass_parallel_revoke, tc)
{
	int fd, i;
	pthread_t t[CLIENTS];
	struct cc c[CLIENTS];
	(void)tc;
	ATF_REQUIRE(pipe(gatepipe) == 0);
	fd = door_create(block, NULL, DOOR_NO_DEPLETION_CB);
	ATF_REQUIRE(fd != -1);
	for (i = 0; i < CLIENTS; i++) {
		c[i].fd = fd;
		ATF_REQUIRE(pthread_create(&t[i], NULL, callp, &c[i]) == 0);
	}
	usleep(50000);
	ATF_REQUIRE(door_revoke(fd) == 0);
	for (i = 0; i < CLIENTS; i++) {
		ATF_REQUIRE(pthread_join(t[i], NULL) == 0);
		ATF_REQUIRE(c[i].rc == -1);
		ATF_REQUIRE(c[i].err == EBADF || c[i].err == ECONNRESET ||
			    c[i].err == ENXIO);
	}
	close(gatepipe[0]);
	close(gatepipe[1]);
	close(fd);
}

ATF_TC_WITHOUT_HEAD(fork_exec_smoke_storm);

ATF_TC_BODY(fork_exec_smoke_storm, tc)
{
	int i, status;
	(void)tc;
	for (i = 0; i < EXEC_LOOPS; i++) {
		pid_t p = fork();
		ATF_REQUIRE(p != -1);
		if (p == 0) {
			execl("/usr/bin/true", "true", NULL);
			_exit(127);
		}
		ATF_REQUIRE(waitpid(p, &status, 0) == p);
		ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, mass_parallel_revoke);
	ATF_TP_ADD_TC(tp, fork_exec_smoke_storm);
	return atf_no_error();
}
