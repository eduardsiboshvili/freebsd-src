/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
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

struct wstate {
	pthread_mutex_t lock;
	pthread_t threads[32];
	int nthreads;
	atomic_int entered;
	int notify[2];
	int release[2];
};
static struct wstate *global_state;

static void
setup_cancel(void *cookie)
{
	(void)cookie;
	(void)pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	(void)pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
}

static int
factory(door_info_t *info, void *(*start)(void *), void *arg, void *cookie)
{
	struct wstate *s = cookie;
	pthread_t t;
	int e;
	(void)info;
	e = pthread_create(&t, NULL, start, arg);
	if (e) {
		errno = e;
		return -1;
	}
	pthread_mutex_lock(&s->lock);
	if (s->nthreads < 32)
		s->threads[s->nthreads++] = t;
	pthread_mutex_unlock(&s->lock);
	return 1;
}

static void
blocking(void *c, char *d, size_t n, door_desc_t *x, uint_t nx)
{
	struct wstate *s = c;
	char b = 'E';
	(void)d;
	(void)n;
	(void)x;
	(void)nx;
	atomic_fetch_add(&s->entered, 1);
	(void)write(s->notify[1], &b, 1);
	if (read(s->release[0], &b, 1) != 1)
		pthread_exit(NULL);
	door_return(__DECONST(char *, "ok"), 3, NULL, 0);
}

static void
exiting(void *c, char *d, size_t n, door_desc_t *x, uint_t nx)
{
	struct wstate *s = c;
	char b = 'E';
	(void)d;
	(void)n;
	(void)x;
	(void)nx;
	atomic_fetch_add(&s->entered, 1);
	(void)write(s->notify[1], &b, 1);
	pthread_exit(NULL);
}

struct callctx {
	int fd;
	int rc;
	int err;
};

static void *
caller(void *p)
{
	struct callctx *c = p;
	char r[8];
	door_arg_t a;
	test_init_call(&a, r, sizeof(r));
	errno = 0;
	c->rc = door_call(c->fd, &a);
	c->err = errno;
	return NULL;
}

static void
init_state(struct wstate *s)
{
	memset(s, 0, sizeof(*s));
	ATF_REQUIRE(pthread_mutex_init(&s->lock, NULL) == 0);
	ATF_REQUIRE(pipe(s->notify) == 0);
	ATF_REQUIRE(pipe(s->release) == 0);
	global_state = s;
}

static void
fini_state(struct wstate *s)
{
	close(s->notify[0]);
	close(s->notify[1]);
	close(s->release[0]);
	close(s->release[1]);
	pthread_mutex_destroy(&s->lock);
	global_state = NULL;
}

ATF_TC_WITHOUT_HEAD(pthread_cancel_active_worker_aborts_call);

ATF_TC_BODY(pthread_cancel_active_worker_aborts_call, tc)
{
	struct wstate s;
	struct callctx c;
	pthread_t ct, wt;
	char b;
	int fd;
	(void)tc;
	init_state(&s);
	fd = door_xcreate(
	    blocking, &s, DOOR_NO_DEPLETION_CB, factory, setup_cancel, &s, 1);
	ATF_REQUIRE(fd != -1);
	c.fd = fd;
	ATF_REQUIRE(pthread_create(&ct, NULL, caller, &c) == 0);
	ATF_REQUIRE(read(s.notify[0], &b, 1) == 1);
	pthread_mutex_lock(&s.lock);
	wt = s.threads[0];
	pthread_mutex_unlock(&s.lock);
	ATF_REQUIRE(pthread_cancel(wt) == 0);
	ATF_REQUIRE(pthread_join(wt, NULL) == 0);
	ATF_REQUIRE(pthread_join(ct, NULL) == 0);
	ATF_REQUIRE(c.rc == -1);
	ATF_REQUIRE(c.err == ECONNRESET || c.err == EBADF);
	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
	fini_state(&s);
}

ATF_TC_WITHOUT_HEAD(pthread_exit_worker_aborts_call_other_worker_survives);

ATF_TC_BODY(pthread_exit_worker_aborts_call_other_worker_survives, tc)
{
	struct wstate s;
	struct callctx c;
	pthread_t ct;
	char b;
	int fd;
	(void)tc;
	init_state(&s);
	fd = door_xcreate(
	    exiting, &s, DOOR_NO_DEPLETION_CB, factory, NULL, &s, 2);
	ATF_REQUIRE(fd != -1);
	c.fd = fd;
	ATF_REQUIRE(pthread_create(&ct, NULL, caller, &c) == 0);
	ATF_REQUIRE(read(s.notify[0], &b, 1) == 1);
	ATF_REQUIRE(pthread_join(ct, NULL) == 0);
	ATF_REQUIRE(c.rc == -1);
	ATF_REQUIRE(c.err == ECONNRESET || c.err == EBADF);
	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
	fini_state(&s);
}

ATF_TC_WITHOUT_HEAD(new_worker_binds_during_depletion_after_cancel);

ATF_TC_BODY(new_worker_binds_during_depletion_after_cancel, tc)
{
	struct wstate s;
	struct callctx c1, c2;
	pthread_t t1, t2, wt;
	char b = 'R';
	int fd, i;
	(void)tc;
	init_state(&s);
	fd = door_xcreate(blocking, &s, 0, factory, setup_cancel, &s, 1);
	ATF_REQUIRE(fd != -1);
	c1.fd = fd;
	c2.fd = fd;
	ATF_REQUIRE(pthread_create(&t1, NULL, caller, &c1) == 0);
	ATF_REQUIRE(read(s.notify[0], &b, 1) == 1);
	for (i = 0; i < 100 && s.nthreads < 2; i++)
		usleep(1000);
	ATF_REQUIRE(s.nthreads >= 2);
	ATF_REQUIRE(pthread_create(&t2, NULL, caller, &c2) == 0);
	ATF_REQUIRE(read(s.notify[0], &b, 1) == 1);
	pthread_mutex_lock(&s.lock);
	wt = s.threads[0];
	pthread_mutex_unlock(&s.lock);
	ATF_REQUIRE(pthread_cancel(wt) == 0);
	ATF_REQUIRE(pthread_join(wt, NULL) == 0);
	b = 'R';
	ATF_REQUIRE(write(s.release[1], &b, 1) == 1);
	ATF_REQUIRE(pthread_join(t1, NULL) == 0);
	ATF_REQUIRE(pthread_join(t2, NULL) == 0);
	ATF_REQUIRE(c1.rc == -1 || c2.rc == -1);
	ATF_REQUIRE(c1.rc == 0 || c2.rc == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
	fini_state(&s);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, pthread_cancel_active_worker_aborts_call);
	ATF_TP_ADD_TC(tp,
		      pthread_exit_worker_aborts_call_other_worker_survives);
	ATF_TP_ADD_TC(tp, new_worker_binds_during_depletion_after_cancel);
	return atf_no_error();
}
