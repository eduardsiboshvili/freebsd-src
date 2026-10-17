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

struct xstate {
	atomic_int create_calls;
	atomic_int setup_calls;
	atomic_int callback_calls;
	atomic_int fail_after;
	atomic_int bad_info;
    pthread_t threads[32];
    unsigned int nthreads;
};

/* Serialize publication of joinable factory threads, including depletion. */
static pthread_mutex_t xthreads_lock = PTHREAD_MUTEX_INITIALIZER;

static void
join_xthreads(struct xstate *state)
{
    pthread_t thread;
    unsigned int i;

    /* Revoke/close first; join parent workers before subsequently created ones. */
    for (i = 0; ; i++) {
        ATF_REQUIRE(pthread_mutex_lock(&xthreads_lock) == 0);
        if (i == state->nthreads) {
            ATF_REQUIRE(pthread_mutex_unlock(&xthreads_lock) == 0);
            break;
        }
        thread = state->threads[i];
        ATF_REQUIRE(pthread_mutex_unlock(&xthreads_lock) == 0);
        ATF_REQUIRE(pthread_join(thread, NULL) == 0);
    }
}

static void
xecho(void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	struct xstate *state = cookie;

	(void)desc;
	(void)ndesc;
	atomic_fetch_add(&state->callback_calls, 1);
	(void)door_return(data, size, NULL, 0);
}

static void
xsetup(void *cookie)
{
	struct xstate *state = cookie;

	atomic_fetch_add(&state->setup_calls, 1);
}

static int
xthread_create(door_info_t *info,
	       void *(*start)(void *),
	       void *arg,
	       void *cookie)
{
	struct xstate *state = cookie;
	pthread_t thread;
	int call, error;

	if (info == NULL || (info->di_attributes & DOOR_PRIVATE) == 0 ||
	    (info->di_attributes & DOOR_PRIVCREATE) == 0) {
		atomic_store(&state->bad_info, 1);
		errno = EINVAL;
		return (-1);
	}
	call = atomic_fetch_add(&state->create_calls, 1) + 1;
	if (atomic_load(&state->fail_after) != 0 &&
	    call >= atomic_load(&state->fail_after)) {
		errno = EAGAIN;
		return (-1);
	}
    ATF_REQUIRE(pthread_mutex_lock(&xthreads_lock) == 0);

    if (state->nthreads == nitems(state->threads))
        error = EAGAIN;
    else {
        error = pthread_create(&thread, NULL, start, arg);
        if (error == 0)
            state->threads[state->nthreads++] = thread;
    }
    ATF_REQUIRE(pthread_mutex_unlock(&xthreads_lock) == 0);

    if (error != 0) {
        errno = error;
        return (-1);
    }
	return (1);
}

static int
create_xdoor(struct xstate *state, uint_t attr, int nthreads)
{
	int fd;

	fd = door_xcreate(
	    xecho, state, attr, xthread_create, xsetup, state, nthreads);
	ATF_REQUIRE_MSG(fd != -1, "door_xcreate failed: %s", strerror(errno));
	return (fd);
}

static void
require_echo(int fd, const char *message)
{
	door_arg_t arg;
	char reply[64];
	size_t len;

	len = strlen(message) + 1;
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = __DECONST(char *, message);
	arg.data_size = len;
	ATF_REQUIRE_MSG(
	    door_call(fd, &arg) == 0, "door_call failed: %s", strerror(errno));
	ATF_REQUIRE(arg.data_size == len);
	ATF_REQUIRE(strcmp(arg.data_ptr, message) == 0);
}

ATF_TC_WITHOUT_HEAD(basic_xcreate);

ATF_TC_BODY(basic_xcreate, tc)
{
	struct xstate state = {0};
	int fd;

	(void)tc;
	fd = create_xdoor(&state, 0, 2);
	ATF_REQUIRE(atomic_load(&state.create_calls) == 2);
	ATF_REQUIRE(atomic_load(&state.setup_calls) == 2);
	ATF_REQUIRE(atomic_load(&state.bad_info) == 0);
	require_echo(fd, "xcreate");
	ATF_REQUIRE(atomic_load(&state.callback_calls) == 1);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
    join_xthreads(&state);
}

ATF_TC_WITHOUT_HEAD(attributes_are_normalized);

ATF_TC_BODY(attributes_are_normalized, tc)
{
	struct xstate state = {0};
	door_info_t info;
	int fd;

	(void)tc;
	fd = create_xdoor(&state, DOOR_UNREF_MULTI, 1);
	ATF_REQUIRE(door_info(fd, &info) == 0);
	ATF_REQUIRE((info.di_attributes & DOOR_PRIVATE) != 0);
	ATF_REQUIRE((info.di_attributes & DOOR_PRIVCREATE) != 0);
	ATF_REQUIRE((info.di_attributes & DOOR_UNREF) != 0);
	ATF_REQUIRE((info.di_attributes & DOOR_UNREF_MULTI) != 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
    join_xthreads(&state);
}

ATF_TC_WITHOUT_HEAD(invalid_arguments);

ATF_TC_BODY(invalid_arguments, tc)
{
	struct xstate state = {0};

	(void)tc;
	errno = 0;
	ATF_REQUIRE(
	    door_xcreate(NULL, &state, 0, xthread_create, xsetup, &state, 1) ==
	    -1);
	ATF_REQUIRE(errno == EINVAL);
	errno = 0;
	ATF_REQUIRE(door_xcreate(xecho, &state, 0, NULL, xsetup, &state, 1) ==
		    -1);
	ATF_REQUIRE(errno == EINVAL);
	errno = 0;
	ATF_REQUIRE(
	    door_xcreate(xecho, &state, 0, xthread_create, xsetup, &state, 0) ==
	    -1);
	ATF_REQUIRE(errno == EINVAL);
	errno = 0;
	ATF_REQUIRE(door_xcreate(xecho,
				 &state,
				 DOOR_PRIVCREATE,
				 xthread_create,
				 xsetup,
				 &state,
				 1) == -1);
	ATF_REQUIRE(errno == EINVAL);
}

ATF_TC_WITHOUT_HEAD(initial_thread_count);

ATF_TC_BODY(initial_thread_count, tc)
{
	struct xstate state = {0};
	int fd;

	(void)tc;
	fd = create_xdoor(&state, 0, 4);
	ATF_REQUIRE(atomic_load(&state.create_calls) == 4);
	ATF_REQUIRE(atomic_load(&state.setup_calls) == 4);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
    join_xthreads(&state);
}

ATF_TC_WITHOUT_HEAD(two_private_doors_are_independent);

ATF_TC_BODY(two_private_doors_are_independent, tc)
{
	struct xstate first = {0}, second = {0};
	int fd1, fd2;

	(void)tc;
	fd1 = create_xdoor(&first, 0, 1);
	fd2 = create_xdoor(&second, 0, 1);
	require_echo(fd1, "first");
	require_echo(fd2, "second");
	ATF_REQUIRE(atomic_load(&first.callback_calls) == 1);
	ATF_REQUIRE(atomic_load(&second.callback_calls) == 1);
	ATF_REQUIRE(door_revoke(fd1) == 0);
	require_echo(fd2, "still-alive");
	ATF_REQUIRE(door_revoke(fd2) == 0);
	test_close_door(fd1);
	test_close_door(fd2);
    join_xthreads(&first);
    join_xthreads(&second);
}

ATF_TC_WITHOUT_HEAD(partial_creation_failure_rolls_back);

ATF_TC_BODY(partial_creation_failure_rolls_back, tc)
{
	struct xstate state = {0};

	(void)tc;
	atomic_store(&state.fail_after, 2);
	errno = 0;
	ATF_REQUIRE(
	    door_xcreate(xecho, &state, 0, xthread_create, xsetup, &state, 3) ==
	    -1);
	ATF_REQUIRE(errno == EPIPE);
	ATF_REQUIRE(atomic_load(&state.create_calls) == 2);
    join_xthreads(&state);
}

ATF_TC_WITHOUT_HEAD(ordinary_create_rejects_privcreate);

ATF_TC_BODY(ordinary_create_rejects_privcreate, tc)
{
	struct xstate state = {0};

	(void)tc;
	errno = 0;
	ATF_REQUIRE(door_create(xecho, &state, DOOR_PRIVCREATE) == -1);
	ATF_REQUIRE(errno == EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, basic_xcreate);
	ATF_TP_ADD_TC(tp, attributes_are_normalized);
	ATF_TP_ADD_TC(tp, invalid_arguments);
	ATF_TP_ADD_TC(tp, initial_thread_count);
	ATF_TP_ADD_TC(tp, two_private_doors_are_independent);
	ATF_TP_ADD_TC(tp, partial_creation_failure_rolls_back);
	ATF_TP_ADD_TC(tp, ordinary_create_rejects_privcreate);
	return (atf_no_error());
}
