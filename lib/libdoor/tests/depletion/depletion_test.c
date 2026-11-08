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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

struct depletion_state {
	pthread_mutex_t lock;
	pthread_cond_t cv;
	atomic_int create_calls;
	atomic_int depletion_calls;
	atomic_int callback_calls;
	atomic_int first_entered;
	atomic_int release_first;
	atomic_int default_cancel_disabled;
};

struct client_context {
	int fd;
	const char *message;
	atomic_int done;
	int result;
	int error;
};

static void
state_init(struct depletion_state *state)
{
	memset(state, 0, sizeof(*state));
	ATF_REQUIRE(pthread_mutex_init(&state->lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&state->cv, NULL) == 0);
}

static void
state_destroy(struct depletion_state *state)
{
	ATF_REQUIRE(pthread_cond_destroy(&state->cv) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&state->lock) == 0);
}

static void
depletion_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	struct depletion_state *state = cookie;
	int call, oldstate;

	(void)desc;
	(void)ndesc;
	call = atomic_fetch_add(&state->callback_calls, 1) + 1;
	if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate) == 0) {
		if (oldstate == PTHREAD_CANCEL_DISABLE)
			atomic_store(&state->default_cancel_disabled, 1);
		(void)pthread_setcancelstate(oldstate, NULL);
	}
	if (call == 1) {
		pthread_mutex_lock(&state->lock);
		atomic_store(&state->first_entered, 1);
		pthread_cond_broadcast(&state->cv);
		while (!atomic_load(&state->release_first))
			pthread_cond_wait(&state->cv, &state->lock);
		pthread_mutex_unlock(&state->lock);
	}
	(void)door_return(data, size, NULL, 0);
}

static int
depletion_create(door_info_t *info,
		 void *(*start)(void *),
		 void *arg,
		 void *cookie)
{
	struct depletion_state *state = cookie;
	pthread_t thread;
	int error;

	if (info == NULL || (info->di_attributes & DOOR_PRIVATE) == 0 ||
	    (info->di_attributes & DOOR_PRIVCREATE) == 0) {
		errno = EINVAL;
		return (-1);
	}
	atomic_fetch_add(&state->create_calls, 1);
	if ((info->di_attributes & DOOR_DEPLETION_CB) != 0)
		atomic_fetch_add(&state->depletion_calls, 1);
	error = pthread_create(&thread, NULL, start, arg);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	(void)pthread_detach(thread);
	return (1);
}

static void *
client_main(void *argument)
{
	struct client_context *context = argument;
	door_arg_t arg;
	char reply[64];

	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = __DECONST(char *, context->message);
	arg.data_size = strlen(context->message) + 1;
	errno = 0;
	context->result = door_call(context->fd, &arg);
	context->error = errno;
	atomic_store(&context->done, 1);
	return (NULL);
}

static void
wait_first(struct depletion_state *state)
{
	pthread_mutex_lock(&state->lock);
	while (!atomic_load(&state->first_entered))
		pthread_cond_wait(&state->cv, &state->lock);
	pthread_mutex_unlock(&state->lock);
}

static void
release_first(struct depletion_state *state)
{
	pthread_mutex_lock(&state->lock);
	atomic_store(&state->release_first, 1);
	pthread_cond_broadcast(&state->cv);
	pthread_mutex_unlock(&state->lock);
}

static int
create_door(struct depletion_state *state, uint_t attributes)
{
	int fd;

	fd = door_xcreate(depletion_server,
			  state,
			  attributes,
			  depletion_create,
			  NULL,
			  state,
			  1);
	ATF_REQUIRE_MSG(fd != -1, "door_xcreate failed: %s", strerror(errno));
	return (fd);
}

ATF_TC_WITHOUT_HEAD(xcreate_depletion_creates_worker);

ATF_TC_BODY(xcreate_depletion_creates_worker, tc)
{
	struct depletion_state state;
	struct client_context first = {0}, second = {0};
	pthread_t t1, t2;
	int fd, i;

	(void)tc;
	state_init(&state);
	fd = create_door(&state, 0);
	first.fd = fd;
	first.message = "first";
	second.fd = fd;
	second.message = "second";
	ATF_REQUIRE(pthread_create(&t1, NULL, client_main, &first) == 0);
	wait_first(&state);
	ATF_REQUIRE(pthread_create(&t2, NULL, client_main, &second) == 0);
	for (i = 0; i < 200 && !atomic_load(&second.done); i++)
		usleep(1000);
	ATF_REQUIRE_MSG(atomic_load(&second.done) != 0,
			"second call did not use a depletion worker");
	ATF_REQUIRE_MSG(atomic_load(&state.depletion_calls) >= 1,
			"depletion callback was not invoked");
	ATF_REQUIRE_MSG(atomic_load(&state.create_calls) >= 2,
			"no additional worker was created");
	release_first(&state);
	ATF_REQUIRE(pthread_join(t1, NULL) == 0);
	ATF_REQUIRE(pthread_join(t2, NULL) == 0);
	ATF_REQUIRE(first.result == 0);
	ATF_REQUIRE(second.result == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(xcreate_depletion_attribute);

ATF_TC_BODY(xcreate_depletion_attribute, tc)
{
	struct depletion_state state;
	struct client_context first = {0}, second = {0};
	pthread_t t1, t2;
	int fd, i;

	(void)tc;
	state_init(&state);
	fd = create_door(&state, 0);
	first.fd = second.fd = fd;
	first.message = "a";
	second.message = "b";
	ATF_REQUIRE(pthread_create(&t1, NULL, client_main, &first) == 0);
	wait_first(&state);
	ATF_REQUIRE(pthread_create(&t2, NULL, client_main, &second) == 0);
	for (i = 0; i < 200 && atomic_load(&state.depletion_calls) == 0; i++)
		usleep(1000);
	ATF_REQUIRE(atomic_load(&state.depletion_calls) == 1);
	release_first(&state);
	ATF_REQUIRE(pthread_join(t1, NULL) == 0);
	ATF_REQUIRE(pthread_join(t2, NULL) == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(xcreate_no_depletion_callback);

ATF_TC_BODY(xcreate_no_depletion_callback, tc)
{
	struct depletion_state state;
	struct client_context first = {0}, second = {0};
	pthread_t t1, t2;
	int fd;

	(void)tc;
	state_init(&state);
	fd = create_door(&state, DOOR_NO_DEPLETION_CB);
	first.fd = second.fd = fd;
	first.message = "first";
	second.message = "second";
	ATF_REQUIRE(pthread_create(&t1, NULL, client_main, &first) == 0);
	wait_first(&state);
	ATF_REQUIRE(pthread_create(&t2, NULL, client_main, &second) == 0);
	usleep(50000);
	ATF_REQUIRE(atomic_load(&second.done) == 0);
	ATF_REQUIRE(atomic_load(&state.depletion_calls) == 0);
	release_first(&state);
	ATF_REQUIRE(pthread_join(t1, NULL) == 0);
	ATF_REQUIRE(pthread_join(t2, NULL) == 0);
	ATF_REQUIRE(first.result == 0);
	ATF_REQUIRE(second.result == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(xcreate_default_thread_setup);

ATF_TC_BODY(xcreate_default_thread_setup, tc)
{
	struct depletion_state state;
	struct client_context first = {0};
	pthread_t thread;
	int fd;

	(void)tc;
	state_init(&state);
	atomic_store(&state.release_first, 1);
	fd = create_door(&state, DOOR_NO_DEPLETION_CB);
	first.fd = fd;
	first.message = "setup";
	ATF_REQUIRE(pthread_create(&thread, NULL, client_main, &first) == 0);
	ATF_REQUIRE(pthread_join(thread, NULL) == 0);
	ATF_REQUIRE(first.result == 0);
	ATF_REQUIRE(atomic_load(&state.default_cancel_disabled) == 1);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, xcreate_depletion_creates_worker);
	ATF_TP_ADD_TC(tp, xcreate_depletion_attribute);
	ATF_TP_ADD_TC(tp, xcreate_no_depletion_callback);
	ATF_TP_ADD_TC(tp, xcreate_default_thread_setup);
	return (atf_no_error());
}
