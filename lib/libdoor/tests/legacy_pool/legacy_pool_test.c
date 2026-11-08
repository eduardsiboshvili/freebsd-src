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

struct pool_state {
	pthread_mutex_t lock;
	pthread_cond_t cv;
	atomic_int factory_calls;
	atomic_int shared_null_calls;
	atomic_int private_info_calls;
	atomic_int depletion_calls;
	atomic_int callback_calls;
	atomic_int first_entered;
	atomic_int release_first;
};

struct client_context {
	int fd;
	const char *message;
	atomic_int done;
	int result;
	int error;
};

static struct pool_state *factory_state;

static void
pool_factory(door_info_t *info)
{
	struct pool_state *state = factory_state;

	if (state == NULL)
		return;
	atomic_fetch_add(&state->factory_calls, 1);
	if (info == NULL) {
		atomic_fetch_add(&state->shared_null_calls, 1);
		return;
	}
	atomic_fetch_add(&state->private_info_calls, 1);
	if ((info->di_attributes & DOOR_DEPLETION_CB) != 0)
		atomic_fetch_add(&state->depletion_calls, 1);
}

static void
pool_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	struct pool_state *state = cookie;
	int call;

	(void)desc;
	(void)ndesc;
	call = atomic_fetch_add(&state->callback_calls, 1) + 1;
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

static void
state_init(struct pool_state *state)
{
	memset(state, 0, sizeof(*state));
	ATF_REQUIRE(pthread_mutex_init(&state->lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&state->cv, NULL) == 0);
	factory_state = state;
}

static void
state_destroy(struct pool_state *state)
{
	factory_state = NULL;
	ATF_REQUIRE(pthread_cond_destroy(&state->cv) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&state->lock) == 0);
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
wait_first(struct pool_state *state)
{
	pthread_mutex_lock(&state->lock);
	while (!atomic_load(&state->first_entered))
		pthread_cond_wait(&state->cv, &state->lock);
	pthread_mutex_unlock(&state->lock);
}

static void
release_first(struct pool_state *state)
{
	pthread_mutex_lock(&state->lock);
	atomic_store(&state->release_first, 1);
	pthread_cond_broadcast(&state->cv);
	pthread_mutex_unlock(&state->lock);
}

ATF_TC_WITHOUT_HEAD(factory_replacement_returns_previous);

ATF_TC_BODY(factory_replacement_returns_previous, tc)
{
	(void)tc;
	ATF_REQUIRE(door_server_create(pool_factory) == NULL);
	ATF_REQUIRE(door_server_create(NULL) == pool_factory);
}

ATF_TC_WITHOUT_HEAD(shared_factory_receives_null);

ATF_TC_BODY(shared_factory_receives_null, tc)
{
	struct pool_state state;
	door_server_func_t *old;
	int fd;

	(void)tc;
	state_init(&state);
	old = door_server_create(pool_factory);
	fd = door_create(pool_server, &state, 0);
	ATF_REQUIRE_MSG(fd != -1, "door_create failed: %s", strerror(errno));
	ATF_REQUIRE(atomic_load(&state.shared_null_calls) >= 1);
	ATF_REQUIRE(atomic_load(&state.private_info_calls) == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	(void)door_server_create(old);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(legacy_private_factory_receives_info);

ATF_TC_BODY(legacy_private_factory_receives_info, tc)
{
	struct pool_state state;
	door_server_func_t *old;
	int fd;

	(void)tc;
	state_init(&state);
	old = door_server_create(pool_factory);
	fd = door_create(pool_server, &state, DOOR_PRIVATE);
	ATF_REQUIRE_MSG(fd != -1, "door_create failed: %s", strerror(errno));
	ATF_REQUIRE(atomic_load(&state.private_info_calls) >= 1);
	ATF_REQUIRE(atomic_load(&state.shared_null_calls) == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	(void)door_server_create(old);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(legacy_private_depletion_progress);

ATF_TC_BODY(legacy_private_depletion_progress, tc)
{
	struct pool_state state;
	struct client_context first = {0}, second = {0};
	door_server_func_t *old;
	pthread_t t1, t2;
	int fd, i;

	(void)tc;
	state_init(&state);
	old = door_server_create(pool_factory);
	fd = door_create(pool_server, &state, DOOR_PRIVATE);
	ATF_REQUIRE(fd != -1);
	first.fd = second.fd = fd;
	first.message = "first";
	second.message = "second";
	ATF_REQUIRE(pthread_create(&t1, NULL, client_main, &first) == 0);
	wait_first(&state);
	ATF_REQUIRE(pthread_create(&t2, NULL, client_main, &second) == 0);
	for (i = 0; i < 200 && !atomic_load(&second.done); i++)
		usleep(1000);
	ATF_REQUIRE_MSG(atomic_load(&second.done) != 0,
			"second private call did not make progress");
	ATF_REQUIRE(atomic_load(&state.depletion_calls) >= 1);
	release_first(&state);
	ATF_REQUIRE(pthread_join(t1, NULL) == 0);
	ATF_REQUIRE(pthread_join(t2, NULL) == 0);
	ATF_REQUIRE(first.result == 0);
	ATF_REQUIRE(second.result == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	(void)door_server_create(old);
	state_destroy(&state);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, factory_replacement_returns_previous);
	ATF_TP_ADD_TC(tp, shared_factory_receives_null);
	ATF_TP_ADD_TC(tp, legacy_private_factory_receives_info);
	ATF_TP_ADD_TC(tp, legacy_private_depletion_progress);
	return (atf_no_error());
}
