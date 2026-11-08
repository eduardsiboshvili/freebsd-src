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
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

struct lifecycle_state {
	pthread_mutex_t lock;
	pthread_cond_t cv;
	atomic_int calls;
	atomic_int entered;
	atomic_int release;
	atomic_int create_calls;
	atomic_int depletion_calls;
	atomic_int factory_a_calls;
	atomic_int factory_b_calls;
};

static struct lifecycle_state *factory_state;

static void
state_init(struct lifecycle_state *state)
{
	memset(state, 0, sizeof(*state));
	ATF_REQUIRE(pthread_mutex_init(&state->lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&state->cv, NULL) == 0);
}

static void
state_destroy(struct lifecycle_state *state)
{
	ATF_REQUIRE(pthread_cond_destroy(&state->cv) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&state->lock) == 0);
}

static void
echo_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	struct lifecycle_state *state = cookie;

	(void)desc;
	(void)ndesc;
	atomic_fetch_add(&state->calls, 1);
	(void)door_return(data, size, NULL, 0);
}

static void
blocking_server(
    void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
	struct lifecycle_state *state = cookie;

	(void)desc;
	(void)ndesc;
	atomic_fetch_add(&state->calls, 1);
	pthread_mutex_lock(&state->lock);
	atomic_store(&state->entered, 1);
	pthread_cond_broadcast(&state->cv);
	while (!atomic_load(&state->release))
		pthread_cond_wait(&state->cv, &state->lock);
	pthread_mutex_unlock(&state->lock);
	(void)door_return(data, size, NULL, 0);
}

static void
wait_entered(struct lifecycle_state *state)
{
	pthread_mutex_lock(&state->lock);
	while (!atomic_load(&state->entered))
		pthread_cond_wait(&state->cv, &state->lock);
	pthread_mutex_unlock(&state->lock);
}

static void
release_server(struct lifecycle_state *state)
{
	pthread_mutex_lock(&state->lock);
	atomic_store(&state->release, 1);
	pthread_cond_broadcast(&state->cv);
	pthread_mutex_unlock(&state->lock);
}

static int
call_echo(int fd, const char *message)
{
	door_arg_t arg;
	char reply[64];

	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = __DECONST(char *, message);
	arg.data_size = strlen(message) + 1;
	if (door_call(fd, &arg) == -1)
		return (-1);
	if (strcmp(arg.data_ptr, message) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static void
wait_child_ok(pid_t child)
{
	int status;

	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE_MSG(WIFEXITED(status), "child did not exit normally");
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
			"child exited with status %d",
			WEXITSTATUS(status));
}

static int
xcreate_thread(door_info_t *info,
	       void *(*start)(void *),
	       void *arg,
	       void *cookie)
{
	struct lifecycle_state *state = cookie;
	pthread_t thread;
	int error;

	if (info == NULL || (info->di_attributes & DOOR_PRIVCREATE) == 0) {
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

/* Create only the initial worker; depletion callbacks deliberately decline. */
static int
xcreate_fixed_thread(door_info_t *info,
		     void *(*start)(void *),
		     void *arg,
		     void *cookie)
{
	struct lifecycle_state *state = cookie;
	pthread_t thread;
	int error;

	if ((info->di_attributes & DOOR_DEPLETION_CB) != 0) {
		atomic_fetch_add(&state->depletion_calls, 1);
		return (0);
	}
	atomic_fetch_add(&state->create_calls, 1);
	error = pthread_create(&thread, NULL, start, arg);
	if (error != 0) {
		errno = error;
		return (-1);
	}
	(void)pthread_detach(thread);
	return (1);
}

static int
create_xdoor(struct lifecycle_state *state,
	     door_server_procedure_t *proc,
	     bool fixed)
{
	int fd;

	fd = door_xcreate(proc,
			  state,
			  0,
			  fixed ? xcreate_fixed_thread : xcreate_thread,
			  NULL,
			  state,
			  1);
	ATF_REQUIRE_MSG(fd != -1, "door_xcreate failed: %s", strerror(errno));
	return (fd);
}

static void
factory_a(door_info_t *info)
{
	(void)info;
	if (factory_state != NULL)
		atomic_fetch_add(&factory_state->factory_a_calls, 1);
}

static void
factory_b(door_info_t *info)
{
	(void)info;
	if (factory_state != NULL)
		atomic_fetch_add(&factory_state->factory_b_calls, 1);
}

ATF_TC_WITHOUT_HEAD(fork_shared_idle_child_call);

ATF_TC_BODY(fork_shared_idle_child_call, tc)
{
	struct lifecycle_state state;
	pid_t child;
	int fd;

	(void)tc;
	state_init(&state);
	fd = door_create(echo_server, &state, 0);
	ATF_REQUIRE(fd != -1);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0)
		_exit(call_echo(fd, "shared-child") == 0 ? 0 : 1);
	wait_child_ok(child);
	ATF_REQUIRE(call_echo(fd, "shared-parent") == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(fork_legacy_private_idle_child_call);

ATF_TC_BODY(fork_legacy_private_idle_child_call, tc)
{
	struct lifecycle_state state;
	pid_t child;
	int fd;

	(void)tc;
	state_init(&state);
	fd = door_create(echo_server, &state, DOOR_PRIVATE);
	ATF_REQUIRE(fd != -1);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0)
		_exit(call_echo(fd, "private-child") == 0 ? 0 : 1);
	wait_child_ok(child);
	ATF_REQUIRE(call_echo(fd, "private-parent") == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(fork_xcreate_idle_child_call);

ATF_TC_BODY(fork_xcreate_idle_child_call, tc)
{
	struct lifecycle_state state;
	pid_t child;
	int fd;

	(void)tc;
	state_init(&state);
	fd = create_xdoor(&state, echo_server, false);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0)
		_exit(call_echo(fd, "x-child") == 0 ? 0 : 1);
	wait_child_ok(child);
	ATF_REQUIRE(call_echo(fd, "x-parent") == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(fork_shared_active_child_waits_then_completes);

ATF_TC_BODY(fork_shared_active_child_waits_then_completes, tc)
{
	struct lifecycle_state state;
	pid_t child;
	int fd;

	(void)tc;
	state_init(&state);
	fd = door_create(blocking_server, &state, 0);
	ATF_REQUIRE(fd != -1);
	/* Use a helper child as the first client to avoid another test
	 * callback. */
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0)
		_exit(call_echo(fd, "first") == 0 ? 0 : 1);
	wait_entered(&state);
	{
		pid_t second = fork();
		ATF_REQUIRE(second != -1);
		if (second == 0)
			_exit(call_echo(fd, "second") == 0 ? 0 : 1);
		usleep(50000);
		release_server(&state);
		wait_child_ok(child);
		wait_child_ok(second);
	}
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(fork_legacy_private_active_child_progress);

ATF_TC_BODY(fork_legacy_private_active_child_progress, tc)
{
	struct lifecycle_state state;
	pid_t first, second;
	int fd;

	(void)tc;
	state_init(&state);
	fd = door_create(blocking_server, &state, DOOR_PRIVATE);
	ATF_REQUIRE(fd != -1);
	first = fork();
	ATF_REQUIRE(first != -1);
	if (first == 0)
		_exit(call_echo(fd, "first") == 0 ? 0 : 1);
	wait_entered(&state);
	second = fork();
	ATF_REQUIRE(second != -1);
	if (second == 0)
		_exit(call_echo(fd, "second") == 0 ? 0 : 1);
	usleep(50000);
	release_server(&state);
	wait_child_ok(first);
	wait_child_ok(second);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(fork_xcreate_active_child_progress);

ATF_TC_BODY(fork_xcreate_active_child_progress, tc)
{
	struct lifecycle_state state;
	pid_t first, second;
	int fd;

	(void)tc;
	state_init(&state);
	fd = create_xdoor(&state, blocking_server, false);
	first = fork();
	ATF_REQUIRE(first != -1);
	if (first == 0)
		_exit(call_echo(fd, "first") == 0 ? 0 : 1);
	wait_entered(&state);
	second = fork();
	ATF_REQUIRE(second != -1);
	if (second == 0)
		_exit(call_echo(fd, "second") == 0 ? 0 : 1);
	usleep(50000);
	release_server(&state);
	wait_child_ok(first);
	wait_child_ok(second);
	ATF_REQUIRE(atomic_load(&state.depletion_calls) >= 1);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(fork_child_cannot_revoke_private_doors);

ATF_TC_BODY(fork_child_cannot_revoke_private_doors, tc)
{
	struct lifecycle_state a, b;
	pid_t child;
	int legacy_fd, xfd;

	(void)tc;
	state_init(&a);
	state_init(&b);
	legacy_fd = door_create(echo_server, &a, DOOR_PRIVATE);
	ATF_REQUIRE(legacy_fd != -1);
	xfd = create_xdoor(&b, echo_server, false);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		if (door_revoke(legacy_fd) != -1 || errno != EPERM)
			_exit(1);
		if (door_revoke(xfd) != -1 || errno != EPERM)
			_exit(2);
		_exit(0);
	}
	wait_child_ok(child);
	ATF_REQUIRE(call_echo(legacy_fd, "legacy") == 0);
	ATF_REQUIRE(call_echo(xfd, "xcreate") == 0);
	ATF_REQUIRE(door_revoke(legacy_fd) == 0);
	ATF_REQUIRE(door_revoke(xfd) == 0);
	test_close_door(legacy_fd);
	test_close_door(xfd);
	state_destroy(&a);
	state_destroy(&b);
}

ATF_TC_WITHOUT_HEAD(fork_child_creates_independent_door);

ATF_TC_BODY(fork_child_creates_independent_door, tc)
{
	struct lifecycle_state state;
	pid_t child;
	int fd;

	(void)tc;
	state_init(&state);
	fd = door_create(echo_server, &state, 0);
	ATF_REQUIRE(fd != -1);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		struct lifecycle_state child_state;
		int child_fd;

		memset(&child_state, 0, sizeof(child_state));
		(void)pthread_mutex_init(&child_state.lock, NULL);
		(void)pthread_cond_init(&child_state.cv, NULL);
		child_fd = door_create(echo_server, &child_state, 0);
		if (child_fd == -1 || call_echo(child_fd, "new-child") == -1)
			_exit(1);
		if (door_revoke(child_fd) == -1)
			_exit(2);
		test_close_door(child_fd);
		_exit(0);
	}
	wait_child_ok(child);
	ATF_REQUIRE(call_echo(fd, "parent-old") == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(factory_replacement_isolated_across_fork);

ATF_TC_BODY(factory_replacement_isolated_across_fork, tc)
{
	struct lifecycle_state state;
	door_server_func_t *old;
	pid_t child;
	int fd;

	(void)tc;
	state_init(&state);
	factory_state = &state;
	old = door_server_create(factory_a);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		int child_fd;

		(void)door_server_create(factory_b);
		child_fd = door_create(echo_server, &state, 0);
		if (child_fd == -1)
			_exit(1);
		(void)door_revoke(child_fd);
		test_close_door(child_fd);
		_exit(atomic_load(&state.factory_b_calls) >= 1 ? 0 : 2);
	}
	wait_child_ok(child);
	fd = door_create(echo_server, &state, 0);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE(atomic_load(&state.factory_a_calls) >= 1);
	ATF_REQUIRE(atomic_load(&state.factory_b_calls) == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	(void)door_server_create(old);
	factory_state = NULL;
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(factory_replacement_affects_new_not_existing_door);

ATF_TC_BODY(factory_replacement_affects_new_not_existing_door, tc)
{
	struct lifecycle_state state;
	door_server_func_t *old;
	int first, second, a_before;

	(void)tc;
	state_init(&state);
	factory_state = &state;
	old = door_server_create(factory_a);
	first = door_create(echo_server, &state, 0);
	ATF_REQUIRE(first != -1);
	a_before = atomic_load(&state.factory_a_calls);
	ATF_REQUIRE(door_server_create(factory_b) == factory_a);
	ATF_REQUIRE(call_echo(first, "existing") == 0);
	ATF_REQUIRE(atomic_load(&state.factory_a_calls) == a_before);
	second = door_create(echo_server, &state, 0);
	ATF_REQUIRE(second != -1);
	ATF_REQUIRE(atomic_load(&state.factory_b_calls) >= 1);
	ATF_REQUIRE(door_revoke(first) == 0);
	ATF_REQUIRE(door_revoke(second) == 0);
	test_close_door(first);
	test_close_door(second);
	(void)door_server_create(old);
	factory_state = NULL;
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(xcreate_depletion_rearms_without_growth);

ATF_TC_BODY(xcreate_depletion_rearms_without_growth, tc)
{
	struct lifecycle_state state;
	int fd, first_count;

	(void)tc;
	state_init(&state);
	atomic_store(&state.release, 1);
	fd = create_xdoor(&state, echo_server, true);
	ATF_REQUIRE(call_echo(fd, "episode-one") == 0);
	first_count = atomic_load(&state.depletion_calls);
	ATF_REQUIRE(first_count >= 1);
	ATF_REQUIRE(call_echo(fd, "episode-two") == 0);
	ATF_REQUIRE(atomic_load(&state.depletion_calls) > first_count);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(fork_child_pending_exit_does_not_poison_door);

ATF_TC_BODY(fork_child_pending_exit_does_not_poison_door, tc)
{
	struct lifecycle_state state;
	pid_t first, pending;
	int fd, status;

	(void)tc;
	state_init(&state);
	fd = door_create(blocking_server, &state, 0);
	ATF_REQUIRE(fd != -1);
	first = fork();
	ATF_REQUIRE(first != -1);
	if (first == 0)
		_exit(call_echo(fd, "active") == 0 ? 0 : 1);
	wait_entered(&state);
	pending = fork();
	ATF_REQUIRE(pending != -1);
	if (pending == 0)
		_exit(call_echo(fd, "pending") == 0 ? 0 : 1);
	usleep(50000);
	ATF_REQUIRE(kill(pending, SIGKILL) == 0);
	ATF_REQUIRE(waitpid(pending, &status, 0) == pending);
	ATF_REQUIRE(WIFSIGNALED(status));
	release_server(&state);
	wait_child_ok(first);
	atomic_store(&state.entered, 0);
	atomic_store(&state.release, 1);
	ATF_REQUIRE(call_echo(fd, "recovery") == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(fork_xcreate_active_revoke_wakes_child);

ATF_TC_BODY(fork_xcreate_active_revoke_wakes_child, tc)
{
	struct lifecycle_state state;
	pid_t child;
	int fd;

	(void)tc;
	state_init(&state);
	fd = create_xdoor(&state, blocking_server, false);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		errno = 0;
		if (call_echo(fd, "revoked") == -1 && errno == EBADF)
			_exit(0);
		_exit(1);
	}
	wait_entered(&state);
	ATF_REQUIRE(door_revoke(fd) == 0);
	release_server(&state);
	wait_child_ok(child);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TC_WITHOUT_HEAD(fork_legacy_private_active_revoke_wakes_child);

ATF_TC_BODY(fork_legacy_private_active_revoke_wakes_child, tc)
{
	struct lifecycle_state state;
	pid_t child;
	int fd;

	(void)tc;
	state_init(&state);
	fd = door_create(blocking_server, &state, DOOR_PRIVATE);
	ATF_REQUIRE(fd != -1);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		errno = 0;
		if (call_echo(fd, "revoked") == -1 && errno == EBADF)
			_exit(0);
		_exit(1);
	}
	wait_entered(&state);
	ATF_REQUIRE(door_revoke(fd) == 0);
	release_server(&state);
	wait_child_ok(child);
	test_close_door(fd);
	state_destroy(&state);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fork_shared_idle_child_call);
	ATF_TP_ADD_TC(tp, fork_legacy_private_idle_child_call);
	ATF_TP_ADD_TC(tp, fork_xcreate_idle_child_call);
	ATF_TP_ADD_TC(tp, fork_shared_active_child_waits_then_completes);
	ATF_TP_ADD_TC(tp, fork_legacy_private_active_child_progress);
	ATF_TP_ADD_TC(tp, fork_xcreate_active_child_progress);
	ATF_TP_ADD_TC(tp, fork_child_cannot_revoke_private_doors);
	ATF_TP_ADD_TC(tp, fork_child_creates_independent_door);
	ATF_TP_ADD_TC(tp, factory_replacement_isolated_across_fork);
	ATF_TP_ADD_TC(tp, factory_replacement_affects_new_not_existing_door);
	ATF_TP_ADD_TC(tp, xcreate_depletion_rearms_without_growth);
	ATF_TP_ADD_TC(tp, fork_child_pending_exit_does_not_poison_door);
	ATF_TP_ADD_TC(tp, fork_xcreate_active_revoke_wakes_child);
	ATF_TP_ADD_TC(tp, fork_legacy_private_active_revoke_wakes_child);
	return (atf_no_error());
}
