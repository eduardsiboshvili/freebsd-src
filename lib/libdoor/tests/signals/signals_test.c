/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define SIGNAL_ITERATIONS 32

struct call_context {
	pthread_t thread;
	int door_fd;
	int result;
	int error;
};

static int entered_pipe[2] = {-1, -1};
static int release_pipe[2] = {-1, -1};

static void
noop_handler(int signo)
{
	(void)signo;
}

static void
blocking_server(void *cookie,
		char *data,
		size_t data_size,
		door_desc_t *descs,
		uint_t ndescs)
{
	char byte;
	uint_t i;

	(void)cookie;
	(void)data;
	(void)data_size;
	for (i = 0; i < ndescs; i++)
		(void)close(descs[i].d_descriptor);
	byte = 'E';
	if (write(entered_pipe[1], &byte, 1) != 1)
		door_return(__DECONST(char *, "PIPE"), sizeof("PIPE"), NULL, 0);
	if (read(release_pipe[0], &byte, 1) != 1)
		door_return(__DECONST(char *, "PIPE"), sizeof("PIPE"), NULL, 0);
	door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

static void
setup_pipes(void)
{
	ATF_REQUIRE(pipe(entered_pipe) == 0);
	ATF_REQUIRE(pipe(release_pipe) == 0);
}

static void
close_pipes(void)
{
	(void)close(entered_pipe[0]);
	(void)close(entered_pipe[1]);
	(void)close(release_pipe[0]);
	(void)close(release_pipe[1]);
	entered_pipe[0] = entered_pipe[1] = -1;
	release_pipe[0] = release_pipe[1] = -1;
}

static void
wait_entered(void)
{
	char byte;
	ATF_REQUIRE(read(entered_pipe[0], &byte, 1) == 1);
	ATF_REQUIRE(byte == 'E');
}

static void
release_one(void)
{
	const char byte = 'R';
	ATF_REQUIRE(write(release_pipe[1], &byte, 1) == 1);
}

static void *
call_thread(void *argument)
{
	struct call_context *context = argument;
	char reply[16];
	door_arg_t arg;

	test_init_call(&arg, reply, sizeof(reply));
	errno = 0;
	context->result = door_call(context->door_fd, &arg);
	context->error = errno;
	return (NULL);
}

static void
start_call(struct call_context *context, int door_fd)
{
	int error;
	memset(context, 0, sizeof(*context));
	context->door_fd = door_fd;
	error = pthread_create(&context->thread, NULL, call_thread, context);
	ATF_REQUIRE_MSG(error == 0, "pthread_create: %s", strerror(error));
}

static void
join_call(struct call_context *context)
{
	int error;
	error = pthread_join(context->thread, NULL);
	ATF_REQUIRE_MSG(error == 0, "pthread_join: %s", strerror(error));
}

static void
install_handler(int flags, struct sigaction *old_action)
{
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_handler = noop_handler;
	action.sa_flags = flags;
	ATF_REQUIRE(sigemptyset(&action.sa_mask) == 0);
	ATF_REQUIRE(sigaction(SIGUSR1, &action, old_action) == 0);
}

static void
recovery_call(int door_fd)
{
	struct call_context call;
	start_call(&call, door_fd);
	wait_entered();
	release_one();
	join_call(&call);
	ATF_REQUIRE_MSG(
	    call.result == 0, "recovery call: %s", strerror(call.error));
}

ATF_TC_WITHOUT_HEAD(handled_signal_interrupts_wait);

ATF_TC_BODY(handled_signal_interrupts_wait, tc)
{
	struct sigaction old_action;
	struct call_context call;
	int door_fd, error;

	(void)tc;
	setup_pipes();
	install_handler(0, &old_action);
	door_fd = test_create_door(blocking_server);
	start_call(&call, door_fd);
	wait_entered();
	error = pthread_kill(call.thread, SIGUSR1);
	ATF_REQUIRE_MSG(error == 0, "pthread_kill: %s", strerror(error));
	join_call(&call);
	ATF_REQUIRE(call.result == -1);
	ATF_REQUIRE_MSG(call.error == EINTR,
			"errno=%d (%s)",
			call.error,
			strerror(call.error));
	release_one();
	recovery_call(door_fd);
	test_close_door(door_fd);
	ATF_REQUIRE(sigaction(SIGUSR1, &old_action, NULL) == 0);
	close_pipes();
}

static void *
blocked_call_thread(void *argument)
{
	sigset_t set;

	(void)sigemptyset(&set);
	(void)sigaddset(&set, SIGUSR1);
	(void)pthread_sigmask(SIG_BLOCK, &set, NULL);
	return (call_thread(argument));
}

ATF_TC_WITHOUT_HEAD(blocked_signal_does_not_interrupt_wait);

ATF_TC_BODY(blocked_signal_does_not_interrupt_wait, tc)
{
	struct sigaction old_action;
	struct call_context call;
	int door_fd, error;

	(void)tc;
	setup_pipes();
	install_handler(0, &old_action);
	door_fd = test_create_door(blocking_server);
	memset(&call, 0, sizeof(call));
	call.door_fd = door_fd;
	error = pthread_create(&call.thread, NULL, blocked_call_thread, &call);
	ATF_REQUIRE_MSG(error == 0, "pthread_create: %s", strerror(error));
	wait_entered();
	error = pthread_kill(call.thread, SIGUSR1);
	ATF_REQUIRE_MSG(error == 0, "pthread_kill: %s", strerror(error));
	release_one();
	join_call(&call);
	ATF_REQUIRE_MSG(call.result == 0,
			"blocked signal interrupted call: %s",
			strerror(call.error));
	test_close_door(door_fd);
	ATF_REQUIRE(sigaction(SIGUSR1, &old_action, NULL) == 0);
	close_pipes();
}

ATF_TC_WITHOUT_HEAD(repeated_interrupt_and_recovery);

ATF_TC_BODY(repeated_interrupt_and_recovery, tc)
{
	struct sigaction old_action;
	struct call_context call;
	int door_fd, error, i;

	(void)tc;
	setup_pipes();
	install_handler(0, &old_action);
	door_fd = test_create_door(blocking_server);
	for (i = 0; i < SIGNAL_ITERATIONS; i++) {
		start_call(&call, door_fd);
		wait_entered();
		error = pthread_kill(call.thread, SIGUSR1);
		ATF_REQUIRE_MSG(error == 0,
				"iteration %d pthread_kill: %s",
				i,
				strerror(error));
		join_call(&call);
		ATF_REQUIRE_MSG(call.result == -1 && call.error == EINTR,
				"iteration %d result=%d errno=%d",
				i,
				call.result,
				call.error);
		release_one();
	}
	recovery_call(door_fd);
	test_close_door(door_fd);
	ATF_REQUIRE(sigaction(SIGUSR1, &old_action, NULL) == 0);
	close_pipes();
}

ATF_TC_WITHOUT_HEAD(killed_client_releases_active_call);

ATF_TC_BODY(killed_client_releases_active_call, tc)
{
	char reply[16];
	door_arg_t arg;
	pid_t child;
	int door_fd, status;

	(void)tc;
	setup_pipes();
	door_fd = test_create_door(blocking_server);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		test_init_call(&arg, reply, sizeof(reply));
		(void)door_call(door_fd, &arg);
		_exit(99);
	}
	wait_entered();
	ATF_REQUIRE(kill(child, SIGKILL) == 0);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFSIGNALED(status));
	ATF_REQUIRE(WTERMSIG(status) == SIGKILL);
	release_one();
	recovery_call(door_fd);
	test_close_door(door_fd);
	close_pipes();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, handled_signal_interrupts_wait);
	ATF_TP_ADD_TC(tp, blocked_signal_does_not_interrupt_wait);
	ATF_TP_ADD_TC(tp, repeated_interrupt_and_recovery);
	ATF_TP_ADD_TC(tp, killed_client_releases_active_call);
	return (atf_no_error());
}
