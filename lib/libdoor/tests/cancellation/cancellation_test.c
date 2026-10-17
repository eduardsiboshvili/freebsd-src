/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <door.h>
#include <sys/door_core.h>
#include <sys/syscall.h>

#include "test_common.h"

#define CANCELLATION_CALL_ID_BASE UINT64_C(0x43414e4300000000)
#define POLL_ATTEMPTS 1000
#define POLL_DELAY_US 10000

struct raw_call_context {
	pthread_t thread;
	struct door_ioc_call call;
	struct door_kdesc send_desc;
	char request[32];
	char reply[32];
	int door_fd;
	int result;
	int error;
};

static int entered_pipe[2] = {-1, -1};
static int release_pipe[2] = {-1, -1};

static void
noop_signal_handler(int signo)
{
	(void)signo;
}

static void
controlled_server(void *cookie,
		  char *data,
		  size_t data_size,
		  door_desc_t *descs,
		  uint_t ndescs)
{
	char byte;
	uint_t i;

	(void)cookie;
	for (i = 0; i < ndescs; i++)
		(void)close(descs[i].d_descriptor);

	if (data_size == sizeof("block") &&
	    memcmp(data, "block", sizeof("block")) == 0) {
		byte = 'E';
		if (write(entered_pipe[1], &byte, 1) != 1)
			door_return(
			    __DECONST(char *, "PIPE"), sizeof("PIPE"), NULL, 0);
		if (read(release_pipe[0], &byte, 1) != 1)
			door_return(
			    __DECONST(char *, "PIPE"), sizeof("PIPE"), NULL, 0);
	}

	door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

static void
setup_control_pipes(void)
{
	ATF_REQUIRE(pipe(entered_pipe) == 0);
	ATF_REQUIRE(pipe(release_pipe) == 0);
}

static void
close_control_pipes(void)
{
	if (entered_pipe[0] != -1)
		(void)close(entered_pipe[0]);
	if (entered_pipe[1] != -1)
		(void)close(entered_pipe[1]);
	if (release_pipe[0] != -1)
		(void)close(release_pipe[0]);
	if (release_pipe[1] != -1)
		(void)close(release_pipe[1]);
	entered_pipe[0] = -1;
	entered_pipe[1] = -1;
	release_pipe[0] = -1;
	release_pipe[1] = -1;
}

static void
wait_for_server_entry(void)
{
	char byte;

	ATF_REQUIRE(read(entered_pipe[0], &byte, 1) == 1);
	ATF_REQUIRE(byte == 'E');
}

static void
release_server(void)
{
	char byte;

	byte = 'R';
	ATF_REQUIRE(write(release_pipe[1], &byte, 1) == 1);
}

static void
init_raw_call(struct raw_call_context *context,
	      int door_fd,
	      uint64_t call_id,
	      const char *request)
{
	size_t request_size;

	memset(context, 0, sizeof(*context));
	context->door_fd = door_fd;
	context->result = 0;
	context->error = 0;
	request_size = strlen(request) + 1;
	ATF_REQUIRE(request_size <= sizeof(context->request));
	memcpy(context->request, request, request_size);

	context->call.dic_version = DOOR_ABI_VERSION;
	context->call.dic_request_ptr = (uint64_t)(uintptr_t)context->request;
	context->call.dic_request_size = request_size;
	context->call.dic_reply_ptr = (uint64_t)(uintptr_t)context->reply;
	context->call.dic_reply_size = sizeof(context->reply);
	context->call.dic_call_id = call_id;
	context->call.dic_send_fd = -1;
	context->call.dic_recv_fd = -1;
}

static void
set_raw_move_descriptor(struct raw_call_context *context, int fd)
{
	context->send_desc.dd_fd = fd;
	context->send_desc.dd_flags = DOOR_DESC_F_MOVE;
	context->call.dic_send_desc_ptr =
	    (uint64_t)(uintptr_t)&context->send_desc;
	context->call.dic_send_desc_count = 1;
}

static void *
raw_call_thread(void *argument)
{
	struct raw_call_context *context;

	context = argument;
	errno = 0;
	context->result = (int)__syscall((quad_t)SYS_door,
					 DOOR_SC_CALL,
					 (long)context->door_fd,
					 (long)(uintptr_t)&context->call,
					 0,
					 0,
					 0);
	context->error = errno;
	return (NULL);
}

static void
start_raw_call(struct raw_call_context *context)
{
	int error;

	error =
	    pthread_create(&context->thread, NULL, raw_call_thread, context);
	ATF_REQUIRE_MSG(
	    error == 0, "pthread_create failed: %s", strerror(error));
}

static void
join_raw_call(struct raw_call_context *context)
{
	int error;

	error = pthread_join(context->thread, NULL);
	ATF_REQUIRE_MSG(error == 0, "pthread_join failed: %s", strerror(error));
}

static void
require_call_error(struct raw_call_context *context, int expected)
{
	ATF_REQUIRE(context->result == -1);
	ATF_REQUIRE_MSG(context->error == expected,
			"call returned errno %d (%s), expected %d (%s)",
			context->error,
			strerror(context->error),
			expected,
			strerror(expected));
}

static void
require_call_success(struct raw_call_context *context)
{
	ATF_REQUIRE_MSG(
	    context->result == 0, "call failed: %s", strerror(context->error));
	ATF_REQUIRE(context->call.dic_reply_size == sizeof("OK"));
	ATF_REQUIRE(memcmp(context->reply, "OK", sizeof("OK")) == 0);
}

static int
cancel_call(int door_fd, uint64_t call_id)
{
	struct door_ioc_cancel cancel;

	memset(&cancel, 0, sizeof(cancel));
	cancel.dican_version = DOOR_ABI_VERSION;
	cancel.dican_call_id = call_id;
	return ((int)__syscall((quad_t)SYS_door,
			       DOOR_SC_CANCEL,
			       (long)door_fd,
			       (long)(uintptr_t)&cancel,
			       0,
			       0,
			       0));
}

static void
wait_for_call_counts(int door_fd, uint32_t pending, uint32_t active)
{
	struct door_ioc_info info;
	int attempt;

	for (attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
		memset(&info, 0, sizeof(info));
		if (__syscall((quad_t)SYS_door,
			      DOOR_SC_INFO,
			      (long)door_fd,
			      (long)(uintptr_t)&info,
			      0,
			      0,
			      0) == 0 &&
		    info.di_pending_calls == pending &&
		    info.di_active_calls == active)
			return;
		(void)usleep(POLL_DELAY_US);
	}
	atf_tc_fail(
	    "timed out waiting for pending=%u active=%u", pending, active);
}

static void
require_recovery_call(int door_fd, uint64_t call_id)
{
	struct raw_call_context recovery;

	init_raw_call(&recovery, door_fd, call_id, "ping");
	start_raw_call(&recovery);
	join_raw_call(&recovery);
	require_call_success(&recovery);
}

static void
install_signal_handler(struct sigaction *old_action)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = noop_signal_handler;
	ATF_REQUIRE(sigemptyset(&action.sa_mask) == 0);
	action.sa_flags = 0;
	ATF_REQUIRE(sigaction(SIGUSR1, &action, old_action) == 0);
}

static void
restore_signal_handler(const struct sigaction *old_action)
{
	ATF_REQUIRE(sigaction(SIGUSR1, old_action, NULL) == 0);
}

ATF_TC_WITHOUT_HEAD(cancel_nonexistent);

ATF_TC_BODY(cancel_nonexistent, tc)
{
	int door_fd;

	(void)tc;
	door_fd = test_create_door(controlled_server);
	errno = 0;
	ATF_REQUIRE(cancel_call(door_fd, CANCELLATION_CALL_ID_BASE + 1) == -1);
	ATF_REQUIRE(errno == ESRCH);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(cancel_active_call);

ATF_TC_BODY(cancel_active_call, tc)
{
	struct raw_call_context call;
	uint64_t call_id;
	int door_fd;

	(void)tc;
	setup_control_pipes();
	door_fd = test_create_door(controlled_server);
	call_id = CANCELLATION_CALL_ID_BASE + 2;
	init_raw_call(&call, door_fd, call_id, "block");
	start_raw_call(&call);
	wait_for_server_entry();
	wait_for_call_counts(door_fd, 0, 1);

	ATF_REQUIRE(cancel_call(door_fd, call_id) == 0);
	join_raw_call(&call);
	require_call_error(&call, ECANCELED);

	release_server();
	require_recovery_call(door_fd, CANCELLATION_CALL_ID_BASE + 3);
	test_close_door(door_fd);
	close_control_pipes();
}

ATF_TC_WITHOUT_HEAD(cancel_active_twice);

ATF_TC_BODY(cancel_active_twice, tc)
{
	struct raw_call_context call;
	uint64_t call_id;
	int door_fd;

	(void)tc;
	setup_control_pipes();
	door_fd = test_create_door(controlled_server);
	call_id = CANCELLATION_CALL_ID_BASE + 4;
	init_raw_call(&call, door_fd, call_id, "block");
	start_raw_call(&call);
	wait_for_server_entry();
	wait_for_call_counts(door_fd, 0, 1);

	ATF_REQUIRE(cancel_call(door_fd, call_id) == 0);
	errno = 0;
	ATF_REQUIRE(cancel_call(door_fd, call_id) == -1);
	ATF_REQUIRE(errno == EALREADY);
	join_raw_call(&call);
	require_call_error(&call, ECANCELED);

	release_server();
	require_recovery_call(door_fd, CANCELLATION_CALL_ID_BASE + 5);
	test_close_door(door_fd);
	close_control_pipes();
}

ATF_TC_WITHOUT_HEAD(cancel_pending_call);

ATF_TC_BODY(cancel_pending_call, tc)
{
	struct raw_call_context active_call;
	struct raw_call_context pending_call;
	uint64_t active_id, pending_id;
	int door_fd;

	(void)tc;
	setup_control_pipes();
	door_fd = test_create_door(controlled_server);
	active_id = CANCELLATION_CALL_ID_BASE + 6;
	pending_id = CANCELLATION_CALL_ID_BASE + 7;
	init_raw_call(&active_call, door_fd, active_id, "block");
	start_raw_call(&active_call);
	wait_for_server_entry();
	wait_for_call_counts(door_fd, 0, 1);

	init_raw_call(&pending_call, door_fd, pending_id, "queued");
	start_raw_call(&pending_call);
	wait_for_call_counts(door_fd, 1, 1);
	ATF_REQUIRE(cancel_call(door_fd, pending_id) == 0);
	join_raw_call(&pending_call);
	require_call_error(&pending_call, ECANCELED);

	release_server();
	join_raw_call(&active_call);
	require_call_success(&active_call);
	require_recovery_call(door_fd, CANCELLATION_CALL_ID_BASE + 8);
	test_close_door(door_fd);
	close_control_pipes();
}

ATF_TC_WITHOUT_HEAD(interrupt_active_call);

ATF_TC_BODY(interrupt_active_call, tc)
{
	struct raw_call_context call;
	struct sigaction old_action;
	uint64_t call_id;
	int door_fd, error;

	(void)tc;
	setup_control_pipes();
	install_signal_handler(&old_action);
	door_fd = test_create_door(controlled_server);
	call_id = CANCELLATION_CALL_ID_BASE + 9;
	init_raw_call(&call, door_fd, call_id, "block");
	start_raw_call(&call);
	wait_for_server_entry();
	wait_for_call_counts(door_fd, 0, 1);

	error = pthread_kill(call.thread, SIGUSR1);
	ATF_REQUIRE_MSG(error == 0, "pthread_kill failed: %s", strerror(error));
	join_raw_call(&call);
	require_call_error(&call, EINTR);

	release_server();
	require_recovery_call(door_fd, CANCELLATION_CALL_ID_BASE + 10);
	test_close_door(door_fd);
	restore_signal_handler(&old_action);
	close_control_pipes();
}

ATF_TC_WITHOUT_HEAD(interrupt_pending_call);

ATF_TC_BODY(interrupt_pending_call, tc)
{
	struct raw_call_context active_call;
	struct raw_call_context pending_call;
	struct sigaction old_action;
	int door_fd, error;

	(void)tc;
	setup_control_pipes();
	install_signal_handler(&old_action);
	door_fd = test_create_door(controlled_server);
	init_raw_call(
	    &active_call, door_fd, CANCELLATION_CALL_ID_BASE + 11, "block");
	start_raw_call(&active_call);
	wait_for_server_entry();
	wait_for_call_counts(door_fd, 0, 1);

	init_raw_call(
	    &pending_call, door_fd, CANCELLATION_CALL_ID_BASE + 12, "queued");
	start_raw_call(&pending_call);
	wait_for_call_counts(door_fd, 1, 1);
	error = pthread_kill(pending_call.thread, SIGUSR1);
	ATF_REQUIRE_MSG(error == 0, "pthread_kill failed: %s", strerror(error));
	join_raw_call(&pending_call);
	require_call_error(&pending_call, EINTR);
	wait_for_call_counts(door_fd, 0, 1);

	release_server();
	join_raw_call(&active_call);
	require_call_success(&active_call);
	require_recovery_call(door_fd, CANCELLATION_CALL_ID_BASE + 13);
	test_close_door(door_fd);
	restore_signal_handler(&old_action);
	close_control_pipes();
}

ATF_TC_WITHOUT_HEAD(cancelled_active_preserves_moved_descriptor);

ATF_TC_BODY(cancelled_active_preserves_moved_descriptor, tc)
{
	struct raw_call_context call;
	uint64_t call_id;
	int door_fd, source_fd;

	(void)tc;
	setup_control_pipes();
	door_fd = test_create_door(controlled_server);
	source_fd = test_make_regular_fd();
	ATF_REQUIRE(source_fd != -1);
	call_id = CANCELLATION_CALL_ID_BASE + 14;
	init_raw_call(&call, door_fd, call_id, "block");
	set_raw_move_descriptor(&call, source_fd);
	start_raw_call(&call);
	wait_for_server_entry();
	wait_for_call_counts(door_fd, 0, 1);

	ATF_REQUIRE(cancel_call(door_fd, call_id) == 0);
	join_raw_call(&call);
	require_call_error(&call, ECANCELED);
	test_require_fd_valid(source_fd);

	release_server();
	require_recovery_call(door_fd, CANCELLATION_CALL_ID_BASE + 15);
	ATF_REQUIRE(close(source_fd) == 0);
	test_close_door(door_fd);
	close_control_pipes();
}

ATF_TC_WITHOUT_HEAD(interrupted_pending_preserves_moved_descriptor);

ATF_TC_BODY(interrupted_pending_preserves_moved_descriptor, tc)
{
	struct raw_call_context active_call;
	struct raw_call_context pending_call;
	struct sigaction old_action;
	int door_fd, error, source_fd;

	(void)tc;
	setup_control_pipes();
	install_signal_handler(&old_action);
	door_fd = test_create_door(controlled_server);
	init_raw_call(
	    &active_call, door_fd, CANCELLATION_CALL_ID_BASE + 16, "block");
	start_raw_call(&active_call);
	wait_for_server_entry();
	wait_for_call_counts(door_fd, 0, 1);

	source_fd = test_make_regular_fd();
	ATF_REQUIRE(source_fd != -1);
	init_raw_call(
	    &pending_call, door_fd, CANCELLATION_CALL_ID_BASE + 17, "queued");
	set_raw_move_descriptor(&pending_call, source_fd);
	start_raw_call(&pending_call);
	wait_for_call_counts(door_fd, 1, 1);
	error = pthread_kill(pending_call.thread, SIGUSR1);
	ATF_REQUIRE_MSG(error == 0, "pthread_kill failed: %s", strerror(error));
	join_raw_call(&pending_call);
	require_call_error(&pending_call, EINTR);
	test_require_fd_valid(source_fd);

	release_server();
	join_raw_call(&active_call);
	require_call_success(&active_call);
	require_recovery_call(door_fd, CANCELLATION_CALL_ID_BASE + 18);
	ATF_REQUIRE(close(source_fd) == 0);
	test_close_door(door_fd);
	restore_signal_handler(&old_action);
	close_control_pipes();
}

ATF_TC_WITHOUT_HEAD(foreign_process_cannot_cancel);

ATF_TC_BODY(foreign_process_cannot_cancel, tc)
{
	struct raw_call_context call;
	uint64_t call_id;
	pid_t child;
	int door_fd, status;

	(void)tc;
	setup_control_pipes();
	door_fd = test_create_door(controlled_server);
	call_id = CANCELLATION_CALL_ID_BASE + 19;
	init_raw_call(&call, door_fd, call_id, "block");
	start_raw_call(&call);
	wait_for_server_entry();
	wait_for_call_counts(door_fd, 0, 1);

	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		errno = 0;
		if (cancel_call(door_fd, call_id) == -1 && errno == ESRCH)
			_exit(EXIT_SUCCESS);
		_exit(EXIT_FAILURE);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE(WEXITSTATUS(status) == EXIT_SUCCESS);

	ATF_REQUIRE(cancel_call(door_fd, call_id) == 0);
	join_raw_call(&call);
	require_call_error(&call, ECANCELED);
	release_server();
	require_recovery_call(door_fd, CANCELLATION_CALL_ID_BASE + 20);
	test_close_door(door_fd);
	close_control_pipes();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, cancel_nonexistent);
	ATF_TP_ADD_TC(tp, cancel_active_call);
	ATF_TP_ADD_TC(tp, cancel_active_twice);
	ATF_TP_ADD_TC(tp, cancel_pending_call);
	ATF_TP_ADD_TC(tp, interrupt_active_call);
	ATF_TP_ADD_TC(tp, interrupt_pending_call);
	ATF_TP_ADD_TC(tp, cancelled_active_preserves_moved_descriptor);
	ATF_TP_ADD_TC(tp, interrupted_pending_preserves_moved_descriptor);
	ATF_TP_ADD_TC(tp, foreign_process_cannot_cancel);
	return (atf_no_error());
}
