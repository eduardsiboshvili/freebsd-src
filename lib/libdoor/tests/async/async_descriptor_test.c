/*-
 * Copyright (c) 2026 Eduard Siboshvili
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/capsicum.h>
#include <sys/syscall.h>
#include <stdio.h>

#include "door_raw.h"

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <door.h>

struct result {
	pthread_mutex_t lock;
	pthread_cond_t cv;
	bool done;
	int status;
	uint_t count;
	int fds[2];
	bool payload_ok;
};

static int source_state;
static int raw_endpoint, raw_completion;
static unsigned raw_case;
static bool raw_release;
static struct result *raw_result;

static void
service(void *cookie, char *data, size_t size, door_desc_t *unused,
    uint_t count)
{
	door_desc_t descriptors[2];
	cap_rights_t rights;
	unsigned char command;
	char reply[] = "reply";
	int fds[2], error;

	(void)cookie;
	(void)unused;
	(void)count;
	if (size != 1)
		_exit(20);

	command = (unsigned char)data[0];
	if (command == 'Q') {
		(void)door_return((char *)&source_state, sizeof(source_state),
		    NULL, 0);
		return;
	}

	if (command != 'R')
		_exit(31);

	fds[0] = open("/dev/null", O_RDWR);
	fds[1] = open("/dev/null", O_RDWR);
	if (fds[0] == -1 || fds[1] == -1)
		_exit(21);

	cap_rights_init(&rights, CAP_READ, CAP_FSTAT);
	if (cap_rights_limit(fds[0], &rights) == -1)
		_exit(22);

	memset(descriptors, 0, sizeof(descriptors));
	descriptors[0].d_attributes = DOOR_DESCRIPTOR;
	descriptors[0].d_descriptor = fds[0];
	descriptors[1].d_attributes = DOOR_DESCRIPTOR | DOOR_RELEASE;
	descriptors[1].d_descriptor = fds[1];
	(void)door_return(reply, sizeof(reply) - 1, descriptors, 2);

	/* RETURN has acknowledged receiver installation before MOVE closes. */
	error = errno;
	source_state = 0;
	if (fcntl(fds[0], F_GETFD) != -1)
		source_state |= 1;
	if (fcntl(fds[1], F_GETFD) == -1 && errno == EBADF)
		source_state |= 2;
	if ((source_state & 1) != 0)
		close(fds[0]);
	if ((source_state & 2) == 0)
		close(fds[1]);
	errno = error;
}

static void
complete(uint64_t id, int status, const void *data, size_t size,
    door_desc_t *desc, uint_t count, void *cookie)
{
	struct result *result;

	(void)id;
	result = cookie;
	pthread_mutex_lock(&result->lock);
	result->status = status;
	result->count = count;
	result->payload_ok = size == 5 && data != NULL &&
	    memcmp(data, "reply", 5) == 0;
	for (uint_t i = 0; i < count; i++) {
		if (i < 2)
			result->fds[i] = desc[i].d_descriptor;
		else
			close(desc[i].d_descriptor);
	}
	result->done = true;
	pthread_cond_broadcast(&result->cv);
	pthread_mutex_unlock(&result->lock);
}

static void
data_complete(uint64_t id, int status, const void *data, size_t size,
    void *cookie)
{
	complete(id, status, data, size, NULL, 0, cookie);
}

static void
wait_complete(struct result *result)
{
	struct timespec deadline;

	ATF_REQUIRE_EQ(clock_gettime(CLOCK_REALTIME, &deadline), 0);
	deadline.tv_sec += 10;
	pthread_mutex_lock(&result->lock);
	while (!result->done)
		ATF_REQUIRE_EQ(pthread_cond_timedwait(&result->cv, &result->lock,
		    &deadline), 0);
	pthread_mutex_unlock(&result->lock);
}

static int
start_service(pid_t *child)
{
	door_info_t info;
	struct timespec interval = { .tv_sec = 0, .tv_nsec = 10000000 };
	int file, endpoint;

	file = open("async-descriptor.endpoint", O_CREAT | O_RDWR, 0600);
	ATF_REQUIRE(file != -1);
	close(file);
	*child = fork();
	ATF_REQUIRE(*child != -1);
	if (*child == 0) {
		endpoint = door_create(service, NULL,
		    DOOR_PRIVATE | DOOR_NO_DEPLETION_CB);
		if (endpoint == -1 ||
		    fattach(endpoint, "async-descriptor.endpoint") == -1)
			_exit(23);
		for (;;)
			pause();
	}

	FILE *record = fopen("async-child.pid", "w");
	ATF_REQUIRE(record != NULL);
	fprintf(record, "%ld\n", (long)*child);
	fclose(record);

	for (unsigned i = 0; i < 500; i++) {
		endpoint = open("async-descriptor.endpoint", O_RDWR);
		if (endpoint != -1) {
			if (door_info(endpoint, &info) == 0)
				return (endpoint);
			close(endpoint);
		}
		(void)nanosleep(&interval, NULL);
	}
	ATF_REQUIRE_MSG(false, "child service did not become ready");
	return (-1);
}

static int
query_state(int endpoint)
{
	door_arg_t call;
	int state;
	char query = 'Q';

	memset(&call, 0, sizeof(call));
	call.data_ptr = &query;
	call.data_size = 1;
	call.rbuf = (char *)&state;
	call.rsize = sizeof(state);
	ATF_REQUIRE_EQ(door_call(endpoint, &call), 0);
	ATF_REQUIRE_EQ(call.data_size, sizeof(state));
	return (state);
}

static void
exercise(bool descriptors)
{
	struct result result;
	door_async_t *context;
	cap_rights_t rights;
	pid_t child;
	int endpoint;
	char request = 'R', byte;

	memset(&result, 0, sizeof(result));
	ATF_REQUIRE_EQ(pthread_mutex_init(&result.lock, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&result.cv, NULL), 0);
	endpoint = start_service(&child);
	ATF_REQUIRE_EQ(door_async_open(endpoint, 8, &context), 0);
	for (unsigned iteration = 0; iteration < 16; iteration++) {
		result.done = false;
		request = 'R';
		if (descriptors)
			ATF_REQUIRE_EQ(door_async_submit_desc(context, &request, 1,
			    complete, &result, NULL), 0);
		else
			ATF_REQUIRE_EQ(door_async_submit(context, &request, 1,
			    data_complete, &result, NULL), 0);
		request = 'X'; /* submit has already snapshotted the request */
		wait_complete(&result);

		if (descriptors) {
			ATF_REQUIRE_EQ(result.status, 0);
			ATF_REQUIRE_EQ(result.count, 2);
			ATF_REQUIRE(result.payload_ok);
			ATF_REQUIRE_EQ(cap_rights_get(result.fds[0], &rights), 0);
			ATF_REQUIRE(cap_rights_is_set(&rights, CAP_READ));
			ATF_REQUIRE(!cap_rights_is_set(&rights, CAP_WRITE));
			ATF_REQUIRE_EQ(read(result.fds[0], &byte, 1), 0);
			ATF_REQUIRE_EQ(query_state(endpoint), 3);
			close(result.fds[0]);
			close(result.fds[1]);
		} else {
			ATF_REQUIRE_EQ(result.status, ENOTSUP);
			ATF_REQUIRE_EQ(result.count, 0);
			ATF_REQUIRE_EQ(query_state(endpoint), 1);
		}
	}

	ATF_REQUIRE_EQ(door_async_close(context), 0);
	close(endpoint);
	ATF_REQUIRE_EQ(kill(child, SIGKILL), 0);
	ATF_REQUIRE_EQ(waitpid(child, NULL, 0), child);
	(void)unlink("async-child.pid");
	(void)fdetach("async-descriptor.endpoint");
	(void)unlink("async-descriptor.endpoint");
	pthread_cond_destroy(&result.cv);
	pthread_mutex_destroy(&result.lock);
}


/* Raw collection verifies failure rollback independently of libdoor's helper. */
static void
raw_receive(void *cookie, char *data, size_t size, door_desc_t *desc,
    uint_t ndesc)
{
	struct door_async_completion header;
	struct door_ioc_async_recv_desc receive;
	struct door_kdesc output[2];
	struct rlimit old_limit, limited;
	int occupied[64], used, probe, status;

	(void)cookie;
	(void)desc;
	(void)ndesc;
	if (size < sizeof(header))
		_exit(24);
	memcpy(&header, data, sizeof(header));
	if ((header.dac_flags & DOOR_ASYNC_C_REPLY_DESC) == 0)
		_exit(25);
	/* The source ID remains reserved while descriptors await collection. */
	errno = 0;
	if (raw_submit(raw_endpoint, raw_completion, header.dac_call_id,
	    NULL, 0) != -1 || errno != EEXIST)
		_exit(32);

	memset(&receive, 0, sizeof(receive));
	receive.diard_version = DOOR_ABI_VERSION;
	receive.diard_call_id = header.dac_call_id;
	receive.diard_completion_fd = raw_completion;
	receive.diard_capacity = raw_case == 1 ? 1 : 2;
	receive.diard_desc_ptr = raw_case == 0 ? 1 :
	    (uint64_t)(uintptr_t)output;
	status = 0;
	used = 0;
	if (raw_case == 3) {
		if (getrlimit(RLIMIT_NOFILE, &old_limit) == -1)
			_exit(26);
		limited = old_limit;
		limited.rlim_cur = old_limit.rlim_cur < 64 ? old_limit.rlim_cur : 64;
		if (setrlimit(RLIMIT_NOFILE, &limited) == -1)
			_exit(27);
		while (used < 64) {
			occupied[used] = open("/dev/null", O_RDONLY);
			if (occupied[used] == -1)
				break;
			used++;
		}
		if (used == 0 || used == 64 || errno != EMFILE)
			_exit(28);
		close(occupied[--used]); /* one install succeeds, the second fails */
	}
	if (raw_case != 2 && raw_case != 4) {
		if (raw_op(DOOR_SC_ASYNC_RECV_DESC, raw_endpoint,
		    (long)(uintptr_t)&receive, 0, 0, 0) == -1)
			status = errno;
		else
			status = EPROTO;
	}
	if (raw_case == 3) {
		probe = open("/dev/null", O_RDONLY);
		if (probe == -1)
			_exit(29); /* first installed fd was not rolled back */
		close(probe);
		while (used != 0)
			close(occupied[--used]);
		if (setrlimit(RLIMIT_NOFILE, &old_limit) == -1)
			_exit(30);
	}
	/* With no collection, notification release must unblock the sender. */
	pthread_mutex_lock(&raw_result->lock);
	raw_result->status = status;
	raw_result->done = true;
	pthread_cond_broadcast(&raw_result->cv);
	while (raw_case == 4 && !raw_release)
		pthread_cond_wait(&raw_result->cv, &raw_result->lock);
	pthread_mutex_unlock(&raw_result->lock);
	(void)door_return(NULL, 0, NULL, 0);
}

static void
raw_failure(unsigned which)
{
	struct result result;
	struct door_ioc_async_call call;
	pid_t child;
	char request = 'R';

	memset(&result, 0, sizeof(result));
	pthread_mutex_init(&result.lock, NULL);
	pthread_cond_init(&result.cv, NULL);
	raw_case = which;
	raw_release = false;
	raw_result = &result;
	raw_endpoint = start_service(&child);
	raw_completion = door_create(raw_receive, NULL,
	    DOOR_PRIVATE | DOOR_ONEWAY);
	ATF_REQUIRE(raw_completion != -1);
	memset(&call, 0, sizeof(call));
	call.diac_version = DOOR_ABI_VERSION;
	call.diac_flags = DOOR_ASYNC_F_REPLY_DESC;
	call.diac_call_id = 42;
	call.diac_request_ptr = (uint64_t)(uintptr_t)&request;
	call.diac_request_size = 1;
	call.diac_completion_fd = raw_completion;
	ATF_REQUIRE_EQ(raw_op(DOOR_SC_ASYNC_CALL, raw_endpoint,
	    (long)(uintptr_t)&call, 0, 0, 0), 0);
	wait_complete(&result);
	ATF_REQUIRE_EQ(result.status,
	    which == 0 ? EFAULT : which == 1 ? EMSGSIZE :
	    which == 3 ? EMFILE : 0);
	if (which == 4) {
		ATF_REQUIRE_EQ(door_revoke(raw_completion), 0);
		pthread_mutex_lock(&result.lock);
		raw_release = true;
		pthread_cond_broadcast(&result.cv);
		pthread_mutex_unlock(&result.lock);
	}
	ATF_REQUIRE_EQ(query_state(raw_endpoint), 1);
	if (which != 4)
		ATF_REQUIRE_EQ(door_revoke(raw_completion), 0);
	close(raw_completion);
	close(raw_endpoint);
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	(void)unlink("async-child.pid");
	(void)fdetach("async-descriptor.endpoint");
	(void)unlink("async-descriptor.endpoint");
}

static void
cleanup_service(void)
{
	FILE *record;
	long child;

	record = fopen("async-child.pid", "r");
	if (record != NULL) {
		if (fscanf(record, "%ld", &child) == 1 && child > 1)
			(void)kill((pid_t)child, SIGKILL);
		fclose(record);
	}
	(void)fdetach("async-descriptor.endpoint");
	(void)unlink("async-descriptor.endpoint");
}

#define DESCRIPTOR_CASE(name, expression) \
    ATF_TC_WITH_CLEANUP(name); \
    ATF_TC_HEAD(name, tc) { \
        atf_tc_set_md_var(tc, "timeout", "25"); \
        atf_tc_set_md_var(tc, "require.user", "root"); \
    } \
    ATF_TC_BODY(name, tc) { (void)tc; expression; } \
    ATF_TC_CLEANUP(name, tc) { (void)tc; cleanup_service(); }

DESCRIPTOR_CASE(copy_move_cross_process, exercise(true))
DESCRIPTOR_CASE(data_only_keeps_descriptor_rejection, exercise(false))
DESCRIPTOR_CASE(descriptor_copyout_rollback, raw_failure(0))
DESCRIPTOR_CASE(descriptor_capacity_rollback, raw_failure(1))
DESCRIPTOR_CASE(notification_discard_preserves_move, raw_failure(2))
DESCRIPTOR_CASE(descriptor_emfile_partial_rollback, raw_failure(3))
DESCRIPTOR_CASE(completion_revoke_preserves_move, raw_failure(4))

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, copy_move_cross_process);
	ATF_TP_ADD_TC(tp, data_only_keeps_descriptor_rejection);
	ATF_TP_ADD_TC(tp, descriptor_copyout_rollback);
	ATF_TP_ADD_TC(tp, descriptor_capacity_rollback);
	ATF_TP_ADD_TC(tp, notification_discard_preserves_move);
	ATF_TP_ADD_TC(tp, descriptor_emfile_partial_rollback);
	ATF_TP_ADD_TC(tp, completion_revoke_preserves_move);
	return (atf_no_error());
}
