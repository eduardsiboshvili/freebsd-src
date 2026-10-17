/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <atf-c.h>
#include <door.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define MASS_CLIENTS 100
#define FUZZ_THREADS 16
#define FUZZ_LOOPS 40

static int entered_pipe[2] = {-1, -1};
static int release_pipe[2] = {-1, -1};

static void
noop_handler(int signo)
{
	(void)signo;
}

static void
blocking_move_server(void *cookie,
		     char *data,
		     size_t data_size,
		     door_desc_t *descs,
		     uint_t ndescs)
{
	char byte = 'E';
	uint_t i;

	(void)cookie;
	(void)data;
	(void)data_size;
	for (i = 0; i < ndescs; i++)
		(void)close(descs[i].d_descriptor);
	(void)write(entered_pipe[1], &byte, 1);
	if (read(release_pipe[0], &byte, 1) != 1)
		pthread_exit(NULL);
	door_return(__DECONST(char *, "ok"), sizeof("ok"), NULL, 0);
}

struct mass_call {
	pthread_t thread;
	int door_fd;
	int source_fd;
	int result;
	int error;
	atomic_int done;
};

static void *
mass_call_thread(void *argument)
{
	struct mass_call *call;
	door_desc_t desc;
	door_arg_t arg;
	char reply[16];

	call = argument;
	test_init_desc(&desc, call->source_fd, DOOR_RELEASE);
	test_init_call(&arg, reply, sizeof(reply));
	arg.desc_ptr = &desc;
	arg.desc_num = 1;
	errno = 0;
	call->result = door_call(call->door_fd, &arg);
	call->error = errno;
	atomic_store(&call->done, 1);
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(mass_revoke_move_no_cancel);

ATF_TC_BODY(mass_revoke_move_no_cancel, tc)
{
	struct sigaction action, old_action;
	struct mass_call calls[MASS_CLIENTS];
	char byte;
	int door_fd, i, valid;

	(void)tc;
	ATF_REQUIRE(pipe(entered_pipe) == 0);
	ATF_REQUIRE(pipe(release_pipe) == 0);
	memset(&action, 0, sizeof(action));
	action.sa_handler = noop_handler;
	ATF_REQUIRE(sigemptyset(&action.sa_mask) == 0);
	ATF_REQUIRE(sigaction(SIGUSR1, &action, &old_action) == 0);

	door_fd = door_create(
	    blocking_move_server, NULL, DOOR_NO_CANCEL | DOOR_NO_DEPLETION_CB);
	ATF_REQUIRE_MSG(door_fd != -1, "door_create: %s", strerror(errno));

	memset(calls, 0, sizeof(calls));
	for (i = 0; i < MASS_CLIENTS; i++) {
		calls[i].door_fd = door_fd;
		calls[i].source_fd = test_make_regular_fd();
		ATF_REQUIRE(calls[i].source_fd != -1);
		ATF_REQUIRE(pthread_create(&calls[i].thread,
					   NULL,
					   mass_call_thread,
					   &calls[i]) == 0);
	}

	/* Ensure one invocation is active and owns its received MOVE fd. */
	ATF_REQUIRE(read(entered_pipe[0], &byte, 1) == 1);
	for (i = 0; i < MASS_CLIENTS; i++)
		ATF_REQUIRE(pthread_kill(calls[i].thread, SIGUSR1) == 0);
	usleep(20000);
	for (i = 0; i < MASS_CLIENTS; i++)
		ATF_REQUIRE_MSG(
		    atomic_load(&calls[i].done) == 0,
		    "DOOR_NO_CANCEL call %d was interrupted by signal",
		    i);

	ATF_REQUIRE_MSG(
	    door_revoke(door_fd) == 0, "door_revoke: %s", strerror(errno));
	(void)close(release_pipe[1]);

	valid = 0;
	for (i = 0; i < MASS_CLIENTS; i++) {
		ATF_REQUIRE(pthread_join(calls[i].thread, NULL) == 0);
		ATF_REQUIRE(calls[i].result == -1);
		ATF_REQUIRE_MSG(calls[i].error == EBADF ||
				    calls[i].error == ENXIO ||
				    calls[i].error == ECONNRESET,
				"call %d returned errno %d (%s)",
				i,
				calls[i].error,
				strerror(calls[i].error));
		ATF_REQUIRE_MSG(
		    test_fd_valid(calls[i].source_fd),
		    "MOVE source %d was consumed despite failed/revoked RPC",
		    i);
		valid++;
		(void)close(calls[i].source_fd);
	}
	ATF_REQUIRE_MSG(valid == MASS_CLIENTS,
			"not all MOVE sources survived revoke rollback");

	ATF_REQUIRE(sigaction(SIGUSR1, &old_action, NULL) == 0);
	(void)close(entered_pipe[0]);
	(void)close(entered_pipe[1]);
	(void)close(release_pipe[0]);
	(void)close(door_fd);
}

static void
fuzz_echo_server(void *cookie,
		 char *data,
		 size_t data_size,
		 door_desc_t *descs,
		 uint_t ndescs)
{
	uint_t i;

	(void)cookie;
	for (i = 0; i < ndescs; i++)
		(void)close(descs[i].d_descriptor);
	door_return(data, data_size, NULL, 0);
}

struct fuzz_context {
	unsigned int index;
	atomic_int *failure;
};

static uint32_t
fuzz_next(uint32_t *state)
{
	*state = *state * 1664525U + 1013904223U;
	return (*state);
}

static int
fuzz_echo_call(int fd, uint64_t value)
{
	door_arg_t arg;
	uint64_t reply;

	reply = 0;
	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = (char *)&value;
	arg.data_size = sizeof(value);
	arg.rbuf = (char *)&reply;
	arg.rsize = sizeof(reply);
	if (door_call(fd, &arg) == -1)
		return (-1);
	if (arg.data_size != sizeof(value) ||
	    memcmp(arg.data_ptr, &value, sizeof(value)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static void *
fuzz_thread(void *argument)
{
	struct fuzz_context *context;
	char path[PATH_MAX];
	uint32_t random;
	unsigned int iteration;

	context = argument;
	random = 0x9e3779b9U ^ (context->index * 2654435761U);
	for (iteration = 0; iteration < FUZZ_LOOPS; iteration++) {
		uint32_t choices;
		uint_t attributes;
		uint64_t payload;
		int door_fd, duplicate, path_fd, attached_fd;
		bool attached;

		choices = fuzz_next(&random);
		attributes = (choices & 1U) != 0 ? DOOR_NO_CANCEL : 0;
		door_fd = door_create(fuzz_echo_server, NULL, attributes);
		if (door_fd == -1)
			goto fail;
		duplicate = -1;
		attached_fd = -1;
		attached = false;
		path[0] = '\0';

		if ((choices & 2U) != 0) {
			duplicate = dup(door_fd);
			if (duplicate == -1)
				goto door_fail;
		}
		if ((choices & 4U) != 0) {
			(void)snprintf(path,
				       sizeof(path),
				       "/tmp/libdoor-fuzz.%d.%u.%u",
				       getpid(),
				       context->index,
				       iteration);
			path_fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
			if (path_fd == -1)
				goto door_fail;
			(void)close(path_fd);
			if (fattach(door_fd, path) == -1)
				goto unlink_fail;
			attached = true;
			attached_fd = open(path, O_RDWR);
			if (attached_fd == -1)
				goto detach_fail;
		}

		payload = ((uint64_t)context->index << 32) | iteration;
		if (fuzz_echo_call(attached_fd != -1 ? attached_fd : door_fd,
				   payload) == -1)
			goto detach_fail;
		if ((choices & 8U) != 0 && duplicate != -1 &&
		    fuzz_echo_call(duplicate, payload ^ UINT64_MAX) == -1)
			goto detach_fail;

		/* Vary teardown order while accepting documented revoke errors.
		 */
		if ((choices & 16U) != 0) {
			if (door_revoke(duplicate != -1 ? duplicate
							: door_fd) == -1 &&
			    errno != EBADF && errno != ENXIO)
				goto detach_fail;
		}
		if (attached_fd != -1) {
			(void)close(attached_fd);
			attached_fd = -1;
		}
		if (attached) {
			if (fdetach(path) == -1 && errno != EINVAL &&
			    errno != ENOENT && errno != ENXIO)
				goto door_fail;
			attached = false;
			(void)unlink(path);
		}
		if ((choices & 16U) == 0)
			(void)door_revoke(door_fd);
		if (duplicate != -1)
			(void)close(duplicate);
		(void)close(door_fd);
		continue;

	detach_fail:
		if (attached_fd != -1)
			(void)close(attached_fd);
		if (attached)
			(void)fdetach(path);
	unlink_fail:
		if (path[0] != '\0')
			(void)unlink(path);
	door_fail:
		if (duplicate != -1)
			(void)close(duplicate);
		(void)door_revoke(door_fd);
		(void)close(door_fd);
	fail:
		atomic_store(context->failure, 1);
		return (NULL);
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(multithread_create_call_attach_fuzz);

ATF_TC_BODY(multithread_create_call_attach_fuzz, tc)
{
	struct fuzz_context contexts[FUZZ_THREADS];
	pthread_t threads[FUZZ_THREADS];
	atomic_int failure;
	unsigned int i;

	(void)tc;
	atomic_init(&failure, 0);
	for (i = 0; i < FUZZ_THREADS; i++) {
		contexts[i].index = i;
		contexts[i].failure = &failure;
		ATF_REQUIRE(pthread_create(
				&threads[i], NULL, fuzz_thread, &contexts[i]) ==
			    0);
	}
	for (i = 0; i < FUZZ_THREADS; i++)
		ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);
	ATF_REQUIRE_MSG(atomic_load(&failure) == 0,
			"create/call/fattach/fdetach/revoke fuzz failed");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, mass_revoke_move_no_cancel);
	ATF_TP_ADD_TC(tp, multithread_create_call_attach_fuzz);
	return (atf_no_error());
}
