/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>
#include <sys/types.h>

#include <atf-c.h>

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <door.h>

#include "test_common.h"

#define CONCURRENT_CLIENTS 32
#define CALLS_PER_CLIENT 100
#define BURST_CLIENTS 64
#define MULTIDOOR_COUNT 4
#define MULTIDOOR_CALLS 500
#define DESCRIPTOR_CLIENTS 12
#define DESCRIPTOR_CALLS 40
#define SEQUENTIAL_CALLS 10000
#define CREATE_DESTROY_LOOPS 250
#define REVOKE_CLIENTS 24
#define REVOKE_MAX_CALLS 10000

struct echo_message {
	uint32_t em_thread;
	uint32_t em_iteration;
	uint64_t em_value;
};

struct client_context {
	pthread_t cc_thread;
	int cc_door_fd;
	uint32_t cc_index;
	uint32_t cc_iterations;
	int cc_result;
	int cc_error;
};

struct descriptor_context {
	pthread_t dc_thread;
	int dc_door_fd;
	uint32_t dc_iterations;
	door_attr_t dc_attributes;
	int dc_result;
	int dc_error;
};

struct fd_identity {
	dev_t fi_dev;
	ino_t fi_ino;
};

struct revoke_context {
	pthread_t rc_thread;
	int rc_door_fd;
	uint32_t rc_index;
	uint32_t rc_successes;
	int rc_result;
	int rc_error;
};

struct start_gate {
	pthread_mutex_t sg_lock;
	pthread_cond_t sg_cv;
	uint32_t sg_expected;
	uint32_t sg_waiting;
	bool sg_released;
};

static struct start_gate client_gate;
static atomic_uint descriptor_callbacks;

static void
start_gate_init(struct start_gate *gate, uint32_t expected)
{
	int error;

	memset(gate, 0, sizeof(*gate));
	error = pthread_mutex_init(&gate->sg_lock, NULL);
	ATF_REQUIRE_MSG(
	    error == 0, "pthread_mutex_init failed: %s", strerror(error));
	error = pthread_cond_init(&gate->sg_cv, NULL);
	ATF_REQUIRE_MSG(
	    error == 0, "pthread_cond_init failed: %s", strerror(error));
	gate->sg_expected = expected;
}

static void
start_gate_wait(struct start_gate *gate)
{
	int error;

	error = pthread_mutex_lock(&gate->sg_lock);
	ATF_REQUIRE(error == 0);
	gate->sg_waiting++;
	if (gate->sg_waiting == gate->sg_expected)
		ATF_REQUIRE(pthread_cond_broadcast(&gate->sg_cv) == 0);
	while (!gate->sg_released) {
		error = pthread_cond_wait(&gate->sg_cv, &gate->sg_lock);
		ATF_REQUIRE(error == 0);
	}
	ATF_REQUIRE(pthread_mutex_unlock(&gate->sg_lock) == 0);
}

static void
start_gate_release(struct start_gate *gate)
{
	int error;

	error = pthread_mutex_lock(&gate->sg_lock);
	ATF_REQUIRE(error == 0);
	while (gate->sg_waiting != gate->sg_expected) {
		error = pthread_cond_wait(&gate->sg_cv, &gate->sg_lock);
		ATF_REQUIRE(error == 0);
	}
	gate->sg_released = true;
	ATF_REQUIRE(pthread_cond_broadcast(&gate->sg_cv) == 0);
	ATF_REQUIRE(pthread_mutex_unlock(&gate->sg_lock) == 0);
}

static void
start_gate_destroy(struct start_gate *gate)
{
	ATF_REQUIRE(pthread_cond_destroy(&gate->sg_cv) == 0);
	ATF_REQUIRE(pthread_mutex_destroy(&gate->sg_lock) == 0);
}

static void
echo_server(void *cookie,
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

static void
descriptor_server(void *cookie,
		  char *data,
		  size_t data_size,
		  door_desc_t *descs,
		  uint_t ndescs)
{
	struct stat sb;
	uint32_t result;

	(void)cookie;
	(void)data;
	(void)data_size;
	result = 0;
	if (ndescs == 1 && fstat(descs[0].d_descriptor, &sb) == 0)
		result = 1;
	if (ndescs == 1)
		(void)close(descs[0].d_descriptor);
	atomic_fetch_add_explicit(
	    &descriptor_callbacks, 1, memory_order_relaxed);
	door_return((char *)&result, sizeof(result), NULL, 0);
}

static int
perform_echo_call(int door_fd, uint32_t thread_index, uint32_t iteration)
{
	struct echo_message request, reply;
	door_arg_t arg;

	request.em_thread = thread_index;
	request.em_iteration = iteration;
	request.em_value = ((uint64_t)thread_index << 32) | iteration;
	memset(&reply, 0, sizeof(reply));
	test_init_call(&arg, (char *)&reply, sizeof(reply));
	arg.data_ptr = (char *)&request;
	arg.data_size = sizeof(request);
	if (door_call(door_fd, &arg) == -1)
		return (-1);
	if (arg.data_size != sizeof(reply) ||
	    memcmp(&request, &reply, sizeof(reply)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static void *
echo_client_thread(void *argument)
{
	struct client_context *context;
	uint32_t i;

	context = argument;
	start_gate_wait(&client_gate);
	for (i = 0; i < context->cc_iterations; i++) {
		if (perform_echo_call(
			context->cc_door_fd, context->cc_index, i) == -1) {
			context->cc_result = -1;
			context->cc_error = errno;
			return (NULL);
		}
	}
	context->cc_result = 0;
	return (NULL);
}

static void
start_echo_clients(struct client_context *clients, uint32_t count)
{
	uint32_t i;
	int error;

	for (i = 0; i < count; i++) {
		error = pthread_create(&clients[i].cc_thread,
				       NULL,
				       echo_client_thread,
				       &clients[i]);
		ATF_REQUIRE_MSG(
		    error == 0, "pthread_create failed: %s", strerror(error));
	}
}

static void
join_echo_clients(struct client_context *clients, uint32_t count)
{
	uint32_t i;
	int error;

	for (i = 0; i < count; i++) {
		error = pthread_join(clients[i].cc_thread, NULL);
		ATF_REQUIRE_MSG(
		    error == 0, "pthread_join failed: %s", strerror(error));
		ATF_REQUIRE_MSG(clients[i].cc_result == 0,
				"client %u failed: %s",
				i,
				strerror(clients[i].cc_error));
	}
}

static int
fd_identity_get(int fd, struct fd_identity *identity)
{
	struct stat sb;

	if (fstat(fd, &sb) == -1)
		return (-1);
	identity->fi_dev = sb.st_dev;
	identity->fi_ino = sb.st_ino;
	return (0);
}

static bool
fd_identity_matches(int fd, const struct fd_identity *identity)
{
	struct stat sb;

	if (fstat(fd, &sb) == -1)
		return (false);
	return (sb.st_dev == identity->fi_dev && sb.st_ino == identity->fi_ino);
}

static void *
descriptor_client_thread(void *argument)
{
	struct descriptor_context *context;
	struct fd_identity identity;
	door_desc_t desc;
	door_arg_t arg;
	uint32_t reply;
	uint32_t i;
	bool same_file;
	int fd;

	context = argument;
	start_gate_wait(&client_gate);
	for (i = 0; i < context->dc_iterations; i++) {
		fd = test_make_regular_fd();
		if (fd == -1)
			goto fail;
		if (fd_identity_get(fd, &identity) == -1) {
			(void)close(fd);
			goto fail;
		}

		test_init_desc(&desc, fd, context->dc_attributes);
		reply = 0;
		test_init_call(&arg, (char *)&reply, sizeof(reply));
		arg.desc_ptr = &desc;
		arg.desc_num = 1;
		if (door_call(context->dc_door_fd, &arg) == -1) {
			(void)close(fd);
			goto fail;
		}

		same_file = fd_identity_matches(fd, &identity);
		if (arg.data_size != sizeof(reply) || reply != 1 ||
		    (context->dc_attributes == 0 && !same_file) ||
		    (context->dc_attributes == DOOR_RELEASE && same_file)) {
			if (context->dc_attributes == 0 && same_file)
				(void)close(fd);
			errno = EPROTO;
			goto fail;
		}

		/*
		 * A successful COPY leaves the source descriptor owned by
		 * this thread.  After MOVE, the descriptor number may already
		 * have been reused by another thread and must not be closed
		 * here.
		 */
		if (context->dc_attributes == 0)
			(void)close(fd);
	}
	context->dc_result = 0;
	return (NULL);

fail:
	context->dc_result = -1;
	context->dc_error = errno;
	return (NULL);
}

static void
run_descriptor_stress(door_attr_t attributes)
{
	struct descriptor_context clients[DESCRIPTOR_CLIENTS];
	uint32_t i;
	int door_fd, error;

	atomic_store_explicit(&descriptor_callbacks, 0, memory_order_relaxed);
	door_fd = test_create_door(descriptor_server);
	start_gate_init(&client_gate, DESCRIPTOR_CLIENTS);
	memset(clients, 0, sizeof(clients));
	for (i = 0; i < DESCRIPTOR_CLIENTS; i++) {
		clients[i].dc_door_fd = door_fd;
		clients[i].dc_iterations = DESCRIPTOR_CALLS;
		clients[i].dc_attributes = attributes;
		error = pthread_create(&clients[i].dc_thread,
				       NULL,
				       descriptor_client_thread,
				       &clients[i]);
		ATF_REQUIRE_MSG(
		    error == 0, "pthread_create failed: %s", strerror(error));
	}
	start_gate_release(&client_gate);
	for (i = 0; i < DESCRIPTOR_CLIENTS; i++) {
		error = pthread_join(clients[i].dc_thread, NULL);
		ATF_REQUIRE_MSG(
		    error == 0, "pthread_join failed: %s", strerror(error));
		ATF_REQUIRE_MSG(clients[i].dc_result == 0,
				"descriptor client %u failed: %s",
				i,
				strerror(clients[i].dc_error));
	}
	ATF_REQUIRE(
	    atomic_load_explicit(&descriptor_callbacks, memory_order_relaxed) ==
	    DESCRIPTOR_CLIENTS * DESCRIPTOR_CALLS);
	start_gate_destroy(&client_gate);
	test_close_door(door_fd);
}

static void *
revoke_client_thread(void *argument)
{
	struct revoke_context *context;
	uint32_t i;

	context = argument;
	start_gate_wait(&client_gate);
	for (i = 0; i < REVOKE_MAX_CALLS; i++) {
		if (perform_echo_call(
			context->rc_door_fd, context->rc_index, i) == 0) {
			context->rc_successes++;
			continue;
		}
		context->rc_error = errno;
		if (errno == EBADF) {
			context->rc_result = 0;
			return (NULL);
		}
		context->rc_result = -1;
		return (NULL);
	}
	context->rc_result = -1;
	context->rc_error = ETIMEDOUT;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(concurrent_clients_single_door);

ATF_TC_BODY(concurrent_clients_single_door, tc)
{
	struct client_context clients[CONCURRENT_CLIENTS];
	uint32_t i;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	start_gate_init(&client_gate, CONCURRENT_CLIENTS);
	memset(clients, 0, sizeof(clients));
	for (i = 0; i < CONCURRENT_CLIENTS; i++) {
		clients[i].cc_door_fd = door_fd;
		clients[i].cc_index = i;
		clients[i].cc_iterations = CALLS_PER_CLIENT;
	}
	start_echo_clients(clients, CONCURRENT_CLIENTS);
	start_gate_release(&client_gate);
	join_echo_clients(clients, CONCURRENT_CLIENTS);
	start_gate_destroy(&client_gate);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(simultaneous_burst_drain);

ATF_TC_BODY(simultaneous_burst_drain, tc)
{
	struct client_context clients[BURST_CLIENTS];
	uint32_t i;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	start_gate_init(&client_gate, BURST_CLIENTS);
	memset(clients, 0, sizeof(clients));
	for (i = 0; i < BURST_CLIENTS; i++) {
		clients[i].cc_door_fd = door_fd;
		clients[i].cc_index = i;
		clients[i].cc_iterations = 1;
	}
	start_echo_clients(clients, BURST_CLIENTS);
	start_gate_release(&client_gate);
	join_echo_clients(clients, BURST_CLIENTS);
	start_gate_destroy(&client_gate);

	ATF_REQUIRE_MSG(perform_echo_call(door_fd, UINT32_MAX, 0) == 0,
			"post-burst recovery call failed: %s",
			strerror(errno));
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(independent_doors_progress);

ATF_TC_BODY(independent_doors_progress, tc)
{
	struct client_context clients[MULTIDOOR_COUNT];
	int doors[MULTIDOOR_COUNT];
	uint32_t i;

	(void)tc;
	start_gate_init(&client_gate, MULTIDOOR_COUNT);
	memset(clients, 0, sizeof(clients));
	for (i = 0; i < MULTIDOOR_COUNT; i++) {
		doors[i] = test_create_door(echo_server);
		clients[i].cc_door_fd = doors[i];
		clients[i].cc_index = i;
		clients[i].cc_iterations = MULTIDOOR_CALLS;
	}
	start_echo_clients(clients, MULTIDOOR_COUNT);
	start_gate_release(&client_gate);
	join_echo_clients(clients, MULTIDOOR_COUNT);
	for (i = 0; i < MULTIDOOR_COUNT; i++)
		test_close_door(doors[i]);
	start_gate_destroy(&client_gate);
}

ATF_TC_WITHOUT_HEAD(concurrent_descriptor_copy);

ATF_TC_BODY(concurrent_descriptor_copy, tc)
{
	(void)tc;
	run_descriptor_stress(0);
}

ATF_TC_WITHOUT_HEAD(concurrent_descriptor_move);

ATF_TC_BODY(concurrent_descriptor_move, tc)
{
	(void)tc;
	run_descriptor_stress(DOOR_RELEASE);
}

ATF_TC_WITHOUT_HEAD(sequential_call_stress);

ATF_TC_BODY(sequential_call_stress, tc)
{
	uint32_t i;
	int door_fd;

	(void)tc;
	door_fd = test_create_door(echo_server);
	for (i = 0; i < SEQUENTIAL_CALLS; i++) {
		ATF_REQUIRE_MSG(perform_echo_call(door_fd, 0, i) == 0,
				"call %u failed: %s",
				i,
				strerror(errno));
	}
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(create_call_destroy_stress);

ATF_TC_BODY(create_call_destroy_stress, tc)
{
	uint32_t i;
	int door_fd;

	(void)tc;
	for (i = 0; i < CREATE_DESTROY_LOOPS; i++) {
		door_fd = test_create_door(echo_server);
		ATF_REQUIRE_MSG(perform_echo_call(door_fd, i, 0) == 0,
				"iteration %u failed: %s",
				i,
				strerror(errno));
		test_close_door(door_fd);
	}
}

ATF_TC_WITHOUT_HEAD(concurrent_revoke_race);

ATF_TC_BODY(concurrent_revoke_race, tc)
{
	struct revoke_context clients[REVOKE_CLIENTS];
	uint32_t i, successes;
	int door_fd, error;

	(void)tc;
	door_fd = test_create_door(echo_server);
	start_gate_init(&client_gate, REVOKE_CLIENTS);
	memset(clients, 0, sizeof(clients));
	for (i = 0; i < REVOKE_CLIENTS; i++) {
		clients[i].rc_door_fd = door_fd;
		clients[i].rc_index = i;
		error = pthread_create(&clients[i].rc_thread,
				       NULL,
				       revoke_client_thread,
				       &clients[i]);
		ATF_REQUIRE_MSG(
		    error == 0, "pthread_create failed: %s", strerror(error));
	}
	start_gate_release(&client_gate);
	(void)usleep(20000);
	ATF_REQUIRE_MSG(door_revoke(door_fd) == 0,
			"door_revoke failed: %s",
			strerror(errno));

	successes = 0;
	for (i = 0; i < REVOKE_CLIENTS; i++) {
		error = pthread_join(clients[i].rc_thread, NULL);
		ATF_REQUIRE_MSG(
		    error == 0, "pthread_join failed: %s", strerror(error));
		ATF_REQUIRE_MSG(clients[i].rc_result == 0,
				"client %u stopped with %s",
				i,
				strerror(clients[i].rc_error));
		ATF_REQUIRE(clients[i].rc_error == EBADF);
		successes += clients[i].rc_successes;
	}
	ATF_REQUIRE(successes != 0);
	start_gate_destroy(&client_gate);
	test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, concurrent_clients_single_door);
	ATF_TP_ADD_TC(tp, simultaneous_burst_drain);
	ATF_TP_ADD_TC(tp, independent_doors_progress);
	ATF_TP_ADD_TC(tp, concurrent_descriptor_copy);
	ATF_TP_ADD_TC(tp, concurrent_descriptor_move);
	ATF_TP_ADD_TC(tp, sequential_call_stress);
	ATF_TP_ADD_TC(tp, create_call_destroy_stress);
	ATF_TP_ADD_TC(tp, concurrent_revoke_race);
	return (atf_no_error());
}
