/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "test_common.h"

#include <sys/syscall.h>

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#define PAYLOAD_MAX 8192
#define LONG_CHAIN_RELAYS 12

struct forward_header {
	int error;
	unsigned int hops;
	pid_t backend;
	pid_t backend_caller;
	pid_t caller;
};

struct relay_route {
	atomic_int target;
};

struct child_endpoint {
	pid_t pid;
	int control;
	int door;
};

static void
close_input(door_desc_t *desc, uint_t count)
{
	for (uint_t i = 0; i < count; i++) {
		if ((desc[i].d_attributes & DOOR_DESCRIPTOR) != 0)
			(void)close(desc[i].d_descriptor);
	}
}

static void
return_error(int error, pid_t caller)
{
	struct forward_header header = { .error = error, .caller = caller };

	(void)door_return((char *)&header, sizeof(header), NULL, 0);
}

static void
backend_proc(void *cookie, char *data, size_t size, door_desc_t *desc,
    uint_t count)
{
	char reply[sizeof(struct forward_header) + PAYLOAD_MAX];
	struct forward_header header = { 0 };
	door_desc_t returned;
	door_cred_t cred;

	(void)cookie;
	if (door_cred(&cred) == -1) {
		header.error = errno;
	} else if (size > PAYLOAD_MAX) {
		header.error = EMSGSIZE;
	} else if (count > 1 ||
	    (count == 1 && (desc[0].d_attributes & DOOR_DESCRIPTOR) == 0)) {
		header.error = EPROTO;
	} else {
		header.backend = getpid();
		header.backend_caller = cred.dc_pid;
		if (count == 1) {
			if (write(desc[0].d_descriptor, "B", 1) != 1)
				header.error = EIO;
			test_init_desc(&returned, desc[0].d_descriptor, 0);
		}
	}

	if (header.error != 0) {
		close_input(desc, count);
		return_error(header.error, 0);
		return;
	}

	memcpy(reply, &header, sizeof(header));
	for (size_t i = 0; i < size; i++)
		reply[sizeof(header) + i] = (unsigned char)data[i] ^ 0xa5;

	(void)door_return(reply, sizeof(header) + size,
	    count == 1 ? &returned : NULL, count);
	close_input(desc, count);
}

static void
relay_proc(void *cookie, char *data, size_t size, door_desc_t *desc,
    uint_t count)
{
	struct relay_route *route = cookie;
	struct forward_header header;
	door_cred_t before, after;
	door_desc_t forwarded, returned;
	door_arg_t call;
	char inline_reply[sizeof(header)];
	int error, rc;

	if (door_cred(&before) == -1) {
		error = errno;
		close_input(desc, count);
		return_error(error, 0);
		return;
	}

	if (count > 1 ||
	    (count == 1 && (desc[0].d_attributes & DOOR_DESCRIPTOR) == 0)) {
		close_input(desc, count);
		return_error(EPROTO, before.dc_pid);
		return;
	}

	test_init_call(&call, inline_reply, sizeof(inline_reply));
	call.data_ptr = data;
	call.data_size = size;
	if (count == 1) {
		test_init_desc(&forwarded, desc[0].d_descriptor, 0);
		call.desc_ptr = &forwarded;
		call.desc_num = 1;
	}

	rc = door_call(atomic_load(&route->target), &call);
	error = rc == -1 ? errno : 0;
	close_input(desc, count);

	/* A nested call must leave the outer invocation's credentials intact. */
	if (door_cred(&after) == -1 || after.dc_pid != before.dc_pid ||
	    after.dc_ruid != before.dc_ruid || after.dc_euid != before.dc_euid ||
	    after.dc_rgid != before.dc_rgid || after.dc_egid != before.dc_egid)
		error = EPROTO;

	if (error == 0 && (call.data_size < sizeof(header) ||
	    call.desc_num != count || (count == 1 &&
	    (call.desc_ptr[0].d_attributes & DOOR_DESCRIPTOR) == 0)))
		error = EPROTO;

	if (error != 0) {
		return_error(error, before.dc_pid);
	} else {
		memcpy(&header, call.data_ptr, sizeof(header));
		header.hops++;
		header.caller = before.dc_pid;
		memcpy(call.data_ptr, &header, sizeof(header));

		if (count == 1)
			test_init_desc(&returned, call.desc_ptr[0].d_descriptor, 0);

		(void)door_return(call.data_ptr, call.data_size,
		    count == 1 ? &returned : NULL, count);
	}

	if (rc == 0) {
		test_close_received_descs(&call);
		if (call.rbuf != inline_reply)
			(void)munmap(call.rbuf, call.rsize);
	}
}

static int
new_endpoint(door_server_procedure_t *proc, void *cookie)
{
	int fd = door_create(proc, cookie, DOOR_NO_DEPLETION_CB);

	ATF_REQUIRE_MSG(fd != -1, "door_create: %s", strerror(errno));
	return (fd);
}

static void
drop_endpoint(int fd)
{
	ATF_REQUIRE_EQ(0, door_revoke(fd));
	ATF_REQUIRE_EQ(0, close(fd));
}

static void
check_reply(const door_arg_t *call, const char *payload, size_t size,
    unsigned int hops, pid_t backend, pid_t backend_caller)
{
	struct forward_header header;

	ATF_REQUIRE(call->data_size >= sizeof(header));
	memcpy(&header, call->data_ptr, sizeof(header));
	ATF_REQUIRE_EQ_MSG(0, header.error, "relay error: %s",
	    strerror(header.error));
	ATF_REQUIRE_EQ(sizeof(header) + size, call->data_size);
	ATF_REQUIRE_EQ(hops, header.hops);
	ATF_REQUIRE_EQ(backend, header.backend);
	ATF_REQUIRE_EQ(backend_caller, header.backend_caller);
	ATF_REQUIRE_EQ(getpid(), header.caller);

	for (size_t i = 0; i < size; i++) {
		ATF_REQUIRE_EQ_MSG((unsigned char)payload[i] ^ 0xa5,
		    (unsigned char)call->data_ptr[sizeof(header) + i],
		    "response byte %zu", i);
	}
}

ATF_TC(forward_chain);
ATF_TC_HEAD(forward_chain, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Forward empty and binary requests through two nested relays");
	atf_tc_set_md_var(tc, "timeout", "20");
}

ATF_TC_BODY(forward_chain, tc)
{
	static const size_t sizes[] = { 0, 31, PAYLOAD_MAX, 31 };
	struct relay_route middle_route, front_route;
	char payload[PAYLOAD_MAX], reply[sizeof(struct forward_header) + 31];
	door_arg_t call;
	int backend, middle, front;

	(void)tc;
	backend = new_endpoint(backend_proc, NULL);
	atomic_init(&middle_route.target, backend);
	middle = new_endpoint(relay_proc, &middle_route);
	atomic_init(&front_route.target, middle);
	front = new_endpoint(relay_proc, &front_route);

	for (size_t j = 0; j < sizeof(sizes) / sizeof(sizes[0]); j++) {
		for (size_t i = 0; i < sizes[j]; i++)
			payload[i] = (unsigned char)(i * 31 + j);

		test_init_call(&call, reply, sizeof(reply));
		call.data_ptr = sizes[j] == 0 ? NULL : payload;
		call.data_size = sizes[j];
		ATF_REQUIRE_MSG(door_call(front, &call) == 0,
		    "front door_call: %s", strerror(errno));
		check_reply(&call, payload, sizes[j], 2, getpid(), getpid());
		ATF_REQUIRE_EQ(0, call.desc_num);
		if (sizes[j] == PAYLOAD_MAX) {
			ATF_REQUIRE(call.rbuf != reply);
			ATF_REQUIRE_EQ(0, munmap(call.rbuf, call.rsize));
		} else {
			ATF_REQUIRE(call.rbuf == reply);
		}
	}

	drop_endpoint(front);
	drop_endpoint(middle);
	drop_endpoint(backend);
}

static int
transfer_endpoint(int control, int door)
{
	union {
		struct cmsghdr align;
		char bytes[CMSG_SPACE(sizeof(int))];
	} ancillary = { 0 };
	char marker = 'D';
	struct iovec iov = { .iov_base = &marker, .iov_len = sizeof(marker) };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = ancillary.bytes,
		.msg_controllen = sizeof(ancillary.bytes),
	};
	struct cmsghdr *cmsg;

	if (door != -1) {
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(door));
		memcpy(CMSG_DATA(cmsg), &door, sizeof(door));
		return (sendmsg(control, &msg, 0) == 1 ? 0 : -1);
	}

	if (recvmsg(control, &msg, 0) != 1)
		return (-1);

	cmsg = CMSG_FIRSTHDR(&msg);
	if (marker != 'D' || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
	    cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(door))) {
		errno = EPROTO;
		return (-1);
	}

	memcpy(&door, CMSG_DATA(cmsg), sizeof(door));
	return (door);
}

static void
gated_backend(void *cookie, char *data, size_t size, door_desc_t *desc,
    uint_t count)
{
	int gate = *(int *)cookie;
	char marker;
	ssize_t n;

	if (size == 1 && data[0] == 'G') {
		if (write(gate, "E", 1) != 1)
			_exit(3);
		do {
			n = read(gate, &marker, 1);
		} while (n == -1 && errno == EINTR);
		if (n != 1 || marker != 'R')
			_exit(4);
	}

	backend_proc(NULL, data, size, desc, count);
}

static struct child_endpoint
start_child(int target, int close_fd, int gate)
{
	struct child_endpoint child;
	struct relay_route route;
	int control[2];

	/* The socket only publishes the Door fd and keeps the child alive. */
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, control));
	child.pid = fork();
	ATF_REQUIRE_MSG(child.pid >= 0, "fork: %s", strerror(errno));
	if (child.pid == 0) {
		int door;
		char byte;
		ssize_t n;

		alarm(25);
		(void)close(control[0]);
		if (close_fd != -1)
			(void)close(close_fd);

		if (target != -1) {
			atomic_init(&route.target, target);
			door = door_create(relay_proc, &route,
			    DOOR_NO_DEPLETION_CB);
		} else {
			door = door_create(gate == -1 ? backend_proc :
			    gated_backend, &gate, DOOR_NO_DEPLETION_CB);
		}
		if (door == -1 || transfer_endpoint(control[1], door) == -1)
			_exit(1);

		do {
			n = read(control[1], &byte, 1);
		} while (n == -1 && errno == EINTR);

		_exit(n == 0 && door_revoke(door) == 0 ? 0 : 2);
	}

	ATF_REQUIRE_EQ(0, close(control[1]));
	child.control = control[0];
	child.door = transfer_endpoint(child.control, -1);
	ATF_REQUIRE_MSG(child.door != -1, "receive Door fd: %s",
	    strerror(errno));
	return (child);
}

static void
stop_child(struct child_endpoint *child)
{
	int status;

	ATF_REQUIRE_EQ(0, close(child->door));
	/* Later children can still hold copies of this control socket. */
	ATF_REQUIRE_EQ(0, shutdown(child->control, SHUT_WR));
	ATF_REQUIRE_EQ(0, close(child->control));
	ATF_REQUIRE_EQ(child->pid, waitpid(child->pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
}

ATF_TC(forward_across_processes);
ATF_TC_HEAD(forward_across_processes, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Forward a descriptor in both directions and check caller PIDs");
	atf_tc_set_md_var(tc, "timeout", "20");
}

ATF_TC_BODY(forward_across_processes, tc)
{
	struct child_endpoint backend, relay;
	char data[] = { '\0', 'x', '\0', 'y' };
	char reply[sizeof(struct forward_header) + sizeof(data)], marker;
	door_desc_t sent;
	door_arg_t call;
	int channel[2];

	(void)tc;
	backend = start_child(-1, -1, -1);
	relay = start_child(backend.door, backend.control, -1);
	ATF_REQUIRE_EQ(0, pipe2(channel, O_NONBLOCK));

	test_init_call(&call, reply, sizeof(reply));
	test_init_desc(&sent, channel[1], 0);
	call.data_ptr = data;
	call.data_size = sizeof(data);
	call.desc_ptr = &sent;
	call.desc_num = 1;

	ATF_REQUIRE_MSG(door_call(relay.door, &call) == 0,
	    "front door_call: %s", strerror(errno));
	check_reply(&call, data, sizeof(data), 1, backend.pid, relay.pid);
	ATF_REQUIRE_EQ(1, call.desc_num);
	ATF_REQUIRE((call.desc_ptr[0].d_attributes & DOOR_DESCRIPTOR) != 0);
	ATF_REQUIRE(call.desc_ptr[0].d_descriptor != channel[1]);
	test_require_fd_valid(channel[1]);

	ATF_REQUIRE_EQ(1, read(channel[0], &marker, 1));
	ATF_REQUIRE_EQ('B', marker);
	ATF_REQUIRE_EQ(1, write(call.desc_ptr[0].d_descriptor, "C", 1));
	ATF_REQUIRE_EQ(1, read(channel[0], &marker, 1));
	ATF_REQUIRE_EQ('C', marker);

	test_close_received_descs(&call);
	if (call.rbuf != reply)
		ATF_REQUIRE_EQ(0, munmap(call.rbuf, call.rsize));
	ATF_REQUIRE_EQ(0, close(channel[1]));
	ATF_REQUIRE_EQ(0, close(channel[0]));
	stop_child(&relay);
	stop_child(&backend);
}

static void
blocked_backend(void *cookie, char *data, size_t size, door_desc_t *desc,
    uint_t count)
{
	int gate = *(int *)cookie;
	char marker;

	if (write(gate, "E", 1) == 1)
		(void)read(gate, &marker, 1);

	backend_proc(NULL, data, size, desc, count);
	(void)write(gate, "D", 1);
}

struct client_result {
	int front;
	int error;
	char request;
	struct forward_header reply;
};

static void *
call_while_blocked(void *cookie)
{
	struct client_result *result = cookie;
	char reply[sizeof(result->reply)];
	door_arg_t call;

	test_init_call(&call, reply, sizeof(reply));
	if (result->request != '\0') {
		call.data_ptr = &result->request;
		call.data_size = 1;
	}
	if (door_call(result->front, &call) == -1) {
		result->error = errno;
	} else {
		if (call.data_size != sizeof(result->reply) || call.desc_num != 0)
			result->error = EPROTO;
		else
			memcpy(&result->reply, call.data_ptr, sizeof(result->reply));

		test_close_received_descs(&call);
		if (call.rbuf != reply)
			(void)munmap(call.rbuf, call.rsize);
	}

	return (NULL);
}

ATF_TC(forward_revoke_and_recover);
ATF_TC_HEAD(forward_revoke_and_recover, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Revoke an in-flight downstream call, then reuse the same relay");
	atf_tc_set_md_var(tc, "timeout", "20");
}

ATF_TC_BODY(forward_revoke_and_recover, tc)
{
	struct relay_route route;
	struct client_result result = { 0 };
	char data[] = { 'n', '\0', 'w' };
	char reply[sizeof(struct forward_header) + sizeof(data)], marker;
	int gate[2], backend, replacement;
	pthread_t client;
	door_arg_t call;

	(void)tc;
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, gate));
	backend = new_endpoint(blocked_backend, &gate[1]);
	replacement = new_endpoint(backend_proc, NULL);
	atomic_init(&route.target, backend);
	result.front = new_endpoint(relay_proc, &route);

	ATF_REQUIRE_EQ(0, pthread_create(&client, NULL, call_while_blocked,
	    &result));
	ATF_REQUIRE_EQ(1, read(gate[0], &marker, 1));
	ATF_REQUIRE_EQ('E', marker);
	ATF_REQUIRE_EQ(0, door_revoke(backend));

	/* The upstream caller must finish while the backend is still gated. */
	ATF_REQUIRE_EQ(0, pthread_join(client, NULL));
	ATF_REQUIRE_EQ_MSG(0, result.error, "front door_call: %s",
	    strerror(result.error));
	ATF_REQUIRE_EQ(EBADF, result.reply.error);
	ATF_REQUIRE_EQ(getpid(), result.reply.caller);

	atomic_store(&route.target, replacement);
	test_init_call(&call, reply, sizeof(reply));
	call.data_ptr = data;
	call.data_size = sizeof(data);
	ATF_REQUIRE_MSG(door_call(result.front, &call) == 0,
	    "front door_call after reroute: %s", strerror(errno));
	check_reply(&call, data, sizeof(data), 1, getpid(), getpid());
	ATF_REQUIRE_EQ(0, call.desc_num);
	ATF_REQUIRE(call.rbuf == reply);

	ATF_REQUIRE_EQ(1, write(gate[0], "R", 1));
	ATF_REQUIRE_EQ(1, read(gate[0], &marker, 1));
	ATF_REQUIRE_EQ('D', marker);
	ATF_REQUIRE_EQ(0, close(gate[0]));
	ATF_REQUIRE_EQ(0, close(gate[1]));
	ATF_REQUIRE_EQ(0, close(backend));
	drop_endpoint(result.front);
	drop_endpoint(replacement);
}

static void
check_live_route(int front, char *data, size_t size, unsigned int hops,
    pid_t backend, pid_t backend_caller)
{
	char reply[sizeof(struct forward_header)];
	door_arg_t call;

	test_init_call(&call, reply, sizeof(reply));
	call.data_ptr = data;
	call.data_size = size;
	ATF_REQUIRE_MSG(door_call(front, &call) == 0,
	    "front door_call: %s", strerror(errno));
	check_reply(&call, data, size, hops, backend, backend_caller);
	ATF_REQUIRE_EQ(0, call.desc_num);
	if (size != 0) {
		ATF_REQUIRE(call.rbuf != reply);
		ATF_REQUIRE_EQ(0, munmap(call.rbuf, call.rsize));
	} else {
		ATF_REQUIRE(call.rbuf == reply);
	}
}

ATF_TC(forward_chain_long);
ATF_TC_HEAD(forward_chain_long, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Check data and application errors across twelve relay processes");
	atf_tc_set_md_var(tc, "timeout", "20");
}

ATF_TC_BODY(forward_chain_long, tc)
{
	struct child_endpoint chain[LONG_CHAIN_RELAYS + 1];
	struct forward_header error_reply;
	char data[PAYLOAD_MAX + 1];
	door_arg_t call;
	int front;

	(void)tc;
	chain[0] = start_child(-1, -1, -1);
	for (size_t i = 1; i <= LONG_CHAIN_RELAYS; i++) {
		chain[i] = start_child(chain[i - 1].door,
		    chain[i - 1].control, -1);
	}
	front = chain[LONG_CHAIN_RELAYS].door;
	for (size_t i = 0; i < sizeof(data); i++)
		data[i] = (char)(i * 31 + (i >> 8));

	check_live_route(front, data, PAYLOAD_MAX, LONG_CHAIN_RELAYS,
	    chain[0].pid, chain[1].pid);

	test_init_call(&call, (char *)&error_reply, sizeof(error_reply));
	call.data_ptr = data;
	call.data_size = sizeof(data);
	ATF_REQUIRE_MSG(door_call(front, &call) == 0,
	    "door_call carrying backend error: %s", strerror(errno));
	ATF_REQUIRE_EQ(sizeof(error_reply), call.data_size);
	ATF_REQUIRE(call.data_ptr == (char *)&error_reply);
	ATF_REQUIRE_EQ(0, call.desc_num);
	ATF_REQUIRE_EQ(EMSGSIZE, error_reply.error);
	ATF_REQUIRE_EQ(LONG_CHAIN_RELAYS, error_reply.hops);
	ATF_REQUIRE_EQ(getpid(), error_reply.caller);

	check_live_route(front, NULL, 0, LONG_CHAIN_RELAYS,
	    chain[0].pid, chain[1].pid);
	for (size_t i = LONG_CHAIN_RELAYS + 1; i > 0; i--)
		stop_child(&chain[i - 1]);
}

enum crash_point {
	CRASH_CLIENT,
	CRASH_BACKEND,
	CRASH_RELAY,
};

static pid_t
start_gated_client(int *control)
{
	struct client_result result = { .request = 'G' };
	int pair[2];
	pid_t pid;

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
	pid = fork();
	ATF_REQUIRE_MSG(pid != -1, "fork client: %s", strerror(errno));
	if (pid == 0) {
		alarm(25);
		(void)close(pair[0]);
		result.front = transfer_endpoint(pair[1], -1);
		if (result.front == -1)
			_exit(1);
		(void)close(pair[1]);
		(void)call_while_blocked(&result);
		_exit(2); /* The call must still be pending when killed. */
	}
	ATF_REQUIRE_EQ(0, close(pair[1]));
	*control = pair[0];
	return (pid);
}

static void
kill_and_reap(pid_t pid)
{
	int status;

	ATF_REQUIRE_MSG(kill(pid, SIGKILL) == 0,
	    "kill %d: %s", (int)pid, strerror(errno));
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFSIGNALED(status));
	ATF_REQUIRE_EQ(SIGKILL, WTERMSIG(status));
}

static void
check_dead_endpoint(const struct child_endpoint *child)
{
	door_arg_t call;
	char reply[sizeof(struct forward_header)];
	int rc, error;

	test_init_call(&call, reply, sizeof(reply));
	rc = door_call(child->door, &call);
	error = errno;
	ATF_REQUIRE_EQ_MSG(-1, rc, "call through a dead owner's Door");
	ATF_REQUIRE_EQ_MSG(EBADF, error, "dead owner's Door: %s",
	    strerror(error));
	ATF_REQUIRE_EQ(0, close(child->door));
	ATF_REQUIRE_EQ(0, close(child->control));
}

static void
check_call_state(int door, unsigned int active)
{
	struct door_ioc_info info = { 0 };

	/* The public door_info_t omits the diagnostic queue counts. */
	ATF_REQUIRE_MSG(__syscall((quad_t)SYS_door, DOOR_SC_INFO, (long)door,
	    (long)(uintptr_t)&info, 0, 0, 0) == 0, "Door info fd %d: %s",
	    door, strerror(errno));
	ATF_REQUIRE_EQ_MSG(0, info.di_pending_calls, "Door fd %d", door);
	ATF_REQUIRE_EQ_MSG(active, info.di_active_calls, "Door fd %d", door);
}

static void
exercise_crash(enum crash_point point)
{
	struct child_endpoint backend, relay;
	struct child_endpoint new_backend = { 0 }, new_relay = { 0 };
	struct client_result result = { .request = 'G' };
	struct relay_route route;
	pthread_t caller;
	pid_t client = -1;
	int client_control = -1, gate[2];
	char marker, probe[] = { 'r', '\0', 'v' };

	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, gate));
	backend = start_child(-1, gate[0], gate[1]);
	ATF_REQUIRE_EQ(0, close(gate[1]));
	relay = start_child(backend.door, backend.control, -1);

	/* Fork all process fixtures before creating a local Door worker. */
	if (point == CRASH_BACKEND) {
		new_backend = start_child(-1, -1, -1);
		new_relay = start_child(new_backend.door, new_backend.control, -1);
	} else if (point == CRASH_RELAY) {
		new_relay = start_child(backend.door, backend.control, -1);
	} else {
		client = start_gated_client(&client_control);
	}

	atomic_init(&route.target, relay.door);
	result.front = new_endpoint(relay_proc, &route);
	if (point == CRASH_CLIENT) {
		ATF_REQUIRE_EQ(0, transfer_endpoint(client_control, result.front));
		ATF_REQUIRE_EQ(0, close(client_control));
	} else {
		ATF_REQUIRE_EQ(0, pthread_create(&caller, NULL, call_while_blocked,
		    &result));
	}

	/* The backend is inside the callback; neither relay can reply yet. */
	ATF_REQUIRE_EQ(1, read(gate[0], &marker, 1));
	ATF_REQUIRE_EQ('E', marker);
	check_call_state(result.front, 1);
	check_call_state(relay.door, 1);
	check_call_state(backend.door, 1);
	if (point == CRASH_CLIENT) {
		kill_and_reap(client);
		ATF_REQUIRE_EQ(1, write(gate[0], "R", 1));
		check_live_route(result.front, probe, sizeof(probe), 2,
		    backend.pid, relay.pid);
	} else {
		struct child_endpoint *victim =
		    point == CRASH_BACKEND ? &backend : &relay;

		kill_and_reap(victim->pid);
		/* A dead relay must wake the caller even with its backend gated. */
		ATF_REQUIRE_EQ(0, pthread_join(caller, NULL));
		ATF_REQUIRE_EQ_MSG(0, result.error, "outer door_call: %s",
		    strerror(result.error));
		ATF_REQUIRE_EQ_MSG(EBADF, result.reply.error, "relay reply: %s",
		    strerror(result.reply.error));
		ATF_REQUIRE_EQ(getpid(), result.reply.caller);
		check_dead_endpoint(victim);

		if (point == CRASH_RELAY)
			ATF_REQUIRE_EQ(1, write(gate[0], "R", 1));
		atomic_store(&route.target, new_relay.door);
		check_live_route(result.front, probe, sizeof(probe), 2,
		    point == CRASH_BACKEND ? new_backend.pid : backend.pid,
		    new_relay.pid);
		check_call_state(new_relay.door, 0);
		if (point == CRASH_BACKEND)
			check_call_state(new_backend.door, 0);
	}
	check_call_state(result.front, 0);
	if (point != CRASH_RELAY)
		check_call_state(relay.door, 0);
	if (point != CRASH_BACKEND)
		check_call_state(backend.door, 0);

	drop_endpoint(result.front);
	if (point != CRASH_CLIENT)
		stop_child(&new_relay);
	if (point == CRASH_BACKEND)
		stop_child(&new_backend);
	if (point != CRASH_RELAY)
		stop_child(&relay);
	if (point != CRASH_BACKEND)
		stop_child(&backend);
	ATF_REQUIRE_EQ(0, close(gate[0]));
}

ATF_TC(forward_client_crash);
ATF_TC_HEAD(forward_client_crash, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Kill the client during a nested call and reuse the whole route");
	atf_tc_set_md_var(tc, "timeout", "20");
}

ATF_TC_BODY(forward_client_crash, tc)
{
	(void)tc;
	exercise_crash(CRASH_CLIENT);
}

ATF_TC(forward_backend_crash);
ATF_TC_HEAD(forward_backend_crash, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Kill the backend during a nested call and reroute the next call");
	atf_tc_set_md_var(tc, "timeout", "20");
}

ATF_TC_BODY(forward_backend_crash, tc)
{
	(void)tc;
	exercise_crash(CRASH_BACKEND);
}

ATF_TC(forward_relay_crash);
ATF_TC_HEAD(forward_relay_crash, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "Kill a relay while both adjacent calls are still active");
	atf_tc_set_md_var(tc, "timeout", "20");
}

ATF_TC_BODY(forward_relay_crash, tc)
{
	(void)tc;
	exercise_crash(CRASH_RELAY);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, forward_chain);
	ATF_TP_ADD_TC(tp, forward_across_processes);
	ATF_TP_ADD_TC(tp, forward_revoke_and_recover);
	ATF_TP_ADD_TC(tp, forward_chain_long);
	ATF_TP_ADD_TC(tp, forward_client_crash);
	ATF_TP_ADD_TC(tp, forward_backend_crash);
	ATF_TP_ADD_TC(tp, forward_relay_crash);

	return (atf_no_error());
}
