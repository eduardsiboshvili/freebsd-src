/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <door.h>

struct async_fixture {
	pthread_mutex_t lock;
	pthread_cond_t cv;
	int reply_fd;
	bool entered;
	bool release;
	unsigned completion_count;
	unsigned requests_finished;
	bool request_done; /* Application body has stopped using this fixture. */
	bool completed;
	bool received;
	int status;
	size_t result_size;
	pthread_t completion_thread;
	uint64_t submitted_id;
	uint64_t completed_id;
};

static door_async_server_t *shared_registry;

static void
shared_control(void *cookie, char *data, size_t size, door_desc_t *desc,
    uint_t ndesc)
{
	uint64_t token;
	int result;

	(void)cookie;
	result = EINVAL;
	if (size == sizeof(token) && ndesc == 1 && desc != NULL) {
		memcpy(&token, data, sizeof(token));
		if (door_async_server_register(shared_registry, token,
		    desc[0].d_descriptor) == 0)
			result = 0;
		else
			result = errno;
	}
	(void)door_return((char *)&result, sizeof(result), NULL, 0);
}

static void
shared_request(void *cookie, char *data, size_t size, door_desc_t *desc,
    uint_t ndesc)
{
	door_async_request_t request;
	struct async_fixture *f = cookie;

	(void)desc;
	(void)ndesc;
	if (door_async_request_parse(data, size, &request) == 0)
		(void)door_async_server_respond(shared_registry, &request, 0,
		    request.dar_data, request.dar_size);
	pthread_mutex_lock(&f->lock);
	if (++f->requests_finished == 2)
		f->request_done = true;
	pthread_cond_broadcast(&f->cv);
	pthread_mutex_unlock(&f->lock);
}

static void
register_reply(int control_fd, door_async_t *ctx)
{
	door_desc_t desc;
	door_arg_t arg;
	uint64_t token;
	char reply[sizeof(int)];
	int result;

	ATF_REQUIRE(door_async_token(ctx, &token) == 0);
	memset(&desc, 0, sizeof(desc));
	desc.d_attributes = DOOR_DESCRIPTOR;
	desc.d_descriptor = door_async_reply_fd(ctx);
	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = (char *)&token;
	arg.data_size = sizeof(token);
	arg.desc_ptr = &desc;
	arg.desc_num = 1;
	arg.rbuf = reply;
	arg.rsize = sizeof(reply);
	ATF_REQUIRE_MSG(door_call(control_fd, &arg) == 0,
	    "register Door CALL: %s", strerror(errno));
	ATF_REQUIRE(arg.data_size == sizeof(result));
	memcpy(&result, arg.data_ptr, sizeof(result));
	ATF_REQUIRE_MSG(result == 0, "register reply failed: %d", result);
}

static void
wait_flag(struct async_fixture *f, const bool *flag)
{
	struct timespec deadline;
	int error;

	ATF_REQUIRE(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
	deadline.tv_sec += 10;
	pthread_mutex_lock(&f->lock);
	while (!*flag) {
		error = pthread_cond_timedwait(&f->cv, &f->lock, &deadline);
		ATF_REQUIRE_MSG(error == 0, "async operation timed out: %d", error);
	}
	pthread_mutex_unlock(&f->lock);
}

static void
async_server(void *cookie, char *data, size_t size, door_desc_t *desc,
    uint_t ndesc)
{
	struct async_fixture *f;
	door_async_request_t request;
	int reply_fd;

	(void)desc;
	(void)ndesc;
	f = cookie;
	if (door_async_request_parse(data, size, &request) == -1)
		return;
	pthread_mutex_lock(&f->lock);
	f->entered = true;
	pthread_cond_broadcast(&f->cv);
	while (!f->release)
		pthread_cond_wait(&f->cv, &f->lock);
	reply_fd = f->reply_fd;
	pthread_mutex_unlock(&f->lock);
	(void)door_async_respond(reply_fd, &request, 0, request.dar_data,
	    request.dar_size);
	pthread_mutex_lock(&f->lock);
	f->request_done = true;
	pthread_cond_broadcast(&f->cv);
	pthread_mutex_unlock(&f->lock);
}

static void
async_completed(uint64_t id, int status, const void *data, size_t size,
    void *cookie)
{
	struct async_fixture *f;

	f = cookie;
	pthread_mutex_lock(&f->lock);
	f->completion_count++;
	f->completion_thread = pthread_self();
	f->completed_id = id;
	f->status = status;
	f->result_size = size;
	f->received = true;
	f->completed = status == 0 && size == 4 &&
	    memcmp(data, "ping", 4) == 0;
	pthread_cond_broadcast(&f->cv);
	pthread_mutex_unlock(&f->lock);
}

static void
kernel_echo(void *cookie, char *data, size_t size, door_desc_t *desc,
    uint_t ndesc)
{
	(void)cookie;
	(void)desc;
	(void)ndesc;
	(void)door_return(data, size, NULL, 0);
}

static void
kernel_gated(void *cookie, char *data, size_t size, door_desc_t *desc,
    uint_t ndesc)
{
	struct async_fixture *f;

	(void)desc;
	(void)ndesc;
	f = cookie;
	pthread_mutex_lock(&f->lock);
	f->entered = true;
	pthread_cond_broadcast(&f->cv);
	while (!f->release)
		pthread_cond_wait(&f->cv, &f->lock);
	pthread_mutex_unlock(&f->lock);
	(void)door_return(data, size, NULL, 0);
	/* Reply workers are separate; publish the last request-side access. */
	pthread_mutex_lock(&f->lock);
	f->request_done = true;
	pthread_cond_broadcast(&f->cv);
	pthread_mutex_unlock(&f->lock);
}

static void
kernel_worker_exit(void *cookie, char *data, size_t size,
    door_desc_t *desc, uint_t ndesc)
{
	(void)cookie;
	(void)data;
	(void)size;
	(void)desc;
	(void)ndesc;
	pthread_exit(NULL);
}

ATF_TC_WITHOUT_HEAD(kernel_routed_shared_endpoint);
ATF_TC_BODY(kernel_routed_shared_endpoint, tc)
{
	struct async_fixture first, second;
	door_arg_t sync_arg;
	char sync_request[] = "ping";
	char sync_reply[4];
	door_async_t *client_a, *client_b;
	int fd;

	(void)tc;
	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));
	ATF_REQUIRE(pthread_mutex_init(&first.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&first.cv, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&second.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&second.cv, NULL) == 0);
	fd = door_create(kernel_echo, NULL, 0);
	ATF_REQUIRE(fd >= 0);
	memset(&sync_arg, 0, sizeof(sync_arg));
	sync_arg.data_ptr = sync_request;
	sync_arg.data_size = sizeof(sync_request) - 1;
	sync_arg.rbuf = sync_reply;
	sync_arg.rsize = sizeof(sync_reply);
	ATF_REQUIRE(door_call(fd, &sync_arg) == 0);
	ATF_REQUIRE(sync_arg.data_size == 4);
	ATF_REQUIRE(memcmp(sync_arg.data_ptr, "ping", 4) == 0);
	ATF_REQUIRE(door_async_open(fd, 2, &client_a) == 0);
	ATF_REQUIRE(door_async_open(fd, 2, &client_b) == 0);
	ATF_REQUIRE(door_async_submit(client_a, "ping", 4, async_completed,
	    &first, &first.submitted_id) == 0);
	ATF_REQUIRE(door_async_submit(client_b, "ping", 4, async_completed,
	    &second, &second.submitted_id) == 0);
	wait_flag(&first, &first.completed);
	wait_flag(&second, &second.completed);
	/* Each context receives its own reply without a server registry. */
	ATF_REQUIRE(first.status == 0 && second.status == 0);
	ATF_REQUIRE(door_async_close(client_a) == 0);
	ATF_REQUIRE(door_async_close(client_b) == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
	pthread_cond_destroy(&first.cv);
	pthread_mutex_destroy(&first.lock);
	pthread_cond_destroy(&second.cv);
	pthread_mutex_destroy(&second.lock);
}

ATF_TC_WITHOUT_HEAD(kernel_pending_revoke_completion);
ATF_TC_BODY(kernel_pending_revoke_completion, tc)
{
	struct async_fixture f;
	struct door_ioc_info info;
	door_async_t *ctx;
	int fd;

	(void)tc;
	memset(&f, 0, sizeof(f));
	ATF_REQUIRE(pthread_mutex_init(&f.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&f.cv, NULL) == 0);
	/* Raw CREATE starts no libdoor request worker: acceptance stays PENDING. */
	fd = (int)__syscall((quad_t)SYS_door, DOOR_SC_CREATE,
	    0, 0, DOOR_CREATE_F_NORMAL, 0, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(door_async_open(fd, 1, &ctx) == 0);
	ATF_REQUIRE(door_async_submit(ctx, "ping", 4, async_completed,
	    &f, &f.submitted_id) == 0);
	memset(&info, 0, sizeof(info));
	info.di_version = DOOR_ABI_VERSION;
	ATF_REQUIRE(__syscall((quad_t)SYS_door, DOOR_SC_INFO,
	    (long)fd, (long)(uintptr_t)&info, 0, 0, 0) == 0);
	ATF_REQUIRE(info.di_pending_calls == 1 && info.di_active_calls == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	wait_flag(&f, &f.received);
	ATF_REQUIRE(f.status == EBADF && f.completed_id == f.submitted_id);
	ATF_REQUIRE(door_async_close(ctx) == 0);
	ATF_REQUIRE_EQ(f.completion_count, 1);
	close(fd);
	pthread_cond_destroy(&f.cv);
	pthread_mutex_destroy(&f.lock);
}

ATF_TC_WITHOUT_HEAD(kernel_revoke_completion);
ATF_TC_BODY(kernel_revoke_completion, tc)
{
	struct async_fixture f;
	door_async_t *ctx;
	int fd;

	(void)tc;
	memset(&f, 0, sizeof(f));
	ATF_REQUIRE(pthread_mutex_init(&f.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&f.cv, NULL) == 0);
	fd = door_create(kernel_gated, &f, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(door_async_open(fd, 1, &ctx) == 0);
	ATF_REQUIRE(door_async_submit(ctx, "ping", 4, async_completed,
	    &f, &f.submitted_id) == 0);
	wait_flag(&f, &f.entered);
	ATF_REQUIRE(door_revoke(fd) == 0);
	wait_flag(&f, &f.received);
	ATF_REQUIRE(f.status == EBADF);
	ATF_REQUIRE(f.completed_id == f.submitted_id);
	pthread_mutex_lock(&f.lock);
	f.release = true;
	pthread_cond_broadcast(&f.cv);
	pthread_mutex_unlock(&f.lock);
	wait_flag(&f, &f.request_done);
	ATF_REQUIRE(door_async_close(ctx) == 0);
	ATF_REQUIRE_EQ(f.completion_count, 1);
	close(fd);
	pthread_cond_destroy(&f.cv);
	pthread_mutex_destroy(&f.lock);
}

ATF_TC_WITHOUT_HEAD(kernel_cancel_completion);
ATF_TC_BODY(kernel_cancel_completion, tc)
{
	struct async_fixture f;
	door_async_t *ctx;
	int fd;

	(void)tc;
	memset(&f, 0, sizeof(f));
	ATF_REQUIRE(pthread_mutex_init(&f.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&f.cv, NULL) == 0);
	fd = door_create(kernel_gated, &f, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(door_async_open(fd, 1, &ctx) == 0);
	ATF_REQUIRE(door_async_submit(ctx, "ping", 4, async_completed,
	    &f, &f.submitted_id) == 0);
	wait_flag(&f, &f.entered);
	ATF_REQUIRE(door_async_cancel(ctx, f.submitted_id) == 0);
	wait_flag(&f, &f.received);
	ATF_REQUIRE(f.status == ECANCELED);
	pthread_mutex_lock(&f.lock);
	f.release = true;
	pthread_cond_broadcast(&f.cv);
	pthread_mutex_unlock(&f.lock);
	wait_flag(&f, &f.request_done);
	ATF_REQUIRE(door_async_close(ctx) == 0);
	ATF_REQUIRE_EQ(f.completion_count, 1);
	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
	pthread_cond_destroy(&f.cv);
	pthread_mutex_destroy(&f.lock);
}

ATF_TC_WITHOUT_HEAD(kernel_close_callback_thread);
ATF_TC_BODY(kernel_close_callback_thread, tc)
{
	struct async_fixture f;
	door_async_t *ctx;
	int fd;

	(void)tc;
	memset(&f, 0, sizeof(f));
	ATF_REQUIRE(pthread_mutex_init(&f.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&f.cv, NULL) == 0);
	fd = door_create(kernel_gated, &f, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(door_async_open(fd, 1, &ctx) == 0);
	ATF_REQUIRE(door_async_submit(ctx, "ping", 4, async_completed,
	    &f, &f.submitted_id) == 0);
	wait_flag(&f, &f.entered);
	/* Request is gated: no peer reply can win before close's local drain. */
	ATF_REQUIRE(door_async_close(ctx) == 0);
	ATF_REQUIRE_EQ(f.completion_count, 1);
	ATF_REQUIRE(f.received && f.status == ECANCELED);
	ATF_REQUIRE(f.completed_id == f.submitted_id);
	ATF_REQUIRE(pthread_equal(f.completion_thread, pthread_self()));
	pthread_mutex_lock(&f.lock);
	ATF_REQUIRE(!f.request_done);
	f.release = true;
	pthread_cond_broadcast(&f.cv);
	pthread_mutex_unlock(&f.lock);
	/* close drained reply workers only; request fixture still needs this gate. */
	wait_flag(&f, &f.request_done);
	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
	pthread_cond_destroy(&f.cv);
	pthread_mutex_destroy(&f.lock);
}

ATF_TC_WITHOUT_HEAD(kernel_stop_revoke_completion);
ATF_TC_BODY(kernel_stop_revoke_completion, tc)
{
	struct async_fixture server;
	int channel[2], fd, status;
	pid_t child;
	char submitted;

	(void)tc;
	memset(&server, 0, sizeof(server));
	ATF_REQUIRE(pthread_mutex_init(&server.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&server.cv, NULL) == 0);
	fd = door_create(kernel_gated, &server, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(pipe(channel) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		struct async_fixture client;
		door_async_t *ctx;
		int rc;

		close(channel[0]);
		memset(&client, 0, sizeof(client));
		rc = pthread_mutex_init(&client.lock, NULL);
		rc |= pthread_cond_init(&client.cv, NULL);
		if (rc != 0 || door_async_open(fd, 1, &ctx) != 0 ||
		    door_async_submit(ctx, "ping", 4, async_completed,
		    &client, &client.submitted_id) != 0)
			_exit(10);
		if (write(channel[1], "S", 1) != 1)
			_exit(11);
		raise(SIGSTOP);
		wait_flag(&client, &client.received);
		if (client.status != EBADF ||
		    client.completed_id != client.submitted_id)
			_exit(12);
		if (door_async_close(ctx) != 0)
			_exit(13);
		close(channel[1]);
		close(fd);
		_exit(0);
	}
	close(channel[1]);
	ATF_REQUIRE(read(channel[0], &submitted, 1) == 1);
	ATF_REQUIRE(submitted == 'S');
	wait_flag(&server, &server.entered);
	ATF_REQUIRE(waitpid(child, &status, WUNTRACED) == child);
	ATF_REQUIRE(WIFSTOPPED(status));
	ATF_REQUIRE(door_revoke(fd) == 0);
	ATF_REQUIRE(kill(child, SIGCONT) == 0);
	pthread_mutex_lock(&server.lock);
	server.release = true;
	pthread_cond_broadcast(&server.cv);
	pthread_mutex_unlock(&server.lock);
	wait_flag(&server, &server.request_done);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	close(channel[0]);
	close(fd);
	pthread_cond_destroy(&server.cv);
	pthread_mutex_destroy(&server.lock);
}

/* Stop/revoke tests above exercise the public API. The former reserve/capture
 * tests required removed kernel pause hooks and are intentionally retired.
 * Public tests do not deterministically cover reserve/capture phases. */

ATF_TC_WITHOUT_HEAD(kernel_raw_validation);
ATF_TC_BODY(kernel_raw_validation, tc)
{
	struct door_ioc_async_call arg;
	int request_fd, reply_fd;

	(void)tc;
	request_fd = door_create(kernel_echo, NULL, 0);
	ATF_REQUIRE(request_fd >= 0);
	reply_fd = door_create(kernel_echo, NULL, DOOR_ONEWAY);
	ATF_REQUIRE(reply_fd >= 0);
	memset(&arg, 0, sizeof(arg));
	arg.diac_version = DOOR_ABI_VERSION;
	arg.diac_call_id = 1;
	arg.diac_completion_fd = reply_fd;
	arg.diac_reserved = 1;
	ATF_REQUIRE(syscall(SYS_door, DOOR_SC_ASYNC_CALL, request_fd,
	    &arg, 0, 0, 0) == -1);
	ATF_REQUIRE(errno == EINVAL);
	arg.diac_reserved = 0;
	arg.diac_completion_fd = request_fd;
	ATF_REQUIRE(syscall(SYS_door, DOOR_SC_ASYNC_CALL, request_fd,
	    &arg, 0, 0, 0) == -1);
	ATF_REQUIRE(errno == EINVAL);
	arg.diac_completion_fd = reply_fd;
	arg.diac_request_ptr = 1;
	arg.diac_request_size = 4;
	ATF_REQUIRE(syscall(SYS_door, DOOR_SC_ASYNC_CALL, request_fd,
	    &arg, 0, 0, 0) == -1);
	ATF_REQUIRE(errno == EFAULT);
	ATF_REQUIRE(door_revoke(request_fd) == 0);
	ATF_REQUIRE(door_revoke(reply_fd) == 0);
	close(request_fd);
	close(reply_fd);
}

ATF_TC_WITHOUT_HEAD(kernel_worker_exit_completion);
ATF_TC_BODY(kernel_worker_exit_completion, tc)
{
	struct async_fixture f;
	door_async_t *ctx;
	int fd;

	(void)tc;
	memset(&f, 0, sizeof(f));
	ATF_REQUIRE(pthread_mutex_init(&f.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&f.cv, NULL) == 0);
	fd = door_create(kernel_worker_exit, NULL, 0);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(door_async_open(fd, 1, &ctx) == 0);
	ATF_REQUIRE(door_async_submit(ctx, "ping", 4, async_completed,
	    &f, &f.submitted_id) == 0);
	wait_flag(&f, &f.received);
	ATF_REQUIRE(f.status == ECONNRESET);
	ATF_REQUIRE(door_async_close(ctx) == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
	pthread_cond_destroy(&f.cv);
	pthread_mutex_destroy(&f.lock);
}

ATF_TC_WITHOUT_HEAD(request_reply_and_limit);
ATF_TC_BODY(request_reply_and_limit, tc)
{
	struct async_fixture f;
	door_async_t *ctx;
	int fd;

	(void)tc;
	memset(&f, 0, sizeof(f));
	ATF_REQUIRE(pthread_mutex_init(&f.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&f.cv, NULL) == 0);
	fd = door_create(async_server, &f, DOOR_ONEWAY | DOOR_PRIVATE);
	ATF_REQUIRE_MSG(fd >= 0, "door_create: %s", strerror(errno));
	ATF_REQUIRE_MSG(door_async_open(fd, 1, &ctx) == 0,
	    "door_async_open: %s", strerror(errno));
	f.reply_fd = door_async_reply_fd(ctx);
	ATF_REQUIRE(f.reply_fd >= 0);
	ATF_REQUIRE_MSG(door_async_submit(ctx, "ping", 4, async_completed,
	    &f, &f.submitted_id) == 0, "submit: %s", strerror(errno));
	wait_flag(&f, &f.entered);
	ATF_REQUIRE(door_async_submit(ctx, "second", 6, async_completed,
	    &f, NULL) == -1);
	ATF_REQUIRE(errno == EAGAIN);
	pthread_mutex_lock(&f.lock);
	f.release = true;
	pthread_cond_broadcast(&f.cv);
	pthread_mutex_unlock(&f.lock);
	wait_flag(&f, &f.request_done);
	wait_flag(&f, &f.completed);
	ATF_REQUIRE(f.status == 0);
	ATF_REQUIRE(f.completed_id == f.submitted_id);
	ATF_REQUIRE(door_async_close(ctx) == 0);
	ATF_REQUIRE(door_revoke(fd) == 0);
	close(fd);
	pthread_cond_destroy(&f.cv);
	pthread_mutex_destroy(&f.lock);
}

ATF_TC_WITHOUT_HEAD(invalid_request_frame);
ATF_TC_BODY(invalid_request_frame, tc)
{
	door_async_request_t request;
	char malformed[32];

	(void)tc;
	memset(malformed, 0, sizeof(malformed));
	ATF_REQUIRE(door_async_request_parse(malformed, sizeof(malformed),
	    &request) == -1);
	ATF_REQUIRE(errno == EPROTO);
	ATF_REQUIRE(door_async_request_parse(NULL, 0, &request) == -1);
	ATF_REQUIRE(errno == EPROTO);
}

ATF_TC_WITHOUT_HEAD(shared_request_endpoint);
ATF_TC_BODY(shared_request_endpoint, tc)
{
	struct async_fixture first, second, requests;
	door_async_t *client_a, *client_b;
	int request_fd, control_fd;

	(void)tc;
	memset(&requests, 0, sizeof(requests));
	ATF_REQUIRE(pthread_mutex_init(&requests.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&requests.cv, NULL) == 0);
	memset(&first, 0, sizeof(first));
	memset(&second, 0, sizeof(second));
	ATF_REQUIRE(pthread_mutex_init(&first.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&first.cv, NULL) == 0);
	ATF_REQUIRE(pthread_mutex_init(&second.lock, NULL) == 0);
	ATF_REQUIRE(pthread_cond_init(&second.cv, NULL) == 0);
	ATF_REQUIRE(door_async_server_open(2, &shared_registry) == 0);
	request_fd = door_create(shared_request, &requests, DOOR_ONEWAY);
	ATF_REQUIRE(request_fd >= 0);
	control_fd = door_create(shared_control, NULL, 0);
	ATF_REQUIRE(control_fd >= 0);
	ATF_REQUIRE(door_async_open(request_fd, 2, &client_a) == 0);
	ATF_REQUIRE(door_async_open(request_fd, 2, &client_b) == 0);
	register_reply(control_fd, client_a);
	register_reply(control_fd, client_b);
	ATF_REQUIRE(door_async_submit(client_a, "ping", 4,
	    async_completed, &first, &first.submitted_id) == 0);
	ATF_REQUIRE(door_async_submit(client_b, "ping", 4,
	    async_completed, &second, &second.submitted_id) == 0);
	wait_flag(&first, &first.completed);
	wait_flag(&second, &second.completed);
	ATF_REQUIRE(first.completed_id == first.submitted_id);
	ATF_REQUIRE(second.completed_id == second.submitted_id);
	ATF_REQUIRE(door_async_close(client_a) == 0);
	ATF_REQUIRE(door_async_close(client_b) == 0);
	ATF_REQUIRE(door_revoke(request_fd) == 0);
	ATF_REQUIRE(door_revoke(control_fd) == 0);
	close(request_fd);
	close(control_fd);
	wait_flag(&requests, &requests.request_done);
	ATF_REQUIRE(door_async_server_close(shared_registry) == 0);
	pthread_cond_destroy(&requests.cv);
	pthread_mutex_destroy(&requests.lock);
	pthread_cond_destroy(&first.cv);
	pthread_mutex_destroy(&first.lock);
	pthread_cond_destroy(&second.cv);
	pthread_mutex_destroy(&second.lock);
}

struct terminal_race {
    pthread_barrier_t start;
    struct async_fixture reply;
    door_async_t *ctx;
    int fd, cancel_result, cancel_error, revoke_result;
    atomic_bool body_done;
};

static void
race_return(void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
    struct terminal_race *r = cookie;
    (void)desc; (void)ndesc;
    pthread_barrier_wait(&r->start);
    (void)door_return(data, size, NULL, 0);
    atomic_store(&r->body_done, true); /* No further cookie access. */
}
static void *
race_cancel(void *cookie)
{
    struct terminal_race *r = cookie;
    pthread_barrier_wait(&r->start);
    r->cancel_result = door_async_cancel(r->ctx, r->reply.submitted_id);
    r->cancel_error = errno;
    return (NULL);
}
static void *
race_revoke(void *cookie)
{
    struct terminal_race *r = cookie;
    pthread_barrier_wait(&r->start);
    r->revoke_result = door_revoke(r->fd);
    return (NULL);
}
static void
wait_atomic_bool(atomic_bool *flag)
{
    unsigned n;
    for (n = 0; n < 10000 && !atomic_load(flag); n++)
        usleep(1000);
    ATF_REQUIRE(atomic_load(flag));
}
ATF_TC_WITHOUT_HEAD(kernel_return_cancel_revoke_race);
ATF_TC_BODY(kernel_return_cancel_revoke_race, tc)
{
    unsigned iteration;
    (void)tc;
    for (iteration = 0; iteration < 100; iteration++) {
        struct terminal_race r;
        pthread_t cancel, revoke;
        memset(&r, 0, sizeof(r));
        atomic_init(&r.body_done, false);
        ATF_REQUIRE(pthread_barrier_init(&r.start, NULL, 4) == 0);
        ATF_REQUIRE(pthread_mutex_init(&r.reply.lock, NULL) == 0);
        ATF_REQUIRE(pthread_cond_init(&r.reply.cv, NULL) == 0);
        r.fd = door_create(race_return, &r, DOOR_PRIVATE);
        ATF_REQUIRE(r.fd >= 0);
        ATF_REQUIRE(door_async_open(r.fd, 1, &r.ctx) == 0);
        ATF_REQUIRE(door_async_submit(r.ctx, "ping", 4, async_completed,
            &r.reply, &r.reply.submitted_id) == 0);
        ATF_REQUIRE(pthread_create(&cancel, NULL, race_cancel, &r) == 0);
        ATF_REQUIRE(pthread_create(&revoke, NULL, race_revoke, &r) == 0);
        /* The request callback, cancel and revoke leave this same barrier. */
        pthread_barrier_wait(&r.start);
        ATF_REQUIRE(pthread_join(cancel, NULL) == 0);
        ATF_REQUIRE(pthread_join(revoke, NULL) == 0);
        ATF_REQUIRE(r.revoke_result == 0);
        /* ESRCH: RETURN/revoke removed the id. EALREADY: cancelled ACTIVE id.
         * EBADF: syscall entry observed the revoked request endpoint. */
        ATF_REQUIRE(r.cancel_result == 0 || (r.cancel_result == -1 &&
            (r.cancel_error == ESRCH || r.cancel_error == EALREADY ||
             r.cancel_error == EBADF)));
        wait_flag(&r.reply, &r.reply.received);
        ATF_REQUIRE(r.reply.status == 0 || r.reply.status == ECANCELED ||
            r.reply.status == EBADF);
        if (r.cancel_result == 0)
            ATF_REQUIRE_EQ(r.reply.status, ECANCELED);
        wait_atomic_bool(&r.body_done);
        ATF_REQUIRE(door_async_close(r.ctx) == 0);
        ATF_REQUIRE_EQ(r.reply.completion_count, 1);
        ATF_REQUIRE_EQ(r.reply.completed_id, r.reply.submitted_id);
        close(r.fd);
        pthread_barrier_destroy(&r.start);
        pthread_cond_destroy(&r.reply.cv);
        pthread_mutex_destroy(&r.reply.lock);
    }
}

struct callback_close {
    pthread_mutex_t lock;
    pthread_cond_t cv;
    bool entered, release, caller_started, caller_done;
    unsigned callbacks;
    door_async_t *ctx;
    int result, error;
};
static void
blocked_completion(uint64_t id, int status, const void *data, size_t size, void *cookie)
{
    struct callback_close *f = cookie;
    (void)id; (void)data; (void)size;
    ATF_REQUIRE_EQ(status, 0);
    pthread_mutex_lock(&f->lock);
    f->callbacks++;
    f->entered = true;
    pthread_cond_broadcast(&f->cv);
    while (!f->release)
        pthread_cond_wait(&f->cv, &f->lock);
    pthread_mutex_unlock(&f->lock);
}
static void *
close_in_thread(void *cookie)
{
    struct callback_close *f = cookie;
    pthread_mutex_lock(&f->lock);
    f->caller_started = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->lock);
    f->result = door_async_close(f->ctx);
    f->error = f->result == -1 ? errno : 0;
    pthread_mutex_lock(&f->lock);
    f->caller_done = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->lock);
    return (NULL);
}
ATF_TC_WITHOUT_HEAD(kernel_close_waits_running_callback);
ATF_TC_BODY(kernel_close_waits_running_callback, tc)
{
    struct callback_close f;
    struct timespec deadline;
    pthread_t closer;
    int fd, e;
    (void)tc;
    memset(&f, 0, sizeof(f));
    ATF_REQUIRE(pthread_mutex_init(&f.lock, NULL) == 0);
    ATF_REQUIRE(pthread_cond_init(&f.cv, NULL) == 0);
    fd = door_create(kernel_echo, NULL, 0);
    ATF_REQUIRE(fd >= 0);
    ATF_REQUIRE(door_async_open(fd, 1, &f.ctx) == 0);
    ATF_REQUIRE(door_async_submit(f.ctx, "ping", 4, blocked_completion, &f, NULL) == 0);
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 10;
    pthread_mutex_lock(&f.lock);
    while (!f.entered) {
        e = pthread_cond_timedwait(&f.cv, &f.lock, &deadline);
        ATF_REQUIRE_EQ(e, 0);
    }
    pthread_mutex_unlock(&f.lock);
    ATF_REQUIRE(pthread_create(&closer, NULL, close_in_thread, &f) == 0);
    pthread_mutex_lock(&f.lock);
    while (!f.caller_started) {
        e = pthread_cond_timedwait(&f.cv, &f.lock, &deadline);
        ATF_REQUIRE_EQ(e, 0);
    }
    /* Keep callback blocked for a bounded observation interval. A correct
     * close cannot complete while the worker still holds its ctx cookie. */
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += 100000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_sec++; deadline.tv_nsec -= 1000000000;
    }
    while (!f.caller_done) {
        e = pthread_cond_timedwait(&f.cv, &f.lock, &deadline);
        if (e == ETIMEDOUT)
            break;
        ATF_REQUIRE_EQ(e, 0);
    }
    ATF_REQUIRE_MSG(!f.caller_done || f.result == 0,
        "close returned an error while callback was blocked: rc=%d errno=%d (%s)",
        f.result, f.error, strerror(f.error));
    ATF_REQUIRE_MSG(!f.caller_done,
        "close succeeded before the running completion callback was released");
    f.release = true;
    pthread_cond_broadcast(&f.cv);
    pthread_mutex_unlock(&f.lock);
    ATF_REQUIRE(pthread_join(closer, NULL) == 0);
    ATF_REQUIRE(f.result == 0 && f.caller_done && f.callbacks == 1);
    ATF_REQUIRE(door_revoke(fd) == 0);
    close(fd);
    pthread_cond_destroy(&f.cv);
    pthread_mutex_destroy(&f.lock);
}

struct bad_reply {
    struct async_fixture result;
    int mode, descriptor;
};
static void
malformed_reply(void *cookie, char *data, size_t size, door_desc_t *desc, uint_t ndesc)
{
    struct bad_reply *b = cookie;
    door_desc_t output;
    (void)data; (void)size; (void)desc; (void)ndesc;
    if (b->mode == 0) {
        memset(&output, 0, sizeof(output));
        output.d_attributes = DOOR_DESCRIPTOR;
        output.d_descriptor = b->descriptor;
        (void)door_return(NULL, 0, &output, 1);
    } else if (b->mode == 1) {
        static char oversized[65537];
        (void)door_return(oversized, sizeof(oversized), NULL, 0);
    } else {
        (void)door_return((char *)(uintptr_t)1, 4, NULL, 0);
    }
    pthread_mutex_lock(&b->result.lock);
    b->result.request_done = true;
    pthread_cond_broadcast(&b->result.cv);
    pthread_mutex_unlock(&b->result.lock);
}
ATF_TC_WITHOUT_HEAD(kernel_invalid_reply_statuses);
ATF_TC_BODY(kernel_invalid_reply_statuses, tc)
{
    const int expected[] = {ENOTSUP, EMSGSIZE, EFAULT};
    unsigned mode;
    (void)tc;
    for (mode = 0; mode < 3; mode++) {
        struct bad_reply b;
        door_async_t *ctx;
        int fd;
        memset(&b, 0, sizeof(b));
        b.mode = mode;
        b.descriptor = open("/dev/null", O_RDONLY);
        ATF_REQUIRE(b.descriptor >= 0);
        ATF_REQUIRE(pthread_mutex_init(&b.result.lock, NULL) == 0);
        ATF_REQUIRE(pthread_cond_init(&b.result.cv, NULL) == 0);
        fd = door_create(malformed_reply, &b, DOOR_PRIVATE);
        ATF_REQUIRE(fd >= 0);
        ATF_REQUIRE(door_async_open(fd, 1, &ctx) == 0);
        ATF_REQUIRE(door_async_submit(ctx, "ping", 4, async_completed,
            &b.result, &b.result.submitted_id) == 0);
        wait_flag(&b.result, &b.result.received);
        wait_flag(&b.result, &b.result.request_done);
        ATF_REQUIRE_EQ(b.result.status, expected[mode]);
        ATF_REQUIRE_EQ(b.result.result_size, 0);
        ATF_REQUIRE(door_async_close(ctx) == 0);
        ATF_REQUIRE_EQ(b.result.completion_count, 1);
        ATF_REQUIRE(door_revoke(fd) == 0);
        close(fd); close(b.descriptor);
        pthread_cond_destroy(&b.result.cv);
        pthread_mutex_destroy(&b.result.lock);
    }
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, kernel_return_cancel_revoke_race);
	ATF_TP_ADD_TC(tp, kernel_close_waits_running_callback);
	ATF_TP_ADD_TC(tp, kernel_invalid_reply_statuses);
	ATF_TP_ADD_TC(tp, request_reply_and_limit);
	ATF_TP_ADD_TC(tp, invalid_request_frame);
	ATF_TP_ADD_TC(tp, shared_request_endpoint);
	ATF_TP_ADD_TC(tp, kernel_routed_shared_endpoint);
	ATF_TP_ADD_TC(tp, kernel_pending_revoke_completion);
	ATF_TP_ADD_TC(tp, kernel_revoke_completion);
	ATF_TP_ADD_TC(tp, kernel_cancel_completion);
	ATF_TP_ADD_TC(tp, kernel_close_callback_thread);
	ATF_TP_ADD_TC(tp, kernel_stop_revoke_completion);
	ATF_TP_ADD_TC(tp, kernel_raw_validation);
	ATF_TP_ADD_TC(tp, kernel_worker_exit_completion);
	return (atf_no_error());
}
