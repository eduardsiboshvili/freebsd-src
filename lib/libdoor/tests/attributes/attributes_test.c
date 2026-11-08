/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <door.h>
#include <sys/door_core.h>
#include <sys/syscall.h>

#include "test_common.h"

#define WAIT_SECONDS 5

static pthread_mutex_t event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t event_cv = PTHREAD_COND_INITIALIZER;
static unsigned int unref_count;
static unsigned int unref_bad;
static int reply_fd = -1;
static int entered_pipe[2] = {-1, -1};
static int release_pipe[2] = {-1, -1};

static void
reset_events(void)
{
	pthread_mutex_lock(&event_lock);
	unref_count = 0;
	unref_bad = 0;
	pthread_mutex_unlock(&event_lock);
}

static bool
wait_unref_count(unsigned int expected)
{
	struct timespec limit;
	int error;

	ATF_REQUIRE(clock_gettime(CLOCK_REALTIME, &limit) == 0);
	limit.tv_sec += WAIT_SECONDS;
	pthread_mutex_lock(&event_lock);
	while (unref_count < expected) {
		error = pthread_cond_timedwait(&event_cv, &event_lock, &limit);
		if (error == ETIMEDOUT)
			break;
		ATF_REQUIRE(error == 0);
	}
	error = unref_count >= expected;
	pthread_mutex_unlock(&event_lock);
	return (error != 0);
}

static unsigned int
read_unref_count(void)
{
	unsigned int count;
	pthread_mutex_lock(&event_lock);
	count = unref_count;
	pthread_mutex_unlock(&event_lock);
	return (count);
}

static void
attribute_server(void *cookie,
		 char *data,
		 size_t data_size,
		 door_desc_t *descs,
		 uint_t ndescs)
{
	door_info_t info;
	door_cred_t cred;
	ucred_t *ucred;
	uint_t i;
	bool bad;

	(void)cookie;
	bad = false;
	if (data == DOOR_UNREF_DATA) {
		if (data_size != 0 || descs != NULL || ndescs != 0)
			bad = true;
		if (door_info(DOOR_QUERY, &info) != 0 ||
		    (info.di_attributes & DOOR_IS_UNREF) == 0)
			bad = true;
		errno = 0;
		if (door_cred(&cred) != -1 || errno != EINVAL)
			bad = true;
		errno = 0;
		if (door_ucred(&ucred) != -1 || errno != EINVAL)
			bad = true;
		pthread_mutex_lock(&event_lock);
		unref_count++;
		if (bad)
			unref_bad++;
		pthread_cond_broadcast(&event_cv);
		pthread_mutex_unlock(&event_lock);
		door_return(NULL, 0, NULL, 0);
	}
	for (i = 0; i < ndescs; i++)
		(void)close(descs[i].d_descriptor);
	door_return(data, data_size, NULL, 0);
}

static void
reply_descriptor_server(void *cookie,
			char *data,
			size_t data_size,
			door_desc_t *descs,
			uint_t ndescs)
{
	door_desc_t desc;
	uint_t i;
	(void)cookie;
	(void)data;
	(void)data_size;
	for (i = 0; i < ndescs; i++)
		(void)close(descs[i].d_descriptor);
	test_init_desc(&desc, reply_fd, 0);
	door_return(NULL, 0, &desc, 1);
}

static void
blocking_server(void *cookie,
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
	if (write(entered_pipe[1], &byte, 1) != 1)
		door_return(NULL, 0, NULL, 0);
	if (read(release_pipe[0], &byte, 1) != 1)
		door_return(NULL, 0, NULL, 0);
	door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

static int
create_attached_door(uint_t attributes, char *path, size_t path_size)
{
	int door_fd, path_fd;
	ATF_REQUIRE(path_size >= sizeof("/tmp/libdoor-attr.XXXXXX"));
	strlcpy(path, "/tmp/libdoor-attr.XXXXXX", path_size);
	path_fd = mkstemp(path);
	ATF_REQUIRE(path_fd != -1);
	ATF_REQUIRE(close(path_fd) == 0);
	door_fd = door_create(attribute_server, NULL, attributes);
	ATF_REQUIRE_MSG(door_fd != -1, "door_create: %s", strerror(errno));
	ATF_REQUIRE_MSG(
	    fattach(door_fd, path) == 0, "fattach: %s", strerror(errno));
	return (door_fd);
}

static void
close_attached_door(int door_fd, const char *path)
{
	ATF_REQUIRE_MSG(fdetach(path) == 0, "fdetach: %s", strerror(errno));
	ATF_REQUIRE(unlink(path) == 0);
	test_close_door(door_fd);
}

static void
open_close_path(const char *path)
{
	int fd = open(path, O_RDWR);
	ATF_REQUIRE_MSG(fd != -1, "open: %s", strerror(errno));
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(unref_single_delivery);

ATF_TC_BODY(unref_single_delivery, tc)
{
	char path[64];
	int door_fd;
	(void)tc;
	reset_events();
	door_fd = create_attached_door(DOOR_UNREF, path, sizeof(path));
	ATF_REQUIRE(read_unref_count() == 0);
	open_close_path(path);
	ATF_REQUIRE_MSG(wait_unref_count(1), "UNREF not delivered");
	open_close_path(path);
	usleep(100000);
	ATF_REQUIRE(read_unref_count() == 1);
	pthread_mutex_lock(&event_lock);
	ATF_REQUIRE(unref_bad == 0);
	pthread_mutex_unlock(&event_lock);
	{
		char request[] = "after-unref";
		char reply[32];
		door_arg_t arg;
		test_init_call(&arg, reply, sizeof(reply));
		arg.data_ptr = request;
		arg.data_size = sizeof(request);
		ATF_REQUIRE(door_call(door_fd, &arg) == 0);
		ATF_REQUIRE(arg.data_size == sizeof(request));
		ATF_REQUIRE(memcmp(arg.data_ptr, request, sizeof(request)) ==
			    0);
	}
	close_attached_door(door_fd, path);
}

ATF_TC_WITHOUT_HEAD(unref_last_close_only);

ATF_TC_BODY(unref_last_close_only, tc)
{
	char path[64];
	int door_fd, a, b;
	(void)tc;
	reset_events();
	door_fd = create_attached_door(DOOR_UNREF, path, sizeof(path));
	a = open(path, O_RDWR);
	b = open(path, O_RDWR);
	ATF_REQUIRE(a != -1 && b != -1);
	ATF_REQUIRE(close(a) == 0);
	usleep(50000);
	ATF_REQUIRE(read_unref_count() == 0);
	ATF_REQUIRE(close(b) == 0);
	ATF_REQUIRE(wait_unref_count(1));
	close_attached_door(door_fd, path);
}

ATF_TC_WITHOUT_HEAD(unref_multi_rearms);

ATF_TC_BODY(unref_multi_rearms, tc)
{
	char path[64];
	int door_fd;
	unsigned int i;
	(void)tc;
	reset_events();
	door_fd = create_attached_door(DOOR_UNREF_MULTI, path, sizeof(path));
	for (i = 1; i <= 3; i++) {
		open_close_path(path);
		ATF_REQUIRE_MSG(
		    wait_unref_count(i), "UNREF_MULTI event %u missing", i);
	}
	pthread_mutex_lock(&event_lock);
	ATF_REQUIRE(unref_bad == 0);
	pthread_mutex_unlock(&event_lock);
	close_attached_door(door_fd, path);
}

ATF_TC_WITHOUT_HEAD(unref_multi_normalizes_attribute);

ATF_TC_BODY(unref_multi_normalizes_attribute, tc)
{
	door_info_t info;
	int fd;
	(void)tc;
	fd = door_create(attribute_server, NULL, DOOR_UNREF_MULTI);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE(door_info(fd, &info) == 0);
	ATF_REQUIRE((info.di_attributes & DOOR_UNREF_MULTI) != 0);
	ATF_REQUIRE((info.di_attributes & DOOR_UNREF) != 0);
	test_close_door(fd);
}

struct call_context {
	pthread_t thread;
	int fd;
	int result;
	int error;
};

static void *
call_thread(void *argp)
{
	struct call_context *c = argp;
	char reply[16];
	door_arg_t arg;
	test_init_call(&arg, reply, sizeof(reply));
	errno = 0;
	c->result = door_call(c->fd, &arg);
	c->error = errno;
	return (NULL);
}

static void
noop_handler(int signo)
{
	(void)signo;
}

ATF_TC_WITHOUT_HEAD(no_cancel_ignores_signal);

ATF_TC_BODY(no_cancel_ignores_signal, tc)
{
	struct sigaction action, old;
	struct call_context c;
	char byte;
	int error;
	(void)tc;
	ATF_REQUIRE(pipe(entered_pipe) == 0);
	ATF_REQUIRE(pipe(release_pipe) == 0);
	memset(&action, 0, sizeof(action));
	action.sa_handler = noop_handler;
	ATF_REQUIRE(sigemptyset(&action.sa_mask) == 0);
	ATF_REQUIRE(sigaction(SIGUSR1, &action, &old) == 0);
	memset(&c, 0, sizeof(c));
	c.fd = door_create(blocking_server, NULL, DOOR_NO_CANCEL);
	ATF_REQUIRE(c.fd != -1);
	error = pthread_create(&c.thread, NULL, call_thread, &c);
	ATF_REQUIRE(error == 0);
	ATF_REQUIRE(read(entered_pipe[0], &byte, 1) == 1);
	ATF_REQUIRE(pthread_kill(c.thread, SIGUSR1) == 0);
	usleep(50000);
	byte = 'R';
	ATF_REQUIRE(write(release_pipe[1], &byte, 1) == 1);
	ATF_REQUIRE(pthread_join(c.thread, NULL) == 0);
	ATF_REQUIRE_MSG(
	    c.result == 0, "NO_CANCEL call failed: %s", strerror(c.error));
	test_close_door(c.fd);
	ATF_REQUIRE(sigaction(SIGUSR1, &old, NULL) == 0);
	close(entered_pipe[0]);
	close(entered_pipe[1]);
	close(release_pipe[0]);
	close(release_pipe[1]);
	entered_pipe[0] = entered_pipe[1] = release_pipe[0] = release_pipe[1] =
	    -1;
}

ATF_TC_WITHOUT_HEAD(no_cancel_rejects_explicit_cancel);

ATF_TC_BODY(no_cancel_rejects_explicit_cancel, tc)
{
	struct door_ioc_cancel cancel;
	int fd;
	(void)tc;
	fd = door_create(attribute_server, NULL, DOOR_NO_CANCEL);
	ATF_REQUIRE(fd != -1);
	memset(&cancel, 0, sizeof(cancel));
	cancel.dican_version = DOOR_ABI_VERSION;
	cancel.dican_call_id = 1;
	errno = 0;
	ATF_REQUIRE(__syscall((quad_t)SYS_door,
			      DOOR_SC_CANCEL,
			      (long)fd,
			      (long)(uintptr_t)&cancel,
			      0,
			      0,
			      0) == -1);
	ATF_REQUIRE(errno == ENOTSUP);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(no_cancel_revoke_still_terminates);

ATF_TC_BODY(no_cancel_revoke_still_terminates, tc)
{
	struct call_context c;
	char byte;
	int error;

	(void)tc;
	ATF_REQUIRE(pipe(entered_pipe) == 0);
	ATF_REQUIRE(pipe(release_pipe) == 0);
	memset(&c, 0, sizeof(c));
	c.fd = door_create(blocking_server, NULL, DOOR_NO_CANCEL);
	ATF_REQUIRE(c.fd != -1);
	error = pthread_create(&c.thread, NULL, call_thread, &c);
	ATF_REQUIRE(error == 0);
	ATF_REQUIRE(read(entered_pipe[0], &byte, 1) == 1);
	ATF_REQUIRE(door_revoke(c.fd) == 0);
	ATF_REQUIRE(pthread_join(c.thread, NULL) == 0);
	ATF_REQUIRE(c.result == -1);
	ATF_REQUIRE_MSG(
	    c.error == EBADF, "errno=%d (%s)", c.error, strerror(c.error));
	byte = 'R';
	ATF_REQUIRE(write(release_pipe[1], &byte, 1) == 1);
	test_close_door(c.fd);
	close(entered_pipe[0]);
	close(entered_pipe[1]);
	close(release_pipe[0]);
	close(release_pipe[1]);
	entered_pipe[0] = entered_pipe[1] = -1;
	release_pipe[0] = release_pipe[1] = -1;
}

ATF_TC_WITHOUT_HEAD(refuse_desc_request_preserves_source);

ATF_TC_BODY(refuse_desc_request_preserves_source, tc)
{
	char reply[16];
	door_arg_t arg;
	door_desc_t desc;
	int fd, source;
	(void)tc;
	fd = door_create(attribute_server, NULL, DOOR_REFUSE_DESC);
	ATF_REQUIRE(fd != -1);
	source = test_make_regular_fd();
	ATF_REQUIRE(source != -1);
	test_init_desc(&desc, source, DOOR_RELEASE);
	test_init_call(&arg, reply, sizeof(reply));
	arg.desc_ptr = &desc;
	arg.desc_num = 1;
	errno = 0;
	ATF_REQUIRE(door_call(fd, &arg) == -1);
	ATF_REQUIRE(errno == ENOTSUP);
	test_require_fd_valid(source);
	close(source);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(refuse_desc_reply_preserves_source);

ATF_TC_BODY(refuse_desc_reply_preserves_source, tc)
{
	char reply[16];
	door_arg_t arg;
	int fd;
	(void)tc;
	reply_fd = test_make_regular_fd();
	ATF_REQUIRE(reply_fd != -1);
	fd = door_create(reply_descriptor_server, NULL, DOOR_REFUSE_DESC);
	ATF_REQUIRE(fd != -1);
	test_init_call(&arg, reply, sizeof(reply));
	errno = 0;
	ATF_REQUIRE(door_call(fd, &arg) == -1);
	ATF_REQUIRE(errno == ENOTSUP);
	test_require_fd_valid(reply_fd);
	close(reply_fd);
	reply_fd = -1;
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(refuse_desc_data_only_and_param);

ATF_TC_BODY(refuse_desc_data_only_and_param, tc)
{
	char request[] = "data";
	char reply[16];
	door_arg_t arg;
	size_t value;
	int fd;
	(void)tc;
	fd = door_create(attribute_server, NULL, DOOR_REFUSE_DESC);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE(door_getparam(fd, DOOR_PARAM_DESC_MAX, &value) == 0);
	ATF_REQUIRE(value == 0);
	errno = 0;
	ATF_REQUIRE(door_setparam(fd, DOOR_PARAM_DESC_MAX, 1) == -1);
	ATF_REQUIRE(errno == ENOTSUP);
	test_init_call(&arg, reply, sizeof(reply));
	arg.data_ptr = request;
	arg.data_size = sizeof(request);
	ATF_REQUIRE(door_call(fd, &arg) == 0);
	ATF_REQUIRE(arg.data_size == sizeof(request));
	ATF_REQUIRE(memcmp(arg.data_ptr, request, sizeof(request)) == 0);
	test_close_door(fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, unref_single_delivery);
	ATF_TP_ADD_TC(tp, unref_last_close_only);
	ATF_TP_ADD_TC(tp, unref_multi_rearms);
	ATF_TP_ADD_TC(tp, unref_multi_normalizes_attribute);
	ATF_TP_ADD_TC(tp, no_cancel_ignores_signal);
	ATF_TP_ADD_TC(tp, no_cancel_rejects_explicit_cancel);
	ATF_TP_ADD_TC(tp, no_cancel_revoke_still_terminates);
	ATF_TP_ADD_TC(tp, refuse_desc_request_preserves_source);
	ATF_TP_ADD_TC(tp, refuse_desc_reply_preserves_source);
	ATF_TP_ADD_TC(tp, refuse_desc_data_only_and_param);
	return (atf_no_error());
}
