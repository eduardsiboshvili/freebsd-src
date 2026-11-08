/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define MULTIPLE_CALLS_COUNT 1000

static _Atomic unsigned int null_arg_calls;
static _Atomic unsigned int null_arg_nonempty;

static void
null_arg_server(void *cookie,
	    char *data,
	    size_t data_size,
	    door_desc_t *descs,
	    uint_t ndescs)
{
	(void)cookie;
	(void)data;
	(void)descs;

	atomic_fetch_add_explicit(&null_arg_calls, 1, memory_order_relaxed);
	if (data_size != 0 || ndescs != 0)
		atomic_store_explicit(&null_arg_nonempty, 1,
		    memory_order_relaxed);
	door_return(NULL, 0, NULL, 0);
}

static void
null_server(void *cookie,
	    char *data,
	    size_t data_size,
	    door_desc_t *descs,
	    uint_t ndescs)
{
	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	door_return(NULL, 0, NULL, 0);
}

static void
echo_server(void *cookie,
	    char *data,
	    size_t data_size,
	    door_desc_t *descs,
	    uint_t ndescs)
{
	(void)cookie;
	(void)descs;
	(void)ndescs;

	door_return(data, data_size, NULL, 0);
}

ATF_TC_WITHOUT_HEAD(create_info);

ATF_TC_BODY(create_info, tc)
{
	door_info_t info;
	int door_fd;

	(void)tc;

	door_fd = door_create(null_server, (void *)(uintptr_t)0x1234, 0);
	ATF_REQUIRE(door_fd != -1);
	ATF_REQUIRE(door_info(door_fd, &info) == 0);
	ATF_REQUIRE(info.di_target == getpid());
	ATF_REQUIRE(info.di_data == (door_ptr_t)0x1234);
	ATF_REQUIRE((info.di_attributes & DOOR_LOCAL) != 0);
	ATF_REQUIRE(info.di_uniquifier != 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(echo_call);

ATF_TC_BODY(echo_call, tc)
{
	static const char message[] = "hello through libdoor";
	char reply[128];
	door_arg_t arg;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(echo_server);
	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = (char *)(uintptr_t)message;
	arg.data_size = sizeof(message);
	arg.rbuf = reply;
	arg.rsize = sizeof(reply);

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_ptr == reply);
	ATF_REQUIRE(arg.data_size == sizeof(message));
	ATF_REQUIRE(memcmp(reply, message, sizeof(message)) == 0);
	ATF_REQUIRE(arg.desc_num == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(null_argument_call);

ATF_TC_BODY(null_argument_call, tc)
{
	int door_fd;

	(void)tc;

	atomic_store_explicit(&null_arg_calls, 0, memory_order_relaxed);
	atomic_store_explicit(&null_arg_nonempty, 0, memory_order_relaxed);
	door_fd = test_create_door(null_arg_server);
	ATF_REQUIRE(door_call(door_fd, NULL) == 0);
	ATF_REQUIRE(atomic_load_explicit(&null_arg_calls,
	    memory_order_relaxed) == 1);
	ATF_REQUIRE(atomic_load_explicit(&null_arg_nonempty,
	    memory_order_relaxed) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(multiple_calls);

ATF_TC_BODY(multiple_calls, tc)
{
	char reply[64];
	char request[64];
	door_arg_t arg;
	unsigned int i;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(echo_server);
	for (i = 0; i < MULTIPLE_CALLS_COUNT; i++) {
		(void)snprintf(request, sizeof(request), "request-%u", i);
		memset(&arg, 0, sizeof(arg));
		arg.data_ptr = request;
		arg.data_size = strlen(request) + 1;
		arg.rbuf = reply;
		arg.rsize = sizeof(reply);
		ATF_REQUIRE(door_call(door_fd, &arg) == 0);
		ATF_REQUIRE(strcmp(reply, request) == 0);
	}
	test_close_door(door_fd);
}

static void
pipe_writer_server(void *cookie,
		   char *data,
		   size_t data_size,
		   door_desc_t *descs,
		   uint_t ndescs)
{
	const char byte = 'A';

	(void)cookie;
	(void)data;
	(void)data_size;

	if (ndescs != 1 || descs == NULL ||
	    (descs[0].d_attributes & DOOR_DESCRIPTOR) == 0)
		door_return(
		    __DECONST(char *, "BAD-DESC"), sizeof("BAD-DESC"), NULL, 0);

	if (write(descs[0].d_descriptor, &byte, 1) != 1) {
		(void)close(descs[0].d_descriptor);
		door_return(__DECONST(char *, "WRITE-FAIL"),
			    sizeof("WRITE-FAIL"),
			    NULL,
			    0);
	}
	(void)close(descs[0].d_descriptor);
	door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

ATF_TC_WITHOUT_HEAD(fd_pipe);

ATF_TC_BODY(fd_pipe, tc)
{
	char byte;
	char reply[32];
	door_arg_t arg;
	door_desc_t desc;
	int door_fd;
	int pipe_fds[2];

	(void)tc;

	ATF_REQUIRE(pipe(pipe_fds) == 0);
	door_fd = test_create_door(pipe_writer_server);
	test_init_desc(&desc, pipe_fds[1], 0);
	test_init_call(&arg, reply, sizeof(reply));
	arg.desc_ptr = &desc;
	arg.desc_num = 1;

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_size == sizeof("OK"));
	ATF_REQUIRE(memcmp(arg.data_ptr, "OK", sizeof("OK")) == 0);
	ATF_REQUIRE(read(pipe_fds[0], &byte, 1) == 1);
	ATF_REQUIRE(byte == 'A');
	test_require_fd_valid(pipe_fds[1]);

	ATF_REQUIRE(close(pipe_fds[0]) == 0);
	ATF_REQUIRE(close(pipe_fds[1]) == 0);
	test_close_door(door_fd);
}

static const char client_to_server_data[] = "client-to-server descriptor\n";

static void
reader_server(void *cookie,
	      char *data,
	      size_t data_size,
	      door_desc_t *descs,
	      uint_t ndescs)
{
	char buffer[sizeof(client_to_server_data)];
	ssize_t bytes_read;

	(void)cookie;
	(void)data;
	(void)data_size;

	if (ndescs != 1 || descs == NULL ||
	    (descs[0].d_attributes & DOOR_DESCRIPTOR) == 0)
		door_return(
		    __DECONST(char *, "BAD-DESC"), sizeof("BAD-DESC"), NULL, 0);

	bytes_read = pread(descs[0].d_descriptor, buffer, sizeof(buffer), 0);
	(void)close(descs[0].d_descriptor);
	if (bytes_read != (ssize_t)sizeof(client_to_server_data) ||
	    memcmp(buffer, client_to_server_data, sizeof(buffer)) != 0)
		door_return(
		    __DECONST(char *, "BAD-DATA"), sizeof("BAD-DATA"), NULL, 0);

	door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

ATF_TC_WITHOUT_HEAD(fd_client_to_server);

ATF_TC_BODY(fd_client_to_server, tc)
{
	char path[] = "/tmp/libdoor-c2s.XXXXXX";
	char reply[32];
	door_arg_t arg;
	door_desc_t desc;
	int door_fd;
	int file_fd;

	(void)tc;

	file_fd = mkstemp(path);
	ATF_REQUIRE(file_fd != -1);
	ATF_REQUIRE(write(file_fd,
			  client_to_server_data,
			  sizeof(client_to_server_data)) ==
		    (ssize_t)sizeof(client_to_server_data));

	door_fd = test_create_door(reader_server);
	test_init_desc(&desc, file_fd, 0);
	test_init_call(&arg, reply, sizeof(reply));
	arg.desc_ptr = &desc;
	arg.desc_num = 1;

	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_size == sizeof("OK"));
	ATF_REQUIRE(memcmp(arg.data_ptr, "OK", sizeof("OK")) == 0);
	test_require_fd_valid(file_fd);

	ATF_REQUIRE(close(file_fd) == 0);
	test_close_door(door_fd);
	(void)unlink(path);
}

static char server_to_client_path[PATH_MAX];
static const char server_to_client_data[] = "server-to-client descriptor\n";

static void
sender_server(void *cookie,
	      char *data,
	      size_t data_size,
	      door_desc_t *descs,
	      uint_t ndescs)
{
	door_desc_t output;
	int fd;

	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	fd = open(server_to_client_path, O_RDONLY);
	if (fd == -1)
		door_return(__DECONST(char *, "OPEN-FAIL"),
			    sizeof("OPEN-FAIL"),
			    NULL,
			    0);

	test_init_desc(&output, fd, DOOR_RELEASE);
	door_return(NULL, 0, &output, 1);
}

ATF_TC_WITHOUT_HEAD(fd_server_to_client);

ATF_TC_BODY(fd_server_to_client, tc)
{
	char buffer[sizeof(server_to_client_data)];
	char path[] = "/tmp/libdoor-s2c.XXXXXX";
	char reply[8];
	door_arg_t arg;
	ssize_t bytes_read;
	int door_fd;
	int seed_fd;

	(void)tc;

	seed_fd = mkstemp(path);
	ATF_REQUIRE(seed_fd != -1);
	ATF_REQUIRE(write(seed_fd,
			  server_to_client_data,
			  sizeof(server_to_client_data)) ==
		    (ssize_t)sizeof(server_to_client_data));
	ATF_REQUIRE(close(seed_fd) == 0);
	(void)strlcpy(
	    server_to_client_path, path, sizeof(server_to_client_path));

	door_fd = test_create_door(sender_server);
	test_init_call(&arg, reply, sizeof(reply));
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.desc_num == 1);

	bytes_read = read(arg.desc_ptr[0].d_descriptor, buffer, sizeof(buffer));
	ATF_REQUIRE(bytes_read == (ssize_t)sizeof(server_to_client_data));
	ATF_REQUIRE(memcmp(buffer, server_to_client_data, sizeof(buffer)) == 0);

	test_close_received_descs(&arg);
	test_close_door(door_fd);
	(void)unlink(path);
}

static char secret_path[PATH_MAX];
static const char secret_data[] = "opened by privileged server\n";

static void
privileged_server(void *cookie,
		  char *data,
		  size_t data_size,
		  door_desc_t *descs,
		  uint_t ndescs)
{
	door_desc_t output;
	int fd;

	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	fd = open(secret_path, O_RDONLY);
	if (fd == -1)
		door_return(__DECONST(char *, "OPEN-FAIL"),
			    sizeof("OPEN-FAIL"),
			    NULL,
			    0);

	test_init_desc(&output, fd, DOOR_RELEASE);
	door_return(NULL, 0, &output, 1);
}

static int
run_unprivileged_client(const char *door_path, uid_t uid, gid_t gid)
{
	char buffer[sizeof(secret_data)];
	char reply[16];
	door_arg_t arg;
	ssize_t bytes_read;
	int door_fd;
	int file_fd;

	if (setgroups(0, NULL) == -1 || setgid(gid) == -1 || setuid(uid) == -1)
		return (10);

	errno = 0;
	file_fd = open(secret_path, O_RDONLY);
	if (file_fd != -1 || errno != EACCES)
		return (11);

	door_fd = open(door_path, O_RDWR);
	if (door_fd == -1)
		return (12);

	test_init_call(&arg, reply, sizeof(reply));
	if (door_call(door_fd, &arg) == -1 || arg.desc_num != 1)
		return (13);

	bytes_read = read(arg.desc_ptr[0].d_descriptor, buffer, sizeof(buffer));
	if (bytes_read != (ssize_t)sizeof(secret_data) ||
	    memcmp(buffer, secret_data, sizeof(buffer)) != 0)
		return (14);

	test_close_received_descs(&arg);
	(void)close(door_fd);
	return (0);
}

ATF_TC(fd_permissions);

ATF_TC_HEAD(fd_permissions, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(fd_permissions, tc)
{
	struct passwd *password;
	char door_path[] = "/tmp/libdoor-perm-door.XXXXXX";
	char path[] = "/tmp/libdoor-secret.XXXXXX";
	pid_t pid;
	int door_fd;
	int file_fd;
	int placeholder_fd;
	int status;

	(void)tc;

	password = getpwnam("nobody");
	if (password == NULL)
		atf_tc_skip("user nobody is not available");

	file_fd = mkstemp(path);
	ATF_REQUIRE(file_fd != -1);
	(void)strlcpy(secret_path, path, sizeof(secret_path));
	ATF_REQUIRE(write(file_fd, secret_data, sizeof(secret_data)) ==
		    (ssize_t)sizeof(secret_data));
	ATF_REQUIRE(fchmod(file_fd, 0600) == 0);
	ATF_REQUIRE(close(file_fd) == 0);

	placeholder_fd = mkstemp(door_path);
	ATF_REQUIRE(placeholder_fd != -1);
	ATF_REQUIRE(close(placeholder_fd) == 0);
	ATF_REQUIRE(chmod(door_path, 0666) == 0);

	door_fd = test_create_door(privileged_server);
	ATF_REQUIRE(fattach(door_fd, door_path) == 0);

	pid = fork();
	ATF_REQUIRE(pid != -1);
	if (pid == 0) {
		_exit(run_unprivileged_client(
		    door_path, password->pw_uid, password->pw_gid));
	}

	ATF_REQUIRE(waitpid(pid, &status, 0) == pid);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE(WEXITSTATUS(status) == 0);

	ATF_REQUIRE(fdetach(door_path) == 0);
	test_close_door(door_fd);
	(void)unlink(door_path);
	(void)unlink(secret_path);
}

static int independent_server_fd = -1;
static const char independent_data[] =
    "shared file object remains referenced\n";

enum independent_command {
	INDEPENDENT_GET_FD = 1,
	INDEPENDENT_VERIFY_FD = 2,
};

static void
independent_server(void *cookie,
		   char *data,
		   size_t data_size,
		   door_desc_t *descs,
		   uint_t ndescs)
{
	door_desc_t output;
	char byte;
	int command;

	(void)cookie;
	(void)descs;
	(void)ndescs;

	if (data_size != sizeof(command))
		door_return(
		    __DECONST(char *, "BAD-SIZE"), sizeof("BAD-SIZE"), NULL, 0);
	memcpy(&command, data, sizeof(command));

	switch (command) {
	case INDEPENDENT_GET_FD:
		test_init_desc(&output, independent_server_fd, 0);
		door_return(NULL, 0, &output, 1);
	case INDEPENDENT_VERIFY_FD:
		if (pread(independent_server_fd, &byte, 1, 0) == 1 &&
		    byte == independent_data[0])
			door_return(
			    __DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
		door_return(
		    __DECONST(char *, "CLOSED"), sizeof("CLOSED"), NULL, 0);
	default:
		door_return(
		    __DECONST(char *, "BAD-CMD"), sizeof("BAD-CMD"), NULL, 0);
	}
}

static void
call_independent_command(
    int door_fd, int command, char *reply, size_t reply_size, door_arg_t *arg)
{
	memset(arg, 0, sizeof(*arg));
	arg->data_ptr = (char *)&command;
	arg->data_size = sizeof(command);
	arg->rbuf = reply;
	arg->rsize = reply_size;
	ATF_REQUIRE(door_call(door_fd, arg) == 0);
}

ATF_TC_WITHOUT_HEAD(fd_independent_close);

ATF_TC_BODY(fd_independent_close, tc)
{
	char byte;
	char path[] = "/tmp/libdoor-independent.XXXXXX";
	char reply[32];
	door_arg_t arg;
	int door_fd;
	int received_fd;

	(void)tc;

	independent_server_fd = mkstemp(path);
	ATF_REQUIRE(independent_server_fd != -1);
	ATF_REQUIRE(write(independent_server_fd,
			  independent_data,
			  sizeof(independent_data)) ==
		    (ssize_t)sizeof(independent_data));
	door_fd = test_create_door(independent_server);

	call_independent_command(
	    door_fd, INDEPENDENT_GET_FD, reply, sizeof(reply), &arg);
	ATF_REQUIRE(arg.desc_num == 1);
	received_fd = arg.desc_ptr[0].d_descriptor;
	ATF_REQUIRE(pread(received_fd, &byte, 1, 0) == 1);
	ATF_REQUIRE(byte == independent_data[0]);
	ATF_REQUIRE(close(received_fd) == 0);
	free(arg.desc_ptr);
	arg.desc_ptr = NULL;

	call_independent_command(
	    door_fd, INDEPENDENT_VERIFY_FD, reply, sizeof(reply), &arg);
	ATF_REQUIRE(strcmp(reply, "OK") == 0);
	test_require_fd_valid(independent_server_fd);

	ATF_REQUIRE(close(independent_server_fd) == 0);
	independent_server_fd = -1;
	test_close_door(door_fd);
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(revoke);

ATF_TC_BODY(revoke, tc)
{
	static const int call_errors[] = {
	    EBADF,
	    ECANCELED,
	};
	char reply[8];
	door_arg_t arg;
	door_info_t info;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(null_server);
	ATF_REQUIRE(door_revoke(door_fd) == 0);
	ATF_REQUIRE(door_info(door_fd, &info) == 0);
	ATF_REQUIRE((info.di_attributes & DOOR_REVOKED) != 0);
	test_init_call(&arg, reply, sizeof(reply));
	TEST_REQUIRE_ERRNO_ONE_OF(door_call(door_fd, &arg), call_errors);
	test_close_door(door_fd);
}

struct credential_reply {
	uid_t euid;
	uid_t ruid;
	gid_t egid;
	gid_t rgid;
	pid_t pid;
};

static void
credential_server(void *cookie,
		  char *data,
		  size_t data_size,
		  door_desc_t *descs,
		  uint_t ndescs)
{
	door_cred_t credential;
	struct credential_reply reply;

	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	if (door_cred(&credential) == -1)
		door_return(__DECONST(char *, "CRED-FAIL"),
			    sizeof("CRED-FAIL"),
			    NULL,
			    0);

	reply.euid = credential.dc_euid;
	reply.ruid = credential.dc_ruid;
	reply.egid = credential.dc_egid;
	reply.rgid = credential.dc_rgid;
	reply.pid = credential.dc_pid;
	door_return((char *)&reply, sizeof(reply), NULL, 0);
}

ATF_TC_WITHOUT_HEAD(credentials);

ATF_TC_BODY(credentials, tc)
{
	struct credential_reply reply;
	door_arg_t arg;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(credential_server);
	memset(&arg, 0, sizeof(arg));
	arg.rbuf = (char *)&reply;
	arg.rsize = sizeof(reply);
	ATF_REQUIRE(door_call(door_fd, &arg) == 0);
	ATF_REQUIRE(arg.data_size == sizeof(reply));
	ATF_REQUIRE(reply.euid == geteuid());
	ATF_REQUIRE(reply.ruid == getuid());
	ATF_REQUIRE(reply.egid == getegid());
	ATF_REQUIRE(reply.rgid == getgid());
	ATF_REQUIRE(reply.pid == getpid());
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(parameters);

ATF_TC_BODY(parameters, tc)
{
	size_t data_max;
	size_t data_min;
	size_t desc_max;
	size_t value;
	int door_fd;

	(void)tc;

	door_fd = test_create_door(null_server);
	ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DATA_MIN, &data_min) ==
		    0);
#if SIZE_MAX < UINT64_MAX
    {
        struct door_ioc_param raw;
        memset(&raw, 0, sizeof(raw));
        raw.dip_version = DOOR_ABI_VERSION;
        raw.dip_type = DOOR_PARAM_DATA_MAX;
        ATF_REQUIRE((long)__syscall((quad_t)SYS_door, DOOR_SC_GETPARAM,
            (long)door_fd, (long)(uintptr_t)&raw, 0L, 0L, 0L) == 0);
        if (raw.dip_value > SIZE_MAX) {
            data_max = 123;
            ATF_REQUIRE_ERRNO(EOVERFLOW,
                door_getparam(door_fd, DOOR_PARAM_DATA_MAX, &data_max) == -1);
            ATF_REQUIRE_EQ(data_max, 123U); /* No silent truncation or write. */
            /* Bound for the following caller-size comparison, not kernel policy. */
            data_max = SIZE_MAX;
        } else {
            ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DATA_MAX,
                &data_max) == 0);
            ATF_REQUIRE_EQ(data_max, raw.dip_value);
        }
    }
#else
	ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DATA_MAX, &data_max) ==
		    0);
#endif
	ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DESC_MAX, &desc_max) ==
		    0);
	ATF_REQUIRE(data_min <= data_max);
	ATF_REQUIRE(data_max > 0);
	ATF_REQUIRE(desc_max > 0);

	ATF_REQUIRE(door_setparam(door_fd, DOOR_PARAM_DATA_MAX, 65536) == 0);
	ATF_REQUIRE(door_setparam(door_fd, DOOR_PARAM_DATA_MIN, 16) == 0);
	ATF_REQUIRE(door_setparam(door_fd, DOOR_PARAM_DESC_MAX, 8) == 0);
	ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DATA_MAX, &value) == 0);
	ATF_REQUIRE(value == 65536);
	ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DATA_MIN, &value) == 0);
	ATF_REQUIRE(value == 16);
	ATF_REQUIRE(door_getparam(door_fd, DOOR_PARAM_DESC_MAX, &value) == 0);
	ATF_REQUIRE(value == 8);
	ATF_REQUIRE_ERRNO(EINVAL,
			  door_setparam(door_fd, DOOR_PARAM_DATA_MAX, 8) == -1);

	test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, create_info);
	ATF_TP_ADD_TC(tp, echo_call);
	ATF_TP_ADD_TC(tp, null_argument_call);
	ATF_TP_ADD_TC(tp, multiple_calls);
	ATF_TP_ADD_TC(tp, fd_pipe);
	ATF_TP_ADD_TC(tp, fd_client_to_server);
	ATF_TP_ADD_TC(tp, fd_server_to_client);
	ATF_TP_ADD_TC(tp, fd_permissions);
	ATF_TP_ADD_TC(tp, fd_independent_close);
	ATF_TP_ADD_TC(tp, revoke);
	ATF_TP_ADD_TC(tp, credentials);
	ATF_TP_ADD_TC(tp, parameters);

	return (atf_no_error());
}
