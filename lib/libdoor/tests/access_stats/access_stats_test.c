/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

static char protected_path[PATH_MAX];
static int protected_open_flags;
static struct stat protected_server_stat;

static const char protected_data[] = "server-opened protected descriptor\n";
static const char client_write_data[] = "written through transferred fd\n";

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
	door_return(__DECONST(char *, "OK"), sizeof("OK"), NULL, 0);
}

static void
protected_fd_server(void *cookie,
		    char *data,
		    size_t data_size,
		    door_desc_t *descs,
		    uint_t ndescs)
{
	door_desc_t output;
	struct stat opened_stat;
	int fd;

	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	fd = open(protected_path, protected_open_flags);
	if (fd == -1)
		door_return(__DECONST(char *, "OPEN"), sizeof("OPEN"), NULL, 0);
	if (fstat(fd, &opened_stat) == -1) {
		(void)close(fd);
		door_return(__DECONST(char *, "STAT"), sizeof("STAT"), NULL, 0);
	}
	test_init_desc(&output, fd, DOOR_RELEASE);
	door_return(NULL, 0, &output, 1);
}

static int
become_user(uid_t uid, gid_t gid)
{
	if (setgroups(0, NULL) == -1)
		return (-1);
	if (setgid(gid) == -1 || setuid(uid) == -1)
		return (-1);
	return (0);
}

static int
call_attached_door(const char *path)
{
	char reply[16];
	door_arg_t arg;
	int fd;

	fd = open(path, O_RDWR);
	if (fd == -1)
		return (-1);
	test_init_call(&arg, reply, sizeof(reply));
	if (door_call(fd, &arg) == -1) {
		(void)close(fd);
		return (-1);
	}
	if (arg.data_size != sizeof("OK") ||
	    memcmp(arg.data_ptr, "OK", sizeof("OK")) != 0) {
		(void)close(fd);
		errno = EPROTO;
		return (-1);
	}
	return (close(fd));
}

static void
make_mountpoint(char *path, size_t path_size, mode_t mode)
{
	char template[] = "/tmp/libdoor-access.XXXXXX";
	int fd;

	fd = mkstemp(template);
	ATF_REQUIRE(fd != -1);
	ATF_REQUIRE(fchmod(fd, mode) == 0);
	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE(strlcpy(path, template, path_size) < path_size);
}

static struct passwd *
require_unprivileged_user(void)
{
	struct passwd *pw;

	pw = getpwnam("nobody");
	if (pw == NULL)
		atf_tc_skip("user nobody is not available");
	return (pw);
}

ATF_TC(attached_stat_and_fstat);

ATF_TC_HEAD(attached_stat_and_fstat, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(attached_stat_and_fstat, tc)
{
	char path[PATH_MAX];
	door_info_t info;
	struct stat before, after, opened;
	int door_fd, path_fd;

	(void)tc;
	make_mountpoint(path, sizeof(path), 0640);
	ATF_REQUIRE(stat(path, &before) == 0);
	door_fd = test_create_door(null_server);
	ATF_REQUIRE(fattach(door_fd, path) == 0);

	ATF_REQUIRE_MSG(stat(path, &after) == 0, "stat: %s", strerror(errno));
	ATF_REQUIRE(S_ISREG(after.st_mode));
	ATF_REQUIRE(after.st_uid == before.st_uid);
	ATF_REQUIRE(after.st_gid == before.st_gid);
	ATF_REQUIRE((after.st_mode & ALLPERMS) == (before.st_mode & ALLPERMS));
	ATF_REQUIRE(after.st_nlink >= 1);

	path_fd = open(path, O_RDONLY);
	ATF_REQUIRE_MSG(path_fd != -1, "open: %s", strerror(errno));
	ATF_REQUIRE(fstat(path_fd, &opened) == 0);
	ATF_REQUIRE(S_ISREG(opened.st_mode));
	ATF_REQUIRE((opened.st_mode & ALLPERMS) == 0600);
	ATF_REQUIRE(opened.st_nlink == 1);
	ATF_REQUIRE(door_info(path_fd, &info) == 0);
	ATF_REQUIRE(close(path_fd) == 0);

	ATF_REQUIRE(fdetach(path) == 0);
	test_close_door(door_fd);
	ATF_REQUIRE(unlink(path) == 0);
}

ATF_TC(denied_mountpoint_cannot_be_opened);

ATF_TC_HEAD(denied_mountpoint_cannot_be_opened, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(denied_mountpoint_cannot_be_opened, tc)
{
	struct passwd *pw;
	char path[PATH_MAX];
	pid_t child;
	int door_fd, status;

	(void)tc;
	pw = require_unprivileged_user();
	make_mountpoint(path, sizeof(path), 0600);
	door_fd = test_create_door(null_server);
	ATF_REQUIRE(fattach(door_fd, path) == 0);

	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		if (become_user(pw->pw_uid, pw->pw_gid) == -1)
			_exit(10);
		errno = 0;
		if (access(path, R_OK | W_OK) != -1 || errno != EACCES)
			_exit(11);
		errno = 0;
		if (open(path, O_RDONLY) != -1 || errno != EACCES)
			_exit(12);
		errno = 0;
		if (open(path, O_RDWR) != -1 || errno != EACCES)
			_exit(13);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
			"unprivileged child failed at step %d",
			WEXITSTATUS(status));

	ATF_REQUIRE(fdetach(path) == 0);
	test_close_door(door_fd);
	ATF_REQUIRE(unlink(path) == 0);
}

ATF_TC(allowed_mountpoint_can_call);

ATF_TC_HEAD(allowed_mountpoint_can_call, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(allowed_mountpoint_can_call, tc)
{
	struct passwd *pw;
	char path[PATH_MAX];
	pid_t child;
	int door_fd, status;

	(void)tc;
	pw = require_unprivileged_user();
	make_mountpoint(path, sizeof(path), 0666);
	door_fd = test_create_door(null_server);
	ATF_REQUIRE(fattach(door_fd, path) == 0);

	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		if (become_user(pw->pw_uid, pw->pw_gid) == -1)
			_exit(10);
		if (access(path, R_OK | W_OK) == -1)
			_exit(11);
		if (call_attached_door(path) == -1)
			_exit(12);
		_exit(0);
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
			"unprivileged child failed at step %d",
			WEXITSTATUS(status));

	ATF_REQUIRE(fdetach(path) == 0);
	test_close_door(door_fd);
	ATF_REQUIRE(unlink(path) == 0);
}

static int
unprivileged_read_client(const char *door_path, uid_t uid, gid_t gid)
{
	char buffer[sizeof(protected_data)];
	char reply[16];
	struct stat received_stat;
	door_arg_t arg;
	int door_fd, received_fd;

	if (become_user(uid, gid) == -1)
		return (10);
	errno = 0;
	if (access(protected_path, R_OK) != -1 || errno != EACCES)
		return (11);
	errno = 0;
	if (open(protected_path, O_RDONLY) != -1 || errno != EACCES)
		return (12);
	if ((door_fd = open(door_path, O_RDWR)) == -1)
		return (13);
	test_init_call(&arg, reply, sizeof(reply));
	if (door_call(door_fd, &arg) == -1 || arg.desc_num != 1)
		return (14);
	received_fd = arg.desc_ptr[0].d_descriptor;
	if (fstat(received_fd, &received_stat) == -1)
		return (15);
	if (received_stat.st_dev != protected_server_stat.st_dev ||
	    received_stat.st_ino != protected_server_stat.st_ino ||
	    received_stat.st_size != protected_server_stat.st_size ||
	    received_stat.st_uid != protected_server_stat.st_uid ||
	    received_stat.st_gid != protected_server_stat.st_gid ||
	    received_stat.st_mode != protected_server_stat.st_mode)
		return (16);
	if (pread(received_fd, buffer, sizeof(buffer), 0) !=
		(ssize_t)sizeof(buffer) ||
	    memcmp(buffer, protected_data, sizeof(buffer)) != 0)
		return (17);
	errno = 0;
	if (write(received_fd, "x", 1) != -1 || errno != EBADF)
		return (18);
	test_close_received_descs(&arg);
	(void)close(door_fd);
	return (0);
}

ATF_TC(transferred_read_fd_works_without_path_access);

ATF_TC_HEAD(transferred_read_fd_works_without_path_access, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(transferred_read_fd_works_without_path_access, tc)
{
	struct passwd *pw;
	char door_path[PATH_MAX];
	char file_template[] = "/tmp/libdoor-protected.XXXXXX";
	pid_t child;
	int door_fd, file_fd, status;

	(void)tc;
	pw = require_unprivileged_user();
	file_fd = mkstemp(file_template);
	ATF_REQUIRE(file_fd != -1);
	ATF_REQUIRE(write(file_fd, protected_data, sizeof(protected_data)) ==
		    (ssize_t)sizeof(protected_data));
	ATF_REQUIRE(fchmod(file_fd, 0600) == 0);
	ATF_REQUIRE(fstat(file_fd, &protected_server_stat) == 0);
	ATF_REQUIRE(close(file_fd) == 0);
	ATF_REQUIRE(strlcpy(protected_path,
			    file_template,
			    sizeof(protected_path)) < sizeof(protected_path));
	protected_open_flags = O_RDONLY;

	make_mountpoint(door_path, sizeof(door_path), 0666);
	door_fd = test_create_door(protected_fd_server);
	ATF_REQUIRE(fattach(door_fd, door_path) == 0);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0)
		_exit(unprivileged_read_client(
		    door_path, pw->pw_uid, pw->pw_gid));
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
			"unprivileged read client failed at step %d",
			WEXITSTATUS(status));

	ATF_REQUIRE(fdetach(door_path) == 0);
	test_close_door(door_fd);
	ATF_REQUIRE(unlink(door_path) == 0);
	ATF_REQUIRE(unlink(protected_path) == 0);
}

static int
unprivileged_write_client(const char *door_path, uid_t uid, gid_t gid)
{
	char reply[16];
	door_arg_t arg;
	int door_fd, received_fd;

	if (become_user(uid, gid) == -1)
		return (10);
	errno = 0;
	if (access(protected_path, W_OK) != -1 || errno != EACCES)
		return (11);
	errno = 0;
	if (open(protected_path, O_WRONLY) != -1 || errno != EACCES)
		return (12);
	if ((door_fd = open(door_path, O_RDWR)) == -1)
		return (13);
	test_init_call(&arg, reply, sizeof(reply));
	if (door_call(door_fd, &arg) == -1 || arg.desc_num != 1)
		return (14);
	received_fd = arg.desc_ptr[0].d_descriptor;
	if (write(received_fd, client_write_data, sizeof(client_write_data)) !=
	    (ssize_t)sizeof(client_write_data))
		return (15);
	errno = 0;
	if (read(received_fd, reply, 1) != -1 || errno != EBADF)
		return (16);
	test_close_received_descs(&arg);
	(void)close(door_fd);
	return (0);
}

ATF_TC(transferred_write_fd_works_without_path_access);

ATF_TC_HEAD(transferred_write_fd_works_without_path_access, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(transferred_write_fd_works_without_path_access, tc)
{
	struct passwd *pw;
	char door_path[PATH_MAX];
	char file_template[] = "/tmp/libdoor-protected-write.XXXXXX";
	char verify[sizeof(client_write_data)];
	pid_t child;
	int door_fd, file_fd, status;

	(void)tc;
	pw = require_unprivileged_user();
	file_fd = mkstemp(file_template);
	ATF_REQUIRE(file_fd != -1);
	ATF_REQUIRE(fchmod(file_fd, 0600) == 0);
	ATF_REQUIRE(close(file_fd) == 0);
	ATF_REQUIRE(strlcpy(protected_path,
			    file_template,
			    sizeof(protected_path)) < sizeof(protected_path));
	protected_open_flags = O_WRONLY | O_TRUNC;

	make_mountpoint(door_path, sizeof(door_path), 0666);
	door_fd = test_create_door(protected_fd_server);
	ATF_REQUIRE(fattach(door_fd, door_path) == 0);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0)
		_exit(unprivileged_write_client(
		    door_path, pw->pw_uid, pw->pw_gid));
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
			"unprivileged write client failed at step %d",
			WEXITSTATUS(status));

	file_fd = open(protected_path, O_RDONLY);
	ATF_REQUIRE(file_fd != -1);
	ATF_REQUIRE(read(file_fd, verify, sizeof(verify)) ==
		    (ssize_t)sizeof(verify));
	ATF_REQUIRE(memcmp(verify, client_write_data, sizeof(verify)) == 0);
	ATF_REQUIRE(close(file_fd) == 0);

	ATF_REQUIRE(fdetach(door_path) == 0);
	test_close_door(door_fd);
	ATF_REQUIRE(unlink(door_path) == 0);
	ATF_REQUIRE(unlink(protected_path) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, attached_stat_and_fstat);
	ATF_TP_ADD_TC(tp, denied_mountpoint_cannot_be_opened);
	ATF_TP_ADD_TC(tp, allowed_mountpoint_can_call);
	ATF_TP_ADD_TC(tp, transferred_read_fd_works_without_path_access);
	ATF_TP_ADD_TC(tp, transferred_write_fd_works_without_path_access);
	return (atf_no_error());
}
