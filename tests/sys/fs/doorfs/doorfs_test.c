/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <door.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void
echo_server(void *cookie, char *data, size_t size, door_desc_t *descs,
    uint_t ndescs)
{
	(void)cookie;
	(void)descs;
	(void)ndescs;
	door_return(data, size, NULL, 0);
}

static int
call_echo(int fd)
{
	char request[] = "doorfs-file";
	char reply[sizeof(request)];
	door_arg_t arg;

	memset(&arg, 0, sizeof(arg));
	arg.data_ptr = request;
	arg.data_size = sizeof(request);
	arg.rbuf = reply;
	arg.rsize = sizeof(reply);
	if (door_call(fd, &arg) == -1)
		return (-1);
	if (arg.data_size != sizeof(request) ||
	    memcmp(reply, request, sizeof(request)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

ATF_TC_WITHOUT_HEAD(file_stat);
ATF_TC_BODY(file_stat, tc)
{
	struct stat sb;
	int fd;

	(void)tc;
	fd = door_create(echo_server, NULL, 0);
	ATF_REQUIRE_MSG(fd != -1, "door_create: %s", strerror(errno));
	ATF_REQUIRE(fstat(fd, &sb) == 0);
	ATF_REQUIRE(S_ISREG(sb.st_mode));
	ATF_REQUIRE_EQ(0600, sb.st_mode & ALLPERMS);
	ATF_REQUIRE_EQ(1, sb.st_nlink);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(non_stream_io_rejected);
ATF_TC_BODY(non_stream_io_rejected, tc)
{
	char byte;
	int fd;

	(void)tc;
	fd = door_create(echo_server, NULL, 0);
	ATF_REQUIRE(fd != -1);
	errno = 0;
	ATF_REQUIRE(read(fd, &byte, 1) == -1);
	ATF_REQUIRE(errno != 0);
	errno = 0;
	ATF_REQUIRE(write(fd, &byte, 1) == -1);
	ATF_REQUIRE(errno != 0);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(duplicate_holds_file);
ATF_TC_BODY(duplicate_holds_file, tc)
{
	int copy, fd;

	(void)tc;
	fd = door_create(echo_server, NULL, 0);
	ATF_REQUIRE(fd != -1);
	copy = dup(fd);
	ATF_REQUIRE(copy != -1);
	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE_MSG(call_echo(copy) == 0, "door_call: %s",
	    strerror(errno));
	ATF_REQUIRE(close(copy) == 0);
}

ATF_TC_WITHOUT_HEAD(revoke_visible_to_duplicate);
ATF_TC_BODY(revoke_visible_to_duplicate, tc)
{
	int copy, fd;

	(void)tc;
	fd = door_create(echo_server, NULL, 0);
	ATF_REQUIRE(fd != -1);
	copy = dup(fd);
	ATF_REQUIRE(copy != -1);
	ATF_REQUIRE(door_revoke(fd) == 0);
	errno = 0;
	ATF_REQUIRE(call_echo(copy) == -1);
	/* Revoke finished before CALL; no cancellation race remains. */
	ATF_REQUIRE(errno == EBADF);
	ATF_REQUIRE(close(copy) == 0);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(inherited_file_capability);
ATF_TC_BODY(inherited_file_capability, tc)
{
	pid_t child;
	int fd, status;

	(void)tc;
	fd = door_create(echo_server, NULL, 0);
	ATF_REQUIRE(fd != -1);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0)
		_exit(call_echo(fd) == 0 ? 0 : 1);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, file_stat);
	ATF_TP_ADD_TC(tp, non_stream_io_rejected);
	ATF_TP_ADD_TC(tp, duplicate_holds_file);
	ATF_TP_ADD_TC(tp, revoke_visible_to_duplicate);
	ATF_TP_ADD_TC(tp, inherited_file_capability);
	return (atf_no_error());
}
