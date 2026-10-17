/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
parse_fd(const char *s)
{
	char *e;
	long v;
	errno = 0;
	v = strtol(s, &e, 10);
	return (errno || !*s || *e || v < 0 || v > INT_MAX) ? -1 : (int)v;
}

static int
call_echo(int fd)
{
	static const char req[] = "fork-exec";
	char rep[sizeof(req)];
	door_arg_t a;
	memset(&a, 0, sizeof(a));
	a.data_ptr = (char *)(uintptr_t)req;
	a.data_size = sizeof(req);
	a.rbuf = rep;
	a.rsize = sizeof(rep);
	if (door_call(fd, &a) == -1)
		return 1;
	return a.data_size == sizeof(req) &&
		       memcmp(a.data_ptr, req, sizeof(req)) == 0
		 ? 0
		 : 2;
}

static int
call_success(int fd)
{
	static const char req[] = "fork-exec";
	char rep[32];
	door_arg_t a;
	memset(&a, 0, sizeof(a));
	a.data_ptr = (char *)(uintptr_t)req;
	a.data_size = sizeof(req);
	a.rbuf = rep;
	a.rsize = sizeof(rep);
	return door_call(fd, &a) == 0 ? 0 : 1;
}

static int
call_revoked(int fd)
{
	static const char req[] = "revoked";
	char rep[16];
	door_arg_t a;
	memset(&a, 0, sizeof(a));
	a.data_ptr = (char *)(uintptr_t)req;
	a.data_size = sizeof(req);
	a.rbuf = rep;
	a.rsize = sizeof(rep);
	errno = 0;
	return door_call(fd, &a) == -1 && (errno == EBADF || errno == ENXIO)
		 ? 0
		 : 1;
}

static void
echo(void *c, char *d, size_t n, door_desc_t *x, uint_t nx)
{
	(void)c;
	(void)x;
	(void)nx;
	door_return(d, n, NULL, 0);
}

static int
create_own(void)
{
	int fd = door_create(echo, NULL, 0);
	int r;
	if (fd == -1)
		return 1;
	r = call_echo(fd);
	if (door_revoke(fd) == -1 && r == 0)
		r = 2;
	if (close(fd) == -1 && r == 0)
		r = 3;
	return r;
}

int
main(int argc, char **argv)
{
	door_info_t i;
	int fd;
	if (argc == 2 && strcmp(argv[1], "create-own") == 0)
		return create_own();
	if (argc != 3 || (fd = parse_fd(argv[2])) == -1)
		return 64;
	if (!strcmp(argv[1], "call"))
		return call_echo(fd);
	if (!strcmp(argv[1], "call-success"))
		return call_success(fd);
	if (!strcmp(argv[1], "info"))
		return door_info(fd, &i) == 0 ? 0 : 1;
	if (!strcmp(argv[1], "closed")) {
		errno = 0;
		return fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 1;
	}
	if (!strcmp(argv[1], "close"))
		return close(fd) == 0 ? 0 : 1;
	if (!strcmp(argv[1], "revoked"))
		return call_revoked(fd);
	return 65;
}
