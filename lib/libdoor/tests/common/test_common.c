/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

void
test_close_received_descs(door_arg_t *arg)
{
	uint_t i;

	if (arg == NULL || arg->desc_ptr == NULL)
		return;

	for (i = 0; i < arg->desc_num; i++) {
		if ((arg->desc_ptr[i].d_attributes & DOOR_DESCRIPTOR) == 0)
			continue;
		if (arg->desc_ptr[i].d_descriptor < 0)
			continue;
		(void)close(arg->desc_ptr[i].d_descriptor);
	}

	free(arg->desc_ptr);
	arg->desc_ptr = NULL;
	arg->desc_num = 0;
}

bool
test_fd_valid(int fd)
{
	int error;

	errno = 0;
	if (fcntl(fd, F_GETFD) != -1)
		return (true);

	error = errno;
	return (error != EBADF);
}

void
test_require_fd_valid(int fd)
{
	ATF_REQUIRE_MSG(
	    test_fd_valid(fd), "descriptor %d was unexpectedly closed", fd);
}

void
test_require_errno_one_of(int result,
			  int actual,
			  const int *errors,
			  size_t nerrors,
			  const char *expression)
{
	size_t i;

	ATF_REQUIRE_MSG(result == -1, "%s unexpectedly succeeded", expression);

	for (i = 0; i < nerrors; i++) {
		if (actual == errors[i])
			return;
	}

	atf_tc_fail("%s returned unexpected errno %d (%s)",
		    expression,
		    actual,
		    strerror(actual));
}

int
test_make_regular_fd(void)
{
	char path[] = "/tmp/libdoor-test.XXXXXX";
	int fd;

	fd = mkstemp(path);
	if (fd != -1)
		(void)unlink(path);
	return (fd);
}

int
test_make_socket_fd(void)
{
	return (socket(AF_UNIX, SOCK_STREAM, 0));
}

int
test_create_door(door_server_procedure_t *procedure)
{
	int fd;

	fd = door_create(procedure, NULL, 0);
	ATF_REQUIRE_MSG(fd != -1, "door_create failed: %s", strerror(errno));
	return (fd);
}

void
test_close_door(int fd)
{
	/* close is not revoke/join. Publications and private SHM fds may keep
	 * workers alive; fixtures/mappings need their own completion barrier. */
	if (fd < 0)
		return;
	ATF_REQUIRE_MSG(
	    close(fd) == 0, "close(%d) failed: %s", fd, strerror(errno));
}

void
test_init_desc(door_desc_t *desc, int fd, door_attr_t attributes)
{
	memset(desc, 0, sizeof(*desc));
	desc->d_attributes = DOOR_DESCRIPTOR | attributes;
	desc->d_descriptor = fd;
}

void
test_init_call(door_arg_t *arg, char *reply, size_t reply_size)
{
	memset(arg, 0, sizeof(*arg));
	arg->rbuf = reply;
	arg->rsize = reply_size;
}

int
test_guarded_region_create(struct test_guarded_region *region)
{
	long page_size;
	int error;

	memset(region, 0, sizeof(*region));
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0) {
		errno = EINVAL;
		return (-1);
	}

	region->page_size = (size_t)page_size;
	region->mapping_size = region->page_size * 2;
	region->mapping = mmap(NULL,
			       region->mapping_size,
			       PROT_READ | PROT_WRITE,
			       MAP_ANON | MAP_PRIVATE,
			       -1,
			       0);
	if (region->mapping == MAP_FAILED) {
		region->mapping = NULL;
		return (-1);
	}

	region->guard = (char *)region->mapping + region->page_size;
	if (mprotect(region->guard, region->page_size, PROT_NONE) == 0)
		return (0);

	error = errno;
	(void)munmap(region->mapping, region->mapping_size);
	memset(region, 0, sizeof(*region));
	errno = error;
	return (-1);
}

void
test_guarded_region_destroy(struct test_guarded_region *region)
{
	if (region->mapping != NULL)
		(void)munmap(region->mapping, region->mapping_size);
	memset(region, 0, sizeof(*region));
}

int
test_run_child(test_child_fn function,
	       void *argument,
	       int *exit_code,
	       int *signal_number)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid == -1)
		return (-1);

	if (pid == 0) {
		alarm(TEST_TIMEOUT_SECONDS);
		_exit(function(argument) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	while (waitpid(pid, &status, 0) == -1) {
		if (errno != EINTR)
			return (-1);
	}

	*exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	*signal_number = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
	return (0);
}
