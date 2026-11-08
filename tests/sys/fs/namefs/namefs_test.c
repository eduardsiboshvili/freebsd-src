/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <door.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
marker_server(void *cookie, char *data, size_t size, door_desc_t *descs,
    uint_t ndescs)
{
	const char *marker;

	(void)data;
	(void)size;
	(void)descs;
	(void)ndescs;
	marker = cookie;
	door_return(__DECONST(char *, marker), strlen(marker) + 1, NULL, 0);
}

static int
call_expect(int fd, const char *expected)
{
	char reply[64];
	door_arg_t arg;

	memset(&arg, 0, sizeof(arg));
	arg.rbuf = reply;
	arg.rsize = sizeof(reply);
	if (door_call(fd, &arg) == -1)
		return (-1);
	if (arg.data_size != strlen(expected) + 1 ||
	    strcmp(reply, expected) != 0) {
		errno = EPROTO;
		return (-1);
	}
	return (0);
}

static void
make_directory(char *path, size_t size, const char *tag)
{
	ATF_REQUIRE(strlcpy(path, tag, size) < size);
	ATF_REQUIRE_MSG(mkdir(path, 0700) == 0, "mkdir(%s): %s", path,
	    strerror(errno));
}

static void
make_placeholder(const char *directory, char *path, size_t size)
{
	int fd;

	ATF_REQUIRE(snprintf(path, size, "%s/door", directory) > 0);
	fd = open(path, O_CREAT | O_RDWR | O_EXCL, 0600);
	ATF_REQUIRE_MSG(fd != -1, "open(%s): %s", path, strerror(errno));
	ATF_REQUIRE(close(fd) == 0);
}

static int
mount_nullfs(const char *source, const char *target)
{
	struct iovec iov[6];

	iov[0].iov_base = __DECONST(char *, "fstype");
	iov[0].iov_len = sizeof("fstype");
	iov[1].iov_base = __DECONST(char *, "nullfs");
	iov[1].iov_len = sizeof("nullfs");
	iov[2].iov_base = __DECONST(char *, "fspath");
	iov[2].iov_len = sizeof("fspath");
	iov[3].iov_base = __DECONST(char *, target);
	iov[3].iov_len = strlen(target) + 1;
	iov[4].iov_base = __DECONST(char *, "target");
	iov[4].iov_len = sizeof("target");
	iov[5].iov_base = __DECONST(char *, source);
	iov[5].iov_len = strlen(source) + 1;
	return (nmount(iov, nitems(iov), 0));
}

static int
enter_jail(void)
{
	struct jail jail_spec;
	static char root[] = "/";
	static char hostname[] = "namefs-test";
	char jailname[64];

	(void)snprintf(jailname, sizeof(jailname), "namefs-test-%ld",
	    (long)getpid());
	memset(&jail_spec, 0, sizeof(jail_spec));
	jail_spec.version = JAIL_API_VERSION;
	jail_spec.path = root;
	jail_spec.hostname = hostname;
	jail_spec.jailname = jailname;
	return (jail(&jail_spec));
}

static void
cleanup_path(const char *path, const char *directory)
{
	(void)fdetach(path);
	(void)unlink(path);
	(void)rmdir(directory);
}

static void
cleanup_directory(const char *directory)
{
	char path[PATH_MAX];

	(void)snprintf(path, sizeof(path), "%s/door", directory);
	(void)fdetach(path);
	(void)unmount(directory, MNT_FORCE);
	(void)unlink(path);
	(void)rmdir(directory);
}

ATF_TC_WITH_CLEANUP(basic_publish);
ATF_TC_HEAD(basic_publish, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(basic_publish, tc)
{
	struct statfs sfs;
	char directory[PATH_MAX], path[PATH_MAX];
	int client, server;

	(void)tc;
	make_directory(directory, sizeof(directory), "basic");
	make_placeholder(directory, path, sizeof(path));
	server = door_create(marker_server, __DECONST(char *, "basic"), 0);
	ATF_REQUIRE(server != -1);
	ATF_REQUIRE(fattach(server, path) == 0);
	ATF_REQUIRE(statfs(path, &sfs) == 0);
	ATF_REQUIRE_STREQ("namefs", sfs.f_fstypename);
	client = open(path, O_RDWR);
	ATF_REQUIRE(client != -1);
	ATF_REQUIRE(call_expect(client, "basic") == 0);
	ATF_REQUIRE(close(client) == 0);
	ATF_REQUIRE(fdetach(path) == 0);
	ATF_REQUIRE(close(server) == 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(rmdir(directory) == 0);
}
ATF_TC_CLEANUP(basic_publish, tc)
{
	(void)tc;
	cleanup_directory("basic");
}

ATF_TC_WITH_CLEANUP(rebind_preserves_open_generation);
ATF_TC_HEAD(rebind_preserves_open_generation, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(rebind_preserves_open_generation, tc)
{
	char directory[PATH_MAX], path[PATH_MAX];
	int first, new_client, old_client, second;

	(void)tc;
	make_directory(directory, sizeof(directory), "rebind");
	make_placeholder(directory, path, sizeof(path));
	first = door_create(marker_server, __DECONST(char *, "first"), 0);
	second = door_create(marker_server, __DECONST(char *, "second"), 0);
	ATF_REQUIRE(first != -1 && second != -1);
	ATF_REQUIRE(fattach(first, path) == 0);
	old_client = open(path, O_RDWR);
	ATF_REQUIRE(old_client != -1);
	ATF_REQUIRE(fattach(second, path) == 0);
	new_client = open(path, O_RDWR);
	ATF_REQUIRE(new_client != -1);
	ATF_REQUIRE(call_expect(old_client, "first") == 0);
	ATF_REQUIRE(call_expect(new_client, "second") == 0);
	ATF_REQUIRE(close(old_client) == 0);
	ATF_REQUIRE(close(new_client) == 0);
	ATF_REQUIRE(fdetach(path) == 0);
	ATF_REQUIRE(close(first) == 0);
	ATF_REQUIRE(close(second) == 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(rmdir(directory) == 0);
}
ATF_TC_CLEANUP(rebind_preserves_open_generation, tc)
{
	(void)tc;
	cleanup_directory("rebind");
}

ATF_TC_WITH_CLEANUP(owner_exit_recovery_rebind);
ATF_TC_HEAD(owner_exit_recovery_rebind, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(owner_exit_recovery_rebind, tc)
{
	char byte, directory[PATH_MAX], path[PATH_MAX];
	pid_t child;
	int anchor, client, control[2], ready[2], replacement, status;

	(void)tc;
	make_directory(directory, sizeof(directory), "recovery");
	make_placeholder(directory, path, sizeof(path));
	ATF_REQUIRE(pipe(ready) == 0);
	ATF_REQUIRE(pipe(control) == 0);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0) {
		int server;

		(void)close(ready[0]);
		(void)close(control[1]);
		server = door_create(marker_server,
		    __DECONST(char *, "departed"), 0);
		if (server == -1 || fattach(server, path) == -1 ||
		    write(ready[1], "R", 1) != 1 ||
		    read(control[0], &byte, 1) != 1)
			_exit(20);
		_exit(0);
	}
	ATF_REQUIRE(close(ready[1]) == 0);
	ATF_REQUIRE(close(control[0]) == 0);
	ATF_REQUIRE(read(ready[0], &byte, 1) == 1);
	client = open(path, O_RDWR);
	ATF_REQUIRE(client != -1);
	anchor = open(path, O_PATH);
	ATF_REQUIRE_MSG(anchor != -1, "O_PATH recovery anchor: %s",
	    strerror(errno));
	ATF_REQUIRE(write(control[1], "X", 1) == 1);
	ATF_REQUIRE(close(control[1]) == 0);
	ATF_REQUIRE(close(ready[0]) == 0);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
	/* Revoked Door may give EBADF before delayed GC enters RECOVERY/ENXIO.
	 * The O_PATH anchor keeps the publication available for rebind. */
	errno = 0;
	status = open(path, O_RDWR);
	ATF_REQUIRE_MSG(status == -1,
	    "open of ownerless publication unexpectedly succeeded");
	ATF_REQUIRE_MSG(errno == EBADF || errno == ENXIO,
	    "open of ownerless publication: %s", strerror(errno));

	replacement = door_create(marker_server,
	    __DECONST(char *, "replacement"), 0);
	ATF_REQUIRE(replacement != -1);
	ATF_REQUIRE_MSG(fattach(replacement, path) == 0,
	    "rebind after owner exit: %s", strerror(errno));
	ATF_REQUIRE(close(anchor) == 0);
	errno = 0;
	ATF_REQUIRE(call_expect(client, "departed") == -1);
	ATF_REQUIRE(errno == EBADF || errno == ECANCELED || errno == ENXIO);
	ATF_REQUIRE(close(client) == 0);
	client = open(path, O_RDWR);
	ATF_REQUIRE(client != -1);
	ATF_REQUIRE(call_expect(client, "replacement") == 0);
	ATF_REQUIRE(close(client) == 0);
	ATF_REQUIRE(fdetach(path) == 0);
	ATF_REQUIRE(close(replacement) == 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(rmdir(directory) == 0);
}
ATF_TC_CLEANUP(owner_exit_recovery_rebind, tc)
{
	(void)tc;
	cleanup_directory("recovery");
}

ATF_TC_WITH_CLEANUP(detach_preserves_open_capability);
ATF_TC_HEAD(detach_preserves_open_capability, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(detach_preserves_open_capability, tc)
{
	char directory[PATH_MAX], path[PATH_MAX];
	int client, fd, server;

	(void)tc;
	make_directory(directory, sizeof(directory), "detach");
	make_placeholder(directory, path, sizeof(path));
	server = door_create(marker_server, __DECONST(char *, "held"), 0);
	ATF_REQUIRE(server != -1);
	ATF_REQUIRE(fattach(server, path) == 0);
	client = open(path, O_RDWR);
	ATF_REQUIRE(client != -1);
	ATF_REQUIRE(fdetach(path) == 0);
	fd = open(path, O_RDWR);
	ATF_REQUIRE(fd != -1);
	errno = 0;
	ATF_REQUIRE(door_call(fd, NULL) == -1);
	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE(call_expect(client, "held") == 0);
	ATF_REQUIRE(close(client) == 0);
	ATF_REQUIRE(close(server) == 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(rmdir(directory) == 0);
}
ATF_TC_CLEANUP(detach_preserves_open_capability, tc)
{
	(void)tc;
	cleanup_directory("detach");
}

ATF_TC_WITH_CLEANUP(dead_door_open_and_attach_rejected);
ATF_TC_HEAD(dead_door_open_and_attach_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(dead_door_open_and_attach_rejected, tc)
{
	char first_dir[PATH_MAX], first[PATH_MAX];
	char second_dir[PATH_MAX], second[PATH_MAX];
	int client, server;

	(void)tc;
	make_directory(first_dir, sizeof(first_dir), "dead-open");
	make_placeholder(first_dir, first, sizeof(first));
	server = door_create(marker_server, __DECONST(char *, "dead"), 0);
	ATF_REQUIRE(server != -1);
	ATF_REQUIRE(fattach(server, first) == 0);
	ATF_REQUIRE(door_revoke(server) == 0);
	errno = 0;
	client = open(first, O_RDWR);
	ATF_REQUIRE_MSG(client == -1, "open of revoked Door succeeded");
	ATF_REQUIRE_MSG(errno == EBADF || errno == ENXIO,
	    "open of revoked Door: %s", strerror(errno));
	ATF_REQUIRE(fdetach(first) == 0);

	make_directory(second_dir, sizeof(second_dir), "dead-attach");
	make_placeholder(second_dir, second, sizeof(second));
	errno = 0;
	ATF_REQUIRE_MSG(fattach(server, second) == -1,
	    "fattach of revoked Door succeeded");
	ATF_REQUIRE_MSG(errno == EBADF,
	    "fattach of revoked Door: %s", strerror(errno));
	ATF_REQUIRE(close(server) == 0);
	ATF_REQUIRE(unlink(first) == 0);
	ATF_REQUIRE(rmdir("dead-open") == 0);
	ATF_REQUIRE(unlink(second) == 0);
	ATF_REQUIRE(rmdir("dead-attach") == 0);
}
ATF_TC_CLEANUP(dead_door_open_and_attach_rejected, tc)
{
	(void)tc;
	cleanup_directory("dead-open");
	cleanup_directory("dead-attach");
}

ATF_TC_WITH_CLEANUP(invalid_target_rejected);
ATF_TC_HEAD(invalid_target_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(invalid_target_rejected, tc)
{
	char directory[PATH_MAX], path[PATH_MAX];
	int fd;

	(void)tc;
	make_directory(directory, sizeof(directory), "invalid");
	make_placeholder(directory, path, sizeof(path));
	fd = open("/dev/null", O_RDONLY);
	ATF_REQUIRE(fd != -1);
	errno = 0;
	ATF_REQUIRE(fattach(fd, path) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);
	ATF_REQUIRE(close(fd) == 0);
	cleanup_path(path, directory);
}
ATF_TC_CLEANUP(invalid_target_rejected, tc)
{
	(void)tc;
	cleanup_directory("invalid");
}

ATF_TC_WITH_CLEANUP(mounted_path_mutation_rejected);
ATF_TC_HEAD(mounted_path_mutation_rejected, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(mounted_path_mutation_rejected, tc)
{
	char directory[PATH_MAX], path[PATH_MAX];
	int server;

	(void)tc;
	make_directory(directory, sizeof(directory), "mutation");
	make_placeholder(directory, path, sizeof(path));
	server = door_create(marker_server, __DECONST(char *, "mutation"), 0);
	ATF_REQUIRE(server != -1);
	ATF_REQUIRE(fattach(server, path) == 0);
	errno = 0;
	ATF_REQUIRE(unlink(path) == -1);
	ATF_REQUIRE_EQ(EBUSY, errno);
	errno = 0;
	ATF_REQUIRE(rename(path, "mutation/renamed") == -1);
	ATF_REQUIRE_EQ(EBUSY, errno);
	ATF_REQUIRE(fdetach(path) == 0);
	ATF_REQUIRE(close(server) == 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(rmdir(directory) == 0);
}
ATF_TC_CLEANUP(mounted_path_mutation_rejected, tc)
{
	(void)tc;
	cleanup_directory("mutation");
	(void)unlink("mutation/renamed");
}

ATF_TC_WITH_CLEANUP(nullfs_over_namefs);
ATF_TC_HEAD(nullfs_over_namefs, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(nullfs_over_namefs, tc)
{
	char source[PATH_MAX], target[PATH_MAX], path[PATH_MAX], view[PATH_MAX];
	int client, server;

	(void)tc;
	make_directory(source, sizeof(source), "null-source");
	make_directory(target, sizeof(target), "null-target");
	make_placeholder(source, path, sizeof(path));
	ATF_REQUIRE(snprintf(view, sizeof(view), "%s/door", target) > 0);
	server = door_create(marker_server, __DECONST(char *, "null-over"), 0);
	ATF_REQUIRE(server != -1);
	ATF_REQUIRE(fattach(server, path) == 0);
	ATF_REQUIRE_MSG(mount_nullfs(source, target) == 0,
	    "nmount(nullfs): %s", strerror(errno));
	client = open(view, O_RDWR);
	ATF_REQUIRE_MSG(client != -1, "open through nullfs: %s",
	    strerror(errno));
	errno = 0;
	ATF_REQUIRE_MSG(call_expect(client, "null-over") == -1,
	    "hidden namefs mount leaked through nullfs");
	ATF_REQUIRE_MSG(errno == ENOTTY,
	    "hidden namefs mount through nullfs: %s", strerror(errno));
	ATF_REQUIRE(close(client) == 0);
	client = open(path, O_RDWR);
	ATF_REQUIRE_MSG(client != -1, "open direct namefs path: %s",
	    strerror(errno));
	ATF_REQUIRE(call_expect(client, "null-over") == 0);
	ATF_REQUIRE(unmount(target, 0) == 0);
	ATF_REQUIRE(call_expect(client, "null-over") == 0);
	ATF_REQUIRE(close(client) == 0);
	ATF_REQUIRE(fdetach(path) == 0);
	ATF_REQUIRE(close(server) == 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(rmdir(source) == 0);
	ATF_REQUIRE(rmdir(target) == 0);
}
ATF_TC_CLEANUP(nullfs_over_namefs, tc)
{
	(void)tc;
	cleanup_directory("null-target");
	cleanup_directory("null-source");
}

ATF_TC_WITH_CLEANUP(namefs_over_nullfs);
ATF_TC_HEAD(namefs_over_nullfs, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(namefs_over_nullfs, tc)
{
	char source[PATH_MAX], target[PATH_MAX], path[PATH_MAX], view[PATH_MAX];
	int client, server;

	(void)tc;
	make_directory(source, sizeof(source), "under-source");
	make_directory(target, sizeof(target), "under-target");
	make_placeholder(source, path, sizeof(path));
	ATF_REQUIRE(snprintf(view, sizeof(view), "%s/door", target) > 0);
	ATF_REQUIRE(mount_nullfs(source, target) == 0);
	server = door_create(marker_server, __DECONST(char *, "name-over"), 0);
	ATF_REQUIRE(server != -1);
	ATF_REQUIRE(fattach(server, view) == 0);
	client = open(view, O_RDWR);
	ATF_REQUIRE(client != -1);
	ATF_REQUIRE(call_expect(client, "name-over") == 0);
	ATF_REQUIRE(close(client) == 0);
	ATF_REQUIRE_MSG(fdetach(view) == 0, "fdetach through nullfs: %s",
	    strerror(errno));
	ATF_REQUIRE(unmount(target, 0) == 0);
	ATF_REQUIRE(close(server) == 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(rmdir(source) == 0);
	ATF_REQUIRE(rmdir(target) == 0);
}
ATF_TC_CLEANUP(namefs_over_nullfs, tc)
{
	(void)tc;
	cleanup_directory("under-target");
	cleanup_directory("under-source");
}

static int
jail_open_result(const char *path, const char *marker, bool should_open)
{
	int fd;

	if (enter_jail() == -1)
		return (10);
	errno = 0;
	fd = open(path, O_RDWR);
	if (!should_open)
		return (fd == -1 && errno == EACCES ? 0 : 11);
	if (fd == -1)
		return (12);
	if (call_expect(fd, marker) == -1)
		return (13);
	(void)close(fd);
	return (0);
}

static void
run_jail_open_test(uint_t attributes, bool should_open)
{
	char directory[PATH_MAX], fullpath[PATH_MAX], path[PATH_MAX];
	pid_t child;
	int server, status;

	make_directory(directory, sizeof(directory), "jail");
	make_placeholder(directory, path, sizeof(path));
	ATF_REQUIRE(realpath(path, fullpath) != NULL);
	server = door_create(marker_server, __DECONST(char *, "jail"),
	    attributes);
	ATF_REQUIRE_MSG(server != -1, "door_create(%#x): %s", attributes,
	    strerror(errno));
	ATF_REQUIRE(fattach(server, path) == 0);
	child = fork();
	ATF_REQUIRE(child != -1);
	if (child == 0)
		_exit(jail_open_result(fullpath, "jail", should_open));
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
	    "jailed child failed at step %d", WEXITSTATUS(status));
	ATF_REQUIRE(fdetach(path) == 0);
	ATF_REQUIRE(close(server) == 0);
	ATF_REQUIRE(unlink(path) == 0);
	ATF_REQUIRE(rmdir(directory) == 0);
}

ATF_TC_WITH_CLEANUP(host_to_jail_denied);
ATF_TC_HEAD(host_to_jail_denied, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(host_to_jail_denied, tc)
{
	(void)tc;
	run_jail_open_test(0, false);
}
ATF_TC_CLEANUP(host_to_jail_denied, tc)
{
	(void)tc;
	cleanup_directory("jail");
}

ATF_TC_WITH_CLEANUP(host_to_jail_cross_allowed);
ATF_TC_HEAD(host_to_jail_cross_allowed, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(host_to_jail_cross_allowed, tc)
{
	(void)tc;
	run_jail_open_test(DOOR_CROSS_JAIL, true);
}
ATF_TC_CLEANUP(host_to_jail_cross_allowed, tc)
{
	(void)tc;
	cleanup_directory("jail");
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, basic_publish);
	ATF_TP_ADD_TC(tp, rebind_preserves_open_generation);
	ATF_TP_ADD_TC(tp, owner_exit_recovery_rebind);
	ATF_TP_ADD_TC(tp, detach_preserves_open_capability);
	ATF_TP_ADD_TC(tp, dead_door_open_and_attach_rejected);
	ATF_TP_ADD_TC(tp, invalid_target_rejected);
	ATF_TP_ADD_TC(tp, mounted_path_mutation_rejected);
	ATF_TP_ADD_TC(tp, nullfs_over_namefs);
	ATF_TP_ADD_TC(tp, namefs_over_nullfs);
	ATF_TP_ADD_TC(tp, host_to_jail_denied);
	ATF_TP_ADD_TC(tp, host_to_jail_cross_allowed);
	return (atf_no_error());
}
