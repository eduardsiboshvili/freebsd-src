/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/mount.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "libdoor_impl.h"

static int
door_namefs_mount(int fd, const char *path, int flags)
{
    struct iovec *iov;
    int iovlen, rc;

    iov = NULL;
    iovlen = 0;

    if (__door_iov_add(&iov, &iovlen, "fstype", "namefs",
        sizeof("namefs")) == -1 ||
        __door_iov_add(&iov, &iovlen, "fspath", path,
        strlen(path) + 1) == -1 ||
        __door_iov_add(&iov, &iovlen, "doorfd", &fd,
        sizeof(fd)) == -1) {
        rc = -1;
    } else
        rc = nmount(iov, (unsigned)iovlen, flags);

    __door_iov_free(iov, iovlen);
    return (rc);
}

int
fattach(int fd, const char *path)
{
    if (fd < 0 || path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return (-1);
    }

    if (door_namefs_mount(fd, path, 0) == 0)
        return (0);

    if (errno != EBUSY)
        return (-1);

    return (door_namefs_mount(fd, path, MNT_UPDATE));
}

int
fdetach(const char *path)
{
	struct statfs sb;
	char fsid[64];
	int len;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return (-1);
    }

	if (statfs(path, &sb) == -1)
		return (-1);

	if (strcmp(sb.f_fstypename, "namefs") != 0) {
		errno = EINVAL;
		return (-1);
	}

	len = snprintf(fsid, sizeof(fsid), "FSID:%d:%d",
	    sb.f_fsid.val[0], sb.f_fsid.val[1]);
	if (len < 0 || (size_t)len >= sizeof(fsid)) {
		errno = EOVERFLOW;
		return (-1);
	}

	return (unmount(fsid, MNT_BYFSID));
}
