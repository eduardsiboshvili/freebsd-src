/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/user.h>

#include <sys/door_impl.h>

static fo_stat_t door_file_stat;
static fo_close_t door_file_close;
static fo_fill_kinfo_t door_file_fill_kinfo;

static fo_close_t door_client_file_close;
static fo_fill_kinfo_t door_client_file_fill_kinfo;

static const struct fileops door_fileops = {
    .fo_read = invfo_rdwr,
    .fo_write = invfo_rdwr,
    .fo_truncate = invfo_truncate,
    .fo_ioctl = invfo_ioctl,
    .fo_poll = invfo_poll,
    .fo_kqfilter = invfo_kqfilter,
    .fo_stat = door_file_stat,
    .fo_close = door_file_close,
    .fo_chmod = invfo_chmod,
    .fo_chown = invfo_chown,
    .fo_sendfile = invfo_sendfile,
    .fo_fill_kinfo = door_file_fill_kinfo,
    .fo_flags = DFLAG_PASSABLE,
};
static const struct fileops door_client_fileops = {
    .fo_read = invfo_rdwr,
    .fo_write = invfo_rdwr,
    .fo_truncate = invfo_truncate,
    .fo_ioctl = invfo_ioctl,
    .fo_poll = invfo_poll,
    .fo_kqfilter = invfo_kqfilter,
    .fo_stat = door_file_stat,
    .fo_close = door_client_file_close,
    .fo_chmod = invfo_chmod,
    .fo_chown = invfo_chown,
    .fo_sendfile = invfo_sendfile,
    .fo_fill_kinfo = door_client_file_fill_kinfo,
    .fo_flags = DFLAG_PASSABLE,
};

bool
door_file_is_door(const struct file *fp)
{
	return (fp->f_type == DTYPE_DOOR &&
	    (fp->f_ops == &door_fileops || fp->f_ops == &door_client_fileops));
}

bool
door_file_is_live(const struct file *fp)
{
	struct door *door;
	bool live;

	if (!door_file_is_door(fp) || fp->f_data == NULL)
		return (false);
	door = fp->f_data;
	mtx_lock(&door->d_lock);
	live = !door->d_revoked && !door->d_orphaning;
	mtx_unlock(&door->d_lock);
	return (live);
}

static int
door_file_stat(
    struct file *fp, struct stat *sb, struct ucred *active_cred __unused)
{
	if (fp->f_data == NULL)
		return (ENXIO);

	bzero(sb, sizeof(*sb));
	sb->st_mode = S_IFREG | 0600;
	sb->st_nlink = 1;
	sb->st_blksize = PAGE_SIZE;
	return (0);
}

static int
door_file_close(struct file *fp, struct thread *td __unused)
{
	struct door *door;

	door = fp->f_data;
	fp->f_data = NULL;

	if (door != NULL) {
		/*
		 * The file reference still protects door while the helper possibly
		 * removes the owner-list reference.
		 */
		door_last_file_closed(door);
		door_drop(door); /* file reference */
	}

	return (0);
}

static int
door_file_fill_kinfo(
    struct file *fp, struct kinfo_file *kif, struct filedesc *fdp __unused)
{
	struct door *door;
	uint64_t cookie;

	kif->kf_type = KF_TYPE_DOOR;
	door = fp->f_data;

	if (door == NULL) {
		strlcpy(kif->kf_path, "door:[closed]", sizeof(kif->kf_path));
		return (0);
	}

	/* The live struct file reference protects f_data. */
	cookie = door->d_cookie;
	snprintf(kif->kf_path, sizeof(kif->kf_path),
	    "door:[id=%#jx cookie=%#jx]", (uintmax_t)door->d_uniquifier,
	    (uintmax_t)cookie);
	return (0);
}
static int
door_client_file_close(struct file *fp, struct thread *td __unused)
{
	struct door *door;

	door = fp->f_data;
	fp->f_data = NULL;
	if (door != NULL) {
		door_client_closed(door);
		door_drop(door);
	}
	return (0);
}

static int
door_client_file_fill_kinfo(
    struct file *fp, struct kinfo_file *kif, struct filedesc *fdp __unused)
{
	struct door *door;

	kif->kf_type = KF_TYPE_DOOR;
	door = fp->f_data;
	if (door == NULL) {
		strlcpy(
		    kif->kf_path, "door-client:[closed]", sizeof(kif->kf_path));
		return (0);
	}

	snprintf(kif->kf_path, sizeof(kif->kf_path), "door-client:[id=%#jx]",
	    (uintmax_t)door->d_uniquifier);
	return (0);
}

int
door_client_file_install(struct thread *td, struct door *door, int *fdp)
{
	struct file *fp;
	int error, fd;

	error = door_client_open(door);
	if (error != 0)
		return (error);

	error = falloc(td, &fp, &fd, 0);
	if (error != 0) {
		door_client_closed(door);
		return (error);
	}

	door_hold(door);
	finit(fp, FREAD | FWRITE, DTYPE_DOOR, door, &door_client_fileops);
	fdrop(fp, td);
	*fdp = fd;
	return (0);
}

/*
 * Replace an open(2) result with a native Door client file.
 *
 * The source file must be held by the caller.  The new file owns one Door
 * reference and one logical client-open reference, exactly like a capability
 * returned by door_named_connect().
 */
int
door_file_clone(struct file *source, struct file *destination, int flags,
    struct ucred *cred)
{
	struct door *door;
	int error;

	if (source == NULL || destination == NULL ||
	    !door_file_is_door(source) || source->f_data == NULL)
		return (EINVAL);

	door = source->f_data;
	error = door_check_jail(door, cred);
	if (error != 0)
		return (error);
	error = door_client_open(door);
	if (error != 0)
		return (error);

	door_hold(door);
	finit(destination, flags, DTYPE_DOOR, door, &door_client_fileops);
	return (0);
}

int
door_file_install(struct thread *td, struct door *door, int *fdp)
{
	struct file *fp;
	int error, fd;

	error = falloc(td, &fp, &fd, 0);

	if (error != 0)
		return (error);

	door_hold(door);

	finit(fp, FREAD | FWRITE, DTYPE_DOOR, door, &door_fileops);
	door_file_installed(door);
	fdrop(fp, td);
	*fdp = fd;
	return (0);
}

int
door_file_get(struct thread *td, int fd, struct door **doorp)
{
	static const cap_rights_t rights =
	    CAP_RIGHTS_INITIALIZER(CAP_DOOR_ADMIN);
	struct file *fp;
	struct door *door;
	int error;

	error = fget(td, fd, &rights, &fp);

	if (error != 0)
		return (error);

	if (fp->f_type != DTYPE_DOOR || fp->f_ops != &door_fileops ||
	    fp->f_data == NULL) {
		fdrop(fp, td);
		return (EINVAL);
	}

	door = fp->f_data;
	door_hold(door);
	fdrop(fp, td);
	*doorp = door;
	return (0);
}

/*
 * Return a Door protected by the held file reference in *fpp.  This helper
 * performs only descriptor/fileops validation; syscall semantics belong to
 * door_syscall.c.
 */
int
door_file_get_ref(
    struct thread *td, int fd, const cap_rights_t *rights, struct file **fpp,
    struct door **doorp)
{
	struct file *fp;
	int error;

	error = fget(td, fd, rights, &fp);
	if (error != 0)
		return (error);
	if ((fp->f_flag & (FREAD | FWRITE)) == 0)
		error = EBADF;
	else if (!door_file_is_door(fp))
		error = ENOTTY;
	else if (fp->f_data == NULL)
		error = ENXIO;
	else {
		*fpp = fp;
		*doorp = fp->f_data;
		return (0);
	}
	fdrop(fp, td);
	return (error);
}
