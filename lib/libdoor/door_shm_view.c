/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "libdoor_impl.h"

static void
door_shm_view_reset(door_shm_view_t *view)
{
    memset(view, 0, sizeof(*view));
    view->dsv_fd = -1;
}

static int
door_shm_view_request(door_shm_view_t *view, unsigned int op,
    struct door_ioc_shm_view *arg)
{
    if (view == NULL || view->dsv_fd < 0 || view->dsv_id == 0 ||
        view->dsv_token == 0) {
        errno = EINVAL;
        return (-1);
    }

    memset(arg, 0, sizeof(*arg));
    arg->disv_version = DOOR_ABI_VERSION;
    arg->disv_id = view->dsv_id;
    arg->disv_token = view->dsv_token;
    return ((int)__door_syscall(op, view->dsv_fd,
        (long)(uintptr_t)arg, 0, 0, 0));
}

int
door_shm_view_publish(int fd, const door_shm_ref_t *segments, uint_t count,
    door_shm_view_t *view)
{
    struct door_ioc_shm_view arg;
    struct door_ioc_shm_view_segment wire[DOOR_SHM_VIEW_MAX_SEGMENTS];
    int private_fd, error;

    if (fd < 0 || segments == NULL || view == NULL || count == 0 ||
        count > DOOR_SHM_VIEW_MAX_SEGMENTS) {
        errno = EINVAL;
        return (-1);
    }

    for (uint_t i = 0; i < count; i++) {
        wire[i].disvs_region = segments[i].dsr_region;
        wire[i].disvs_offset = segments[i].dsr_offset;
        wire[i].disvs_size = segments[i].dsr_size;
        wire[i].disvs_uniquifier = segments[i].dsr_uniquifier;
    }

    private_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (private_fd == -1)
        return (-1);

    memset(&arg, 0, sizeof(arg));
    arg.disv_version = DOOR_ABI_VERSION;
    arg.disv_segments_ptr = (uintptr_t)wire;
    arg.disv_segment_count = count;
    if (__door_syscall(DOOR_SC_SHM_VIEW_PUBLISH, private_fd,
        (long)(uintptr_t)&arg, 0, 0, 0) == -1) {
        error = errno;
        (void)close(private_fd);
        errno = error;
        return (-1);
    }

    door_shm_view_reset(view);
    view->dsv_id = arg.disv_id;
    view->dsv_token = arg.disv_token;
    view->dsv_size = (size_t)arg.disv_size;
    view->dsv_state = arg.disv_state;
    view->dsv_fd = private_fd;
    view->dsv_role = DOOR_SHM_VIEW_PRODUCER;
    return (0);
}

int
door_shm_view_attach(int fd, uint64_t id, uint64_t token, door_shm_view_t *view)
{
    struct door_ioc_shm_view arg;
    int private_fd, error;

    if (fd < 0 || id == 0 || token == 0 || view == NULL) {
        errno = EINVAL;
        return (-1);
    }

    private_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (private_fd == -1)
        return (-1);

    memset(&arg, 0, sizeof(arg));
    arg.disv_version = DOOR_ABI_VERSION;
    arg.disv_id = id;
    arg.disv_token = token;
    if (__door_syscall(DOOR_SC_SHM_VIEW_ATTACH, private_fd,
        (long)(uintptr_t)&arg, 0, 0, 0) == -1) {
        error = errno;
        (void)close(private_fd);
        errno = error;
        return (-1);
    }

    door_shm_view_reset(view);
    view->dsv_id = id;
    view->dsv_token = token;
    view->dsv_addr = (void *)(uintptr_t)arg.disv_addr;
    view->dsv_size = (size_t)arg.disv_size;
    view->dsv_state = arg.disv_state;
    view->dsv_fd = private_fd;
    view->dsv_role = DOOR_SHM_VIEW_CONSUMER;
    return (0);
}

int
door_shm_view_query(door_shm_view_t *view, uint_t *state)
{
    struct door_ioc_shm_view arg;

    if (door_shm_view_request(view, DOOR_SC_SHM_VIEW_QUERY, &arg) == -1)
        return (-1);

    view->dsv_state = arg.disv_state;
    if (state != NULL)
        *state = arg.disv_state;

    return (0);
}

int
door_shm_view_release(door_shm_view_t *view)
{
    struct door_ioc_shm_view arg;

    if (door_shm_view_request(view, DOOR_SC_SHM_VIEW_RELEASE, &arg) == -1)
        return (-1);

    view->dsv_addr = NULL;
    view->dsv_state = DOOR_SHM_VIEW_RELEASED;
    return (0);
}

int
door_shm_view_close(door_shm_view_t *view)
{
    int fd;

    if (view == NULL || view->dsv_fd < 0) {
        errno = EINVAL;
        return (-1);
    }

    if (view->dsv_role != DOOR_SHM_VIEW_CONSUMER ||
        view->dsv_addr != NULL || view->dsv_state != DOOR_SHM_VIEW_RELEASED) {
        errno = EBUSY;
        return (-1);
    }

    fd = view->dsv_fd;
    door_shm_view_reset(view);
    return (close(fd));
}

int
door_shm_view_destroy(door_shm_view_t *view)
{
    struct door_ioc_shm_view arg;
    int fd;

    if (door_shm_view_request(view, DOOR_SC_SHM_VIEW_DESTROY, &arg) == -1 &&
        errno != ENOENT)
        return (-1);

    fd = view->dsv_fd;
    door_shm_view_reset(view);
    return (close(fd));
}
