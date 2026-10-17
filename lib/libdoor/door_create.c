/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "libdoor_impl.h"

static int
door_create_kernel(uintptr_t cookie, uint32_t attributes, uint32_t flags)
{
    return ((int)__door_syscall(
        DOOR_SC_CREATE, attributes, cookie, flags, 0, 0));
}

void
__door_entry_pool_destroy(struct door_entry *entry)
{
    if (entry == NULL)
        return;

    (void)pthread_cond_destroy(&entry->de_pool_cv);
    (void)pthread_mutex_destroy(&entry->de_pool_lock);
    free(entry);
}

int
__door_create_common(door_server_procedure_t *proc, void *cookie,
    uint_t attributes, uint32_t create_flags, struct door_entry **entryp)
{
    struct door_entry *entry;
    int door_fd, error;

    if (entryp != NULL)
        *entryp = NULL;

    if (proc == NULL || (attributes & ~DOOR_CREATE_MASK) != 0 ||
        (attributes & DOOR_PRIVCREATE) != 0 ||
        (create_flags != DOOR_CREATE_F_NORMAL &&
        create_flags != DOOR_CREATE_F_XCREATE)) {
        errno = EINVAL;
        return (-1);
    }

    if (create_flags == DOOR_CREATE_F_XCREATE)
        attributes |= DOOR_PRIVATE;

    if ((attributes & DOOR_UNREF_MULTI) != 0)
        attributes |= DOOR_UNREF;

    if ((attributes & DOOR_ONEWAY) != 0)
        attributes |= DOOR_REFUSE_DESC;

    door_fd = door_create_kernel((uintptr_t)cookie, attributes,
        create_flags);
    if (door_fd == -1)
        return (-1);

    entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
        error = errno;
        (void)close(door_fd);
        errno = error;
        return (-1);
    }

    entry->de_fd = door_fd;
    entry->de_proc = proc;
    entry->de_cookie = cookie;
    entry->de_attributes = attributes;
    entry->de_pool_type = create_flags == DOOR_CREATE_F_XCREATE ?
        DOOR_POOL_XCREATE_PRIVATE :
        ((attributes & DOOR_PRIVATE) != 0 ?
        DOOR_POOL_LEGACY_PRIVATE : DOOR_POOL_SHARED);
    error = pthread_mutex_init(&entry->de_pool_lock, NULL);
    if (error != 0)
        goto fail_entry;

    error = pthread_cond_init(&entry->de_pool_cv, NULL);
    if (error != 0) {
        (void)pthread_mutex_destroy(&entry->de_pool_lock);
        goto fail_entry;
    }

    (void)__door_entry_add(entry);
    if (entryp != NULL)
        *entryp = entry;

    return (door_fd);

fail_entry:
    (void)close(door_fd);
    free(entry);
    errno = error;
    return (-1);
}

int
door_create(door_server_procedure_t *proc, void *cookie, uint_t attributes)
{
    struct door_entry *entry;
    int fd, error;

    fd = __door_create_common(proc, cookie, attributes,
        DOOR_CREATE_F_NORMAL, &entry);
    if (fd == -1)
        return (-1);

    if (__door_spawn_server(entry) == -1) {
        error = errno;
        (void)door_revoke(fd);
        (void)close(fd);
        errno = error;
        return (-1);
    }

    /*
     * pthread_create() only proves that a thread object was created.  Do not
     * expose the door until its initial worker has allocated all loop buffers,
     * successfully bound to the kernel door, and published the ready state.
     */
    pthread_mutex_lock(&entry->de_pool_lock);
    while (entry->de_start_error == 0 && entry->de_workers_ready == 0 &&
        entry->de_workers_exited == 0)
        pthread_cond_wait(&entry->de_pool_cv, &entry->de_pool_lock);

    if (entry->de_start_error != 0)
        error = entry->de_start_error;
    else if (entry->de_workers_ready == 0)
        error = EPIPE;
    else
        error = 0;

    pthread_mutex_unlock(&entry->de_pool_lock);

    if (error != 0) {
        (void)door_revoke(fd);
        (void)close(fd);
        errno = error;
        return (-1);
    }

    return (fd);
}
