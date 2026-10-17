/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "libdoor_impl.h"

pthread_mutex_t __door_lock = PTHREAD_MUTEX_INITIALIZER;
struct door_entry *__door_entries;
door_server_func_t *__door_server_factory;

static pthread_key_t door_tls_key;
static pthread_once_t door_tls_once = PTHREAD_ONCE_INIT;

#if defined(__clang__)
static void door_atfork_prepare(void)
    __attribute__((acquire_capability(&__door_lock)));
static void door_atfork_parent(void)
    __attribute__((release_capability(&__door_lock)));
static void door_atfork_child(void)
    __attribute__((release_capability(&__door_lock)));
#endif

static void
door_tls_release(struct door_tls *tls, bool unbind)
{
    if (tls == NULL)
        return;

    if (unbind && tls->dt_bound)
        (void)__door_syscall(tls->dt_call_id != 0 ?
            DOOR_SC_WORKER_EXIT : DOOR_SC_UNBIND, 0, 0, 0, 0, 0);

    if (tls->dt_worker_fd >= 0)
        (void)close(tls->dt_worker_fd);

    tls->dt_entry = NULL;
    tls->dt_worker_fd = -1;
    tls->dt_call_id = 0;
    tls->dt_bound = false;
}

static void
door_tls_destructor(void *arg)
{
    struct door_tls *tls;

    tls = arg;
    if (tls != NULL) {
        door_tls_release(tls, true);
        free(tls);
    }
}

static void
door_atfork_prepare(void)
{
    /*
     * Serialize fork() with registry mutation.  Without this, the child may
     * inherit __door_lock while it is owned by a worker thread that does not
     * exist in the child, permanently blocking door_create()/door_info().
     */
    (void)pthread_mutex_lock(&__door_lock);
}

static void
door_atfork_parent(void)
{
    (void)pthread_mutex_unlock(&__door_lock);
}

static void
door_atfork_child(void)
{
    struct door_tls *tls;

    /*
     * Server workers and their per-entry mutex/condition state are not
     * inherited across fork().  Drop the child-side registry view without
     * walking or freeing it: entries may contain mutexes that were owned by
     * vanished parent threads.  Inherited descriptors remain valid client
     * handles and are serviced by the parent's workers.  Doors created by
     * the child build a fresh registry.
     */
    __door_entries = NULL;

    /*
     * User TLS is copied by fork(), but the kernel binding belongs to the
     * parent thread and process.  Close only the inherited transport fd;
     * issuing UNBIND here could target an unrelated child-side binding.
     */
    tls = pthread_getspecific(door_tls_key);
    if (tls != NULL)
        door_tls_release(tls, false);

    (void)pthread_mutex_unlock(&__door_lock);
}

static void
door_tls_init(void)
{
    (void)pthread_key_create(&door_tls_key, door_tls_destructor);
    (void)pthread_atfork(door_atfork_prepare, door_atfork_parent,
        door_atfork_child);
}

struct door_tls *
__door_tls_get(bool create)
{
    struct door_tls *tls;
    int error;

    error = pthread_once(&door_tls_once, door_tls_init);
    if (error != 0) {
        errno = error;
        return (NULL);
    }

    tls = pthread_getspecific(door_tls_key);
    if (tls == NULL && create) {
        tls = calloc(1, sizeof(*tls));
        if (tls == NULL)
            return (NULL);

        tls->dt_worker_fd = -1;
        tls->dt_pid = getpid();
        error = pthread_setspecific(door_tls_key, tls);
        if (error != 0) {
            free(tls);
            errno = error;
            return (NULL);
        }
    }

    return (tls);
}

struct door_entry *
__door_entry_lookup(int fd)
{
    struct door_entry *entry;

    pthread_mutex_lock(&__door_lock);
    for (entry = __door_entries; entry != NULL; entry = entry->de_next) {
        if (entry->de_fd == fd && !entry->de_revoked)
            break;
    }

    /* Entries are retained for process lifetime, so this raw pointer survives
     * unlock. Numeric fd lookup does not protect concurrent close/reuse; use
     * strong Door identity where generation matters. */
    pthread_mutex_unlock(&__door_lock);
    return (entry);
}

int
__door_entry_add(struct door_entry *entry)
{
    pthread_mutex_lock(&__door_lock);
    entry->de_next = __door_entries;
    __door_entries = entry;
    pthread_mutex_unlock(&__door_lock);
    return (0);
}

struct door_entry *
__door_entry_begin_revoke(int fd)
{
    struct door_entry *entry;

    entry = NULL;
    pthread_mutex_lock(&__door_lock);
    for (entry = __door_entries; entry != NULL; entry = entry->de_next) {
        if (entry->de_fd == fd && !entry->de_revoked) {
            pthread_mutex_lock(&entry->de_pool_lock);
            entry->de_revoke_pending = true;
            entry->de_pool_stopping = true;
            pthread_cond_broadcast(&entry->de_pool_cv);
            pthread_mutex_unlock(&entry->de_pool_lock);
            break;
        }
    }

    pthread_mutex_unlock(&__door_lock);
    return (entry);
}

void
__door_entry_finish_revoke(struct door_entry *entry, bool success)
{
    if (entry == NULL)
        return;

    pthread_mutex_lock(&__door_lock);
    pthread_mutex_lock(&entry->de_pool_lock);
    if (success) {
        entry->de_revoked = true;
        entry->de_pool_stopping = true;
    } else if (!entry->de_revoked) {
        /*
         * Kernel revoke failed: restore the pool so the door remains usable.
         * A concurrent successful revoke leaves de_revoked set and wins.
         */
        entry->de_pool_stopping = false;
    }

    entry->de_revoke_pending = false;
    pthread_cond_broadcast(&entry->de_pool_cv);
    pthread_mutex_unlock(&entry->de_pool_lock);
    pthread_mutex_unlock(&__door_lock);
}
