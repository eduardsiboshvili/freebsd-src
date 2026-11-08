/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>

#include "libdoor_impl.h"

/*
 * Convert SIGSEGV/SIGBUS in this copying thread's protected window to EFAULT;
 * other threads chain to the saved handlers. We do not classify fault addresses.
 * The mutex serializes libdoor copies, not application sigaction() changes.
 */
static pthread_mutex_t door_copy_lock = PTHREAD_MUTEX_INITIALIZER;
static struct sigaction door_old_segv;
static struct sigaction door_old_bus;
static _Thread_local sigjmp_buf *door_copy_env;

static void
door_copy_chain(int signo, siginfo_t *info, void *context)
{
    const struct sigaction *old;

    if (door_copy_env != NULL)
        siglongjmp(*door_copy_env, 1);

    old = signo == SIGBUS ? &door_old_bus : &door_old_segv;
    if ((old->sa_flags & SA_SIGINFO) != 0) {
        if (old->sa_sigaction != NULL)
            old->sa_sigaction(signo, info, context);

        return;
    }

    if (old->sa_handler == SIG_IGN)
        return;

    if (old->sa_handler == SIG_DFL) {
        (void)signal(signo, SIG_DFL);
        (void)raise(signo);
        return;
    }

    old->sa_handler(signo);
}

int
__door_safe_copyin(void *dst, const void *src, size_t len)
{
    struct sigaction action;
    sigjmp_buf env;
    int saved_errno, failed;

    if (len == 0)
        return (0);

    if (dst == NULL || src == NULL) {
        errno = EFAULT;
        return (-1);
    }

    saved_errno = errno;
    failed = 0;
    (void)pthread_mutex_lock(&door_copy_lock);

    memset(&action, 0, sizeof(action));
    sigemptyset(&action.sa_mask);
    action.sa_sigaction = door_copy_chain;
    action.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSEGV, &action, &door_old_segv) == -1) {
        failed = errno;
        goto out_unlock;
    }

    if (sigaction(SIGBUS, &action, &door_old_bus) == -1) {
        failed = errno;
        (void)sigaction(SIGSEGV, &door_old_segv, NULL);
        goto out_unlock;
    }

    door_copy_env = &env;
    if (sigsetjmp(env, 1) == 0)
        memcpy(dst, src, len);
    else
        failed = EFAULT;

    door_copy_env = NULL;

    (void)sigaction(SIGBUS, &door_old_bus, NULL);
    (void)sigaction(SIGSEGV, &door_old_segv, NULL);

out_unlock:
    (void)pthread_mutex_unlock(&door_copy_lock);
    if (failed != 0) {
        errno = failed;
        return (-1);
    }

    errno = saved_errno;
    return (0);
}
