/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/queue.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <door.h>

struct door_async_session {
    TAILQ_ENTRY(door_async_session) das_link;
    uint64_t das_token;
    pid_t das_pid;
    int32_t das_jid;
    int das_reply_fd;
};
TAILQ_HEAD(door_async_session_head, door_async_session);

struct door_async_server {
    pthread_mutex_t das_lock;
    struct door_async_session_head das_sessions;
    size_t das_count;
    size_t das_limit;
};

int
door_async_server_open(size_t max_sessions, door_async_server_t **out)
{
    door_async_server_t *server;
    int error;

    if (max_sessions == 0 || out == NULL) {
        errno = EINVAL;
        return (-1);
    }

    *out = NULL;
    server = calloc(1, sizeof(*server));
    if (server == NULL)
        return (-1);

    error = pthread_mutex_init(&server->das_lock, NULL);
    if (error != 0) {
        free(server);
        errno = error;
        return (-1);
    }

    TAILQ_INIT(&server->das_sessions);
    server->das_limit = max_sessions;
    *out = server;
    return (0);
}

int
door_async_server_register(door_async_server_t *server, uint64_t token,
    int reply_fd)
{
    struct door_async_session *session, *iter;
    door_info_t info;
    ucred_t *cred;
    int error;

    if (server == NULL || token == 0 || reply_fd < 0) {
        errno = EINVAL;
        return (-1);
    }

    /* Registration occurs inside a descriptor-bearing control Door CALL. */
    if (door_ucred(&cred) == -1)
        return (-1);

    if (door_info(reply_fd, &info) == -1)
        return (-1);

    if ((info.di_attributes & DOOR_ONEWAY) == 0 ||
        info.di_target != cred->du_pid) {
        errno = EPERM;
        return (-1);
    }

    session = calloc(1, sizeof(*session));
    if (session == NULL)
        return (-1);

    session->das_reply_fd = fcntl(reply_fd, F_DUPFD_CLOEXEC, 0);
    if (session->das_reply_fd == -1) {
        free(session);
        return (-1);
    }

    session->das_token = token;
    session->das_pid = cred->du_pid;
    session->das_jid = cred->du_jid;
    pthread_mutex_lock(&server->das_lock);
    TAILQ_FOREACH(iter, &server->das_sessions, das_link) {
        if (iter->das_token == token)
            break;
    }

    if (iter != NULL)
        error = EEXIST;
    else if (server->das_count >= server->das_limit)
        error = EAGAIN;
    else {
        TAILQ_INSERT_TAIL(&server->das_sessions, session, das_link);
        server->das_count++;
        error = 0;
    }

    pthread_mutex_unlock(&server->das_lock);
    if (error != 0) {
        close(session->das_reply_fd);
        free(session);
        errno = error;
        return (-1);
    }

    return (0);
}

int
door_async_server_respond(door_async_server_t *server,
    const door_async_request_t *request, int status, const void *data,
    size_t size)
{
    struct door_async_session *session;
    int fd, error, rc;

    if (server == NULL || request == NULL || request->dar_token == 0 ||
        request->dar_id == 0) {
        errno = EINVAL;
        return (-1);
    }

    pthread_mutex_lock(&server->das_lock);
    TAILQ_FOREACH(session, &server->das_sessions, das_link) {
        if (session->das_token == request->dar_token)
            break;
    }

    if (session == NULL)
        error = ENOENT;
    else if (session->das_pid != request->dar_pid ||
        session->das_jid != request->dar_jid)
        error = EPERM;
    else
        error = 0;

    /* Pin the fd before unlock so unregister cannot close this send's handle. */
    fd = error == 0 ? fcntl(session->das_reply_fd, F_DUPFD_CLOEXEC, 0) : -1;
    if (error == 0 && fd == -1)
        error = errno;

    pthread_mutex_unlock(&server->das_lock);
    if (error != 0) {
        errno = error;
        return (-1);
    }

    rc = door_async_respond(fd, request, status, data, size);
    error = errno;
    close(fd);
    errno = error;
    return (rc);
}

int
door_async_server_unregister(door_async_server_t *server, uint64_t token)
{
    struct door_async_session *session;

    if (server == NULL || token == 0) {
        errno = EINVAL;
        return (-1);
    }

    pthread_mutex_lock(&server->das_lock);
    TAILQ_FOREACH(session, &server->das_sessions, das_link) {
        if (session->das_token == token)
            break;
    }

    if (session != NULL) {
        TAILQ_REMOVE(&server->das_sessions, session, das_link);
        server->das_count--;
    }

    pthread_mutex_unlock(&server->das_lock);
    if (session == NULL) {
        errno = ENOENT;
        return (-1);
    }

    close(session->das_reply_fd);
    free(session);
    return (0);
}

int
door_async_server_close(door_async_server_t *server)
{
    struct door_async_session *session;

    if (server == NULL) {
        errno = EINVAL;
        return (-1);
    }

    /* The application must first drain callbacks using this registry. */
    while ((session = TAILQ_FIRST(&server->das_sessions)) != NULL) {
        TAILQ_REMOVE(&server->das_sessions, session, das_link);
        close(session->das_reply_fd);
        free(session);
    }

    pthread_mutex_destroy(&server->das_lock);
    free(server);
    return (0);
}
