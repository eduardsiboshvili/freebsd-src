/*-
 * Copyright (c) 2026 Eduard Siboshvili
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void
echo(void *cookie, char *data, size_t size, door_desc_t *desc, uint_t count)
{
    (void)cookie;
    (void)desc;
    (void)count;
    (void)door_return(data, size, NULL, 0);
}

static int
publish(char *name, size_t capacity, const char *tag, uint_t flags)
{
    int fd;

    if (access("/dev/doorctl", F_OK) != 0)
        atf_tc_skip("doorctl is unavailable");
    snprintf(name, capacity, "libdoor.policy.%s.%ld", tag, (long)getpid());
    fd = door_create(echo, NULL, DOOR_PRIVATE | DOOR_NO_DEPLETION_CB);
    ATF_REQUIRE(fd >= 0);
    ATF_REQUIRE(door_named_register(fd, name, flags) == 0);
    return (fd);
}

static void
ping(int fd)
{
    char request[] = "policy";
    char reply[64];
    door_arg_t arg;

    memset(&arg, 0, sizeof(arg));
    arg.data_ptr = request;
    arg.data_size = sizeof(request);
    arg.rbuf = reply;
    arg.rsize = sizeof(reply);
    ATF_REQUIRE(door_call(fd, &arg) == 0);
    ATF_REQUIRE_EQ(arg.data_size, sizeof(request));
    ATF_REQUIRE(memcmp(arg.data_ptr, request, sizeof(request)) == 0);
}

static ssize_t
send_fd(int socket, int fd)
{
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    struct msghdr message;
    struct cmsghdr *header;
    char byte = 'F';
    struct iovec iov = { .iov_base = &byte, .iov_len = 1 };

    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    return (sendmsg(socket, &message, 0));
}

static void
require_no_transfer(int socket, int fd)
{
    errno = 0;
    ATF_REQUIRE(send_fd(socket, fd) == -1);
    ATF_REQUIRE_EQ(errno, EOPNOTSUPP);
    ATF_REQUIRE(fcntl(fd, F_GETFD) >= 0);
}

ATF_TC_WITHOUT_HEAD(nopass_blocks_unix_and_door_transfer);
ATF_TC_BODY(nopass_blocks_unix_and_door_transfer, tc)
{
    char name[128], reply[64];
    door_arg_t arg;
    door_desc_t descriptor;
    int owner, client, duplicate, sockets[2], status;
    pid_t child;

    (void)tc;
    owner = publish(name, sizeof(name), "nopass", DOOR_NAMED_NO_PASS);
    client = door_named_connect(name, 0, NULL);
    ATF_REQUIRE(client >= 0);
    ping(client);
    ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    require_no_transfer(sockets[0], client);
    duplicate = dup(client);
    ATF_REQUIRE(duplicate >= 0);
    require_no_transfer(sockets[0], duplicate);

    /* COPY and MOVE through Doors must both honor the fileops restriction. */
    for (unsigned move = 0; move < 2; move++) {
        memset(&descriptor, 0, sizeof(descriptor));
        descriptor.d_attributes = DOOR_DESCRIPTOR | (move ? DOOR_RELEASE : 0);
        descriptor.d_descriptor = client;
        memset(&arg, 0, sizeof(arg));
        arg.desc_ptr = &descriptor;
        arg.desc_num = 1;
        arg.rbuf = reply;
        arg.rsize = sizeof(reply);
        errno = 0;
        ATF_REQUIRE(door_call(owner, &arg) == -1);
        ATF_REQUIRE_EQ(errno, EOPNOTSUPP);
        ATF_REQUIRE(fcntl(client, F_GETFD) >= 0);
    }

    /* This policy is delegation control, not a fork-inheritance prohibition. */
    child = fork();
    ATF_REQUIRE(child >= 0);
    if (child == 0) {
        char request[] = "fork-policy";
        door_arg_t child_arg;

        if (fcntl(client, F_GETFD) == -1) {
            dprintf(STDERR_FILENO, "child inherited fd: %s\n", strerror(errno));
            _exit(10);
        }
        memset(&child_arg, 0, sizeof(child_arg));
        child_arg.data_ptr = request;
        child_arg.data_size = sizeof(request);
        child_arg.rbuf = reply;
        child_arg.rsize = sizeof(reply);
        if (door_call(client, &child_arg) == -1) {
            dprintf(STDERR_FILENO, "child inherited call: %s\n", strerror(errno));
            _exit(11);
        }
        if (child_arg.data_size != sizeof(request) ||
            memcmp(child_arg.data_ptr, request, sizeof(request)) != 0)
            _exit(12);
        errno = 0;
        if (send_fd(sockets[0], client) != -1 || errno != EOPNOTSUPP)
            _exit(13);
        _exit(0);
    }
    ATF_REQUIRE(waitpid(child, &status, 0) == child);
    ATF_REQUIRE_MSG(WIFEXITED(status), "child raw wait status %#x", status);
    ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0,
        "child exit %d (10=fd missing, 11=RPC, 12=reply, 13=transfer policy)",
        WEXITSTATUS(status));
    ATF_REQUIRE(close(duplicate) == 0);
    ATF_REQUIRE(close(client) == 0);
    close(sockets[0]);
    close(sockets[1]);
    ATF_REQUIRE(door_named_unregister(owner, name, 0) == 0);
    ATF_REQUIRE(door_revoke(owner) == 0);
    ATF_REQUIRE(close(owner) == 0);
}

ATF_TC_WITHOUT_HEAD(default_capability_remains_passable);
ATF_TC_BODY(default_capability_remains_passable, tc)
{
    char name[128], byte;
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    struct msghdr message;
    struct cmsghdr *header;
    struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
    int owner, client, received, sockets[2];

    (void)tc;
    owner = publish(name, sizeof(name), "default", 0);
    client = door_named_connect(name, 0, NULL);
    ATF_REQUIRE(client >= 0);
    ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    ATF_REQUIRE(send_fd(sockets[0], client) == 1);
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    ATF_REQUIRE(recvmsg(sockets[1], &message, 0) == 1);
    header = CMSG_FIRSTHDR(&message);
    ATF_REQUIRE(header != NULL && header->cmsg_level == SOL_SOCKET &&
        header->cmsg_type == SCM_RIGHTS && header->cmsg_len == CMSG_LEN(sizeof(int)));
    memcpy(&received, CMSG_DATA(header), sizeof(received));
    ping(received);
    close(received);
    close(client);
    close(sockets[0]);
    close(sockets[1]);
    ATF_REQUIRE(door_named_unregister(owner, name, 0) == 0);
    ATF_REQUIRE(door_revoke(owner) == 0);
    close(owner);
}

struct connect_race {
    const char *name;
    pthread_barrier_t *barrier;
    int fd, error;
};

static void *
connect_one(void *cookie)
{
    struct connect_race *race = cookie;

    (void)pthread_barrier_wait(race->barrier);
    race->fd = door_named_connect(race->name, 0, NULL);
    race->error = errno;
    return (NULL);
}

ATF_TC_WITHOUT_HEAD(connect_once_concurrent_and_replacement);
ATF_TC_BODY(connect_once_concurrent_and_replacement, tc)
{
    char name[128];
    struct connect_race races[8];
    pthread_t threads[8];
    pthread_barrier_t barrier;
    int owner, client = -1, replacement, next, sockets[2];
    unsigned winners = 0;

    (void)tc;
    owner = publish(name, sizeof(name), "once",
        DOOR_NAMED_CONNECT_ONCE | DOOR_NAMED_NO_PASS);
    ATF_REQUIRE(door_named_lookup(name, 0, NULL) == 0);
    ATF_REQUIRE(door_named_lookup(name, 0, NULL) == 0);
    ATF_REQUIRE(pthread_barrier_init(&barrier, NULL, 8) == 0);
    for (unsigned i = 0; i < 8; i++) {
        races[i] = (struct connect_race){ .name = name, .barrier = &barrier };
        ATF_REQUIRE(pthread_create(&threads[i], NULL, connect_one, &races[i]) == 0);
    }
    for (unsigned i = 0; i < 8; i++) {
        ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);
        if (races[i].fd >= 0) {
            winners++;
            client = races[i].fd;
        } else
            ATF_REQUIRE_EQ(races[i].error, EACCES);
    }
    ATF_REQUIRE_EQ(winners, 1);
    ATF_REQUIRE(pthread_barrier_destroy(&barrier) == 0);
    ping(client);
    ping(client); /* CONNECT_ONCE is not CALL_ONCE. */
    ATF_REQUIRE(door_named_unregister(owner, name, 0) == 0);
    ping(client); /* Existing capabilities survive removal of a name. */
    replacement = door_create(echo, NULL, DOOR_PRIVATE | DOOR_NO_DEPLETION_CB);
    ATF_REQUIRE(replacement >= 0);
    ATF_REQUIRE(door_named_register(replacement, name, DOOR_NAMED_CONNECT_ONCE) == 0);
    next = door_named_connect(name, 0, NULL);
    ATF_REQUIRE(next >= 0);
    ping(next);
    errno = 0;
    ATF_REQUIRE(door_named_connect(name, 0, NULL) == -1);
    ATF_REQUIRE_EQ(errno, EACCES);
    ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    require_no_transfer(sockets[0], client); /* Old policy is immutable. */
    ATF_REQUIRE(send_fd(sockets[0], next) == 1); /* New policy is independent. */
    close(sockets[0]);
    close(sockets[1]);
    close(client);
    close(next);
    ATF_REQUIRE(door_named_unregister(replacement, name, 0) == 0);
    ATF_REQUIRE(door_revoke(owner) == 0);
    ATF_REQUIRE(door_revoke(replacement) == 0);
    close(owner);
    close(replacement);
}

ATF_TC_WITHOUT_HEAD(connect_once_emfile_rollback);
ATF_TC_BODY(connect_once_emfile_rollback, tc)
{
    char name[128];
    struct rlimit old_limit, limited;
    struct door_ctl_connect arg;
    int owner, ctl, occupied[128], used = 0;

    (void)tc;
    owner = publish(name, sizeof(name), "rollback", DOOR_NAMED_CONNECT_ONCE);
    ctl = open("/dev/doorctl", O_RDWR);
    ATF_REQUIRE(ctl >= 0);
    ATF_REQUIRE(getrlimit(RLIMIT_NOFILE, &old_limit) == 0);
    limited = old_limit;
    if (limited.rlim_cur > 64)
        limited.rlim_cur = 64;
    ATF_REQUIRE(setrlimit(RLIMIT_NOFILE, &limited) == 0);
    while (used < 128) {
        occupied[used] = open("/dev/null", O_RDONLY);
        if (occupied[used] < 0)
            break;
        used++;
    }
    ATF_REQUIRE(used > 0 && used < 128 && errno == EMFILE);
    memset(&arg, 0, sizeof(arg));
    arg.dcc_version = DOOR_CTL_ABI_VERSION;
    memcpy(arg.dcc_name, name, strlen(name) + 1);
    errno = 0;
    ATF_REQUIRE(ioctl(ctl, DOORCTL_IOC_CONNECT, &arg) == -1);
    ATF_REQUIRE_EQ(errno, EMFILE);
    close(occupied[--used]);
    ATF_REQUIRE(ioctl(ctl, DOORCTL_IOC_CONNECT, &arg) == 0);
    close(arg.dcc_fd);
    while (used != 0)
        close(occupied[--used]);
    ATF_REQUIRE(setrlimit(RLIMIT_NOFILE, &old_limit) == 0);
    close(ctl);
    ATF_REQUIRE(door_named_unregister(owner, name, 0) == 0);
    ATF_REQUIRE(door_revoke(owner) == 0);
    close(owner);
}

ATF_TC_WITH_CLEANUP(nopass_namefs_clone);
ATF_TC_HEAD(nopass_namefs_clone, tc)
{
    atf_tc_set_md_var(tc, "require.user", "root");
    atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(nopass_namefs_clone, tc)
{
    char name[128];
    int owner, client, clone, anchor, sockets[2];

    (void)tc;
    owner = publish(name, sizeof(name), "clone", DOOR_NAMED_NO_PASS);
    client = door_named_connect(name, 0, NULL);
    ATF_REQUIRE(client >= 0);
    anchor = open("policy.endpoint", O_CREAT | O_RDWR, 0600);
    ATF_REQUIRE(anchor >= 0);
    close(anchor);
    ATF_REQUIRE(fattach(client, "policy.endpoint") == 0);
    clone = open("policy.endpoint", O_RDWR);
    ATF_REQUIRE(clone >= 0);
    ping(clone);
    ATF_REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    require_no_transfer(sockets[0], clone);
    ATF_REQUIRE(fdetach("policy.endpoint") == 0);
    unlink("policy.endpoint");
    close(clone);
    close(client);
    close(sockets[0]);
    close(sockets[1]);
    ATF_REQUIRE(door_named_unregister(owner, name, 0) == 0);
    ATF_REQUIRE(door_revoke(owner) == 0);
    close(owner);
}
ATF_TC_CLEANUP(nopass_namefs_clone, tc)
{
    (void)tc;
    (void)fdetach("policy.endpoint");
    (void)unlink("policy.endpoint");
}

ATF_TP_ADD_TCS(tp)
{
    ATF_TP_ADD_TC(tp, nopass_blocks_unix_and_door_transfer);
    ATF_TP_ADD_TC(tp, default_capability_remains_passable);
    ATF_TP_ADD_TC(tp, connect_once_concurrent_and_replacement);
    ATF_TP_ADD_TC(tp, connect_once_emfile_rollback);
    ATF_TP_ADD_TC(tp, nopass_namefs_clone);
    return (atf_no_error());
}
