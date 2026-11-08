/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Raw mixed-bitness smoke test. No libdoor or ATF linkage is needed.
 */
#include <sys/types.h>
#include <stdint.h>
#include <sys/door_core.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REQUIRE(x) do { if (!(x)) errx(1, "%s:%d: %s (errno=%d)", \
    __FILE__, __LINE__, #x, errno); } while (0)
#define HIGH_ID UINT64_C(0xf123456789abcdef)
static pid_t child;

static void
cleanup_child(void)
{
    int status;
    if (child > 0) {
        (void)kill(child, SIGTERM);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR)
            ;
        child = 0;
    }
}

static int
sc(long op, long a, long b, long c)
{
    return ((int)__syscall((quad_t)SYS_door, op, a, b, c, 0L, 0L));
}

static void
write_all(int fd, const void *data, size_t size)
{
    const char *p = data;
    ssize_t n;
    while (size != 0) {
        n = write(fd, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        REQUIRE(n > 0);
        p += n;
        size -= (size_t)n;
    }
}

static void
read_all(int fd, void *data, size_t size)
{
    char *p = data;
    ssize_t n;
    while (size != 0) {
        n = read(fd, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        REQUIRE(n > 0);
        p += n;
        size -= (size_t)n;
    }
}

static void
send_doors(int sock, const int doors[2])
{
    union { struct cmsghdr align; char bytes[CMSG_SPACE(2 * sizeof(int))]; } c;
    struct cmsghdr *h;
    struct msghdr msg;
    struct iovec iov;
    char tag = 'D';
    memset(&c, 0, sizeof(c));
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = &tag;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = c.bytes;
    msg.msg_controllen = sizeof(c.bytes);
    h = CMSG_FIRSTHDR(&msg);
    h->cmsg_level = SOL_SOCKET;
    h->cmsg_type = SCM_RIGHTS;
    h->cmsg_len = CMSG_LEN(2 * sizeof(int));
    memcpy(CMSG_DATA(h), doors, 2 * sizeof(int));
    REQUIRE(sendmsg(sock, &msg, 0) == 1);
}

static void
recv_doors(int sock, int doors[2])
{
    union { struct cmsghdr align; char bytes[CMSG_SPACE(2 * sizeof(int))]; } c;
    struct cmsghdr *h;
    struct msghdr msg;
    struct iovec iov;
    char tag;
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = &tag;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = c.bytes;
    msg.msg_controllen = sizeof(c.bytes);
    REQUIRE(recvmsg(sock, &msg, 0) == 1 && tag == 'D');
    REQUIRE((msg.msg_flags & MSG_CTRUNC) == 0);
    h = CMSG_FIRSTHDR(&msg);
    REQUIRE(h != NULL && h->cmsg_level == SOL_SOCKET &&
        h->cmsg_type == SCM_RIGHTS && h->cmsg_len == CMSG_LEN(2 * sizeof(int)));
    memcpy(doors, CMSG_DATA(h), 2 * sizeof(int));
}

struct server_state {
    pthread_mutex_t lock;
    pthread_cond_t cv;
    int sock, ready;
    int release;
};
struct worker_arg { struct server_state *state; int door, oneway; };

static void *
worker(void *data)
{
    struct worker_arg *w = data;
    struct server_state *s = w->state;
    struct door_ioc_return_shm ret;
    struct door_ioc_cred cred;
    struct door_kdesc input, output;
    char request[8192], reply[2] = { 'o', 'k' }, tag;
    char *payload;
    int held = -1, rc;
    uint64_t bytes;

    REQUIRE(sc(DOOR_SC_BIND, w->door, 0, 0) == 0);
    REQUIRE(pthread_mutex_lock(&s->lock) == 0);
    s->ready++;
    REQUIRE(pthread_cond_broadcast(&s->cv) == 0);
    REQUIRE(pthread_mutex_unlock(&s->lock) == 0);
    memset(&ret, 0, sizeof(ret));
    ret.dirs_return.dir_version = DOOR_ABI_VERSION;
    ret.dirs_return.dir_reply_fd = -1;
    for (;;) {
        ret.dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
        ret.dirs_return.dir_request_ptr = (uintptr_t)request;
        ret.dirs_return.dir_request_size = sizeof(request);
        ret.dirs_return.dir_request_desc_ptr = (uintptr_t)&input;
        ret.dirs_return.dir_request_desc_count = 1;
        rc = sc(DOOR_SC_RETURN, (long)(uintptr_t)&ret, 0, 0);
        if (held >= 0) {
            REQUIRE(close(held) == 0);
            held = -1;
        }
        if (rc < 0) {
            REQUIRE(errno == EBADF || errno == ECANCELED || errno == EINVAL);
            break;
        }
        REQUIRE(ret.dirs_return.dir_padding == 0);
        ret.dirs_return.dir_reply_ptr = 0;
        ret.dirs_return.dir_reply_size = 0;
        ret.dirs_return.dir_reply_desc_ptr = 0;
        ret.dirs_return.dir_reply_desc_count = 0;
        if (ret.dirs_return.dir_call_id == 0) {
            REQUIRE((ret.dirs_return.dir_flags & DOOR_RETURN_F_REWAIT) != 0);
            continue;
        }
        if ((ret.dirs_return.dir_flags & DOOR_RETURN_F_SHM) != 0) {
            payload = (char *)(uintptr_t)ret.dirs_shm_ptr;
            bytes = ret.dirs_shm.disr_size;
        } else {
            payload = request;
            bytes = ret.dirs_return.dir_request_size;
        }
        REQUIRE(bytes > 0 && payload != NULL);
        tag = payload[0];
        if (!w->oneway) {
            memset(&cred, 0, sizeof(cred));
            cred.dicr_version = DOOR_ABI_VERSION;
            cred.dicr_call_id = ret.dirs_return.dir_call_id;
            REQUIRE(sc(DOOR_SC_CRED, (long)(uintptr_t)&cred, 0, 0) == 0);
            REQUIRE(cred.dicr_cred.dc_pid > 0);
        }
        if (tag == 'H') {
            write_all(s->sock, "H", 1);
            REQUIRE(pthread_mutex_lock(&s->lock) == 0);
            while (!s->release)
                REQUIRE(pthread_cond_wait(&s->cv, &s->lock) == 0);
            REQUIRE(pthread_mutex_unlock(&s->lock) == 0);
        } else if (w->oneway) {
            REQUIRE(tag == 'O');
            write_all(s->sock, "O", 1);
        } else {
            REQUIRE(tag == 'C' || tag == 'A' || tag == 'S');
            if (tag == 'C')
                REQUIRE(bytes == sizeof(request) && payload[1] == 'x' &&
                    payload[sizeof(request) - 1] == 'x');
        }
        if (!w->oneway) {
            ret.dirs_return.dir_reply_ptr = (uintptr_t)reply;
            ret.dirs_return.dir_reply_size = sizeof(reply);
        }
        if (ret.dirs_return.dir_request_desc_count != 0) {
            held = input.dd_fd;
            REQUIRE(fcntl(held, F_GETFD) >= 0);
            output.dd_fd = held;
            output.dd_flags = 0;
            ret.dirs_return.dir_reply_desc_ptr = (uintptr_t)&output;
            ret.dirs_return.dir_reply_desc_count = 1;
        }
    }
    (void)sc(DOOR_SC_WORKER_EXIT, 0, 0, 0);
    return (NULL);
}

static int
server(int sock)
{
    struct server_state state;
    struct worker_arg args[2];
    struct door_ioc_shm_attach shm;
    pthread_t threads[2];
    int doors[2], i;
    char command;
    memset(&state, 0, sizeof(state));
    memset(&shm, 0, sizeof(shm));
    state.sock = sock;
    REQUIRE(pthread_mutex_init(&state.lock, NULL) == 0);
    REQUIRE(pthread_cond_init(&state.cv, NULL) == 0);
    for (i = 0; i < 2; i++) {
        doors[i] = sc(DOOR_SC_CREATE, i == 1 ? DOOR_ONEWAY : 0,
            (long)(uintptr_t)&state, DOOR_CREATE_F_NORMAL);
        REQUIRE(doors[i] >= 0);
        args[i].state = &state;
        args[i].door = doors[i];
        args[i].oneway = i;
        REQUIRE(pthread_create(&threads[i], NULL, worker, &args[i]) == 0);
    }
    REQUIRE(pthread_mutex_lock(&state.lock) == 0);
    while (state.ready != 2)
        REQUIRE(pthread_cond_wait(&state.cv, &state.lock) == 0);
    REQUIRE(pthread_mutex_unlock(&state.lock) == 0);
    send_doors(sock, doors);
    for (;;) {
        read_all(sock, &command, 1);
        if (command == 'Q')
            break;
        if (command == 'R') {
            REQUIRE(pthread_mutex_lock(&state.lock) == 0);
            state.release = 1;
            REQUIRE(pthread_cond_broadcast(&state.cv) == 0);
            REQUIRE(pthread_mutex_unlock(&state.lock) == 0);
        } else if (command == 'V') {
            struct door_ioc_shm_view view;
            read_all(sock, &view, sizeof(view));
            REQUIRE(sc(DOOR_SC_SHM_VIEW_ATTACH, doors[0],
                (long)(uintptr_t)&view, 0) == 0);
            const char *bytes = (const char *)(uintptr_t)view.disv_addr;
            size_t page = (size_t)getpagesize();
            REQUIRE(view.disv_size == 2 * page && bytes[0] == 'B' && bytes[page] == 'A');
            REQUIRE(mprotect((void *)(uintptr_t)view.disv_addr, 2 * page,
                PROT_READ | PROT_WRITE) == -1 && errno == EACCES);
            REQUIRE(sc(DOOR_SC_SHM_VIEW_RELEASE, doors[0],
                (long)(uintptr_t)&view, 0) == 0);
            write_all(sock, "V", 1);
        } else {
            REQUIRE(command == 'S');
            read_all(sock, &shm.disa_region, sizeof(shm.disa_region));
            shm.disa_version = DOOR_ABI_VERSION;
            shm.disa_flags = DOOR_SHM_F_RW;
            REQUIRE(sc(DOOR_SC_SHM_ATTACH, doors[0],
                (long)(uintptr_t)&shm, 0) == 0);
            write_all(sock, "S", 1);
        }
    }
    for (i = 0; i < 2; i++)
        REQUIRE(sc(DOOR_SC_REVOKE, doors[i], 0, 0) == 0);
    for (i = 0; i < 2; i++) {
        REQUIRE(pthread_join(threads[i], NULL) == 0);
        REQUIRE(close(doors[i]) == 0);
    }
    if (shm.disa_addr != 0)
        REQUIRE(munmap((void *)(uintptr_t)shm.disa_addr,
            (size_t)shm.disa_size) == 0);
    REQUIRE(pthread_cond_destroy(&state.cv) == 0);
    REQUIRE(pthread_mutex_destroy(&state.lock) == 0);
    REQUIRE(close(sock) == 0);
    return (0);
}

static void
async_case(int fd, int sock, int cancel)
{
    struct door_ioc_async_call call;
    struct door_ioc_async_cancel stop;
    struct door_ioc_return_shm ret;
    struct door_async_completion header;
    char buffer[128], request = cancel ? 'H' : 'A', ack;
    int completion;
    completion = sc(DOOR_SC_CREATE, DOOR_ONEWAY, 0, DOOR_CREATE_F_NORMAL);
    REQUIRE(completion >= 0);
    REQUIRE(sc(DOOR_SC_BIND, completion, 0, 0) == 0);
    memset(&call, 0, sizeof(call));
    call.diac_version = DOOR_ABI_VERSION;
    call.diac_call_id = HIGH_ID;
    call.diac_request_ptr = (uintptr_t)&request;
    call.diac_request_size = 1;
    call.diac_completion_fd = completion;
    REQUIRE(sc(DOOR_SC_ASYNC_CALL, fd, (long)(uintptr_t)&call, 0) == 0);
    if (cancel) {
        read_all(sock, &ack, 1);
        REQUIRE(ack == 'H'); /* callback is held until explicit R */
        memset(&stop, 0, sizeof(stop));
        stop.diacc_version = DOOR_ABI_VERSION;
        stop.diacc_completion_fd = completion;
        stop.diacc_call_id = HIGH_ID;
        REQUIRE(sc(DOOR_SC_ASYNC_CANCEL_FULL, fd,
            (long)(uintptr_t)&stop, 0) == 0);
    }
    memset(&ret, 0, sizeof(ret));
    ret.dirs_return.dir_version = DOOR_ABI_VERSION;
    ret.dirs_return.dir_flags = DOOR_RETURN_F_RESIZABLE;
    ret.dirs_return.dir_reply_fd = -1;
    ret.dirs_return.dir_request_ptr = (uintptr_t)buffer;
    ret.dirs_return.dir_request_size = sizeof(buffer);
    REQUIRE(sc(DOOR_SC_RETURN, (long)(uintptr_t)&ret, 0, 0) == 0);
    REQUIRE(ret.dirs_return.dir_request_size >= sizeof(header));
    memcpy(&header, buffer, sizeof(header));
    REQUIRE(header.dac_version == DOOR_ABI_VERSION &&
        header.dac_call_id == HIGH_ID);
    REQUIRE(header.dac_status == (cancel ? ECANCELED : 0));
    REQUIRE(header.dac_data_size == (cancel ? 0 : 2));
    REQUIRE(ret.dirs_return.dir_request_size == sizeof(header) + header.dac_data_size);
    if (cancel) {
        REQUIRE((header.dac_flags & DOOR_ASYNC_C_CANCELLED) != 0);
        write_all(sock, "R", 1);
    } else
        REQUIRE(memcmp(buffer + sizeof(header), "ok", 2) == 0);
    REQUIRE(sc(DOOR_SC_WORKER_EXIT, 0, 0, 0) == 0);
    REQUIRE(sc(DOOR_SC_REVOKE, completion, 0, 0) == 0);
    REQUIRE(close(completion) == 0);
}

static void
view_case(int fd, int sock)
{
    struct door_ioc_shm_create sources[2];
    struct door_ioc_shm_view_segment parts[2];
    struct door_ioc_shm_view view;
    struct door_ioc_shm_destroy destroy;
    size_t page = (size_t)getpagesize();
    char ack;

    for (unsigned int i = 0; i < 2; i++) {
        memset(&sources[i], 0, sizeof(sources[i]));
        sources[i].disc_version = DOOR_ABI_VERSION;
        sources[i].disc_flags = DOOR_SHM_F_RW;
        sources[i].disc_size = page;
        REQUIRE(sc(DOOR_SC_SHM_CREATE, fd, (long)(uintptr_t)&sources[i], 0) == 0);
        memset((void *)(uintptr_t)sources[i].disc_addr, 'A' + (int)i, page);
        parts[1-i].disvs_region = sources[i].disc_region;
        parts[1-i].disvs_offset = 0;
        parts[1-i].disvs_size = page;
        parts[1-i].disvs_uniquifier = sources[i].disc_uniquifier;
    }
    memset(&view, 0, sizeof(view));
    view.disv_version = DOOR_ABI_VERSION;
    view.disv_segments_ptr = (uintptr_t)parts;
    view.disv_segment_count = 2;
    REQUIRE(sc(DOOR_SC_SHM_VIEW_PUBLISH, fd, (long)(uintptr_t)&view, 0) == 0);
    write_all(sock, "V", 1);
    write_all(sock, &view, sizeof(view));
    read_all(sock, &ack, 1);
    REQUIRE(ack == 'V');
    REQUIRE(sc(DOOR_SC_SHM_VIEW_QUERY, fd, (long)(uintptr_t)&view, 0) == 0);
    REQUIRE(view.disv_state == DOOR_SHM_VIEW_RELEASED);
    REQUIRE(sc(DOOR_SC_SHM_VIEW_DESTROY, fd, (long)(uintptr_t)&view, 0) == 0);
    for (unsigned int i = 0; i < 2; i++) {
        memset(&destroy, 0, sizeof(destroy));
        destroy.disd_version = DOOR_ABI_VERSION;
        destroy.disd_region = sources[i].disc_region;
        REQUIRE(sc(DOOR_SC_SHM_DESTROY, fd, (long)(uintptr_t)&destroy, 0) == 0);
        REQUIRE(munmap((void *)(uintptr_t)sources[i].disc_addr, page) == 0);
    }
}

static int
client(const char *server_path)
{
    struct door_ioc_call call;
    struct door_ioc_info info;
    struct door_ioc_shm_create shm;
    struct door_ioc_call_shm shared;
    struct door_ioc_shm_destroy destroy;
    struct door_kdesc send, received;
    char request[8192], reply[16], number[32], ack;
    int sockets[2], doors[2], source, status;
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    child = fork();
    REQUIRE(child >= 0);
    if (child == 0) {
        REQUIRE(close(sockets[0]) == 0);
        snprintf(number, sizeof(number), "%d", sockets[1]);
        execl(server_path, server_path, "--server", number, (char *)NULL);
        err(1, "exec server");
    }
    REQUIRE(atexit(cleanup_child) == 0);
    REQUIRE(close(sockets[1]) == 0);
    recv_doors(sockets[0], doors);
    memset(&info, 0, sizeof(info));
    REQUIRE(sc(DOOR_SC_INFO, doors[0], (long)(uintptr_t)&info, 0) == 0);
    REQUIRE(info.di_target == child);
    memset(&call, 0, sizeof(call));
    memset(request, 'x', sizeof(request));
    request[0] = 'C';
    source = open("/dev/null", O_RDWR);
    REQUIRE(source >= 0);
    send.dd_fd = source;
    send.dd_flags = 0;
    call.dic_version = DOOR_ABI_VERSION;
    call.dic_call_id = HIGH_ID;
    call.dic_request_ptr = (uintptr_t)request;
    call.dic_request_size = sizeof(request);
    call.dic_reply_ptr = (uintptr_t)reply;
    call.dic_reply_size = sizeof(reply);
    call.dic_send_fd = -1;
    call.dic_send_desc_ptr = (uintptr_t)&send;
    call.dic_send_desc_count = 1;
    call.dic_recv_desc_ptr = (uintptr_t)&received;
    call.dic_recv_desc_count = 1;
#if UINTPTR_MAX == UINT32_MAX
    call.dic_request_ptr |= UINT64_C(1) << 32;
    REQUIRE(sc(DOOR_SC_CALL, doors[0], (long)(uintptr_t)&call, 0) == -1 && errno == EFAULT);
    call.dic_request_ptr = (uintptr_t)request;
    call.dic_request_size = UINT64_C(1) << 32;
    REQUIRE(sc(DOOR_SC_CALL, doors[0], (long)(uintptr_t)&call, 0) == -1 && errno == EOVERFLOW);
    call.dic_request_size = sizeof(request);
    REQUIRE(sc(DOOR_SC_FAST_CALL, doors[0], 0, 0) == -1 && errno == ENOSYS);
#endif
    REQUIRE(sc(DOOR_SC_CALL, doors[0], (long)(uintptr_t)&call, 0) == 0);
    REQUIRE(call.dic_call_id == HIGH_ID && call.dic_reply_size == 2 &&
        memcmp(reply, "ok", 2) == 0);
    REQUIRE(call.dic_recv_desc_count == 1 && fcntl(received.dd_fd, F_GETFD) >= 0);
    REQUIRE(close(received.dd_fd) == 0 && close(source) == 0);
    memset(&shm, 0, sizeof(shm));
    shm.disc_version = DOOR_ABI_VERSION;
    shm.disc_flags = DOOR_SHM_F_RW;
    shm.disc_size = 4096;
    REQUIRE(sc(DOOR_SC_SHM_CREATE, doors[0], (long)(uintptr_t)&shm, 0) == 0);
    *(char *)(uintptr_t)shm.disc_addr = 'S';
    write_all(sockets[0], "S", 1);
    write_all(sockets[0], &shm.disc_region, sizeof(shm.disc_region));
    read_all(sockets[0], &ack, 1);
    REQUIRE(ack == 'S');
    memset(&shared, 0, sizeof(shared));
    shared.dics_call.dic_version = DOOR_ABI_VERSION;
    shared.dics_call.dic_send_fd = -1;
    shared.dics_call.dic_reply_ptr = (uintptr_t)reply;
    shared.dics_call.dic_reply_size = sizeof(reply);
    shared.dics_shm.disr_region = shm.disc_region;
    shared.dics_shm.disr_size = 1;
    shared.dics_uniquifier = shm.disc_uniquifier;
    REQUIRE(sc(DOOR_SC_CALL_SHM, doors[0], (long)(uintptr_t)&shared, 0) == 0);
    REQUIRE(shared.dics_call.dic_reply_size == 2 && memcmp(reply, "ok", 2) == 0);
    memset(&destroy, 0, sizeof(destroy));
    destroy.disd_version = DOOR_ABI_VERSION;
    destroy.disd_region = shm.disc_region;
    REQUIRE(sc(DOOR_SC_SHM_DESTROY, doors[0], (long)(uintptr_t)&destroy, 0) == 0);
    REQUIRE(munmap((void *)(uintptr_t)shm.disc_addr, (size_t)shm.disc_size) == 0);
    ack = 'O';
    REQUIRE(sc(DOOR_SC_ONEWAY, doors[1], (long)(uintptr_t)&ack, 1) == 0);
    read_all(sockets[0], &ack, 1);
    REQUIRE(ack == 'O');
    view_case(doors[0], sockets[0]);
    async_case(doors[0], sockets[0], 0);
    async_case(doors[0], sockets[0], 1);
    write_all(sockets[0], "Q", 1);
    REQUIRE(close(doors[0]) == 0 && close(doors[1]) == 0);
    REQUIRE(close(sockets[0]) == 0);
    REQUIRE(waitpid(child, &status, 0) == child);
    child = 0;
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return (0);
}

int
main(int argc, char **argv)
{
    (void)alarm(30);
    if (argc == 3 && strcmp(argv[1], "--server") == 0)
        return (server(atoi(argv[2])));
    if (argc != 2)
        errx(1, "usage: %s SERVER_EXECUTABLE", argv[0]);
    return (client(argv[1]));
}
