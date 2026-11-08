/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _SYS_DOOR_TEST_H_
#define _SYS_DOOR_TEST_H_
#include <sys/types.h>
#include <sys/ioccom.h>

/* Private test-build interface. It is not part of the Door ABI. */
#define DOOR_TEST_PREPARK 1
#define DOOR_TEST_CV_PREPARK 2
#define DOOR_TEST_EXPORT 3
#define DOOR_TEST_CLIENT_COPY 4
#define DOOR_TEST_ASYNC_RESERVED 5
#define DOOR_TEST_NAMEFS_GC 6
#define DOOR_TEST_REPLY_MOVE_INSTALL 7
#define DOOR_TEST_REPLY_MOVE_CLOSE 8

struct door_test_control {
    uint32_t stage;
    int32_t pid;
    int64_t tid; /* 0 matches the first thread at this stage. */
    uint32_t entered;
    uint32_t expired;
    uint32_t active;
    uint32_t reserved;
    uint32_t finished; /* NAMEFS_GC evaluation completed after gate release. */
    /* Explicit amd64 padding: ignored on ARM, zero in STATE. */
    uint32_t padding;
    uint64_t object; /* fsid for NAMEFS_GC; zero for thread-local gates. */
};
struct door_test_inspect {
    int32_t fd;
    uint32_t pending, active, reserved, assigned, delivered, waiting;
};
#define DOOR_TEST_ARM _IOW('T', 1, struct door_test_control)
#define DOOR_TEST_STATE _IOR('T', 2, struct door_test_control)
#define DOOR_TEST_RELEASE _IO('T', 3)
#define DOOR_TEST_INSPECT _IOWR('T', 4, struct door_test_inspect)
#define DOOR_TEST_DRAIN _IO('T', 5)
#define DOOR_TEST_NOBJECTS 7
#define DOOR_TEST_OBJ_DOOR 0
#define DOOR_TEST_OBJ_CALL 1
#define DOOR_TEST_OBJ_BINDING 2
#define DOOR_TEST_OBJ_SHM 3
#define DOOR_TEST_OBJ_MOUNT 4
#define DOOR_TEST_OBJ_GC 5
#define DOOR_TEST_OBJ_GC_PIN 6 /* vfs_ref held by delayed GC, not an object. */
struct door_test_objects {
    uint32_t live[DOOR_TEST_NOBJECTS];
    uint32_t async_jobs;
};
#define DOOR_TEST_OBJECTS _IOR('T', 6, struct door_test_objects)
#ifdef _KERNEL
void door_test_object_add(unsigned int);
void door_test_object_drop(unsigned int);
void door_test_async_begin(void);
void door_test_async_end(void);
void door_test_gc_gate(uint64_t);
void door_test_gc_done(uint64_t);

void door_test_init(void);
void door_test_fini(void);
bool door_test_busy(void);
bool door_test_cv_requested(void);
void door_test_gate(unsigned int);
#endif
#endif
