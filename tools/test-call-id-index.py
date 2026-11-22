#!/usr/bin/env python3
"""Exercise actual ID-index helpers with modeled queue/lock lifetimes.

Portable validation only. Native ATF/kernel tests must run on FreeBSD.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
rpc = (ROOT / 'sys/fs/doorfs/door_rpc.c').read_text()
header = (ROOT / 'sys/sys/door_impl.h').read_text()


def function(name):
    match = re.search(r'(?m)^(?:static __inline u_int|static int|void)\n' + name +
                      r'\([^\n]*\)\n\{.*?^\}', rpc, re.S | re.M)
    if not match:
        raise RuntimeError('Cannot locate helper: ' + name)
    return match[0]


# Audit every queue mutation, not just the happy-path dispatch/return pair.
mutations = 0
for path in (ROOT / 'sys/fs/doorfs').glob('*.c'):
    text = path.read_text()
    pattern = (r'TAILQ_(INSERT_TAIL|INSERT_HEAD|REMOVE)\(&door->d_'
               r'(?:pending|active|async_replies), call,\s*'
               r'(?:dc_link|dc_async_reply_link)\);')
    for match in re.finditer(pattern, text):
        action = 'remove' if match[1] == 'REMOVE' else 'insert'
        expected = f'door_call_id_{action}_locked(door, call);'
        assert text[match.end():].lstrip().startswith(expected), (path, match[0])
        mutations += 1
assert mutations == 19, ('Review changed queue mutation coverage', mutations)
assert 'destroying an indexed Door call' in rpc
core = (ROOT / 'sys/fs/doorfs/door_core.c').read_text()
assert 'LIST_INIT(&door->d_call_ids[i]);' in core
assert 'LIST_EMPTY(&door->d_call_ids[i])' in core
buckets = re.search(r'#define DOOR_CALL_ID_BUCKETS (\d+)', header)[1]

prefix = r'''
#include <sys/queue.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdarg.h>
typedef unsigned int u_int;
struct door;
struct door_call {
    TAILQ_ENTRY(door_call) dc_link;
    TAILQ_ENTRY(door_call) dc_async_reply_link;
    LIST_ENTRY(door_call) dc_id_link;
    struct door *dc_id_owner;
    uint64_t dc_id;
};
LIST_HEAD(door_call_id_head, door_call);
TAILQ_HEAD(door_call_head, door_call);
struct door {
    pthread_mutex_t d_lock;
    struct door_call_id_head d_call_ids[DOOR_CALL_ID_BUCKETS];
    struct door_call_head d_pending, d_active, d_async_replies;
};
static _Thread_local const pthread_mutex_t *held;
#define MA_OWNED 1
#define KASSERT(expr, message) assert(expr)
#define mtx_assert(lock, mode) assert(held == (lock))
static void lock(struct door *d) {
    assert(held == NULL);
    assert(pthread_mutex_lock(&d->d_lock) == 0);
    held = &d->d_lock;
}
static void unlock(struct door *d) {
    assert(held == &d->d_lock);
    held = NULL;
    assert(pthread_mutex_unlock(&d->d_lock) == 0);
}
'''
body = r'''
static void init(struct door *d) {
    memset(d, 0, sizeof(*d));
    assert(pthread_mutex_init(&d->d_lock, NULL) == 0);
    for (u_int i = 0; i < DOOR_CALL_ID_BUCKETS; i++)
        LIST_INIT(&d->d_call_ids[i]);
    TAILQ_INIT(&d->d_pending);
    TAILQ_INIT(&d->d_active);
    TAILQ_INIT(&d->d_async_replies);
}
static void add(struct door *door, struct door_call *call, unsigned stage) {
    if (stage == 1) TAILQ_INSERT_TAIL(&door->d_pending, call, dc_link);
    else if (stage == 2) TAILQ_INSERT_TAIL(&door->d_active, call, dc_link);
    else { assert(stage == 3);
        TAILQ_INSERT_TAIL(&door->d_async_replies, call, dc_async_reply_link);
    }
    door_call_id_insert_locked(door, call);
}
static void remove_call(struct door *door, struct door_call *call, unsigned stage) {
    if (stage == 1) TAILQ_REMOVE(&door->d_pending, call, dc_link);
    else if (stage == 2) TAILQ_REMOVE(&door->d_active, call, dc_link);
    else { assert(stage == 3);
        TAILQ_REMOVE(&door->d_async_replies, call, dc_async_reply_link);
    }
    door_call_id_remove_locked(door, call);
}
static int reference(struct door *d, uint64_t id) {
    struct door_call *c;
    TAILQ_FOREACH(c, &d->d_pending, dc_link)
        if (c->dc_id == id) return EEXIST;
    TAILQ_FOREACH(c, &d->d_active, dc_link)
        if (c->dc_id == id) return EEXIST;
    TAILQ_FOREACH(c, &d->d_async_replies, dc_async_reply_link)
        if (c->dc_id == id) return EEXIST;
    return 0;
}
static uint64_t state = 1;
static uint64_t random64(void) {
    state ^= state << 13; state ^= state >> 7; state ^= state << 17;
    return state;
}
struct race { struct door *d; struct door_call call; bool won; };
static void *admit(void *cookie) {
    struct race *r = cookie;
    lock(r->d);
    if (door_call_check_id_locked(r->d, r->call.dc_id) == 0) {
        add(r->d, &r->call, 1); r->won = true;
    }
    unlock(r->d);
    return NULL;
}
int main(void) {
    struct door d, other;
    struct door_call calls[512] = {0};
    unsigned stages[512] = {0};
    init(&d); init(&other);
    lock(&d);
    /* Force a single full collision chain; duplicate generated IDs are legal. */
    uint64_t candidate = 1;
    for (unsigned i = 0; i < 512; i++) {
        while (door_call_id_bucket(candidate) != 0) candidate++;
        calls[i].dc_id = candidate++;
        add(&d, &calls[i], 1); stages[i] = 1;
    }
    for (unsigned i = 0; i < 512; i++) {
        assert(door_call_check_id_locked(&d, calls[i].dc_id) == EEXIST);
        remove_call(&d, &calls[i], 1);
        assert(door_call_check_id_locked(&d, calls[i].dc_id) == 0);
        stages[i] = 0;
    }
    for (unsigned iteration = 0; iteration < 100000; iteration++) {
        unsigned i = random64() % 512;
        if (stages[i]) remove_call(&d, &calls[i], stages[i]);
        stages[i] = random64() % 4;
        /* Include repeated IDs and both 64-bit boundary values. */
        calls[i].dc_id = iteration % 17 == 0 ? UINT64_MAX : random64() % 1024;
        if (stages[i]) add(&d, &calls[i], stages[i]);
        for (unsigned n = 0; n < 8; n++) {
            uint64_t id = n == 0 ? calls[i].dc_id : random64() % 1024;
            assert(door_call_check_id_locked(&d, id) == reference(&d, id));
        }
    }
    /* Revoke/teardown removes every queue member; no index ownership remains. */
    for (unsigned i = 0; i < 512; i++) {
        if (stages[i]) remove_call(&d, &calls[i], stages[i]);
        assert(calls[i].dc_id_owner == NULL);
    }
    for (unsigned i = 0; i < DOOR_CALL_ID_BUCKETS; i++)
        assert(LIST_EMPTY(&d.d_call_ids[i]));
    unlock(&d);

    /* A failed duplicate admission never publishes a second entry. */
    for (unsigned round = 0; round < 100; round++) {
        pthread_t threads[8]; struct race races[8] = {0};
        unsigned winners = 0;
        for (unsigned i = 0; i < 8; i++) {
            races[i].d = &d; races[i].call.dc_id = 42;
            assert(pthread_create(&threads[i], NULL, admit, &races[i]) == 0);
        }
        for (unsigned i = 0; i < 8; i++) {
            assert(pthread_join(threads[i], NULL) == 0);
            winners += races[i].won;
        }
        assert(winners == 1);
        lock(&d);
        for (unsigned i = 0; i < 8; i++)
            if (races[i].won) remove_call(&d, &races[i].call, 1);
        unlock(&d);
    }
    /* The same ID is independent in different Door objects. */
    calls[0].dc_id = calls[1].dc_id = 42;
    lock(&d); add(&d, &calls[0], 1); unlock(&d);
    lock(&other); assert(door_call_check_id_locked(&other, 42) == 0);
    add(&other, &calls[1], 1); remove_call(&other, &calls[1], 1); unlock(&other);
    lock(&d); assert(door_call_check_id_locked(&d, 42) == EEXIST);
    remove_call(&d, &calls[0], 1); unlock(&d);
    assert(pthread_mutex_destroy(&d.d_lock) == 0);
    assert(pthread_mutex_destroy(&other.d_lock) == 0);
    puts("PASS: actual index helpers; collisions, queue equivalence, ID reuse, concurrent admission and isolation");
    return 0;
}
'''
helpers = '\n\n'.join(function(name) for name in (
    'door_call_id_bucket', 'door_call_id_insert_locked',
    'door_call_id_remove_locked', 'door_call_check_id_locked'))
with tempfile.TemporaryDirectory(prefix='door-id-model-') as tmp:
    source = Path(tmp) / 'model.c'
    binary = Path(tmp) / 'model'
    source.write_text(f'#define DOOR_CALL_ID_BUCKETS {buckets}\n' + prefix + helpers + body)
    command = shlex.split(os.environ.get('CC', 'cc'))
    command += ['-std=gnu17', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread']
    command += shlex.split(os.environ.get('MODEL_CFLAGS', ''))
    subprocess.run(command + [str(source), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print(f'PASS: all {mutations} queue mutations update the ID index')
