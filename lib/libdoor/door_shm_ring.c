/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "libdoor_impl.h"

#define DOOR_RING_MAGIC UINT64_C(0x444f4f5252494e47)
#define DOOR_RING_VERSION 1
#define DOOR_RING_ALIGN 64
#define DOOR_RING_STATE_PRODUCER_RESERVED 0x00000001U
#define DOOR_RING_STATE_CONSUMER_ACQUIRED 0x00000002U

struct door_ring_header {
    uint64_t drh_magic;
    uint32_t drh_version;
    uint32_t drh_header_size;
    uint64_t drh_region_size;
    uint64_t drh_slot_size;
    uint64_t drh_slot_stride;
    uint64_t drh_slot_count;
    uint64_t drh_producer;
    uint64_t drh_consumer;
} __attribute__((__aligned__(8)));

struct door_ring_slot {
    uint64_t drs_sequence;
    uint64_t drs_length;
    uint64_t drs_resv0;
    uint64_t drs_resv1;
} __attribute__((__aligned__(8)));

_Static_assert(_Alignof(struct door_ring_header) >= 8,
    "ring header must support aligned 64-bit atomics");
_Static_assert(_Alignof(struct door_ring_slot) >= 8,
    "ring slot must support aligned 64-bit atomics");
_Static_assert(sizeof(struct door_ring_header) == DOOR_RING_ALIGN,
    "ring header layout changed");
_Static_assert(sizeof(struct door_ring_slot) == 32,
    "ring slot layout changed");

/* Shared ring records must have identical offsets in both data models. */
_Static_assert(offsetof(struct door_ring_header, drh_magic) == 0,
    "door_ring_header.drh_magic wire offset");
_Static_assert(offsetof(struct door_ring_header, drh_version) == 8,
    "door_ring_header.drh_version wire offset");
_Static_assert(offsetof(struct door_ring_header, drh_header_size) == 12,
    "door_ring_header.drh_header_size wire offset");
_Static_assert(offsetof(struct door_ring_header, drh_region_size) == 16,
    "door_ring_header.drh_region_size wire offset");
_Static_assert(offsetof(struct door_ring_header, drh_slot_size) == 24,
    "door_ring_header.drh_slot_size wire offset");
_Static_assert(offsetof(struct door_ring_header, drh_slot_stride) == 32,
    "door_ring_header.drh_slot_stride wire offset");
_Static_assert(offsetof(struct door_ring_header, drh_slot_count) == 40,
    "door_ring_header.drh_slot_count wire offset");
_Static_assert(offsetof(struct door_ring_header, drh_producer) == 48,
    "door_ring_header.drh_producer wire offset");
_Static_assert(offsetof(struct door_ring_header, drh_consumer) == 56,
    "door_ring_header.drh_consumer wire offset");
_Static_assert(offsetof(struct door_ring_slot, drs_sequence) == 0,
    "door_ring_slot.drs_sequence wire offset");
_Static_assert(offsetof(struct door_ring_slot, drs_length) == 8,
    "door_ring_slot.drs_length wire offset");
_Static_assert(offsetof(struct door_ring_slot, drs_resv0) == 16,
    "door_ring_slot.drs_resv0 wire offset");
_Static_assert(offsetof(struct door_ring_slot, drs_resv1) == 24,
    "door_ring_slot.drs_resv1 wire offset");

static int
door_ring_align(size_t value, size_t *result)
{
    if (value > SIZE_MAX - (DOOR_RING_ALIGN - 1))
        return (-1);

    *result = roundup2(value, DOOR_RING_ALIGN);
    return (0);
}

static struct door_ring_header *
door_ring_header(door_shm_ring_t *ring)
{
    return ((struct door_ring_header *)ring->dsr_shm.dsh_addr);
}

static struct door_ring_slot *
door_ring_slot(door_shm_ring_t *ring, uint64_t sequence)
{
    unsigned char *base;
    uint64_t index;

    base = ring->dsr_shm.dsh_addr;
    index = sequence % ring->dsr_slot_count;
    return ((struct door_ring_slot *)(void *)(base + DOOR_RING_ALIGN +
        index * ring->dsr_slot_stride));
}

static void *
door_ring_payload(struct door_ring_slot *slot)
{
    return ((unsigned char *)(void *)slot + sizeof(*slot));
}

static int
door_ring_load_layout(door_shm_ring_t *ring, uint32_t role)
{
    struct door_ring_header *header;
    uint64_t magic, region_size, slot_size, slot_stride, slot_count;
    uint64_t slots_size;

    header = door_ring_header(ring);
    magic = __atomic_load_n(&header->drh_magic, __ATOMIC_ACQUIRE);
    region_size = __atomic_load_n(&header->drh_region_size, __ATOMIC_RELAXED);
    slot_size = __atomic_load_n(&header->drh_slot_size, __ATOMIC_RELAXED);
    slot_stride = __atomic_load_n(&header->drh_slot_stride, __ATOMIC_RELAXED);
    slot_count = __atomic_load_n(&header->drh_slot_count, __ATOMIC_RELAXED);
    if (magic != DOOR_RING_MAGIC ||
        __atomic_load_n(&header->drh_version, __ATOMIC_RELAXED) !=
        DOOR_RING_VERSION ||
        __atomic_load_n(&header->drh_header_size, __ATOMIC_RELAXED) !=
        DOOR_RING_ALIGN || region_size != ring->dsr_shm.dsh_size ||
        region_size < DOOR_RING_ALIGN || slot_size == 0 || slot_count < 2 ||
        slot_stride < sizeof(struct door_ring_slot) ||
        slot_stride % DOOR_RING_ALIGN != 0 ||
        slot_size > slot_stride - sizeof(struct door_ring_slot) ||
        slot_count > (UINT64_MAX - DOOR_RING_ALIGN) / slot_stride) {
        errno = EPROTO;
        return (-1);
    }

    slots_size = slot_count * slot_stride;
    if (slots_size > region_size - DOOR_RING_ALIGN ||
        __atomic_load_n(&header->drh_magic, __ATOMIC_ACQUIRE) != magic) {
        errno = EPROTO;
        return (-1);
    }

    ring->dsr_slot_size = slot_size;
    ring->dsr_slot_stride = slot_stride;
    ring->dsr_slot_count = slot_count;
    ring->dsr_local_producer =
        __atomic_load_n(&header->drh_producer, __ATOMIC_ACQUIRE);
    ring->dsr_local_consumer =
        __atomic_load_n(&header->drh_consumer, __ATOMIC_ACQUIRE);
    ring->dsr_role = role;
    return (0);
}

int
door_shm_ring_create(int fd, size_t slot_size, size_t slot_count,
    door_shm_ring_t *ring)
{
    struct door_ring_header *header;
    struct door_ring_slot *slot;
    size_t stride, region_size;
    uint64_t i;

    if (fd < 0 || ring == NULL || slot_size == 0 || slot_count < 2 ||
        door_ring_align(sizeof(*slot) + slot_size, &stride) == -1 ||
        slot_count > (SIZE_MAX - DOOR_RING_ALIGN) / stride) {
        errno = EINVAL;
        return (-1);
    }

    region_size = DOOR_RING_ALIGN + slot_count * stride;
    memset(ring, 0, sizeof(*ring));
    ring->dsr_shm.dsh_fd = -1;
    if (door_shm_create(fd, region_size, DOOR_SHM_RW, &ring->dsr_shm) == -1)
        return (-1);

    memset(ring->dsr_shm.dsh_addr, 0, region_size);
    header = door_ring_header(ring);
    header->drh_version = DOOR_RING_VERSION;
    header->drh_header_size = DOOR_RING_ALIGN;
    header->drh_region_size = region_size;
    header->drh_slot_size = slot_size;
    header->drh_slot_stride = stride;
    header->drh_slot_count = slot_count;
    for (i = 0; i < slot_count; i++) {
        slot = (struct door_ring_slot *)(void *)
            ((unsigned char *)ring->dsr_shm.dsh_addr + DOOR_RING_ALIGN +
            i * stride);
        __atomic_store_n(&slot->drs_sequence, i, __ATOMIC_RELAXED);
    }

    /* Publish initialization last; attach acquires magic before using layout. */
    __atomic_store_n(&header->drh_magic, DOOR_RING_MAGIC, __ATOMIC_RELEASE);
    return (door_ring_load_layout(ring, DOOR_SHM_RING_PRODUCER));
}

int
door_shm_ring_attach(int fd, door_shm_id_t region, uint_t role,
    door_shm_ring_t *ring)
{
    int error;

    if (ring == NULL || (role != DOOR_SHM_RING_PRODUCER &&
        role != DOOR_SHM_RING_CONSUMER)) {
        errno = EINVAL;
        return (-1);
    }

    memset(ring, 0, sizeof(*ring));
    ring->dsr_shm.dsh_fd = -1;
    if (door_shm_attach(fd, region, DOOR_SHM_RW, &ring->dsr_shm) == -1)
        return (-1);

    if (door_ring_load_layout(ring, role) == 0)
        return (0);

    error = errno;
    (void)door_shm_unmap(&ring->dsr_shm);
    memset(ring, 0, sizeof(*ring));
    ring->dsr_shm.dsh_fd = -1;
    errno = error;
    return (-1);
}

int
door_shm_ring_reserve(door_shm_ring_t *ring, door_shm_ring_writer_t *writer)
{
    struct door_ring_header *header;
    struct door_ring_slot *slot;
    uint64_t consumer, producer, sequence;
    size_t offset;

    if (ring == NULL || writer == NULL ||
        ring->dsr_role != DOOR_SHM_RING_PRODUCER) {
        errno = EINVAL;
        return (-1);
    }

    if ((ring->dsr_resv & DOOR_RING_STATE_PRODUCER_RESERVED) != 0) {
        errno = EBUSY;
        return (-1);
    }

    header = door_ring_header(ring);
    producer = ring->dsr_local_producer;
    consumer = __atomic_load_n(&header->drh_consumer, __ATOMIC_ACQUIRE);
    if (consumer > producer || producer - consumer > ring->dsr_slot_count) {
        errno = EPROTO;
        return (-1);
    }

    if (producer - consumer == ring->dsr_slot_count) {
        errno = EAGAIN;
        return (-1);
    }

    /* Reject exhaustion: sequence wrap would alias an earlier slot owner. */
    if (producer == UINT64_MAX) {
        errno = EOVERFLOW;
        return (-1);
    }

    slot = door_ring_slot(ring, producer);
    sequence = __atomic_load_n(&slot->drs_sequence, __ATOMIC_ACQUIRE);
    if (sequence != producer) {
        errno = EPROTO;
        return (-1);
    }

    if (ring->dsr_local_reservation == UINT64_MAX) {
        errno = EOVERFLOW;
        return (-1);
    }

    ring->dsr_local_reservation++;
    offset = (size_t)((unsigned char *)door_ring_payload(slot) -
        (unsigned char *)ring->dsr_shm.dsh_addr);
    memset(writer, 0, sizeof(*writer));
    writer->drw_data = door_ring_payload(slot);
    writer->drw_capacity = ring->dsr_slot_size;
    writer->drw_offset = offset;
    writer->drw_sequence = producer;
    writer->drw_reservation = ring->dsr_local_reservation;
    ring->dsr_resv |= DOOR_RING_STATE_PRODUCER_RESERVED;
    return (0);
}

static int
door_ring_validate_writer(door_shm_ring_t *ring,
    const door_shm_ring_writer_t *writer, struct door_ring_slot **slotp)
{
    struct door_ring_slot *slot;
    uint64_t sequence;
    size_t offset;

    if (ring == NULL || writer == NULL || writer->drw_data == NULL ||
        ring->dsr_role != DOOR_SHM_RING_PRODUCER) {
        errno = EINVAL;
        return (-1);
    }

    if ((ring->dsr_resv & DOOR_RING_STATE_PRODUCER_RESERVED) == 0) {
        errno = EINVAL;
        return (-1);
    }

    /* Validate the current mapping/slot/reservation, not a Door uniquifier.
     * Sequence discipline protects cooperating SPSC peers, not hostile writes. */
    slot = door_ring_slot(ring, ring->dsr_local_producer);
    sequence = __atomic_load_n(&slot->drs_sequence, __ATOMIC_ACQUIRE);
    offset = (size_t)((unsigned char *)door_ring_payload(slot) -
        (unsigned char *)ring->dsr_shm.dsh_addr);
    if (sequence != ring->dsr_local_producer ||
        writer->drw_data != door_ring_payload(slot) ||
        writer->drw_capacity != ring->dsr_slot_size ||
        writer->drw_offset != offset ||
        writer->drw_sequence != ring->dsr_local_producer ||
        writer->drw_reservation != ring->dsr_local_reservation) {
        errno = EPROTO;
        return (-1);
    }

    *slotp = slot;
    return (0);
}

int
door_shm_ring_commit(door_shm_ring_t *ring,
    const door_shm_ring_writer_t *writer, size_t size, door_shm_ref_t *ref)
{
    struct door_ring_header *header;
    struct door_ring_slot *slot;
    uint64_t consumer, producer;

    if (ref == NULL) {
        errno = EINVAL;
        return (-1);
    }

    if (door_ring_validate_writer(ring, writer, &slot) == -1)
        return (-1);

    if (size > writer->drw_capacity) {
        errno = EMSGSIZE;
        return (-1);
    }

    header = door_ring_header(ring);
    producer = ring->dsr_local_producer;
    consumer = __atomic_load_n(&header->drh_consumer, __ATOMIC_ACQUIRE);
    if (consumer > producer || producer - consumer >= ring->dsr_slot_count) {
        errno = EPROTO;
        return (-1);
    }

    if (producer == UINT64_MAX) {
        errno = EOVERFLOW;
        return (-1);
    }

    if (door_shm_ref_init(&ring->dsr_shm, writer->drw_offset, size,
        ref) == -1)
        return (-1);

    __atomic_store_n(&slot->drs_length, size, __ATOMIC_RELAXED);
    __atomic_store_n(&slot->drs_resv0, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&slot->drs_resv1, 0, __ATOMIC_RELAXED);
    /* The consumer acquires sequence before reading length/payload. */
    __atomic_store_n(&slot->drs_sequence, producer + 1, __ATOMIC_RELEASE);
    __atomic_store_n(&header->drh_producer, producer + 1, __ATOMIC_RELEASE);
    ring->dsr_local_producer = producer + 1;
    ring->dsr_resv &= ~DOOR_RING_STATE_PRODUCER_RESERVED;
    return (0);
}

int
door_shm_ring_abort(door_shm_ring_t *ring,
    const door_shm_ring_writer_t *writer)
{
    struct door_ring_slot *slot;

    if (door_ring_validate_writer(ring, writer, &slot) == -1)
        return (-1);

    (void)slot;
    ring->dsr_resv &= ~DOOR_RING_STATE_PRODUCER_RESERVED;
    return (0);
}

int
door_shm_ring_push(door_shm_ring_t *ring, const void *data, size_t size,
    door_shm_ref_t *ref)
{
    door_shm_ring_writer_t writer;
    int error;

    if (ring == NULL || data == NULL || ref == NULL ||
        ring->dsr_role != DOOR_SHM_RING_PRODUCER ||
        size > ring->dsr_slot_size) {
        errno = EINVAL;
        return (-1);
    }

    if (door_shm_ring_reserve(ring, &writer) == -1)
        return (-1);

    memcpy(writer.drw_data, data, size);
    if (door_shm_ring_commit(ring, &writer, size, ref) == 0)
        return (0);

    error = errno;
    (void)door_shm_ring_abort(ring, &writer);
    errno = error;
    return (-1);
}

int
door_shm_ring_acquire(door_shm_ring_t *ring, door_shm_ring_view_t *view)
{
    struct door_ring_header *header;
    struct door_ring_slot *slot;
    uint64_t consumer, producer, sequence;
    size_t offset, size;

    if (ring == NULL || view == NULL ||
        ring->dsr_role != DOOR_SHM_RING_CONSUMER) {
        errno = EINVAL;
        return (-1);
    }

    if ((ring->dsr_resv & DOOR_RING_STATE_CONSUMER_ACQUIRED) != 0) {
        errno = EBUSY;
        return (-1);
    }

    header = door_ring_header(ring);
    consumer = ring->dsr_local_consumer;
    producer = __atomic_load_n(&header->drh_producer, __ATOMIC_ACQUIRE);
    if (producer < consumer || producer - consumer > ring->dsr_slot_count) {
        errno = EPROTO;
        return (-1);
    }

    if (producer == consumer) {
        errno = EAGAIN;
        return (-1);
    }

    if (consumer == UINT64_MAX) {
        errno = EOVERFLOW;
        return (-1);
    }

    slot = door_ring_slot(ring, consumer);
    /* Acquire publishes payload/length; producer must not reuse until consume. */
    sequence = __atomic_load_n(&slot->drs_sequence, __ATOMIC_ACQUIRE);
    size = __atomic_load_n(&slot->drs_length, __ATOMIC_RELAXED);
    if (sequence != consumer + 1 || size > ring->dsr_slot_size) {
        errno = EPROTO;
        return (-1);
    }

    if (__atomic_load_n(&slot->drs_length, __ATOMIC_RELAXED) != size ||
        __atomic_load_n(&slot->drs_sequence, __ATOMIC_ACQUIRE) != sequence) {
        errno = EPROTO;
        return (-1);
    }

    offset = (size_t)((unsigned char *)door_ring_payload(slot) -
        (unsigned char *)ring->dsr_shm.dsh_addr);
    memset(view, 0, sizeof(*view));
    view->drv_data = door_ring_payload(slot);
    view->drv_size = size;
    view->drv_offset = offset;
    view->drv_sequence = sequence;
    ring->dsr_resv |= DOOR_RING_STATE_CONSUMER_ACQUIRED;
    return (0);
}

int
door_shm_ring_consume(door_shm_ring_t *ring,
    const door_shm_ring_view_t *view)
{
    struct door_ring_header *header;
    struct door_ring_slot *slot;
    uint64_t consumer, producer, sequence;
    size_t offset, size;

    if (ring == NULL || view == NULL || view->drv_data == NULL ||
        ring->dsr_role != DOOR_SHM_RING_CONSUMER) {
        errno = EINVAL;
        return (-1);
    }

    if ((ring->dsr_resv & DOOR_RING_STATE_CONSUMER_ACQUIRED) == 0) {
        errno = EINVAL;
        return (-1);
    }

    header = door_ring_header(ring);
    consumer = ring->dsr_local_consumer;
    producer = __atomic_load_n(&header->drh_producer, __ATOMIC_ACQUIRE);
    if (producer < consumer || producer - consumer > ring->dsr_slot_count ||
        producer == consumer || consumer == UINT64_MAX) {
        errno = EPROTO;
        return (-1);
    }

    slot = door_ring_slot(ring, consumer);
    sequence = __atomic_load_n(&slot->drs_sequence, __ATOMIC_ACQUIRE);
    size = __atomic_load_n(&slot->drs_length, __ATOMIC_RELAXED);
    offset = (size_t)((unsigned char *)door_ring_payload(slot) -
        (unsigned char *)ring->dsr_shm.dsh_addr);
    if (sequence != consumer + 1 || view->drv_sequence != sequence ||
        view->drv_data != door_ring_payload(slot) ||
        view->drv_offset != offset || view->drv_size != size ||
        size > ring->dsr_slot_size) {
        errno = EPROTO;
        return (-1);
    }

    if (__atomic_load_n(&slot->drs_length, __ATOMIC_RELAXED) != size ||
        __atomic_load_n(&slot->drs_sequence, __ATOMIC_ACQUIRE) != sequence) {
        errno = EPROTO;
        return (-1);
    }

    /* Release gives this slot back: the caller must stop reading the old view. */
    __atomic_store_n(&slot->drs_sequence,
        consumer + ring->dsr_slot_count, __ATOMIC_RELEASE);
    __atomic_store_n(&header->drh_consumer, consumer + 1, __ATOMIC_RELEASE);
    ring->dsr_local_consumer = consumer + 1;
    ring->dsr_resv &= ~DOOR_RING_STATE_CONSUMER_ACQUIRED;
    return (0);
}

int
door_shm_ring_pop(door_shm_ring_t *ring, void *data, size_t capacity,
    size_t *sizep)
{
    door_shm_ring_view_t view;

    if (ring == NULL || data == NULL || sizep == NULL ||
        ring->dsr_role != DOOR_SHM_RING_CONSUMER) {
        errno = EINVAL;
        return (-1);
    }

    if (door_shm_ring_acquire(ring, &view) == -1)
        return (-1);

    if (view.drv_size > capacity) {
        *sizep = view.drv_size;
        ring->dsr_resv &= ~DOOR_RING_STATE_CONSUMER_ACQUIRED;
        errno = EMSGSIZE;
        return (-1);
    }

    memcpy(data, view.drv_data, view.drv_size);
    if (door_shm_ring_consume(ring, &view) == -1)
        return (-1);

    *sizep = view.drv_size;
    return (0);
}

int
door_shm_ring_unmap(door_shm_ring_t *ring)
{
    int error;

    if (ring == NULL) {
        errno = EINVAL;
        return (-1);
    }

    error = door_shm_unmap(&ring->dsr_shm);
    if (error == 0) {
        memset(ring, 0, sizeof(*ring));
        ring->dsr_shm.dsh_fd = -1;
    }

    return (error);
}
