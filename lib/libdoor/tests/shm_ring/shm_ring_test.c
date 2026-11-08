/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <atf-c.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <door.h>

#include "test_common.h"

#define RING_SLOTS 4
#define RING_PAYLOAD 128

struct ring_transfer_context {
	door_shm_ring_t *consumer;
	const unsigned char *expected;
	size_t expected_size;
	size_t tail_size;
	unsigned char tail_byte;
	int result;
};

static void
ring_transfer_server(void *cookie, char *data, size_t size,
    door_desc_t *descs, uint_t ndescs)
{
	struct ring_transfer_context *context;
	door_shm_ring_view_t view;
	const unsigned char *tail;
	size_t i;

	(void)descs;
	(void)ndescs;
	context = cookie;
	context->result = 1;
	if (door_shm_ring_acquire(context->consumer, &view) == -1)
		goto out;
	context->result = 2;
	if (size != context->expected_size || view.drv_size != size ||
	    (size != 0 && memcmp(data, context->expected, size) != 0) ||
	    (size != 0 && memcmp(view.drv_data, context->expected, size) != 0))
		goto consume;
	context->result = 3;
	tail = (const unsigned char *)view.drv_data + size;
	for (i = 0; i < context->tail_size; i++)
		if (tail[i] != context->tail_byte)
			goto consume;
	context->result = 0;
consume:
	if (door_shm_ring_consume(context->consumer, &view) == -1)
		context->result = 4;
out:
	door_return(NULL, 0, NULL, 0);
}

static void
ring_server(void *cookie, char *data, size_t size, door_desc_t *descs,
    uint_t ndescs)
{
	(void)cookie;
	(void)data;
	(void)size;
	(void)descs;
	(void)ndescs;
	door_return(NULL, 0, NULL, 0);
}

static void
create_ring_pair(int fd, door_shm_ring_t *producer,
    door_shm_ring_t *consumer)
{
	ATF_REQUIRE_MSG(door_shm_ring_create(fd, RING_PAYLOAD, RING_SLOTS,
	    producer) == 0, "door_shm_ring_create: %s", strerror(errno));
	ATF_REQUIRE_MSG(door_shm_ring_attach(fd,
	    producer->dsr_shm.dsh_region, DOOR_SHM_RING_CONSUMER, consumer) == 0,
	    "door_shm_ring_attach: %s", strerror(errno));
}

static void
destroy_ring_pair(int fd, door_shm_ring_t *producer,
    door_shm_ring_t *consumer)
{
	ATF_REQUIRE(door_shm_destroy(fd, producer->dsr_shm.dsh_region) == 0);
	if (consumer->dsr_shm.dsh_addr != producer->dsr_shm.dsh_addr) {
		ATF_REQUIRE(door_shm_ring_unmap(consumer) == 0);
	} else {
		ATF_REQUIRE(close(consumer->dsr_shm.dsh_fd) == 0);
		consumer->dsr_shm.dsh_fd = -1;
	}
	ATF_REQUIRE(door_shm_ring_unmap(producer) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(push_pop_and_reuse);
ATF_TC_BODY(push_pop_and_reuse, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ref_t ref;
	char input[RING_PAYLOAD], output[RING_PAYLOAD];
	size_t output_size;
	int fd;
	unsigned int i;

	(void)tc;
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	for (i = 0; i < 32; i++) {
		memset(input, (int)i, sizeof(input));
		ATF_REQUIRE(door_shm_ring_push(&producer, input, sizeof(input),
		    &ref) == 0);
		ATF_REQUIRE(ref.dsr_offset <= producer.dsr_shm.dsh_size);
		ATF_REQUIRE(ref.dsr_size <=
		    producer.dsr_shm.dsh_size - ref.dsr_offset);
		ATF_REQUIRE(door_shm_ring_pop(&consumer, output, sizeof(output),
		    &output_size) == 0);
		ATF_REQUIRE_EQ(sizeof(input), output_size);
		ATF_REQUIRE(memcmp(input, output, sizeof(input)) == 0);
	}
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(full_ring_rejected);
ATF_TC_BODY(full_ring_rejected, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ref_t ref;
	char byte;
	int fd;
	unsigned int i;

	(void)tc;
	byte = 1;
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	for (i = 0; i < RING_SLOTS; i++)
		ATF_REQUIRE(door_shm_ring_push(&producer, &byte, 1, &ref) == 0);
	errno = 0;
	ATF_REQUIRE(door_shm_ring_push(&producer, &byte, 1, &ref) == -1);
	ATF_REQUIRE_EQ(EAGAIN, errno);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(independent_regions_do_not_overlap);
ATF_TC_BODY(independent_regions_do_not_overlap, tc)
{
	door_shm_ring_t producer_a, consumer_a, producer_b, consumer_b;
	door_shm_ring_view_t view_a, view_b;
	door_shm_ref_t ref_a, ref_b;
	char input_a[32], input_b[32];
	int fd;

	(void)tc;
	memset(input_a, 0x11, sizeof(input_a));
	memset(input_b, 0xee, sizeof(input_b));
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer_a, &consumer_a);
	create_ring_pair(fd, &producer_b, &consumer_b);
	ATF_REQUIRE(producer_a.dsr_shm.dsh_region !=
	    producer_b.dsr_shm.dsh_region);
	ATF_REQUIRE(door_shm_ring_push(&producer_a, input_a, sizeof(input_a),
	    &ref_a) == 0);
	ATF_REQUIRE(door_shm_ring_push(&producer_b, input_b, sizeof(input_b),
	    &ref_b) == 0);
	ATF_REQUIRE(ref_a.dsr_region != ref_b.dsr_region);
	ATF_REQUIRE(door_shm_ring_acquire(&consumer_a, &view_a) == 0);
	ATF_REQUIRE(door_shm_ring_acquire(&consumer_b, &view_b) == 0);
	ATF_REQUIRE(memcmp(view_a.drv_data, input_a, sizeof(input_a)) == 0);
	ATF_REQUIRE(memcmp(view_b.drv_data, input_b, sizeof(input_b)) == 0);
	ATF_REQUIRE(door_shm_ring_consume(&consumer_a, &view_a) == 0);
	ATF_REQUIRE(door_shm_ring_consume(&consumer_b, &view_b) == 0);
	ATF_REQUIRE(door_shm_destroy(fd, producer_a.dsr_shm.dsh_region) == 0);
	ATF_REQUIRE(door_shm_destroy(fd, producer_b.dsr_shm.dsh_region) == 0);
	if (consumer_a.dsr_shm.dsh_addr != producer_a.dsr_shm.dsh_addr)
		ATF_REQUIRE(door_shm_ring_unmap(&consumer_a) == 0);
	else
		ATF_REQUIRE(close(consumer_a.dsr_shm.dsh_fd) == 0);
	if (consumer_b.dsr_shm.dsh_addr != producer_b.dsr_shm.dsh_addr)
		ATF_REQUIRE(door_shm_ring_unmap(&consumer_b) == 0);
	else
		ATF_REQUIRE(close(consumer_b.dsr_shm.dsh_fd) == 0);
	ATF_REQUIRE(door_shm_ring_unmap(&producer_a) == 0);
	ATF_REQUIRE(door_shm_ring_unmap(&producer_b) == 0);
	test_close_door(fd);
}

ATF_TC_WITHOUT_HEAD(oversized_payload_rejected);
ATF_TC_BODY(oversized_payload_rejected, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ref_t ref;
	char input[RING_PAYLOAD + 1];
	int fd;

	(void)tc;
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	errno = 0;
	ATF_REQUIRE(door_shm_ring_push(&producer, input, sizeof(input), &ref) ==
	    -1);
	ATF_REQUIRE_EQ(EINVAL, errno);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(acquire_consume_zero_copy);
ATF_TC_BODY(acquire_consume_zero_copy, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ref_t ref;
	door_shm_ring_view_t view;
	char input[32];
	int fd;

	(void)tc;
	memset(input, 0xa5, sizeof(input));
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	ATF_REQUIRE(door_shm_ring_push(&producer, input, sizeof(input), &ref) ==
	    0);
	ATF_REQUIRE(door_shm_ring_acquire(&consumer, &view) == 0);
	ATF_REQUIRE_EQ(sizeof(input), view.drv_size);
	ATF_REQUIRE_EQ(ref.dsr_offset, view.drv_offset);
	ATF_REQUIRE(view.drv_data == (const unsigned char *)
	    consumer.dsr_shm.dsh_addr + ref.dsr_offset);
	ATF_REQUIRE(memcmp(input, view.drv_data, sizeof(input)) == 0);
	ATF_REQUIRE(door_shm_ring_consume(&consumer, &view) == 0);
	errno = 0;
	ATF_REQUIRE(door_shm_ring_consume(&consumer, &view) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(acquire_lifecycle_and_wrong_view);
ATF_TC_BODY(acquire_lifecycle_and_wrong_view, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ring_view_t view, wrong;
	door_shm_ref_t ref;
	char input[32];
	int fd;

	(void)tc;
	memset(input, 0x3c, sizeof(input));
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	ATF_REQUIRE(door_shm_ring_push(&producer, input, sizeof(input), &ref) ==
	    0);
	ATF_REQUIRE(door_shm_ring_acquire(&consumer, &view) == 0);
	errno = 0;
	ATF_REQUIRE(door_shm_ring_acquire(&consumer, &wrong) == -1);
	ATF_REQUIRE_EQ(EBUSY, errno);
	wrong = view;
	wrong.drv_offset++;
	errno = 0;
	ATF_REQUIRE(door_shm_ring_consume(&consumer, &wrong) == -1);
	ATF_REQUIRE_EQ(EPROTO, errno);
	wrong = view;
	wrong.drv_data = (const unsigned char *)consumer.dsr_shm.dsh_addr +
	    consumer.dsr_shm.dsh_size;
	errno = 0;
	ATF_REQUIRE(door_shm_ring_consume(&consumer, &wrong) == -1);
	ATF_REQUIRE_EQ(EPROTO, errno);
	ATF_REQUIRE(door_shm_ring_consume(&consumer, &view) == 0);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(payload_mutation_cannot_change_view_bounds);
ATF_TC_BODY(payload_mutation_cannot_change_view_bounds, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ring_view_t view;
	door_shm_ref_t ref;
	unsigned char *payload;
	char input[32];
	int fd;

	(void)tc;
	memset(input, 0x69, sizeof(input));
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	ATF_REQUIRE(door_shm_ring_push(&producer, input, sizeof(input), &ref) ==
	    0);
	ATF_REQUIRE(door_shm_ring_acquire(&consumer, &view) == 0);
	payload = (unsigned char *)producer.dsr_shm.dsh_addr + ref.dsr_offset;
	payload[0] ^= 1;
	ATF_REQUIRE_EQ(sizeof(input), view.drv_size);
	ATF_REQUIRE_EQ(ref.dsr_offset, view.drv_offset);
	ATF_REQUIRE_EQ((unsigned char)(input[0] ^ 1),
	    ((const unsigned char *)view.drv_data)[0]);
	ATF_REQUIRE(door_shm_ring_consume(&consumer, &view) == 0);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(short_pop_can_retry);
ATF_TC_BODY(short_pop_can_retry, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ref_t ref;
	char input[32], output[32];
	size_t output_size;
	int fd;

	(void)tc;
	memset(input, 0x96, sizeof(input));
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	ATF_REQUIRE(door_shm_ring_push(&producer, input, sizeof(input), &ref) ==
	    0);
	errno = 0;
	ATF_REQUIRE(door_shm_ring_pop(&consumer, output, 1, &output_size) == -1);
	ATF_REQUIRE_EQ(EMSGSIZE, errno);
	ATF_REQUIRE_EQ(sizeof(input), output_size);
	ATF_REQUIRE(door_shm_ring_pop(&consumer, output, sizeof(output),
	    &output_size) == 0);
	ATF_REQUIRE(memcmp(input, output, sizeof(input)) == 0);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(corrupt_slot_length_rejected);
ATF_TC_BODY(corrupt_slot_length_rejected, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ref_t ref;
	uint64_t *length;
	char input[8], output[RING_PAYLOAD];
	size_t output_size;
	int fd;

	(void)tc;
	memset(input, 0x5a, sizeof(input));
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	ATF_REQUIRE(door_shm_ring_push(&producer, input, sizeof(input), &ref) ==
	    0);
	length = (uint64_t *)(void *)((unsigned char *)producer.dsr_shm.dsh_addr +
	    64 + sizeof(uint64_t));
	*length = UINT64_MAX;
	errno = 0;
	ATF_REQUIRE(door_shm_ring_pop(&consumer, output, sizeof(output),
	    &output_size) == -1);
	ATF_REQUIRE_EQ(EPROTO, errno);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(corrupt_tail_rejected);
ATF_TC_BODY(corrupt_tail_rejected, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ref_t ref;
	uint64_t *tail;
	char byte;
	int fd;

	(void)tc;
	byte = 1;
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	tail = (uint64_t *)(void *)((unsigned char *)producer.dsr_shm.dsh_addr +
	    7 * sizeof(uint64_t));
	*tail = RING_SLOTS + 1;
	errno = 0;
	ATF_REQUIRE(door_shm_ring_push(&producer, &byte, 1, &ref) == -1);
	ATF_REQUIRE_EQ(EPROTO, errno);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(reserve_commit_fragments);
ATF_TC_BODY(reserve_commit_fragments, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ring_writer_t writer, busy;
	door_shm_ring_view_t view;
	door_shm_ref_t ref;
	static const char first[] = "GET /index.html";
	static const char second[] = " HTTP/1.1\r\nHost: local\r\n\r\n";
	size_t used;
	int fd;

	(void)tc;
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	ATF_REQUIRE(door_shm_ring_reserve(&producer, &writer) == 0);
	ATF_REQUIRE_EQ(RING_PAYLOAD, writer.drw_capacity);
	ATF_REQUIRE(writer.drw_offset <= producer.dsr_shm.dsh_size);
	ATF_REQUIRE(writer.drw_capacity <=
	    producer.dsr_shm.dsh_size - writer.drw_offset);
	errno = 0;
	ATF_REQUIRE(door_shm_ring_reserve(&producer, &busy) == -1);
	ATF_REQUIRE_EQ(EBUSY, errno);
	memcpy(writer.drw_data, first, sizeof(first) - 1);
	used = sizeof(first) - 1;
	memcpy((unsigned char *)writer.drw_data + used, second,
	    sizeof(second) - 1);
	used += sizeof(second) - 1;
	errno = 0;
	ATF_REQUIRE(door_shm_ring_acquire(&consumer, &view) == -1);
	ATF_REQUIRE_EQ(EAGAIN, errno);
	ATF_REQUIRE(door_shm_ring_commit(&producer, &writer, used, &ref) == 0);
	ATF_REQUIRE_EQ(writer.drw_offset, ref.dsr_offset);
	ATF_REQUIRE_EQ(used, ref.dsr_size);
	ATF_REQUIRE(door_shm_ring_acquire(&consumer, &view) == 0);
	ATF_REQUIRE_EQ(used, view.drv_size);
	ATF_REQUIRE(memcmp(view.drv_data, first, sizeof(first) - 1) == 0);
	ATF_REQUIRE(memcmp((const unsigned char *)view.drv_data +
	    sizeof(first) - 1, second, sizeof(second) - 1) == 0);
	ATF_REQUIRE(door_shm_ring_consume(&consumer, &view) == 0);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(reserve_bounds_and_modified_writer);
ATF_TC_BODY(reserve_bounds_and_modified_writer, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ring_writer_t writer, wrong;
	door_shm_ref_t ref;
	int fd;

	(void)tc;
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	ATF_REQUIRE(door_shm_ring_reserve(&producer, &writer) == 0);
	errno = 0;
	ATF_REQUIRE(door_shm_ring_commit(&producer, &writer,
	    writer.drw_capacity + 1, &ref) == -1);
	ATF_REQUIRE_EQ(EMSGSIZE, errno);
	wrong = writer;
	wrong.drw_data = (unsigned char *)producer.dsr_shm.dsh_addr +
	    producer.dsr_shm.dsh_size;
	errno = 0;
	ATF_REQUIRE(door_shm_ring_commit(&producer, &wrong, 1, &ref) == -1);
	ATF_REQUIRE_EQ(EPROTO, errno);
	wrong = writer;
	wrong.drw_offset++;
	errno = 0;
	ATF_REQUIRE(door_shm_ring_abort(&producer, &wrong) == -1);
	ATF_REQUIRE_EQ(EPROTO, errno);
	ATF_REQUIRE(door_shm_ring_abort(&producer, &writer) == 0);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(abort_rejects_stale_writer);
ATF_TC_BODY(abort_rejects_stale_writer, tc)
{
	door_shm_ring_t producer, consumer;
	door_shm_ring_writer_t stale, writer;
	door_shm_ring_view_t view;
	door_shm_ref_t ref;
	char value;
	int fd;

	(void)tc;
	value = 0x5a;
	fd = test_create_door(ring_server);
	create_ring_pair(fd, &producer, &consumer);
	ATF_REQUIRE(door_shm_ring_reserve(&producer, &stale) == 0);
	ATF_REQUIRE(door_shm_ring_abort(&producer, &stale) == 0);
	errno = 0;
	ATF_REQUIRE(door_shm_ring_abort(&producer, &stale) == -1);
	ATF_REQUIRE_EQ(EINVAL, errno);
	ATF_REQUIRE(door_shm_ring_reserve(&producer, &writer) == 0);
	ATF_REQUIRE(stale.drw_reservation != writer.drw_reservation);
	errno = 0;
	ATF_REQUIRE(door_shm_ring_commit(&producer, &stale, 1, &ref) == -1);
	ATF_REQUIRE_EQ(EPROTO, errno);
	memcpy(writer.drw_data, &value, sizeof(value));
	ATF_REQUIRE(door_shm_ring_commit(&producer, &writer, sizeof(value),
	    &ref) == 0);
	ATF_REQUIRE(door_shm_ring_acquire(&consumer, &view) == 0);
	ATF_REQUIRE_EQ(sizeof(value), view.drv_size);
	ATF_REQUIRE_EQ(value, *(const char *)view.drv_data);
	ATF_REQUIRE(door_shm_ring_consume(&consumer, &view) == 0);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TC_WITHOUT_HEAD(committed_length_hides_reused_tail);
ATF_TC_BODY(committed_length_hides_reused_tail, tc)
{
	struct ring_transfer_context context;
	door_shm_ring_t producer, consumer;
	door_shm_ring_writer_t writer;
	door_shm_ref_t ref;
	unsigned char long_message[96], short_message[17];
	int fd;
	unsigned int i;

	(void)tc;
	memset(long_message, 0x41, sizeof(long_message));
	memset(short_message, 0x42, sizeof(short_message));
	memset(&context, 0, sizeof(context));
	context.consumer = &consumer;
	fd = door_create(ring_transfer_server, &context, 0);
	ATF_REQUIRE_MSG(fd != -1, "door_create: %s", strerror(errno));
	create_ring_pair(fd, &producer, &consumer);

	/* Fill and consume every slot so the next reservation reuses slot zero. */
	for (i = 0; i < RING_SLOTS; i++) {
		ATF_REQUIRE(door_shm_ring_reserve(&producer, &writer) == 0);
		memset(writer.drw_data, 0x41, writer.drw_capacity);
		memcpy(writer.drw_data, long_message, sizeof(long_message));
		context.expected = long_message;
		context.expected_size = sizeof(long_message);
		context.tail_size = writer.drw_capacity - sizeof(long_message);
		context.tail_byte = 0x41;
		context.result = -1;
		ATF_REQUIRE(door_shm_ring_commit(&producer, &writer,
		    sizeof(long_message), &ref) == 0);
		ATF_REQUIRE(door_call_shm(fd, &ref) == 0);
		ATF_REQUIRE_MSG(context.result == 0,
		    "long transfer check failed at stage %d", context.result);
	}

	ATF_REQUIRE(door_shm_ring_reserve(&producer, &writer) == 0);
	memcpy(writer.drw_data, short_message, sizeof(short_message));
	context.expected = short_message;
	context.expected_size = sizeof(short_message);
	context.tail_size = writer.drw_capacity - sizeof(short_message);
	context.tail_byte = 0x41;
	context.result = -1;
	ATF_REQUIRE(door_shm_ring_commit(&producer, &writer,
	    sizeof(short_message), &ref) == 0);
	ATF_REQUIRE_EQ(sizeof(short_message), ref.dsr_size);
	ATF_REQUIRE(door_call_shm(fd, &ref) == 0);
	ATF_REQUIRE_MSG(context.result == 0,
	    "short transfer exposed or modified stale tail at stage %d",
	    context.result);
	destroy_ring_pair(fd, &producer, &consumer);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, push_pop_and_reuse);
	ATF_TP_ADD_TC(tp, full_ring_rejected);
	ATF_TP_ADD_TC(tp, independent_regions_do_not_overlap);
	ATF_TP_ADD_TC(tp, oversized_payload_rejected);
	ATF_TP_ADD_TC(tp, acquire_consume_zero_copy);
	ATF_TP_ADD_TC(tp, acquire_lifecycle_and_wrong_view);
	ATF_TP_ADD_TC(tp, payload_mutation_cannot_change_view_bounds);
	ATF_TP_ADD_TC(tp, short_pop_can_retry);
	ATF_TP_ADD_TC(tp, corrupt_slot_length_rejected);
	ATF_TP_ADD_TC(tp, corrupt_tail_rejected);
	ATF_TP_ADD_TC(tp, reserve_commit_fragments);
	ATF_TP_ADD_TC(tp, reserve_bounds_and_modified_writer);
	ATF_TP_ADD_TC(tp, abort_rejects_stale_writer);
	ATF_TP_ADD_TC(tp, committed_length_hides_reused_tail);
	return (atf_no_error());
}
