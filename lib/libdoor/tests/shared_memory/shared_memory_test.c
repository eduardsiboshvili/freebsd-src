/*-
 * Copyright (c) 2026 Eduard Siboshvili
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <atf-c.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_common.h"

#define SMALL_MAPPING_SIZE (64 * 1024)
#define LARGE_MAPPING_SIZE (16 * 1024 * 1024)
#define PARALLEL_WORKERS 8
#define PARALLEL_REGION_SIZE 4096

#define SHM_OP_VERIFY 1
#define SHM_OP_FILL 2

#define SHM_STATUS_OK 0
#define SHM_STATUS_PROTOCOL 1
#define SHM_STATUS_BOUNDS 2
#define SHM_STATUS_CONTENT 3
#define SHM_STATUS_SYSTEM 4

struct shm_request {
	uint64_t sr_offset;
	uint64_t sr_length;
	uint32_t sr_seed;
	uint32_t sr_operation;
};

struct parallel_context {
	int pc_door_fd;
	int pc_shm_fd;
	uint64_t pc_offset;
	uint32_t pc_seed;
	int pc_error;
};

static int server_shm_fd = -1;
static size_t server_shm_size;
static uint32_t server_shm_seed;

static uint8_t
pattern_byte(uint32_t seed, uint64_t index)
{
	uint64_t value;

	value = index + ((uint64_t)seed << 32) + seed;
	value ^= value >> 33;
	value *= UINT64_C(0xff51afd7ed558ccd);
	value ^= value >> 33;
	value *= UINT64_C(0xc4ceb9fe1a85ec53);
	value ^= value >> 33;
	return ((uint8_t)value);
}

static void
fill_pattern(void *address, size_t length, uint32_t seed, uint64_t base)
{
	uint8_t *bytes;
	size_t i;

	bytes = address;
	for (i = 0; i < length; i++)
		bytes[i] = pattern_byte(seed, base + i);
}

static bool
verify_pattern(const void *address, size_t length, uint32_t seed, uint64_t base)
{
	const uint8_t *bytes;
	size_t i;

	bytes = address;
	for (i = 0; i < length; i++) {
		if (bytes[i] != pattern_byte(seed, base + i))
			return (false);
	}
	return (true);
}

static int
create_shm(size_t size)
{
	int fd;

	fd = shm_open(SHM_ANON, O_RDWR, 0600);
	ATF_REQUIRE_MSG(
	    fd != -1, "shm_open(SHM_ANON) failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(ftruncate(fd, (off_t)size) == 0,
			"ftruncate failed: %s",
			strerror(errno));
	return (fd);
}

static void *
map_shared(int fd, size_t size)
{
	void *mapping;

	mapping = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	ATF_REQUIRE_MSG(
	    mapping != MAP_FAILED, "mmap failed: %s", strerror(errno));
	return (mapping);
}

static int
validate_region(int fd, const struct shm_request *request, size_t *sizep)
{
	struct stat status;
	uint64_t object_size;

	if (fstat(fd, &status) == -1 || status.st_size < 0)
		return (SHM_STATUS_SYSTEM);
	object_size = (uint64_t)status.st_size;
	if (request->sr_offset > object_size ||
	    request->sr_length > object_size - request->sr_offset)
		return (SHM_STATUS_BOUNDS);
	if (object_size > SIZE_MAX)
		return (SHM_STATUS_BOUNDS);
	*sizep = (size_t)object_size;
	return (SHM_STATUS_OK);
}

static void
shm_request_server(void *cookie,
		   char *data,
		   size_t data_size,
		   door_desc_t *descs,
		   uint_t ndescs)
{
	const struct shm_request *request;
	uint8_t *mapping;
	size_t object_size;
	int status;

	(void)cookie;

	status = SHM_STATUS_PROTOCOL;
	mapping = MAP_FAILED;
	if (data == NULL || data_size != sizeof(*request) || descs == NULL ||
	    ndescs != 1)
		goto out;
	request = (const struct shm_request *)(const void *)data;
	status = validate_region(descs[0].d_descriptor, request, &object_size);
	if (status != SHM_STATUS_OK)
		goto out;
	mapping = mmap(NULL,
		       object_size,
		       PROT_READ | PROT_WRITE,
		       MAP_SHARED,
		       descs[0].d_descriptor,
		       0);
	if (mapping == MAP_FAILED) {
		status = SHM_STATUS_SYSTEM;
		goto out;
	}

	switch (request->sr_operation) {
	case SHM_OP_VERIFY:
		if (!verify_pattern(mapping + request->sr_offset,
				    (size_t)request->sr_length,
				    request->sr_seed,
				    request->sr_offset))
			status = SHM_STATUS_CONTENT;
		break;
	case SHM_OP_FILL:
		fill_pattern(mapping + request->sr_offset,
			     (size_t)request->sr_length,
			     request->sr_seed,
			     request->sr_offset);
		break;
	default:
		status = SHM_STATUS_PROTOCOL;
		break;
	}

out:
	if (mapping != MAP_FAILED)
		(void)munmap(mapping, object_size);
	if (descs != NULL && ndescs == 1)
		(void)close(descs[0].d_descriptor);
	door_return((char *)(void *)&status, sizeof(status), NULL, 0);
}

static void
shm_return_copy_server(void *cookie,
		       char *data,
		       size_t data_size,
		       door_desc_t *descs,
		       uint_t ndescs)
{
	door_desc_t output;

	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	test_init_desc(&output, server_shm_fd, 0);
	door_return(NULL, 0, &output, 1);
}

static void
shm_return_move_server(void *cookie,
		       char *data,
		       size_t data_size,
		       door_desc_t *descs,
		       uint_t ndescs)
{
	door_desc_t output;

	(void)cookie;
	(void)data;
	(void)data_size;
	(void)descs;
	(void)ndescs;

	test_init_desc(&output, server_shm_fd, DOOR_RELEASE);
	door_return(NULL, 0, &output, 1);
}

static int
perform_shm_call(int door_fd,
		 int shm_fd,
		 door_attr_t attributes,
		 const struct shm_request *request)
{
	char reply[sizeof(int)];
	door_arg_t arg;
	door_desc_t descriptor;
	int status;

	memset(&arg, 0, sizeof(arg));
	test_init_desc(&descriptor, shm_fd, attributes);
	arg.data_ptr = (char *)(uintptr_t)request;
	arg.data_size = sizeof(*request);
	arg.desc_ptr = &descriptor;
	arg.desc_num = 1;
	arg.rbuf = reply;
	arg.rsize = sizeof(reply);
	if (door_call(door_fd, &arg) == -1)
		return (-1);
	if (arg.data_size != sizeof(status)) {
		errno = EPROTO;
		return (-1);
	}
	memcpy(&status, arg.data_ptr, sizeof(status));
	if (status != SHM_STATUS_OK) {
		errno = status == SHM_STATUS_BOUNDS ? ERANGE : EPROTO;
		return (-1);
	}
	return (0);
}

static int
receive_server_mapping(int door_fd)
{
	char reply[1];
	door_arg_t arg;

	test_init_call(&arg, reply, sizeof(reply));
	ATF_REQUIRE_MSG(door_call(door_fd, &arg) == 0,
			"door_call failed: %s",
			strerror(errno));
	ATF_REQUIRE_MSG(arg.desc_num == 1,
			"server returned %u descriptors instead of one",
			arg.desc_num);
	return (arg.desc_ptr[0].d_descriptor);
}

static void *
parallel_caller(void *argument)
{
	struct parallel_context *context;
	struct shm_request request;

	context = argument;
	memset(&request, 0, sizeof(request));
	request.sr_offset = context->pc_offset;
	request.sr_length = PARALLEL_REGION_SIZE;
	request.sr_seed = context->pc_seed;
	request.sr_operation = SHM_OP_FILL;
	if (perform_shm_call(
		context->pc_door_fd, context->pc_shm_fd, 0, &request) == -1)
		context->pc_error = errno;
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(local_shared_mapping_visibility);

ATF_TC_BODY(local_shared_mapping_visibility, tc)
{
	uint8_t *first, *second;
	int fd;

	(void)tc;
	fd = create_shm(SMALL_MAPPING_SIZE);
	first = map_shared(fd, SMALL_MAPPING_SIZE);
	second = map_shared(fd, SMALL_MAPPING_SIZE);
	fill_pattern(first, SMALL_MAPPING_SIZE, 0x10203040, 0);
	ATF_REQUIRE(verify_pattern(second, SMALL_MAPPING_SIZE, 0x10203040, 0));
	ATF_REQUIRE(munmap(second, SMALL_MAPPING_SIZE) == 0);
	ATF_REQUIRE(munmap(first, SMALL_MAPPING_SIZE) == 0);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC_WITHOUT_HEAD(client_copy_to_server);

ATF_TC_BODY(client_copy_to_server, tc)
{
	struct shm_request request;
	uint8_t *mapping;
	int door_fd, shm_fd;

	(void)tc;
	door_fd = test_create_door(shm_request_server);
	shm_fd = create_shm(SMALL_MAPPING_SIZE);
	mapping = map_shared(shm_fd, SMALL_MAPPING_SIZE);
	fill_pattern(mapping, SMALL_MAPPING_SIZE, 0x12345678, 0);
	request = (struct shm_request){
	    .sr_offset = 0,
	    .sr_length = SMALL_MAPPING_SIZE,
	    .sr_seed = 0x12345678,
	    .sr_operation = SHM_OP_VERIFY,
	};
	ATF_REQUIRE_MSG(perform_shm_call(door_fd, shm_fd, 0, &request) == 0,
			"shared-memory verification failed: %s",
			strerror(errno));
	test_require_fd_valid(shm_fd);
	ATF_REQUIRE(munmap(mapping, SMALL_MAPPING_SIZE) == 0);
	ATF_REQUIRE(close(shm_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(client_move_to_server);

ATF_TC_BODY(client_move_to_server, tc)
{
	struct shm_request request;
	uint8_t *mapping;
	int door_fd, shm_fd;

	(void)tc;
	door_fd = test_create_door(shm_request_server);
	shm_fd = create_shm(SMALL_MAPPING_SIZE);
	mapping = map_shared(shm_fd, SMALL_MAPPING_SIZE);
	fill_pattern(mapping, SMALL_MAPPING_SIZE, 0xa5a55a5a, 0);
	request = (struct shm_request){
	    .sr_offset = 0,
	    .sr_length = SMALL_MAPPING_SIZE,
	    .sr_seed = 0xa5a55a5a,
	    .sr_operation = SHM_OP_VERIFY,
	};
	ATF_REQUIRE_MSG(
	    perform_shm_call(door_fd, shm_fd, DOOR_RELEASE, &request) == 0,
	    "shared-memory move failed: %s",
	    strerror(errno));
	ATF_REQUIRE(!test_fd_valid(shm_fd));
	ATF_REQUIRE(verify_pattern(mapping, SMALL_MAPPING_SIZE, 0xa5a55a5a, 0));
	ATF_REQUIRE(munmap(mapping, SMALL_MAPPING_SIZE) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(server_copy_to_client);

ATF_TC_BODY(server_copy_to_client, tc)
{
	uint8_t *source, *received;
	int door_fd, received_fd;

	(void)tc;
	server_shm_size = SMALL_MAPPING_SIZE;
	server_shm_seed = 0x31415926;
	server_shm_fd = create_shm(server_shm_size);
	source = map_shared(server_shm_fd, server_shm_size);
	fill_pattern(source, server_shm_size, server_shm_seed, 0);
	door_fd = test_create_door(shm_return_copy_server);
	received_fd = receive_server_mapping(door_fd);
	received = map_shared(received_fd, server_shm_size);
	ATF_REQUIRE(
	    verify_pattern(received, server_shm_size, server_shm_seed, 0));
	test_require_fd_valid(server_shm_fd);
	ATF_REQUIRE(munmap(received, server_shm_size) == 0);
	ATF_REQUIRE(close(received_fd) == 0);
	ATF_REQUIRE(munmap(source, server_shm_size) == 0);
	ATF_REQUIRE(close(server_shm_fd) == 0);
	server_shm_fd = -1;
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(server_move_to_client);

ATF_TC_BODY(server_move_to_client, tc)
{
	uint8_t *source, *received;
	door_arg_t arg;
	char reply[1];
	int door_fd, received_fd, result, source_status, source_error;

	(void)tc;
	server_shm_size = SMALL_MAPPING_SIZE;
	server_shm_seed = 0x27182818;
	server_shm_fd = create_shm(server_shm_size);
	source = map_shared(server_shm_fd, server_shm_size);
	fill_pattern(source, server_shm_size, server_shm_seed, 0);
	door_fd = test_create_door(shm_return_move_server);
	test_init_call(&arg, reply, sizeof(reply));
	result = door_call(door_fd, &arg);
	/* Observe before helpers or new fd allocation can hide a delayed MOVE. */
	source_status = fcntl(server_shm_fd, F_GETFD);
	source_error = errno;
	ATF_REQUIRE_EQ(result, 0);
	ATF_REQUIRE(source_status == -1 && source_error == EBADF);
	ATF_REQUIRE_EQ(arg.desc_num, 1);
	received_fd = arg.desc_ptr[0].d_descriptor;
	ATF_REQUIRE(received_fd != server_shm_fd);
	received = map_shared(received_fd, server_shm_size);
	ATF_REQUIRE(
	    verify_pattern(received, server_shm_size, server_shm_seed, 0));
	ATF_REQUIRE(
	    verify_pattern(source, server_shm_size, server_shm_seed, 0));
	ATF_REQUIRE(munmap(received, server_shm_size) == 0);
	ATF_REQUIRE(close(received_fd) == 0);
	ATF_REQUIRE(munmap(source, server_shm_size) == 0);
	server_shm_fd = -1;
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(mapping_survives_descriptor_close);

ATF_TC_BODY(mapping_survives_descriptor_close, tc)
{
	uint8_t *mapping;
	int fd;

	(void)tc;
	fd = create_shm(SMALL_MAPPING_SIZE);
	mapping = map_shared(fd, SMALL_MAPPING_SIZE);
	ATF_REQUIRE(close(fd) == 0);
	fill_pattern(mapping, SMALL_MAPPING_SIZE, 0xfeedface, 0);
	ATF_REQUIRE(verify_pattern(mapping, SMALL_MAPPING_SIZE, 0xfeedface, 0));
	ATF_REQUIRE(munmap(mapping, SMALL_MAPPING_SIZE) == 0);
}

ATF_TC_WITHOUT_HEAD(offset_length_region);

ATF_TC_BODY(offset_length_region, tc)
{
	struct shm_request request;
	uint8_t *mapping;
	const uint64_t offset = 123;
	const uint64_t length = 8193;
	int door_fd, shm_fd;

	(void)tc;
	door_fd = test_create_door(shm_request_server);
	shm_fd = create_shm(SMALL_MAPPING_SIZE);
	mapping = map_shared(shm_fd, SMALL_MAPPING_SIZE);
	memset(mapping, 0, SMALL_MAPPING_SIZE);
	request = (struct shm_request){
	    .sr_offset = offset,
	    .sr_length = length,
	    .sr_seed = 0x01020304,
	    .sr_operation = SHM_OP_FILL,
	};
	ATF_REQUIRE_MSG(perform_shm_call(door_fd, shm_fd, 0, &request) == 0,
			"region fill failed: %s",
			strerror(errno));
	ATF_REQUIRE(mapping[offset - 1] == 0);
	ATF_REQUIRE(
	    verify_pattern(mapping + offset, length, request.sr_seed, offset));
	ATF_REQUIRE(mapping[offset + length] == 0);
	ATF_REQUIRE(munmap(mapping, SMALL_MAPPING_SIZE) == 0);
	ATF_REQUIRE(close(shm_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(out_of_bounds_region_rejected);

ATF_TC_BODY(out_of_bounds_region_rejected, tc)
{
	struct shm_request request;
	int door_fd, shm_fd;

	(void)tc;
	door_fd = test_create_door(shm_request_server);
	shm_fd = create_shm(SMALL_MAPPING_SIZE);
	request = (struct shm_request){
	    .sr_offset = SMALL_MAPPING_SIZE - 32,
	    .sr_length = 64,
	    .sr_seed = 0,
	    .sr_operation = SHM_OP_FILL,
	};
	errno = 0;
	ATF_REQUIRE(perform_shm_call(door_fd, shm_fd, 0, &request) == -1);
	ATF_REQUIRE(errno == ERANGE);
	test_require_fd_valid(shm_fd);
	ATF_REQUIRE(close(shm_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(offset_length_overflow_rejected);

ATF_TC_BODY(offset_length_overflow_rejected, tc)
{
	struct shm_request request;
	int door_fd, shm_fd;

	(void)tc;
	door_fd = test_create_door(shm_request_server);
	shm_fd = create_shm(SMALL_MAPPING_SIZE);
	request = (struct shm_request){
	    .sr_offset = UINT64_MAX - 7,
	    .sr_length = 16,
	    .sr_seed = 0,
	    .sr_operation = SHM_OP_FILL,
	};
	errno = 0;
	ATF_REQUIRE(perform_shm_call(door_fd, shm_fd, 0, &request) == -1);
	ATF_REQUIRE(errno == ERANGE);
	test_require_fd_valid(shm_fd);
	ATF_REQUIRE(close(shm_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(parallel_disjoint_regions);

ATF_TC_BODY(parallel_disjoint_regions, tc)
{
	struct parallel_context contexts[PARALLEL_WORKERS];
	pthread_t threads[PARALLEL_WORKERS];
	uint8_t *mapping;
	size_t total_size;
	int door_fd, shm_fd;
	unsigned int i;

	(void)tc;
	total_size = PARALLEL_WORKERS * PARALLEL_REGION_SIZE;
	door_fd = test_create_door(shm_request_server);
	shm_fd = create_shm(total_size);
	mapping = map_shared(shm_fd, total_size);
	memset(mapping, 0, total_size);
	for (i = 0; i < PARALLEL_WORKERS; i++) {
		contexts[i] = (struct parallel_context){
		    .pc_door_fd = door_fd,
		    .pc_shm_fd = shm_fd,
		    .pc_offset = i * PARALLEL_REGION_SIZE,
		    .pc_seed = 0x1000 + i,
		    .pc_error = 0,
		};
		ATF_REQUIRE_MSG(
		    pthread_create(
			&threads[i], NULL, parallel_caller, &contexts[i]) == 0,
		    "pthread_create failed");
	}
	for (i = 0; i < PARALLEL_WORKERS; i++) {
		ATF_REQUIRE(pthread_join(threads[i], NULL) == 0);
		ATF_REQUIRE_MSG(contexts[i].pc_error == 0,
				"parallel call %u failed: %s",
				i,
				strerror(contexts[i].pc_error));
		ATF_REQUIRE(verify_pattern(mapping + contexts[i].pc_offset,
					   PARALLEL_REGION_SIZE,
					   contexts[i].pc_seed,
					   contexts[i].pc_offset));
	}
	ATF_REQUIRE(munmap(mapping, total_size) == 0);
	ATF_REQUIRE(close(shm_fd) == 0);
	test_close_door(door_fd);
}

ATF_TC_WITHOUT_HEAD(large_random_pattern);

ATF_TC_BODY(large_random_pattern, tc)
{
	struct shm_request request;
	uint8_t *mapping;
	int door_fd, shm_fd;

	(void)tc;
	door_fd = test_create_door(shm_request_server);
	shm_fd = create_shm(LARGE_MAPPING_SIZE);
	mapping = map_shared(shm_fd, LARGE_MAPPING_SIZE);
	fill_pattern(mapping, LARGE_MAPPING_SIZE, 0x6d2b79f5, 0);
	request = (struct shm_request){
	    .sr_offset = 0,
	    .sr_length = LARGE_MAPPING_SIZE,
	    .sr_seed = 0x6d2b79f5,
	    .sr_operation = SHM_OP_VERIFY,
	};
	ATF_REQUIRE_MSG(perform_shm_call(door_fd, shm_fd, 0, &request) == 0,
			"large mapping verification failed: %s",
			strerror(errno));
	ATF_REQUIRE(munmap(mapping, LARGE_MAPPING_SIZE) == 0);
	ATF_REQUIRE(close(shm_fd) == 0);
	test_close_door(door_fd);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, local_shared_mapping_visibility);
	ATF_TP_ADD_TC(tp, client_copy_to_server);
	ATF_TP_ADD_TC(tp, client_move_to_server);
	ATF_TP_ADD_TC(tp, server_copy_to_client);
	ATF_TP_ADD_TC(tp, server_move_to_client);
	ATF_TP_ADD_TC(tp, mapping_survives_descriptor_close);
	ATF_TP_ADD_TC(tp, offset_length_region);
	ATF_TP_ADD_TC(tp, out_of_bounds_region_rejected);
	ATF_TP_ADD_TC(tp, offset_length_overflow_rejected);
	ATF_TP_ADD_TC(tp, parallel_disjoint_regions);
	ATF_TP_ADD_TC(tp, large_random_pattern);

	return (atf_no_error());
}
