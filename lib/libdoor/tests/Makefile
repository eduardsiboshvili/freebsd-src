PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/lib/libdoor

TESTS_SUBDIRS=	abi \
	async \
	access_stats \
	api \
	attributes \
	basic \
	cancellation \
	capsicum \
	concurrency_stress \
	depletion \
	descriptor \
	descriptor_graph \
	descriptor_limits \
	descriptor_ownership \
	descriptor_types \
	doorctl \
	doorctl_oneway \
	doorctl_oneway_shm \
	doorctl_shm \
	fault_injection \
	final_stress \
	fork_exec \
	huge_payload \
	legacy_pool \
	lifetime \
	lifetime_extended \
	mass_stress \
	mixed_payload \
	persistent_shm \
	pool_lifecycle \
	process_control \
	race_hardening \
	recursive \
	resource_limits \
	oneway \
	shared_memory \
	shm_view \
	shm_ring \
	shm_fd_reuse \
	signals \
	worker_hardening \
	xcreate

.if defined(WITH_DOOR_TESTS) && ${WITH_DOOR_TESTS} == "yes"
TESTS_SUBDIRS+=	phases
.endif

.include <bsd.test.mk>
