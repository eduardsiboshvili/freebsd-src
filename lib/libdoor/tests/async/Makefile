ATF_TESTS_C= async_test async_kernel_limits_test

.if defined(WITH_DOOR_TESTS) && ${WITH_DOOR_TESTS} == "yes"
CFLAGS+= -DDOOR_TESTS -I${SRCTOP}/sys
# The strict raw race uses the global test drain interface.
TEST_METADATA.async_kernel_limits_test+= is_exclusive="true"
.endif

.include "../Makefile.inc"
.include <bsd.test.mk>
