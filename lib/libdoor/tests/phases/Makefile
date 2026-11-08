ATF_TESTS_C=	phase_test invariant_test
SRCS.phase_test=	phase_test.c
SRCS.invariant_test=	invariant_test.c

TEST_METADATA.phase_test+=	is_exclusive="true"
TEST_METADATA.invariant_test+=	is_exclusive="true"

CFLAGS+=	-I${SRCTOP}/sys

.include "../Makefile.inc"
.include <bsd.test.mk>
