ATF_TESTS_C=	recursive_test forward_test
SRCS.recursive_test=	recursive_test.c ../common/test_common.c
SRCS.forward_test=	forward_test.c ../common/test_common.c

.include "../Makefile.inc"
.include <bsd.test.mk>

# Refresh the generated manifest after the test list changes.
.if target(Kyuafile)
Kyuafile: ${.CURDIR}/Makefile
.endif
