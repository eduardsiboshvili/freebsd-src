PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/lib/libdoor/${.CURDIR:T}

CFLAGS+=	-I${.CURDIR}/../common
LIBADD+=	door pthread
