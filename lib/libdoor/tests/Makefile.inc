PACKAGE=	tests
TESTSDIR=	${TESTSBASE}/lib/libdoor/${.CURDIR:T}

# Test the matching source ABI, even before headers have been installed.
# Keep these paths consistent with lib/libdoor/Makefile.
CFLAGS+=	-I${SRCTOP}/include -I${SRCTOP}/sys
CFLAGS+=	-I${.CURDIR}/../common
LIBADD+=	door pthread
