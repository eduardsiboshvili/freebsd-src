.PATH: ${SRCTOP}/sys/fs/doorfs

KMOD=	doorfs
SRCS=	opt_doorfs.h opt_doorctl.h \
	door_core.c \
	door_rpc.c \
	door_test.c \
	door_xfer.c \
	door_shm.c \
	door_file.c \
	door_ctl.c

CFLAGS+=	-DDOORFS -DDOORCTL

.include <bsd.kmod.mk>
