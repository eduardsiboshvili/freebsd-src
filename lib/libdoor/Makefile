.include <src.opts.mk>

PACKAGE=	clibs
LIB=		door
SHLIB_MAJOR=	1
HAS_TESTS=

MAN=		door.2 door.3 doorfs.4 namefs.4
MLINKS=		door.3 door_create.3 \
		door.3 door_revoke.3 \
		door.3 door_info.3 \
		door.3 door_call.3 \
		door.3 door_oneway.3 \
		door.3 door_async_open.3 \
		door.3 door_async_submit.3 \
		door.3 door_async_cancel.3 \
		door.3 door_async_close.3 \
		door.3 door_async_server_open.3 \
		door.3 door_async_server_register.3 \
		door.3 door_async_server_respond.3 \
		door.3 door_return.3 \
		door.3 door_cred.3 \
		door.3 door_ucred.3 \
		door.3 door_bind.3 \
		door.3 door_unbind.3 \
		door.3 door_getparam.3 \
		door.3 door_setparam.3 \
		door.3 door_server_create.3 \
		door.3 door_xcreate.3 \
		door.3 fattach.3 \
		door.3 fdetach.3 \
		door.3 door_shm_create.3 \
		door.3 door_shm_attach.3 \
		door.3 door_shm_unmap.3 \
		door.3 door_shm_destroy.3 \
		door.3 door_call_shm.3 \
		door.3 door_call_shm_region.3 \
		door.3 door_shm_ref_init.3 \
		door.3 door_shm_destroy_handle.3 \
		door.3 door_shm_view_publish.3 \
		door.3 door_shm_view_attach.3 \
		door.3 door_shm_view_query.3 \
		door.3 door_shm_view_release.3 \
		door.3 door_shm_view_destroy.3 \
		door.3 door_shm_view_close.3 \
		door.3 door_shm_ring_create.3 \
		door.3 door_shm_ring_attach.3 \
		door.3 door_shm_ring_reserve.3 \
		door.3 door_shm_ring_commit.3 \
		door.3 door_shm_ring_abort.3 \
		door.3 door_shm_ring_push.3 \
		door.3 door_shm_ring_acquire.3 \
		door.3 door_shm_ring_consume.3 \
		door.3 door_shm_ring_pop.3 \
		door.3 door_shm_ring_unmap.3 \
		door.3 door_named_register.3 \
		door.3 door_named_unregister.3 \
		door.3 door_named_lookup.3 \
		door.3 door_named_connect.3

SUBDIR.${MK_TESTS}+=	tests

SRCS=	 door_attach.c \
	 door_async.c \
	 door_async_server.c \
	 door_call.c \
	 door_create.c \
	 door_desc.c \
	 door_iov.c \
	 door_misc.c \
	 door_named.c \
	 door_oneway.c \
	 door_registry.c \
	 door_shm_ring.c \
	 door_safe.c \
	 door_server.c \
	 door_shm_view.c \
	 door_shm.c

CFLAGS+=	-I${SRCTOP}/include -I${SRCTOP}/sys
LIBADD=		pthread
LDFLAGS+=	-Wl,-z,nodelete

VERSION_MAP=	${.CURDIR}/Symbol.map

.include <bsd.lib.mk>
