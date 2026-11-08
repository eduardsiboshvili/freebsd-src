# Raw FreeBSD32 / native matrix

Run `sh /usr/src/lib/libdoor/tests/compat32/run-mixed.sh` in the updated full
FreeBSD tree, with the regenerated syscall tables, a booted COMPAT_FREEBSD32
DoorFS kernel and installed lib32 libc/libthr. No private test hooks or libdoor
linkage are needed. The script fails if either executable cannot be built.

It builds temporary amd64 and i386 executables, runs all four client/server
pairs, then removes build outputs. This is a manual kernel wire test, not a
replacement for rebuilding and testing the 32-bit libdoor API.

Contract, coverage and qualification limits: `docs/freebsd32-compat.md`.
