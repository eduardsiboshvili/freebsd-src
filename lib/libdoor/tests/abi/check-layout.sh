#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Compile with actual FreeBSD system headers; no 32-bit libraries required.
set -eu
case "${1-}" in
    "") strict= ;;
    --require-common-wire) strict=-DDOOR_ABI_REQUIRE_LP64_WIRE_LAYOUT ;;
    *) echo "usage: $0 [--require-common-wire]" >&2; exit 2 ;;
esac
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project=$(CDPATH= cd -- "$here/../../../.." && pwd)
for bits in 64 32; do
    echo "Checking ${bits}-bit ABI${strict:+ (common wire layout)}"
    "${CC:-cc}" -m"$bits" -std=c11 -Wall -Wextra -Werror -fsyntax-only \
        -DDOOR_ABI_CHECK_TEST_INTERFACE ${strict:+"$strict"} \
        -I"$project/sys" -I"$project/include" "$here/abi_layout_check.c"
done
