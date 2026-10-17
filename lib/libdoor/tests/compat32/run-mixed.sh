#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (C) 2026 Eduard Siboshvili
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../../../.." && pwd)
build=$(mktemp -d "${TMPDIR:-/tmp}/door-compat32.XXXXXX")
trap 'rm -rf "$build"' EXIT HUP INT TERM
: "${CC:=cc}"
for bits in 64 32; do
    "$CC" -m"$bits" -std=gnu17 -Wall -Wextra -Werror -pthread \
        -I"$root/sys" "$here/raw_mixed.c" -o "$build/raw$bits"
done
for pair in 64:64 32:32 32:64 64:32; do
    client=${pair%:*}
    server=${pair#*:}
    "$build/raw$client" "$build/raw$server"
    echo "PASS: client $client / server $server"
done
