#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build="$repo/build-opt"
output="$build/coexist-tools/synatlsmoc-standalone-check"

test -f "$build/libfprint/libfprint-2.so" || {
  echo "Missing isolated libfprint build; run ./packaging/build-isolated.sh first." >&2
  exit 1
}

mkdir -p "$(dirname -- "$output")"

cc -std=gnu11 -Wall -Wextra -Werror \
  -I"$repo/libfprint/libfprint" \
  -I"$build/libfprint" \
  -I"$build" \
  "$repo/packaging/synatlsmoc-standalone-check.c" \
  -L"$build/libfprint" -Wl,-rpath,"$build/libfprint" -lfprint-2 \
  $(pkg-config --cflags --libs glib-2.0 gio-2.0) \
  -o "$output"

echo "Built safe standalone checker: $output"
