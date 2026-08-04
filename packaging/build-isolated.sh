#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build="$repo/build-opt"

if test -d "$build"; then
  meson setup --reconfigure "$build" "$repo/libfprint/libfprint" \
    --prefix=/opt/synatlsmoc-coexist \
    --libdir=lib/x86_64-linux-gnu \
    -Ddrivers=synatlsmoc -Dintrospection=false -Ddoc=false \
    -Dinstalled-tests=false -Dudev_rules=disabled -Dudev_hwdb=disabled \
    -Dc_link_args=-Wl,-rpath,/opt/synatlsmoc-coexist/lib/x86_64-linux-gnu
else
  meson setup "$build" "$repo/libfprint/libfprint" \
    --prefix=/opt/synatlsmoc-coexist \
    --libdir=lib/x86_64-linux-gnu \
    -Ddrivers=synatlsmoc -Dintrospection=false -Ddoc=false \
    -Dinstalled-tests=false -Dudev_rules=disabled -Dudev_hwdb=disabled \
    -Dc_link_args=-Wl,-rpath,/opt/synatlsmoc-coexist/lib/x86_64-linux-gnu
fi

meson compile -C "$build"
meson test -C "$build" --print-errorlogs

echo "Built and tested without installation: $build"
echo "No service, D-Bus, PAM, or sensor state was changed."
