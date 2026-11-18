#!/usr/bin/env bash
#
# mayhem/build.sh — build busybox-w32 (its Linux/POSIX build) twice, out of tree:
#   mayhem/build/fuzz  AFL-instrumented, ASan+UBSan (halting), DWARF 3  -> /mayhem/busybox-afl
#   mayhem/build/test  the project's normal flags, for mayhem/test.sh (upstream's testsuite/runtest)
# Runs in the commit image as `mayhem` in /mayhem; re-runnable and offline.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX MAYHEM_JOBS COVERAGE_FLAGS

# Four UBSan checks fire on valid input in deliberate busybox idioms and would abort whole targets under
# halting UBSan, so only those are relaxed (ASan and every other UBSan check stay on and halting):
#  - shift-base:   MAXINT(off_t) is computed as 1 << 63 (httpd.c on every request, libbb)
#  - alignment:    reads through bb__aliased_uint32_t / unaligned_get* on packed headers (gunzip, fdisk, ...)
#  - array-bounds: decompress_bunzip2.c steps `hufGroup->base - 1` to skip an always-unused first entry
#  - function:     md5_sha1_sum.c calls the hash's `end` through a `unsigned (*)(void *, void *)` pointer
#                  although sha1_end takes a typed context, on every checksum (`sha256sum -c` included)
RELAX="-fno-sanitize=shift-base,alignment,array-bounds,function"

cd "$SRC"
BUILD="$SRC/mayhem/build"
mkdir -p "$BUILD"

# Out-of-tree configure: the default config, minus `tc` (needs kernel headers newer than the image's),
# plus the applets the default config leaves off (ar with creation and long names, uncompress, .Z in tar/rpm).
# `ar` must be able to create archives: upstream's dpkg-deb tests build their .deb with it.
configure() {
  local dir="$1"
  mkdir -p "$dir"
  env -u CFLAGS -u LDFLAGS CC=clang HOSTCC=clang make O="$dir" defconfig >/dev/null
  sed -i \
    -e 's/^CONFIG_TC=y/# CONFIG_TC is not set/' \
    -e 's/^# CONFIG_AR is not set/CONFIG_AR=y/' \
    -e 's/^# CONFIG_FEATURE_AR_LONG_FILENAMES is not set/CONFIG_FEATURE_AR_LONG_FILENAMES=y/' \
    -e 's/^# CONFIG_FEATURE_AR_CREATE is not set/CONFIG_FEATURE_AR_CREATE=y/' \
    -e 's/^# CONFIG_UNCOMPRESS is not set/CONFIG_UNCOMPRESS=y/' \
    -e 's/^# CONFIG_FEATURE_SEAMLESS_Z is not set/CONFIG_FEATURE_SEAMLESS_Z=y/' \
    "$dir/.config"
  { yes "" || true; } | env -u CFLAGS -u LDFLAGS CC=clang HOSTCC=clang make O="$dir" oldconfig >/dev/null
}

# 1) Fuzz build: AFL's clang wrapper over the whole multi-call binary, so every applet is instrumented.
FUZZ="$BUILD/fuzz"
configure "$FUZZ"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$BUILD/lsan_off.o"
# sandbox_shim.c stops ash/awk/sed scripts from running programs, writing files or signalling outside their tree.
$CC $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -c "$SRC/mayhem/sandbox_shim.c" -o "$BUILD/sandbox_shim.o"
# LDFLAGS/EXTRA_LDFLAGS also reach busybox's partial `ld -r` links (duplicating the sanitizer runtime or the
# leak-off object), so the objects ride on CFLAGS_busybox, which only the final link sees.
# The default (PCGUARD) instrumentation numbers the ~80k edges of the whole multi-call binary one by one, so
# the coverage map grows to 79,699 entries; Mayhem's AFL only sees the first 65,536, which hid most of
# diff, grep and base64 (edges 58-65 against 230 on the same seeds in afl-showmap). CLASSIC hashes every
# edge into a fixed 65,536-entry map, so all code is visible, at the price of a few colliding slots.
AFL_LLVM_INSTRUMENT=CLASSIC CFLAGS="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS" CFLAGS_busybox="$BUILD/lsan_off.o $BUILD/sandbox_shim.o" \
  make O="$FUZZ" CC=afl-clang-fast HOSTCC=clang SKIP_STRIP=y -j"$MAYHEM_JOBS"
# The binary's name must start with "busybox" for the multi-call dispatch.
cp "$FUZZ/busybox_unstripped" /mayhem/busybox-afl

# 2) Oracle build: normal flags, plus what upstream's testsuite/runtest expects beside the binary.
TEST="$BUILD/test"
configure "$TEST"
env -u CFLAGS -u LDFLAGS CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
  make O="$TEST" CC=clang HOSTCC=clang -j"$MAYHEM_JOBS"
env -u CFLAGS -u LDFLAGS make O="$TEST" CC=clang HOSTCC=clang busybox.links >/dev/null
rm -rf "$TEST/testsuite"
cp -pPR "$SRC/testsuite" "$TEST/testsuite"
# runtest's own rule for this helper compiles ../scripts/echo.c, which only exists in-tree.
clang -Os -o "$TEST/testsuite/echo-ne" "$SRC/scripts/echo.c"
