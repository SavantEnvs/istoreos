#!/usr/bin/env bash
#
# mayhem/build.sh — build the istoreos fuzz harnesses and the functional test suite.
#
# istoreos is an OpenWrt fork: the top-level Makefile is a whole firmware buildroot (cross
# toolchain, downloads, hours) and is NOT used. The fuzzed code is the in-tree userspace C that
# parses untrusted data, and each piece is a few self-contained C files, so this script compiles
# them directly with clang:
#   ead                package/network/services/ead/src (+ tinysrp)   broadcast UDP frames, pre-auth
#   bcm4908img         package/utils/bcm4908img/src                   BCM4908 firmware images
#   osafeloader        package/utils/osafeloader/src                  TP-Link SafeLoader images
#   fritz_tffs_read    package/utils/fritz-tools/src                  AVM TFFS flash dumps
#   fritz_cal_extract  package/utils/fritz-tools/src                  AVM calibration blobs (zlib)
#   jboot_config_read  package/utils/jboot-tools/src                  JBOOT config partitions
#   nvram              package/utils/nvram/src                        Broadcom NVRAM partitions
#
# Everything is written under mayhem/out/ (gitignored by mayhem/.gitignore); nothing is fetched
# (libpcap headers and zlib come from apt in the Dockerfile), so a re-run is offline + idempotent.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
OBJ="$OUT/obj"
TOBJ="$OUT/test-obj"
mkdir -p "$OUT" "$OBJ" "$TOBJ"

EAD="$SRC/package/network/services/ead/src"
SRP="$EAD/tinysrp"
H="$SRC/mayhem/harnesses"
# Old C sources: K&R definitions (tinysrp) and 32-bit pointer casts (fritz-tools); keep the
# warnings non-fatal, as upstream's gcc build does.
WARN="-w"
# Upstream's per-package CPPFLAGS: ead builds with -I. -Itinysrp; tinysrp's config.h is the
# one its configure would write (mayhem/ead/config.h) so configure never runs in-tree.
EAD_INC="-DHAVE_CONFIG_H -I$SRC/mayhem/ead -I$EAD -I$SRP"
# ead-crypt.c calls ntohl/htonl without <arpa/inet.h> (gcc's legacy implicit declarations
# accept that; clang 19 rejects it): force-include the system header, no source change.
EAD_CRYPT_INC="$EAD_INC -include arpa/inet.h"

TINYSRP_SRC="tinysrp.c t_client.c t_getconf.c t_conv.c t_getpass.c t_sha.c t_math.c
  t_misc.c t_pw.c t_read.c t_server.c t_truerand.c
  bn_add.c bn_ctx.c bn_div.c bn_exp.c bn_mul.c bn_word.c bn_asm.c bn_lib.c
  bn_shift.c bn_sqr.c"

# Fuzz build: project code AND harness instrumented (sanitizers + SanCov) with DWARF 3.
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link $WARN"
# Test build: the project's normal flags (like upstream's -Os -Wall), no sanitizers.
TEST_CFLAGS="-O2 $WARN $COVERAGE_FLAGS"

# compile_lib <objdir> <cflags> <archive> <srcdir> <includes> <files...>
compile_lib() {
  local objdir="$1" cflags="$2" archive="$3" srcdir="$4" inc="$5"; shift 5
  local objs=() f o
  mkdir -p "$objdir"
  for f in "$@"; do
    o="$objdir/${f%.c}.o"
    # shellcheck disable=SC2086
    $CC $cflags $inc -c "$srcdir/$f" -o "$o"
    objs+=("$o")
  done
  rm -f "$archive"
  ar rcs "$archive" "${objs[@]}"
}

# ---------------------------------------------------------------- 1) fuzz build
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OBJ/lsan_off.o"

# shellcheck disable=SC2086
compile_lib "$OBJ/tinysrp" "$FUZZ_CFLAGS" "$OBJ/libtinysrp.a" "$SRP" "$EAD_INC" $TINYSRP_SRC
compile_lib "$OBJ/ead" "$FUZZ_CFLAGS" "$OBJ/libead.a" "$EAD" "$EAD_CRYPT_INC" ead-crypt.c libbridge_init.c
compile_lib "$OBJ/nvram" "$FUZZ_CFLAGS" "$OBJ/libnvram.a" "$SRC/package/utils/nvram/src" "" nvram.c crc.c

# link_fuzzer <name> <harness.c> <extra args...>: <name> (libFuzzer) + <name>-standalone
link_fuzzer() {
  local name="$1" src="$2"; shift 2
  # shellcheck disable=SC2086
  $CC $FUZZ_CFLAGS -c "$src" -o "$OBJ/$name.o" "$@"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OBJ/$name.o" "$OBJ/lsan_off.o" \
    $LINK_LIBS -o "$OUT/$name"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OBJ/$name.o" "$OBJ/standalone_main.o" "$OBJ/lsan_off.o" \
    $LINK_LIBS -o "$OUT/$name-standalone"
}

LINK_LIBS="$OBJ/libead.a $OBJ/libtinysrp.a"
link_fuzzer fuzz_ead "$H/fuzz_ead.c" $EAD_INC
LINK_LIBS=""
link_fuzzer fuzz_bcm4908img "$H/fuzz_bcm4908img.c"
LINK_LIBS="$OBJ/osafeloader-md5.o"
$CC $FUZZ_CFLAGS -c "$SRC/package/utils/osafeloader/src/md5.c" -o "$OBJ/osafeloader-md5.o"
link_fuzzer fuzz_osafeloader "$H/fuzz_osafeloader.c"
LINK_LIBS="-lz"
link_fuzzer fuzz_fritz_cal_extract "$H/fuzz_fritz_cal_extract.c"
LINK_LIBS="$OBJ/libnvram.a"
link_fuzzer fuzz_nvram "$H/fuzz_nvram.c"

# FILE-INPUT targets: the tools themselves, run by Mayhem on `@@`, not libFuzzer harnesses.
#  - fritz_tffs_read (`-i @@ -a`) reads past a zero-length buffer on an empty file, and libFuzzer
#    always executes the empty input first, so an in-process harness could never start.
#  - jboot_config_read (`-i @@ -m -e /dev/null`): find_header() scans for a STAG header with a
#    4-byte memcmp at every offset up to buf_size inclusive, so every input without a valid STAG
#    header reads past the buffer; libFuzzer stops at the first such mutation.
# Built with the same sanitizers + SanCov; each is its own reproducer (no -standalone).
# raw_target <name> <source.c> [link args]
raw_target() {
  local name="$1" src="$2"; shift 2
  # shellcheck disable=SC2086
  $CC $FUZZ_CFLAGS --std=gnu99 -c "$src" -o "$OBJ/$name.o"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "$OBJ/$name.o" "$OBJ/lsan_off.o" "$@" -o "$OUT/$name"
}
raw_target fritz_tffs_read "$SRC/package/utils/fritz-tools/src/fritz_tffs_read.c"
raw_target jboot_config_read "$SRC/package/utils/jboot-tools/src/jboot_config_read.c"

# ---------------------------------------------------------------- 2) test build (normal flags)
TB="$OUT/test-bin"
mkdir -p "$TB"
U="$SRC/package/utils"
# shellcheck disable=SC2086
compile_lib "$TOBJ/tinysrp" "$TEST_CFLAGS" "$TOBJ/libtinysrp.a" "$SRP" "$EAD_INC" $TINYSRP_SRC
compile_lib "$TOBJ/ead" "$TEST_CFLAGS" "$TOBJ/libead.a" "$EAD" "$EAD_CRYPT_INC" ead-crypt.c libbridge_init.c
# shellcheck disable=SC2086
$CC $TEST_CFLAGS $EAD_INC "$SRC/mayhem/tests/ead_selftest.c" "$TOBJ/libead.a" "$TOBJ/libtinysrp.a" -o "$TB/ead_selftest"
# shellcheck disable=SC2086
$CC $TEST_CFLAGS "$SRC/mayhem/tests/nvram_selftest.c" "$U/nvram/src/nvram.c" "$U/nvram/src/crc.c" -o "$TB/nvram_selftest"
# The firmware tools themselves, built as their upstream Makefiles/CMakeLists do.
# shellcheck disable=SC2086
$CC $TEST_CFLAGS -o "$TB/bcm4908img" "$U/bcm4908img/src/bcm4908img.c"
# shellcheck disable=SC2086
$CC $TEST_CFLAGS -o "$TB/osafeloader" "$U/osafeloader/src/osafeloader.c" "$U/osafeloader/src/md5.c"
# shellcheck disable=SC2086
$CC $TEST_CFLAGS --std=gnu99 -o "$TB/fritz_tffs_read" "$U/fritz-tools/src/fritz_tffs_read.c"
# shellcheck disable=SC2086
$CC $TEST_CFLAGS --std=gnu99 -o "$TB/fritz_cal_extract" "$U/fritz-tools/src/fritz_cal_extract.c" -lz

echo "build.sh: built $(ls "$OUT" | grep -c '^fuzz_.*-standalone$') libFuzzer harnesses + 2 file-input targets into $OUT"
