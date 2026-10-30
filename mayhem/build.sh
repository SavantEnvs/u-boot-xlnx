#!/usr/bin/env bash
#
# mayhem/build.sh — build the sandbox U-Boot libFuzzer binaries (one per fuzz target) and the unit-test build.
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem; offline and re-runnable.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

TARGETS="fuzz_vring fuzz_fdt fuzz_fdt_overlay fuzz_fit fuzz_gzip fuzz_bzip2 fuzz_lzma fuzz_lz4 fuzz_lzo \
fuzz_zstd fuzz_x509 fuzz_pkcs7 fuzz_env fuzz_charset"

# 1) Sanitized fuzz build: U-Boot's own CONFIG_FUZZ sandbox (clang; CONFIG_FUZZ selects ASan and adds
#    -fsanitize=fuzzer), with the extra FUZZ_TESTs in mayhem/fuzz/ linked in. LTO is off because sancov
#    sections are discarded by the LTO link. Two UBSan checks are relaxed because they flood on benign
#    patterns: vla-bound (lib/hashtable.c's himport_r() declares a zero-length VLA when importing all
#    variables) and alignment (libfdt/U-Boot read be32 fields of untrusted blobs through unaligned pointers).
FO="$SRC/build-fuzz"
KFLAGS="$SANITIZER_FLAGS -fno-sanitize=vla-bound,alignment $DEBUG_FLAGS"
KMAKE=(make O="$FO" HOSTCC=clang CC="$CC" KCFLAGS="$KFLAGS")

"${KMAKE[@]}" sandbox_defconfig
./scripts/config --file "$FO/.config" -e FUZZ -d LTO -d LTO_CLANG_THIN -d LTO_CLANG_FULL -d SANDBOX_SDL
"${KMAKE[@]}" olddefconfig
"${KMAKE[@]}" mayhem/fuzz/
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/fuzz/mayhem_main.c -o "$FO/mayhem_main.o"
rm -f "$FO/u-boot"
"${KMAKE[@]}" -j"$MAYHEM_JOBS" \
  PLATFORM_LIBS="-lrt -lpthread $SANITIZER_FLAGS $FO/mayhem_main.o -Wl,--whole-archive $FO/mayhem/fuzz/built-in.a -Wl,--no-whole-archive"

# One executable per target: mayhem/fuzz/mayhem_main.c picks the FUZZ_TEST from the file name it is run as.
for t in $TARGETS; do
  ln -f "$FO/u-boot" "$SRC/$t"
done

# 2) Unit-test build with the project's normal flags (stock gcc sandbox_defconfig), run by mayhem/test.sh.
TO="$SRC/build-tests"
make O="$TO" CC=gcc HOSTCC=gcc sandbox_defconfig
make O="$TO" CC=gcc HOSTCC=gcc KCFLAGS="$COVERAGE_FLAGS" -j"$MAYHEM_JOBS"
