#!/usr/bin/env bash
#
# mayhem/test.sh — RUN U-Boot's own sandbox unit tests (built by mayhem/build.sh into build-tests/u-boot)
# plus three known-answer hash checks, and report CTRF counts. Does not build anything.
#
# The oracle asserts parsed behavior: per-suite "Tests run: N ... failures: F" lines from U-Boot's `ut`
# command, and exact digests printed by `hash`/`crc32`. A neutered binary prints nothing, so every
# expected suite is then reported as failed.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


UBOOT=build-tests/u-boot
[ -x "$UBOOT" ] || { echo "missing $UBOOT — mayhem/build.sh must build it" >&2; emit_ctrf "u-boot-ut" 0 1 0; exit 1; }

# U-Boot's sandbox tests read ./README (membuf) and find arch/sandbox/dts/test.dtb relative to the binary;
# run from the source root.
SUITES="lib common bloblist cmd env fdt fdt_overlay log mem setexpr loadm"
passed=0 failed=0

for s in $SUITES; do
  out=$("$UBOOT" -T -c "ut $s" 2>&1) || true
  line=$(printf '%s\n' "$out" | grep -a -E '^Tests run: [0-9]+,.*failures: [0-9]+' | tail -1)
  if [ -z "$line" ]; then
    echo "FAIL suite $s: no 'Tests run' summary"; printf '%s\n' "$out" | tail -5
    failed=$((failed + 1)); continue
  fi
  run=$(printf '%s' "$line" | sed -E 's/^Tests run: ([0-9]+),.*/\1/')
  bad=$(printf '%s' "$line" | sed -E 's/.*failures: ([0-9]+).*/\1/')
  if [ "$run" -gt 0 ] && [ "$bad" -eq 0 ]; then
    echo "PASS suite $s: $run tests"; passed=$((passed + run))
  else
    echo "FAIL suite $s: $line"; printf '%s\n' "$out" | grep -a -E 'failed|Expected' | head -10
    passed=$((passed + run - bad)); failed=$((failed + bad + (run == 0 ? 1 : 0)))
  fi
done

# Known-answer digests of the three bytes "abc".
kat_out=$("$UBOOT" -T -c 'mw.b 0 0x61 1; mw.b 1 0x62 1; mw.b 2 0x63 1; hash sha256 0 3; hash md5 0 3; crc32 0 3' 2>&1) || true
check_kat() {
  if printf '%s\n' "$kat_out" | grep -a -q -F "$2"; then echo "PASS KAT $1"; passed=$((passed + 1))
  else echo "FAIL KAT $1: expected '$2'"; failed=$((failed + 1)); fi
}
check_kat sha256 "sha256 for 00000000 ... 00000002 ==> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
check_kat md5 "md5 for 00000000 ... 00000002 ==> 900150983cd24fb0d6963f7d28e17f72"
check_kat crc32 "crc32 for 00000000 ... 00000002 ==> 352441c2"

emit_ctrf "u-boot-ut" "$passed" "$failed" 0
