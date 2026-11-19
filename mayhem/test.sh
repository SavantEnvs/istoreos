#!/usr/bin/env bash
#
# mayhem/test.sh — istoreos functional oracle (everything already built by mayhem/build.sh).
# exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader rebuilds
# (build.sh) then runs this.
#
# Upstream (an OpenWrt buildroot) ships no unit tests for this code, so the suite is known-answer
# tests over the fuzzed code, built with normal flags into mayhem/out/test-bin:
#   - ead_selftest: frames fed to ead's handle_packet(), replies checked field by field;
#   - nvram_selftest: libnvram open/getall/get/set/unset on a fixture partition, diffed;
#   - the firmware tools (bcm4908img, osafeloader, fritz_tffs_read, fritz_cal_extract) run on
#     committed fixtures (mayhem/tests/fixtures, made by gen_fixtures.py), output diffed against
#     golden files.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
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


T="$SRC/mayhem/out/test-bin"
F="$SRC/mayhem/tests/fixtures"
for b in ead_selftest nvram_selftest bcm4908img osafeloader fritz_tffs_read fritz_cal_extract; do
  if [ ! -x "$T/$b" ]; then
    echo "test.sh: missing $T/$b — run mayhem/build.sh first" >&2
    emit_ctrf "istoreos-known-answer" 0 1 0
    exit 1
  fi
done
W="$(mktemp -d "${TMPDIR:-/tmp}/istoreos-test.XXXXXX")"
trap 'rm -rf "$W"' EXIT

passed=0 failed=0
ok()  { passed=$((passed + 1)); echo "PASS $1"; }
bad() { failed=$((failed + 1)); echo "FAIL $1"; }
# expect_file <name> <expected file> <actual file>
expect_file() { if cmp -s "$2" "$3"; then ok "$1"; else bad "$1"; diff "$2" "$3" | head -20 || true; fi; }
# expect_rc <name> <rc> <cmd...>
expect_rc() { local n="$1" want="$2"; shift 2; "$@" >/dev/null 2>&1; local rc=$?; [ "$rc" = "$want" ] && ok "$n" || bad "$n (rc=$rc, want $want)"; }

# --- ead: its own PASS/FAIL lines + summary
"$T/ead_selftest" "$SRC/package/network/services/ead/src/passwd" > "$W/ead.out" 2>&1
cat "$W/ead.out"
ep=$(sed -n 's/^SUMMARY \([0-9]*\) passed \([0-9]*\) failed$/\1/p' "$W/ead.out")
ef=$(sed -n 's/^SUMMARY \([0-9]*\) passed \([0-9]*\) failed$/\2/p' "$W/ead.out")
if [ -n "$ep" ] && [ -n "$ef" ] && [ "$ep" -ge 14 ]; then
  passed=$((passed + ep)); failed=$((failed + ef))
else
  bad "ead_selftest summary (expected >= 14 checks)"
fi

# --- libnvram
cp "$F/nvram.bin" "$W/nvram.bin"; chmod u+w "$W/nvram.bin"   # nvram_open() opens O_RDWR
"$T/nvram_selftest" "$W/nvram.bin" > "$W/nvram.out" 2>&1
expect_file "nvram: variables + get/set/unset" "$F/nvram.expected" "$W/nvram.out"

# --- bcm4908img
"$T/bcm4908img" info -i "$F/bcm4908.img" > "$W/bcm.info" 2>&1
expect_file "bcm4908img info" "$F/bcm4908.info.expected" "$W/bcm.info"
"$T/bcm4908img" bootfs -i "$F/bcm4908.img" ls > "$W/bcm.ls" 2>&1
expect_file "bcm4908img bootfs ls" "$F/bcm4908.ls.expected" "$W/bcm.ls"
"$T/bcm4908img" extract -i "$F/bcm4908.img" -t rootfs > "$W/bcm.rootfs" 2>/dev/null
expect_file "bcm4908img extract rootfs" "$F/bcm4908.rootfs.expected" "$W/bcm.rootfs"
cp "$F/bcm4908.img" "$W/mv.img"
"$T/bcm4908img" bootfs -i "$W/mv.img" mv vmlinux.lz vmlinux.xz >/dev/null 2>&1
"$T/bcm4908img" bootfs -i "$W/mv.img" ls > "$W/bcm.mv.ls" 2>&1
printf 'cferom.000\nvmlinux.xz\ndtb\n' > "$W/bcm.mv.expected"
expect_file "bcm4908img bootfs mv renames the dirent" "$W/bcm.mv.expected" "$W/bcm.mv.ls"
head -c 4096 "$F/bcm4908.img" > "$W/short.img"
expect_rc "bcm4908img rejects a truncated image" 1 bash -c '"$0" info -i "$1"; [ $? -ne 0 ] && exit 1' "$T/bcm4908img" "$W/short.img"

# --- osafeloader
"$T/osafeloader" info "$F/safeloader.bin" > "$W/sl.info" 2>&1
expect_file "osafeloader info" "$F/safeloader.info.expected" "$W/sl.info"
"$T/osafeloader" extract "$F/safeloader.bin" -p os-image -o "$W/os-image" >/dev/null 2>&1
expect_file "osafeloader extract os-image" "$F/safeloader.os-image.expected" "$W/os-image"
cp "$F/safeloader.bin" "$W/bad-md5.bin"; printf '\x00' | dd of="$W/bad-md5.bin" bs=1 seek=8 conv=notrunc 2>/dev/null
"$T/osafeloader" info "$W/bad-md5.bin" > "$W/sl.bad" 2>&1
grep -q "invalid MD5" "$W/sl.bad" && ok "osafeloader rejects a bad MD5" || bad "osafeloader rejects a bad MD5"

# --- fritz_tffs_read
"$T/fritz_tffs_read" -i "$F/tffs.bin" -a > "$W/tffs.all" 2>&1
expect_file "fritz_tffs_read -a" "$F/tffs.all.expected" "$W/tffs.all"
"$T/fritz_tffs_read" -i "$F/tffs.bin" -l > "$W/tffs.names" 2>&1
expect_file "fritz_tffs_read -l" "$F/tffs.names.expected" "$W/tffs.names"
[ "$("$T/fritz_tffs_read" -i "$F/tffs.bin" -n serialnumber 2>&1)" = "SN0042" ] && ok "fritz_tffs_read -n serialnumber" || bad "fritz_tffs_read -n serialnumber"

# --- fritz_cal_extract
"$T/fritz_cal_extract" -e 7 -o "$W/cal.out" "$F/cal.bin" >/dev/null 2>&1
expect_file "fritz_cal_extract -e 7 inflates the entry" "$F/cal.expected" "$W/cal.out"
"$T/fritz_cal_extract" -e 7 -r -o "$W/cal.rev" "$F/cal.bin" >/dev/null 2>&1
python3 -I -c 'import sys; a=open(sys.argv[1],"rb").read(); b=open(sys.argv[2],"rb").read(); sys.exit(0 if a==b[::-1] and a else 1)' "$W/cal.rev" "$F/cal.expected" \
  && ok "fritz_cal_extract -r reverses the data" || bad "fritz_cal_extract -r reverses the data"
expect_rc "fritz_cal_extract missing entry fails" 1 "$T/fritz_cal_extract" -e 9 -o "$W/cal.none" "$F/cal.bin"

echo "SUMMARY $passed passed $failed failed"
emit_ctrf "istoreos-known-answer" "$passed" "$failed" 0
