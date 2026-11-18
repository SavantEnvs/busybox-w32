#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
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

# Upstream's own suite (testsuite/runtest): ~1100 known-answer checks of the applets, run against the
# normal-flags multi-call binary that build.sh left in mayhem/build/test.
BUILD="$SRC/mayhem/build/test"
[ -x "$BUILD/busybox" ] || { echo "missing $BUILD/busybox — mayhem/build.sh did not build it" >&2; emit_ctrf busybox-runtest 0 1 0; exit 1; }
[ -f "$BUILD/busybox.links" ] && [ -x "$BUILD/testsuite/echo-ne" ] \
  || { echo "missing busybox.links/echo-ne in $BUILD — mayhem/build.sh did not stage them" >&2; emit_ctrf busybox-runtest 0 1 0; exit 1; }

LOG="$BUILD/runtest.log"
( cd "$BUILD/testsuite" && bindir="$BUILD" srcdir="$SRC/testsuite" sh "$SRC/testsuite/runtest" ) > "$LOG" 2>&1 || true

passed=$(grep -ac '^PASS: ' "$LOG")
failed_names=$(grep -a '^FAIL: ' "$LOG" | sed 's/^FAIL: //')
skipped=$(grep -ace '^SKIPPED: ' -e '^UNTESTED: ' "$LOG")

# Cases that fail on an unmodified checkout in this image; upstream's runner counts them as failures, so they
# are reported as skipped, by exact name, and a new failure anywhere else still fails the suite. Causes:
#  - network or privileges the image lacks: wget* (fetch from the internet), hostname-d-works (asks DNS),
#    taskset (needs CAP_SYS_NICE)
#  - the image's /bin/sh is dash, whose printf has no \x escapes, so the test cannot create its file names:
#    ls -q, ls -Q, ls -qQ
#  - the build tree is on overlayfs, which reports 4 blocks for an empty directory where the test expects 0
#    (tmpfs): du include duplicated directory only once
#  - the fix is compiled only on Windows (#if ENABLE_PLATFORM_MINGW32 in awk.c), so this Linux build prints
#    "-0": awk print negative zero as 0
#  - upstream's own testsuite wraps these in `test x"$SKIP_KNOWN_BUGS" = x""` (open busybox bugs: sed does
#    not handle NUL bytes and does not reject a jump to a missing label on empty input, cpio -t omits hardlink
#    names, tar cannot extract a file into a read-only directory when not root): sed embedded NUL,
#    sed NUL in command, sed nonexistent label, cpio lists hardlinks, tar writing into read-only dir
KNOWN_FAILING="|hostname-d-works|wget--O-overrides--P|wget-handles-empty-path|wget-handles-https|wget-retrieves-google-index|wget-supports--P|awk print negative zero as 0|cpio lists hardlinks|du include duplicated directory only once|ls -q|ls -Q|ls -qQ|sed embedded NUL|sed nonexistent label|sed NUL in command|tar writing into read-only dir|taskset (set_aff, needs CAP_SYS_NICE)|"
# "dpkg-deb -e" lists the extracted files with `find DEBIAN` and expects control before md5sums, i.e. the
# directory's readdir order. It passes on some filesystems and failed on the GitHub runner's, where the only
# host-dependent part of the case is that order. The same extraction is therefore re-checked here with sorted
# names and a content comparison, and the upstream case is excused only when that check passes.
dpkg_e_check() {
  local d rc=1
  d=$(mktemp -d) || return 1
  (
    cd "$d" && mkdir c bin \
      && printf 'Package: hello\nVersion: 1.2-3\n' > c/control && printf 'abc  bin/hello\n' > c/md5sums \
      && printf 'hi\n' > bin/hello && tar czf data.tar.gz bin && tar czf control.tar.gz -C c control md5sums \
      && printf '2.0\n' > debian-binary \
      && "$BUILD/busybox" ar rc hello.deb debian-binary control.tar.gz data.tar.gz \
      && "$BUILD/busybox" dpkg-deb -e hello.deb \
      && [ "$(ls DEBIAN | sort | tr '\n' ' ')" = "control md5sums " ] \
      && cmp DEBIAN/control c/control && cmp DEBIAN/md5sums c/md5sums
  ) >/dev/null 2>&1 && rc=0
  rm -rf "$d"
  return $rc
}
dpkg_e_ok=0; dpkg_e_extra_passed=0; dpkg_e_extra_failed=0
if dpkg_e_check; then dpkg_e_ok=1; dpkg_e_extra_passed=1; else dpkg_e_extra_failed=1; echo "FAILED: dpkg-deb -e (order-independent re-check)" >&2; fi

failed=0; env_skipped=0
while IFS= read -r n; do
  [ -n "$n" ] || continue
  case "$KNOWN_FAILING" in
    *"|$n|"*) env_skipped=$((env_skipped + 1)) ;;
    *) if [ "$n" = "dpkg-deb -e" ] && [ "$dpkg_e_ok" = 1 ]; then env_skipped=$((env_skipped + 1))
       else failed=$((failed + 1)); echo "FAILED: $n" >&2; fi ;;
  esac
done <<EOT
$failed_names
EOT
failed=$((failed + dpkg_e_extra_failed)); passed=$((passed + dpkg_e_extra_passed))

# Anything short of a real run of the suite is a failure, not a pass of zero tests.
if [ "$passed" -lt 500 ]; then
  echo "only $passed tests passed — the suite did not run (see $LOG)" >&2
  tail -20 "$LOG" >&2
  failed=$((failed + 1))
fi
emit_ctrf busybox-runtest "$passed" "$failed" $((skipped + env_skipped))
