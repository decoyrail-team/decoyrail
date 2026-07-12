#!/usr/bin/env bash
# Diff coverage gate: every changed line of src/ must be exercised by the test
# suite. This is the "code written, test quietly skipped" catch — a diff that
# adds logic without a test covering it fails here, whatever its author claims.
#
# Usage:   bash scripts/diff-cover.sh [base-ref]
#   base-ref defaults to the merge-base with origin/main (falling back to main),
#   so it measures exactly the lines this branch introduced.
# Env:
#   DIFF_COVER_MIN      minimum percent of changed instrumented lines covered
#                       (default 100)
#   DIFF_COVER_EXCLUDE  colon-separated repo-relative paths to skip
#                       (default src/main.rs — CLI glue, covered by e2e.sh
#                       which runs uninstrumented)
set -euo pipefail
cd "$(dirname "$0")/.."

# Cargo must not run through a Decoyrail proxy (crates.io would be blocked).
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

BASE="${1:-}"
if [[ -z "$BASE" ]]; then
  BASE="$(git merge-base HEAD origin/main 2>/dev/null || git merge-base HEAD main)"
fi

LCOV="target/diff-cover.lcov"
echo "==> Running instrumented test suite (cargo llvm-cov)"
cargo llvm-cov --lcov --output-path "$LCOV" >/dev/null

echo "==> Diff coverage vs $(git rev-parse --short "$BASE")"
# The diff goes through a file: python's stdin already carries the heredoc
# program below, so it can't also carry the diff.
DIFF_FILE="$(mktemp)"
trap 'rm -f "$DIFF_FILE"' EXIT
git diff -U0 --no-color "$BASE" -- 'src/*.rs' > "$DIFF_FILE"
python3 - "$LCOV" "$DIFF_FILE" <<'PY'
import os
import re
import sys

lcov_path = sys.argv[1]
diff_path = sys.argv[2]
min_pct = float(os.environ.get("DIFF_COVER_MIN", "100"))
excluded = set(
    filter(None, os.environ.get("DIFF_COVER_EXCLUDE", "src/main.rs").split(":"))
)
repo = os.getcwd()

# Changed (new-side) lines per file, from the unified-0 diff.
changed: dict[str, set[int]] = {}
current = None
for line in open(diff_path):
    if line.startswith("+++ b/"):
        current = line[6:].strip()
    elif line.startswith("@@") and current:
        m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
        if m:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count:
                changed.setdefault(current, set()).update(
                    range(start, start + count)
                )

changed = {f: lines for f, lines in changed.items() if f not in excluded}
if not changed:
    print("No changed lines in src/ (after exclusions); nothing to gate.")
    sys.exit(0)

# Hit counts per (repo-relative file, line) from the lcov report. A line can
# appear once per test binary; counts are summed.
hits: dict[str, dict[int, int]] = {}
with open(lcov_path) as f:
    sf = None
    for line in f:
        line = line.strip()
        if line.startswith("SF:"):
            path = line[3:]
            sf = os.path.relpath(path, repo) if os.path.isabs(path) else path
        elif line.startswith("DA:") and sf:
            ln, count = line[3:].split(",")[:2]
            file_hits = hits.setdefault(sf, {})
            file_hits[int(ln)] = file_hits.get(int(ln), 0) + int(count)

total = 0
covered = 0
uncovered: dict[str, list[int]] = {}
for f, lines in sorted(changed.items()):
    file_hits = hits.get(f)
    if file_hits is None:
        # File absent from the report entirely: nothing in it ran.
        file_hits = {}
    for ln in sorted(lines):
        if ln not in file_hits:
            continue  # not instrumented (blank/comment/signature)
        total += 1
        if file_hits[ln] > 0:
            covered += 1
        else:
            uncovered.setdefault(f, []).append(ln)

if total == 0:
    print("Changed lines carry no instrumented code; nothing to gate.")
    sys.exit(0)

pct = 100.0 * covered / total
print(f"Diff coverage: {covered}/{total} changed instrumented lines ({pct:.1f}%)")
if uncovered:
    print("Uncovered changed lines:")
    shown = 0
    for f, lines in sorted(uncovered.items()):
        # Collapse consecutive lines into ranges for readability.
        ranges, start, prev = [], lines[0], lines[0]
        for ln in lines[1:]:
            if ln == prev + 1:
                prev = ln
                continue
            ranges.append((start, prev))
            start = prev = ln
        ranges.append((start, prev))
        for a, b in ranges:
            print(f"  {f}:{a}" if a == b else f"  {f}:{a}-{b}")
            shown += 1
            if shown >= 100:
                print("  ... (truncated)")
                break
        if shown >= 100:
            break
if pct < min_pct:
    print(f"FAIL: below DIFF_COVER_MIN={min_pct:.0f}%")
    sys.exit(1)
print("PASS")
PY
