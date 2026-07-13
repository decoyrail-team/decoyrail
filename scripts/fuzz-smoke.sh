#!/usr/bin/env bash
# Run every fuzz target briefly, seeded from fuzz/seeds/. A smoke pass, not a
# campaign: it proves the invariants hold on the seed corpus plus a short
# random exploration, and that no target has bit-rotted. Leave a target
# running overnight (cargo +nightly fuzz run <target> fuzz/seeds/<target>)
# for a real campaign.
#
# Usage: bash scripts/fuzz-smoke.sh [seconds-per-target]   (default 30)
# Needs: rustup nightly toolchain + cargo-fuzz.
set -euo pipefail
cd "$(dirname "$0")/.."

# Cargo must not run through a Decoyrail proxy (crates.io would be blocked).
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

SECS="${1:-30}"

for target in $(cargo +nightly fuzz list); do
  echo "==> fuzz $target (${SECS}s)"
  # First corpus dir is where libFuzzer writes new entries; keep that in the
  # gitignored fuzz/corpus/ and pass the committed seeds read-only after it.
  corpus="fuzz/corpus/$target"
  mkdir -p "$corpus"
  seeds="fuzz/seeds/$target"
  [[ -d "$seeds" ]] || seeds=""
  cargo +nightly fuzz run "$target" "$corpus" $seeds -- \
    -max_total_time="$SECS" -rss_limit_mb=4096 -print_final_stats=0
done
echo "PASS: all fuzz targets survived"
