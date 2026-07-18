#!/usr/bin/env bash
# Regenerate the demo GIFs embedded in the docs from the tapes in docs/demos/.
#
# Requires ascii-gif and its runtime deps:
#   go install github.com/tamnd/ascii-gif/cmd/ascii-gif@latest
#   brew install ttyd ffmpeg
#
# The tapes run the real binary against a throwaway DECOYRAIL_HOME, so this
# never touches ~/.decoyrail. Run it outside `decoyrail run` (or let the
# env -u below clear the proxy for the build).
#
# Two tapes demo Pro-gated features (soft-landing.tape, model-route.tape) and
# need a Pro license: set DECOYRAIL_DEMO_LICENSE to an absolute path to one
# (no ~; it is passed through to the tape shell verbatim). Without it, those
# two are skipped, since an unlicensed run would record a misleading Free-tier
# no-op instead of the rewrite the demo is about.
set -euo pipefail
cd "$(dirname "$0")/.."

PRO_TAPES=" soft-landing model-route "

env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy cargo build --release
# The spend-tripwire, waste-report, soft-landing, and model-route tapes run
# against the local stub upstream, the same one the e2e script uses.
env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy cargo build --release --example echo_upstream

for tape in docs/demos/*.tape; do
  name="$(basename "${tape%.tape}")"
  if [[ "$PRO_TAPES" == *" $name "* && -z "${DECOYRAIL_DEMO_LICENSE:-}" ]]; then
    echo "skipping $name (Pro feature; set DECOYRAIL_DEMO_LICENSE to render it)"
    continue
  fi
  env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    DECOYRAIL_DEMO_LICENSE="${DECOYRAIL_DEMO_LICENSE:-}" \
    ascii-gif render "$tape" -o "${tape%.tape}.gif" --quiet
  echo "rendered ${tape%.tape}.gif"
done
