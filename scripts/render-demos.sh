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
set -euo pipefail
cd "$(dirname "$0")/.."

env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy cargo build --release

for tape in docs/demos/*.tape; do
  env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
    ascii-gif render "$tape" -o "${tape%.tape}.gif" --quiet
  echo "rendered ${tape%.tape}.gif"
done
