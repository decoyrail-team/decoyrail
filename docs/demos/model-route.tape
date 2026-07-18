# Model router demo (Pro): a route rule allows like allow and rewrites the
# requested model per its explicit map, audited and marked on the response.
# The "LLM" is a local stub upstream (echo_upstream) mapped to a provider
# via pricing.json, so the whole demo runs offline.
# Needs a Pro license: set DECOYRAIL_DEMO_LICENSE to a license file path.
# Regenerate with scripts/render-demos.sh (run from the repo root).

# Frame matches decoyrail.com (paper-and-ink theme), overriding the preset's
# purple margin and rounded corners.
Set MarginFill "#171914"
Set BorderRadius 0

# Invisible setup: fresh throwaway state, a local TLS upstream standing in
# for an LLM API, a route rule written through the trusted edit path, and a
# Pro license.
Hide
Type `export PATH="$PWD/target/release:$PWD/target/release/examples:$PATH"; export DECOYRAIL_HOME="$(mktemp -d)"; unset SSL_CERT_FILE HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; for v in $(env | cut -d= -f1 | grep -iE 'api_key|token|secret|password'); do unset "$v"; done; echo_upstream 19281 "$DECOYRAIL_HOME/upstream.pem" >/dev/null 2>&1 & export DECOYRAIL_EXTRA_CA="$DECOYRAIL_HOME/upstream.pem"; sleep 1; printf '{"hosts": {"localhost": "anthropic"}}\n' > "$DECOYRAIL_HOME/pricing.json"; decoyrail ca path >/dev/null`
Enter
Sleep 3s
Type `printf '%s\n' '#!/bin/bash' 'printf "\n[[rule]]\nname = \"cheap-tier\"\nhosts = [\"localhost\"]\naction = \"route\"\nroute = { \"claude-opus-4\" = \"claude-haiku-4-5\" }\n" >> "$1"' > "$DECOYRAIL_HOME/append.sh"; chmod +x "$DECOYRAIL_HOME/append.sh"; EDITOR="$DECOYRAIL_HOME/append.sh" decoyrail policy edit >/dev/null`
Enter
Sleep 2s
Type `decoyrail license install "$DECOYRAIL_DEMO_LICENSE" >/dev/null; decoyrail proxy --addr 127.0.0.1:19280 >/dev/null 2>&1 & sleep 2; export https_proxy=http://127.0.0.1:19280 CURL_CA_BUNDLE="$DECOYRAIL_HOME/ca-cert.pem"; clear`
Enter
Sleep 5s
Show

Type `decoyrail policy ls | tail -4`
Sleep 1s
Enter
Sleep 5s

Type `curl -si https://localhost:19281/v1/messages -d '{"model":"claude-opus-4","messages":[{"role":"user","content":"summarize the diff"}]}' | grep -iE 'x-decoyrail|"model"'`
Sleep 1s
Enter
Sleep 7s

Type "decoyrail log -n 2"
Sleep 1s
Enter
Sleep 6s

# Invisible teardown so nothing outlives the recording.
Hide
Type `kill %1 %2 2>/dev/null; rm -rf "$DECOYRAIL_HOME"`
Enter
Sleep 1s
