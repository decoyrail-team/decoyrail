# Spend tripwire demo: an agent wedged in a retry loop is caught in minutes,
# watched live with `decoyrail log -t`, and cleared explicitly by the operator.
# The "LLM" is a local stub upstream (echo_upstream) mapped to a provider via
# pricing.json, so the whole demo runs offline.
# Regenerate with scripts/render-demos.sh (run from the repo root).

# Frame matches decoyrail.com (paper-and-ink theme), overriding the preset's
# purple margin and rounded corners.
Set MarginFill "#171914"
Set BorderRadius 0

# Invisible setup: fresh throwaway state, no inherited proxies or real keys,
# a local TLS upstream standing in for an LLM API, and the proxy started so
# CA generation doesn't stall the visible part.
Hide
Type `export PATH="$PWD/target/release:$PWD/target/release/examples:$PATH"; export DECOYRAIL_HOME="$(mktemp -d)"; unset SSL_CERT_FILE HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; for v in $(env | cut -d= -f1 | grep -iE 'api_key|token|secret|password'); do unset "$v"; done; echo_upstream 19171 "$DECOYRAIL_HOME/upstream.pem" >/dev/null 2>&1 & export DECOYRAIL_EXTRA_CA="$DECOYRAIL_HOME/upstream.pem"; sleep 1; printf '{"hosts": {"localhost": "anthropic"}}\n' > "$DECOYRAIL_HOME/pricing.json"; decoyrail policy add local-llm --host localhost --action allow >/dev/null; decoyrail ca path >/dev/null; decoyrail proxy --addr 127.0.0.1:19170 >/dev/null 2>&1 & sleep 2; export https_proxy=http://127.0.0.1:19170 CURL_CA_BUNDLE="$DECOYRAIL_HOME/ca-cert.pem"; clear`
Enter
Sleep 5s
Show

Type `while true; do curl -s https://localhost:19171/v1/messages -d '{"model":"claude-sonnet-5","messages":[{"role":"user","content":"fix the build"}]}' -o /dev/null; sleep 0.4; done &`
Sleep 1s
Enter
Sleep 1s

Type "decoyrail log -t"
Sleep 1s
Enter
Sleep 16s
Ctrl+C
Sleep 1s

Type "decoyrail trip"
Sleep 1s
Enter
Sleep 5s

Type "decoyrail trip clear"
Sleep 1s
Enter
Sleep 4s

# Invisible teardown so nothing outlives the recording.
Hide
Type `kill %1 %2 2>/dev/null; rm -rf "$DECOYRAIL_HOME"`
Enter
Sleep 1s
