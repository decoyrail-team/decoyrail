# Waste report demo: `decoyrail stats --waste` prices what a session wasted
# and why — retried identical requests, runaway loops, and what the spend
# tripwire refused to keep paying for. The "LLM" is a local stub upstream
# (echo_upstream) mapped to a provider via pricing.json, so the whole demo
# runs offline; the traffic it prices happens in the hidden setup below.
# Regenerate with scripts/render-demos.sh (run from the repo root).

# Frame matches decoyrail.com (paper-and-ink theme), overriding the preset's
# purple margin and rounded corners.
Set MarginFill "#171914"
Set BorderRadius 0

# Invisible setup: fresh throwaway state, a local TLS upstream standing in
# for an LLM API, then a plausible session: three distinct requests, one
# request retried 5x, and one runaway loop the tripwire cuts off.
Hide
Type `export PATH="$PWD/target/release:$PWD/target/release/examples:$PATH"; export DECOYRAIL_HOME="$(mktemp -d)"; unset SSL_CERT_FILE HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; for v in $(env | cut -d= -f1 | grep -iE 'api_key|token|secret|password'); do unset "$v"; done; echo_upstream 19181 "$DECOYRAIL_HOME/upstream.pem" >/dev/null 2>&1 & export DECOYRAIL_EXTRA_CA="$DECOYRAIL_HOME/upstream.pem"; sleep 1; printf '{"hosts": {"localhost": "anthropic"}}\n' > "$DECOYRAIL_HOME/pricing.json"; decoyrail policy add local-llm --host localhost --action allow >/dev/null; decoyrail ca path >/dev/null; decoyrail proxy --addr 127.0.0.1:19180 >/dev/null 2>&1 & sleep 2; llm() { curl -s -m 10 -x http://127.0.0.1:19180 --cacert "$DECOYRAIL_HOME/ca-cert.pem" https://localhost:19181/v1/messages -d '{"model":"claude-sonnet-5","messages":[{"role":"user","content":"'"$1"'"}]}' -o /dev/null; }; for m in "read the failing test" "propose a fix" "apply the patch"; do llm "$m"; done; for i in 1 2 3 4 5; do llm "run the flaky suite"; done; for i in $(seq 1 18); do llm "fix the build"; done; clear`
Enter
Sleep 12s
Show

Type "decoyrail stats --line"
Sleep 1s
Enter
Sleep 4s

Type "decoyrail stats --waste"
Sleep 1s
Enter
Sleep 14s

# Invisible teardown so nothing outlives the recording.
Hide
Type `kill %1 %2 2>/dev/null; rm -rf "$DECOYRAIL_HOME"`
Enter
Sleep 1s
