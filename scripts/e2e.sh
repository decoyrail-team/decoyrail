#!/usr/bin/env bash
# End-to-end smoke test for Decoyrail's core security behaviors, against a local
# in-process TLS upstream (no third-party dependency, runnable in CI/offline).
# Proves: TLS interception, decoy->real swap on approved host, tripwire block
# on off-policy decoy, policy deny on unknown host, tamper-evident audit.
set -euo pipefail

BIN="${BIN:-target/release/decoyrail}"
PORT="${PORT:-19077}"
UP_PORT="${UP_PORT:-19078}"
HOME_DIR="$(mktemp -d)"
export DECOYRAIL_HOME="$HOME_DIR"
# Never route through an inherited proxy / trust override during the test.
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy SSL_CERT_FILE || true

UP_CERT="$HOME_DIR/upstream.pem"
export DECOYRAIL_EXTRA_CA="$UP_CERT"

cleanup() {
  # `wait` reports 143 for the SIGTERM'd children; without `|| true`, errexit
  # (still in force inside the trap) turns that into the script's exit code
  # after every check has passed — and skips the rm below.
  [[ -n "${PROXY_PID:-}" ]] && { kill "$PROXY_PID" 2>/dev/null; wait "$PROXY_PID" 2>/dev/null || true; }
  [[ -n "${UP_PID:-}" ]] && { kill "$UP_PID" 2>/dev/null; wait "$UP_PID" 2>/dev/null || true; }
  rm -rf "$HOME_DIR"
}
trap cleanup EXIT

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1"; exit 1; }

echo "== decoyrail e2e (DECOYRAIL_HOME=$DECOYRAIL_HOME) =="

# A leftover listener from an aborted run serves a *stale* cert while
# DECOYRAIL_EXTRA_CA points at the fresh one — every TLS check then fails with
# a baffling BadSignature. Refuse to start instead.
for p in "$PORT" "$UP_PORT"; do
  if lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    fail "port $p is already in use (stale proxy/upstream from a previous run?)"
  fi
done

# 0. Build the local TLS upstream and start it. It writes its self-signed cert
#    to $UP_CERT, which DECOYRAIL_EXTRA_CA points at so Decoyrail trusts it.
cargo build --release --example echo_upstream >/dev/null 2>&1
UPSTREAM_BIN="${UPSTREAM_BIN:-target/release/examples/echo_upstream}"
"$UPSTREAM_BIN" "$UP_PORT" "$UP_CERT" >/dev/null 2>&1 &
UP_PID=$!
for i in $(seq 1 30); do [[ -s "$UP_CERT" ]] && break; sleep 0.2; done
kill -0 "$UP_PID" 2>/dev/null || fail "upstream died on startup"
UP="https://localhost:$UP_PORT"

# 1. Vault: a secret whose REAL value we can recognize when the upstream echoes
#    it, released at localhost via the --allow-host appended policy rule. A
#    second secret released nowhere must trip if sent toward localhost.
REAL="REALSECRET-$RANDOM$RANDOM"
"$BIN" vault add --name svc --env MY_TOKEN --allow-host localhost \
  --location header:x-secret --secret "$REAL" >/dev/null
"$BIN" vault add --name honeyonly \
  --location header:x-honey --secret "TRIPME-$RANDOM" >/dev/null

DECOY_SVC=$("$BIN" vault ls --json | python3 -c 'import json,sys;print(next(s["decoy"] for s in json.load(sys.stdin) if s["name"]=="svc"))')
DECOY_HONEY=$("$BIN" vault ls --json | python3 -c 'import json,sys;print(next(s["decoy"] for s in json.load(sys.stdin) if s["name"]=="honeyonly"))')
echo "  decoy(svc)=$DECOY_SVC"
echo "  decoy(honeyonly)=$DECOY_HONEY"
[[ "$DECOY_SVC" != "$REAL" ]] && pass "decoy differs from real secret" || fail "decoy equals real"

# 2. Policy: --allow-host appended an allow rule for localhost that releases
#    svc; the shipped default_action = deny handles the unknown-host case, and
#    honeyonly is listed in no rule. Check both landed in the file.
grep -q 'allow_secrets = \["svc"\]' "$HOME_DIR/policy.toml" \
  && pass "vault add --allow-host appended the releasing rule" \
  || fail "releasing rule missing from policy.toml"
RELEASED=$("$BIN" vault ls --json | python3 -c 'import json,sys;d=json.load(sys.stdin);print(",".join(next(s["released_by"] for s in d if s["name"]=="svc")), next(len(s["released_by"]) for s in d if s["name"]=="honeyonly"))')
[[ "$RELEASED" == "svc 0" ]] && pass "vault ls shows svc released, honeyonly tripwire-only" \
  || fail "unexpected release status: $RELEASED"

CA="$HOME_DIR/ca-cert.pem"
"$BIN" ca path >/dev/null   # materialize CA

# 3. Start proxy.
"$BIN" proxy --addr "127.0.0.1:$PORT" >/dev/null 2>&1 &
PROXY_PID=$!
for i in $(seq 1 30); do
  if curl -s -m 8 -o /dev/null -x "http://127.0.0.1:$PORT" --cacert "$CA" "$UP/headers" 2>/dev/null; then
    break
  fi
  sleep 0.3
done

PROXY="http://127.0.0.1:$PORT"

# 4. SWAP: send the decoy in x-secret to the approved host; the upstream echoes
#    the header it received — it must be the REAL value, not the decoy.
ECHO=$(curl -s -m 15 -x "$PROXY" --cacert "$CA" "$UP/headers" -H "x-secret: $DECOY_SVC")
if grep -q "$REAL" <<<"$ECHO"; then pass "decoy swapped to real secret at approved host"; else
  echo "$ECHO"; fail "real secret not seen upstream (swap failed)"; fi
if grep -q "$DECOY_SVC" <<<"$ECHO"; then fail "decoy leaked upstream"; else
  pass "decoy did not leak upstream"; fi

# 5. TRIPWIRE: send the other.invalid-bound decoy toward localhost -> blocked.
CODE=$(curl -s -m 15 -o /dev/null -w "%{http_code}" -x "$PROXY" --cacert "$CA" \
  "$UP/headers" -H "x-honey: $DECOY_HONEY")
[[ "$CODE" == "403" ]] && pass "tripwire blocked off-policy decoy (403)" || fail "tripwire did not block (got $CODE)"

# 6. POLICY DENY: unknown host -> blocked without ever forwarding.
CODE=$(curl -s -m 15 -o /dev/null -w "%{http_code}" -x "$PROXY" --cacert "$CA" \
  "https://denied.invalid:$UP_PORT/headers" 2>/dev/null || true)
[[ "$CODE" == "403" ]] && pass "unknown host denied by policy (403)" || fail "policy deny failed (got $CODE)"

# 7. AUDIT: chain verifies, and shows the tripwire + swap events. Capture the
#    full output first — piping into `grep -q` would close the pipe early.
VERIFY_OUT=$("$BIN" log --verify)
grep -q "OK" <<<"$VERIFY_OUT" && pass "audit hash chain verifies" || fail "audit chain broken"
LOG_OUT=$("$BIN" log -n 20)
grep -q "TRIPWIRE" <<<"$LOG_OUT" && pass "tripwire recorded in audit log" || fail "no tripwire in audit"

# 8. STATS: the analytics command sees the session's requests, denies, and
#    tripwire, and the one-line mode emits exactly one line.
STATS_OUT=$("$BIN" stats)
grep -q "1 tripwire" <<<"$STATS_OUT" && pass "stats counts the tripwire" || fail "stats missed the tripwire: $STATS_OUT"
LINE_OUT=$("$BIN" stats --line)
[[ $(wc -l <<<"$LINE_OUT" | tr -d ' ') == 1 ]] && grep -q "alerts" <<<"$LINE_OUT" \
  && pass "stats --line emits one line ($LINE_OUT)" || fail "stats --line malformed: $LINE_OUT"
"$BIN" stats --json | grep -q '"schema": 1' && pass "stats --json is schema v1" || fail "stats --json missing schema"

# 9. POLICY INTEGRITY: an out-of-band edit never loads. The running proxy
#    keeps the last good policy and raises the tamper alarm; a fresh start
#    refuses; blessing demands a TTY; a byte-identical restore just works.
cp "$HOME_DIR/policy.toml" "$HOME_DIR/policy.orig"
printf '# tampered out-of-band\n' >> "$HOME_DIR/policy.toml"

"$BIN" policy ls | grep -q "NOT TRUSTED" \
  && pass "policy ls reports the hand-edited file as untrusted" \
  || fail "policy ls missed the tamper"

if "$BIN" policy sign </dev/null >/dev/null 2>&1; then
  fail "policy sign must refuse without a TTY"
else
  pass "policy sign refuses without a TTY"
fi

# The next request makes the running proxy re-check the file: it must keep
# enforcing the last good policy (the swap still works) and write the
# distinct tamper event.
ECHO=$(curl -s -m 15 -x "$PROXY" --cacert "$CA" "$UP/headers" -H "x-secret: $DECOY_SVC")
grep -q "$REAL" <<<"$ECHO" && pass "running proxy kept the last good policy" \
  || fail "proxy behavior changed under a rejected policy"
grep -q '"action":"tamper"' "$HOME_DIR/audit.jsonl" \
  && pass "tamper event recorded in the audit log" \
  || fail "no tamper event in the audit log"
LOG_TAIL=$("$BIN" log -n 20)
grep -q '\[TAMP\]' <<<"$LOG_TAIL" \
  && pass "live log renders the tamper with alarm prominence" \
  || { echo "$LOG_TAIL"; fail "no [TAMP] line in the log"; }

# Started in the background so a wrongly-successful boot can't hang the
# script: alive after a second means it started, which is the failure.
"$BIN" proxy --addr "127.0.0.1:$((PORT+2))" >/dev/null 2>&1 &
BOOT_PID=$!
sleep 1
if kill -0 "$BOOT_PID" 2>/dev/null; then
  kill "$BOOT_PID" 2>/dev/null; wait "$BOOT_PID" 2>/dev/null || true
  fail "a fresh proxy must refuse to start on a tampered policy"
else
  wait "$BOOT_PID" 2>/dev/null || true
  pass "fresh proxy start fails closed on the tampered policy"
fi

cp "$HOME_DIR/policy.orig" "$HOME_DIR/policy.toml" && rm "$HOME_DIR/policy.orig"
ECHO=$(curl -s -m 15 -x "$PROXY" --cacert "$CA" "$UP/headers" -H "x-secret: $DECOY_SVC")
grep -q "$REAL" <<<"$ECHO" && pass "byte-identical restore loads with no blessing" \
  || fail "restored policy did not load"
"$BIN" policy ls | grep -q "integrity: trusted" \
  && pass "policy ls reports the restored file as trusted" \
  || fail "restored file not reported trusted"

echo "== all e2e checks passed =="
"$BIN" status
