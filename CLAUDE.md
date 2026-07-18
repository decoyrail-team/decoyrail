# Decoyrail: notes for Claude Code

Endpoint firewall for AI agents: a single Rust binary that runs coding agents
behind a local TLS-intercepting proxy. The agent holds decoy credentials; the
proxy swaps in the real secret only for approved destinations and treats a
decoy seen elsewhere as an exfiltration tripwire. Roadmap in `ROADMAP.md`,
user-facing docs in `docs/` (start at `docs/README.md`), threat model in
`docs/threat-model.md`.

## Build / test / run

```sh
cargo build                       # debug
cargo build --release             # release (LTO + strip)
cargo test                        # unit + integration tests
cargo test --test proxy_integration   # the in-process proxy e2e (Rust)
cargo clippy --all-targets -- -D warnings
cargo fmt --all                   # CI enforces --check
bash scripts/e2e.sh               # live e2e vs a local TLS upstream
bash scripts/diff-cover.sh        # gate: changed src/ lines must be test-covered
bash scripts/fuzz-smoke.sh 30     # all fuzz targets briefly (nightly + cargo-fuzz)
```

CI (`.github/workflows/ci.yml`) runs fmt-check, clippy `-D warnings`, tests,
the e2e script, the diff-coverage gate (PRs only), and the fuzz smoke on
`macos-latest`.

The diff-coverage gate (`cargo llvm-cov` + `scripts/diff-cover.sh`) fails any
diff whose changed `src/` lines the test suite never executes; add a covering
test rather than lowering `DIFF_COVER_MIN` (`src/main.rs` is excluded: CLI
glue, exercised by the uninstrumented e2e). Fuzz targets live in
`fuzz/fuzz_targets/` with committed seeds in `fuzz/seeds/`; they assert real
invariants (no real-secret leak without release+TLS in `swap_roundtrip`,
chunking-invariant usage metering in `usage_parse`, JSON-preserving body
rewrites in `proxy_surface`), so extend them when those surfaces change.

## Conventions that aren't obvious from the code

- **`DECOYRAIL_HOME`** overrides `~/.decoyrail` (state dir: vault, CA, policy, audit,
  meter, budget). Every test and the e2e script set it to a temp dir; use it to
  run against throwaway state. Tests that mutate this process-global env are
  serialized with `util::env_guard()`.
- **`DECOYRAIL_EXTRA_CA`** points at a PEM bundle added as an extra trust root for
  *upstream* verification (enterprise internal CA, or a test's local upstream).
  It never disables verification.
- **`DECOYRAIL_DEBUG`** makes the proxy print per-connection errors (otherwise
  quiet, since clients hang up routinely).
- **Never run cargo through a Decoyrail proxy.** If your shell has `HTTPS_PROXY`
  set (e.g. you're inside `decoyrail run`), `cargo fetch`/`test` that need
  crates.io will be blocked by policy. Clear the proxy env for cargo:
  `env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy cargo ...`.

## Module map

`ca.rs` device CA + per-host leaf minting · `vault.rs` encrypted real vault +
deterministic decoys + provider labels + vault-key backend selection/migration
(`decoyrail key`) · `keyring.rs` macOS login-keychain item for the vault key
(silently readable only by this binary, bound to the default home) ·
`guard.rs` session vault: auto-decoy
sensitive env vars for `decoyrail run` · `swap.rs` decoy↔real substitution + tripwire
(incl. encoded-form detection) · `detect.rs` request-side DLP detectors
(PAN/SSN/IBAN/ABA/email; block|mask|warn|off per detector in policy `[dlp]`;
`debug = true` dumps hit payloads, secrets scrubbed, to `dlp-debug/`) ·
`policy.rs` rules-first egress policy + per-rule secret release
(`allow_secrets`) + the trusted/parse-only load split (`load_trusted` vs
`load_or_default`) · `integrity.rs` policy integrity (plan 018): keyed record
in `policy.toml.sig` (HMAC under a key derived from the vault key), verify
verdicts, the one recorded write path (`install`), blessing
(`decoyrail policy sign`), diff ·
`audit.rs` hash-chained, lock-serialized, head-anchored tamper-evident log ·
`meter.rs` spend metering + budget + subscription reference cost and the
declared plan price/verdict (`decoyrail plan`, plan 019) · `pricing.rs`
per-model token pricing + provider `usage` accounting (built-in table,
`pricing.json` overrides) + the billable/reference split (`split_cost`) ·
`license.rs` offline signed license unlocking paid tiers, fails open to Free
(never blocks traffic; `decoyrail license`) · `cache.rs` prompt-cache layer:
observe-only hygiene doctor per host+model, `decoyrail cache` report
(state in `cache.json` holds offsets/counters, never prompt content; it sees
the pre-swap body, so nothing derives from a real secret); plus the Pro
active layer: byte-surgical `cache_control` repair (`splice_marker`),
fan-out serialization (`FanoutGate`), and keep-alive pre-warm scheduling
(`KeepAlive`), all off unless `[cache]` in the policy opts in and the license
is Pro ·
`stats.rs` analytics over the audit log
(`decoyrail stats`: windows/breakdowns/JSON/one-line; incremental aggregate
cache in `stats-cache.json`) · `proxy.rs` CONNECT + TLS MITM + plaintext
HTTP + request pipeline · `engine.rs` shared runtime state + hot-reload ·
`config.rs` paths + atomic writes · `main.rs` CLI. `src/lib.rs` exposes these
modules so `tests/` can drive the pipeline in-process.

## Invariants worth preserving

- Real secrets leave only over TLS, only where the winning policy rule's
  `allow_secrets` releases them, only in the secret's location. The
  upstream client follows no redirects and honors no env proxy; don't loosen
  either without re-reading `swap.rs` and `engine.rs`.
- Fail closed: policy defaults to deny, `escalate` falls back to deny until the
  judge ships, tripwire/DLP-block/over-budget override an allow. DLP audit
  events carry salted fingerprints only, never the matched value. `[dlp]`
  debug mode writes payloads to owner-only dump files (real secrets scrubbed
  first) and puts only the file path in the audit note.
- SSE responses pass through untouched (latency); other responses are buffered
  up to `SCAN_CAP` and scanned for echoed real secrets.
- The prompt-cache active layer (repair, keep-alive, fan-out) is Pro + policy
  opt-in and never gates a security verb: the tier read sits behind the
  security pipeline, so no license state can block traffic. Repair mutates only
  `cache_control` metadata, byte-surgically on the original body, so the model
  reads byte-identical content. A keep-alive pre-warm re-runs policy + swap, so
  a real secret rides it only to a releasing destination over TLS, exactly like
  a forwarded request; templates live in memory only, never on disk. Every
  injection and pre-warm is audited (`cache` / `keepalive`).
- The keychain vault-key backend is presence-selected (item bound to the default home exists), never a config flag, and is consulted only when `DECOYRAIL_HOME` is unset or canonically equal to `~/.decoyrail`, so tests and the e2e script always get the file backend. A release build's first run against the default home mints the key directly in the keychain; dev builds stay on the file (unsigned binaries re-prompt every rebuild). A selected-but-failed keychain read aborts; it must never fall back to minting a fresh file key. The one permitted fallback is first-run creation (`create_default_key`): if the keychain write fails while nothing is encrypted yet, mint the file key instead. Coverage builds (`--cfg coverage`) swap `load_or_create_key` for its file arm so the untestable OS wiring stays out of the diff gate; the logic behind it is covered via mock stores.
- The proxy loads only a policy that verifies against `policy.toml.sig`
  (`Policy::load_trusted`): no record, a mismatch, or a missing file with a
  record all fail closed, with no trust-on-first-use window and no off
  switch, in every home. The MAC covers raw bytes (byte-identical restore
  must verify) under a key derived from the vault key, so `decoyrail key
  migrate` moves both protections and the strength tracks the backend.
  Every Decoyrail policy write goes through `integrity::install` (record
  first, then the atomic rename; the reload only re-verifies on an mtime
  move, and it watches both files). CLI mutations refuse to build on an
  untrusted file (no tamper laundering); `policy sign` (TTY-only) and
  `policy reset` are the ways back. A rejected load audits as `tamper`
  (alarm prominence), distinct from the parse-failure `alert`; every write
  and blessing audits as `policy` with the file's sha256. Tests write
  policies via `policy_edit::write_policy`, never `fs::write`.
