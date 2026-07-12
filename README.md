# Decoyrail

Decoyrail is an endpoint firewall for AI agents. It is a single macOS/Unix
binary that runs coding agents (Claude Code, Codex CLI, and similar) with
decoy credentials, so real secrets never enter the agent's environment. An
embedded TLS-intercepting proxy is the only road to a real secret: it swaps
the real value in only for approved destinations, blocks everything
off-policy, and treats a decoy seen heading anywhere else as an exfiltration
tripwire. An agent that sidesteps the proxy sends decoys that work nowhere.

Scope, stated up front: Decoyrail currently runs as your user, in
explicit-proxy mode. It guards the configured network path against
accidental secret inclusion and prompt-driven exfiltration. It is not yet an
enforceable boundary against hostile code that attacks Decoyrail's own
on-disk state as the same user; the privileged system mode on the
[roadmap](ROADMAP.md) is what closes that. The
[threat model](docs/threat-model.md) draws every line precisely.

![A decoy AWS key sent to an unapproved host is blocked, and decoyrail log records the exfiltration attempt](docs/demos/tripwire.gif)

This README covers what works today; what's coming next is in
[`ROADMAP.md`](ROADMAP.md).

## What works today

- **Decoy vault.** Real secrets are stored encrypted (ChaCha20-Poly1305).
  Each gets a deterministic, format-correct decoy (`sk-ant-…`, `ghp_…`,
  `AKIA…`). Agents only ever see decoys.
- **Automatic decoying for `decoyrail run`.** Sensitive-looking terminal env
  vars are replaced with decoys for the child process, without any vault
  setup. Opt out per variable with `--pass-env`, or entirely with
  `--pass-all-env`.
- **TLS interception.** Per-device CA, per-host leaf certificates. SSE and
  streaming responses pass through untouched; bounded responses are scanned
  for echoed real secrets.
- **Secret swap.** Decoy to real, in headers or body. The policy rule that
  allows a destination also says which secrets it releases
  (`allow_secrets`); the real secret leaves the machine only toward those
  destinations, only over TLS, only in the location the secret rides in.
- **Tripwire.** A decoy headed anywhere its winning rule does not expect is
  blocked and recorded, whether it appears literally, in an encoded form
  (base64, hex, percent), in the URL, or inside a binary body.
- **Egress policy.** Ordered allow / deny / escalate rules with a
  default-deny posture and a starter pack tuned for coding agents.
  Reachability and secret release live in the same rules. `escalate` fails
  closed to deny (no judge tier yet).
- **Exact spend metering.** Per-model token accounting parsed from provider
  `usage` fields (cache tokens at their own rates), priced from a built-in
  table with `pricing.json` overrides; byte-based estimates only where usage
  can't be parsed, labeled as estimates. Subscription traffic is detected and
  kept off the budget. A monthly budget and a kill switch deny requests once
  the budget is spent.
- **Sensitive-data filtering.** Request-side detectors for card numbers,
  SSNs, IBANs, bank routing numbers, and emails; block, mask, or warn per
  detector in policy. Audit events carry salted fingerprints, never the
  matched value.
- **Analytics.** `decoyrail stats`: spend, tokens, and security events by
  window, session, model, or destination, with JSON output for scripts.
- **Prompt-cache doctor.** `decoyrail cache` reports your provider
  prompt-cache hit rate and what keeps breaking it (observe-only; the active
  repair layer is a licensed feature).
- **Keychain-backed vault key (macOS).** `decoyrail key migrate` moves the
  vault key into a login-keychain item only this binary reads silently,
  closing the silent same-user key-read path.
- **Tamper-evident audit.** Append-only, hash-chained JSONL with the writing
  process's pid on every event. `decoyrail log --verify` detects edits and
  mid-file deletions via the chain, and truncation or deletion via a
  persisted head anchor. An attacker with write access to `~/.decoyrail` can
  still rewrite both consistently; hardware-backed head storage is on the
  roadmap. See the [threat model](docs/threat-model.md).

## Quick start

```sh
brew install decoyrail-team/tap/decoyrail   # or build it: cargo build --release

# 1. Trust the device CA (macOS login keychain).
decoyrail ca install

# 2. Run your agent behind Decoyrail. With a Claude subscription this is
#    the whole setup: default-deny egress, an audit log, and any other
#    credentials in your terminal env auto-decoyed.
decoyrail run -- claude

# 3. Only if you use an API key: vault it. The agent then sees a decoy as
#    ANTHROPIC_API_KEY; api.anthropic.com receives the real key (the default
#    policy releases recognized Anthropic keys there).
#    Omit --secret to be prompted (hidden), or pipe it: `... --secret - < key.txt`.
decoyrail vault add \
  --name anthropic --env ANTHROPIC_API_KEY --location bearer

# Watch every decision live in a second terminal (like `tail -f`),
# or inspect after the fact.
decoyrail log -t
decoyrail log -n 20
decoyrail status
```

The full walkthrough (locations for different auth styles, editing policy,
pointing GUI apps at the proxy, enterprise internal CAs, budgets,
troubleshooting) is in **[docs/getting-started.md](docs/getting-started.md)**.

## Documentation

| Doc | What's in it |
|---|---|
| [Getting started](docs/getting-started.md) | install and protect your first agent |
| [How it works](docs/how-it-works.md) | architecture and the path of every request, with diagrams |
| [Policy reference](docs/policy.md) | rule matching, ordering, `allow_secrets`, `escalate` semantics |
| [Vault & secret release](docs/vault-and-bindings.md) | secrets, decoy formats, release rules, auto-decoying |
| [Audit & metering](docs/audit-and-metering.md) | audit schema, chain verification, budgets |
| [Threat model](docs/threat-model.md) | what is and is not defended against |

## Commands

| Command | Purpose |
|---|---|
| `decoyrail run -- <cmd>` | Launch a command with decoys, proxy, and CA trust wired into its env. |
| `decoyrail proxy` | Run the proxy standalone (point other apps at it). |
| `decoyrail vault add/ls/rm` | Manage real secrets (where each is released shows in `ls`). |
| `decoyrail policy show/path` | Inspect the egress policy. |
| `decoyrail log [-n N] [-t] [--pid P] [--verify]` | View, follow, filter, or verify the audit log. |
| `decoyrail stats` | Spend, token, and security analytics over the audit log. |
| `decoyrail dlp show/set` | Configure the sensitive-data detectors. |
| `decoyrail key status/migrate` | Choose where the vault key lives (file or macOS keychain). |
| `decoyrail cache` | Prompt-cache hit rate and hygiene report. |
| `decoyrail license install/status` | Manage the offline license (security is never gated). |
| `decoyrail status` / `decoyrail budget <usd>` | Spend visibility and the monthly budget. |
| `decoyrail ca install/uninstall/path` | Install, remove, or locate the device CA trust root. |
| `decoyrail uninstall` | Remove everything: CA trust, keychain items, and `~/.decoyrail`. |

## Verify it end-to-end

```sh
cargo test            # unit + integration tests (vault, swap, policy, audit, meter, proxy)
bash scripts/e2e.sh   # live: swap, tripwire, policy deny, and audit against a local TLS upstream
```

## Layout

```
src/
  ca.rs      device CA + per-host leaf minting
  vault.rs   encrypted real vault + deterministic decoy generation
  keyring.rs macOS login-keychain item for the vault key
  guard.rs   session vault: auto-decoy sensitive env vars
  swap.rs    decoy-to-real substitution and tripwire detection
  detect.rs  request-side sensitive-data detectors
  policy.rs  rules-first egress policy (+ default pack)
  audit.rs   hash-chained tamper-evident log
  meter.rs   spend metering, budget, kill switch
  pricing.rs per-model token pricing + provider usage accounting
  license.rs offline signed license (fails open to the free tier)
  cache.rs   prompt-cache doctor + licensed repair layer
  stats.rs   analytics over the audit log
  proxy.rs   CONNECT + TLS-terminating MITM, request pipeline, streaming passthrough
  engine.rs  shared runtime state
  main.rs    CLI
```

## Threat model (summary)

Today Decoyrail runs in explicit-proxy mode: the trust boundary is a local
process that the agent's HTTPS traffic is routed through. It defends against secret
exfiltration to unapproved destinations (the agent only ever holds decoys;
the real secret is swapped in only where policy releases it, over TLS),
off-policy egress (default-deny, everything recorded), and history
tampering (hash-chained, head-anchored audit log).

It does not defend against a same-user attacker reading `~/.decoyrail` off
disk or editing the policy that decides where secrets are released (a
privileged system mode is on the roadmap), an agent that bypasses the proxy
(worst case: a failed request carrying a useless decoy), decoys obfuscated
beyond the scanned encodings, cert-pinned apps (allowlist-only fallback), or
in-memory exposure inside the proxy itself.

In one sentence: same-user mode is a guardrail against accidents and
prompt-driven exfiltration along the configured network path, not yet an
enforceable boundary against arbitrary hostile code running as your user.

The full **[threat model](docs/threat-model.md)** spells out each limit.

## Status and limitations

Not yet built: machine-wide capture (Network Extension), LLM-as-judge, AWS
SigV4 re-signing, SSRF/private-range blocking, per-source rate limiting, and
the admin GUI. [`ROADMAP.md`](ROADMAP.md) has the order.

## License

The endpoint core (this repository) is licensed under the
[Functional Source License, v1.1, ALv2 future license](LICENSE). It is
source-available so you can audit and build the exact binary that intercepts
your TLS and holds your keys, and each release converts to Apache-2.0 two
years after it ships. Fleet-management components (admin console, policy
distribution, SIEM content packs) will be proprietary. The dividing rule:
anything that protects a single machine is FSL, anything that manages many
machines is commercial.
