# Roadmap

Where Decoyrail is going, phase by phase. Each phase opens with the bar it
has to clear to count as done; phases ship when they clear it, which is why
there are no dates on this page. For what works *today*, see the
[README](README.md) and [docs](docs/README.md).

The long arc: Decoyrail starts as the **security boundary** for AI agents
(decoy credentials, egress policy, tripwires) and, once that boundary is
trusted, becomes the natural place to govern and measure everything that
crosses it.

## Working core (shipped: the v0.2.x releases)

An encrypted decoy vault with policy-declared secret release, a TLS-intercepting proxy
with SSE passthrough, the decoy-to-real swap with tripwires (including
encoded-form detection), a default-deny egress policy with an escalate tier
that fails closed, spend metering with a monthly budget and kill switch, a
hash-chained and head-anchored audit log, hot reload, and integration tests
plus a live e2e script.

Not in the product yet: machine-wide capture, the LLM judge, SigV4
re-signing, SSRF blocking, rate limiting, and any GUI. The phases below cover
them.

## v0.3: The boundary pays for itself (shipped: the v0.3.x releases)

*The bar: Decoyrail can show a team, in dollars, what it saved them last
month, and the number is bigger than its own bill.*

The proxy that inspects every request is also the only thing positioned to
make those requests cheaper: it sees all the traffic, from stock agents,
with no configuration change. A gateway can only optimize traffic that was
configured to route through it; an endpoint proxy measures and improves
everything, including traffic that would have skipped a gateway. And it
composes with the gateway you may already run (LiteLLM, OpenRouter, a
corporate proxy): Decoyrail can sit in front of it, with the gateway key
vaulted like any other secret, so even that credential never rests in an
agent's environment. This phase comes before the fleet phases because
everything in it serves a single seat with no IT involvement: install it,
run your agent, and the report speaks for itself. Security features stay
free, always. In this phase, measurement is free for everyone and the
automatic fixes are the paid tier.

- **Accurate spend metering** (free, shipped): the proxy parses the token
  counts providers report in responses (Anthropic and OpenAI `usage` fields,
  cache tokens at their own rates) and prices them per model from a built-in
  table with a hot-reloadable `pricing.json` override. Streaming responses
  are scanned as they pass, never buffered, so the SSE latency guarantee
  holds. Billing mode is part of the accounting: subscription traffic
  (Claude Code signed into a Claude plan, say) is detected by its auth
  shape, tagged, and kept off the budget, since a flat plan adds no
  per-request bill. Its tokens are still metered in full; the
  reference-cost item below covers why a flat plan is not free
  tokens. Token counts also land in the audit log per
  request. Where usage can't be parsed, the byte estimate remains and is
  labeled as an estimate. Accurate metering stays in the free core; the
  fleet roll-up in v0.4 is what the team tiers add.
- **The waste report** (free, shipped): the metering above, turned into a
  verdict. `decoyrail stats --waste` reports what was identifiably wasted
  this month and why: retried identical requests, runaway loops, and cache
  misses on repeated context, priced in dollars, with billable and
  plan-absorbed kept apart and unpriceable repeats flagged rather than
  guessed at.
- **Reference cost for subscription plans** (free): flat plans are not free
  tokens. The included allowance runs out, heavy sessions hit plan limits,
  and usage past the plan bills at API rates. Subscription traffic keeps
  its zero marginal spend for the budget, but the waste report prices it at
  API-equivalent rates, so you can see what your plan absorbed this month,
  how close you are to outgrowing it, and what your waste costs in the
  currency that matters on a plan: headroom.
- **Spend tripwire** (free, shipped): an agent stuck re-sending the same
  request, or burning tokens far faster than its own baseline, gets caught
  in minutes, not at the end of the month. Alert or block, your choice, and
  the block explains itself so the agent can break its own loop. Clearing a
  trip is an explicit command (`decoyrail trip clear`), never a timeout.
- **Budget soft-landing**: past a threshold you set, traffic downgrades to a
  cheaper model instead of stopping. The kill switch stays for the hard
  limit. Every downgrade is audited and visible; nothing is ever silent.
- **Prompt-cache tuning** (diagnosis free, fixes paid; shipped): provider
  prompt caches cut repeated-context cost
  by up to 90%, and agent traffic wastes them constantly. Decoyrail measures
  your hit rate, points at the exact byte that keeps breaking your cache,
  then fixes what can be fixed without touching content: cache markers where
  they're missing, keep-alives so a warm cache survives a long build, and
  smart release of parallel requests so they share one cache write instead
  of each paying full price. None of this changes what the model reads. And
  the results check themselves: the free report names the dollar figure,
  the fix makes next month's report smaller, and you can do the math on
  your own audit log.
- **Model routing by policy**: rules like "this team gets Sonnet at most" or
  "batch jobs run on the cheap tier", written in the same policy engine as
  everything else, with every rewrite audited and marked.

## v0.4: Manageable by IT

*The bar: an IT admin can install Decoyrail on a handful of developer
Macs, author and push signed rules from one console, and review the fleet's
audit trail in the log/SIEM system they already run, without touching a
terminal on any dev machine.*

- **Admin console.** A web UI served by `decoyrail console`: rule editing with
  validation and ordering, dry-run against recorded traffic, then sign and
  publish a policy bundle (org Ed25519 key). Plus a spend view: per seat, per
  model, per project, with exportable chargeback reports. Nobody today can
  answer "what do AI agents cost us per team, across providers" from one
  screen; the boundary that meters every request can.
- **Policy distribution.** Endpoints pull signed, versioned bundles with
  rollback; enrolled machines reject unsigned local edits. Bundles can carry
  org-set budgets and model rules ("contractors get claude-sonnet only",
  "deny models above this price"), enforced by the same kill switch that
  guards local budgets.
- **System mode (privilege separation).** The daemon runs as a dedicated
  service user via LaunchDaemon; state lives in a root-installed directory
  that non-admin users can't read or modify; the vault becomes **write-only**
  (GitHub-Actions-secret semantics: values go in, only the swap comes out).
- **Audit via your log pipeline.** A versioned JSONL event schema with
  machine/user/process identity, log rotation designed around the hash chain,
  optional syslog/TCP-TLS output, and a SIEM content pack (Splunk/Datadog
  dashboards plus a tripwire alert rule). No collector of ours required.
- **Secret provisioning.** Policy bundles carry release *templates*, never
  values; real values arrive via an MDM one-liner, a one-time prompt, or (for
  teams on 1Password without MDM) a shared 1Password vault that endpoints
  read by reference.
- **Distribution.** A signed and notarized `.pkg` with enrollment and a
  Homebrew tap. Versioned checksummed releases and the clean uninstall
  (`decoyrail uninstall`, including `decoyrail ca uninstall`) already ship.
- **Request-path hardening.** SSRF/private-range blocking that overrides
  policy allows (with resolved-IP pinning against DNS rebinding), per-source
  rate limiting, and AWS SigV4 re-signing.
- **Offline org licensing.** One signed file per org covering seats, expiry,
  and grace; no phone-home, air-gap friendly.

Through all of this, the surface a developer sees stays deliberately thin:
`decoyrail run`, `decoyrail status`, and (in v0.5) approval prompts. A
security tool that developers resent gets routed around, so staying out of
the way is a design goal, not a nicety.

## v0.5: Policy intelligence

*The bar: `escalate` resolves to something better than deny, and admins
stop writing rules by hand.*

- **LLM-as-judge** on `escalate`, with a ladder of opt-in backends that all
  keep the offline story: Apple's on-device Foundation Models where available
  (zero setup, no per-token cost, typed verdicts via guided generation), a
  local model (MLX or llama.cpp on Apple Silicon), or your own endpoint. Two
  invariants hold for every backend: the judge only resolves `escalate` and
  can never override a deny, a tripwire, or the budget kill switch; and an
  unavailable or timed-out judge means `escalate` falls back to deny, exactly
  as today. The judge is fed request *metadata* (host, path, method, the
  winning rule and what it releases, recent history) rather than raw body text wherever possible, since
  body text is attacker-influenced and the less of it the judge reads, the
  less there is to inject.
- **Human approvals**: a menubar app (a Swift shim over the same core) with an
  approval queue, a live egress view, and a kill switch. On managed fleets,
  org policy sets what the judge may auto-allow; everything else lands in
  this queue.
- **Secret backends.** A backend trait behind the vault: the encrypted file
  stays the default, macOS Keychain adds OS-level ACLs and biometric gating,
  and 1Password support stores an `op://` reference so the real value never
  rests in Decoyrail's state directory at all. References resolve once at
  `decoyrail run` startup (never on the request path), and a locked or
  missing backend fails closed with a clear audit event.
- **MCP-aware rules**: protocol-level policy over tool calls and tool results
  rather than byte matching.
- **Policy replay/eval**: `decoyrail policy test --replay audit.jsonl` scores a
  candidate policy against real recorded traffic before you roll it out.
- **Auto-drafted policies**: propose allow-rules from observed denials for an
  admin to approve.
- **Data guards at the request edge**: detection of structured sensitive
  data in outbound requests, before anything leaves the machine. Card
  numbers, bank identifiers, US SSNs, and API keys that were never vaulted,
  validated by checksums so test fixtures don't trip it, with well-known
  test values allowlisted. Policy decides per detector and destination:
  block, redact, or escalate, and a hit overrides an allow. Blocked requests
  return a machine-readable error, so coding agents fix the prompt and retry
  on their own. Matched values are never logged, only fingerprints. Honest
  scope: structured identifiers only; names, addresses, and free-text health
  data wait for the local judge model. Further out, the interesting upgrade:
  deterministic pseudonymization, where the model works on a format-correct
  fake and the real value never crosses the wire, built on the same swap
  machinery as decoys.
- **Maintained policy packs.** Free starter templates stay in the repo; paid
  packs are the maintenance: per-agent defaults kept current as vendors add
  endpoints, compliance packs (policy plus SIEM dashboards plus evidence
  mapping for SOC 2 / ISO 27001), detector packs for the data guards above
  (per-country identifiers), and response-side detector packs (PII,
  source-code signatures). Packs ship through the same signed-bundle channel
  as org policy, and the console's replay shows what a pack would have
  allowed or denied against your recorded traffic before rollout.
- **Canary decoys.** Opt-in provisioning of a decoy as a canarytoken
  (Thinkst's service or a self-hosted instance), so a stolen decoy raises an
  alert when used anywhere on the internet, months later, from anyone's
  machine, whether or not it ever crossed the proxy. Decoyrail itself never calls a canary
  service at runtime: provisioning happens at `vault add` time and alerts
  flow from the canary service straight to the admin.

## Further out

Directions we're committed to exploring, not yet promises: machine-wide
traffic capture that doesn't depend on env vars, with per-process
attribution; MDM and SSO fleet deployment; a fleet console for teams that
don't run a SIEM; routing traffic onto the model contracts you already pay
for; growing the data guards into a full detector line; agents beyond the
developer Mac, starting with CI runners and Linux; and first-party hosted
canary alerting, which waits until the project has earned the trust that any
hosted component demands.
