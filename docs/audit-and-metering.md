# Audit log & spend metering

Every decision Decoyrail makes (allow, deny, tripwire, response alert) is
appended to a tamper-evident audit log. Alongside it, a meter tracks
per-host traffic and enforces a monthly budget.

## The audit log

`~/.decoyrail/audit.jsonl`: one JSON event per line, append-only.

You rarely need to read the file raw. `decoyrail log` pretty-prints it, and
`decoyrail log -t` follows it live, like `tail -f`. Keeping that open in a
second terminal while an agent runs is the fastest way to see what it is
doing and why something was denied.

```json
{
  "seq": 42,
  "ts": "2026-07-05T17:03:11Z",
  "host": "api.anthropic.com",
  "path": "/v1/messages",
  "method": "POST",
  "action": "allow",
  "rule": "anthropic",
  "escalated": false,
  "swaps": ["anthropic@header:authorization"],
  "tripwires": [],
  "status": 200,
  "note": "",
  "pid": 812,
  "prev_hash": "9f2c…",
  "hash": "a41b…"
}
```

| Field | Meaning |
|---|---|
| `action` | `allow`, `deny`, `alert` (real secret echoed in a response, or a config hot-reload failure), `session` (a `decoyrail run` or `proxy` launch, labeled in `note`), `usage` (deferred token counts for a streamed response), `cache` (a prompt-cache marker injected, Pro), or `keepalive` (a proxy-initiated cache pre-warm, Pro) |
| `rule` | the policy rule that decided it (`default` when nothing matched) |
| `escalated` | the matching rule said `escalate` (resolved via fallback) |
| `swaps` | secrets substituted, as `name@location` |
| `tripwires` | decoys seen off-policy, as `name@location` (including `path`, `encoded:base64`, `body:raw`, `name@response`) |
| `status` | HTTP status returned to the agent (403 deny, 413 cap, upstream status on allow) |
| `note` | human-readable reason (`tripwire: …`, `budget exhausted`, …) |
| `pid` | process id of the decoyrail process that recorded the event (0 on events written before this field existed) |
| `sid` | session id of the recording process, stable where pids get reused; what `decoyrail stats --by session` groups on |
| `dur_ms` | request duration in milliseconds; on streamed responses it moves to the companion `usage` event so nothing is measured twice |
| `bytes_up`, `bytes_down` | request and response sizes as seen at the proxy (omitted when zero) |
| `usage` | structured token counts and cost for LLM requests: `{model, input, output, cache_read, cache_write, cost_usd}` |
| `req_seq` | on `usage` events: the `seq` of the allow event the counts belong to |

The analytics fields (`sid` through `req_seq`) exist so `decoyrail stats`
can aggregate the log without parsing prose; see [Analytics](stats.md). Like
the pid before them, they are part of the hashed payload: events written
before they existed verify through a fallback, and rewriting any of them on
a real event breaks the chain.

Several decoyrail processes can share one log. To follow a single session,
filter on its pid; `decoyrail run` prints it at launch:

```sh
decoyrail log --pid 812          # only that session's events
decoyrail log -t --pid 812       # follow it live
```

The pid filter applies before `-n`, so `--pid 812 -n 20` means "the last 20
events of session 812", not "session 812's share of the last 20 events".

The log is treated as required, not best-effort. If an append fails (disk
full, permissions, lock error), the error prints to stderr, and for an
allowed request the response is withheld with a `503 audit log unavailable;
failing closed` instead of being delivered. Traffic does not flow
unrecorded. (Denied requests are already blocked, so a failed deny-event
write costs visibility, not enforcement.)

## The hash chain

Each event's `hash` commits to the previous event's hash plus the event's
own canonical payload, so history can't be edited or thinned without
detection:

```mermaid
flowchart LR
    z["genesis<br/>prev = 000…0"] --> e0["event 0<br/>hash₀ = SHA-256(prev | payload₀)"]
    e0 --> e1["event 1<br/>hash₁ = SHA-256(hash₀ | payload₁)"]
    e1 --> e2["event 2<br/>hash₂ = SHA-256(hash₁ | payload₂)"]
    e2 -.latest seq + hash,<br/>written atomically.-> anchor[("audit.head<br/>(head anchor)")]
```

The payload is hashed as a canonical JSON array (not delimiter-joined
strings), so no crafted field value can shift field boundaries and make two
different events hash identically. The pid is part of the hashed payload;
events written before the field existed still verify through a legacy
fallback, and rewriting a real event's pid breaks the chain.

### What `decoyrail log --verify` catches

```mermaid
flowchart TD
    v["decoyrail log --verify"] --> walk["re-derive every hash<br/>from the genesis"]
    walk --> broken{chain intact?}
    broken -->|no| bad1["❌ edit or mid-file deletion<br/>reported with the breaking seq"]
    broken -->|yes| head{"last event ==<br/>head anchor?"}
    head -->|"log missing but anchor exists"| bad2["❌ log deleted"]
    head -->|"last seq behind anchor"| bad3["❌ tail truncated"]
    head -->|match| ok["✓ N events verified"]
```

- **Edits and mid-file deletions** break a hash link.
- **Tail truncation** leaves a perfectly valid prefix, which is why the
  chain alone isn't enough. The head anchor (`audit.head`, updated
  atomically on every append) records the last sealed `seq` and `hash`; a
  log that verifies but stops short of the anchor was truncated, and a
  missing log with a surviving anchor was deleted.

**Known limit:** an attacker with write access to `~/.decoyrail` can rewrite
the log and the anchor consistently. The anchor defeats naive truncation,
not a full local compromise. Hardware-backed or off-box head storage is on
the [roadmap](../ROADMAP.md), and shipping events to a central log system in
near-real time (which enterprises already do for other logs) bounds the
rewrite window to seconds. See the [threat model](threat-model.md).

### Concurrent writers

Multiple Decoyrail processes (a `decoyrail proxy` plus one or more
`decoyrail run` sessions) can share one log. Appends take an exclusive OS
file lock and re-derive `seq`/`prev_hash` from the tail if another process
wrote in between; without this, each process would chain from stale state
and fork the chain, tripping a false tamper alarm.

## Spend metering & budget

For LLM provider hosts (`api.anthropic.com` and `api.openai.com` out of the
box), metering is exact: the proxy reads the token counts the provider
itself reports in each response (the `usage` fields, including prompt-cache
reads and writes) and prices them per model. Streaming responses are scanned
incrementally as the bytes pass through, so the SSE passthrough stays
untouched. Everything the proxy can't parse falls back to a coarse byte
estimate (about 4 bytes per token at a blended per-provider rate; non-LLM
egress is metered but costed at zero), and `decoyrail status` labels which
number is which.

Billing mode matters for real cost, so Decoyrail tracks it: a request
authenticated the way flat-rate plans authenticate (for Anthropic, an OAuth
`Authorization: Bearer` with no `x-api-key`, which is what Claude Code sends
when signed into a Claude plan) is tagged `[subscription]` and counted at
zero marginal cost. Its tokens still show in `status`, in full; they just
don't burn the budget, because a flat plan adds no per-request bill. That
isn't the same as free: plan allowances are finite, heavy sessions hit plan
limits, and usage beyond the plan bills at API rates. An API-equivalent
reference cost for subscription traffic is on the [roadmap](../ROADMAP.md),
so you'll be able to see what your plan absorbed and how close you are to
outgrowing it.

```sh
decoyrail status        # tokens + $ per model for LLM hosts, MB for the rest
decoyrail budget 50     # monthly cap in USD; 0 = unlimited
```

## The prompt-cache report

Provider prompt caches cut repeated-context cost by up to 90%, and agent
traffic breaks them constantly, usually by accident: a timestamp in the
system prompt, a tool list that changes order, a request landing just past
the cache TTL. `decoyrail cache` explains what the cache did for you and
what keeps breaking it:

- hit rate per model, and the dollars cache reads saved against full-price
  input (for subscription traffic: the API-equivalent value, which is plan
  headroom),
- whether requests carry cache markers at all,
- prefix stability between consecutive requests: preserved, new
  conversation, diverged, or landed past the 5-minute TTL,
- for the last divergence, the exact byte offset and the section it fell in
  (`system`, `tools[2]`, `messages[7]`), which is usually enough to name
  the timestamp or id that keeps invalidating everything after it.

Token counts come from the same provider-reported usage the meter records.
The request-side diagnosis is observe-only: requests leave byte-identical
whether it runs or not, and its state file (`cache.json`) holds counters,
offsets, and section labels, never prompt content. Diagnosis is free for
everyone.

## Cache repair and active management (Pro)

Diagnosis names the waste; the Pro tier fixes it. All three behaviors are
off by default and switch on in the policy's `[cache]` table (hot-reloaded,
like the rest of the policy); none touches what the model reads, and every
mutation and proxy-initiated request is audited.

- **`repair`**: when a prefix demonstrably repeats (seen at least twice, at
  or above the model's cacheable minimum) but the client sends no cache
  markers, Decoyrail splices an ephemeral `cache_control` marker onto the
  last cacheable block. The edit is byte-surgical on the original request, so
  the text the model reads is untouched; the marker is metadata the model
  never sees. Observed inter-request gaps tune the marker to a 5-minute or
  1-hour TTL. A repaired response carries an `x-decoyrail-cache` header and
  the injection lands in the audit log (`action: cache`). `decoyrail cache`
  reports how many requests were repairable and how many were repaired.
- **`keep_alive`**: during idle (a long local build, say), a warm cache
  lapses and the next request re-pays the full cache write. With keep-alive
  on, the proxy replays a minimal, zero-output version of the last request to
  refresh the cache before it expires. Pre-warms are capped per prefix per
  session, metered as proxy-initiated spend, and audited (`action:
  keepalive`).
- **`serialize_fanout`**: when parallel subagents fire the same prefix at
  once, each one pays for its own cache write. Serialization lets the first
  write the cache and holds the rest until its response starts, so they read
  the warm cache instead, one write and N-1 reads. A per-request timeout keeps
  a stalled leader from wedging its siblings.

These are Pro features: without a license, or with the knobs left off, the
proxy runs the free, observe-only doctor and forwards every request
byte-identical.

Per-model rates ship built in. `~/.decoyrail/pricing.json` (hot-reloaded)
overrides or extends them, maps extra hosts to a provider protocol (an
internal gateway, say), and can force a billing mode per host:

```json
{
  "hosts":   {"llm.corp.internal": "openai"},
  "billing": {"api.anthropic.com": "subscription"},
  "models":  {"claude-sonnet-5": {"input": 3.0, "output": 15.0,
              "cache_read": 0.3, "cache_write": 3.75}}
}
```

How it behaves:

- **Kill switch:** once the month's spend (metered plus estimated) reaches
  the budget, every request is denied (`budget exhausted` in the audit log)
  until the month rolls over or the budget is raised. The check runs before
  forwarding. Subscription traffic never trips it.
- **Streams are metered too:** for SSE and oversized responses, the upload
  is recorded at forward time and the download size is folded in as the
  stream drains, including when the agent disconnects mid-stream. Token
  usage is scanned out of the SSE events on the fly, one line buffer deep,
  never delaying the stream. Some subscription backends stream SSE without
  the `text/event-stream` content type (ChatGPT's Codex endpoint,
  `chatgpt.com/backend-api/codex/responses`, is one); their usage is still
  recovered by scanning the buffered body as SSE when a whole-body JSON
  parse finds none.
- **Token counts land in the audit log:** an allowed LLM request's event
  carries a `usage: <model> in=… out=…` note when the response was buffered;
  streamed responses append a companion `usage` event once the stream ends
  and the counts are known. Neither adds latency: the buffered counts were
  already parsed for metering, and the companion event is written after the
  last byte has been delivered.
- **Global across sessions:** each session accrues a local delta and merges
  it into `meter.json` under a file lock, then folds other sessions' flushed
  usage back in. Two concurrent `decoyrail run`s add up instead of
  overwriting each other, so the budget is enforced machine-wide, not
  per-session.
- **The budget lives in its own file** (`budget.json`), so the proxy's
  frequent usage writes can never clobber a budget you set while it was
  running. Both hot-reload into a running proxy.
