# Sensitive-data filtering (DLP)

The vault protects known secrets. DLP detectors catch structured sensitive
data that was never vaulted, such as a card number in a prompt or a bank
account in an uploaded log. They scan every outbound request. A blocking hit
overrides any policy allow, like a decoy tripwire.

Watch it work live with `decoyrail log -t` in a second terminal: blocks show
up as `[DENY]` events with `dlp:` notes, warnings as `[ALRT]`.

## The detectors

Each detector validates a checksum or strict structure. Well-known test
values from payment-provider documentation pass through to avoid blocking
test suites.

| Detector | Matches | Validation |
|---|---|---|
| `pan` | payment card numbers, plain or `4242 4242` / `4242-4242` styled | Luhn checksum plus a real issuer prefix (Visa, Mastercard, Amex, Discover, JCB, Diners) |
| `ssn` | US Social Security numbers in the dashed form `123-45-6789` | area/group/serial validity rules |
| `iban` | international bank account numbers, compact or print-spaced | ISO 13616 mod-97 check, known country lengths |
| `aba` | US bank routing numbers | ABA checksum plus valid Federal Reserve prefix |
| `email` | email addresses | structural |

Names, street addresses, and free-text health data are out of scope for
rules: that is judgment-call territory and waits for the local judge model.
No detector here supports a HIPAA claim.

Digit runs glued to identifiers stay quiet: UUIDs, timestamps, version
strings, and `order_4539...` style IDs don't fire, because a card number
inside a longer token is not a standalone card number.

## Modes

Each detector has one of four modes:

| Mode | What a hit does |
|---|---|
| `block` | the request is rejected with a 403 naming the detector and offset |
| `mask` | the value is replaced with `[decoyrail:masked:<detector>]` and the request goes through |
| `warn` | the request goes through untouched; an alert lands in the audit log |
| `off` | detector disabled |

Defaults: `pan`, `ssn`, `iban`, and `aba` warn; `email` is off, because
ordinary developer traffic (commits, package metadata) is full of email
addresses. Warn-first is deliberate: the detectors are new, so out of the
box a hit shows up in `decoyrail log -t` as an `[ALRT]` event but nothing
breaks. Run like that for a while; when the alerts you see are values you
genuinely don't want leaving the machine, upgrade those detectors to block:

```sh
decoyrail dlp show              # current modes
decoyrail dlp set pan block     # upgrade one; a running proxy picks it up
decoyrail dlp set ssn mask      # or replace values instead of rejecting
decoyrail dlp set aba off       # the local override when you need one
```

The settings live in the `[dlp]` section of `policy.toml`, next to the
egress rules, and hot-reload the same way. The shipped defaults:

```toml
[dlp]
pan = "warn"
ssn = "warn"
iban = "warn"
aba = "warn"
email = "off"
```

A tightened setup, with fixture values excused, looks like this:

```toml
[dlp]
pan = "block"    # reject requests carrying a real card number
ssn = "block"
iban = "mask"    # replace with [decoyrail:masked:iban] and forward
aba = "warn"     # keep watching before deciding
email = "off"
# Org-specific fixture values, compared ignoring case and separators:
allow = ["4111 1111 1111 1111", "GB82 WEST 1234 5698 7654 32"]
```

## What a block looks like

The error body is machine-readable so a coding agent can fix its own request
and retry:

```json
{
  "decoyrail": true,
  "blocked": true,
  "reason": "dlp",
  "detectors": [{"detector": "pan", "location": "body", "offset": 17}],
  "message": "decoyrail blocked this request: sensitive data detected. ..."
}
```

The audit event records the detector, the location, and a salted fingerprint
of the value. The value itself is never written anywhere. The fingerprint
salt is local to the machine (`~/.decoyrail/dlp.salt`), so you can tell "the
same card number tried to leave three times" from your own log, but a log
consumer can't reverse or cross-reference it.

## Debug mode: seeing what actually matched

Fingerprints tell you the same value fired repeatedly, but not what it was.
When a block surprises you and you suspect a false positive, turn on debug
mode:

```sh
decoyrail dlp set debug on      # or debug = true under [dlp] in policy.toml
```

While it is on, every request that carries a DLP hit is written in full to a
file under `~/.decoyrail/dlp-debug/`, one file per request, readable by your
user only. The file starts with a header naming each hit and showing the
matched value in its surrounding text, with the match marked:

```
# decoyrail dlp debug dump  2026-07-09T14:21:19.064Z
# POST api.anthropic.com/api/event_logging/v2/batch
# hits:
#   block aba@body:base64 off=306874 fp=6d313032fc2e9609
#     ..."routing_number": ">>>061000052<<<", "account": ...
```

For hits inside base64, hex, or percent encoded blobs, the snippet comes from
the decoded text, so you see what the detector saw. The rest of the file is
the request headers and body exactly as they would have left the machine,
with one exception: any real secret the vault swapped in is scrubbed back to
a named placeholder before the file is written. The audit log gains only a
`payload=<file>` pointer in the event note, so `decoyrail log -t` tells you
where to look; the log itself never holds the value, debug mode or not.

Once you know what fired, either add the value to `allow` (fixtures and
test data), change the detector's mode, or take the block as the save it was.
Then turn debug off and delete the dumps; they exist to answer a question,
not to accumulate:

```sh
decoyrail dlp set debug off
rm -r ~/.decoyrail/dlp-debug
```

## Scope and bounds

- Detectors scan the URL, header values, and UTF-8 request bodies, after
  decoy swapping (so a decoy that happens to look numeric can't trip them).
- Base64, hex, and percent-encoded values are caught one decode level deep,
  within a bounded decode budget per request. Hitting the bound is stated in
  the audit event. Compression, encryption, or double encoding evades the
  scan; like the tripwire's encoded-form scan, this is detection in depth.
- `mask` rewrites plain request bodies only. A mask-mode hit in a URL, a
  header, or inside an encoded blob fails closed and blocks instead, since
  rewriting those safely can't be guaranteed.
- Non-UTF-8 (binary) bodies are not text-scanned.
- Responses are not scanned by these detectors (the existing echoed-secret
  scan still runs); response-side packs come later.
