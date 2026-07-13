# Vault, decoys, and secret release

The vault holds your real secrets encrypted at rest and pairs each with a
deterministic decoy. Where a real secret may travel is not stored here: the
[policy](policy.md) decides that, through each rule's `allow_secrets`.

```sh
decoyrail vault add --name anthropic --env ANTHROPIC_API_KEY --location bearer
decoyrail vault ls            # human view (real value redacted)
decoyrail vault ls --json     # machine view (real value omitted entirely)
decoyrail vault rm anthropic
```

## How a secret is stored

```mermaid
flowchart LR
    real["real secret<br/>(prompted hidden / stdin)"] --> enc["ChaCha20-Poly1305<br/>key: ~/.decoyrail/vault.key (0600)"]
    enc --> file[("vault.json")]
    real --> h["SHA-256(name + real)"]
    h --> decoy["deterministic decoy<br/>format-correct fake"]
    decoy --> env["injected into the agent env<br/>by `decoyrail run`"]
```

- **Encryption at rest:** the vault file is ChaCha20-Poly1305 encrypted. By
  default the key lives beside it (`vault.key`, `0600`); on macOS you can
  move it into the login keychain instead (next section). Moving the whole
  directory out of the agent user's reach is a roadmap item; see the
  [threat model](threat-model.md) for what this does and doesn't protect
  today.
- **Zeroization:** decrypted vault plaintext and key material are wiped
  after use.

## Where the key lives: file or keychain

`vault.key` on disk is the default backend everywhere. It is simple and
right for development, but any process running as your user can read it. On
macOS you can move the key into the login keychain instead:

```sh
decoyrail key status                  # active backend, item presence, bound home
decoyrail key migrate --to keychain   # move the key in (removes vault.key)
decoyrail key migrate --to file       # move it back out
```

The keychain backend buys you two things:

- **No silent reads.** The keychain item is readable without a prompt only
  by the Decoyrail binary that created it. Any other process asking for it,
  `security find-generic-password -w` included, triggers the macOS consent
  prompt or is denied. An unexpected prompt naming
  `dev.decoyrail.vault-key` is therefore itself a tripwire: something on
  your machine wants your vault key.
- **Home binding.** The item is bound to the canonicalized path of the
  default home (`~/.decoyrail`), and Decoyrail consults the keychain only
  when running against that home. This closes the rented-deputy trick,
  where an attacker who can't read the key copies your encrypted vault
  next to a hostile policy and runs `DECOYRAIL_HOME=/tmp/evil decoyrail
  run` so a fresh Decoyrail does the decrypting for them. A non-default
  home never touches the keychain, so the hostile copy never decrypts:
  reaching the real key means running the real home, and the real home
  enforces the real policy.

There is no config flag for any of this. The backend is chosen by
presence: if a keychain item bound to the default home exists it is used,
otherwise the file is. A flag in a same-user-writable file would just be
one more thing an attacker could flip.

Migration is safe to interrupt (the key is verified in its new location
before the old copy is destroyed) and reversible at any time with the
opposite `migrate`. If a keychain read is ever denied or fails, Decoyrail
aborts rather than inventing a fresh key; a fresh key would present as an
inexplicably empty vault and mask the failure.

Development builds are unsigned, so the keychain identifies the binary
itself and prompts again after every rebuild. Use the file backend in
development and the keychain with an installed release. Any non-default
`DECOYRAIL_HOME`, including tests and throwaway runs, always uses a file key
inside that directory.

## Decoys: deterministic, format-correct honeytokens

The decoy is derived from a hash of the entry name and the real value, so
re-adding the same secret always reproduces the same decoy; tripwire matches
and audit history stay stable across vault edits. Decoys mimic the real
secret's format so SDKs and validators accept them:

| Real secret looks like | Decoy generated |
|---|---|
| `sk-ant-…` (Anthropic) | `sk-ant-api03-` + 93 chars |
| `sk-…` (OpenAI) | `sk-proj-` + 48 chars |
| `github_pat_…` | `github_pat_` + 70 chars |
| `ghp_…` | `ghp_` + 36 chars |
| `AKIA…` (AWS access key) | `AKIA` + 16 uppercase chars |
| `xoxb-…` (Slack) | `xoxb-` + 48 chars |
| connection string (`scheme://user:pass@host`) | `postgres://decoy:…@db.invalid:5432/app` |
| anything else | opaque token, same length class (16-64 chars) |

A decoy is not valid anywhere. Its only function is that Decoyrail
recognizes it.

Recognized formats also give the entry a **provider label** (`anthropic`,
`openai`, `github`, `gitlab`, `slack`, `npm`). A policy rule can release a
secret by that label (`allow_secrets = ["provider:github"]`) instead of by
name; the shipped default policy does exactly that, so provider keys work
with zero configuration.

## The session vault: automatic decoys for `decoyrail run`

Vault entries are the secrets you added explicitly. On top of them,
`decoyrail run` builds a session vault each time it starts: env vars with
credential-shaped names or known key formats are replaced with decoys in
the child's environment.

Session secrets run through the same swap/tripwire pipeline as vault
entries, but live only in memory and only for that run. Recognized provider
keys carry their provider label, and the default policy's provider rules
release those labels, so they keep working. Everything else is
tripwire-only: usable nowhere, and any attempt to send it is blocked and
recorded.

To make an auto-decoyed credential usable, release it in the policy by its
session name, which is `env:` plus the variable: a rule with
`allow_secrets = ["env:AWS_SECRET_ACCESS_KEY"]` releases that one at the
hosts the rule matches. Add it to the vault instead if you want an entry
that outlives the session. To exempt it from decoying entirely, use
`--pass-env VAR` (or `--pass-all-env` to disable the scanning). Details and caveats:
[getting started](getting-started.md#3-automatic-decoying-env-vars),
[threat model](threat-model.md#automatic-decoying-is-best-effort-coverage).

## Release: the one road a real secret may travel

The policy rule that wins a request decides whether the real secret rides
it. `decoyrail vault add --allow-host HOST` appends the releasing rule for
you:

```sh
decoyrail vault add --name acme --env ACME_API_KEY \
  --allow-host api.acme.com --location header:x-api-key
```

which adds to `policy.toml`:

```toml
[[rule]]
name = "acme"
hosts = ["api.acme.com"]
action = "allow"
allow_secrets = ["acme"]
```

Narrower release (a path prefix, specific methods) is a policy edit away;
everything in the [policy reference](policy.md) applies, including
first-match ordering. Without a releasing rule the secret is tripwire-only,
and `vault ls` says so.

## Location: where in the request the secret rides

The one release axis that stays on the vault entry is the location, because
it is a property of the credential, not of the destination:

| `--location` | Swaps when the decoy is found in | Typical use |
|---|---|---|
| `bearer` | the `Authorization` header | Anthropic, OpenAI, most APIs |
| `header:<name>` | that named header | vendor APIs with custom headers |
| `body` | the request body (UTF-8) | form posts, webhook payloads |
| `any` (default) | headers and body | when unsure |

The location is enforced, not advisory: a decoy found at a releasing rule
but in the wrong location (say, the location is `bearer` and the decoy
appears in a custom header) is treated as a tripwire, not swapped. The URL
is never a swappable location: a decoy in the path or query string always
tripwires.

## Entering the secret safely

`decoyrail vault add` accepts the value three ways, safest first:

```sh
decoyrail vault add --name gh --allow-host api.github.com --location bearer
# → prompted, hidden: never in shell history or `ps`

op read "op://vault/github/token" | decoyrail vault add … --secret -
# → piped via stdin

decoyrail vault add … --secret ghp_xxx
# → inline: works, but visible in history and `ps` (decoyrail warns)
```

## What the swap engine does with all this

Per request, per secret: if the decoy (or an encoded form of it) appears
anywhere in the request, Decoyrail either swaps it (winning rule releases
the secret, TLS transport, correct location) or fires a tripwire (anything
else, with one exception: a secret listed on a deny or escalate rule blocks
quietly, since the agent's own credential riding a blocked request is
expected). The complete decision tree, including the encoded-decoy, URL,
and plaintext-HTTP rules, is diagrammed in
[how-it-works](how-it-works.md#swap-vs-tripwire-the-decision-per-secret).

Reachability and release live in one file and one evaluation: the rule that
lets a request through is the rule that says which credentials it may
carry. There is no separate binding to keep in sync.
