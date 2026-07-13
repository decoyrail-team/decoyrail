# Security policy

Decoyrail is a security product: it installs a local trust root, intercepts
TLS, and holds real credentials. We treat every report about that surface
seriously and we want to hear from you.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
[Report a vulnerability](https://github.com/decoyrail-team/decoyrail/security/advisories/new).

Do not open a public issue for anything you believe is exploitable.

What helps us most: the version you tested (`decoyrail --version`), your
policy file if it matters to the finding, and steps to reproduce. A proof of
concept is welcome but not required.

## What counts

Anything that breaks the invariants the product promises. In particular:

- A real secret leaving the machine to a destination the policy did not
  release it to, or over plaintext.
- A way to read the vault, the vault key, or a real secret without the
  protections the docs claim (see [docs/threat-model.md](docs/threat-model.md)).
- Bypassing the tripwire, DLP blocks, or budget enforcement in a way the
  threat model says should hold.
- Tampering with the audit log without detection.
- Abuse of the minted CA or per-host leaf certificates.

The threat model also documents what Decoyrail deliberately does not defend
against. Reports inside those stated limits are still useful as docs feedback,
but are not treated as vulnerabilities.

## What to expect

We will acknowledge your report within 3 business days and keep you updated as
we investigate. We ask for a reasonable disclosure window to ship a fix;
we will credit you in the release notes unless you prefer otherwise.

## Scope

The latest release and the current `main` branch. License enforcement bypasses
are out of scope: licensing fails open by design and only gates paid
conveniences, never security features.
