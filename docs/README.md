# Decoyrail documentation

Decoyrail runs AI coding agents behind a local TLS-intercepting proxy. The
agent holds decoy credentials, the proxy swaps in real secrets only for
approved destinations, and a decoy seen anywhere else is treated as an
exfiltration attempt: blocked and recorded.

| Doc | Read it when you want to |
|---|---|
| [Getting started](getting-started.md) | install Decoyrail and protect your first agent |
| [How it works](how-it-works.md) | follow the architecture and request path |
| [Policy reference](policy.md) | write egress and secret-release rules |
| [Vault & secret release](vault-and-bindings.md) | manage secrets, decoys, and release destinations |
| [Sensitive-data filtering](dlp.md) | block, mask, or warn on structured sensitive data |
| [Audit & metering](audit-and-metering.md) | inspect events, verify logs, and control spend |
| [Analytics](stats.md) | query spend, usage, and security events |
| [Licensing](license.md) | install a license and understand tiers, expiry, and grace |
| [Threat model](threat-model.md) | understand Decoyrail's guarantees and limits |

What's coming next is in the [roadmap](../ROADMAP.md).
