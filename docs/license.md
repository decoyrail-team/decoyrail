# Licensing and tiers

Every security feature in Decoyrail is free, forever: decoys and the real-secret swap, tripwires, the egress policy, the sensitive-data detectors, the audit log, and exact spend metering. A license unlocks the paid conveniences on top, starting with the Pro cost pack ([cache repair and active management](audit-and-metering.md#cache-repair-and-active-management-pro)). Tiers and prices are on the [pricing page](https://decoyrail.com/pricing).

## How a license works

A license is a small signed file we email you. Verification is offline, against keys built into the binary: there is no license server, no activation step, no account, and no phone-home. This is why Decoyrail works the same on an air-gapped machine.

```sh
decoyrail license install decoyrail-license.txt
# License installed.
# Licensee: Ada Lovelace
# Tier:     pro (1 seat(s))
# Term:     2026-07-18 to 2027-07-18 (then 14 grace day(s))
# Status:   valid
```

A running proxy picks the license up on its own; there is nothing to restart. The install is recorded in the audit log like any other state change.

## Checking what you have

```sh
decoyrail license status
# Licensee: Ada Lovelace
# Tier:     pro (1 seat(s))
# Term:     2026-07-18 to 2027-07-18 (then 14 grace day(s))
# Status:   valid
```

With no license installed, `status` says so and confirms you are on the free tier. `decoyrail status` also carries a one-line tier summary.

## Expiry, grace, and the safe direction

When a license expires you get a grace window (14 days by default, stated in the license itself) where everything keeps working and `decoyrail license status` warns. After the grace window the effective tier drops to Free: paid conveniences switch off in their safe direction, and every security feature keeps running exactly as before.

The invariant behind this: license state can never block traffic, release a secret, or weaken enforcement. A missing, expired, or corrupt license file means the free tier, never an error in the request path. If the installed file is unreadable or fails verification, `status` tells you why and a reinstall fixes it.

## One seat, your machines

A seat is a human. One person's seat covers all of that person's machines; each machine installs its own copy of the license file. Seat counts are license terms, not endpoint enforcement: nothing bricks itself over a count.
