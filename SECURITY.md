# Security policy

## Supported versions

Only the current minor version receives security fixes. Older versions are
best-effort.

## Threat model

`netscan-core` is a **client-side network scanner**. It:

- Opens outbound TCP connections to user-supplied targets.
- Sends UDP magic packets (WoL) to user-supplied MAC addresses.
- Never listens on any port.
- Never reads or writes files outside those a user explicitly points it at.
- Never touches raw sockets — no privileged access needed.

The main threats we care about:

- **Scan-of-scan** — someone feeding a compromised target list to trigger
  unexpected outbound traffic. Mitigation: targets are parsed strictly through
  `cidr-utils`, never shell-interpolated.
- **Panic on hostile input** — malformed MAC / IP / port strings. Mitigation:
  every parser returns `Result`; unwrap/expect are only used on invariants
  proven by the surrounding code (e.g. `SocketAddr::new` after successful
  parse).
- **Denial-of-service via memory exhaustion** — huge target sets multiplied
  by port lists. Mitigation: the caller must materialize the target set;
  concurrency is bounded by a semaphore so pending futures stay small.

## Reporting a vulnerability

Please email **yabowarcher8590@gmail.com** with a subject prefix of
`[netscan-core security]`. Public issue trackers are for feature requests
and non-security bugs.

We aim for a first reply within 5 business days and a patched release within
30 days for anything with a reproducible impact.
