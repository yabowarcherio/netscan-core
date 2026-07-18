# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

Initial release. The scanner works end-to-end.

### Added

- `Scanner` struct with target set, port spec, timeout, and concurrency, plus
  a probe iterator and a total-probe counter.
- `Scanner::run()` — bounded-concurrency scan that returns results grouped
  by host with dead hosts preserved.
- `Scanner::stream()` — low-latency variant emitting each probe result over
  a `tokio::sync::mpsc::UnboundedReceiver` as it lands.
- `probe(sock, deadline)` async TCP-connect probe with `ProbeStatus`
  (`Open` / `Closed` / `Filtered`).
- `HostResult::is_alive()` and `HostResult::enrich(mac)` producing an
  `EnrichedHost` with the resolved OUI vendor.
- `wake(mac)` async Wake-on-LAN helper delegating to `wol-rs`.
- `netscan` CLI: positional targets, `--ports` (accepting service names),
  `--timeout-ms`, `--concurrency`, `--json`, `--dry-run`, `--wake MAC...`.
- Git-tag deps on the sibling stepping-stone crates (`cidr-utils@v0.3.0`,
  `portspec@v0.3.0`, `oui-lookup@v0.8.0`, `wol-rs@v0.2.0`).
- CI (Linux/macOS/Windows), CONTRIBUTING, SECURITY, dual MIT/Apache-2.0.

[Unreleased]: https://github.com/yabowarcherio/netscan-core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yabowarcherio/netscan-core/releases/tag/v0.1.0
