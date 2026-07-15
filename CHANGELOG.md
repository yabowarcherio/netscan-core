# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- Sections use `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`. -->


## [Unreleased]

### Added

- Port-preset slice constants: `QUICK_PORTS`, `WEB_PORTS`, `SHELL_PORTS`,
  `DB_PORTS`, plus `DEFAULT_STREAM_BUFFER`.
- Scanner extensions: `Scanner::empty`, `is_empty`, `with_targets`,
  `with_ports`, `push_target`, `clear_targets`, `target_count`,
  `total_addresses`, `total_ports`, `estimated_duration`.
- Streaming variants: `Scanner::stream_bounded`, `Scanner::stream_bounded_default`.
- Batch helpers: `alive_hosts`, `dead_hosts`, `alive_dead_split`, `alive_count`,
  `dead_count`, `distinct_open_ports`, `total_open_port_hits`,
  `most_common_open_port`, `top_open_ports`, `histogram_by_port_count`,
  `top_host`, `filter_by_addr`, `split_by_family`.
- Wake helpers: `wake_repeat`, `wake_many`, `wake_many_collect`,
  `wake_success_count`, `wake_failure_count`, `PROBE_MIN_TIMEOUT`,
  `PROBE_MAX_TIMEOUT`, `DEFAULT_WAKE_REPEATS`, `DEFAULT_WAKE_INTERVAL`.
- Enriched-host accessors: `EnrichedHost::is_alive`, `addr`, `open_ports`,
  `set_vendor`, `has_vendor`.
- ProbeStatus predicates: `is_open`, `is_closed`, `is_filtered`, `as_str`,
  `Display`.
- CLI: `--quiet`, `--report`, `--sort`, `--limit`, `--wake-repeat`,
  `--wake-interval-ms`, stderr alive/dead tally.
- Release workflow (per-target binaries on tag push), Dependabot for
  cargo + GitHub Actions, cargo-deny advisories job, CODEOWNERS, PR/issue
  templates.

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
