# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial `Scanner` struct: target set, port spec, timeout, concurrency,
  probe iterator, total-probe count.
- `HostResult` type with `is_alive()` predicate.
- `netscan` CLI with `--ports`, `--timeout-ms`, `--concurrency`, `--json`,
  and `--dry-run`. Live scanning not yet wired.
- Path deps on the sibling stepping-stone crates (`cidr-utils`, `portspec`,
  `oui-lookup`, `wol-rs`).
