# netscan-core

[![CI](https://github.com/yabowarcherio/netscan-core/actions/workflows/ci.yml/badge.svg)](https://github.com/yabowarcherio/netscan-core/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Async TCP connect-scanner in safe Rust. The engine behind **NetScan** — an
IP scanner aimed at surpassing every free (and most paid) alternatives.

`netscan-core` composes the four stepping-stone crates:

- [`cidr-utils`](https://github.com/yabowarcherio/cidr-utils) — target parsing (CIDR / range / bare address)
- [`portspec`](https://github.com/yabowarcherio/portspec) — port-list parsing with named services
- [`oui-lookup`](https://github.com/yabowarcherio/oui-lookup) — MAC → vendor enrichment
- [`wol-rs`](https://github.com/yabowarcherio/wol-rs) — Wake-on-LAN magic packets

into a single async engine plus a small CLI. Front-ends (Tauri desktop, TUI,
custom CLI) sit on top of the engine.

## Status

**Very early.** The `Scanner` type is settled, `--dry-run` prints the plan,
but live TCP connect probing lands in a later commit. Track the CHANGELOG.

## Install

### CLI

```sh
cargo install netscan-core     # installs the `netscan` binary
```

### Library

```toml
[dependencies]
netscan-core = { version = "0.1", default-features = false }   # library-only
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Usage (CLI)

```sh
netscan 192.168.1.0/24 --ports ssh,http,https,8000-8100
netscan 10.0.0.1-10.0.0.50 --ports 22,80 --json
netscan 192.168.1.0/24 --dry-run          # print the plan without scanning
```

## Usage (library)

```rust
use netscan_core::Scanner;
use cidr_utils::IpSet;
use portspec::PortSpec;

let targets: Vec<IpSet> = vec!["192.168.1.0/24".parse().unwrap()];
let ports: PortSpec = "ssh,http,https".parse().unwrap();
let scanner = Scanner::new(targets, ports);
println!("planned probes: {}", scanner.total_probes());
```

## Why another scanner?

nmap wins on depth of service/OS fingerprinting — don't try to out-nmap nmap.
Where NetScan aims to be better:

- **Cross-platform** (Angry / Advanced IP Scanner are Windows-only).
- **Truly free + OSS + zero telemetry.**
- Fast async scanning, single static binary, no .NET/Java runtime.
- The Windows-shop conveniences (SMB shares, WoL, RDP/SSH launch) built in.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT).
