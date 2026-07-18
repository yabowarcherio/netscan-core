# netscan-core

<!-- badges -->
[![crate](https://img.shields.io/crates/v/netscan-core.svg)](https://crates.io/crates/netscan-core)
[![docs](https://docs.rs/netscan-core/badge.svg)](https://docs.rs/netscan-core)

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

Working. `Scanner::run` does concurrent TCP connect scanning with a bounded
semaphore; `Scanner::stream` / `stream_bounded` give low-latency channels
for UIs that want to render results as they arrive. WoL is one call away
via `netscan_core::wake` (or `wake_repeat` for BIOSes that need multiple
packets).

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
netscan --wake AA:BB:CC:DD:EE:FF          # send a Wake-on-LAN packet, no scan
netscan --wake AA:BB:CC:DD:EE:FF --wake-repeat 3 --wake-interval-ms 200
netscan 10.0.0.0/24 --sort ports --limit 5     # top-5 hosts by open ports
netscan 10.0.0.0/24 --report all --quiet       # write only errors + tally
```

## Usage (library)

```rust,no_run
use netscan_core::{Scanner, cidr_utils::IpSet, portspec::PortSpec};

#[tokio::main]
async fn main() {
    let targets: Vec<IpSet> = vec!["192.168.1.0/24".parse().unwrap()];
    let ports: PortSpec = "ssh,http,https".parse().unwrap();
    let scanner = Scanner::new(targets, ports);
    let results = scanner.run().await;
    for r in results.iter().filter(|r| r.is_alive()) {
        println!("{} -> {:?}", r.addr, r.open_ports);
    }
}
```

Preset port lists are exposed as `&'static [u16]` slices, plus a `PortPreset`
enum wired through the CLI as `--ports preset:NAME` (accepts
`quick`, `web`, `shell`, `db`/`database`, `mail`, `file`/`fileshare`):

```rust
use netscan_core::{PortPreset, ALL_PRESETS, QUICK_PORTS, preset, union_of_presets};
assert!(QUICK_PORTS.contains(&22));
assert_eq!(preset("web"), Some(PortPreset::Web));
for &p in ALL_PRESETS {
    println!("{p}: {} ports", p.len());
}
let all_ports = union_of_presets();
assert!(all_ports.len() >= QUICK_PORTS.len());
```

Or stream results as they come in:

```rust,no_run
use netscan_core::{Scanner, cidr_utils::IpSet, portspec::PortSpec, ProbeStatus};

#[tokio::main]
async fn main() {
    let s = Scanner::new(vec!["192.168.1.0/24".parse().unwrap()], "22".parse().unwrap());
    let mut rx = s.stream();
    while let Some((sock, status)) = rx.recv().await {
        if status == ProbeStatus::Open {
            println!("{sock} open");
        }
    }
}
```

## Batch helpers

The library ships a small kit of batch-analysis helpers on top of
`Vec<HostResult>`:

- `alive_hosts` / `dead_hosts` / `alive_dead_split`
- `alive_count` / `dead_count` / `count_known` (via oui-lookup)
- `distinct_open_ports` / `total_open_port_hits`
- `most_common_open_port` / `top_open_ports` / `histogram_by_port_count`
- `filter_by_addr` / `split_by_family` / `top_host`

## Why another scanner?

nmap wins on depth of service/OS fingerprinting — don't try to out-nmap nmap.
Where NetScan aims to be better:

- **Cross-platform** (Angry / Advanced IP Scanner are Windows-only).
- **Truly free + OSS + zero telemetry.**
- Fast async scanning, single static binary, no .NET/Java runtime.
- The Windows-shop conveniences (SMB shares, WoL, RDP/SSH launch) built in.
- Streaming output for TUIs and desktop UIs.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT).

## Related crates

- [oui-lookup](https://github.com/yabowarcherio/oui-lookup) — offline MAC → vendor
- [cidr-utils](https://github.com/yabowarcherio/cidr-utils) — CIDR / range / set math
- [portspec](https://github.com/yabowarcherio/portspec) — port-list parser
- [wol-rs](https://github.com/yabowarcherio/wol-rs) — Wake-on-LAN magic packets
