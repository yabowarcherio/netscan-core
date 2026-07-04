//! Command-line front-end for `netscan-core`.
//!
//! ```text
//! netscan 192.168.1.0/24 --ports ssh,http,https,8000-8100
//! netscan 10.0.0.1-10.0.0.50 --ports 22,80 --json
//! ```

use std::process::ExitCode;

use clap::Parser;
use netscan_core::{Scanner, DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT};

use cidr_utils::IpSet;
use portspec::PortSpec;

/// Async TCP connect-scanner. Composes cidr-utils, portspec, oui-lookup, and
/// wol-rs into a single command.
#[derive(Parser, Debug)]
#[command(name = "netscan", version, about)]
struct Cli {
    /// One or more targets: CIDR block, address range, or bare address.
    #[arg(value_name = "TARGET", required_unless_present = "wake")]
    targets: Vec<String>,

    /// Ports to probe (any format PortSpec accepts, incl. service names).
    #[arg(long, short = 'p', default_value = "22,80,443,3389")]
    ports: String,

    /// Per-connection TCP-connect timeout, in milliseconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT.as_millis() as u64)]
    timeout_ms: u64,

    /// Maximum concurrent connection attempts.
    #[arg(long, short = 'c', default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Emit machine-readable JSON output instead of the default text.
    #[arg(long)]
    json: bool,

    /// Report only alive hosts (matches the default) or all hosts.
    #[arg(long, value_name = "MODE", default_value = "alive")]
    report: String,

    /// Only print the total number of probes and exit, without scanning.
    #[arg(long)]
    dry_run: bool,

    /// Suppress alive-hosts stdout (still emits errors to stderr).
    #[arg(long, conflicts_with = "json")]
    quiet: bool,

    /// Send a Wake-on-LAN magic packet to each MAC (repeatable), then exit.
    /// Scanning targets are ignored when --wake is set.
    #[arg(long, value_name = "MAC", num_args = 1..)]
    wake: Vec<String>,
}

fn parse_targets(raw: &[String]) -> Result<Vec<IpSet>, String> {
    raw.iter()
        .map(|s| s.parse::<IpSet>().map_err(|e| format!("{s:?}: {e}")))
        .collect()
}

fn run(cli: Cli) -> Result<(), String> {
    // --wake short-circuits: skip target/port validation entirely.
    if !cli.wake.is_empty() {
        let macs: Vec<[u8; 6]> = cli
            .wake
            .iter()
            .map(|s| wol_rs::parse_mac(s).map_err(|e| format!("{s:?}: {e}")))
            .collect::<Result<_, _>>()?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        rt.block_on(async {
            for mac in macs {
                netscan_core::wake(mac)
                    .await
                    .map_err(|e| format!("wake {}: {e}", wol_rs::format_mac(mac)))?;
            }
            Ok::<(), String>(())
        })?;
        return Ok(());
    }

    let targets = parse_targets(&cli.targets)?;
    let ports: PortSpec = cli.ports.parse().map_err(|e| format!("--ports: {e}"))?;

    let scanner = Scanner::new(targets, ports)
        .with_timeout(std::time::Duration::from_millis(cli.timeout_ms))
        .with_concurrency(cli.concurrency);

    if cli.dry_run {
        // Exposes the effective plan without touching the network — useful for
        // sanity-checking large scan sets before you run them for real.
        let total = scanner.total_probes();
        if cli.json {
            println!(
                "{{\"probes\":{total},\"timeout_ms\":{},\"concurrency\":{}}}",
                cli.timeout_ms, cli.concurrency
            );
        } else {
            println!("planned probes: {total}");
            println!("timeout: {} ms", cli.timeout_ms);
            println!("concurrency: {}", cli.concurrency);
        }
        return Ok(());
    }

    // Live scan.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    let results = rt.block_on(scanner.run());

    if cli.json {
        let records: Vec<_> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "addr": r.addr.to_string(),
                    "open_ports": r.open_ports,
                    "alive": r.is_alive(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&records).map_err(|e| format!("json: {e}"))?
        );
    } else if !cli.quiet {
        for r in &results {
            if r.is_alive() {
                let ports = r
                    .open_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!("{}\t{ports}", r.addr);
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("netscan: {e}");
            ExitCode::from(2)
        }
    }
}
