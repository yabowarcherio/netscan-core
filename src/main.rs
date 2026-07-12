//! Command-line front-end for `netscan-core`.
//!
//! ```text
//! netscan 192.168.1.0/24 --ports ssh,http,https,8000-8100
//! netscan 10.0.0.1-10.0.0.50 --ports 22,80 --json
//! netscan --wake AA:BB:CC:DD:EE:FF --wake-repeat 3 --wake-interval-ms 200
//! ```

use std::process::ExitCode;

use clap::Parser;
use netscan_core::{alive_count, Scanner, DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT};

use cidr_utils::IpSet;
use portspec::PortSpec;

/// Async TCP connect-scanner. Composes cidr-utils, portspec, oui-lookup, and
/// wol-rs into a single command.
#[derive(Parser, Debug)]
#[command(
    name = "netscan",
    version,
    about,
    long_about = "TCP connect scanner. Targets and --ports accept everything the sibling crates parse (CIDR, ranges, bare IPs; port numbers, ranges, and service names)."
)]
struct Cli {
    /// One or more targets: CIDR block, address range, or bare address.
    #[arg(value_name = "TARGET", required_unless_present = "wake")]
    targets: Vec<String>,

    /// Ports to probe (any format PortSpec accepts, incl. service names).
    #[arg(long, short = 'p', default_value = "22,80,443,3389")]
    ports: String,

    /// Per-connection TCP-connect timeout, in milliseconds.
    ///
    /// Values above PROBE_MAX_TIMEOUT (120 seconds) are silently clamped
    /// by the underlying library.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT.as_millis() as u64)]
    timeout_ms: u64,

    /// Maximum concurrent connection attempts.
    #[arg(long, short = 'c', default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Emit machine-readable JSON output instead of the default text.
    #[arg(long)]
    json: bool,

    /// Report only alive hosts (matches the default) or all hosts.
    ///
    /// Accepts `alive` (skip dead hosts) or `all` (include every scanned
    /// address even if no port responded).
    #[arg(long, value_name = "MODE", default_value = "alive")]
    report: String,

    /// Sort output by address (default) or by number of open ports desc.
    ///
    /// Accepts `addr` (lexicographic address order) or `ports`
    /// (descending count of open ports, ties broken by address).
    #[arg(long, value_name = "KEY", default_value = "addr")]
    sort: String,

    /// Cap the number of output rows to N (0 = unlimited).
    ///
    /// Applied after `--sort`; useful together with `--sort ports` for
    /// "give me the top-N hosts by open ports".
    #[arg(long, value_name = "N", default_value_t = 0)]
    limit: usize,

    /// Only print the total number of probes and exit, without scanning.
    #[arg(long)]
    dry_run: bool,

    /// Suppress alive-hosts stdout. Errors still go to stderr, as does the
    /// `# alive: N / M` tally.
    #[arg(long, conflicts_with = "json")]
    quiet: bool,

    /// Send a Wake-on-LAN magic packet to each MAC (repeatable), then exit.
    /// Scanning targets are ignored when --wake is set.
    #[arg(long, value_name = "MAC", num_args = 1..)]
    wake: Vec<String>,

    /// With --wake, send the packet N times per MAC.
    ///
    /// Some BIOSes need 2-3 packets before the NIC reacts. 0 is treated as 1.
    #[arg(long, value_name = "N", default_value_t = 1, requires = "wake")]
    wake_repeat: u32,

    /// With --wake --wake-repeat, pause this many ms between sends.
    ///
    /// Ignored when --wake-repeat is 1 (the default).
    #[arg(long, value_name = "MS", default_value_t = 100, requires = "wake")]
    wake_interval_ms: u64,
}

fn parse_targets(raw: &[String]) -> Result<Vec<IpSet>, String> {
    raw.iter()
        .map(|s| s.parse::<IpSet>().map_err(|e| format!("{s:?}: {e}")))
        .collect()
}

fn parse_macs(raw: &[String]) -> Result<Vec<[u8; 6]>, String> {
    raw.iter()
        .map(|s| wol_rs::parse_mac(s).map_err(|e| format!("{s:?}: {e}")))
        .collect()
}

fn run(cli: Cli) -> Result<(), String> {
    // --wake short-circuits: skip target/port validation entirely.
    if !cli.report.eq_ignore_ascii_case("alive") && !cli.report.eq_ignore_ascii_case("all") {
        return Err(format!(
            "--report expects 'alive' or 'all', got {:?}",
            cli.report
        ));
    }
    if !cli.sort.eq_ignore_ascii_case("addr") && !cli.sort.eq_ignore_ascii_case("ports") {
        return Err(format!(
            "--sort expects 'addr' or 'ports', got {:?}",
            cli.sort
        ));
    }

    if !cli.wake.is_empty() {
        let macs = parse_macs(&cli.wake)?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        let interval = std::time::Duration::from_millis(cli.wake_interval_ms);
        let repeats = cli.wake_repeat.max(1);
        if repeats == 1 && cli.wake_interval_ms != 100 {
            eprintln!("netscan: --wake-interval-ms is ignored when --wake-repeat=1");
        }
        rt.block_on(async {
            for mac in macs {
                netscan_core::wake_repeat(mac, repeats, interval)
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
    let mut results = rt.block_on(scanner.run());
    if cli.sort.eq_ignore_ascii_case("ports") {
        // Descending by number of open ports, ties broken by address for
        // deterministic output.
        results.sort_by(|a, b| {
            b.open_ports
                .len()
                .cmp(&a.open_ports.len())
                .then(a.addr.cmp(&b.addr))
        });
    }
    if cli.limit > 0 && results.len() > cli.limit {
        results.truncate(cli.limit);
    }

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
        let want_all = cli.report.eq_ignore_ascii_case("all");
        for r in &results {
            if r.is_alive() || want_all {
                let ports = r
                    .open_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!("{}\t{ports}", r.addr);
            }
        }
        eprintln!("# alive: {} / {}", alive_count(&results), results.len());
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
