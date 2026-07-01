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
    #[arg(value_name = "TARGET", required = true)]
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

    /// Only print the total number of probes and exit, without scanning.
    #[arg(long)]
    dry_run: bool,
}

fn parse_targets(raw: &[String]) -> Result<Vec<IpSet>, String> {
    raw.iter()
        .map(|s| s.parse::<IpSet>().map_err(|e| format!("{s:?}: {e}")))
        .collect()
}

fn run(cli: Cli) -> Result<(), String> {
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

    // Live scanning lands in a follow-up commit; for now the binary refuses
    // to pretend it did something it didn't.
    Err("live scanning not yet implemented — pass --dry-run to preview the plan".into())
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
