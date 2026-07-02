//! # netscan-core
//!
//! Async TCP connect-scanner that composes the stepping-stone crates:
//!
//! - [`cidr_utils::IpSet`] for target parsing (CIDR / range / bare address)
//! - [`portspec::PortSpec`] for port-list parsing (`22,80,1000-2000`)
//! - [`oui_lookup`] for MAC → vendor enrichment
//! - [`wol_rs`] for magic-packet construction (wake helpers)
//!
//! The crate is intentionally the *engine* — no UI, no scheduling niceties,
//! just an async [`Scanner`] that yields [`HostResult`]s. Front-ends (Tauri,
//! CLI, TUI) sit on top.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use cidr_utils::IpSet;
use portspec::PortSpec;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub use cidr_utils;
pub use oui_lookup;
pub use portspec;
pub use wol_rs;

/// Default per-connection TCP-connect timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Default number of in-flight connection attempts.
pub const DEFAULT_CONCURRENCY: usize = 256;

/// A single scan configuration.
#[derive(Debug, Clone)]
pub struct Scanner {
    /// The host targets to probe.
    pub targets: Vec<IpSet>,
    /// The port set to try against each host.
    pub ports: PortSpec,
    /// Per-connection timeout for the TCP handshake.
    pub timeout: Duration,
    /// Maximum concurrent connection attempts.
    pub concurrency: usize,
}

impl Scanner {
    /// Construct a scanner with the default timeout and concurrency.
    pub fn new(targets: Vec<IpSet>, ports: PortSpec) -> Self {
        Self {
            targets,
            ports,
            timeout: DEFAULT_TIMEOUT,
            concurrency: DEFAULT_CONCURRENCY,
        }
    }

    /// Override the per-connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the maximum concurrency.
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency.max(1);
        self
    }

    /// Total number of (address, port) pairs the scan will attempt.
    pub fn total_probes(&self) -> u128 {
        let addr_count: u128 = self.targets.iter().map(IpSet::count).sum();
        addr_count * u128::from(self.ports.count())
    }

    /// Iterate over every (address, port) pair the scan will probe, in
    /// target-then-port order.
    pub fn probes(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.targets.iter().flat_map(move |t| {
            t.addresses()
                .flat_map(move |a| self.ports.iter().map(move |p| SocketAddr::new(a, p)))
        })
    }
}

/// The state of a single host after the scan finishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostResult {
    /// The scanned address.
    pub addr: IpAddr,
    /// Ports that answered a SYN-ACK within the timeout.
    pub open_ports: Vec<u16>,
}

impl HostResult {
    /// A host counts as *alive* when at least one probed port responded.
    pub fn is_alive(&self) -> bool {
        !self.open_ports.is_empty()
    }
}

/// The outcome of a single (address, port) probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStatus {
    /// TCP handshake completed within the timeout — port is open.
    Open,
    /// The remote actively refused the connection (RST). Distinguishing this
    /// from a filtered timeout tells the caller the host is up.
    Closed,
    /// The handshake didn't complete within the timeout.
    Filtered,
}

/// Attempt a TCP connect to `sock` with the given `deadline`.
///
/// Returns [`ProbeStatus::Open`] on a successful handshake,
/// [`ProbeStatus::Closed`] on an explicit refusal (`ECONNREFUSED`), and
/// [`ProbeStatus::Filtered`] on timeout or any other IO error.
pub async fn probe(sock: SocketAddr, deadline: Duration) -> ProbeStatus {
    match timeout(deadline, TcpStream::connect(sock)).await {
        Ok(Ok(_stream)) => ProbeStatus::Open,
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => ProbeStatus::Closed,
        Ok(Err(_)) => ProbeStatus::Filtered,
        Err(_) => ProbeStatus::Filtered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scanner_total_probes_multiplies_addresses_by_ports() {
        let t: IpSet = "10.0.0.0/30".parse().unwrap();
        let p: PortSpec = "22,80,443".parse().unwrap();
        let s = Scanner::new(vec![t], p);
        // 4 addresses × 3 ports.
        assert_eq!(s.total_probes(), 12);
    }

    #[test]
    fn scanner_probes_yield_socket_addrs_in_order() {
        let t: IpSet = "10.0.0.1-10.0.0.2".parse().unwrap();
        let p: PortSpec = "22,80".parse().unwrap();
        let s = Scanner::new(vec![t], p);
        let got: Vec<_> = s.probes().collect();
        assert_eq!(
            got,
            vec![
                "10.0.0.1:22".parse().unwrap(),
                "10.0.0.1:80".parse().unwrap(),
                "10.0.0.2:22".parse().unwrap(),
                "10.0.0.2:80".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn concurrency_floor_is_one() {
        let s = Scanner::new(vec![], PortSpec::new()).with_concurrency(0);
        assert_eq!(s.concurrency, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn probe_closed_port_on_localhost_is_closed_or_filtered() {
        // We can't guarantee 127.0.0.1:1 is closed on every CI image (it
        // usually is), but the probe must return without panicking either way.
        let s = probe("127.0.0.1:1".parse().unwrap(), Duration::from_millis(200)).await;
        assert!(
            matches!(s, ProbeStatus::Closed | ProbeStatus::Filtered),
            "unexpected status: {s:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn probe_open_port_via_ephemeral_listener() {
        // Bind an ephemeral listener and probe it: the connect must succeed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let status = probe(addr, Duration::from_millis(500)).await;
        handle.abort();
        assert_eq!(status, ProbeStatus::Open);
    }

    #[test]
    fn host_result_alive_predicate() {
        let alive = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22],
        };
        assert!(alive.is_alive());
        let dead = HostResult {
            addr: "10.0.0.2".parse().unwrap(),
            open_ports: vec![],
        };
        assert!(!dead.is_alive());
    }
}
