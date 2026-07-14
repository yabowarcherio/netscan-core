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
//!
//! # Example
//!
//! ```
//! use netscan_core::Scanner;
//! use cidr_utils::IpSet;
//! use portspec::PortSpec;
//!
//! let targets: Vec<IpSet> = vec!["10.0.0.0/30".parse().unwrap()];
//! let ports: PortSpec = "ssh,http,https".parse().unwrap();
//! let s = Scanner::new(targets, ports);
//! // 4 hosts × 3 ports.
//! assert_eq!(s.total_probes(), 12);
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use cidr_utils::IpSet;
use portspec::PortSpec;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;

pub use cidr_utils;
pub use oui_lookup;
pub use portspec;
pub use wol_rs;

/// Default per-connection TCP-connect timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1500);

/// Default number of in-flight connection attempts.
pub const DEFAULT_CONCURRENCY: usize = 256;

/// Default buffer size handed to [`Scanner::stream_bounded`] when the caller
/// doesn't override it. Small enough to backpressure quickly, large enough
/// to keep the sender busy on a 1-Gbps link.
pub const DEFAULT_STREAM_BUFFER: usize = 128;

/// A curated short list of ports that a "quick scan" typically hits — SSH,
/// HTTP, HTTPS, RDP. Matches the CLI's default `--ports` value.
pub const QUICK_PORTS: &[u16] = &[22, 80, 443, 3389];

/// The set of ports commonly enumerated as "web" services.
pub const WEB_PORTS: &[u16] = &[80, 443, 8000, 8008, 8080, 8443, 8888];

/// The set of ports commonly enumerated as "remote-shell" services.
pub const SHELL_PORTS: &[u16] = &[22, 23, 3389, 5900];

/// The set of ports commonly enumerated as "database" services.
pub const DB_PORTS: &[u16] = &[1433, 3306, 5432, 6379, 27017, 9042, 9200, 11211];

/// A single scan configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
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

    /// Construct an empty scanner — no targets, no ports.
    /// Equivalent to [`Scanner::default`], but reads more naturally at the
    /// head of a builder chain.
    pub fn empty() -> Self {
        Self::default()
    }

    /// `true` when the scanner has zero probes to run.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty() || self.ports.is_empty()
    }

    /// Rough upper bound on how long the scan will take.
    ///
    /// Computed as `ceil(total_probes / concurrency) * max(timeout, 1s)`,
    /// so a caller with `1e9` probes gets a large but non-wrapping estimate.
    /// Assumes the worst case where every probe times out — real scans are
    /// typically much faster because open ports respond within a few ms.
    pub fn estimated_duration(&self) -> Duration {
        let batches = self
            .total_probes()
            .div_ceil(self.concurrency.max(1) as u128);
        // Saturating math: a caller with 1e9 probes should get a large, but
        // not wrapped, estimate.
        let secs = (batches as u64).saturating_mul(self.timeout.as_secs().max(1));
        Duration::from_secs(secs)
    }

    /// Sum of address counts across every target set.
    pub fn total_addresses(&self) -> u128 {
        self.targets.iter().map(IpSet::count).sum()
    }

    /// Number of ports probed against each host.
    pub fn total_ports(&self) -> u32 {
        self.ports.count()
    }

    /// Number of target sets configured on this scanner.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Append a target to the existing list, returning the scanner for chaining.
    pub fn push_target(mut self, target: IpSet) -> Self {
        self.targets.push(target);
        self
    }

    /// Clear the target list without disturbing the ports/timeout/concurrency.
    pub fn clear_targets(mut self) -> Self {
        self.targets.clear();
        self
    }

    /// Replace the target list, keeping timeout/concurrency/ports intact.
    pub fn with_targets(mut self, targets: Vec<IpSet>) -> Self {
        self.targets = targets;
        self
    }

    /// Replace the port list, keeping timeout/concurrency/targets intact.
    pub fn with_ports(mut self, ports: PortSpec) -> Self {
        self.ports = ports;
        self
    }

    /// Override the per-connection timeout. Values above
    /// [`PROBE_MAX_TIMEOUT`] are silently clamped.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.min(PROBE_MAX_TIMEOUT);
        self
    }

    /// Override the maximum concurrency. Zero is promoted to one — a scan is
    /// pointless with no in-flight probes.
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

    /// Bounded-channel variant of [`Scanner::stream`] using
    /// [`DEFAULT_STREAM_BUFFER`].
    pub fn stream_bounded_default(&self) -> mpsc::Receiver<(SocketAddr, ProbeStatus)> {
        self.stream_bounded(DEFAULT_STREAM_BUFFER)
    }

    /// Bounded-channel variant of [`Scanner::stream`] — drop-in with a caller
    /// picked buffer size. When the receiver falls behind, the sending tasks
    /// wait on send instead of piling up memory.
    pub fn stream_bounded(
        &self,
        buffer: usize,
    ) -> mpsc::Receiver<(SocketAddr, ProbeStatus)> {
        let (tx, rx) = mpsc::channel(buffer.max(1));
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let timeout_dur = self.timeout;
        let probes: Vec<SocketAddr> = self.probes().collect();
        tokio::spawn(async move {
            let mut handles = Vec::with_capacity(probes.len());
            for sock in probes {
                let sem = Arc::clone(&sem);
                let tx = tx.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire_owned().await.expect("semaphore not closed");
                    let status = probe(sock, timeout_dur).await;
                    let _ = tx.send((sock, status)).await;
                }));
            }
            for h in handles {
                let _ = h.await;
            }
        });
        rx
    }

    /// Spawn every probe concurrently (bounded by `concurrency`) and stream
    /// each `(SocketAddr, ProbeStatus)` result as soon as it lands.
    ///
    /// The returned receiver closes when every probe has been reported. This
    /// is the low-latency alternative to [`Scanner::run`], useful when a UI
    /// wants to display results as they arrive.
    ///
    /// The channel is unbounded — a slow consumer will backlog memory. For
    /// tight backpressure, wrap the receiver in a bounded channel of your
    /// own or use [`Scanner::run`] for the complete-batch API.
    pub fn stream(&self) -> mpsc::UnboundedReceiver<(SocketAddr, ProbeStatus)> {
        let (tx, rx) = mpsc::unbounded_channel();
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let timeout_dur = self.timeout;
        // Materialize the probe list so we can move it into the runner task
        // without keeping `&self` alive across await points.
        let probes: Vec<SocketAddr> = self.probes().collect();
        tokio::spawn(async move {
            let mut handles = Vec::with_capacity(probes.len());
            for sock in probes {
                let sem = Arc::clone(&sem);
                let tx = tx.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire_owned().await.expect("semaphore not closed");
                    let status = probe(sock, timeout_dur).await;
                    let _ = tx.send((sock, status));
                }));
            }
            for h in handles {
                let _ = h.await;
            }
        });
        rx
    }

    /// Run every probe concurrently (bounded by `concurrency`) and return
    /// the results grouped by host, in address order.
    ///
    /// Ports that answered a SYN-ACK land in [`HostResult::open_ports`],
    /// sorted ascending. Hosts with zero open ports are still present in the
    /// returned map — callers can filter with [`HostResult::is_alive`].
    pub async fn run(&self) -> Vec<HostResult> {
        let sem = Arc::new(Semaphore::new(self.concurrency));
        let timeout_dur = self.timeout;
        let mut handles = Vec::new();
        for sock in self.probes() {
            let sem = Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                // Slot acquired for the lifetime of the probe.
                let _permit = sem.acquire_owned().await.expect("semaphore not closed");
                let status = probe(sock, timeout_dur).await;
                (sock, status)
            }));
        }

        let mut open: BTreeMap<IpAddr, Vec<u16>> = BTreeMap::new();
        // Pre-seed every target so hosts with zero open ports still appear
        // in the output — that's what "no answer at all" looks like to a
        // caller writing a report.
        for t in &self.targets {
            for a in t.addresses() {
                open.entry(a).or_default();
            }
        }

        for h in handles {
            if let Ok((sock, ProbeStatus::Open)) = h.await {
                open.entry(sock.ip()).or_default().push(sock.port());
            }
        }

        open.into_iter()
            .map(|(addr, mut ports)| {
                ports.sort_unstable();
                HostResult {
                    addr,
                    open_ports: ports,
                }
            })
            .collect()
    }
}

/// The state of a single host after the scan finishes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostResult {
    /// The scanned address.
    pub addr: IpAddr,
    /// Ports that answered a SYN-ACK within the timeout.
    pub open_ports: Vec<u16>,
}

impl HostResult {
    /// Construct a fresh `HostResult` with no observed open ports.
    pub fn new(addr: IpAddr) -> Self {
        Self {
            addr,
            open_ports: Vec::new(),
        }
    }

    /// A host counts as *alive* when at least one probed port responded.
    pub fn is_alive(&self) -> bool {
        !self.open_ports.is_empty()
    }

    /// Attach a MAC + vendor to this host result, producing an [`EnrichedHost`].
    ///
    /// Vendor resolution is done through the embedded `oui-lookup` registry;
    /// unknown OUIs get `None`.
    pub fn enrich(self, mac: [u8; 6]) -> EnrichedHost {
        let vendor = oui_lookup::lookup_octets(mac).map(str::to_string);
        EnrichedHost {
            host: self,
            mac: Some(mac),
            vendor,
        }
    }
}

/// Extract every alive host from a batch of results, borrowing them from the
/// original slice.
pub fn alive_hosts(results: &[HostResult]) -> impl Iterator<Item = &HostResult> {
    results.iter().filter(|r| r.is_alive())
}

/// Extract every dead host from a batch of results — the complement of
/// [`alive_hosts`].
pub fn dead_hosts(results: &[HostResult]) -> impl Iterator<Item = &HostResult> {
    results.iter().filter(|r| !r.is_alive())
}

/// Split a batch into (alive, dead) counts in one linear pass.
pub fn alive_dead_split(results: &[HostResult]) -> (usize, usize) {
    let alive = alive_count(results);
    (alive, results.len() - alive)
}

/// Total open-port count across every host in the batch. Repeats between
/// hosts count separately; use [`distinct_open_ports`] for the deduped set.
pub fn total_open_port_hits(results: &[HostResult]) -> usize {
    results.iter().map(|r| r.open_ports.len()).sum()
}

/// The single most-common open port across the batch, or `None` if no host
/// answered on anything.
pub fn most_common_open_port(results: &[HostResult]) -> Option<u16> {
    let mut counts: std::collections::HashMap<u16, usize> = Default::default();
    for r in results {
        for p in &r.open_ports {
            *counts.entry(*p).or_insert(0) += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, c)| *c).map(|(p, _)| p)
}

/// Filter results whose address matches a caller-supplied predicate.
///
/// Handy for slicing an IPv6-heavy scan down to just its IPv4 half, or the
/// reverse.
pub fn filter_by_addr<F>(results: &[HostResult], pred: F) -> Vec<&HostResult>
where
    F: Fn(&IpAddr) -> bool,
{
    results.iter().filter(|r| pred(&r.addr)).collect()
}

/// Partition results into `(ipv4, ipv6)` slices, borrowing from the input.
pub fn split_by_family(results: &[HostResult]) -> (Vec<&HostResult>, Vec<&HostResult>) {
    let (v4, v6): (Vec<_>, Vec<_>) = results.iter().partition(|r| r.addr.is_ipv4());
    (v4, v6)
}

/// Group results by their open-port count, keyed on the count.
///
/// Useful for histograms — most hosts have 0 open ports, a few have 1-3,
/// outliers have dozens.
pub fn histogram_by_port_count(
    results: &[HostResult],
) -> std::collections::BTreeMap<usize, usize> {
    let mut hist: std::collections::BTreeMap<usize, usize> = Default::default();
    for r in results {
        *hist.entry(r.open_ports.len()).or_insert(0) += 1;
    }
    hist
}

/// The top-N most-common open ports across the batch, in descending count
/// order. Ties break by ascending port number for deterministic output.
pub fn top_open_ports(results: &[HostResult], n: usize) -> Vec<(u16, usize)> {
    if n == 0 {
        return Vec::new();
    }
    let mut counts: std::collections::HashMap<u16, usize> = Default::default();
    for r in results {
        for p in &r.open_ports {
            *counts.entry(*p).or_insert(0) += 1;
        }
    }
    let mut v: Vec<(u16, usize)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

/// Count how many hosts in a batch had zero open ports.
pub fn dead_count(results: &[HostResult]) -> usize {
    dead_hosts(results).count()
}

/// Find the [`HostResult`] with the highest number of open ports.
///
/// Ties are broken by the address's natural order, and an empty slice yields
/// `None`.
pub fn top_host(results: &[HostResult]) -> Option<&HostResult> {
    results.iter().max_by(|a, b| {
        a.open_ports
            .len()
            .cmp(&b.open_ports.len())
            .then(b.addr.cmp(&a.addr))
    })
}

/// Count how many hosts in a batch responded on at least one port.
pub fn alive_count(results: &[HostResult]) -> usize {
    alive_hosts(results).count()
}

/// The distinct open ports observed across a batch of results, deduped and
/// sorted ascending.
pub fn distinct_open_ports(results: &[HostResult]) -> Vec<u16> {
    let mut ports: Vec<u16> = results
        .iter()
        .flat_map(|r| r.open_ports.iter().copied())
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// A [`HostResult`] plus a MAC address and (resolved) vendor.
///
/// Meant for the case where a caller has an ARP table or similar
/// side-channel mapping IPs to MACs — this crate can't discover MACs on its
/// own without raw-socket access, which requires privileges we deliberately
/// don't ask for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EnrichedHost {
    /// The underlying scan result.
    pub host: HostResult,
    /// The MAC address of the host, if known.
    pub mac: Option<[u8; 6]>,
    /// The vendor name for the MAC's OUI, if the OUI is in the registry.
    pub vendor: Option<String>,
}

impl EnrichedHost {
    /// Delegating shortcut to [`HostResult::is_alive`].
    pub fn is_alive(&self) -> bool {
        self.host.is_alive()
    }

    /// The scanned address, delegating through the underlying `host`.
    pub fn addr(&self) -> IpAddr {
        self.host.addr
    }

    /// The list of open ports, delegating through the underlying `host`.
    pub fn open_ports(&self) -> &[u16] {
        &self.host.open_ports
    }

    /// Update the vendor name in-place. Useful when a caller wants to try
    /// their own fallback registry after this crate's OUI lookup miss.
    pub fn set_vendor(&mut self, vendor: Option<String>) {
        self.vendor = vendor;
    }

    /// `true` when both a MAC and a vendor name are attached.
    pub fn has_vendor(&self) -> bool {
        self.mac.is_some() && self.vendor.is_some()
    }
}

/// Build and send a Wake-on-LAN magic packet to `mac` on the local subnet
/// broadcast. Non-blocking; returns after the UDP send completes.
///
/// Delegates to `wol_rs` for the packet layout. Uses IPv4 limited broadcast
/// (`255.255.255.255`) on port [`wol_rs::BROADCAST_PORT`] (9 by convention)
/// — the conventional WoL destination.
pub async fn wake(mac: [u8; 6]) -> std::io::Result<()> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.set_broadcast(true)?;
    let pkt = wol_rs::magic_packet_array(mac);
    sock.send_to(
        &pkt,
        (wol_rs::IPV4_LIMITED_BROADCAST, wol_rs::BROADCAST_PORT),
    )
    .await?;
    Ok(())
}

/// Wake many MACs sequentially, stopping on the first error.
pub async fn wake_many<I>(macs: I) -> std::io::Result<()>
where
    I: IntoIterator<Item = [u8; 6]>,
{
    for mac in macs {
        wake(mac).await?;
    }
    Ok(())
}

/// Wake many MACs sequentially, collecting each individual result rather than
/// aborting on the first error. The output preserves input order.
pub async fn wake_many_collect<I>(macs: I) -> Vec<std::io::Result<()>>
where
    I: IntoIterator<Item = [u8; 6]>,
{
    let mut out = Vec::new();
    for mac in macs {
        out.push(wake(mac).await);
    }
    out
}

/// Count how many MACs in the batch responded successfully — i.e. the packet
/// reached the socket layer without error.
pub fn wake_success_count(results: &[std::io::Result<()>]) -> usize {
    results.iter().filter(|r| r.is_ok()).count()
}

/// Count how many MACs in the batch failed at the socket layer.
pub fn wake_failure_count(results: &[std::io::Result<()>]) -> usize {
    results.iter().filter(|r| r.is_err()).count()
}

/// Default number of repeats used by [`wake_repeat`] when the caller doesn't
/// override it — some BIOSes need at least two magic packets before the NIC
/// actually reacts.
pub const DEFAULT_WAKE_REPEATS: u32 = 3;

/// Default pause between successive [`wake_repeat`] sends.
pub const DEFAULT_WAKE_INTERVAL: Duration = Duration::from_millis(100);

/// Send the same magic packet `n` times, pausing `interval` between sends.
///
/// Some BIOSes need 2-3 packets before the NIC reacts. `n` is treated as at
/// least 1.
pub async fn wake_repeat(mac: [u8; 6], n: u32, interval: Duration) -> std::io::Result<()> {
    let n = n.max(1);
    for i in 0..n {
        wake(mac).await?;
        if i + 1 < n {
            tokio::time::sleep(interval).await;
        }
    }
    Ok(())
}

/// The outcome of a single (address, port) probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeStatus {
    /// TCP handshake completed within the timeout — port is open.
    Open,
    /// The remote actively refused the connection (RST). Distinguishing this
    /// from a filtered timeout tells the caller the host is up.
    Closed,
    /// The handshake didn't complete within the timeout.
    Filtered,
}

impl ProbeStatus {
    /// `true` when the port is [`ProbeStatus::Open`].
    pub fn is_open(self) -> bool {
        matches!(self, ProbeStatus::Open)
    }

    /// `true` when the remote actively refused the connection.
    pub fn is_closed(self) -> bool {
        matches!(self, ProbeStatus::Closed)
    }

    /// `true` when the probe timed out or errored.
    pub fn is_filtered(self) -> bool {
        matches!(self, ProbeStatus::Filtered)
    }

    /// A short, allocation-free label — `"open"`, `"closed"`, or `"filtered"`.
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeStatus::Open => "open",
            ProbeStatus::Closed => "closed",
            ProbeStatus::Filtered => "filtered",
        }
    }
}

impl std::fmt::Display for ProbeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Maximum probe timeout accepted by [`probe`]. Longer timeouts are clamped
/// silently — no realistic scan wants a single connect attempt to block for
/// more than a couple of minutes.
pub const PROBE_MAX_TIMEOUT: Duration = Duration::from_secs(120);

/// Minimum probe timeout accepted by [`probe`]. Values below this are
/// treated as this — anything shorter is a foot-gun (Linux kernels routinely
/// round short `connect` deadlines up anyway).
pub const PROBE_MIN_TIMEOUT: Duration = Duration::from_millis(10);

/// Probe several `(SocketAddr, Duration)` pairs sequentially, returning each
/// result in input order.
///
/// Prefer [`Scanner::run`] or [`Scanner::stream`] when you want the probes
/// fanned out concurrently — this helper is only useful for tiny lists and
/// tests where sequential timing matters.
pub async fn probe_many(
    targets: impl IntoIterator<Item = (SocketAddr, Duration)>,
) -> Vec<(SocketAddr, ProbeStatus)> {
    let mut out = Vec::new();
    for (sock, dur) in targets {
        out.push((sock, probe(sock, dur).await));
    }
    out
}

/// Attempt a TCP connect to `sock` with the given `deadline`. `deadline` is
/// clamped to [`PROBE_MAX_TIMEOUT`].
///
/// Returns [`ProbeStatus::Open`] on a successful handshake,
/// [`ProbeStatus::Closed`] on an explicit refusal (`ECONNREFUSED`), and
/// [`ProbeStatus::Filtered`] on timeout or any other IO error.
pub async fn probe(sock: SocketAddr, deadline: Duration) -> ProbeStatus {
    let deadline = deadline.min(PROBE_MAX_TIMEOUT);
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
    fn builder_methods_chain_cleanly() {
        let s = Scanner::empty()
            .with_targets(vec!["10.0.0.0/29".parse().unwrap()])
            .with_ports("22,80".parse().unwrap())
            .with_timeout(Duration::from_millis(200))
            .with_concurrency(4);
        assert_eq!(s.total_probes(), 16);
        assert_eq!(s.timeout, Duration::from_millis(200));
        assert_eq!(s.concurrency, 4);
    }

    #[test]
    fn clear_targets_leaves_ports_and_config() {
        let s = Scanner::empty()
            .push_target("10.0.0.0/30".parse().unwrap())
            .with_ports("22,80".parse().unwrap())
            .with_concurrency(8)
            .clear_targets();
        assert_eq!(s.target_count(), 0);
        // Ports/concurrency survive the clear.
        assert_eq!(s.total_ports(), 2);
        assert_eq!(s.concurrency, 8);
    }

    #[test]
    fn estimated_duration_scales_with_probes() {
        let single = Scanner::new(vec!["10.0.0.1".parse().unwrap()], "22".parse().unwrap())
            .with_concurrency(1)
            .with_timeout(Duration::from_secs(1));
        let wide = Scanner::new(vec!["10.0.0.0/28".parse().unwrap()], "22".parse().unwrap())
            .with_concurrency(1)
            .with_timeout(Duration::from_secs(1));
        assert!(wide.estimated_duration() > single.estimated_duration());
    }

    #[test]
    fn push_target_appends_and_updates_count() {
        let s = Scanner::empty();
        assert_eq!(s.target_count(), 0);
        let s = s.push_target("10.0.0.0/30".parse().unwrap());
        assert_eq!(s.target_count(), 1);
        assert_eq!(s.total_addresses(), 4);
        let s = s.push_target("192.168.0.1".parse().unwrap());
        assert_eq!(s.target_count(), 2);
        assert_eq!(s.total_addresses(), 5);
    }

    #[test]
    fn total_addresses_and_ports_match_total_probes() {
        let s = Scanner::new(
            vec!["10.0.0.0/29".parse().unwrap()],
            "22,80".parse().unwrap(),
        );
        assert_eq!(s.total_addresses(), 8);
        assert_eq!(s.total_ports(), 2);
        assert_eq!(
            s.total_probes(),
            u128::from(s.total_ports()) * s.total_addresses()
        );
    }

    #[test]
    fn top_host_picks_the_host_with_most_open_ports() {
        let a = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22, 80],
        };
        let b = HostResult {
            addr: "10.0.0.2".parse().unwrap(),
            open_ports: vec![22],
        };
        let batch = [a.clone(), b];
        assert_eq!(top_host(&batch), Some(&a));
        let empty: [HostResult; 0] = [];
        assert!(top_host(&empty).is_none());
    }

    #[test]
    fn filter_by_addr_slices_ipv4_only() {
        let a = HostResult::new("10.0.0.1".parse().unwrap());
        let b = HostResult::new("2001:db8::1".parse().unwrap());
        let batch = [a, b];
        let v4: Vec<_> = filter_by_addr(&batch, |a| a.is_ipv4());
        assert_eq!(v4.len(), 1);
        assert!(v4[0].addr.is_ipv4());
    }

    #[test]
    fn histogram_by_port_count_groups_hosts() {
        let a = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22, 80],
        };
        let b = HostResult {
            addr: "10.0.0.2".parse().unwrap(),
            open_ports: vec![22, 80],
        };
        let c = HostResult::new("10.0.0.3".parse().unwrap());
        let h = histogram_by_port_count(&[a, b, c]);
        assert_eq!(h.get(&2), Some(&2));
        assert_eq!(h.get(&0), Some(&1));
    }

    #[test]
    fn top_open_ports_is_sorted_and_capped() {
        let a = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22, 80, 443],
        };
        let b = HostResult {
            addr: "10.0.0.2".parse().unwrap(),
            open_ports: vec![22, 80],
        };
        let c = HostResult {
            addr: "10.0.0.3".parse().unwrap(),
            open_ports: vec![22],
        };
        let top = top_open_ports(&[a, b, c], 2);
        assert_eq!(top, vec![(22, 3), (80, 2)]);
        assert!(top_open_ports(&[], 5).is_empty());
        assert!(top_open_ports(&[HostResult::new("10.0.0.1".parse().unwrap())], 0).is_empty());
    }

    #[test]
    fn most_common_open_port_picks_the_repeat() {
        let a = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22, 80],
        };
        let b = HostResult {
            addr: "10.0.0.2".parse().unwrap(),
            open_ports: vec![22],
        };
        assert_eq!(most_common_open_port(&[a, b]), Some(22));
        let empty: [HostResult; 0] = [];
        assert_eq!(most_common_open_port(&empty), None);
    }

    #[test]
    fn total_open_port_hits_sums_with_multiplicity() {
        let a = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22, 80],
        };
        let b = HostResult {
            addr: "10.0.0.2".parse().unwrap(),
            open_ports: vec![22],
        };
        // 22 appears on both hosts but is still counted twice — that's the
        // point of the "hits" name.
        assert_eq!(total_open_port_hits(&[a, b]), 3);
    }

    #[test]
    fn alive_dead_split_matches_individual_counts() {
        let a = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22],
        };
        let b = HostResult::new("10.0.0.2".parse().unwrap());
        let batch = [a, b];
        let (alive, dead) = alive_dead_split(&batch);
        assert_eq!(alive, alive_count(&batch));
        assert_eq!(dead, dead_count(&batch));
    }

    #[test]
    fn dead_and_alive_counts_partition_the_batch() {
        let a = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22],
        };
        let b = HostResult::new("10.0.0.2".parse().unwrap());
        let batch = [a, b];
        assert_eq!(alive_count(&batch) + dead_count(&batch), batch.len());
    }

    #[test]
    fn distinct_open_ports_is_sorted_and_deduped() {
        let a = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![80, 22, 80],
        };
        let b = HostResult {
            addr: "10.0.0.2".parse().unwrap(),
            open_ports: vec![22, 443],
        };
        assert_eq!(distinct_open_ports(&[a, b]), vec![22, 80, 443]);
    }

    #[test]
    fn alive_count_matches_alive_hosts_count() {
        let a = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22],
        };
        let b = HostResult::new("10.0.0.2".parse().unwrap());
        let batch = [a, b];
        assert_eq!(alive_count(&batch), alive_hosts(&batch).count());
        assert_eq!(alive_count(&batch), 1);
    }

    #[test]
    fn quick_ports_and_web_ports_are_non_empty() {
        assert!(!QUICK_PORTS.is_empty());
        assert!(!WEB_PORTS.is_empty());
        assert!(QUICK_PORTS.contains(&22));
        assert!(WEB_PORTS.contains(&80));
    }

    #[test]
    fn empty_scanner_has_zero_probes() {
        let s = Scanner::empty();
        assert!(s.is_empty());
        assert_eq!(s.total_probes(), 0);
    }

    #[test]
    fn with_timeout_clamps_to_probe_max_timeout() {
        let s = Scanner::empty().with_timeout(Duration::from_secs(3600));
        assert_eq!(s.timeout, PROBE_MAX_TIMEOUT);
    }

    #[test]
    fn concurrency_floor_is_one() {
        let s = Scanner::new(vec![], PortSpec::new()).with_concurrency(0);
        assert_eq!(s.concurrency, 1);
    }

    #[test]
    fn probe_status_predicates() {
        assert!(ProbeStatus::Open.is_open());
        assert!(!ProbeStatus::Open.is_closed());
        assert!(ProbeStatus::Closed.is_closed());
        assert!(ProbeStatus::Filtered.is_filtered());
    }

    #[test]
    fn probe_status_as_str_matches_display() {
        for s in [
            ProbeStatus::Open,
            ProbeStatus::Closed,
            ProbeStatus::Filtered,
        ] {
            assert_eq!(s.as_str(), s.to_string());
        }
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
    async fn probe_many_preserves_input_order() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let closed: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let out = probe_many([
            (open, Duration::from_millis(400)),
            (closed, Duration::from_millis(100)),
        ])
        .await;
        handle.abort();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, open);
        assert_eq!(out[0].1, ProbeStatus::Open);
        assert_eq!(out[1].0, closed);
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scanner_stream_bounded_delivers_results() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepter = tokio::spawn(async move {
            for _ in 0..2 {
                let _ = listener.accept().await;
            }
        });
        let s = Scanner::new(
            vec!["127.0.0.1".parse().unwrap()],
            format!("{port}").parse().unwrap(),
        )
        .with_timeout(Duration::from_millis(400));
        let mut rx = s.stream_bounded(1);
        let mut got = Vec::new();
        while let Some(event) = rx.recv().await {
            got.push(event);
        }
        accepter.abort();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, ProbeStatus::Open);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scanner_stream_reports_open_port_promptly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepter = tokio::spawn(async move {
            for _ in 0..4 {
                let _ = listener.accept().await;
            }
        });

        let target: IpSet = "127.0.0.1".parse().unwrap();
        let ports: PortSpec = format!("{port}").parse().unwrap();
        let s = Scanner::new(vec![target], ports).with_timeout(Duration::from_millis(400));

        let mut rx = s.stream();
        let mut got = Vec::new();
        while let Some(event) = rx.recv().await {
            got.push(event);
        }
        accepter.abort();

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, ProbeStatus::Open);
        assert_eq!(got[0].0.port(), port);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scanner_run_finds_ephemeral_listener() {
        // Bind one listener, then scan localhost across a range containing
        // the listener's port and one closed neighbour.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepter = tokio::spawn(async move {
            // Accept several connections so the semaphore doesn't back up.
            for _ in 0..8 {
                let _ = listener.accept().await;
            }
        });

        let target: IpSet = "127.0.0.1".parse().unwrap();
        let ports: PortSpec = format!("{port}").parse().unwrap();
        let s = Scanner::new(vec![target], ports)
            .with_timeout(Duration::from_millis(400))
            .with_concurrency(4);
        let results = s.run().await;
        accepter.abort();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(results[0].open_ports, vec![port]);
        assert!(results[0].is_alive());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn scanner_run_includes_dead_hosts() {
        // Scan a two-address range where neither address has any open ports.
        // Both must appear in the output with an empty open_ports vec so the
        // caller can report a full grid without missing rows.
        let target: IpSet = "127.0.0.1-127.0.0.2".parse().unwrap();
        let ports: PortSpec = "1".parse().unwrap();
        let s = Scanner::new(vec![target], ports).with_timeout(Duration::from_millis(50));
        let results = s.run().await;
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(!r.is_alive());
        }
    }

    #[test]
    fn wake_success_count_matches_manual_count() {
        let results: Vec<std::io::Result<()>> = vec![
            Ok(()),
            Err(std::io::Error::from(std::io::ErrorKind::HostUnreachable)),
            Ok(()),
        ];
        assert_eq!(wake_success_count(&results), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wake_repeat_zero_is_promoted_to_one() {
        // Passing 0 shouldn't panic or hang; the fn silently sends one packet.
        use std::io::ErrorKind;
        let res = wake_repeat([0; 6], 0, Duration::from_millis(1)).await;
        match res {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable
                ) => {}
            Err(e) => panic!("wake_repeat failed unexpectedly: {e:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wake_reaches_the_socket_layer() {
        // The interesting invariant is that wake() gets the packet all the way
        // to the OS socket layer without a bind/setsockopt failure. Whether
        // the broadcast actually leaves the box depends on the CI image's
        // routing table (GitHub's macOS runners refuse 255.255.255.255 with
        // ENETUNREACH/EHOSTUNREACH), so those errors are treated as pass.
        use std::io::ErrorKind;
        let res = wake([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).await;
        match res {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable
                ) => {}
            Err(e) => panic!("wake failed with unexpected IO error: {e:?}"),
        }
    }

    #[test]
    fn enriched_host_accessors_delegate_to_underlying_host() {
        let host = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22, 80],
        };
        let e = host.enrich([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(e.addr(), "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(e.open_ports(), &[22, 80]);
        assert!(e.is_alive());
    }

    #[test]
    fn enriched_host_has_vendor_requires_both_mac_and_vendor() {
        let host = HostResult::new("10.0.0.1".parse().unwrap());
        let mut e = host.enrich([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        e.set_vendor(None);
        assert!(!e.has_vendor());
        e.set_vendor(Some("test".into()));
        assert!(e.has_vendor());
    }

    #[test]
    fn host_result_enrich_resolves_vendor_for_registered_oui() {
        let host = HostResult {
            addr: "10.0.0.1".parse().unwrap(),
            open_ports: vec![22],
        };
        // A4:83:E7 is the Apple OUI at the time of writing; the assertion is
        // permissive: enrich must at least round-trip the MAC without panics.
        let mac = [0xA4, 0x83, 0xE7, 0x11, 0x22, 0x33];
        let e = host.enrich(mac);
        assert_eq!(e.mac, Some(mac));
        // vendor may be Some or None depending on the embedded snapshot.
        assert_eq!(e.vendor.is_some(), oui_lookup::lookup_octets(mac).is_some());
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
