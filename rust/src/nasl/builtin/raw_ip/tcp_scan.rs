// SPDX-FileCopyrightText: 2026 Greenbone AG
// SPDX-License-Identifier: GPL-2.0-or-later

use anyhow::Result;
use nasl_function_proc_macro::nasl_function;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::function_set;
use crate::nasl::{FnError, ScanCtx};
use crate::storage::items::kb::{self, Host, KbItem, KbKey};

/// Maximum number of concurrent sockets (based on FD_SETSIZE)
const GRAB_MAX_SOCK: usize = 1024;
const GRAB_MIN_SOCK: usize = 32;
const GRAB_MAX_SOCK_SAFE: usize = 128;
const MAX_PASS_NB: usize = 16;
const MAX_SANE_RTT: Duration = Duration::from_secs(2);

/// Port state enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Unknown,
    Closed,
    Open,
    Silent,   // Filtered - no response
    Rejected, // Filtered - ICMP unreachable
    NotTested,
    Testing,
}

/// RTT (Round Trip Time) statistics
#[derive(Debug, Default, Clone)]
pub struct RttStats {
    pub count: usize,
    pub sum: Duration,
    pub sum_squared: f64,
    pub min: Duration,
    pub max: Duration,
}

impl RttStats {
    fn new() -> Self {
        Self {
            count: 0,
            sum: Duration::ZERO,
            sum_squared: 0.0,
            min: Duration::from_secs(u64::MAX),
            max: Duration::ZERO,
        }
    }

    fn add(&mut self, rtt: Duration) {
        self.count += 1;
        self.sum += rtt;
        let secs = rtt.as_secs_f64();
        self.sum_squared += secs * secs;
        self.min = self.min.min(rtt);
        self.max = self.max.max(rtt);
    }

    pub fn mean(&self) -> Option<Duration> {
        if self.count == 0 {
            None
        } else {
            Some(self.sum / self.count as u32)
        }
    }

    pub fn std_dev(&self) -> Option<f64> {
        if self.count <= 1 {
            None
        } else {
            let mean = self.mean()?.as_secs_f64();
            let variance = (self.sum_squared / self.count as f64 - mean * mean) * self.count as f64
                / (self.count - 1) as f64;
            Some(variance.sqrt())
        }
    }

    pub fn estimated_max(&self) -> Option<Duration> {
        let mean = self.mean()?.as_secs_f64();
        let sd = self.std_dev()?;
        Some(Duration::from_secs_f64(mean + 3.0 * sd))
    }
}

/// Scan results for a single host
#[derive(Debug, Default)]
pub struct ScanResults {
    pub open_ports: Vec<u16>,
    pub closed_ports: Vec<u16>,
    pub filtered_ports: Vec<u16>,
    pub banners: HashMap<u16, Vec<u8>>,
    pub connection_times: HashMap<u16, Duration>,
    pub banner_read_times: HashMap<u16, Duration>,
    pub rtt_stats: [RttStats; 3], // 0: unfiltered, 1: open, 2: closed
    pub passes: usize,
    pub rst_rate_limited: bool,
}

/// Scanner configuration
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub target_ip: IpAddr,
    pub port_range: Vec<u16>,
    pub read_timeout: Duration,
    pub min_connections: usize,
    pub max_connections: usize,
    pub safe_checks: bool,
}

/// Main TCP scanner
pub struct TcpScanner {
    config: ScannerConfig,
}

fn max_load_average() -> f64 {
    let load_avg = System::load_average();
    load_avg
        .one
        .max(load_avg.five)
        .max(load_avg.fifteen)
        .max(-1.0)
}

impl TcpScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    /// Calculate optimal connection limits based on system resources
    pub fn calculate_resource_limits(
        max_hosts: usize,
        max_checks: usize,
        safe_checks: bool,
    ) -> (usize, usize) {
        // Base connection calculation
        let min_cnx = 8 * max_checks;
        let mut max_cnx = if safe_checks {
            24 * max_checks
        } else {
            80 * max_checks
        };

        // Get system load average
        let load_avg = max_load_average();
        if load_avg > 0.0 {
            max_cnx = (max_cnx as f64 / (1.0 + load_avg)) as usize;
        }

        // Get system file descriptor limits
        let max_sys_fd = Self::get_system_fd_limit().unwrap_or(16384);

        // Reserve FDs for other processes
        let available_fd = max_sys_fd.saturating_sub(1024);
        let per_host_fd = if available_fd > 0 {
            available_fd / max_hosts
        } else {
            GRAB_MIN_SOCK
        };

        max_cnx = max_cnx.min(per_host_fd).min(GRAB_MAX_SOCK);

        if safe_checks {
            max_cnx = max_cnx.min(GRAB_MAX_SOCK_SAFE);
        }

        max_cnx = max_cnx.max(GRAB_MIN_SOCK);
        let min_cnx = min_cnx.min(max_cnx / 2).max(1);

        (min_cnx, max_cnx)
    }

    /// Get system file descriptor limit
    fn get_system_fd_limit() -> Option<usize> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            // Try fs.file-max
            if let Ok(content) = fs::read_to_string("/proc/sys/fs/file-max") {
                if let Ok(limit) = content.trim().parse::<usize>() {
                    return Some(limit);
                }
            }
        }

        #[cfg(unix)]
        {
            // Try getrlimit
            use nix::sys::resource::{Resource, getrlimit};
            if let Ok((soft, _hard)) = getrlimit(Resource::RLIMIT_NOFILE) {
                return Some(soft as usize);
            }
        }

        None
    }

    /// Execute the port scan
    pub async fn scan(&self) -> Result<ScanResults> {
        let mut results = ScanResults::default();
        results.rtt_stats = [RttStats::new(), RttStats::new(), RttStats::new()];

        let mut port_states: HashMap<u16, PortState> = self
            .config
            .port_range
            .iter()
            .map(|&port| (port, PortState::Unknown))
            .collect();

        let mut min_connections = self.config.min_connections;
        let mut max_connections = self.config.max_connections;

        // Multi-pass scanning for reliability
        for pass in 1..=MAX_PASS_NB {
            debug!("Starting scan pass {}/{}", pass, MAX_PASS_NB);

            let pass_results = self
                .scan_pass(&mut port_states, min_connections, max_connections)
                .await?;

            results.open_ports.extend(&pass_results.open_ports);
            results.closed_ports.extend(&pass_results.closed_ports);
            results.filtered_ports.extend(&pass_results.filtered_ports);
            results.banners.extend(pass_results.banners);
            results
                .connection_times
                .extend(pass_results.connection_times);
            results
                .banner_read_times
                .extend(pass_results.banner_read_times);

            // Merge RTT statistics
            for i in 0..3 {
                if pass_results.rtt_stats[i].count > 0 {
                    results.rtt_stats[i].sum += pass_results.rtt_stats[i].sum;
                    results.rtt_stats[i].sum_squared += pass_results.rtt_stats[i].sum_squared;
                    results.rtt_stats[i].count += pass_results.rtt_stats[i].count;
                    results.rtt_stats[i].min =
                        results.rtt_stats[i].min.min(pass_results.rtt_stats[i].min);
                    results.rtt_stats[i].max =
                        results.rtt_stats[i].max.max(pass_results.rtt_stats[i].max);
                }
            }

            results.passes = pass;

            // Check if we need another pass
            let untested = port_states
                .values()
                .filter(|&&s| s == PortState::Unknown || s == PortState::Silent)
                .count();

            if untested == 0 {
                break;
            }

            // Adjust connection limits for next pass
            if results.filtered_ports.len() > 10 || pass_results.rst_rate_limited {
                min_connections = min_connections / (pass + 1).max(1);
                min_connections = min_connections.max(1);

                if pass_results.rst_rate_limited {
                    max_connections = max_connections.min(GRAB_MAX_SOCK_SAFE);
                    results.rst_rate_limited = true;
                }
            }
        }

        // Deduplicate results
        results.open_ports.sort_unstable();
        results.open_ports.dedup();
        results.closed_ports.sort_unstable();
        results.closed_ports.dedup();
        results.filtered_ports.sort_unstable();
        results.filtered_ports.dedup();

        Ok(results)
    }

    /// Execute a single scan pass
    async fn scan_pass(
        &self,
        port_states: &mut HashMap<u16, PortState>,
        min_connections: usize,
        max_connections: usize,
    ) -> Result<ScanResults> {
        let mut results = ScanResults::default();
        results.rtt_stats = [RttStats::new(), RttStats::new(), RttStats::new()];

        // Create semaphore to limit concurrent connections
        let semaphore = Arc::new(Semaphore::new(max_connections));
        let mut tasks = Vec::new();

        // Scan all ports that need testing
        for (&port, &state) in port_states.iter() {
            if state == PortState::Unknown || state == PortState::Silent {
                let sem = semaphore.clone();
                let target = self.config.target_ip;
                let read_timeout = self.config.read_timeout;

                let task = tokio::spawn(async move {
                    let _permit = sem.acquire().await.ok();
                    Self::scan_port(target, port, read_timeout).await
                });

                tasks.push((port, task));
            }
        }

        for (port, task) in tasks {
            match task.await {
                Ok(port_result) => match port_result.state {
                    PortState::Open => {
                        results.open_ports.push(port);
                        port_states.insert(port, PortState::Open);

                        if let Some(banner) = port_result.banner {
                            results.banners.insert(port, banner);
                        }
                        if let Some(conn_time) = port_result.connection_time {
                            results.connection_times.insert(port, conn_time);
                            if conn_time < MAX_SANE_RTT {
                                results.rtt_stats[0].add(conn_time);
                                results.rtt_stats[1].add(conn_time);
                            }
                        }
                        if let Some(read_time) = port_result.read_time {
                            results.banner_read_times.insert(port, read_time);
                        }
                    }
                    PortState::Closed => {
                        results.closed_ports.push(port);
                        port_states.insert(port, PortState::Closed);

                        if let Some(conn_time) = port_result.connection_time {
                            if conn_time < MAX_SANE_RTT {
                                results.rtt_stats[0].add(conn_time);
                                results.rtt_stats[2].add(conn_time);
                            }
                        }
                    }
                    PortState::Silent => {
                        results.filtered_ports.push(port);
                    }
                    PortState::Rejected => {
                        results.filtered_ports.push(port);
                        port_states.insert(port, PortState::Rejected);
                    }
                    _ => {}
                },
                Err(e) => {
                    warn!("Task error for port {}: {}", port, e);
                }
            }
        }

        // Detect RST rate limiting (BSD-like systems)
        if results.closed_ports.len() > min_connections
            && results.open_ports.is_empty()
            && results.closed_ports.len() < 200
        {
            results.rst_rate_limited = true;
        }

        Ok(results)
    }

    /// Scan a single port
    async fn scan_port(target: IpAddr, port: u16, read_timeout: Duration) -> PortResult {
        let addr = SocketAddr::new(target, port);
        let start = Instant::now();

        // Attempt connection with timeout
        let stream = match timeout(read_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => {
                // Connection refused = closed port
                return PortResult {
                    state: PortState::Closed,
                    connection_time: Some(start.elapsed()),
                    banner: None,
                    read_time: None,
                };
            }
            Err(_) => {
                // Timeout = filtered/silent
                return PortResult {
                    state: PortState::Silent,
                    connection_time: None,
                    banner: None,
                    read_time: None,
                };
            }
        };

        let connection_time = start.elapsed();

        // Try to grab banner
        let (banner, read_time) = Self::grab_banner(stream, read_timeout).await;

        PortResult {
            state: PortState::Open,
            connection_time: Some(connection_time),
            banner,
            read_time,
        }
    }

    /// Attempt to read banner from open port
    async fn grab_banner(
        mut stream: TcpStream,
        read_timeout: Duration,
    ) -> (Option<Vec<u8>>, Option<Duration>) {
        let start = Instant::now();
        let mut buffer = vec![0u8; 2048];

        match timeout(read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                (Some(buffer), Some(start.elapsed()))
            }
            _ => (None, None),
        }
    }
}

/// Result of scanning a single port
#[derive(Debug)]
struct PortResult {
    state: PortState,
    connection_time: Option<Duration>,
    banner: Option<Vec<u8>>,
    read_time: Option<Duration>,
}

fn set_rtt_stats(context: &ScanCtx<'_>, stat: &RttStats, rtt_type: &str) -> Result<(), FnError> {
    if stat.count == 0 {
        return Ok(());
    }

    // Unwrapping the mean is safe here since count > 0
    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::MeanRTT(rtt_type.to_string())),
        KbItem::String(format!("{:.6}", stat.mean().unwrap().as_secs_f64())),
    )?;
    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::MeanRTT1000(rtt_type.to_string())),
        KbItem::Number(stat.mean().unwrap().as_millis() as i64),
    )?;

    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::MaxRTT(rtt_type.to_string())),
        KbItem::String(format!("{:.6}", stat.max.as_secs_f64())),
    )?;
    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::MaxRTT1000(rtt_type.to_string())),
        KbItem::Number(stat.max.as_millis() as i64),
    )?;

    if stat.count == 1 {
        return Ok(());
    }

    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::SDRTT(rtt_type.to_string())),
        KbItem::String(format!("{:.6}", stat.std_dev().unwrap())),
    )?;
    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::SDRTT1000(rtt_type.to_string())),
        KbItem::Number((stat.std_dev().unwrap() * 1000.0) as i64),
    )?;

    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::EstimatedMaxRTT(rtt_type.to_string())),
        KbItem::String(format!(
            "{:.6}",
            stat.estimated_max().unwrap().as_secs_f64()
        )),
    )?;
    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::EstimatedMaxRTT1000(rtt_type.to_string())),
        KbItem::Number(stat.estimated_max().unwrap().as_millis() as i64),
    )?;

    Ok(())
}

#[nasl_function]
async fn plugin_run_openvas_tcp_scanner(context: &ScanCtx<'_>) -> Result<(), FnError> {
    let target_ip = context.target().ip_addr();
    let port_range = context.target().ports_tcp().iter().cloned().collect();

    let mut params = context.scan_params();

    let safe_checks = params
        .find(|x| x.id == "safe_checks")
        .map(|x| x.value == "yes")
        .unwrap_or(false);

    // Calculate optimal resource limits
    let (min_cnx, max_cnx) = TcpScanner::calculate_resource_limits(
        params
            .find(|x| x.id == "max_hosts")
            .map(|x| x.value.parse::<usize>().unwrap_or(15))
            .map(|x| if x == 0 { 15 } else { x })
            .unwrap_or(15),
        params
            .find(|x| x.id == "max_checks")
            .map(|x| x.value.parse::<usize>().unwrap_or(5))
            .map(|x| if x == 0 || x > 5 { 5 } else { x })
            .unwrap_or(5),
        safe_checks,
    );

    // Create scanner configuration
    let config = ScannerConfig {
        target_ip,
        port_range,
        read_timeout: Duration::from_secs(5),
        min_connections: min_cnx,
        max_connections: max_cnx,
        safe_checks,
    };

    // Create and run scanner
    let scanner = TcpScanner::new(config);
    let results = scanner.scan().await.unwrap();

    // Store results in context
    context.set_kb_item(KbKey::Host(Host::Tcp), KbItem::Boolean(true))?;
    context.set_kb_item(KbKey::Host(Host::TcpScanned), KbItem::Boolean(true))?;
    for (port, time) in &results.connection_times {
        context.set_kb_item(
            KbKey::TcpScanner(kb::TcpScanner::CnxTime(*port)),
            KbItem::Number(time.as_secs() as i64),
        )?;
        context.set_kb_item(
            KbKey::TcpScanner(kb::TcpScanner::CnxTime1000(*port)),
            KbItem::Number(time.as_millis() as i64),
        )?;
    }
    for (port, time) in &results.banner_read_times {
        context.set_kb_item(
            KbKey::TcpScanner(kb::TcpScanner::RwTime(*port)),
            KbItem::Number(time.as_secs() as i64),
        )?;
        context.set_kb_item(
            KbKey::TcpScanner(kb::TcpScanner::RwTime1000(*port)),
            KbItem::Number(time.as_millis() as i64),
        )?;
    }

    for port in &results.open_ports {
        if let Some(banner) = results.banners.get(port) {
            // No need for BannerHex in rust anymore, as it was only needed, if the Banner contained
            // a \0, which ends a string in c. But in rust a \0 is just ignored in a String.
            // context.set_kb_item(KbKey::BannerHex(*port), KbItem::String(hex::encode(banner)))?;
            context.set_kb_item(
                KbKey::Banner(*port),
                KbItem::String(String::from_utf8_lossy(banner).to_string()),
            )?;
        } else {
            context.set_kb_item(KbKey::TmpNoBanner(*port), KbItem::Boolean(true))?;
        }
    }

    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::NbPasses),
        KbItem::Number(results.passes as i64),
    )?;

    set_rtt_stats(context, &results.rtt_stats[0], "unfiltered")?;
    set_rtt_stats(context, &results.rtt_stats[1], "open")?;
    set_rtt_stats(context, &results.rtt_stats[2], "closed")?;

    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::OpenPortsNb),
        KbItem::Number(results.open_ports.len() as i64),
    )?;
    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::ClosedPortsNb),
        KbItem::Number(results.closed_ports.len() as i64),
    )?;
    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::FilteredPortsNb),
        KbItem::Number(results.filtered_ports.len() as i64),
    )?;

    context.set_kb_item(
        KbKey::TcpScanner(kb::TcpScanner::RSTRateLimit),
        KbItem::Boolean(results.rst_rate_limited),
    )?;

    context.set_kb_item(KbKey::Host(Host::FullScan), KbItem::Boolean(true))?;
    context.set_kb_item(
        KbKey::Host(Host::NumPortsScanned),
        KbItem::Number(
            (results.open_ports.len() + results.closed_ports.len() + results.filtered_ports.len())
                as i64,
        ),
    )?;

    Ok(())
}

pub struct TcpScan;

function_set! {
    TcpScan,
    (plugin_run_openvas_tcp_scanner)
}
