// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Prometheus metrics for openvasd.
//!
//! A single process-wide [`ScannerMetrics`] instance is exposed via [`scanner_metrics`]
//! so that instrumentation sites across the server (HTTP entry point, scan scheduling,
//! VT execution, feed orchestration, database) all update the same collectors.
//!
//! The metrics are rendered in Prometheus text format by [`ScannerMetrics::render`],
//! which is consumed by the `GET /metrics` handler.
//!
//! # Metric catalog
//!
//! | Metric | Type | Labels | Description |
//! |---|---|---|---|
//! | `openvasd_scans_started_total` | counter | — | Total scans started |
//! | `openvasd_scans_completed_total` | counter | `status` | Scans reached a terminal state |
//! | `openvasd_scans_active` | gauge | — | Currently running scans |
//! | `openvasd_vt_executions_total` | counter | `result` | VT executions by outcome |
//! | `openvasd_vt_execution_seconds` | histogram | `stage` | VT execution duration |
//! | `openvasd_feed_state` | gauge | `type` | 0=unknown, 1=syncing, 2=synced |
//! | `openvasd_feed_last_sync_timestamp` | gauge | — | Unix seconds of last successful sync |
//! | `openvasd_results_total` | counter | `type` | Results emitted by type |
//! | `openvasd_db_active_connections` | gauge | — | Active DB connections |
//! | `openvasd_db_query_seconds` | histogram | `op` | DB query duration |
//! | `openvasd_http_requests_total` | counter | `method`, `status` | HTTP requests handled |
//! | `openvasd_http_request_seconds` | histogram | `method` | HTTP request duration |
//! | `openvasd_http_active` | gauge | — | In-flight HTTP requests |

use std::sync::{Arc, OnceLock};

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder, core::Collector,
};

/// Feed state gauge values used for `openvasd_feed_state`.
pub const FEED_STATE_UNKNOWN: i64 = 0;
pub const FEED_STATE_SYNCING: i64 = 1;
pub const FEED_STATE_SYNCED: i64 = 2;

/// Central collection of openvasd Prometheus collectors.
///
/// All collectors are registered with a single [`Registry`] and rendered together
/// via [`ScannerMetrics::render`]. The struct is cheaply cloneable (`Arc`) and
/// safe to share across async tasks; the underlying counters/gauges use atomics
/// and do not require async-aware locking.
#[derive(Clone)]
pub struct ScannerMetrics {
    registry: Arc<Registry>,

    // Scan lifecycle
    scans_started: IntCounterVec,
    scans_completed: IntCounterVec,
    scans_active: IntGauge,

    // VT execution
    vt_executions: IntCounterVec,
    vt_duration: HistogramVec,

    // Feed
    feed_state: IntGaugeVec,
    feed_last_sync: IntGauge,

    // Results emitted
    results_total: IntCounterVec,

    // DB
    db_active_connections: IntGauge,
    db_query_duration: HistogramVec,

    // HTTP
    http_requests: IntCounterVec,
    http_request_duration: HistogramVec,
    http_active: IntGauge,
}

impl ScannerMetrics {
    /// Creates a new metrics set and registers all collectors.
    ///
    /// Each call produces an independent registry; in production a single shared
    /// instance should be obtained via [`scanner_metrics`].
    pub fn new() -> Self {
        let registry = Registry::new();

        let scans_started = IntCounterVec::new(
            Opts::new("openvasd_scans_started_total", "Total scans started"),
            &[],
        )
        .expect("valid counter opts");
        let scans_completed = IntCounterVec::new(
            Opts::new(
                "openvasd_scans_completed_total",
                "Scans that reached a terminal state",
            ),
            &["status"],
        )
        .expect("valid counter opts");
        let scans_active = IntGauge::new("openvasd_scans_active", "Currently running scans")
            .expect("valid gauge opts");

        let vt_executions = IntCounterVec::new(
            Opts::new("openvasd_vt_executions_total", "VT executions by outcome"),
            &["result"],
        )
        .expect("valid counter opts");
        let vt_duration = HistogramVec::new(
            HistogramOpts::new(
                "openvasd_vt_execution_seconds",
                "VT execution duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0,
            ]),
            &["stage"],
        )
        .expect("valid histogram opts");

        let feed_state = IntGaugeVec::new(
            Opts::new(
                "openvasd_feed_state",
                "Feed state: 0=unknown, 1=syncing, 2=synced",
            ),
            &["type"],
        )
        .expect("valid gauge opts");
        let feed_last_sync = IntGauge::new(
            "openvasd_feed_last_sync_timestamp",
            "Unix timestamp of last successful feed sync (0 when never synced)",
        )
        .expect("valid gauge opts");

        let results_total = IntCounterVec::new(
            Opts::new("openvasd_results_total", "Results emitted by type"),
            &["type"],
        )
        .expect("valid counter opts");

        let db_active_connections = IntGauge::new(
            "openvasd_db_active_connections",
            "Active database connections",
        )
        .expect("valid gauge opts");
        let db_query_duration = HistogramVec::new(
            HistogramOpts::new(
                "openvasd_db_query_seconds",
                "Database query duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["op"],
        )
        .expect("valid histogram opts");

        let http_requests = IntCounterVec::new(
            Opts::new("openvasd_http_requests_total", "HTTP requests handled"),
            &["method", "status"],
        )
        .expect("valid counter opts");
        let http_request_duration = HistogramVec::new(
            HistogramOpts::new(
                "openvasd_http_request_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![
                0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0,
            ]),
            &["method"],
        )
        .expect("valid histogram opts");
        let http_active =
            IntGauge::new("openvasd_http_active", "In-flight HTTP requests").expect("valid gauge opts");

        let collectors: Vec<Box<dyn Collector>> = vec![
            Box::new(scans_started.clone()),
            Box::new(scans_completed.clone()),
            Box::new(scans_active.clone()),
            Box::new(vt_executions.clone()),
            Box::new(vt_duration.clone()),
            Box::new(feed_state.clone()),
            Box::new(feed_last_sync.clone()),
            Box::new(results_total.clone()),
            Box::new(db_active_connections.clone()),
            Box::new(db_query_duration.clone()),
            Box::new(http_requests.clone()),
            Box::new(http_request_duration.clone()),
            Box::new(http_active.clone()),
        ];
        for c in collectors {
            registry
                .register(c)
                .expect("collector registration must not conflict");
        }

        Self {
            registry: Arc::new(registry),
            scans_started,
            scans_completed,
            scans_active,
            vt_executions,
            vt_duration,
            feed_state,
            feed_last_sync,
            results_total,
            db_active_connections,
            db_query_duration,
            http_requests,
            http_request_duration,
            http_active,
        }
    }

    /// Renders all registered metrics in Prometheus text format.
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        match encoder.encode(&self.registry.gather(), &mut buf) {
            Ok(()) => String::from_utf8(buf).unwrap_or_default(),
            Err(e) => {
                tracing::warn!(error = %e, "failed to encode metrics");
                String::new()
            }
        }
    }

    // --- Scan lifecycle ---------------------------------------------------

    /// Record that a scan has been started.
    pub fn record_scan_start(&self) {
        self.scans_started.with_label_values(&[]).inc();
        self.scans_active.inc();
    }

    /// Record that a scan reached a terminal state.
    ///
    /// `status` should be one of: `running` (should not be used here), `stopped`,
    /// `failed`, `succeeded`.
    pub fn record_scan_end(&self, status: &str) {
        self.scans_completed.with_label_values(&[status]).inc();
        self.scans_active.dec();
    }

    // --- VT execution -----------------------------------------------------

    /// Record the outcome of a single VT execution.
    ///
    /// `result` should be `ok`, `error`, or `timeout`. `stage` is the scheduling
    /// stage name (e.g. `discovery`, `non_evasive`, `exhausting`, `end`).
    pub fn record_vt_execution(&self, stage: &str, result: &str, duration_secs: f64) {
        self.vt_executions.with_label_values(&[result]).inc();
        self.vt_duration
            .with_label_values(&[stage])
            .observe(duration_secs);
    }

    // --- Feed -------------------------------------------------------------

    /// Set the feed state gauge for a given feed type (`nasl` or `advisories`).
    pub fn set_feed_state(&self, feed_type: &str, value: i64) {
        self.feed_state.with_label_values(&[feed_type]).set(value);
    }

    /// Record the timestamp of the last successful feed sync (unix seconds).
    pub fn set_feed_last_sync(&self, timestamp_secs: i64) {
        self.feed_last_sync.set(timestamp_secs);
    }

    // --- Results ----------------------------------------------------------

    /// Record a result emitted by the scanner (`alarm`, `log`, `error`,
    /// `host_detail`, ...).
    pub fn record_result(&self, kind: &str) {
        self.results_total.with_label_values(&[kind]).inc();
    }

    // --- DB ---------------------------------------------------------------

    /// Increment the active DB connection gauge. Call on connection acquire.
    pub fn db_connection_acquired(&self) {
        self.db_active_connections.inc();
    }

    /// Decrement the active DB connection gauge. Call on connection release.
    pub fn db_connection_released(&self) {
        self.db_active_connections.dec();
    }

    /// Observe a database query duration for a given operation label.
    pub fn record_db_query(&self, op: &str, duration_secs: f64) {
        self.db_query_duration
            .with_label_values(&[op])
            .observe(duration_secs);
    }

    // --- HTTP -------------------------------------------------------------

    /// Increment the in-flight HTTP request gauge.
    pub fn http_request_started(&self) {
        self.http_active.inc();
    }

    /// Decrement the in-flight HTTP request gauge.
    pub fn http_request_finished(&self) {
        self.http_active.dec();
    }

    /// Record a completed HTTP request.
    pub fn record_http_request(&self, method: &str, status: &str, duration_secs: f64) {
        self.http_requests
            .with_label_values(&[method, status])
            .inc();
        self.http_request_duration
            .with_label_values(&[method])
            .observe(duration_secs);
    }
}

impl Default for ScannerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

static SCANNER_METRICS: OnceLock<ScannerMetrics> = OnceLock::new();

/// Returns the process-wide [`ScannerMetrics`] instance, initializing it on first
/// access. All instrumentation sites should call this to obtain the shared metrics
/// set so that the `/metrics` endpoint reports consistent values.
pub fn scanner_metrics() -> &'static ScannerMetrics {
    SCANNER_METRICS.get_or_init(ScannerMetrics::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_contains_catalog_metrics() {
        let metrics = ScannerMetrics::new();
        let rendered = metrics.render();
        assert!(rendered.contains("openvasd_scans_active"));
        assert!(rendered.contains("openvasd_vt_executions_total"));
        assert!(rendered.contains("openvasd_feed_state"));
        assert!(rendered.contains("openvasd_http_requests_total"));
    }

    #[test]
    fn scan_lifecycle_counters_update() {
        let metrics = ScannerMetrics::new();
        metrics.record_scan_start();
        metrics.record_scan_start();
        metrics.record_scan_end("succeeded");
        let rendered = metrics.render();
        // started_total increments by 2
        assert!(rendered.contains("openvasd_scans_started_total 2"));
        // active goes 2 - 1 = 1
        assert!(rendered.contains("openvasd_scans_active 1"));
        // completed{status="succeeded"} == 1
        assert!(rendered.contains(r#"openvasd_scans_completed_total{status="succeeded"} 1"#));
    }

    #[test]
    fn feed_state_gauge_reflects_value() {
        let metrics = ScannerMetrics::new();
        metrics.set_feed_state("nasl", FEED_STATE_SYNCED);
        metrics.set_feed_state("advisories", FEED_STATE_SYNCING);
        let rendered = metrics.render();
        assert!(rendered.contains(r#"openvasd_feed_state{type="nasl"} 2"#));
        assert!(rendered.contains(r#"openvasd_feed_state{type="advisories"} 1"#));
    }

    #[test]
    fn http_metrics_record_labels() {
        let metrics = ScannerMetrics::new();
        metrics.record_http_request("GET", "200", 0.01);
        let rendered = metrics.render();
        assert!(rendered.contains(r#"openvasd_http_requests_total{method="GET",status="200"} 1"#));
    }

    #[test]
    fn scanner_metrics_singleton_is_stable() {
        let a = scanner_metrics() as *const _;
        let b = scanner_metrics() as *const _;
        assert_eq!(a, b, "scanner_metrics must return the same instance");
    }
}
