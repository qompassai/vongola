// #################################################################
// /qompassai/vongola/crates/vongola/src/metrics.rs
// Qompass AI — Vongola clean-room metrics
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// #################################################################

//! Prometheus registry, populated from the first request.
//!
//! The previous tree's named defect was an endpoint serving an
//! empty registry. Here every series is emitted unconditionally
//! (counters start at 0, gauges reflect live state), and the smoke
//! suite asserts the request counters actually move.
//!
//! Label cardinality is bounded by construction. Fixed families
//! (status class, TLS group, handshake failure class, log level
//! and source) are arrays indexed by closed enums. Keyed families
//! (route, upstream) take their keys from the configuration only,
//! and each is capped at `MAX_KEYED_SERIES` keys: a key past the
//! cap is folded into `OVERFLOW_KEY`. No family is ever labelled
//! with a client identifier, a client address, or a client-sent
//! SNI.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Handshake failure classes, by the last handshake stage the
/// connection reached (see `HandshakeGuard`). Alphabetical; the
/// order is the `HandshakeFailure` index order.
pub const HANDSHAKE_FAILURE_CLASSES: [&str; 3] =
    ["after_certificate", "before_certificate", "no_certificate"];
/// Histogram bucket upper bounds in milliseconds (`+Inf` implied).
pub const LATENCY_BUCKETS_MS: [u64; 11] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
/// Log levels, alphabetical; index order of `LOG_LINES` rows.
pub const LOG_LEVELS: [&str; 5] = ["debug", "error", "info", "trace", "warn"];
/// Log sources (by record target prefix), alphabetical; index
/// order of `LOG_LINES` columns.
pub const LOG_SOURCES: [&str; 3] = ["other", "pingora", "vongola"];
/// Most distinct keys any keyed family holds before folding.
pub const MAX_KEYED_SERIES: usize = 256;
/// The key that absorbs every key past `MAX_KEYED_SERIES`.
pub const OVERFLOW_KEY: &str = "overflow";
/// Status classes, index order of the request counters.
pub const STATUS_CLASSES: [&str; 4] = ["2xx", "3xx", "4xx", "5xx"];
/// Negotiated TLS group labels (ASCII order). Every name except
/// `unknown` is on the config allowlist (`config::HYBRID_GROUPS`
/// and `config::CLASSICAL_GROUPS`; a test pins the two together).
pub const TLS_GROUPS: [&str; 6] = [
    "SecP384r1MLKEM1024",
    "X25519",
    "X25519MLKEM768",
    "secp256r1",
    "secp384r1",
    "unknown",
];

/// Process-wide dropped-log-line counter, shared with the
/// bounded logger in main.rs (the logger exists before State).
pub static DROPPED_LOG_LINES: AtomicU64 = AtomicU64::new(0);
/// Emitted log lines by [level][source]; the logger exists
/// before State, so this is process-wide like the drop counter.
pub static LOG_LINES: [[AtomicU64; LOG_SOURCES.len()]; LOG_LEVELS.len()] =
    [const { [const { AtomicU64::new(0) }; LOG_SOURCES.len()] }; LOG_LEVELS.len()];

pub fn dropped_log_lines() -> u64 { DROPPED_LOG_LINES.load(Ordering::Relaxed) }

/// Count one emitted log line. The target only selects one of
/// three fixed sources; it never becomes a label value.
pub fn record_log_line(level: log::Level, target: &str) {
    let row = match level {
        log::Level::Debug => 0,
        log::Level::Error => 1,
        log::Level::Info => 2,
        log::Level::Trace => 3,
        log::Level::Warn => 4,
    };
    let column = if target.starts_with("vongola") {
        2
    } else if target.starts_with("pingora") {
        1
    } else {
        0
    };
    LOG_LINES[row][column].fetch_add(1, Ordering::Relaxed);
}

// The shared suffix is the point: each variant names the stage
// relative to certificate selection, matching its metric label.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HandshakeFailure {
    AfterCertificate,
    BeforeCertificate,
    NoCertificate,
}

impl HandshakeFailure {
    fn index(self) -> usize {
        match self {
            HandshakeFailure::AfterCertificate => 0,
            HandshakeFailure::BeforeCertificate => 1,
            HandshakeFailure::NoCertificate => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TlsGroup {
    SecP384r1MlKem1024,
    Secp256r1,
    Secp384r1,
    Unknown,
    X25519,
    X25519MlKem768,
}

impl TlsGroup {
    /// Every group, in `TLS_GROUPS` order.
    pub const ALL: [TlsGroup; TLS_GROUPS.len()] = [
        TlsGroup::SecP384r1MlKem1024,
        TlsGroup::X25519,
        TlsGroup::X25519MlKem768,
        TlsGroup::Secp256r1,
        TlsGroup::Secp384r1,
        TlsGroup::Unknown,
    ];

    fn index(self) -> usize {
        match self {
            TlsGroup::SecP384r1MlKem1024 => 0,
            TlsGroup::X25519 => 1,
            TlsGroup::X25519MlKem768 => 2,
            TlsGroup::Secp256r1 => 3,
            TlsGroup::Secp384r1 => 4,
            TlsGroup::Unknown => 5,
        }
    }

    pub fn is_classical(self) -> bool {
        matches!(
            self,
            TlsGroup::Secp256r1 | TlsGroup::Secp384r1 | TlsGroup::X25519
        )
    }

    pub fn label(self) -> &'static str { TLS_GROUPS[self.index()] }
}

/// A Prometheus histogram over `LATENCY_BUCKETS_MS`. Buckets are
/// stored per-bucket and made cumulative at render time.
#[derive(Default)]
pub struct Histogram {
    buckets: [AtomicU64; LATENCY_BUCKETS_MS.len()],
    count: AtomicU64,
    sum_ms: AtomicU64,
}

impl Histogram {
    pub fn observe(&self, latency_ms: u64) {
        if let Some(index) = LATENCY_BUCKETS_MS
            .iter()
            .position(|bound| latency_ms <= *bound)
        {
            self.buckets[index].fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ms.fetch_add(latency_ms, Ordering::Relaxed);
    }

    /// Append `_bucket`/`_sum`/`_count` lines; `labels` is either
    /// empty or a rendered `key="value"` list without braces.
    fn render(&self, out: &mut String, name: &str, labels: &str) {
        let separator = if labels.is_empty() { "" } else { "," };
        let mut cumulative: u64 = 0;
        for (index, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            cumulative += self.buckets[index].load(Ordering::Relaxed);
            out.push_str(&format!(
                "{name}_bucket{{{labels}{separator}le=\"{bound}\"}} {cumulative}\n"
            ));
        }
        let count = self.count.load(Ordering::Relaxed);
        out.push_str(&format!(
            "{name}_bucket{{{labels}{separator}le=\"+Inf\"}} {count}\n"
        ));
        let braces = if labels.is_empty() {
            String::new()
        } else {
            format!("{{{labels}}}")
        };
        out.push_str(&format!(
            "{name}_sum{braces} {}\n{name}_count{braces} {count}\n",
            self.sum_ms.load(Ordering::Relaxed)
        ));
    }
}

/// TLS handshake accounting: completed handshakes by negotiated
/// group and failed handshakes by class. Shared (Arc) with the
/// TLS callbacks, which outlive no one but run off the State.
#[derive(Default)]
pub struct TlsCounters {
    failures: [AtomicU64; HANDSHAKE_FAILURE_CLASSES.len()],
    handshakes: [AtomicU64; TLS_GROUPS.len()],
}

impl TlsCounters {
    pub fn classical_fallbacks(&self) -> u64 {
        TlsGroup::ALL
            .iter()
            .filter(|group| group.is_classical())
            .map(|group| self.handshakes[group.index()].load(Ordering::Relaxed))
            .sum()
    }

    pub fn record_failure(&self, class: HandshakeFailure) {
        self.failures[class.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_handshake(&self, group: TlsGroup) {
        self.handshakes[group.index()].fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, out: &mut String) {
        out.push_str("# HELP vongola_tls_handshakes_total Completed TLS handshakes by negotiated group.\n# TYPE vongola_tls_handshakes_total counter\n");
        for group in TlsGroup::ALL {
            out.push_str(&format!(
                "vongola_tls_handshakes_total{{group=\"{}\"}} {}\n",
                group.label(),
                self.handshakes[group.index()].load(Ordering::Relaxed)
            ));
        }
        out.push_str(&format!(
            "# HELP vongola_tls_classical_fallback_total Completed handshakes that negotiated a classical (non-hybrid) group.\n# TYPE vongola_tls_classical_fallback_total counter\nvongola_tls_classical_fallback_total {}\n",
            self.classical_fallbacks()
        ));
        out.push_str("# HELP vongola_tls_handshake_failures_total Failed TLS handshakes by last stage reached.\n# TYPE vongola_tls_handshake_failures_total counter\n");
        for (index, class) in HANDSHAKE_FAILURE_CLASSES.iter().enumerate() {
            out.push_str(&format!(
                "vongola_tls_handshake_failures_total{{class=\"{class}\"}} {}\n",
                self.failures[index].load(Ordering::Relaxed)
            ));
        }
    }
}

const STAGE_CERTIFICATE: u8 = 1;
const STAGE_CLIENT_HELLO: u8 = 0;
const STAGE_COMPLETE: u8 = 3;
const STAGE_NO_CERTIFICATE: u8 = 2;

/// Per-connection handshake tracker. It is attached to the SSL
/// object at the first ClientHello and dropped when OpenSSL frees
/// that object. A guard dropped before `complete` counts one
/// failure, classed by the furthest stage it reached; `complete`
/// counts the success exactly once. Connections that never send a
/// ClientHello (plain TCP probes) carry no guard and are not
/// counted.
pub struct HandshakeGuard {
    counters: Arc<TlsCounters>,
    stage: AtomicU8,
}

impl HandshakeGuard {
    pub fn new(counters: Arc<TlsCounters>) -> HandshakeGuard {
        HandshakeGuard {
            counters,
            stage: AtomicU8::new(STAGE_CLIENT_HELLO),
        }
    }

    pub fn certificate_selected(&self) { self.advance(STAGE_CERTIFICATE); }

    pub fn complete(&self, group: TlsGroup) {
        if self.stage.swap(STAGE_COMPLETE, Ordering::AcqRel) != STAGE_COMPLETE {
            self.counters.record_handshake(group);
        }
    }

    pub fn no_certificate(&self) { self.advance(STAGE_NO_CERTIFICATE); }

    /// Move to `stage` unless the handshake already completed.
    fn advance(&self, stage: u8) {
        let mut current = self.stage.load(Ordering::Acquire);
        while current != STAGE_COMPLETE {
            match self.stage.compare_exchange_weak(
                current,
                stage,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        let class = match self.stage.load(Ordering::Acquire) {
            STAGE_CERTIFICATE => HandshakeFailure::AfterCertificate,
            STAGE_CLIENT_HELLO => HandshakeFailure::BeforeCertificate,
            STAGE_NO_CERTIFICATE => HandshakeFailure::NoCertificate,
            _ => return,
        };
        self.counters.record_failure(class);
    }
}

#[derive(Default)]
pub struct Metrics {
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub chain_failures: AtomicU64,
    pub request_latency: Histogram,
    pub requests: [AtomicU64; STATUS_CLASSES.len()],
    /// Requests by route: route -> counts in `STATUS_CLASSES` order.
    pub route_requests: Mutex<BTreeMap<String, [u64; STATUS_CLASSES.len()]>>,
    pub tls: Arc<TlsCounters>,
    pub upstream_checks_failed: AtomicU64,
    pub upstream_checks_ok: AtomicU64,
    /// Time to upstream response header, by "route/address".
    pub upstream_latency: Mutex<BTreeMap<String, Histogram>>,
}

impl Metrics {
    pub fn new() -> Self { Metrics::default() }

    pub fn record_request(&self, route: &str, status: u16, latency_ms: u64) {
        let class = status_class_index(status);
        self.requests[class].fetch_add(1, Ordering::Relaxed);
        self.request_latency.observe(latency_ms);
        if let Ok(mut map) = self.route_requests.lock() {
            let key = capped_key(&map, route).to_string();
            map.entry(key).or_default()[class] += 1;
        }
    }

    pub fn record_upstream_latency(&self, upstream: &str, latency_ms: u64) {
        if let Ok(mut map) = self.upstream_latency.lock() {
            let key = capped_key(&map, upstream).to_string();
            map.entry(key).or_default().observe(latency_ms);
        }
    }

    pub fn total_requests(&self) -> u64 {
        self.requests
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .sum()
    }

    /// Render Prometheus text. `extra_gauges` carries live state
    /// (upstream health, cert expiry, NAT/Tor status) as
    /// (name, labels, value) triples, sorted by the caller.
    pub fn render(&self, extra_gauges: &[(String, String, f64)]) -> String {
        let mut out = String::with_capacity(8192);
        out.push_str(
            "# HELP vongola_up Whether the node is up.\n# TYPE vongola_up gauge\nvongola_up 1\n",
        );
        out.push_str("# HELP vongola_requests_total Requests by status class.\n# TYPE vongola_requests_total counter\n");
        for (index, class) in STATUS_CLASSES.iter().enumerate() {
            out.push_str(&format!(
                "vongola_requests_total{{status_class=\"{class}\"}} {}\n",
                self.requests[index].load(Ordering::Relaxed)
            ));
        }
        out.push_str("# HELP vongola_route_requests_total Requests by route and status class.\n# TYPE vongola_route_requests_total counter\n");
        if let Ok(map) = self.route_requests.lock() {
            for (route, counts) in map.iter() {
                for (index, class) in STATUS_CLASSES.iter().enumerate() {
                    out.push_str(&format!(
                        "vongola_route_requests_total{{route=\"{}\",status_class=\"{class}\"}} {}\n",
                        escape_label(route),
                        counts[index]
                    ));
                }
            }
        }
        out.push_str("# HELP vongola_request_latency_ms Request latency in milliseconds.\n# TYPE vongola_request_latency_ms histogram\n");
        self.request_latency
            .render(&mut out, "vongola_request_latency_ms", "");
        out.push_str("# HELP vongola_upstream_latency_ms Time to upstream response header in milliseconds, by route/address.\n# TYPE vongola_upstream_latency_ms histogram\n");
        if let Ok(map) = self.upstream_latency.lock() {
            for (upstream, histogram) in map.iter() {
                histogram.render(
                    &mut out,
                    "vongola_upstream_latency_ms",
                    &format!("upstream=\"{}\"", escape_label(upstream)),
                );
            }
        }
        out.push_str(&format!(
            "# HELP vongola_cache_hits_total Static cache hits.\n# TYPE vongola_cache_hits_total counter\nvongola_cache_hits_total {}\n",
            self.cache_hits.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "# HELP vongola_cache_misses_total Static cache misses.\n# TYPE vongola_cache_misses_total counter\nvongola_cache_misses_total {}\n",
            self.cache_misses.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "# HELP vongola_chain_failures_total Chain dial failures (fail-closed 502s).\n# TYPE vongola_chain_failures_total counter\nvongola_chain_failures_total {}\n",
            self.chain_failures.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "# HELP vongola_dropped_log_lines_total Log lines dropped by the bounded pipeline.\n# TYPE vongola_dropped_log_lines_total counter\nvongola_dropped_log_lines_total {}\n",
            dropped_log_lines()
        ));
        out.push_str("# HELP vongola_log_lines_total Log lines emitted, by level and source.\n# TYPE vongola_log_lines_total counter\n");
        for (row, level) in LOG_LEVELS.iter().enumerate() {
            for (column, source) in LOG_SOURCES.iter().enumerate() {
                out.push_str(&format!(
                    "vongola_log_lines_total{{level=\"{level}\",source=\"{source}\"}} {}\n",
                    LOG_LINES[row][column].load(Ordering::Relaxed)
                ));
            }
        }
        self.tls.render(&mut out);
        out.push_str(&format!(
            "# HELP vongola_upstream_health_checks_total Health check outcomes.\n# TYPE vongola_upstream_health_checks_total counter\nvongola_upstream_health_checks_total{{result=\"ok\"}} {}\nvongola_upstream_health_checks_total{{result=\"failed\"}} {}\n",
            self.upstream_checks_ok.load(Ordering::Relaxed),
            self.upstream_checks_failed.load(Ordering::Relaxed)
        ));
        #[cfg(feature = "ech")]
        {
            // Accepted ECH handshakes, counted exactly by the
            // binding crate's status callback. Deliberately no
            // "rejected" series: server-side, a rejected
            // attempt is indistinguishable from GREASE by
            // protocol design (see the vongola-ech status
            // module docs).
            let counters = vongola_ech::status_counters();
            out.push_str(&format!(
                "# HELP vongola_ech_handshakes_total ECH handshakes accepted (OpenSSL 4 variant builds).\n# TYPE vongola_ech_handshakes_total counter\nvongola_ech_handshakes_total{{result=\"accepted\"}} {}\n",
                counters.accepted
            ));
        }
        for (name, labels, value) in extra_gauges {
            out.push_str(&format!("{name}{{{labels}}} {value}\n"));
        }
        out
    }
}

/// `key` itself while the family has room (or already holds it),
/// otherwise `OVERFLOW_KEY`. A family therefore never exceeds
/// `MAX_KEYED_SERIES + 1` keys.
fn capped_key<'a, V>(map: &BTreeMap<String, V>, key: &'a str) -> &'a str {
    if map.contains_key(key) || map.len() < MAX_KEYED_SERIES {
        key
    } else {
        OVERFLOW_KEY
    }
}

pub fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn status_class_index(status: u16) -> usize {
    match status {
        200..=299 => 0,
        300..=399 => 1,
        400..=499 => 2,
        _ => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series_count(text: &str, family: &str) -> usize {
        text.lines()
            .filter(|line| !line.starts_with('#') && line.starts_with(family))
            .count()
    }

    #[test]
    fn adversarial_guard_counts_success_once_and_never_as_failure() {
        let counters = Arc::new(TlsCounters::default());
        {
            let guard = HandshakeGuard::new(counters.clone());
            guard.certificate_selected();
            guard.complete(TlsGroup::X25519MlKem768);
            guard.complete(TlsGroup::X25519MlKem768);
            // Late stage signals after completion must not
            // resurrect the guard into a failure on drop.
            guard.no_certificate();
        }
        let text = Metrics {
            tls: counters,
            ..Metrics::default()
        }
        .render(&[]);
        assert!(text.contains("vongola_tls_handshakes_total{group=\"X25519MLKEM768\"} 1"));
        for class in HANDSHAKE_FAILURE_CLASSES {
            assert!(
                text.contains(&format!(
                    "vongola_tls_handshake_failures_total{{class=\"{class}\"}} 0"
                )),
                "{class} must stay 0"
            );
        }
    }

    #[test]
    fn adversarial_keyed_families_capped_under_route_flood() {
        let metrics = Metrics::new();
        for index in 0..(MAX_KEYED_SERIES * 8) {
            let name = format!("route-{index}");
            metrics.record_request(&name, 200, 1);
            metrics.record_upstream_latency(&name, 1);
        }
        let text = metrics.render(&[]);
        assert_eq!(
            series_count(&text, "vongola_route_requests_total{"),
            (MAX_KEYED_SERIES + 1) * STATUS_CLASSES.len()
        );
        assert_eq!(
            series_count(&text, "vongola_upstream_latency_ms_count{"),
            MAX_KEYED_SERIES + 1
        );
        let overflow = (MAX_KEYED_SERIES * 7) as u64;
        assert!(text.contains(&format!(
            "vongola_route_requests_total{{route=\"overflow\",status_class=\"2xx\"}} {overflow}"
        )));
        assert_eq!(metrics.total_requests(), (MAX_KEYED_SERIES * 8) as u64);
    }

    #[test]
    fn adversarial_label_values_escaped() {
        let metrics = Metrics::new();
        metrics.record_request("evil\"} 1\nvongola_up 0", 200, 1);
        let text = metrics.render(&[]);
        assert!(
            !text.contains("\nvongola_up 0"),
            "label must not inject a line"
        );
        assert!(text.contains("route=\"evil\\\"} 1\\nvongola_up 0\""));
    }

    #[test]
    fn adversarial_tls_failure_flood_keeps_series_fixed() {
        // A flood of failed handshakes (each with a distinct
        // client-chosen SNI in real life) must not grow the
        // registry: no family is labelled by anything a client
        // sends.
        let metrics = Metrics::new();
        let before = metrics.render(&[]).lines().count();
        for index in 0..10_000 {
            let guard = HandshakeGuard::new(metrics.tls.clone());
            if index % 2 == 0 {
                guard.no_certificate();
            }
        }
        let text = metrics.render(&[]);
        assert_eq!(text.lines().count(), before);
        assert!(
            text.contains("vongola_tls_handshake_failures_total{class=\"no_certificate\"} 5000")
        );
        assert!(
            text.contains(
                "vongola_tls_handshake_failures_total{class=\"before_certificate\"} 5000"
            )
        );
    }

    #[test]
    fn validation_counters_move() {
        let metrics = Metrics::new();
        metrics.record_request("example.test", 200, 5);
        metrics.record_request("example.test", 502, 9);
        let text = metrics.render(&[]);
        assert!(text.contains("vongola_requests_total{status_class=\"2xx\"} 1"));
        assert!(text.contains("vongola_requests_total{status_class=\"5xx\"} 1"));
        assert!(text.contains(
            "vongola_route_requests_total{route=\"example.test\",status_class=\"2xx\"} 1"
        ));
        assert!(text.contains(
            "vongola_route_requests_total{route=\"example.test\",status_class=\"5xx\"} 1"
        ));
        assert_eq!(metrics.total_requests(), 2);
    }

    #[test]
    fn validation_guard_failure_classes_by_stage() {
        let counters = Arc::new(TlsCounters::default());
        drop(HandshakeGuard::new(counters.clone()));
        let after = HandshakeGuard::new(counters.clone());
        after.certificate_selected();
        drop(after);
        let none = HandshakeGuard::new(counters.clone());
        none.no_certificate();
        drop(none);
        for class in [
            HandshakeFailure::AfterCertificate,
            HandshakeFailure::BeforeCertificate,
            HandshakeFailure::NoCertificate,
        ] {
            assert_eq!(counters.failures[class.index()].load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn validation_histogram_buckets_cumulative() {
        let metrics = Metrics::new();
        metrics.record_upstream_latency("api/127.0.0.1:9000", 3);
        metrics.record_upstream_latency("api/127.0.0.1:9000", 40);
        metrics.record_upstream_latency("api/127.0.0.1:9000", 99_999);
        let text = metrics.render(&[]);
        for line in [
            "vongola_upstream_latency_ms_bucket{upstream=\"api/127.0.0.1:9000\",le=\"1\"} 0",
            "vongola_upstream_latency_ms_bucket{upstream=\"api/127.0.0.1:9000\",le=\"5\"} 1",
            "vongola_upstream_latency_ms_bucket{upstream=\"api/127.0.0.1:9000\",le=\"50\"} 2",
            "vongola_upstream_latency_ms_bucket{upstream=\"api/127.0.0.1:9000\",le=\"5000\"} 2",
            "vongola_upstream_latency_ms_bucket{upstream=\"api/127.0.0.1:9000\",le=\"+Inf\"} 3",
            "vongola_upstream_latency_ms_count{upstream=\"api/127.0.0.1:9000\"} 3",
            "vongola_upstream_latency_ms_sum{upstream=\"api/127.0.0.1:9000\"} 100042",
        ] {
            assert!(text.contains(line), "missing {line}");
        }
    }

    #[test]
    fn validation_registry_renders_all_series_at_boot() {
        let metrics = Metrics::new();
        let text = metrics.render(&[]);
        for series in [
            "vongola_up 1",
            "vongola_requests_total{status_class=\"2xx\"} 0",
            "vongola_cache_hits_total 0",
            "vongola_dropped_log_lines_total 0",
            "vongola_request_latency_ms_bucket{le=\"+Inf\"} 0",
            "vongola_request_latency_ms_count 0",
            "vongola_tls_classical_fallback_total 0",
            "vongola_tls_handshakes_total{group=\"SecP384r1MLKEM1024\"} 0",
            "vongola_tls_handshake_failures_total{class=\"no_certificate\"} 0",
        ] {
            assert!(text.contains(series), "missing {series}");
        }
        assert_eq!(
            series_count(&text, "vongola_log_lines_total{"),
            LOG_LEVELS.len() * LOG_SOURCES.len()
        );
    }

    #[test]
    fn validation_tls_labels_match_config_allowlist() {
        let mut allowlist: Vec<&str> = crate::config::HYBRID_GROUPS
            .iter()
            .chain(crate::config::CLASSICAL_GROUPS.iter())
            .copied()
            .collect();
        allowlist.push("unknown");
        allowlist.sort();
        let mut labels = TLS_GROUPS.to_vec();
        labels.sort();
        assert_eq!(labels, allowlist);
        assert_eq!(labels, TLS_GROUPS.to_vec(), "TLS_GROUPS must stay sorted");
        for (index, group) in TlsGroup::ALL.into_iter().enumerate() {
            assert_eq!(group.index(), index, "ALL must follow TLS_GROUPS order");
            let classical = crate::config::CLASSICAL_GROUPS.contains(&group.label());
            assert_eq!(group.is_classical(), classical, "{}", group.label());
        }
    }
}
