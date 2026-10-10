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

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide dropped-log-line counter, shared with the
/// bounded logger in main.rs (the logger exists before State).
pub static DROPPED_LOG_LINES: AtomicU64 = AtomicU64::new(0);

pub fn dropped_log_lines() -> u64 { DROPPED_LOG_LINES.load(Ordering::Relaxed) }

#[derive(Default)]
pub struct Metrics {
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub chain_failures: AtomicU64,
    pub latency_count: AtomicU64,
    pub latency_sum_ms: AtomicU64,
    pub requests_2xx: AtomicU64,
    pub requests_3xx: AtomicU64,
    pub requests_4xx: AtomicU64,
    pub requests_5xx: AtomicU64,
    pub route_requests: Mutex<BTreeMap<String, u64>>,
    pub upstream_checks_failed: AtomicU64,
    pub upstream_checks_ok: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self { Metrics::default() }

    pub fn record_request(&self, route: &str, status: u16, latency_ms: u64) {
        match status {
            200..=299 => self.requests_2xx.fetch_add(1, Ordering::Relaxed),
            300..=399 => self.requests_3xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.requests_4xx.fetch_add(1, Ordering::Relaxed),
            _ => self.requests_5xx.fetch_add(1, Ordering::Relaxed),
        };
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_ms.fetch_add(latency_ms, Ordering::Relaxed);
        if let Ok(mut map) = self.route_requests.lock() {
            *map.entry(route.to_string()).or_default() += 1;
        }
    }

    pub fn total_requests(&self) -> u64 {
        self.requests_2xx.load(Ordering::Relaxed)
            + self.requests_3xx.load(Ordering::Relaxed)
            + self.requests_4xx.load(Ordering::Relaxed)
            + self.requests_5xx.load(Ordering::Relaxed)
    }

    /// Render Prometheus text. `extra_gauges` carries live state
    /// (upstream health, cert expiry, NAT/Tor status) as
    /// (name, labels, value) triples, sorted by the caller.
    pub fn render(&self, extra_gauges: &[(String, String, f64)]) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str(
            "# HELP vongola_up Whether the node is up.\n# TYPE vongola_up gauge\nvongola_up 1\n",
        );
        out.push_str("# HELP vongola_requests_total Requests by status class.\n# TYPE vongola_requests_total counter\n");
        for (class, value) in [
            ("2xx", self.requests_2xx.load(Ordering::Relaxed)),
            ("3xx", self.requests_3xx.load(Ordering::Relaxed)),
            ("4xx", self.requests_4xx.load(Ordering::Relaxed)),
            ("5xx", self.requests_5xx.load(Ordering::Relaxed)),
        ] {
            out.push_str(&format!(
                "vongola_requests_total{{status_class=\"{class}\"}} {value}\n"
            ));
        }
        out.push_str("# HELP vongola_route_requests_total Requests by route.\n# TYPE vongola_route_requests_total counter\n");
        if let Ok(map) = self.route_requests.lock() {
            for (route, count) in map.iter() {
                out.push_str(&format!(
                    "vongola_route_requests_total{{route=\"{}\"}} {count}\n",
                    escape_label(route)
                ));
            }
        }
        out.push_str(&format!(
            "# HELP vongola_request_latency_ms_sum Summed request latency.\n# TYPE vongola_request_latency_ms_sum counter\nvongola_request_latency_ms_sum {}\n",
            self.latency_sum_ms.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "# HELP vongola_request_latency_ms_count Latency sample count.\n# TYPE vongola_request_latency_ms_count counter\nvongola_request_latency_ms_count {}\n",
            self.latency_count.load(Ordering::Relaxed)
        ));
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
        out.push_str(&format!(
            "# HELP vongola_upstream_health_checks_total Health check outcomes.\n# TYPE vongola_upstream_health_checks_total counter\nvongola_upstream_health_checks_total{{result=\"ok\"}} {}\nvongola_upstream_health_checks_total{{result=\"failed\"}} {}\n",
            self.upstream_checks_ok.load(Ordering::Relaxed),
            self.upstream_checks_failed.load(Ordering::Relaxed)
        ));
        for (name, labels, value) in extra_gauges {
            out.push_str(&format!("{name}{{{labels}}} {value}\n"));
        }
        out
    }
}

fn escape_label(value: &str) -> String { value.replace('\\', "\\\\").replace('"', "\\\"") }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_registry_renders_all_series_at_boot() {
        let metrics = Metrics::new();
        let text = metrics.render(&[]);
        for series in [
            "vongola_up 1",
            "vongola_requests_total{status_class=\"2xx\"} 0",
            "vongola_cache_hits_total 0",
            "vongola_dropped_log_lines_total 0",
        ] {
            assert!(text.contains(series), "missing {series}");
        }
    }

    #[test]
    fn validation_counters_move() {
        let metrics = Metrics::new();
        metrics.record_request("example.test", 200, 5);
        metrics.record_request("example.test", 502, 9);
        let text = metrics.render(&[]);
        assert!(text.contains("vongola_requests_total{status_class=\"2xx\"} 1"));
        assert!(text.contains("vongola_requests_total{status_class=\"5xx\"} 1"));
        assert!(text.contains("vongola_route_requests_total{route=\"example.test\"} 2"));
        assert_eq!(metrics.total_requests(), 2);
    }
}
