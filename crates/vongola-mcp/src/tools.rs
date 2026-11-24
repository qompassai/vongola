// #################################################################
// /qompassai/vongola/crates/vongola-mcp/src/tools.rs
// Qompass AI — vongola-mcp read-only tools
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

//! The tool table. Every tool is read-only and argument-free:
//! each call performs fresh GETs against the daemon and shapes
//! the answer; nothing is written, cached, or defaulted. A series
//! the daemon does not export is an error (`daemon.metric_missing`),
//! not a zero.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::daemon::{DaemonError, Source};
use crate::prometheus::{self, Sample};

/// Certificates expiring inside this many days are flagged.
pub const CERT_WARN_DAYS: f64 = 30.0;

pub struct ToolSpec {
    pub description: &'static str,
    pub name: &'static str,
}

/// The complete tool table, alphabetical. There are no mutating
/// tools, and none can be added without changing this table.
pub const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        description: "Per-SNI certificate subject, issuer, notAfter, and days remaining; flags anything inside 30 days.",
        name: "cert_status",
    },
    ToolSpec {
        description: "Emitted log lines by level and source (vongola, pingora, other), plus lines dropped by the bounded log pipeline.",
        name: "log_counters",
    },
    ToolSpec {
        description: "Configured routes with their upstreams, chains, and SNI names.",
        name: "routes_list",
    },
    ToolSpec {
        description: "TLS handshakes by negotiated group (PQ hybrids by name, classical groups), classical-fallback rate, and handshake failures by class.",
        name: "tls_stats",
    },
    ToolSpec {
        description: "Per-upstream health (up/down/unknown) and upstream latency summary from the daemon's histogram.",
        name: "upstream_health",
    },
];

pub fn tool_spec(name: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|tool| tool.name == name)
}

pub fn call(source: &dyn Source, name: &str) -> Result<Value, DaemonError> {
    let mut result = match name {
        "cert_status" => cert_status(&state(source)?),
        "log_counters" => log_counters(&metrics(source)?),
        "routes_list" => routes_list(&state(source)?),
        "tls_stats" => tls_stats(&metrics(source)?),
        "upstream_health" => upstream_health(&state(source)?, &metrics(source)?),
        other => Err(DaemonError {
            code: "tool.unknown",
            message: format!("unknown tool: {other}"),
        }),
    }?;
    result["fetched_at_unix"] = json!(unix_now());
    Ok(result)
}

fn metrics(source: &dyn Source) -> Result<Vec<Sample>, DaemonError> {
    let text = source.get("/metrics")?;
    prometheus::parse(&text).map_err(|message| DaemonError {
        code: "daemon.malformed_metrics",
        message,
    })
}

fn state(source: &dyn Source) -> Result<Value, DaemonError> {
    let text = source.get("/api/state")?;
    let value: Value = serde_json::from_str(&text).map_err(|e| DaemonError {
        code: "daemon.malformed_state",
        message: format!("/api/state is not JSON: {e}"),
    })?;
    if !value.is_object() {
        return Err(DaemonError {
            code: "daemon.malformed_state",
            message: "/api/state is not a JSON object".to_string(),
        });
    }
    Ok(value)
}

fn missing(series: &str) -> DaemonError {
    DaemonError {
        code: "daemon.metric_missing",
        message: format!("the daemon does not export {series} (older vongola build?)"),
    }
}

fn state_array<'a>(state: &'a Value, key: &str) -> Result<&'a Vec<Value>, DaemonError> {
    state
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| DaemonError {
            code: "daemon.malformed_state",
            message: format!("/api/state has no {key} array"),
        })
}

fn cert_status(state: &Value) -> Result<Value, DaemonError> {
    let mut expiring = Vec::new();
    let certificates: Vec<Value> = state_array(state, "certificates")?
        .iter()
        .map(|cert| {
            let host = cert.get("host").cloned().unwrap_or(Value::Null);
            let seconds = cert.get("expiry_seconds").and_then(Value::as_i64);
            let days = seconds.map(|s| s as f64 / 86_400.0);
            let soon = days.map(|d| d < CERT_WARN_DAYS);
            if soon == Some(true) {
                expiring.push(host.clone());
            }
            json!({
                "days_remaining": days.map(|d| (d * 100.0).floor() / 100.0),
                "expired": seconds.map(|s| s < 0),
                "expiring_soon": soon,
                "fingerprint_sha256": cert.get("fingerprint_sha256"),
                "host": host,
                "issuer": cert.get("issuer"),
                "not_after": cert.get("not_after"),
                "not_after_unix": cert.get("not_after_unix"),
                "self_signed": cert.get("self_signed"),
                "subject": cert.get("subject"),
            })
        })
        .collect();
    Ok(json!({
        "certificates": certificates,
        "expiring_soon": expiring,
        "generated_at_unix": state.get("generated_at_unix"),
        "warn_days": CERT_WARN_DAYS,
    }))
}

fn log_counters(samples: &[Sample]) -> Result<Value, DaemonError> {
    let mut by_level: BTreeMap<String, f64> = BTreeMap::new();
    let mut by_level_and_source: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
    for sample in samples
        .iter()
        .filter(|s| s.name == "vongola_log_lines_total")
    {
        let (Some(level), Some(source)) = (sample.label("level"), sample.label("source")) else {
            continue;
        };
        *by_level.entry(level.to_string()).or_default() += sample.value;
        by_level_and_source
            .entry(level.to_string())
            .or_default()
            .insert(source.to_string(), sample.value);
    }
    if by_level.is_empty() {
        return Err(missing("vongola_log_lines_total"));
    }
    let dropped = prometheus::value(samples, "vongola_dropped_log_lines_total", &[])
        .ok_or_else(|| missing("vongola_dropped_log_lines_total"))?;
    let errors_and_warnings = by_level.get("error").copied().unwrap_or(0.0)
        + by_level.get("warn").copied().unwrap_or(0.0);
    Ok(json!({
        "by_level": by_level,
        "by_level_and_source": by_level_and_source,
        "dropped_log_lines": dropped,
        "errors_and_warnings": errors_and_warnings,
    }))
}

fn routes_list(state: &Value) -> Result<Value, DaemonError> {
    let routes: Vec<Value> = state_array(state, "routes")?
        .iter()
        .map(|route| {
            let mut sni_names: Vec<Value> = route.get("host").cloned().into_iter().collect();
            if let Some(extra) = route.get("additional_hosts").and_then(Value::as_array) {
                sni_names.extend(extra.iter().cloned());
            }
            json!({
                "chain": route.get("chain"),
                "host": route.get("host"),
                "name": route.get("name"),
                "onion": route.get("onion"),
                "sni_names": sni_names,
                "static": route.get("static"),
                "upstreams": route.get("upstreams"),
            })
        })
        .collect();
    Ok(json!({
        "count": routes.len(),
        "generated_at_unix": state.get("generated_at_unix"),
        "routes": routes,
    }))
}

fn tls_stats(samples: &[Sample]) -> Result<Value, DaemonError> {
    let mut by_group: BTreeMap<String, f64> = BTreeMap::new();
    let mut failures: BTreeMap<String, f64> = BTreeMap::new();
    for sample in samples {
        match (
            sample.name.as_str(),
            sample.label("group"),
            sample.label("class"),
        ) {
            ("vongola_tls_handshakes_total", Some(group), _) => {
                by_group.insert(group.to_string(), sample.value);
            }
            ("vongola_tls_handshake_failures_total", _, Some(class)) => {
                failures.insert(class.to_string(), sample.value);
            }
            _ => {}
        }
    }
    if by_group.is_empty() {
        return Err(missing("vongola_tls_handshakes_total"));
    }
    if failures.is_empty() {
        return Err(missing("vongola_tls_handshake_failures_total"));
    }
    let classical = prometheus::value(samples, "vongola_tls_classical_fallback_total", &[])
        .ok_or_else(|| missing("vongola_tls_classical_fallback_total"))?;
    let total: f64 = by_group.values().sum();
    let hybrid: f64 = by_group
        .iter()
        .filter(|(group, _)| group.contains("MLKEM"))
        .map(|(_, count)| count)
        .sum();
    let failures_total: f64 = failures.values().sum();
    let ratio = |part: f64, whole: f64| (whole > 0.0).then(|| part / whole);
    Ok(json!({
        "classical_fallback": classical,
        "fallback_rate": ratio(classical, total),
        "failure_rate": ratio(failures_total, total + failures_total),
        "failures_by_class": failures,
        "failures_total": failures_total,
        "handshakes_by_group": by_group,
        "handshakes_total": total,
        "hybrid_pq": hybrid,
    }))
}

/// Upper bound (ms) of the first bucket holding quantile `q`.
/// Finite bounds are numbers; the overflow bucket is "+Inf".
fn quantile_bound(buckets: &[(f64, f64)], count: f64, q: f64) -> Value {
    let target = (q * count).ceil();
    buckets
        .iter()
        .find(|(_, cumulative)| *cumulative >= target)
        .map(|(bound, _)| {
            if bound.is_finite() {
                json!(bound)
            } else {
                json!("+Inf")
            }
        })
        .unwrap_or(Value::Null)
}

fn latency_summary(samples: &[Sample], upstream: &str) -> Value {
    let labels = [("upstream", upstream)];
    let Some(count) = prometheus::value(samples, "vongola_upstream_latency_ms_count", &labels)
    else {
        return Value::Null;
    };
    let sum = prometheus::value(samples, "vongola_upstream_latency_ms_sum", &labels).unwrap_or(0.0);
    let mut buckets: Vec<(f64, f64)> = samples
        .iter()
        .filter(|s| {
            s.name == "vongola_upstream_latency_ms_bucket" && s.label("upstream") == Some(upstream)
        })
        .filter_map(|s| {
            let bound = match s.label("le")? {
                "+Inf" => f64::INFINITY,
                text => text.parse().ok()?,
            };
            Some((bound, s.value))
        })
        .collect();
    buckets.sort_by(|a, b| a.0.total_cmp(&b.0));
    if count == 0.0 {
        return json!({"count": 0});
    }
    json!({
        "count": count,
        "mean_ms": sum / count,
        "p50_le_ms": quantile_bound(&buckets, count, 0.50),
        "p90_le_ms": quantile_bound(&buckets, count, 0.90),
        "p99_le_ms": quantile_bound(&buckets, count, 0.99),
    })
}

fn upstream_health(state: &Value, samples: &[Sample]) -> Result<Value, DaemonError> {
    let health = state
        .get("upstream_health")
        .and_then(Value::as_object)
        .ok_or_else(|| DaemonError {
            code: "daemon.malformed_state",
            message: "/api/state has no upstream_health object".to_string(),
        })?;
    let mut keys: Vec<String> = health.keys().cloned().collect();
    for sample in samples
        .iter()
        .filter(|s| s.name == "vongola_upstream_latency_ms_count")
    {
        if let Some(upstream) = sample.label("upstream")
            && !keys.iter().any(|key| key == upstream)
        {
            keys.push(upstream.to_string());
        }
    }
    keys.sort();
    let (mut up, mut down, mut unknown) = (0, 0, 0);
    let upstreams: Vec<Value> = keys
        .iter()
        .map(|key| {
            let healthy = health.get(key).and_then(Value::as_bool);
            match healthy {
                Some(true) => up += 1,
                Some(false) => down += 1,
                None => unknown += 1,
            }
            json!({
                "healthy": healthy,
                "latency": latency_summary(samples, key),
                "upstream": key,
            })
        })
        .collect();
    Ok(json!({
        "down": down,
        "generated_at_unix": state.get("generated_at_unix"),
        "unknown": unknown,
        "up": up,
        "upstreams": upstreams,
    }))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A fixture daemon: fixed bodies per path, or down.
    pub struct Fixture {
        pub metrics: Option<String>,
        pub state: Option<String>,
    }

    impl Source for Fixture {
        fn get(&self, path: &str) -> Result<String, DaemonError> {
            let body = match path {
                "/api/state" => &self.state,
                "/metrics" => &self.metrics,
                _ => &None,
            };
            body.clone().ok_or(DaemonError {
                code: "daemon.unavailable",
                message: "fixture daemon is down".to_string(),
            })
        }
    }

    pub fn live_fixture() -> Fixture {
        let state = json!({
            "certificates": [
                {"expiry_seconds": 10 * 86_400, "fingerprint_sha256": "ab", "host": "soon.test", "issuer": "CN=soon.test", "not_after": "Oct 28 00:00:00 2026 GMT", "not_after_unix": 1, "self_signed": true, "subject": "CN=soon.test"},
                {"expiry_seconds": 300 * 86_400, "fingerprint_sha256": "cd", "host": "far.test", "issuer": "CN=Root", "not_after": "Aug 14 00:00:00 2027 GMT", "not_after_unix": 2, "self_signed": false, "subject": "CN=far.test"}
            ],
            "generated_at_unix": 1_790_000_000u64,
            "routes": [{"additional_hosts": ["www.a.test"], "chain": [], "host": "a.test", "name": "apex", "onion": false, "static": true, "upstreams": []}],
            "upstream_health": {"api/127.0.0.1:9000": true, "api/127.0.0.1:9001": false}
        });
        let metrics = "vongola_up 1\n\
            vongola_tls_handshakes_total{group=\"SecP384r1MLKEM1024\"} 3\n\
            vongola_tls_handshakes_total{group=\"X25519\"} 1\n\
            vongola_tls_handshakes_total{group=\"X25519MLKEM768\"} 0\n\
            vongola_tls_classical_fallback_total 1\n\
            vongola_tls_handshake_failures_total{class=\"before_certificate\"} 2\n\
            vongola_tls_handshake_failures_total{class=\"no_certificate\"} 0\n\
            vongola_upstream_latency_ms_bucket{upstream=\"api/127.0.0.1:9000\",le=\"5\"} 1\n\
            vongola_upstream_latency_ms_bucket{upstream=\"api/127.0.0.1:9000\",le=\"50\"} 9\n\
            vongola_upstream_latency_ms_bucket{upstream=\"api/127.0.0.1:9000\",le=\"+Inf\"} 10\n\
            vongola_upstream_latency_ms_sum{upstream=\"api/127.0.0.1:9000\"} 200\n\
            vongola_upstream_latency_ms_count{upstream=\"api/127.0.0.1:9000\"} 10\n\
            vongola_log_lines_total{level=\"error\",source=\"pingora\"} 2\n\
            vongola_log_lines_total{level=\"warn\",source=\"vongola\"} 5\n\
            vongola_dropped_log_lines_total 0\n";
        Fixture {
            metrics: Some(metrics.to_string()),
            state: Some(state.to_string()),
        }
    }

    #[test]
    fn adversarial_daemon_down_every_tool_errors_structurally() {
        let down = Fixture {
            metrics: None,
            state: None,
        };
        for tool in TOOLS {
            let error = call(&down, tool.name).unwrap_err();
            assert_eq!(error.code, "daemon.unavailable", "{}", tool.name);
        }
    }

    #[test]
    fn adversarial_garbage_and_old_daemon_are_errors_not_zeros() {
        let garbage = Fixture {
            metrics: Some("<html>not metrics</html>".to_string()),
            state: Some("[1,2,3]".to_string()),
        };
        assert_eq!(
            call(&garbage, "tls_stats").unwrap_err().code,
            "daemon.malformed_metrics"
        );
        assert_eq!(
            call(&garbage, "routes_list").unwrap_err().code,
            "daemon.malformed_state"
        );
        let old = Fixture {
            metrics: Some("vongola_up 1\nvongola_dropped_log_lines_total 0\n".to_string()),
            state: Some("{}".to_string()),
        };
        assert_eq!(
            call(&old, "tls_stats").unwrap_err().code,
            "daemon.metric_missing"
        );
        assert_eq!(
            call(&old, "log_counters").unwrap_err().code,
            "daemon.metric_missing"
        );
        assert_eq!(
            call(&old, "cert_status").unwrap_err().code,
            "daemon.malformed_state"
        );
    }

    #[test]
    fn validation_cert_status_flags_inside_30_days() {
        let result = call(&live_fixture(), "cert_status").unwrap();
        assert_eq!(result["expiring_soon"], json!(["soon.test"]));
        assert_eq!(result["certificates"][0]["days_remaining"], json!(10.0));
        assert_eq!(result["certificates"][0]["expiring_soon"], json!(true));
        assert_eq!(result["certificates"][1]["expiring_soon"], json!(false));
        assert_eq!(result["certificates"][1]["issuer"], json!("CN=Root"));
    }

    #[test]
    fn validation_routes_tls_upstream_logs_shapes() {
        let fixture = live_fixture();
        let routes = call(&fixture, "routes_list").unwrap();
        assert_eq!(
            routes["routes"][0]["sni_names"],
            json!(["a.test", "www.a.test"])
        );
        let tls = call(&fixture, "tls_stats").unwrap();
        assert_eq!(tls["handshakes_total"], json!(4.0));
        assert_eq!(tls["hybrid_pq"], json!(3.0));
        assert_eq!(tls["fallback_rate"], json!(0.25));
        assert_eq!(tls["failures_total"], json!(2.0));
        let health = call(&fixture, "upstream_health").unwrap();
        assert_eq!(
            (health["up"].clone(), health["down"].clone()),
            (json!(1), json!(1))
        );
        let latency = &health["upstreams"][0]["latency"];
        assert_eq!(latency["mean_ms"], json!(20.0));
        assert_eq!(latency["p50_le_ms"], json!(50.0));
        assert_eq!(latency["p99_le_ms"], json!("+Inf"));
        assert_eq!(health["upstreams"][1]["latency"], Value::Null);
        let logs = call(&fixture, "log_counters").unwrap();
        assert_eq!(logs["errors_and_warnings"], json!(7.0));
        assert_eq!(logs["by_level_and_source"]["error"]["pingora"], json!(2.0));
    }

    #[test]
    fn validation_tls_stats_rates_null_when_no_traffic() {
        let fixture = Fixture {
            metrics: Some(
                "vongola_tls_handshakes_total{group=\"X25519\"} 0\nvongola_tls_classical_fallback_total 0\nvongola_tls_handshake_failures_total{class=\"no_certificate\"} 0\n"
                    .to_string(),
            ),
            state: None,
        };
        let tls = call(&fixture, "tls_stats").unwrap();
        assert_eq!(
            tls["fallback_rate"],
            Value::Null,
            "no traffic is not a 0% rate"
        );
        assert_eq!(tls["failure_rate"], Value::Null);
    }

    #[test]
    fn validation_tool_table_alphabetical_and_read_only() {
        let names: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert_eq!(
            names,
            [
                "cert_status",
                "log_counters",
                "routes_list",
                "tls_stats",
                "upstream_health"
            ]
        );
    }
}
