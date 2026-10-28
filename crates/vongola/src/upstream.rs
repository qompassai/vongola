// #################################################################
// /qompassai/vongola/crates/vongola/src/upstream.rs
// Qompass AI — Vongola clean-room upstream selection and health
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

//! Upstream selection (round-robin over healthy upstreams) and
//! the background TCP health checker. Selection state lives in
//! per-route atomics so a config reload simply starts fresh
//! counters; health lives in the shared state map the dashboard
//! and MCP surfaces read.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::config::{Config, Route, Upstream};
use crate::state::State;

#[derive(Default)]
pub struct RouteRuntime {
    pub counters: BTreeMap<String, AtomicUsize>,
}

impl RouteRuntime {
    pub fn new(config: &Config) -> RouteRuntime {
        let mut counters = BTreeMap::new();
        for route in &config.routes {
            counters.insert(route.display_name(), AtomicUsize::new(0));
        }
        RouteRuntime { counters }
    }
}

/// Pick the next upstream for a route: round-robin, skipping
/// upstreams the health checker currently marks down. If health
/// is unknown for all of them, round-robin over all (health
/// unknown is not treated as down at first boot). If every
/// upstream is known-down, return None: the route answers 502.
pub fn select_upstream(state: &State, runtime: &RouteRuntime, route: &Route) -> Option<Upstream> {
    if route.upstreams.is_empty() {
        return None;
    }
    let counter = runtime
        .counters
        .get(&route.display_name())?
        .fetch_add(1, Ordering::Relaxed);
    let health = state.upstream_health.read().ok()?;
    let key = |u: &Upstream| format!("{}/{}", route.display_name(), u.address);
    let any_known = route.upstreams.iter().any(|u| health.contains_key(&key(u)));
    let all_known_down = any_known
        && route
            .upstreams
            .iter()
            .all(|u| health.get(&key(u)) == Some(&false));
    if all_known_down {
        return None;
    }
    for offset in 0..route.upstreams.len() {
        let candidate = &route.upstreams[(counter + offset) % route.upstreams.len()];
        if !any_known || health.get(&key(candidate)) != Some(&false) {
            return Some(candidate.clone());
        }
    }
    None
}

/// Background health checker: TCP-connect every upstream of every
/// route on an interval, recording results into shared state and
/// metrics. Runs until the process exits (spawned on the Pingora
/// runtime via a background service in main).
pub async fn health_check_loop(state: Arc<State>, interval: Duration) {
    loop {
        let config = state.config_snapshot();
        for route in &config.routes {
            for upstream in &route.upstreams {
                let healthy = tcp_reachable(&upstream.address).await;
                let key = format!("{}/{}", route.display_name(), upstream.address);
                if let Ok(mut map) = state.upstream_health.write() {
                    map.insert(key, healthy);
                }
                if healthy {
                    state
                        .metrics
                        .upstream_checks_ok
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    state
                        .metrics
                        .upstream_checks_failed
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            // Chain hop health feeds the dashboard chain panel.
            if !route.chain.is_empty() {
                let hops = crate::chain::probe_hops(&config, route).await;
                if let Ok(mut map) = state.chain_health.write() {
                    map.insert(route.display_name(), hops);
                }
            }
        }
        tokio::time::sleep(interval).await;
    }
}

async fn tcp_reachable(address: &str) -> bool {
    let timeout = Duration::from_secs(2);
    matches!(
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await,
        Ok(Ok(_stream))
    )
}

/// Docker/Swarm discovery: read container labels from the engine
/// API over the configured endpoint and return discovered
/// upstreams grouped by host label. Structured failure (string)
/// when the engine is absent — discovery degrades, never crashes.
pub async fn discover_docker_upstreams(
    endpoint: &str,
) -> Result<BTreeMap<String, Vec<Upstream>>, String> {
    let socket_path = endpoint
        .strip_prefix("unix://")
        .ok_or_else(|| "only unix:// docker endpoints are supported".to_string())?;
    let mut stream = tokio::net::UnixStream::connect(socket_path)
        .await
        .map_err(|e| format!("docker endpoint unreachable: {e}"))?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream
        .write_all(b"GET /containers/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| format!("docker request: {e}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| format!("docker response: {e}"))?;
    let text = String::from_utf8_lossy(&raw);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .ok_or_else(|| "docker response malformed".to_string())?;
    // Chunked transfer may wrap the JSON; find the JSON array.
    let start = body.find('[').ok_or("docker response has no array")?;
    let end = body.rfind(']').ok_or("docker response has no array end")? + 1;
    let containers: serde_json::Value =
        serde_json::from_str(&body[start..end]).map_err(|e| format!("docker json: {e}"))?;
    let mut found: BTreeMap<String, Vec<Upstream>> = BTreeMap::new();
    if let Some(items) = containers.as_array() {
        for item in items {
            let labels = item.get("Labels");
            let host = labels
                .and_then(|l| l.get("vongola.host"))
                .and_then(|v| v.as_str());
            let port = labels
                .and_then(|l| l.get("vongola.port"))
                .and_then(|v| v.as_str());
            if let (Some(host), Some(port)) = (host, port) {
                // Container IP from the first network attachment.
                let ip = item
                    .get("NetworkSettings")
                    .and_then(|n| n.get("Networks"))
                    .and_then(|n| n.as_object())
                    .and_then(|nets| nets.values().next())
                    .and_then(|net| net.get("IPAddress"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !ip.is_empty() {
                    found.entry(host.to_string()).or_default().push(Upstream {
                        address: format!("{ip}:{port}"),
                        sni: None,
                        tls: false,
                    });
                }
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cert::CertStore;

    fn state_with_route() -> (Arc<State>, Route) {
        let config: Config = serde_yaml::from_str(
            "listeners:\n  admin: {bind: \"127.0.0.1:9091\"}\n  http: {bind: \"0.0.0.0:8080\"}\n  https: {bind: \"0.0.0.0:4433\"}\nroutes:\n  - host: \"lb.test\"\n    upstreams: [{address: \"127.0.0.1:9001\"}, {address: \"127.0.0.1:9002\"}]",
        )
        .unwrap();
        let route = config.routes[0].clone();
        let certs = CertStore::build(&config).unwrap();
        let state = State::new(config, PathBuf::from("vongola.yaml"), certs);
        (state, route)
    }

    #[test]
    fn validation_round_robin_rotates() {
        let (state, route) = state_with_route();
        let config = state.config_snapshot();
        let runtime = RouteRuntime::new(&config);
        let a = select_upstream(&state, &runtime, &route).unwrap();
        let b = select_upstream(&state, &runtime, &route).unwrap();
        assert_ne!(a.address, b.address);
    }

    #[test]
    fn adversarial_all_down_returns_none() {
        let (state, route) = state_with_route();
        let config = state.config_snapshot();
        let runtime = RouteRuntime::new(&config);
        {
            let mut map = state.upstream_health.write().unwrap();
            map.insert("lb.test/127.0.0.1:9001".to_string(), false);
            map.insert("lb.test/127.0.0.1:9002".to_string(), false);
        }
        assert!(select_upstream(&state, &runtime, &route).is_none());
    }

    #[tokio::test]
    async fn validation_docker_absent_is_structured_error() {
        let result = discover_docker_upstreams("unix:///nonexistent/docker.sock").await;
        assert!(result.is_err());
    }
}
