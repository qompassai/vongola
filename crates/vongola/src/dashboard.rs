// #################################################################
// /qompassai/vongola/crates/vongola/src/dashboard.rs
// Qompass AI — Vongola clean-room operator dashboard
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

//! Operator dashboard: a self-contained page served only from
//! the admin listener, polling `/api/state` every two seconds.
//! Every state frame carries a server timestamp so the operator
//! can see data freshness. Panels: NAT, Tor, chains, fleet and
//! hosting basics (node health, upstreams, certificate expiry).
//! Onion private keys and all other key material are never part
//! of the state model, so they can never render here.

use std::sync::Arc;

use crate::state::State;

pub fn state_json(state: &Arc<State>) -> serde_json::Value {
    let config = state.config_snapshot();
    let certs = state
        .certs
        .read()
        .map(|store| store.inventory())
        .unwrap_or_default();
    let nat = state.nat.read().map(|map| map.clone()).unwrap_or_default();
    let tor = state
        .tor
        .read()
        .map(|status| status.clone())
        .unwrap_or_else(|_| crate::tor::TorStatus::disabled());
    let upstream_health = state
        .upstream_health
        .read()
        .map(|map| map.clone())
        .unwrap_or_default();
    let chain_health = state
        .chain_health
        .read()
        .map(|map| map.clone())
        .unwrap_or_default();
    let routes: Vec<serde_json::Value> = config
        .routes
        .iter()
        .map(|route| {
            serde_json::json!({
                "chain": route.chain.iter().map(|hop| {
                    serde_json::json!({
                        "address": hop.address.clone().unwrap_or_else(|| config.tor.socks_addr.clone()),
                        "kind": format!("{:?}", hop.kind),
                    })
                }).collect::<Vec<_>>(),
                "host": route.host.clone(),
                "name": route.display_name(),
                "onion": route.onion.enabled,
                "static": route.static_root.is_some(),
                "upstreams": route.upstreams.iter().map(|u| u.address.clone()).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::json!({
        "bundle": {"sha256": state.bundle_sha256.clone(), "version": config.bundle_version.clone()},
        "certificates": certs,
        "chain_health": chain_health,
        "generated_at_unix": unix_now(),
        "metrics": {
            "cache_hits": state.metrics.cache_hits.load(std::sync::atomic::Ordering::Relaxed),
            "cache_misses": state.metrics.cache_misses.load(std::sync::atomic::Ordering::Relaxed),
            "chain_failures": state.metrics.chain_failures.load(std::sync::atomic::Ordering::Relaxed),
            "dropped_log_lines": crate::metrics::dropped_log_lines(),
            "requests_total": state.metrics.total_requests(),
        },
        "nat": nat,
        "node": {
            "name": config.node_name.clone(),
            "profile": format!("{:?}", config.profile).to_lowercase(),
            "uptime_secs": state.started.elapsed().as_secs(),
        },
        "routes": routes,
        "tor": tor,
        "upstream_health": upstream_health,
    })
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vongola operator dashboard</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2rem; background: #111; color: #eee; }
h1 { font-size: 1.3rem; } h2 { font-size: 1.05rem; margin-top: 1.6rem; }
table { border-collapse: collapse; } td, th { border: 1px solid #444; padding: 0.3rem 0.6rem; text-align: left; }
.stale { color: #f66; } .ok { color: #7e7; }
</style>
</head>
<body>
<h1>Vongola operator dashboard</h1>
<p>Node <strong id="node">?</strong> · profile <span id="profile">?</span> ·
bundle <span id="bundle">?</span> · data as of <span id="fresh">?</span>
<span id="stale" class="stale"></span></p>

<h2>NAT traversal</h2>
<table id="nat"><tr><th>listener</th><th>state</th><th>external</th><th>mapped port</th><th>lease remaining</th><th>gateway</th><th>error</th></tr></table>

<h2>Tor onion services (never an exit node)</h2>
<p>Control: <span id="tor-control">?</span> · connected: <span id="tor-connected">?</span></p>
<table id="tor"><tr><th>route</th><th>onion address</th><th>virtual port</th></tr></table>

<h2>Proxy chains</h2>
<table id="chains"><tr><th>route</th><th>configured chain</th><th>hop health</th></tr></table>

<h2>Upstreams and certificates</h2>
<table id="upstreams"><tr><th>route/upstream</th><th>healthy</th></tr></table>
<table id="certs"><tr><th>host</th><th>days to expiry</th><th>sha256 fingerprint</th><th>self-signed</th></tr></table>

<h2>Counters</h2>
<p id="counters">?</p>

<script>
const $ = (id) => document.getElementById(id);
function rows(table, items, cells) {
  const t = $(table);
  while (t.rows.length > 1) t.deleteRow(1);
  for (const item of items) {
    const row = t.insertRow();
    for (const cell of cells(item)) {
      const td = row.insertCell();
      td.textContent = cell === null || cell === undefined ? "" : String(cell);
    }
  }
}
async function refresh() {
  try {
    const response = await fetch("/api/state");
    if (!response.ok) { $("stale").textContent = "HTTP " + response.status; return; }
    const state = await response.json();
    const age = Math.floor(Date.now() / 1000) - state.generated_at_unix;
    $("fresh").textContent = new Date(state.generated_at_unix * 1000).toISOString();
    $("stale").textContent = age > 5 ? "STALE (" + age + "s)" : "";
    $("node").textContent = state.node.name;
    $("profile").textContent = state.node.profile;
    $("bundle").textContent = state.bundle.version + " " + state.bundle.sha256.slice(0, 12);
    rows("nat", Object.entries(state.nat), ([name, s]) => [name, s.state, s.external_addr, s.mapped_port, s.lease_remaining_secs, s.gateway, s.last_error]);
    $("tor-control").textContent = state.tor.control_addr || "(disabled)";
    $("tor-connected").textContent = state.tor.connected;
    rows("tor", state.tor.services, (s) => [s.route, s.address, s.virt_port]);
    rows("chains", state.routes.filter(r => r.chain.length > 0), (r) => [
      r.name,
      r.chain.map(h => h.kind + " " + h.address).join(" -> "),
      (state.chain_health[r.name] || []).map(h => h.kind + ":" + (h.healthy ? "up" : "DOWN") + " " + h.latency_ms + "ms").join(", ")
    ]);
    rows("upstreams", Object.entries(state.upstream_health), ([key, healthy]) => [key, healthy]);
    rows("certs", state.certificates, (c) => [c.host, Math.round(c.days_until_expiry), c.fingerprint_sha256.slice(0, 16) + "…", c.self_signed]);
    $("counters").textContent = "requests " + state.metrics.requests_total +
      " · cache hits " + state.metrics.cache_hits + " · misses " + state.metrics.cache_misses +
      " · chain failures " + state.metrics.chain_failures +
      " · dropped log lines " + state.metrics.dropped_log_lines;
  } catch (error) {
    $("stale").textContent = "fetch failed: " + error;
  }
}
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cert::CertStore;

    #[test]
    fn validation_state_json_has_all_panels() {
        let config: crate::config::Config = serde_yaml::from_str(
            "listeners:\n  admin: {bind: \"127.0.0.1:9091\"}\n  http: {bind: \"0.0.0.0:8080\"}\n  https: {bind: \"0.0.0.0:4433\"}\nroutes:\n  - host: \"x.test\"\n    upstreams: [{address: \"127.0.0.1:9000\"}]",
        )
        .unwrap();
        let certs = CertStore::build(&config).unwrap();
        let state = State::new(config, PathBuf::from("vongola.yaml"), certs);
        let json = state_json(&state);
        for panel in [
            "bundle",
            "certificates",
            "chain_health",
            "nat",
            "node",
            "routes",
            "tor",
            "upstream_health",
        ] {
            assert!(json.get(panel).is_some(), "missing panel {panel}");
        }
        let text = serde_json::to_string(&json).unwrap();
        assert!(!text.contains("PrivateKey"), "no key material in state");
    }

    #[test]
    fn validation_dashboard_html_panels_present() {
        for marker in [
            "NAT traversal",
            "Tor onion services",
            "Proxy chains",
            "setInterval(refresh, 2000)",
        ] {
            assert!(DASHBOARD_HTML.contains(marker), "missing {marker}");
        }
    }
}
