// #################################################################
// /qompassai/vongola/crates/vongola/src/state.rs
// Qompass AI — Vongola clean-room shared state
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

//! Process-wide shared state: the live config snapshot, the
//! certificate store, metrics, and the status models the dashboard
//! and MCP surfaces render. Everything here is cheap to clone
//! (Arc) or lock briefly; nothing blocks the request path.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::cert::CertStore;
use crate::config::Config;
use crate::metrics::Metrics;
use crate::nat::NatStatus;
use crate::tor::TorStatus;

/// Public ECH material for operator surfaces, set at startup
/// by the ECH path (variant builds). The ECHConfigList is
/// public by design — it is what DNS publishes — so it is
/// safe to show on the dashboard. Private key material never
/// enters the state model.
#[derive(Clone, Debug, serde::Serialize)]
pub struct EchPublic {
    pub config_list_base64: String,
    pub public_name: String,
}

pub struct State {
    /// ACME HTTP-01 challenge tokens: token -> key authorization.
    pub acme_challenges: RwLock<BTreeMap<String, String>>,
    pub bundle_sha256: String,
    pub certs: Arc<RwLock<Arc<CertStore>>>,
    /// Docker/Swarm discovery results: host -> upstream addresses.
    pub discovered: RwLock<BTreeMap<String, Vec<String>>>,
    /// Per-route chain health: route name -> rendered hop states.
    pub chain_health: RwLock<BTreeMap<String, Vec<crate::chain::HopHealth>>>,
    pub ech: RwLock<Option<EchPublic>>,
    pub config: RwLock<Arc<Config>>,
    pub config_path: PathBuf,
    pub metrics: Metrics,
    pub nat: RwLock<BTreeMap<String, NatStatus>>,
    pub request_counter: AtomicU64,
    pub started: Instant,
    pub tor: RwLock<TorStatus>,
    /// Upstream health: "route/address" -> healthy.
    pub upstream_health: RwLock<BTreeMap<String, bool>>,
}

impl State {
    pub fn new(config: Config, config_path: PathBuf, certs: CertStore) -> Arc<State> {
        let bundle_sha256 = config.bundle_sha256();
        Arc::new(State {
            acme_challenges: RwLock::new(BTreeMap::new()),
            bundle_sha256,
            certs: Arc::new(RwLock::new(Arc::new(certs))),
            discovered: RwLock::new(BTreeMap::new()),
            chain_health: RwLock::new(BTreeMap::new()),
            ech: RwLock::new(None),
            config: RwLock::new(Arc::new(config)),
            config_path,
            metrics: Metrics::new(),
            nat: RwLock::new(BTreeMap::new()),
            request_counter: AtomicU64::new(0),
            started: Instant::now(),
            tor: RwLock::new(TorStatus::disabled()),
            upstream_health: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn config_snapshot(&self) -> Arc<Config> {
        self.config.read().expect("config lock").clone()
    }

    /// Hot reload: re-read, re-validate, atomically swap config
    /// and certificates. On any error the old state is kept and
    /// the structured errors are returned.
    pub fn reload(&self) -> Result<String, Vec<crate::config::ConfigError>> {
        let new_config = Config::load(&self.config_path)?;
        let new_certs = CertStore::build(&new_config).map_err(|message| {
            vec![crate::config::ConfigError {
                code: "reload.cert_failed".to_string(),
                field: "certs".to_string(),
                message,
            }]
        })?;
        let bundle = new_config.bundle_sha256();
        *self.config.write().expect("config lock") = Arc::new(new_config);
        *self.certs.write().expect("cert lock") = Arc::new(new_certs);
        Ok(bundle)
    }

    pub fn next_request_id(&self) -> String {
        let n = self
            .request_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("req-{n}")
    }

    /// Gauges for the Prometheus render: cert expiry, upstream
    /// health, NAT lease, Tor connectivity.
    pub fn extra_gauges(&self) -> Vec<(String, String, f64)> {
        let mut gauges: Vec<(String, String, f64)> = Vec::new();
        if let Ok(certs) = self.certs.read() {
            for entry in certs.inventory() {
                gauges.push((
                    "vongola_cert_days_until_expiry".to_string(),
                    format!("host=\"{}\"", entry.host),
                    entry.days_until_expiry,
                ));
            }
        }
        if let Ok(health) = self.upstream_health.read() {
            for (key, healthy) in health.iter() {
                gauges.push((
                    "vongola_upstream_healthy".to_string(),
                    format!("upstream=\"{key}\""),
                    if *healthy { 1.0 } else { 0.0 },
                ));
            }
        }
        if let Ok(nat) = self.nat.read() {
            for (listener, status) in nat.iter() {
                gauges.push((
                    "vongola_nat_mapped".to_string(),
                    format!("listener=\"{listener}\""),
                    if status.external_addr.is_some() {
                        1.0
                    } else {
                        0.0
                    },
                ));
            }
        }
        if let Ok(tor) = self.tor.read() {
            gauges.push((
                "vongola_tor_connected".to_string(),
                String::new(),
                if tor.connected { 1.0 } else { 0.0 },
            ));
            gauges.push((
                "vongola_tor_onion_services".to_string(),
                String::new(),
                tor.services.len() as f64,
            ));
        }
        if let Ok(ech) = self.ech.read() {
            gauges.push((
                "vongola_ech_enabled".to_string(),
                String::new(),
                if ech.is_some() { 1.0 } else { 0.0 },
            ));
        }
        gauges.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        gauges
    }
}
