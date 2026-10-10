// #################################################################
// /qompassai/vongola/crates/vongola/src/main.rs
// Qompass AI — Vongola clean-room entry point
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

//! Vongola entry point.
//!
//! Subcommands (alphabetical): `mcp` (stdio MCP operator server),
//! `serve` (the proxy; default), `validate-config`, `version`.
//! Logging runs through a bounded channel (1024 lines): producers
//! never block the request path, drops increment a counter that
//! is exported as a metric, and every line passes through
//! credential redaction before it is written.

mod a2a;
mod admin;
mod auth;
mod cert;
mod chain;
mod config;
mod dashboard;
#[cfg(feature = "ech")]
mod ech;
mod mcp;
mod metrics;
mod nat;
mod oauth;
mod proxy;
mod state;
mod static_site;
mod tor;
mod upstream;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use pingora::apps::http_app::HttpServer;
use pingora::listeners::Listeners;
use pingora::listeners::tls::TlsSettings;
use pingora::proxy::http_proxy_service;
use pingora::server::Server;
use pingora::services::listening::Service;

use crate::auth::OperatorAuth;
use crate::cert::CertStore;
use crate::config::Config;
use crate::state::State;

pub const LOG_CHANNEL_CAPACITY: usize = 1024;
pub const PINGORA_VERSION: &str = "0.9.0";

// ---------- Bounded, redacting logger ----------

struct BoundedLogger {
    level: log::LevelFilter,
    sender: std::sync::mpsc::SyncSender<String>,
}

static LOGGER_DROPPED: AtomicU64 = AtomicU64::new(0);

impl log::Log for BoundedLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool { metadata.level() <= self.level }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!("{} {} {}", record.level(), record.target(), record.args());
        let line = auth::redact(&line);
        match self.sender.try_send(line) {
            Ok(()) => {}
            Err(_) => {
                let dropped = LOGGER_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
                metrics::DROPPED_LOG_LINES.store(dropped, Ordering::Relaxed);
            }
        }
    }

    fn flush(&self) {}
}

fn init_logger() {
    let (sender, receiver) = std::sync::mpsc::sync_channel::<String>(LOG_CHANNEL_CAPACITY);
    std::thread::spawn(move || {
        let stderr = std::io::stderr();
        while let Ok(line) = receiver.recv() {
            let mut handle = stderr.lock();
            let _ = writeln!(handle, "{line}");
        }
    });
    let level = match std::env::var("VONGOLA_LOG")
        .unwrap_or_else(|_| "info".to_string())
        .to_lowercase()
        .as_str()
    {
        "debug" => log::LevelFilter::Debug,
        "error" => log::LevelFilter::Error,
        "off" => log::LevelFilter::Off,
        "trace" => log::LevelFilter::Trace,
        "warn" => log::LevelFilter::Warn,
        _ => log::LevelFilter::Info,
    };
    let logger = Box::new(BoundedLogger { level, sender });
    let _ = log::set_logger(Box::leak(logger));
    log::set_max_level(level);
}

// ---------- Background tasks (Pingora services) ----------

struct BackgroundTasks {
    state: Arc<State>,
}

#[async_trait::async_trait]
impl pingora::services::background::BackgroundService for BackgroundTasks {
    async fn start(&self, mut shutdown: pingora::server::ShutdownWatch) {
        let state = self.state.clone();
        // Health checks + chain probes.
        let health = {
            let state = state.clone();
            tokio::spawn(async move {
                upstream::health_check_loop(state, std::time::Duration::from_secs(5)).await;
            })
        };
        // Tor onion publication: retried until the daemon
        // accepts us (it may still be starting), then done.
        // Status is recorded in shared state on every attempt.
        let tor_task = {
            let state = state.clone();
            tokio::spawn(async move {
                if !state.config_snapshot().tor.enabled {
                    return;
                }
                loop {
                    tor::publish_onion_services(state.clone()).await;
                    let connected = state
                        .tor
                        .read()
                        .map(|status| status.connected)
                        .unwrap_or(false);
                    if connected {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                }
            })
        };
        // NAT managers per listener.
        let config = state.config_snapshot();
        let records: Arc<std::sync::Mutex<BTreeMap<String, nat::MappingRecord>>> =
            Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let mut nat_tasks = Vec::new();
        for (name, listener) in [
            ("http", &config.listeners.http),
            ("https", &config.listeners.https),
        ] {
            if listener.enabled && listener.nat.enabled {
                let manager_state = state.clone();
                let manager_records = records.clone();
                let bind = listener.bind.clone();
                let nat_config = listener.nat.clone();
                let name = name.to_string();
                nat_tasks.push(tokio::spawn(async move {
                    let manager = nat::NatManager {
                        records: manager_records,
                        state: manager_state,
                    };
                    manager.run_listener(&name, &bind, &nat_config).await;
                }));
            }
        }
        // Docker/Swarm discovery (best-effort, structured).
        let discovery = {
            let state = state.clone();
            tokio::spawn(async move {
                loop {
                    discovery_once(&state).await;
                    let interval = state.config_snapshot().discovery.interval_secs.max(5);
                    tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                }
            })
        };
        let _ = shutdown.changed().await;
        health.abort();
        tor_task.abort();
        discovery.abort();
        for task in nat_tasks {
            task.abort();
        }
        // Release NAT mappings on the way out. The guard is
        // dropped before any await (Send-ness of this future).
        let release_actions: Vec<ReleaseAction> = if let Ok(records) = records.lock() {
            records
                .values()
                .map(|record| match &record.upnp_control_url {
                    Some(control_url) => (Some(control_url.clone()), record.internal_port, None),
                    None => (None, record.internal_port, Some(record.clone())),
                })
                .collect()
        } else {
            Vec::new()
        };
        for (control_url, internal_port, sync_record) in release_actions {
            match (control_url, sync_record) {
                (Some(control_url), _) => {
                    let _ = nat::upnp_release(&control_url, internal_port).await;
                }
                (None, Some(record)) => nat::release_record_sync(&record),
                (None, None) => {}
            }
        }
    }
}

/// One discovery pass: query the engine API and store the
/// rendered result in shared state for the dashboard/MCP.
async fn discovery_once(state: &Arc<State>) {
    let config = state.config_snapshot();
    if !config.discovery.docker_enabled {
        return;
    }
    match upstream::discover_docker_upstreams(&config.discovery.docker_endpoint).await {
        Ok(found) => {
            let rendered: BTreeMap<String, Vec<String>> = found
                .iter()
                .map(|(host, ups)| {
                    (
                        host.clone(),
                        ups.iter().map(|u| u.address.clone()).collect(),
                    )
                })
                .collect();
            if let Ok(mut map) = state.discovered.write() {
                *map = rendered;
            }
        }
        Err(message) => {
            log::debug!("discovery: {message}");
        }
    }
}

/// One NAT release action captured before the guard drops:
/// (UPnP control URL, internal port, sync-release record).
type ReleaseAction = (Option<String>, u16, Option<nat::MappingRecord>);

// ---------- Operator auth ----------

fn operator_auth(config: &Config) -> OperatorAuth {
    let token = std::env::var(&config.admin_token_env).ok();
    let bind = &config.listeners.admin.bind;
    let bind_is_loopback = bind.starts_with("127.0.0.1") || bind.starts_with("[::1]");
    OperatorAuth {
        bind_is_loopback,
        token,
    }
}

// ---------- Commands ----------

fn config_path_from(args: &[String]) -> PathBuf {
    let mut path = PathBuf::from("./vongola.yaml");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--config"
            && let Some(value) = iter.next()
        {
            path = PathBuf::from(value);
        }
    }
    path
}

fn print_config_errors(errors: &[config::ConfigError]) {
    let text = serde_json::to_string_pretty(&serde_json::json!({"errors": errors}))
        .unwrap_or_else(|_| "config errors".to_string());
    eprintln!("{text}");
}

fn load_or_exit(path: &Path) -> Config {
    match Config::load(path) {
        Ok(config) => config,
        Err(errors) => {
            print_config_errors(&errors);
            std::process::exit(2);
        }
    }
}

fn build_state(config: Config, path: PathBuf) -> Arc<State> {
    let certs = match CertStore::build(&config) {
        Ok(store) => store,
        Err(message) => {
            eprintln!("certificate store failed: {message}");
            std::process::exit(2);
        }
    };
    State::new(config, path, certs)
}

fn cmd_mcp(path: PathBuf) {
    let config = load_or_exit(&path);
    let auth = operator_auth(&config);
    let state = build_state(config, path);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(mcp::serve_stdio(state, auth));
}

fn cmd_serve(path: PathBuf) {
    let config = load_or_exit(&path);
    let auth = operator_auth(&config);
    let state = build_state(config.clone(), path);
    log::info!(
        "vongola {} starting: node={} profile={:?} bundle={} sha256={}",
        env!("CARGO_PKG_VERSION"),
        config.node_name,
        config.profile,
        config.bundle_version,
        state.bundle_sha256
    );

    // ECH (RFC 9849): variant builds only (cargo feature
    // `ech`, OpenSSL 4). Fail closed: a config that asks for
    // ECH never silently serves without it — setup errors and
    // feature-less builds both stop startup.
    #[cfg(feature = "ech")]
    let ech_store = if config.tls.ech.enabled {
        match ech::prepare(&config) {
            Ok(prepared) => {
                if let Ok(mut slot) = state.ech.write() {
                    *slot = Some(prepared.public.clone());
                }
                log::info!(
                    "ECH enabled: public_name={} (publishable config list in <state_dir>/ech/)",
                    prepared.public.public_name
                );
                Some(prepared.store)
            }
            Err(message) => {
                eprintln!("ECH setup failed: {message}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };
    #[cfg(not(feature = "ech"))]
    if config.tls.ech.enabled {
        eprintln!(
            "tls.ech.enabled is set, but this build has no ECH support: ECH requires the OpenSSL 4 variant build (see SPEC.md section 16)"
        );
        std::process::exit(2);
    }

    // Wire the config knobs into Pingora's server configuration:
    // worker_threads bounds each service's runtime, and
    // shutdown_grace_secs caps connection drain on SIGTERM
    // (Pingora's default drain timeout is unbounded, which is
    // exactly the old tree's shutdown-stall defect).
    let server_conf = pingora::server::configuration::ServerConf {
        grace_period_seconds: Some(0),
        graceful_shutdown_timeout_seconds: Some(config.shutdown_grace_secs),
        threads: config.worker_threads.max(1),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, server_conf);
    server.bootstrap();

    // HTTPS proxy with SNI certificate selection.
    if config.listeners.https.enabled {
        let proxy = proxy::VongolaProxy::new(state.clone());
        let mut service = http_proxy_service(&server.configuration, proxy);
        let selector = cert::SniCertSelector {
            store: state.certs.clone(),
        };
        let mut tls_settings =
            TlsSettings::with_callbacks(Box::new(selector)).expect("tls settings");
        // TLS 1.3 only, with the validated PQ-hybrid group
        // allowlist as the preference order (config validation
        // has already rejected anything weaker).
        tls_settings
            .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
            .expect("tls min version");
        tls_settings
            .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_3))
            .expect("tls max version");
        tls_settings
            .set_groups_list(&config.tls.groups.join(":"))
            .expect("tls groups list");
        // Attach the ECH store to this listener's SSL_CTX
        // (OpenSSL deep-copies it; the local store may drop
        // afterwards). Failure here is startup-fatal: ECH was
        // explicitly enabled.
        #[cfg(feature = "ech")]
        if let Some(store) = &ech_store
            && let Err(message) = ech::attach(&mut tls_settings, store)
        {
            eprintln!("ECH setup failed: {message}");
            std::process::exit(2);
        }
        tls_settings.enable_h2();
        service.add_tls_with_settings(&config.listeners.https.bind, None, tls_settings);
        server.add_service(service);
    }

    // HTTP redirect + ACME challenges + agent card.
    if config.listeners.http.enabled {
        let app = HttpServer::new_app(admin::RedirectApp {
            state: state.clone(),
        });
        let service = Service::with_listeners(
            "http-redirect".to_string(),
            Listeners::tcp(&config.listeners.http.bind),
            app,
        );
        server.add_service(service);
    }

    // Admin listener.
    if config.listeners.admin.enabled {
        let app = HttpServer::new_app(admin::AdminApp {
            auth,
            state: state.clone(),
        });
        let service = Service::with_listeners(
            "admin".to_string(),
            Listeners::tcp(&config.listeners.admin.bind),
            app,
        );
        server.add_service(service);
    }

    // Background: health, NAT, Tor, discovery.
    let background = pingora::services::background::background_service(
        "vongola-background",
        BackgroundTasks {
            state: state.clone(),
        },
    );
    server.add_service(background);

    server.run_forever();
}

fn cmd_validate(path: PathBuf) {
    match Config::load(&path) {
        Ok(config) => {
            println!(
                "{}",
                serde_json::json!({
                    "bundle_sha256": config.bundle_sha256(),
                    "bundle_version": config.bundle_version,
                    "routes": config.routes.len(),
                    "valid": true
                })
            );
        }
        Err(errors) => {
            print_config_errors(&errors);
            std::process::exit(2);
        }
    }
}

fn main() {
    init_logger();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args
        .first()
        .filter(|a| !a.starts_with('-'))
        .map(|s| s.as_str())
        .unwrap_or("serve");
    let path = config_path_from(&args);
    match command {
        "mcp" => cmd_mcp(path),
        "serve" => cmd_serve(path),
        "validate-config" => cmd_validate(path),
        "version" => {
            println!(
                "vongola {} (pingora {})",
                env!("CARGO_PKG_VERSION"),
                PINGORA_VERSION
            );
        }
        other => {
            eprintln!("unknown command: {other} (expected: mcp, serve, validate-config, version)");
            std::process::exit(2);
        }
    }
}
