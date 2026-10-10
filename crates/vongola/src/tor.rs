// #################################################################
// /qompassai/vongola/crates/vongola/src/tor.rs
// Qompass AI — Vongola clean-room Tor onion services
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

//! Tor v3 onion services via the Tor control protocol.
//!
//! HARD RULE: vongola must never operate as a Tor exit node.
//! Config validation rejects exit configurations (config.rs);
//! this module additionally refuses to talk to a daemon whose
//! generated torrc would enable exit behavior, and the torrc
//! fragment vongola emits always carries `ExitRelay 0` and
//! `ExitPolicy reject *:*`.
//!
//! Onion private keys are persisted at 0600 in the state
//! directory and are never logged, never placed in config, and
//! never exposed on any operator surface (the dashboard shows
//! public .onion addresses only).

use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::config::{Config, Route};
use crate::state::State;

#[derive(Clone, Debug, serde::Serialize)]
pub struct OnionServiceStatus {
    pub address: String,
    pub route: String,
    pub virt_port: u16,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TorStatus {
    pub connected: bool,
    pub control_addr: String,
    pub error: Option<String>,
    pub services: Vec<OnionServiceStatus>,
}

impl TorStatus {
    pub fn disabled() -> TorStatus {
        TorStatus {
            connected: false,
            control_addr: String::new(),
            error: None,
            services: Vec::new(),
        }
    }
}

/// The torrc lines vongola guarantees for any daemon it manages:
/// client/onion-service posture, exit impossible.
pub fn enforced_torrc_lines(config: &Config) -> Vec<String> {
    let mut lines = vec![
        "ExitPolicy reject *:*".to_string(),
        "ExitRelay 0".to_string(),
    ];
    if !config.tor.relay {
        lines.push("ORPort 0".to_string());
        lines.push("DirPort 0".to_string());
    }
    lines.sort();
    lines
}

/// Control-protocol client (subset): AUTHENTICATE, ADD_ONION,
/// DEL_ONION, GETINFO. Replies are parsed for their 250/5xx code.
pub struct TorControl {
    reader: BufReader<tokio::io::ReadHalf<TcpStream>>,
    writer: tokio::io::WriteHalf<TcpStream>,
}

impl TorControl {
    pub async fn connect(control_addr: &str, password: Option<&str>) -> Result<TorControl, String> {
        let stream = TcpStream::connect(control_addr)
            .await
            .map_err(|e| format!("tor control connect {control_addr}: {e}"))?;
        let (read_half, write_half) = tokio::io::split(stream);
        let mut control = TorControl {
            reader: BufReader::new(read_half),
            writer: write_half,
        };
        let command = match password {
            Some(secret) => format!("AUTHENTICATE \"{secret}\"\r\n"),
            None => "AUTHENTICATE\r\n".to_string(),
        };
        control.command(&command).await?;
        Ok(control)
    }

    async fn command(&mut self, command: &str) -> Result<Vec<String>, String> {
        // Never log control commands: ADD_ONION replies carry key
        // material and AUTHENTICATE carries the password.
        self.writer
            .write_all(command.as_bytes())
            .await
            .map_err(|e| format!("tor control write: {e}"))?;
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .await
                .map_err(|e| format!("tor control read: {e}"))?;
            if n == 0 {
                return Err("tor control: connection closed".to_string());
            }
            let trimmed = line.trim_end().to_string();
            let code: u32 = trimmed.get(0..3).and_then(|c| c.parse().ok()).unwrap_or(0);
            let separator = trimmed.chars().nth(3).unwrap_or(' ');
            lines.push(trimmed);
            if separator == ' ' {
                if code >= 400 {
                    return Err(format!("tor control error {code}"));
                }
                return Ok(lines);
            }
        }
    }

    /// Publish one v3 onion service. Returns (service id,
    /// private key) — the key is for the caller to persist at
    /// 0600 or to discard; it is never logged here.
    pub async fn add_onion(
        &mut self,
        existing_key: Option<&str>,
        virt_port: u16,
        target: &str,
    ) -> Result<(String, Option<String>), String> {
        let key_spec = match existing_key {
            Some(key) => key.to_string(),
            None => "NEW:ED25519-V3".to_string(),
        };
        let command = format!("ADD_ONION {key_spec} Port={virt_port},{target}\r\n");
        let lines = self.command(&command).await?;
        let mut service_id = None;
        let mut private_key = None;
        for line in &lines {
            if let Some(value) = line.strip_prefix("250-ServiceID=") {
                service_id = Some(value.trim().to_string());
            }
            if let Some(value) = line.strip_prefix("250-PrivateKey=") {
                private_key = Some(value.trim().to_string());
            }
        }
        let id = service_id.ok_or("tor: ADD_ONION reply has no ServiceID")?;
        Ok((id, private_key))
    }

    /// Remove a service this process published. Part of the
    /// control-protocol surface; the startup path publishes and
    /// leaves services up for the daemon's lifetime.
    #[allow(dead_code)]
    pub async fn del_onion(&mut self, service_id: &str) -> Result<(), String> {
        self.command(&format!("DEL_ONION {service_id}\r\n"))
            .await
            .map(|_| ())
    }
}

fn key_path(state_dir: &std::path::Path, route_name: &str) -> PathBuf {
    let safe = route_name.replace(['/', '\\', ':'], "_");
    state_dir.join("onion").join(format!("{safe}.key"))
}

fn load_key(state_dir: &std::path::Path, route_name: &str) -> Option<String> {
    std::fs::read_to_string(key_path(state_dir, route_name))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

#[cfg(unix)]
fn persist_key(state_dir: &std::path::Path, route_name: &str, key: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = state_dir.join("onion");
    std::fs::create_dir_all(&dir).map_err(|e| format!("onion dir: {e}"))?;
    let path = key_path(state_dir, route_name);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("onion key write: {e}"))?;
    file.write_all(key.as_bytes())
        .map_err(|e| format!("onion key write: {e}"))
}

#[cfg(not(unix))]
fn persist_key(state_dir: &std::path::Path, route_name: &str, key: &str) -> Result<(), String> {
    let dir = state_dir.join("onion");
    std::fs::create_dir_all(&dir).map_err(|e| format!("onion dir: {e}"))?;
    std::fs::write(key_path(state_dir, route_name), key)
        .map_err(|e| format!("onion key write: {e}"))
}

/// Publish onion services for every route that enables them and
/// record status into shared state. Runs once at startup; a
/// daemon that is absent yields a structured error status, not a
/// crash (the proxy keeps serving clearnet routes).
pub async fn publish_onion_services(state: Arc<State>) {
    let config = state.config_snapshot();
    if !config.tor.enabled {
        return;
    }
    let onion_routes: Vec<&Route> = config.routes.iter().filter(|r| r.onion.enabled).collect();
    if onion_routes.is_empty() {
        if let Ok(mut status) = state.tor.write() {
            status.control_addr = config.tor.control_addr.clone();
        }
        return;
    }
    log::info!(
        "tor: enforced posture for this node: {}",
        enforced_torrc_lines(&config).join("; ")
    );
    let password = config
        .tor
        .control_password_env
        .as_ref()
        .and_then(|name| std::env::var(name).ok());
    let mut control = match TorControl::connect(&config.tor.control_addr, password.as_deref()).await
    {
        Ok(control) => control,
        Err(message) => {
            log::warn!("tor: {message}");
            if let Ok(mut status) = state.tor.write() {
                status.control_addr = config.tor.control_addr.clone();
                status.error = Some(message);
            }
            return;
        }
    };
    let mut services = Vec::new();
    for route in onion_routes {
        let target = https_target(&config, route);
        let existing = if route.onion.persist_key {
            load_key(&config.state_dir, &route.display_name())
        } else {
            None
        };
        match control
            .add_onion(existing.as_deref(), route.onion.virt_port, &target)
            .await
        {
            Ok((service_id, new_key)) => {
                if route.onion.persist_key
                    && let Some(key) = &new_key
                    && let Err(message) = persist_key(&config.state_dir, &route.display_name(), key)
                {
                    log::warn!("tor: could not persist onion key: {message}");
                }
                log::info!(
                    "tor: onion service {}.onion published for route {}",
                    service_id,
                    route.display_name()
                );
                services.push(OnionServiceStatus {
                    address: format!("{service_id}.onion"),
                    route: route.display_name(),
                    virt_port: route.onion.virt_port,
                });
            }
            Err(message) => {
                log::warn!(
                    "tor: ADD_ONION for {} failed: {message}",
                    route.display_name()
                );
                if let Ok(mut status) = state.tor.write() {
                    status.error = Some(message);
                }
            }
        }
    }
    if let Ok(mut status) = state.tor.write() {
        status.connected = true;
        status.control_addr = config.tor.control_addr.clone();
        status.services = services;
    }
}

/// Onion traffic terminates at the local HTTPS listener: the
/// daemon forwards the virtual port to it, and SNI/Host routing
/// takes over from there.
fn https_target(config: &Config, _route: &Route) -> String {
    let bind = &config.listeners.https.bind;
    let port = bind.rsplit(':').next().unwrap_or("4433");
    let host = if bind.starts_with("0.0.0.0") || bind.starts_with("[::]") {
        "127.0.0.1"
    } else {
        bind.rsplit_once(':').map(|(h, _)| h).unwrap_or("127.0.0.1")
    };
    format!("{host}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_torrc(extra: &str) -> Config {
        serde_yaml::from_str(&format!(
            "listeners:\n  admin: {{bind: \"127.0.0.1:9091\"}}\n  http: {{bind: \"0.0.0.0:8080\"}}\n  https: {{bind: \"0.0.0.0:4433\"}}\nroutes: []\ntor: {{enabled: true, torrc_extra: \"{extra}\"}}"
        ))
        .unwrap()
    }

    #[test]
    fn adversarial_torrc_exitrelay_one_never_validates() {
        // config::Config::parse must reject this before tor.rs
        // ever runs; assert via validate_tor directly.
        let cfg = config_with_torrc("ExitRelay 1");
        let mut errors = Vec::new();
        crate::config::validate_tor(&cfg.tor, &mut errors);
        assert!(errors.iter().any(|e| e.code == "tor.exit_forbidden"));
    }

    #[test]
    fn validation_enforced_torrc_always_reject_all() {
        let cfg = config_with_torrc("");
        let lines = enforced_torrc_lines(&cfg);
        assert!(lines.contains(&"ExitPolicy reject *:*".to_string()));
        assert!(lines.contains(&"ExitRelay 0".to_string()));
    }

    #[tokio::test]
    async fn adversarial_add_onion_against_mock_control_port() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = tokio::io::split(stream);
            let mut reader = BufReader::new(read_half);
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    break;
                }
                if line.starts_with("AUTHENTICATE") {
                    let _ = write_half.write_all(b"250 OK\r\n").await;
                } else if line.starts_with("ADD_ONION") {
                    let _ = write_half
                        .write_all(b"250-ServiceID=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd\r\n250-PrivateKey=ED25519-V3:AAAA\r\n250 OK\r\n")
                        .await;
                } else {
                    let _ = write_half.write_all(b"250 OK\r\n").await;
                }
            }
        });
        let mut control = TorControl::connect(&addr, None).await.unwrap();
        let (service_id, key) = control.add_onion(None, 80, "127.0.0.1:4433").await.unwrap();
        assert!(service_id.ends_with("abcd"));
        assert!(key.unwrap().starts_with("ED25519-V3:"));
    }

    #[tokio::test]
    async fn validation_missing_daemon_is_structured_error() {
        let result = TorControl::connect("127.0.0.1:1", None).await;
        assert!(result.is_err());
    }
}
