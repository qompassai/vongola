// #################################################################
// /qompassai/vongola/crates/vongola/src/config.rs
// Qompass AI — Vongola clean-room configuration
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

//! Configuration model and fail-closed validation.
//!
//! Canonical format is YAML. Every field is explicit, unknown fields
//! are rejected, and validation returns structured errors. A knob
//! that parses but is not wired to behavior is a defect: each field
//! here is consumed by exactly one subsystem, named in its docs.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Groups that combine a classical curve with ML-KEM (hybrid only).
pub const HYBRID_GROUPS: [&str; 2] = ["SecP384r1MLKEM1024", "X25519MLKEM768"];
/// Classical groups permitted as fallback after a hybrid.
pub const CLASSICAL_GROUPS: [&str; 3] = ["X25519", "secp256r1", "secp384r1"];
/// Default TLS 1.3 group preference order (strongest first).
pub const DEFAULT_TLS_GROUPS: [&str; 5] = [
    "SecP384r1MLKEM1024",
    "X25519MLKEM768",
    "X25519",
    "secp256r1",
    "secp384r1",
];
/// Hard bound on proxy chain length.
pub const MAX_CHAIN_HOPS: usize = 8;
/// Hard bound on request body size when a route does not set one.
pub const MAX_BODY_BYTES_DEFAULT: u64 = 10 * 1024 * 1024;
/// Hard bound on routes per config.
pub const MAX_ROUTES: usize = 512;
/// Hard bound on upstreams per route.
pub const MAX_UPSTREAMS_PER_ROUTE: usize = 64;

/// One structured validation error.
#[derive(Clone, Debug, Serialize)]
pub struct ConfigError {
    pub code: String,
    pub field: String,
    pub message: String,
}

impl ConfigError {
    fn new(code: &str, field: &str, message: impl Into<String>) -> Self {
        ConfigError {
            code: code.to_string(),
            field: field.to_string(),
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct A2aConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_a2a_name")]
    pub name: String,
    #[serde(default)]
    pub skills: Vec<String>,
}

fn default_a2a_name() -> String { "vongola".to_string() }

impl Default for A2aConfig {
    fn default() -> Self {
        A2aConfig {
            enabled: false,
            name: default_a2a_name(),
            skills: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    #[serde(default = "default_acme_directory")]
    pub directory_url: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub enabled: bool,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

impl Default for AcmeConfig {
    fn default() -> Self {
        AcmeConfig {
            directory_url: default_acme_directory(),
            email: String::new(),
            enabled: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BasicUser {
    pub name: String,
    /// Lowercase hex SHA-256 of the password. Plaintext never appears.
    pub password_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    /// Name of the environment variable holding the HS256 secret.
    pub secret_env: String,
    #[serde(default)]
    pub issuer: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthConfig {
    pub authorize_url: String,
    pub client_id: String,
    /// Name of the environment variable holding the client secret.
    pub client_secret_env: String,
    #[serde(default = "default_oauth_redirect_path")]
    pub redirect_path: String,
    /// Name of the environment variable holding the state HMAC secret.
    pub state_secret_env: String,
    pub token_url: String,
}

fn default_oauth_redirect_path() -> String { "/oauth/callback".to_string() }

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default)]
    pub basic_users: Vec<BasicUser>,
    #[serde(default)]
    pub jwt: Option<JwtConfig>,
    #[serde(default)]
    pub oauth2: Option<OAuthConfig>,
}

impl AuthConfig {
    pub fn is_empty(&self) -> bool {
        self.basic_users.is_empty() && self.jwt.is_none() && self.oauth2.is_none()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(default = "default_cache_max_age")]
    pub max_age_secs: u64,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_immutable_max_age")]
    pub immutable_max_age_secs: u64,
    #[serde(default = "default_cache_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,
}

fn default_cache_max_age() -> u64 { 3600 }
fn default_immutable_max_age() -> u64 { 31_536_000 }
fn default_cache_max_bytes() -> u64 { 64 * 1024 * 1024 }
fn default_cache_max_entries() -> usize { 1024 }

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_age_secs: default_cache_max_age(),
            enabled: false,
            immutable_max_age_secs: default_immutable_max_age(),
            max_bytes: default_cache_max_bytes(),
            max_entries: default_cache_max_entries(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChainHopKind {
    HttpConnect,
    Socks5,
    Tor,
    Vongola,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChainHop {
    /// `host:port` of the hop. Required except for `tor`, which
    /// defaults to the configured Tor SOCKS address.
    #[serde(default)]
    pub address: Option<String>,
    pub kind: ChainHopKind,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NatConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_nat_lease")]
    pub lease_secs: u32,
    /// Ordered preference; subset of `pcp`, `natpmp`, `upnp`.
    #[serde(default = "default_nat_protocols")]
    pub protocols: Vec<String>,
}

fn default_nat_lease() -> u32 { 3600 }
fn default_nat_protocols() -> Vec<String> {
    vec!["pcp".to_string(), "natpmp".to_string(), "upnp".to_string()]
}

impl Default for NatConfig {
    fn default() -> Self {
        NatConfig {
            enabled: false,
            lease_secs: default_nat_lease(),
            protocols: default_nat_protocols(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub bind: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub nat: NatConfig,
}

fn default_true() -> bool { true }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenersConfig {
    pub admin: ListenerConfig,
    pub http: ListenerConfig,
    pub https: ListenerConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnionConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Persist the generated v3 key in the state dir (0600).
    #[serde(default = "default_true")]
    pub persist_key: bool,
    #[serde(default = "default_onion_virt_port")]
    pub virt_port: u16,
}

fn default_onion_virt_port() -> u16 { 80 }

impl Default for OnionConfig {
    fn default() -> Self {
        OnionConfig {
            enabled: false,
            persist_key: true,
            virt_port: default_onion_virt_port(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// `host:port` (name or IP). Names resolve locally only for
    /// direct routes; chained routes hand the name to the last hop.
    pub address: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub tls: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default)]
    pub a2a_enabled: bool,
    #[serde(default)]
    pub additional_hosts: Vec<String>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    /// Ordered egress proxy chain; empty means direct.
    #[serde(default)]
    pub chain: Vec<ChainHop>,
    pub host: String,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub onion: OnionConfig,
    #[serde(default = "default_path_prefixes")]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub redirect_www_to_apex: bool,
    #[serde(default = "default_true")]
    pub security_headers: bool,
    #[serde(default)]
    pub self_signed_fallback: bool,
    #[serde(default)]
    pub spa_fallback: Option<String>,
    #[serde(default)]
    pub static_root: Option<PathBuf>,
    #[serde(default)]
    pub tls_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_key: Option<PathBuf>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
}

fn default_max_body() -> u64 { MAX_BODY_BYTES_DEFAULT }
fn default_path_prefixes() -> Vec<String> { vec!["/".to_string()] }

impl Route {
    pub fn display_name(&self) -> String {
        if self.name.is_empty() {
            self.host.clone()
        } else {
            self.name.clone()
        }
    }

    pub fn matches_host(&self, host: &str) -> bool {
        self.host == host || self.additional_hosts.iter().any(|h| h == host)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Fleet,
    #[default]
    Hosting,
    Lean,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EchConfig {
    /// Master switch. False (default): the key file is never
    /// touched and ECH is not offered.
    #[serde(default)]
    pub enabled: bool,
    /// ECH PEM file (RFC 9934: private key + ECHConfigList).
    /// Loaded when present; generated for `public_name` and
    /// written (0600) on first start when absent. Required
    /// when `enabled`. Consumed only by the ECH startup path
    /// (src/ech.rs), which exists solely in the OpenSSL 4
    /// variant build (cargo feature `ech`); every other build
    /// refuses to start with ECH enabled.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// The cover name clients see in the outer ClientHello and
    /// the name published inside the ECHConfig. Required when
    /// `enabled`. A fronting name for this node's listeners,
    /// not a route.
    #[serde(default)]
    pub public_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsPolicy {
    #[serde(default)]
    pub ech: EchConfig,
    #[serde(default = "default_tls_groups")]
    pub groups: Vec<String>,
    /// Only "1.3" is accepted; anything else fails validation.
    #[serde(default = "default_tls_version")]
    pub min_version: String,
}

fn default_tls_groups() -> Vec<String> {
    DEFAULT_TLS_GROUPS.iter().map(|s| s.to_string()).collect()
}
fn default_tls_version() -> String { "1.3".to_string() }

impl Default for TlsPolicy {
    fn default() -> Self {
        TlsPolicy {
            ech: EchConfig::default(),
            groups: default_tls_groups(),
            min_version: default_tls_version(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TorConfig {
    #[serde(default = "default_tor_control")]
    pub control_addr: String,
    #[serde(default)]
    pub control_password_env: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    /// HARD RULE: must be false. True fails validation, always.
    #[serde(default)]
    pub exit_relay: bool,
    /// Optional operator exit policy text. Only a reject-all policy
    /// is accepted; anything else fails validation.
    #[serde(default)]
    pub exit_policy: Option<String>,
    /// Non-exit relay opt-in. Exit behavior stays impossible.
    #[serde(default)]
    pub relay: bool,
    #[serde(default = "default_tor_socks")]
    pub socks_addr: String,
    /// Extra torrc lines, scanned for exit-enabling directives.
    #[serde(default)]
    pub torrc_extra: Option<String>,
}

fn default_tor_control() -> String { "127.0.0.1:9051".to_string() }
fn default_tor_socks() -> String { "127.0.0.1:9050".to_string() }

impl Default for TorConfig {
    fn default() -> Self {
        TorConfig {
            control_addr: default_tor_control(),
            control_password_env: None,
            enabled: false,
            exit_relay: false,
            exit_policy: None,
            relay: false,
            socks_addr: default_tor_socks(),
            torrc_extra: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub a2a: A2aConfig,
    #[serde(default = "default_operator_token_env")]
    pub admin_token_env: String,
    #[serde(default = "default_bundle_version")]
    pub bundle_version: String,
    #[serde(default)]
    pub lets_encrypt: AcmeConfig,
    pub listeners: ListenersConfig,
    #[serde(default = "default_node_name")]
    pub node_name: String,
    #[serde(default)]
    pub profile: Profile,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default = "default_shutdown_grace")]
    pub shutdown_grace_secs: u64,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default)]
    pub tls: TlsPolicy,
    #[serde(default)]
    pub tor: TorConfig,
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
    /// Fleet peers (other nodes' admin base URLs) for discovery.
    #[serde(default)]
    pub fleet_peers: Vec<String>,
    /// Docker/Swarm discovery settings.
    #[serde(default)]
    pub discovery: DiscoveryConfig,
}

fn default_operator_token_env() -> String { "VONGOLA_OPERATOR_TOKEN".to_string() }
fn default_bundle_version() -> String { "0".to_string() }
fn default_node_name() -> String { "node-1".to_string() }
fn default_shutdown_grace() -> u64 { 10 }
fn default_state_dir() -> PathBuf { PathBuf::from("./vongola-state") }
fn default_worker_threads() -> usize { 4 }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryConfig {
    #[serde(default = "default_docker_endpoint")]
    pub docker_endpoint: String,
    #[serde(default)]
    pub docker_enabled: bool,
    #[serde(default = "default_discovery_interval")]
    pub interval_secs: u64,
}

fn default_docker_endpoint() -> String { "unix:///var/run/docker.sock".to_string() }
fn default_discovery_interval() -> u64 { 15 }

impl Default for DiscoveryConfig {
    fn default() -> Self {
        DiscoveryConfig {
            docker_endpoint: default_docker_endpoint(),
            docker_enabled: false,
            interval_secs: default_discovery_interval(),
        }
    }
}

impl Config {
    /// Load and validate a YAML config file. HCL input is a
    /// structured error (YAML is canonical; see SPEC §3).
    pub fn load(path: &std::path::Path) -> Result<Config, Vec<ConfigError>> {
        if path.extension().is_some_and(|e| e == "hcl") {
            return Err(vec![ConfigError::new(
                "config.hcl_not_supported",
                "path",
                "HCL is import-only in the clean-room rewrite; convert to YAML (SPEC section 3)",
            )]);
        }
        let text = std::fs::read_to_string(path).map_err(|e| {
            vec![ConfigError::new(
                "config.read_failed",
                "path",
                e.to_string(),
            )]
        })?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Config, Vec<ConfigError>> {
        let cfg: Config = serde_yaml::from_str(text)
            .map_err(|e| vec![ConfigError::new("config.parse_failed", "", e.to_string())])?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// SHA-256 of the canonical (sorted-key JSON) config, used as
    /// the fleet bundle fingerprint.
    pub fn bundle_sha256(&self) -> String {
        let value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        let canonical = canonical_json(&value);
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(canonical.as_bytes());
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn validate(&self) -> Result<(), Vec<ConfigError>> {
        let mut errors: Vec<ConfigError> = Vec::new();
        // Listeners parse.
        for (name, listener) in [
            ("admin", &self.listeners.admin),
            ("http", &self.listeners.http),
            ("https", &self.listeners.https),
        ] {
            if listener.enabled && listener.bind.parse::<std::net::SocketAddr>().is_err() {
                errors.push(ConfigError::new(
                    "listener.bind_unparsable",
                    &format!("listeners.{name}.bind"),
                    format!("{} is not a socket address", listener.bind),
                ));
            }
            validate_nat(&listener.nat, &format!("listeners.{name}.nat"), &mut errors);
        }
        // ACME email contract (checked even when disabled).
        if self.lets_encrypt.email.is_empty() || self.lets_encrypt.email.ends_with("@example.com") {
            if self.lets_encrypt.enabled {
                errors.push(ConfigError::new(
                    "acme.email_invalid",
                    "lets_encrypt.email",
                    "a real contact email is required when ACME is enabled",
                ));
            } else if !self.lets_encrypt.email.is_empty() {
                errors.push(ConfigError::new(
                    "acme.email_placeholder",
                    "lets_encrypt.email",
                    "placeholder @example.com email is never accepted",
                ));
            }
        }
        // TLS policy.
        if self.tls.min_version != "1.3" {
            errors.push(ConfigError::new(
                "tls.version_forbidden",
                "tls.min_version",
                "only TLS 1.3 is permitted; TLS below 1.3 is refused by design",
            ));
        }
        let mut has_hybrid = false;
        for group in &self.tls.groups {
            if HYBRID_GROUPS.contains(&group.as_str()) {
                has_hybrid = true;
            } else if CLASSICAL_GROUPS.contains(&group.as_str()) {
                // permitted fallback
            } else if group.starts_with("MLKEM") {
                errors.push(ConfigError::new(
                    "tls.pure_mlkem_forbidden",
                    "tls.groups",
                    format!("{group}: pure ML-KEM groups are not offered; hybrid groups only"),
                ));
            } else {
                errors.push(ConfigError::new(
                    "tls.group_not_allowlisted",
                    "tls.groups",
                    format!("{group} is not on the TLS group allowlist"),
                ));
            }
        }
        if !has_hybrid {
            errors.push(ConfigError::new(
                "tls.no_hybrid_group",
                "tls.groups",
                "at least one hybrid post-quantum group is required",
            ));
        }
        // ECH knob shape, checked in every build (the OpenSSL 4
        // variant enforces the behavior at startup; other builds
        // refuse to start with ECH enabled — see main.rs). When
        // disabled the key path is inert and deliberately left
        // unchecked: a config must stay loadable on nodes that
        // do not serve ECH.
        if self.tls.ech.enabled {
            if self.tls.ech.public_name.is_empty() {
                errors.push(ConfigError::new(
                    "tls.ech_public_name_required",
                    "tls.ech.public_name",
                    "public_name is required when ECH is enabled",
                ));
            } else if !valid_dns_name(&self.tls.ech.public_name) {
                errors.push(ConfigError::new(
                    "tls.ech_public_name_invalid",
                    "tls.ech.public_name",
                    "public_name must be a DNS name (LDH letters, digits, '-', '.', '_')",
                ));
            }
            match &self.tls.ech.key_file {
                Some(path) if !path.as_os_str().is_empty() => {}
                _ => {
                    errors.push(ConfigError::new(
                        "tls.ech_key_file_required",
                        "tls.ech.key_file",
                        "key_file is required when ECH is enabled",
                    ));
                }
            }
        }
        // Tor never-exit rule.
        validate_tor(&self.tor, &mut errors);
        // Routes.
        if self.routes.len() > MAX_ROUTES {
            errors.push(ConfigError::new(
                "routes.too_many",
                "routes",
                format!("more than {MAX_ROUTES} routes"),
            ));
        }
        let mut seen_hosts: BTreeMap<String, usize> = BTreeMap::new();
        for (idx, route) in self.routes.iter().enumerate() {
            let field = format!("routes[{idx}]");
            if route.host.is_empty() || route.host != route.host.to_lowercase() {
                errors.push(ConfigError::new(
                    "route.host_invalid",
                    &field,
                    "host must be non-empty lowercase",
                ));
            }
            let seen_key = format!("{}|{}", route.host, route.path_prefixes.join(","));
            *seen_hosts.entry(seen_key).or_default() += 1;
            if route.upstreams.len() > MAX_UPSTREAMS_PER_ROUTE {
                errors.push(ConfigError::new(
                    "route.too_many_upstreams",
                    &field,
                    format!("more than {MAX_UPSTREAMS_PER_ROUTE} upstreams"),
                ));
            }
            if route.upstreams.is_empty() && route.static_root.is_none() {
                errors.push(ConfigError::new(
                    "route.no_destination",
                    &field,
                    "route needs upstreams or a static_root",
                ));
            }
            if route.static_root.is_some() && !route.upstreams.is_empty() {
                errors.push(ConfigError::new(
                    "route.ambiguous_destination",
                    &field,
                    "static_root and upstreams are mutually exclusive",
                ));
            }
            for upstream in &route.upstreams {
                if upstream.address.parse::<std::net::SocketAddr>().is_err()
                    && !valid_host_port(&upstream.address)
                {
                    errors.push(ConfigError::new(
                        "route.upstream_unparsable",
                        &field,
                        format!("upstream {} is not host:port", upstream.address),
                    ));
                }
            }
            if route.tls_cert.is_some() != route.tls_key.is_some() {
                errors.push(ConfigError::new(
                    "route.tls_pair_incomplete",
                    &field,
                    "tls_cert and tls_key must be set together",
                ));
            }
            if route.onion.enabled && !self.tor.enabled {
                errors.push(ConfigError::new(
                    "route.onion_without_tor",
                    &field,
                    "onion service requires tor.enabled",
                ));
            }
            validate_chain(route, self, &field, &mut errors);
            for user in &route.auth.basic_users {
                if user.password_sha256.len() != 64
                    || !user.password_sha256.chars().all(|c| c.is_ascii_hexdigit())
                {
                    errors.push(ConfigError::new(
                        "route.basic_user_hash_invalid",
                        &field,
                        format!("user {} password_sha256 must be 64 hex chars", user.name),
                    ));
                }
            }
        }
        for (key, count) in &seen_hosts {
            if *count > 1 {
                errors.push(ConfigError::new(
                    "route.host_duplicate",
                    "routes",
                    format!("host+prefixes {key} appears {count} times"),
                ));
            }
        }
        if self.worker_threads == 0 || self.worker_threads > 256 {
            errors.push(ConfigError::new(
                "server.worker_threads_bounds",
                "worker_threads",
                "worker_threads must be in 1..=256",
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Route lookup: among host+path matches, the longest
    /// matching path prefix wins (so `/api/*` beats `/` for API
    /// paths on the same host); ties break by config order.
    pub fn route_for(&self, host: &str, path: &str) -> Option<&Route> {
        let mut best: Option<(&Route, usize)> = None;
        for route in &self.routes {
            if !route.matches_host(host) {
                continue;
            }
            for prefix in &route.path_prefixes {
                let (matches, specificity) = if let Some(stem) = prefix.strip_suffix('*') {
                    (path.starts_with(stem), stem.len())
                } else if prefix == "/" {
                    (true, 1)
                } else {
                    (
                        path == prefix || path.starts_with(&format!("{prefix}/")),
                        prefix.len(),
                    )
                };
                if matches && best.map(|(_, score)| specificity > score).unwrap_or(true) {
                    best = Some((route, specificity));
                }
            }
        }
        best.map(|(route, _)| route)
    }
}

/// DNS name shape for values that end up inside protocol
/// structures (mirrors the vongola-ech store's own check):
/// non-empty, at most 253 bytes, letters/digits/'-' plus '.'
/// and '_' separators, no leading '.'/'-', no empty labels.
fn valid_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.starts_with(['.', '-'])
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

fn validate_nat(nat: &NatConfig, field: &str, errors: &mut Vec<ConfigError>) {
    if !nat.enabled {
        return;
    }
    if nat.lease_secs == 0 || nat.lease_secs > 86_400 {
        errors.push(ConfigError::new(
            "nat.lease_bounds",
            field,
            "lease_secs must be in 1..=86400",
        ));
    }
    for proto in &nat.protocols {
        if !["natpmp", "pcp", "upnp"].contains(&proto.as_str()) {
            errors.push(ConfigError::new(
                "nat.protocol_unknown",
                field,
                format!("{proto} is not a supported NAT protocol"),
            ));
        }
    }
    if nat.protocols.is_empty() {
        errors.push(ConfigError::new(
            "nat.no_protocols",
            field,
            "enabled NAT needs at least one protocol",
        ));
    }
}

/// The never-exit rule, enforced as structured config errors.
pub fn validate_tor(tor: &TorConfig, errors: &mut Vec<ConfigError>) {
    if tor.exit_relay {
        errors.push(ConfigError::new(
            "tor.exit_forbidden",
            "tor.exit_relay",
            "vongola must never operate as a Tor exit node (hard rule)",
        ));
    }
    if let Some(policy) = &tor.exit_policy {
        let normalized = policy.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized != "reject *:*" {
            errors.push(ConfigError::new(
                "tor.exit_policy_forbidden",
                "tor.exit_policy",
                "the only permitted exit policy is reject *:*",
            ));
        }
    }
    if let Some(extra) = &tor.torrc_extra {
        for line in extra.lines() {
            let lowered = line.trim().to_lowercase();
            if lowered.starts_with("exitrelay") && !lowered.starts_with("exitrelay 0") {
                errors.push(ConfigError::new(
                    "tor.exit_forbidden",
                    "tor.torrc_extra",
                    "torrc_extra attempts to enable exit relaying",
                ));
            }
            if lowered.starts_with("exitpolicy") && !lowered.contains("reject") {
                errors.push(ConfigError::new(
                    "tor.exit_policy_forbidden",
                    "tor.torrc_extra",
                    "torrc_extra carries a non-reject exit policy",
                ));
            }
        }
    }
    if tor.control_addr.parse::<std::net::SocketAddr>().is_err() {
        errors.push(ConfigError::new(
            "tor.control_addr_unparsable",
            "tor.control_addr",
            "control_addr must be a socket address",
        ));
    }
}

fn validate_chain(route: &Route, config: &Config, field: &str, errors: &mut Vec<ConfigError>) {
    if route.chain.len() > MAX_CHAIN_HOPS {
        errors.push(ConfigError::new(
            "chain.too_long",
            field,
            format!("chain exceeds {MAX_CHAIN_HOPS} hops"),
        ));
    }
    let mut seen: Vec<String> = Vec::new();
    for hop in &route.chain {
        match hop.kind {
            ChainHopKind::Tor => {}
            _ => {
                let Some(address) = &hop.address else {
                    errors.push(ConfigError::new(
                        "chain.hop_address_missing",
                        field,
                        "non-tor hops require an address",
                    ));
                    continue;
                };
                if !valid_host_port(address) && address.parse::<std::net::SocketAddr>().is_err() {
                    errors.push(ConfigError::new(
                        "chain.hop_address_unparsable",
                        field,
                        format!("hop address {address} is not host:port"),
                    ));
                }
                // A hop pointing at this node's own HTTPS listener or
                // repeated verbatim is a cycle.
                if *address == config.listeners.https.bind || *address == config.listeners.http.bind
                {
                    errors.push(ConfigError::new(
                        "chain.cycle_self",
                        field,
                        "chain hop points at this node's own listener",
                    ));
                }
                let key = format!("{:?}:{address}", hop.kind);
                if seen.contains(&key) {
                    errors.push(ConfigError::new(
                        "chain.cycle_repeat",
                        field,
                        format!("hop {key} repeats; cycles are rejected"),
                    ));
                }
                seen.push(key);
            }
        }
    }
}

fn valid_host_port(address: &str) -> bool {
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && port.parse::<u16>().is_ok_and(|p| p > 0)
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '[' | ']'))
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        serde_json::Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
listeners:
  admin: {bind: "127.0.0.1:9091"}
  http: {bind: "0.0.0.0:8080"}
  https: {bind: "0.0.0.0:4433"}
routes:
  - host: "example.test"
    upstreams: [{address: "127.0.0.1:9000"}]
"#;

    #[test]
    fn adversarial_chain_cycle_rejected() {
        let text = MINIMAL.replace(
            "upstreams: [{address: \"127.0.0.1:9000\"}]",
            "upstreams: [{address: \"127.0.0.1:9000\"}]\n    chain: [{kind: socks5, address: \"127.0.0.1:1080\"}, {kind: socks5, address: \"127.0.0.1:1080\"}]",
        );
        let errors = Config::parse(&text).expect_err("cycle must fail");
        assert!(errors.iter().any(|e| e.code == "chain.cycle_repeat"));
    }

    #[test]
    fn adversarial_ech_disabled_ignores_garbage() {
        // A disabled ECH block must stay inert: nonsense paths
        // and names validate clean, so a config stays loadable
        // on nodes and builds that never serve ECH.
        let text = format!(
            "{MINIMAL}\ntls: {{ech: {{enabled: false, key_file: \"/nonexistent/garbage.pem\", public_name: \"not a name!!\"}}}}\n"
        );
        assert!(Config::parse(&text).is_ok());
    }

    #[test]
    fn adversarial_ech_enabled_rejects_bad_public_name() {
        let text = format!(
            "{MINIMAL}\ntls: {{ech: {{enabled: true, key_file: \"/tmp/ech.pem\", public_name: \"bad name\"}}}}\n"
        );
        let errors = Config::parse(&text).expect_err("bad name must fail");
        assert!(
            errors
                .iter()
                .any(|e| e.code == "tls.ech_public_name_invalid")
        );
    }

    #[test]
    fn adversarial_ech_enabled_requires_fields() {
        let text = format!("{MINIMAL}\ntls: {{ech: {{enabled: true}}}}\n");
        let errors = Config::parse(&text).expect_err("bare enabled must fail");
        assert!(
            errors
                .iter()
                .any(|e| e.code == "tls.ech_public_name_required")
        );
        assert!(errors.iter().any(|e| e.code == "tls.ech_key_file_required"));
    }

    #[test]
    fn adversarial_exit_relay_rejected() {
        let text = format!("{MINIMAL}\ntor: {{enabled: true, exit_relay: true}}\n");
        let errors = Config::parse(&text).expect_err("exit must fail");
        assert!(errors.iter().any(|e| e.code == "tor.exit_forbidden"));
    }

    #[test]
    fn adversarial_exit_policy_rejected() {
        let text = format!("{MINIMAL}\ntor: {{enabled: true, exit_policy: \"accept *:80\"}}\n");
        let errors = Config::parse(&text).expect_err("accept policy must fail");
        assert!(errors.iter().any(|e| e.code == "tor.exit_policy_forbidden"));
    }

    #[test]
    fn adversarial_hcl_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vongola.hcl");
        std::fs::write(&path, "routes {}").unwrap();
        let errors = Config::load(&path).expect_err("hcl must fail");
        assert_eq!(errors[0].code, "config.hcl_not_supported");
    }

    #[test]
    fn adversarial_pure_mlkem_rejected() {
        let text = format!("{MINIMAL}\ntls: {{groups: [\"MLKEM768\", \"X25519\"]}}\n");
        let errors = Config::parse(&text).expect_err("pure mlkem must fail");
        assert!(errors.iter().any(|e| e.code == "tls.pure_mlkem_forbidden"));
    }

    #[test]
    fn adversarial_tls12_rejected() {
        let text = format!("{MINIMAL}\ntls: {{min_version: \"1.2\"}}\n");
        let errors = Config::parse(&text).expect_err("tls1.2 must fail");
        assert!(errors.iter().any(|e| e.code == "tls.version_forbidden"));
    }

    #[test]
    fn adversarial_torrc_exit_rejected() {
        let text = format!("{MINIMAL}\ntor: {{enabled: true, torrc_extra: \"ExitRelay 1\"}}\n");
        let errors = Config::parse(&text).expect_err("torrc exit must fail");
        assert!(errors.iter().any(|e| e.code == "tor.exit_forbidden"));
    }

    #[test]
    fn adversarial_unknown_field_rejected() {
        let text = format!("{MINIMAL}\nbogus_field: 1\n");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn validation_ech_disabled_by_default() {
        let cfg = Config::parse(MINIMAL).expect("minimal config");
        assert!(!cfg.tls.ech.enabled);
        assert!(cfg.tls.ech.key_file.is_none());
    }

    #[test]
    fn validation_ech_enabled_well_formed() {
        // Validation is pure: a well-formed enabled block
        // parses even though the key file does not exist yet
        // (startup generates it; see src/ech.rs).
        let text = format!(
            "{MINIMAL}\ntls: {{ech: {{enabled: true, key_file: \"/tmp/ech.pem\", public_name: \"cover.example.test\"}}}}\n"
        );
        let cfg = Config::parse(&text).expect("well-formed ech block");
        assert!(cfg.tls.ech.enabled);
        assert_eq!(cfg.tls.ech.public_name, "cover.example.test");
    }

    #[test]
    fn validation_minimal_config_parses() {
        let cfg = Config::parse(MINIMAL).expect("minimal config");
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.tls.groups[0], "SecP384r1MLKEM1024");
    }

    #[test]
    fn validation_reject_all_exit_policy_accepted() {
        let text = format!("{MINIMAL}\ntor: {{enabled: true, exit_policy: \"reject *:*\"}}\n");
        assert!(Config::parse(&text).is_ok());
    }

    #[test]
    fn validation_bundle_hash_stable_ech() {
        // Deliberate, documented behavior change: the bundle
        // hash now covers the ECH block, so configs differing
        // only in ECH settings produce different bundles.
        let a = Config::parse(MINIMAL).unwrap();
        let text = format!(
            "{MINIMAL}\ntls: {{ech: {{enabled: true, key_file: \"/tmp/ech.pem\", public_name: \"cover.example.test\"}}}}\n"
        );
        let b = Config::parse(&text).unwrap();
        assert_ne!(a.bundle_sha256(), b.bundle_sha256());
    }

    #[test]
    fn validation_bundle_hash_stable() {
        let a = Config::parse(MINIMAL).unwrap();
        let b = Config::parse(MINIMAL).unwrap();
        assert_eq!(a.bundle_sha256(), b.bundle_sha256());
        assert_eq!(a.bundle_sha256().len(), 64);
    }
}
