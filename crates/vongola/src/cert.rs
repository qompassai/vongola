// #################################################################
// /qompassai/vongola/crates/vongola/src/cert.rs
// Qompass AI — Vongola clean-room certificate store
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

//! Certificate store: exact-SNI selection over operator-supplied
//! PEM files, plus a per-route self-signed fallback that exists
//! only when the route explicitly opts in. Keys on disk are 0600.
//! No certificate is ever served for a name it does not cover:
//! unknown SNI with no fallback fails the handshake.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use pingora::tls::pkey::PKey;
use pingora::tls::x509::X509;

use crate::config::Config;

pub struct CertEntry {
    pub cert_pem: Vec<u8>,
    pub days_until_expiry: f64,
    pub fingerprint_sha256: String,
    pub host: String,
    pub key_pem: Vec<u8>,
    pub self_signed: bool,
}

pub struct CertStore {
    pub entries: BTreeMap<String, CertEntry>,
}

#[derive(serde::Serialize)]
pub struct CertInventoryItem {
    pub days_until_expiry: f64,
    pub fingerprint_sha256: String,
    pub host: String,
    pub self_signed: bool,
}

impl CertStore {
    pub fn build(config: &Config) -> Result<CertStore, String> {
        let mut entries: BTreeMap<String, CertEntry> = BTreeMap::new();
        for route in &config.routes {
            if let (Some(cert_path), Some(key_path)) = (&route.tls_cert, &route.tls_key) {
                let entry = load_entry(&route.host, cert_path, key_path, false)?;
                entries.insert(route.host.clone(), entry);
            } else if route.self_signed_fallback {
                let entry = self_signed_entry(config, &route.host)?;
                entries.insert(route.host.clone(), entry);
            }
            for extra in &route.additional_hosts {
                if let Some(entry) = entries.get(&route.host) {
                    let clone = CertEntry {
                        cert_pem: entry.cert_pem.clone(),
                        days_until_expiry: entry.days_until_expiry,
                        fingerprint_sha256: entry.fingerprint_sha256.clone(),
                        host: extra.clone(),
                        key_pem: entry.key_pem.clone(),
                        self_signed: entry.self_signed,
                    };
                    entries.entry(extra.clone()).or_insert(clone);
                }
            }
        }
        Ok(CertStore { entries })
    }

    pub fn get(&self, sni: &str) -> Option<&CertEntry> { self.entries.get(&sni.to_lowercase()) }

    pub fn default_entry(&self) -> Option<&CertEntry> { self.entries.values().next() }

    /// Inventory for operator surfaces: metadata only, never keys.
    pub fn inventory(&self) -> Vec<CertInventoryItem> {
        self.entries
            .values()
            .map(|entry| CertInventoryItem {
                days_until_expiry: entry.days_until_expiry,
                fingerprint_sha256: entry.fingerprint_sha256.clone(),
                host: entry.host.clone(),
                self_signed: entry.self_signed,
            })
            .collect()
    }

    /// Parse PEM into an openssl cert + key pair for the TLS
    /// accept callback.
    pub fn parsed(&self, entry: &CertEntry) -> Option<(X509, PKey<openssl::pkey::Private>)> {
        let cert = X509::from_pem(&entry.cert_pem).ok()?;
        let key = PKey::private_key_from_pem(&entry.key_pem).ok()?;
        Some((cert, key))
    }
}

fn load_entry(
    host: &str,
    cert_path: &Path,
    key_path: &Path,
    self_signed: bool,
) -> Result<CertEntry, String> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| format!("cert for {host}: cannot read {:?}: {e}", cert_path))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| format!("key for {host}: cannot read {:?}: {e}", key_path))?;
    entry_from_pem(host, cert_pem, key_pem, self_signed)
}

fn entry_from_pem(
    host: &str,
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    self_signed: bool,
) -> Result<CertEntry, String> {
    let cert = X509::from_pem(&cert_pem).map_err(|e| format!("cert for {host}: {e}"))?;
    let fingerprint = cert
        .digest(openssl::hash::MessageDigest::sha256())
        .map_err(|e| format!("cert digest for {host}: {e}"))?;
    let fingerprint_sha256 = fingerprint
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let days_until_expiry = days_until(cert.not_after());
    Ok(CertEntry {
        cert_pem,
        days_until_expiry,
        fingerprint_sha256,
        host: host.to_string(),
        key_pem,
        self_signed,
    })
}

fn days_until(not_after: &openssl::asn1::Asn1TimeRef) -> f64 {
    let now = openssl::asn1::Asn1Time::days_from_now(0).expect("asn1 time");
    let diff = now.diff(not_after).expect("asn1 diff");
    diff.days as f64 + (diff.secs as f64 / 86_400.0)
}

/// Generate (or reuse) the self-signed fallback certificate for a
/// host under `<state_dir>/certs/<host>.{crt,key}`. ECDSA P-384,
/// one year, key file 0600. Generation happens once; an existing
/// pair is reused so clients see a stable certificate.
pub fn self_signed_entry(config: &Config, host: &str) -> Result<CertEntry, String> {
    let dir: PathBuf = config.state_dir.join("certs");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create cert dir: {e}"))?;
    let safe_host = host.replace(['/', '\\', ':'], "_");
    let cert_path = dir.join(format!("{safe_host}.crt"));
    let key_path = dir.join(format!("{safe_host}.key"));
    if cert_path.exists() && key_path.exists() {
        return load_entry(host, &cert_path, &key_path, true);
    }
    let mut params = rcgen::CertificateParams::new(vec![host.to_string()])
        .map_err(|e| format!("self-signed params for {host}: {e}"))?;
    params.not_before = time_now();
    params.not_after = time_plus_days(365);
    params.distinguished_name = {
        let mut name = rcgen::DistinguishedName::new();
        name.push(rcgen::DnType::CommonName, host);
        name
    };
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        .map_err(|e| format!("self-signed keygen for {host}: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("self-signed cert for {host}: {e}"))?;
    let cert_pem = cert.pem().into_bytes();
    let key_pem = key_pair.serialize_pem().into_bytes();
    std::fs::write(&cert_path, &cert_pem).map_err(|e| format!("write cert: {e}"))?;
    write_key_0600(&key_path, &key_pem)?;
    entry_from_pem(host, cert_pem, key_pem, true)
}

fn time_now() -> time::OffsetDateTime { time::OffsetDateTime::now_utc() }

fn time_plus_days(days: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::days(days)
}

#[cfg(unix)]
fn write_key_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("write key {:?}: {e}", path))?;
    file.write_all(bytes)
        .map_err(|e| format!("write key {:?}: {e}", path))
}

#[cfg(not(unix))]
fn write_key_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("write key {:?}: {e}", path))
}

/// Rotate a route's self-signed fallback certificate: delete
/// the persisted pair so the next build regenerates it. Refuses
/// for routes without the fallback (operator certs are the
/// operator's own material and are never deleted here).
pub fn rotate_self_signed(config: &Config, host: &str) -> Result<(), String> {
    let route = config
        .routes
        .iter()
        .find(|r| r.host == host)
        .ok_or_else(|| format!("no route for host {host}"))?;
    if !route.self_signed_fallback || route.tls_cert.is_some() {
        return Err(format!(
            "route {host} does not use a self-signed fallback certificate"
        ));
    }
    let dir: PathBuf = config.state_dir.join("certs");
    let safe_host = host.replace(['/', '\\', ':'], "_");
    for extension in ["crt", "key"] {
        let path = dir.join(format!("{safe_host}.{extension}"));
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("rotate remove: {e}"))?;
        }
    }
    // Regenerate immediately so the store build that follows
    // (the caller reloads) has a fresh pair on disk.
    let _ = self_signed_entry(config, host)?;
    Ok(())
}

/// TLS accept callback: exact-SNI certificate selection. Falls
/// back to the default (first) entry only when the client sent no
/// SNI at all; a wrong certificate is never served.
pub struct SniCertSelector {
    pub store: std::sync::Arc<std::sync::RwLock<std::sync::Arc<CertStore>>>,
}

#[async_trait::async_trait]
impl pingora::listeners::TlsAccept for SniCertSelector {
    async fn certificate_callback(&self, ssl: &mut pingora::protocols::tls::TlsRef) {
        let sni = ssl
            .servername(openssl::ssl::NameType::HOST_NAME)
            .map(|s| s.to_lowercase());
        let store = match self.store.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return,
        };
        let entry = match &sni {
            Some(name) => store.get(name),
            None => store.default_entry(),
        };
        let Some(entry) = entry else {
            // No certificate for this name and no fallback: leave
            // the handshake to fail rather than serve a wrong cert.
            return;
        };
        if let Some((cert, key)) = store.parsed(entry) {
            let _ = pingora::tls::ext::ssl_use_certificate(ssl, &cert);
            let _ = pingora::tls::ext::ssl_use_private_key(ssl, &key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Route;

    fn route_with_fallback() -> Route {
        serde_yaml::from_str(
            "host: \"fallback.test\"\nself_signed_fallback: true\nupstreams: [{address: \"127.0.0.1:9000\"}]",
        )
        .unwrap()
    }

    #[test]
    fn validation_self_signed_generated_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let mut config: Config = serde_yaml::from_str(&format!(
            "listeners:\n  admin: {{bind: \"127.0.0.1:9091\"}}\n  http: {{bind: \"0.0.0.0:8080\"}}\n  https: {{bind: \"0.0.0.0:4433\"}}\nstate_dir: \"{}\"\nroutes: []",
            dir.path().to_string_lossy()
        ))
        .unwrap();
        config.routes.push(route_with_fallback());
        let store = CertStore::build(&config).unwrap();
        let item = store
            .inventory()
            .into_iter()
            .find(|item| item.host == "fallback.test")
            .expect("inventory entry");
        assert!(
            item.days_until_expiry > 300.0,
            "fresh self-signed cert must have ~365 days left, got {}",
            item.days_until_expiry
        );
        let first = store.get("fallback.test").expect("entry");
        assert!(first.self_signed);
        assert_eq!(first.fingerprint_sha256.len(), 64);
        let key_path = dir.path().join("certs/fallback.test.key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key must be 0600");
        }
        let store2 = CertStore::build(&config).unwrap();
        assert_eq!(
            store2.get("fallback.test").unwrap().fingerprint_sha256,
            first.fingerprint_sha256,
            "existing pair must be reused"
        );
    }

    #[test]
    fn adversarial_unknown_sni_has_no_entry() {
        let config: Config = serde_yaml::from_str(
            "listeners:\n  admin: {bind: \"127.0.0.1:9091\"}\n  http: {bind: \"0.0.0.0:8080\"}\n  https: {bind: \"0.0.0.0:4433\"}\nroutes:\n  - host: \"known.test\"\n    upstreams: [{address: \"127.0.0.1:9000\"}]",
        )
        .unwrap();
        let store = CertStore::build(&config).unwrap();
        assert!(store.get("evil.test").is_none());
        assert!(store.get("known.test").is_none(), "no cert configured");
    }
}
