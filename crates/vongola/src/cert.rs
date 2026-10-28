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
use std::sync::{Arc, OnceLock};

use openssl::ex_data::Index;
use openssl::pkey::{Id, PKeyRef, Public};
use openssl::ssl::{ClientHelloResponse, Ssl, SslContextBuilder, SslRef};
use pingora::tls::pkey::PKey;
use pingora::tls::x509::X509;

use crate::config::Config;
use crate::metrics::{HandshakeGuard, TlsCounters, TlsGroup};

const SECONDS_PER_DAY: f64 = 86_400.0;

pub struct CertEntry {
    pub cert_pem: Vec<u8>,
    pub fingerprint_sha256: String,
    pub host: String,
    pub issuer: String,
    pub key_pem: Vec<u8>,
    /// notAfter as OpenSSL prints it (`openssl x509 -enddate`).
    pub not_after: String,
    pub not_after_unix: i64,
    pub self_signed: bool,
    pub subject: String,
}

impl CertEntry {
    /// Seconds from now until notAfter (negative once expired),
    /// computed at call time so gauges never go stale between
    /// reloads.
    pub fn expiry_seconds(&self) -> i64 {
        self.not_after_unix - crate::dashboard::unix_now() as i64
    }
}

pub struct CertStore {
    pub entries: BTreeMap<String, CertEntry>,
}

#[derive(serde::Serialize)]
pub struct CertInventoryItem {
    pub days_until_expiry: f64,
    pub expiry_seconds: i64,
    pub fingerprint_sha256: String,
    pub host: String,
    pub issuer: String,
    pub not_after: String,
    pub not_after_unix: i64,
    pub self_signed: bool,
    pub subject: String,
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
                        fingerprint_sha256: entry.fingerprint_sha256.clone(),
                        host: extra.clone(),
                        issuer: entry.issuer.clone(),
                        key_pem: entry.key_pem.clone(),
                        not_after: entry.not_after.clone(),
                        not_after_unix: entry.not_after_unix,
                        self_signed: entry.self_signed,
                        subject: entry.subject.clone(),
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
            .map(|entry| {
                let expiry_seconds = entry.expiry_seconds();
                CertInventoryItem {
                    days_until_expiry: expiry_seconds as f64 / SECONDS_PER_DAY,
                    expiry_seconds,
                    fingerprint_sha256: entry.fingerprint_sha256.clone(),
                    host: entry.host.clone(),
                    issuer: entry.issuer.clone(),
                    not_after: entry.not_after.clone(),
                    not_after_unix: entry.not_after_unix,
                    self_signed: entry.self_signed,
                    subject: entry.subject.clone(),
                }
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
    let not_after_unix =
        unix_seconds(cert.not_after()).map_err(|e| format!("cert notAfter for {host}: {e}"))?;
    Ok(CertEntry {
        cert_pem,
        fingerprint_sha256,
        host: host.to_string(),
        issuer: name_text(cert.issuer_name()),
        key_pem,
        not_after: cert.not_after().to_string(),
        not_after_unix,
        self_signed,
        subject: name_text(cert.subject_name()),
    })
}

/// `CN=example, O=Org` style rendering of an X.509 name, in
/// certificate order. Unconvertible entries render as `?`.
fn name_text(name: &openssl::x509::X509NameRef) -> String {
    name.entries()
        .map(|entry| {
            let key = entry.object().nid().short_name().unwrap_or("?");
            let value = entry.data().to_string().unwrap_or_else(|_| "?".to_string());
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn unix_seconds(time: &openssl::asn1::Asn1TimeRef) -> Result<i64, openssl::error::ErrorStack> {
    let epoch = openssl::asn1::Asn1Time::from_unix(0)?;
    let diff = epoch.diff(time)?;
    Ok(i64::from(diff.days) * 86_400 + i64::from(diff.secs))
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

/// The name certificate selection must use for this
/// connection. With ECH (OpenSSL 4 variant builds), an ECH
/// handshake is bound to its INNER SNI — the outer name is a
/// cover and deliberately has no certificate — so the inner
/// name wins whenever the ECH status reports one. Classical
/// connections: the SNI as sent.
fn effective_servername(ssl: &pingora::protocols::tls::TlsRef) -> Option<String> {
    #[cfg(feature = "ech")]
    if let Some(inner) = crate::ech::inner_servername(ssl) {
        return Some(inner);
    }
    ssl.servername(openssl::ssl::NameType::HOST_NAME)
        .map(|s| s.to_lowercase())
}

/// Classify the negotiated key-exchange group from the client's
/// key share for it (`SSL_get_peer_tmp_key`), using safe APIs
/// only. Classical groups carry a legacy key id (and an EC curve
/// name). The hybrid groups are provider-only keys (id -1); they
/// are told apart by their exact (bits, size) pair, measured on
/// OpenSSL 3.6.5 and pinned by the handshake tests below:
/// SecP384r1MLKEM1024 = (1024, 1665), X25519MLKEM768 = (768,
/// 1120) — size being the hybrid ciphertext length. Anything else
/// is `Unknown`, never guessed.
pub fn classify_group(key: &PKeyRef<Public>) -> TlsGroup {
    let id = key.id();
    if id == Id::X25519 {
        return TlsGroup::X25519;
    }
    if id == Id::EC {
        let curve = key.ec_key().ok().and_then(|ec| ec.group().curve_name());
        return match curve {
            Some(openssl::nid::Nid::SECP384R1) => TlsGroup::Secp384r1,
            Some(openssl::nid::Nid::X9_62_PRIME256V1) => TlsGroup::Secp256r1,
            _ => TlsGroup::Unknown,
        };
    }
    match (key.bits(), key.size()) {
        (1024, 1665) => TlsGroup::SecP384r1MlKem1024,
        (768, 1120) => TlsGroup::X25519MlKem768,
        _ => TlsGroup::Unknown,
    }
}

/// The SSL ex-data slot holding each connection's guard.
fn guard_index() -> Option<Index<Ssl, HandshakeGuard>> {
    static INDEX: OnceLock<Option<Index<Ssl, HandshakeGuard>>> = OnceLock::new();
    *INDEX.get_or_init(|| Ssl::new_ex_index().ok())
}

/// Attach handshake accounting to a listener: a ClientHello
/// callback that gives each connection one `HandshakeGuard`. It
/// always answers SUCCESS — it observes, it never changes the
/// handshake. A second ClientHello (after HelloRetryRequest)
/// finds the guard already present and leaves it alone.
pub fn install_handshake_accounting(builder: &mut SslContextBuilder, counters: Arc<TlsCounters>) {
    builder.set_client_hello_callback(move |ssl, _alert| {
        if let Some(index) = guard_index()
            && ssl.ex_data(index).is_none()
        {
            ssl.set_ex_data(index, HandshakeGuard::new(counters.clone()));
        }
        Ok(ClientHelloResponse::SUCCESS)
    });
}

/// Count a completed handshake on `ssl` by its negotiated group.
pub fn record_handshake_complete(ssl: &SslRef) {
    let group = ssl
        .peer_tmp_key()
        .map(|key| classify_group(&key))
        .unwrap_or(TlsGroup::Unknown);
    with_guard(ssl, |guard| guard.complete(group));
}

fn with_guard(ssl: &SslRef, action: impl FnOnce(&HandshakeGuard)) {
    if let Some(guard) = guard_index().and_then(|index| ssl.ex_data(index)) {
        action(guard);
    }
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
        let sni = effective_servername(ssl);
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
            with_guard(ssl, HandshakeGuard::no_certificate);
            return;
        };
        if let Some((cert, key)) = store.parsed(entry) {
            let _ = pingora::tls::ext::ssl_use_certificate(ssl, &cert);
            let _ = pingora::tls::ext::ssl_use_private_key(ssl, &key);
            with_guard(ssl, HandshakeGuard::certificate_selected);
        } else {
            with_guard(ssl, HandshakeGuard::no_certificate);
        }
    }

    async fn handshake_complete_callback(
        &self,
        ssl: &pingora::protocols::tls::TlsRef,
    ) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        record_handshake_complete(ssl);
        None
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

    /// One real loopback handshake through the accounting hooks
    /// (ClientHello guard + completion record), server allowing
    /// the full default group list. Returns the rendered TLS
    /// metrics once the server-side SSL object has been freed.
    fn handshake_metrics(
        client_groups: &str,
        client_max: openssl::ssl::SslVersion,
    ) -> (bool, String) {
        use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let generated = rcgen::CertificateParams::new(vec!["hs.test".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let cert = X509::from_pem(generated.pem().as_bytes()).unwrap();
        let key = PKey::private_key_from_pem(key_pair.serialize_pem().as_bytes()).unwrap();
        let counters = Arc::new(TlsCounters::default());
        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls()).unwrap();
        builder.set_certificate(&cert).unwrap();
        builder.set_private_key(&key).unwrap();
        builder
            .set_groups_list(&crate::config::DEFAULT_TLS_GROUPS.join(":"))
            .unwrap();
        install_handshake_accounting(&mut builder, counters.clone());
        let acceptor = builder.build();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            match acceptor.accept(socket) {
                Ok(stream) => {
                    record_handshake_complete(stream.ssl());
                    true
                }
                Err(_) => false,
            }
        });
        let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        connector.set_groups_list(client_groups).unwrap();
        connector.set_max_proto_version(Some(client_max)).unwrap();
        let socket = std::net::TcpStream::connect(address).unwrap();
        let client = connector.build().connect("hs.test", socket);
        let accepted = server.join().unwrap();
        drop(client);
        let text = crate::metrics::Metrics {
            tls: counters,
            ..crate::metrics::Metrics::default()
        }
        .render(&[]);
        (accepted, text)
    }

    fn expired_entry() -> CertEntry {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["old.test".to_string()]).unwrap();
        params.distinguished_name = {
            let mut name = rcgen::DistinguishedName::new();
            name.push(rcgen::DnType::CommonName, "old.test");
            name
        };
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(30);
        params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        let cert = params.self_signed(&key_pair).unwrap();
        entry_from_pem(
            "old.test",
            cert.pem().into_bytes(),
            key_pair.serialize_pem().into_bytes(),
            true,
        )
        .unwrap()
    }

    #[test]
    fn adversarial_expired_cert_reports_negative_expiry() {
        let entry = expired_entry();
        let seconds = entry.expiry_seconds();
        assert!(
            (-3 * 86_400..-86_400).contains(&seconds),
            "expired two days ago, got {seconds}s"
        );
        let store = CertStore {
            entries: BTreeMap::from([("old.test".to_string(), entry)]),
        };
        let item = &store.inventory()[0];
        assert!(item.days_until_expiry < -1.0);
        assert_eq!(item.expiry_seconds.signum(), -1);
    }

    #[test]
    fn adversarial_tls12_client_counted_as_failure_not_handshake() {
        let (accepted, text) =
            handshake_metrics("X25519:secp256r1", openssl::ssl::SslVersion::TLS1_2);
        assert!(
            !accepted,
            "TLS 1.3-only server must refuse a TLS 1.2 client"
        );
        assert!(
            text.contains("vongola_tls_handshake_failures_total{class=\"before_certificate\"} 1"),
            "{text}"
        );
        for group in crate::metrics::TLS_GROUPS {
            assert!(text.contains(&format!(
                "vongola_tls_handshakes_total{{group=\"{group}\"}} 0"
            )));
        }
    }

    #[test]
    fn validation_cert_metadata_matches_certificate() {
        let entry = expired_entry();
        assert_eq!(entry.subject, "CN=old.test");
        assert_eq!(entry.issuer, entry.subject, "self-signed");
        let parsed = X509::from_pem(&entry.cert_pem).unwrap();
        assert_eq!(entry.not_after, parsed.not_after().to_string());
        assert!(entry.not_after.ends_with("GMT"), "{}", entry.not_after);
    }

    #[test]
    fn validation_negotiated_group_classified_for_every_allowlisted_group() {
        for (client_groups, label, classical) in [
            ("SecP384r1MLKEM1024", "SecP384r1MLKEM1024", 0),
            ("X25519MLKEM768", "X25519MLKEM768", 0),
            ("X25519", "X25519", 1),
            ("secp256r1", "secp256r1", 1),
            ("secp384r1", "secp384r1", 1),
        ] {
            let (accepted, text) =
                handshake_metrics(client_groups, openssl::ssl::SslVersion::TLS1_3);
            assert!(accepted, "{client_groups} handshake");
            assert!(
                text.contains(&format!(
                    "vongola_tls_handshakes_total{{group=\"{label}\"}} 1"
                )),
                "{client_groups}: {text}"
            );
            assert!(text.contains("vongola_tls_handshakes_total{group=\"unknown\"} 0"));
            assert!(text.contains(&format!("vongola_tls_classical_fallback_total {classical}")));
            for class in crate::metrics::HANDSHAKE_FAILURE_CLASSES {
                assert!(text.contains(&format!(
                    "vongola_tls_handshake_failures_total{{class=\"{class}\"}} 0"
                )));
            }
        }
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
