// #################################################################
// /qompassai/vongola/crates/vongola/src/ech.rs
// Qompass AI — Vongola ECH startup (OpenSSL 4 variant builds)
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

//! ECH (RFC 9849) startup for the OpenSSL 4 variant build
//! (cargo feature `ech`; this module does not exist in other
//! builds — main.rs refuses to start there when ECH is
//! enabled).
//!
//! `prepare` runs before any listener starts and is fail
//! closed: every problem — unreadable key file, malformed
//! PEM, a key file whose public name disagrees with the
//! config, an unwritable key path — is a startup error, never
//! a silent fallback to serving without ECH.
//!
//! Key lifecycle: when the configured key file is absent, a
//! fresh ECH keypair+config is generated for
//! `tls.ech.public_name` and persisted (0600) so restarts
//! keep the published config stable; the publishable
//! ECHConfigList (base64) is rewritten to
//! `<state_dir>/ech/echconfiglist.b64` on every start and
//! mirrored into shared state for the dashboard.

use std::fs;
use std::path::{Path, PathBuf};

use foreign_types_shared::ForeignTypeRef;
use pingora::listeners::tls::TlsSettings;
use vongola_ech::{EchStore, HpkeSuite, MAX_PEM_BYTES};

use crate::config::Config;
use crate::state::EchPublic;

pub struct PreparedEch {
    pub public: EchPublic,
    pub store: EchStore,
}

// Manual Debug: the store wraps private key material and must
// never be printable; only the public half is shown.
impl std::fmt::Debug for PreparedEch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedEch")
            .field("public", &self.public)
            .field("store", &"<redacted>")
            .finish()
    }
}

pub fn prepare(config: &Config) -> Result<PreparedEch, String> {
    let ech = &config.tls.ech;
    // Config validation guarantees key_file is Some when
    // enabled; this guard keeps prepare() sound on its own.
    let key_file: PathBuf = ech
        .key_file
        .clone()
        .ok_or_else(|| "tls.ech.key_file is required when ECH is enabled".to_string())?;
    // The store that gets attached is ALWAYS loaded from the
    // persisted PEM bytes — on a restart and on first start
    // alike. (Empirical, OpenSSL 4.0.3: a store used in-memory
    // straight from OSSL_ECHSTORE_new_config does not decrypt
    // client ECH, while the same material reloaded from its
    // serialized form does. Loading what was persisted also
    // makes first-start behavior identical to restart behavior
    // by construction.)
    let pem = if key_file.exists() {
        read_bounded(&key_file)?
    } else {
        let mut generated = EchStore::new().map_err(|error| format!("ECH store: {error}"))?;
        generated
            .generate(&ech.public_name, 0, HpkeSuite::DEFAULT)
            .map_err(|error| format!("ECH key generation: {error}"))?;
        let pem = generated
            .entry_pem(0)
            .map_err(|error| format!("ECH key serialization: {error}"))?;
        write_key_file(&key_file, &pem)?;
        pem
    };
    let mut store = EchStore::new().map_err(|error| format!("ECH store: {error}"))?;
    store
        .load_pem(&pem, true)
        .map_err(|error| format!("ECH key file {}: {error}", key_file.to_string_lossy()))?;
    let keys = store
        .num_keys()
        .map_err(|error| format!("ECH key file {}: {error}", key_file.to_string_lossy()))?;
    if keys == 0 {
        return Err(format!(
            "ECH key file {} holds no private key; refusing to start",
            key_file.to_string_lossy()
        ));
    }
    let entries = store
        .num_entries()
        .map_err(|error| format!("ECH store: {error}"))?;
    if entries == 0 {
        return Err("ECH store holds no config entries; refusing to start".to_string());
    }
    let info = store
        .entry_info(0)
        .map_err(|error| format!("ECH store: {error}"))?;
    if !info.public_name.eq_ignore_ascii_case(&ech.public_name) {
        return Err(format!(
            "ECH key file public name {} does not match tls.ech.public_name {}; refusing to start",
            info.public_name, ech.public_name
        ));
    }
    let config_list_base64 = store
        .config_list_base64()
        .map_err(|error| format!("ECH config list: {error}"))?;
    write_config_list(config, &config_list_base64)?;
    Ok(PreparedEch {
        public: EchPublic {
            config_list_base64,
            public_name: ech.public_name.clone(),
        },
        store,
    })
}

/// The inner SNI of the ECH connection on `ssl`, when the
/// client offered ECH: the name the handshake is bound to
/// (the outer name is a cover and deliberately has no
/// certificate). Certificate selection uses this when
/// present. `None` for classical connections and whenever
/// the status cannot be determined — selection then uses
/// the sent SNI, exactly as before ECH existed.
pub fn inner_servername(ssl: &pingora::protocols::tls::TlsRef) -> Option<String> {
    // SAFETY: `ssl` is a live connection owned by Pingora's
    // accept loop; OpenSSL has already decrypted the inner
    // ClientHello when certificate selection runs, so the
    // status query is authoritative here, and it only reads.
    let status = unsafe { vongola_ech::connection_status(ssl.as_ptr()) };
    status.inner_sni.map(|name| name.to_lowercase())
}

/// Attach the store to the HTTPS listener's SSL_CTX and
/// install the ECH status callback (metrics counters — the
/// callback is the only place rejected attempts are
/// observable; see the vongola-ech status module docs).
/// `TlsSettings` derefs mutably to Pingora's
/// `SslAcceptorBuilder`; the openssl crate exposes the raw
/// context pointer through `as_ptr` — the documented seam the
/// spike identified (SPEC section 15).
pub fn attach(settings: &mut TlsSettings, store: &EchStore) -> Result<(), String> {
    // SAFETY: `settings` is alive for the whole call and owns
    // the SSL_CTX until `add_tls_with_settings` consumes the
    // builder; OpenSSL deep-copies the store, so no reference
    // to `store` outlives the call.
    unsafe { store.attach_to_ctx(settings.as_ptr()) }
        .map_err(|error| format!("ECH attach: {error}"))?;
    // SAFETY: same context-lifetime argument as above; the
    // callback is a static function in the binding crate.
    unsafe { vongola_ech::install_ctx_status_callback(settings.as_ptr()) };
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("read {}: {error}", path.to_string_lossy()))?;
    if bytes.len() > MAX_PEM_BYTES {
        return Err(format!(
            "ECH key file {} exceeds the {}-byte bound",
            path.to_string_lossy(),
            MAX_PEM_BYTES
        ));
    }
    Ok(bytes)
}

fn write_key_file(path: &Path, pem: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create ECH key dir {}: {error}", parent.to_string_lossy()))?;
    }
    write_0600(path, pem)
}

fn write_config_list(config: &Config, config_list_base64: &str) -> Result<(), String> {
    let dir = config.state_dir.join("ech");
    fs::create_dir_all(&dir)
        .map_err(|error| format!("create ECH state dir {}: {error}", dir.to_string_lossy()))?;
    let path = dir.join("echconfiglist.b64");
    fs::write(&path, format!("{config_list_base64}\n"))
        .map_err(|error| format!("write ECH config list {}: {error}", path.to_string_lossy()))
}

#[cfg(unix)]
fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("create ECH key file {}: {error}", path.to_string_lossy()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write ECH key file {}: {error}", path.to_string_lossy()))
}

#[cfg(not(unix))]
fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("write {}: {error}", path.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(dir: &Path, key_file: &Path, public_name: &str) -> Config {
        let text = format!(
            "listeners:\n  admin: {{bind: \"127.0.0.1:9091\"}}\n  http: {{bind: \"0.0.0.0:8080\"}}\n  https: {{bind: \"0.0.0.0:4433\"}}\nroutes:\n  - host: \"x.test\"\n    upstreams: [{{address: \"127.0.0.1:9000\"}}]\nstate_dir: \"{}\"\ntls:\n  ech: {{enabled: true, key_file: \"{}\", public_name: \"{}\"}}\n",
            dir.to_string_lossy(),
            key_file.to_string_lossy(),
            public_name
        );
        Config::parse(&text).expect("test config parses")
    }

    #[test]
    fn adversarial_prepare_fails_when_key_cannot_be_persisted() {
        // Parent path is an existing regular file: generation
        // succeeds, persistence cannot — startup must fail,
        // not serve ECH from memory alone.
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let key_file = blocker.join("ech.pem");
        let config = test_config(dir.path(), &key_file, "cover.example.test");
        assert!(prepare(&config).is_err());
    }

    #[test]
    fn adversarial_prepare_fails_when_key_file_is_directory() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path(), dir.path(), "cover.example.test");
        assert!(prepare(&config).is_err());
    }

    #[test]
    fn adversarial_prepare_rejects_malformed_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("ech.pem");
        std::fs::write(&key_file, b"-----BEGIN GARBAGE-----\nAAAA\n").unwrap();
        let config = test_config(dir.path(), &key_file, "cover.example.test");
        let error = prepare(&config).expect_err("malformed key must fail");
        assert!(error.contains("ECH key file"), "unexpected error: {error}");
    }

    #[test]
    fn adversarial_prepare_rejects_public_name_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("ech.pem");
        let first = test_config(dir.path(), &key_file, "cover.example.test");
        prepare(&first).expect("first prepare");
        let second = test_config(dir.path(), &key_file, "other.example.test");
        let error = prepare(&second).expect_err("name mismatch must fail");
        assert!(
            error.contains("does not match"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn validation_prepare_generates_persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("nested").join("ech.pem");
        let config = test_config(dir.path(), &key_file, "cover.example.test");
        let first = prepare(&config).expect("first prepare generates");
        assert!(key_file.exists(), "key file persisted");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be 0600");
        }
        let published = std::fs::read_to_string(dir.path().join("ech").join("echconfiglist.b64"))
            .expect("config list emitted to state dir");
        assert_eq!(published.trim(), first.public.config_list_base64);
        let second = prepare(&config).expect("second prepare loads");
        assert_eq!(
            first.public.config_list_base64, second.public.config_list_base64,
            "restart keeps the published config stable"
        );
    }

    #[test]
    fn validation_prepare_public_material_matches_store() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("ech.pem");
        let config = test_config(dir.path(), &key_file, "cover.example.test");
        let mut prepared = prepare(&config).expect("prepare");
        assert_eq!(prepared.public.public_name, "cover.example.test");
        assert_eq!(
            prepared.store.config_list_base64().unwrap(),
            prepared.public.config_list_base64
        );
    }
}
