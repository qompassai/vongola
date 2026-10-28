// #################################################################
// /qompassai/vongola/crates/vongola/src/a2a.rs
// Qompass AI — Vongola clean-room A2A agent card
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

//! A2A agent card: a signed JSON document served at
//! `/.well-known/agent-card.json` describing the services this
//! node hosts. The signing key is an Ed25519 keypair in the state
//! directory (0600), generated on first use; an operator may
//! provision a key minted elsewhere (e.g. by a dedicated key
//! service) by dropping the file in — vongola consumes keys as
//! files and couples to nothing.
//!
//! The signature covers the canonical card JSON (sorted keys)
//! with the `signatures` field removed.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;

use crate::config::Config;

pub const AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";

pub fn key_path(state_dir: &Path) -> PathBuf { state_dir.join("a2a").join("agent-card.key") }

/// Load the signing key, generating and persisting one (0600)
/// when absent and generation is permitted by the caller.
pub fn load_or_create_key(state_dir: &Path) -> Result<SigningKey, String> {
    let path = key_path(state_dir);
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(|e| format!("a2a key read: {e}"))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "a2a key must be 32 raw bytes".to_string())?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("a2a dir: {e}"))?;
    }
    write_0600(&path, &seed)?;
    Ok(key)
}

#[cfg(unix)]
fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("a2a key write: {e}"))?;
    file.write_all(bytes)
        .map_err(|e| format!("a2a key write: {e}"))
}

#[cfg(not(unix))]
fn write_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("a2a key write: {e}"))
}

/// Build the (unsigned) card body for this node + host.
pub fn card_body(config: &Config, host: &str, base_url: &str) -> serde_json::Value {
    let mut skills: Vec<serde_json::Value> = config
        .a2a
        .skills
        .iter()
        .map(|skill| serde_json::json!({"id": skill, "name": skill}))
        .collect();
    if skills.is_empty() {
        skills.push(serde_json::json!({"id": "reverse-proxy", "name": "reverse-proxy"}));
    }
    serde_json::json!({
        "capabilities": {"streaming": false},
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "description": "Vongola fleet node: reverse proxy and web server with MCP/A2A operator surfaces.",
        "name": config.a2a.name.clone(),
        "protocolVersion": "0.3.0",
        "skills": skills,
        "url": base_url,
        "version": env!("CARGO_PKG_VERSION"),
        "x-vongola": {
            "bundle_version": config.bundle_version.clone(),
            "host": host,
            "node_name": config.node_name.clone(),
        }
    })
}

pub fn canonical_json(value: &serde_json::Value) -> String {
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

/// Build and sign the card for serving. The returned JSON is the
/// card with a `signatures` array carrying the Ed25519 signature
/// (base64url) and the public key (base64url).
pub fn signed_card(
    config: &Config,
    host: &str,
    base_url: &str,
) -> Result<serde_json::Value, String> {
    let key = load_or_create_key(&config.state_dir)?;
    let body = card_body(config, host, base_url);
    let canonical = canonical_json(&body);
    let signature = key.sign(canonical.as_bytes());
    let encode = |bytes: &[u8]| {
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
    };
    let mut card = body;
    card["signatures"] = serde_json::json!([{
        "algorithm": "Ed25519",
        "protected": "a2a-agent-card/v1",
        "public_key": encode(key.verifying_key().as_bytes()),
        "signature": encode(&signature.to_bytes()),
    }]);
    Ok(card)
}

/// Verify a signed card (used by fleet peers and tests).
/// Exercised by the test-suite; the serving path only signs.
#[allow(dead_code)]
pub fn verify_card(card: &serde_json::Value) -> bool { verify_card_inner(card).unwrap_or(false) }

fn verify_card_inner(card: &serde_json::Value) -> Option<bool> {
    let signatures = card.get("signatures").and_then(|s| s.as_array())?;
    let first = signatures.first()?;
    let decode = |field: &str| -> Option<Vec<u8>> {
        base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            first.get(field)?.as_str()?,
        )
        .ok()
    };
    let public_bytes = decode("public_key")?;
    let signature_bytes = decode("signature")?;
    let public_array: [u8; 32] = public_bytes.try_into().ok()?;
    let signature_array: [u8; 64] = signature_bytes.try_into().ok()?;
    let verifying = VerifyingKey::from_bytes(&public_array).ok()?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);
    let mut body = card.clone();
    if let Some(object) = body.as_object_mut() {
        object.remove("signatures");
    }
    Some(
        verifying
            .verify(canonical_json(&body).as_bytes(), &signature)
            .is_ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_in(dir: &std::path::Path) -> Config {
        serde_yaml::from_str(&format!(
            "listeners:\n  admin: {{bind: \"127.0.0.1:9091\"}}\n  http: {{bind: \"0.0.0.0:8080\"}}\n  https: {{bind: \"0.0.0.0:4433\"}}\nstate_dir: \"{}\"\na2a: {{enabled: true}}\nroutes: []",
            dir.to_string_lossy()
        ))
        .unwrap()
    }

    #[test]
    fn validation_signed_card_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let card = signed_card(&config, "qompass.ai", "https://qompass.ai/").unwrap();
        assert!(verify_card(&card));
        let key_file = key_path(dir.path());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn adversarial_tampered_card_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(dir.path());
        let mut card = signed_card(&config, "qompass.ai", "https://qompass.ai/").unwrap();
        card["name"] = serde_json::json!("evil-twin");
        assert!(!verify_card(&card));
        let mut stripped = card.clone();
        stripped.as_object_mut().unwrap().remove("signatures");
        assert!(!verify_card(&stripped));
    }
}
