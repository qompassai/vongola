// #################################################################
// /qompassai/vongola/crates/vongola/src/oauth.rs
// Qompass AI — Vongola clean-room OAuth2 support
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

//! OAuth2 authorization-code support.
//!
//! The previous tree's published security finding was that its
//! OAuth2 state blob was obfuscation, not cryptography. Here the
//! state token is `base64url(payload).base64url(HMAC-SHA256)`
//! where payload carries the return path and an issued-at
//! timestamp, rejected after 120 seconds — the same lifetime the
//! old book documented, now with real integrity protection.
//! Session cookies after a successful callback are HS256 JWTs
//! (auth.rs) signed with the same deployment secret discipline.
//! Authorization codes are never logged anywhere (auth::redact
//! is also applied by the logger as a second belt).

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::auth::constant_time_eq;

type HmacSha256 = Hmac<Sha256>;

pub const STATE_MAX_AGE_SECS: u64 = 120;
pub const SESSION_COOKIE: &str = "vongola_session";

pub fn create_state(secret: &[u8], return_to: &str, now_unix: u64) -> String {
    let payload = serde_json::json!({"iat": now_unix, "return_to": return_to});
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(encoded.as_bytes());
    let signature =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{encoded}.{signature}")
}

/// Verify a state token and return the stored return path.
pub fn verify_state(secret: &[u8], state: &str, now_unix: u64) -> Option<String> {
    let (encoded, signature) = state.split_once('.')?;
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(encoded.as_bytes());
    let expected = mac.finalize().into_bytes();
    let given = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature)
        .ok()?;
    if !constant_time_eq(&expected, &given) {
        return None;
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    let issued_at = payload.get("iat")?.as_u64()?;
    if now_unix.saturating_sub(issued_at) > STATE_MAX_AGE_SECS {
        return None;
    }
    payload
        .get("return_to")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Build the provider authorization redirect URL. The `code`
/// never transits our logs: this URL contains only client_id,
/// redirect_uri, scope, and the state token.
pub fn authorize_url(
    authorize_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
) -> String {
    format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&state={}",
        authorize_endpoint,
        url_encode(client_id),
        url_encode(redirect_uri),
        url_encode(state)
    )
}

pub fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Exchange an authorization code at the provider token
/// endpoint (form-encoded POST over HTTPS via openssl). Returns
/// the access token. The code and the client secret are used
/// here and nowhere else; neither is logged.
pub async fn exchange_code(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<String, String> {
    let body = format!(
        "client_id={}&client_secret={}&code={}&redirect_uri={}&grant_type=authorization_code",
        url_encode(client_id),
        url_encode(client_secret),
        url_encode(code),
        url_encode(redirect_uri)
    );
    let response = https_post_form(token_url, &body).await?;
    let parsed: serde_json::Value =
        serde_json::from_str(&response).map_err(|e| format!("token response: {e}"))?;
    parsed
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "token response has no access_token".to_string())
}

/// Minimal HTTPS POST for provider endpoints, using the openssl
/// crate directly (the proxy data path does not depend on this).
async fn https_post_form(url: &str, body: &str) -> Result<String, String> {
    let stripped = url
        .strip_prefix("https://")
        .ok_or("token_url must be https")?;
    let (host_port, path) = match stripped.split_once('/') {
        Some((host, rest)) => (host.to_string(), format!("/{rest}")),
        None => (stripped.to_string(), "/".to_string()),
    };
    let (host, _port) =
        crate::chain::split_host_port(&host_port).ok_or("token_url host unparsable")?;
    let body = body.to_string();
    let path_clone = path.clone();
    let host_port_clone = host_port.clone();
    tokio::task::spawn_blocking(move || {
        use openssl::ssl::{SslConnector, SslMethod};
        use std::io::{Read, Write};
        let stream = std::net::TcpStream::connect(&host_port_clone)
            .map_err(|e| format!("token connect: {e}"))?;
        let connector = SslConnector::builder(SslMethod::tls())
            .map_err(|e| format!("token tls: {e}"))?
            .build();
        let mut tls = connector
            .connect(&host, stream)
            .map_err(|e| format!("token handshake: {e}"))?;
        let request = format!(
            "POST {path_clone} HTTP/1.1\r\nHost: {host_port_clone}\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(request.as_bytes())
            .map_err(|e| format!("token write: {e}"))?;
        let mut raw = String::new();
        tls.read_to_string(&mut raw)
            .map_err(|e| format!("token read: {e}"))?;
        Ok(raw
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or("")
            .to_string())
    })
    .await
    .map_err(|e| format!("token task: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_state_tamper_rejected() {
        let secret = b"state-secret";
        let state = create_state(secret, "/dashboard", 1000);
        assert_eq!(
            verify_state(secret, &state, 1010).as_deref(),
            Some("/dashboard")
        );
        let mut tampered = state.clone();
        tampered.replace_range(0..1, "A");
        if tampered == state {
            tampered.push('x');
        }
        assert!(verify_state(secret, &tampered, 1010).is_none());
        assert!(verify_state(b"wrong", &state, 1010).is_none());
    }

    #[test]
    fn adversarial_state_expires_after_120s() {
        let secret = b"s";
        let state = create_state(secret, "/", 1000);
        assert!(verify_state(secret, &state, 1000 + STATE_MAX_AGE_SECS).is_some());
        assert!(verify_state(secret, &state, 1000 + STATE_MAX_AGE_SECS + 1).is_none());
    }

    #[test]
    fn validation_authorize_url_shape() {
        let url = authorize_url(
            "https://provider.test/authorize",
            "cid",
            "https://qompass.ai/oauth/callback",
            "st",
        );
        assert!(url.contains("response_type=code"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fqompass.ai%2Foauth%2Fcallback"));
        assert!(!url.contains("secret"));
    }
}
