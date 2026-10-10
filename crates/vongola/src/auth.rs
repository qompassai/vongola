// #################################################################
// /qompassai/vongola/crates/vongola/src/auth.rs
// Qompass AI — Vongola clean-room authentication
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

//! Authentication primitives: HTTP Basic against SHA-256 password
//! hashes, HS256 JWT verification, the operator token check shared
//! by every operator surface, and log redaction.
//!
//! No function in this module logs a credential. Comparisons of
//! secrets are constant-time over the compared bytes.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::config::AuthConfig;

type HmacSha256 = Hmac<Sha256>;

/// Constant-time equality for byte strings of any length.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(text).ok())
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

/// Verify a `Basic ...` Authorization header against configured
/// users (password stored as SHA-256 hex).
pub fn check_basic(auth: &AuthConfig, authorization: Option<&str>) -> bool {
    if auth.basic_users.is_empty() {
        return true;
    }
    let Some(header) = authorization else {
        return false;
    };
    let Some(encoded) = header.strip_prefix("Basic ") else {
        return false;
    };
    let Some(raw) = b64_decode(encoded.trim()) else {
        return false;
    };
    let Ok(text) = String::from_utf8(raw) else {
        return false;
    };
    let Some((name, password)) = text.split_once(':') else {
        return false;
    };
    let candidate = sha256_hex(password.as_bytes());
    auth.basic_users.iter().any(|user| {
        user.name == name && constant_time_eq(user.password_sha256.as_bytes(), candidate.as_bytes())
    })
}

/// Verify an HS256 JWT. Returns the claims on success.
pub fn check_jwt(
    secret: &[u8],
    issuer: Option<&str>,
    authorization: Option<&str>,
    now_unix: u64,
) -> Option<serde_json::Value> {
    let header = authorization?.strip_prefix("Bearer ")?;
    let parts: Vec<&str> = header.trim().split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(signing_input.as_bytes());
    let expected = mac.finalize().into_bytes();
    let signature = b64url_decode(parts[2])?;
    if !constant_time_eq(&expected, &signature) {
        return None;
    }
    let header_json: serde_json::Value = serde_json::from_slice(&b64url_decode(parts[0])?).ok()?;
    if header_json.get("alg").and_then(|v| v.as_str()) != Some("HS256") {
        return None;
    }
    let claims: serde_json::Value = serde_json::from_slice(&b64url_decode(parts[1])?).ok()?;
    if let Some(exp) = claims.get("exp").and_then(|v| v.as_u64())
        && exp <= now_unix
    {
        return None;
    }
    if let Some(expected_issuer) = issuer
        && claims.get("iss").and_then(|v| v.as_str()) != Some(expected_issuer)
    {
        return None;
    }
    Some(claims)
}

/// Mint an HS256 JWT (used by tests and by the OAuth2 session
/// cookie flow; header/claims are caller-supplied JSON).
pub fn mint_jwt(secret: &[u8], claims: &serde_json::Value) -> String {
    let header = serde_json::json!({"alg": "HS256", "typ": "JWT"});
    let encode = |value: &serde_json::Value| -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(value).unwrap_or_default())
    };
    let signing_input = format!("{}.{}", encode(&header), encode(claims));
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    let signature =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{signature}")
}

/// Route authorization: basic OR jwt must pass when configured.
/// OAuth2 session cookies are checked by the oauth module and are
/// an alternative path handled by the proxy before calling this.
pub fn check_route_auth(
    auth: &AuthConfig,
    authorization: Option<&str>,
    jwt_secret: Option<&[u8]>,
    now_unix: u64,
) -> bool {
    if auth.is_empty() {
        return true;
    }
    let mut configured = false;
    if !auth.basic_users.is_empty() {
        configured = true;
        if check_basic(auth, authorization) {
            return true;
        }
    }
    if let Some(jwt) = &auth.jwt {
        configured = true;
        if let Some(secret) = jwt_secret
            && check_jwt(secret, jwt.issuer.as_deref(), authorization, now_unix).is_some()
        {
            return true;
        }
    }
    if auth.oauth2.is_some() {
        // OAuth2 has its own redirect/callback path in the proxy;
        // reaching this function without a session means "not yet".
        configured = true;
    }
    !configured
}

/// Operator authorization, shared by admin API, dashboard, and MCP.
/// `configured_token` is None when no token env is set: then reads
/// are allowed only from loopback binds (decided by the caller via
/// `bind_is_loopback`) and mutations are never allowed.
pub struct OperatorAuth {
    pub bind_is_loopback: bool,
    pub token: Option<String>,
}

impl OperatorAuth {
    pub fn can_read(&self, presented: Option<&str>) -> bool {
        match &self.token {
            Some(expected) => presented
                .map(|p| constant_time_eq(strip_bearer(p).as_bytes(), expected.as_bytes()))
                .unwrap_or(false),
            None => self.bind_is_loopback,
        }
    }

    pub fn can_mutate(&self, presented: Option<&str>) -> bool {
        match &self.token {
            Some(expected) => presented
                .map(|p| constant_time_eq(strip_bearer(p).as_bytes(), expected.as_bytes()))
                .unwrap_or(false),
            None => false,
        }
    }
}

fn strip_bearer(value: &str) -> &str { value.strip_prefix("Bearer ").unwrap_or(value).trim() }

/// Redact credential-shaped substrings before anything reaches a
/// log line. The logger applies this to every message; the proxy
/// additionally never formats headers into log lines at all.
pub fn redact(text: &str) -> String {
    // (marker, consume_spaces): header-style markers consume the
    // whole header value (spaces included, so `Bearer abc123`
    // after `Authorization:` is fully covered); token markers
    // consume one token.
    const MARKERS: &[(&str, bool)] = &[
        ("authorization:", true),
        ("Authorization:", true),
        ("Bearer ", false),
        ("access_token=", false),
        ("client_secret=", false),
        ("code=", false),
        ("cookie:", true),
        ("Cookie:", true),
        ("password=", false),
        ("token=", false),
    ];
    let mut out = text.to_string();
    for (marker, consume_spaces) in MARKERS {
        // Single forward pass per marker: the cursor always
        // advances past the replacement, so this terminates.
        let mut cursor = 0usize;
        while let Some(relative) = out[cursor..].find(marker) {
            let value_start = cursor + relative + marker.len();
            let mut value_end = out.len();
            for (offset, ch) in out[value_start..].char_indices() {
                let stop = if *consume_spaces {
                    matches!(ch, '&' | '"' | '\'' | ';' | '\n' | '\r')
                } else {
                    ch.is_whitespace() || matches!(ch, '&' | '"' | '\'' | ';')
                };
                if stop {
                    value_end = value_start + offset;
                    break;
                }
            }
            if value_end == value_start {
                cursor = value_start;
                continue;
            }
            out.replace_range(value_start..value_end, "[redacted]");
            cursor = value_start + "[redacted]".len();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BasicUser;

    fn auth_with_user() -> AuthConfig {
        AuthConfig {
            basic_users: vec![BasicUser {
                name: "admin".to_string(),
                password_sha256: sha256_hex(b"correct horse"),
            }],
            jwt: None,
            oauth2: None,
        }
    }

    #[test]
    fn adversarial_basic_wrong_password_denied() {
        let auth = auth_with_user();
        let header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("admin:wrong")
        );
        assert!(!check_basic(&auth, Some(&header)));
        assert!(!check_basic(&auth, None));
        assert!(!check_basic(&auth, Some("Basic !!!not-base64!!!")));
    }

    #[test]
    fn adversarial_jwt_tampered_denied() {
        let secret = b"test-secret";
        let token = mint_jwt(
            secret,
            &serde_json::json!({"sub": "a", "exp": 9_999_999_999u64}),
        );
        let mut tampered = token.clone();
        tampered.push('x');
        assert!(check_jwt(secret, None, Some(&format!("Bearer {token}")), 0).is_some());
        assert!(check_jwt(secret, None, Some(&format!("Bearer {tampered}")), 0).is_none());
        assert!(check_jwt(b"other", None, Some(&format!("Bearer {token}")), 0).is_none());
    }

    #[test]
    fn adversarial_jwt_expired_denied() {
        let secret = b"s";
        let token = mint_jwt(secret, &serde_json::json!({"exp": 10u64}));
        assert!(check_jwt(secret, None, Some(&format!("Bearer {token}")), 100).is_none());
    }

    #[test]
    fn adversarial_operator_mutation_without_token_denied() {
        let auth = OperatorAuth {
            bind_is_loopback: true,
            token: None,
        };
        assert!(auth.can_read(None));
        assert!(!auth.can_mutate(None));
        let with_token = OperatorAuth {
            bind_is_loopback: false,
            token: Some("sekret".to_string()),
        };
        assert!(!with_token.can_read(None));
        assert!(!with_token.can_mutate(Some("Bearer wrong")));
        assert!(with_token.can_mutate(Some("Bearer sekret")));
    }

    #[test]
    fn adversarial_redaction_strips_secrets() {
        let line = redact("got Authorization: Bearer abc123 and code=xyz789&state=ok token=tok");
        assert!(!line.contains("abc123"), "{line}");
        assert!(!line.contains("xyz789"), "{line}");
        assert!(!line.contains("tok\""), "{line}");
        assert!(line.contains("[redacted]"));
    }

    #[test]
    fn validation_basic_correct_password_accepted() {
        let auth = auth_with_user();
        let header = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("admin:correct horse")
        );
        assert!(check_basic(&auth, Some(&header)));
    }

    #[test]
    fn validation_constant_time_eq() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
