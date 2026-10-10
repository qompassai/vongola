// #################################################################
// /qompassai/vongola/crates/vongola/src/admin.rs
// Qompass AI — Vongola clean-room admin listener
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

//! The admin listener: metrics, dashboard, operator API, and
//! MCP-over-HTTP, all behind the one operator auth posture
//! (auth::OperatorAuth). It binds loopback by default and is
//! never attached to a public listener. `/healthz` is the only
//! unauthenticated endpoint and reveals nothing but liveness.

use std::sync::Arc;

use http::{Response, StatusCode};
use pingora::apps::http_app::ServeHttp;
use pingora::protocols::http::ServerSession;

use crate::auth::OperatorAuth;
use crate::state::State;

pub struct AdminApp {
    pub auth: OperatorAuth,
    pub state: Arc<State>,
}

pub struct RedirectApp {
    pub state: Arc<State>,
}

fn response(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response<Vec<u8>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONTENT_LENGTH, body.len())
        .body(body)
        .unwrap_or_else(|_| Response::new(Vec::new()))
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Vec<u8>> {
    response(
        status,
        "application/json",
        serde_json::to_vec(&value).unwrap_or_default(),
    )
}

/// Extract the presented operator token: Bearer value, or the
/// password half of HTTP Basic (so browsers can authenticate to
/// the dashboard with the token as the password).
fn presented_token(headers: &http::HeaderMap) -> Option<String> {
    let header = headers.get("authorization")?.to_str().ok()?;
    if let Some(token) = header.strip_prefix("Bearer ") {
        return Some(token.trim().to_string());
    }
    if let Some(encoded) = header.strip_prefix("Basic ") {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?;
        let text = String::from_utf8(raw).ok()?;
        let (_user, password) = text.split_once(':')?;
        return Some(password.to_string());
    }
    None
}

async fn read_body(session: &mut ServerSession) -> Vec<u8> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = session.read_request_body().await {
        body.extend_from_slice(&chunk);
        if body.len() > 1024 * 1024 {
            break;
        }
    }
    body
}

#[async_trait::async_trait]
impl ServeHttp for AdminApp {
    async fn response(&self, http_stream: &mut ServerSession) -> Response<Vec<u8>> {
        let (method, path, headers) = {
            let req = http_stream.req_header();
            (
                req.method.clone(),
                req.uri.path().to_string(),
                req.headers.clone(),
            )
        };
        let presented = presented_token(&headers);
        let presented_ref = presented.as_deref();
        match (method.as_str(), path.as_str()) {
            ("GET", "/healthz") => json_response(
                StatusCode::OK,
                serde_json::json!({"status": "ok", "node": self.state.config_snapshot().node_name}),
            ),
            ("GET", "/metrics") => {
                if !self.auth.can_read(presented_ref) {
                    return unauthorized();
                }
                let text = self.state.metrics.render(&self.state.extra_gauges());
                response(
                    StatusCode::OK,
                    "text/plain; version=0.0.4",
                    text.into_bytes(),
                )
            }
            ("GET", "/api/state") => {
                if !self.auth.can_read(presented_ref) {
                    return unauthorized();
                }
                json_response(StatusCode::OK, crate::dashboard::state_json(&self.state))
            }
            ("GET", "/dashboard") => {
                if !self.auth.can_read(presented_ref) {
                    return unauthorized();
                }
                response(
                    StatusCode::OK,
                    "text/html; charset=utf-8",
                    crate::dashboard::DASHBOARD_HTML.as_bytes().to_vec(),
                )
            }
            ("POST", "/api/reload") => {
                if !self.auth.can_mutate(presented_ref) {
                    return unauthorized();
                }
                match self.state.reload() {
                    Ok(bundle) => json_response(
                        StatusCode::OK,
                        serde_json::json!({"bundle_sha256": bundle, "reloaded": true}),
                    ),
                    Err(errors) => json_response(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        serde_json::json!({"errors": errors, "reloaded": false}),
                    ),
                }
            }
            ("POST", "/api/rotate-self-signed") => {
                if !self.auth.can_mutate(presented_ref) {
                    return unauthorized();
                }
                let body = read_body(http_stream).await;
                let parsed: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                let host = parsed.get("host").and_then(|v| v.as_str()).unwrap_or("");
                let config = self.state.config_snapshot();
                match crate::cert::rotate_self_signed(&config, host).and_then(|_| {
                    self.state
                        .reload()
                        .map(|_| ())
                        .map_err(|errors| format!("reload after rotate: {errors:?}"))
                }) {
                    Ok(()) => json_response(StatusCode::OK, serde_json::json!({"rotated": host})),
                    Err(message) => json_response(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        serde_json::json!({"error": message}),
                    ),
                }
            }
            ("POST", "/mcp") => {
                let body = read_body(http_stream).await;
                let Ok(request) = serde_json::from_slice::<serde_json::Value>(&body) else {
                    return json_response(
                        StatusCode::BAD_REQUEST,
                        serde_json::json!({"error": "invalid json"}),
                    );
                };
                let reply =
                    crate::mcp::handle_jsonrpc(&self.state, &self.auth, presented_ref, &request);
                if reply.is_null() {
                    return response(StatusCode::ACCEPTED, "application/json", Vec::new());
                }
                json_response(StatusCode::OK, reply)
            }
            _ => json_response(
                StatusCode::NOT_FOUND,
                serde_json::json!({"error": "not found"}),
            ),
        }
    }
}

fn unauthorized() -> Response<Vec<u8>> {
    let mut reply = json_response(
        StatusCode::UNAUTHORIZED,
        serde_json::json!({"error": "operator authorization required"}),
    );
    reply.headers_mut().insert(
        http::header::WWW_AUTHENTICATE,
        http::HeaderValue::from_static("Basic realm=\"vongola-admin\""),
    );
    reply
}

#[async_trait::async_trait]
impl ServeHttp for RedirectApp {
    async fn response(&self, http_stream: &mut ServerSession) -> Response<Vec<u8>> {
        let config = self.state.config_snapshot();
        let (uri, host_header) = {
            let req = http_stream.req_header();
            (
                req.uri.clone(),
                req.headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string(),
            )
        };
        let path = uri.path();
        // ACME HTTP-01 challenges are served here (SPEC section 7).
        if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
            let challenges = self.state.acme_challenges.read();
            if let Ok(map) = &challenges
                && let Some(key_authorization) = map.get(token)
            {
                return response(
                    StatusCode::OK,
                    "text/plain",
                    key_authorization.clone().into_bytes(),
                );
            }
            return response(
                StatusCode::NOT_FOUND,
                "text/plain",
                b"unknown challenge".to_vec(),
            );
        }
        // Agent card discovery also works over HTTP.
        if path == crate::a2a::AGENT_CARD_PATH && config.a2a.enabled {
            let host = host_header.split(':').next().unwrap_or("localhost");
            if let Ok(card) = crate::a2a::signed_card(&config, host, &format!("https://{host}/")) {
                return json_response(StatusCode::OK, card);
            }
        }
        // Everything else: 308 to the same host/path on HTTPS.
        let https_port = config
            .listeners
            .https
            .bind
            .rsplit(':')
            .next()
            .unwrap_or("4433")
            .to_string();
        let host_name = host_header.split(':').next().unwrap_or("localhost");
        let location = format!(
            "https://{host_name}:{https_port}{}",
            uri.path_and_query().map(|pq| pq.as_str()).unwrap_or(path)
        );
        let mut reply = response(StatusCode::PERMANENT_REDIRECT, "text/plain", Vec::new());
        if let Ok(value) = http::HeaderValue::from_str(&location) {
            reply.headers_mut().insert(http::header::LOCATION, value);
        }
        reply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_presented_token_forms() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "authorization",
            http::HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(presented_token(&headers).as_deref(), Some("abc"));
        headers.insert(
            "authorization",
            http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(presented_token(&headers).as_deref(), Some("pass"));
        headers.clear();
        assert!(presented_token(&headers).is_none());
    }

    #[test]
    fn adversarial_unauthorized_shape() {
        let reply = unauthorized();
        assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
        assert!(reply.headers().contains_key(http::header::WWW_AUTHENTICATE));
    }
}
