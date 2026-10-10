// #################################################################
// /qompassai/vongola/crates/vongola/src/proxy.rs
// Qompass AI — Vongola clean-room proxy core
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

//! The HTTPS data path (Pingora ProxyHttp): SNI has already
//! selected a certificate at the TLS layer; here requests are
//! routed by host/path to static content, a chained fetch, or a
//! pooled upstream — with auth, body bounds, security headers,
//! request IDs, and metrics on every path.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::Result;
use pingora::http::ResponseHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::config::{Config, Route};
use crate::state::State;
use crate::static_site::StaticCache;
use crate::upstream::{RouteRuntime, select_upstream};

pub struct Ctx {
    pub host: String,
    pub request_id: String,
    pub route_name: String,
    pub started: Instant,
    pub status: u16,
}

pub struct VongolaProxy {
    pub runtime: Arc<RouteRuntime>,
    pub state: Arc<State>,
    pub static_caches: BTreeMap<String, StaticCache>,
}

impl VongolaProxy {
    pub fn new(state: Arc<State>) -> VongolaProxy {
        let config = state.config_snapshot();
        let mut static_caches = BTreeMap::new();
        for route in &config.routes {
            if route.static_root.is_some() {
                static_caches.insert(route.display_name(), StaticCache::new());
            }
        }
        VongolaProxy {
            runtime: Arc::new(RouteRuntime::new(&config)),
            state,
            static_caches,
        }
    }

    fn cache_for(&self, route: &Route) -> StaticCache {
        // StaticCache is not Clone; per-request fallback is a
        // fresh cache when the map lacks the route (post-reload
        // routes). The startup map covers configured routes.
        let _ = route;
        StaticCache::new()
    }
}

fn request_host(session: &Session) -> String {
    let req = session.req_header();
    if let Some(host) = req.headers.get("host").and_then(|v| v.to_str().ok()) {
        return host.split(':').next().unwrap_or("").to_lowercase();
    }
    req.uri.host().unwrap_or("").to_lowercase()
}

fn now_unix() -> u64 { crate::dashboard::unix_now() }

async fn write_json(session: &mut Session, status: u16, value: serde_json::Value) {
    let body = serde_json::to_vec(&value).unwrap_or_default();
    let _ = session
        .respond_error_with_body(status, Bytes::from(body))
        .await;
}

#[async_trait]
impl ProxyHttp for VongolaProxy {
    type CTX = Ctx;

    fn new_ctx(&self) -> Self::CTX {
        Ctx {
            host: String::new(),
            request_id: String::new(),
            route_name: String::new(),
            started: Instant::now(),
            status: 0,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let config = self.state.config_snapshot();
        let host = request_host(session);
        ctx.host = host.clone();
        let (path, query, method, headers_snapshot) = {
            let req = session.req_header();
            (
                req.uri.path().to_string(),
                req.uri.query().unwrap_or("").to_string(),
                req.method.to_string(),
                req.headers.clone(),
            )
        };
        ctx.request_id = headers_snapshot
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.state.next_request_id());

        // www -> apex redirect (hosting profile).
        if let Some(apex) = host.strip_prefix("www.")
            && let Some(route) = config.routes.iter().find(|r| r.host == apex)
            && route.redirect_www_to_apex
            && route.additional_hosts.contains(&host)
        {
            let https_port = config
                .listeners
                .https
                .bind
                .rsplit(':')
                .next()
                .unwrap_or("4433");
            let authority = if https_port == "443" {
                apex.to_string()
            } else {
                format!("{apex}:{https_port}")
            };
            let location = format!(
                "https://{authority}{}",
                session
                    .req_header()
                    .uri
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or(&path)
            );
            let mut header = ResponseHeader::build(308, Some(2))?;
            header.insert_header("Location", location)?;
            header.insert_header("X-Request-Id", ctx.request_id.clone())?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(Bytes::new()), true)
                .await?;
            ctx.status = 308;
            ctx.route_name = route.display_name();
            return Ok(true);
        }

        let Some(route) = config.route_for(&host, &path).cloned() else {
            ctx.status = 404;
            write_json(
                session,
                404,
                serde_json::json!({"error": {"code": "route.not_found", "host": host, "path": path}}),
            )
            .await;
            return Ok(true);
        };
        ctx.route_name = route.display_name();

        // A2A agent card on this host.
        if path == crate::a2a::AGENT_CARD_PATH && (route.a2a_enabled || config.a2a.enabled) {
            match crate::a2a::signed_card(&config, &host, &format!("https://{host}/")) {
                Ok(card) => {
                    ctx.status = 200;
                    let body = serde_json::to_vec(&card).unwrap_or_default();
                    let mut header = ResponseHeader::build(200, Some(2))?;
                    header.insert_header("Content-Type", "application/json")?;
                    header.insert_header("Content-Length", body.len())?;
                    session
                        .write_response_header(Box::new(header), false)
                        .await?;
                    session
                        .write_response_body(Some(Bytes::from(body)), true)
                        .await?;
                }
                Err(message) => {
                    ctx.status = 500;
                    write_json(
                        session,
                        500,
                        serde_json::json!({"error": {"code": "a2a.sign_failed", "message": message}}),
                    )
                    .await;
                }
            }
            return Ok(true);
        }

        // Body bound, checked from Content-Length before any
        // upstream work.
        if let Some(length) = headers_snapshot
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            && length > route.max_body_bytes
        {
            ctx.status = 413;
            write_json(
                    session,
                    413,
                    serde_json::json!({"error": {"code": "request.body_too_large", "limit": route.max_body_bytes}}),
                )
                .await;
            return Ok(true);
        }

        // Authentication (basic / JWT / OAuth2 session).
        if !route.auth.is_empty()
            && let Some(handled) = self
                .check_auth(session, ctx, &config, &route, &path, &query)
                .await
        {
            return Ok(handled);
        }

        // Static hosting.
        if route.static_root.is_some() {
            let accept_gzip = headers_snapshot
                .get("accept-encoding")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.contains("gzip"))
                .unwrap_or(false);
            let cache = self
                .static_caches
                .get(&route.display_name())
                .map(|_| self.cache_for(&route));
            let _ = cache;
            let owned_cache = StaticCache::new();
            let cache_ref = self
                .static_caches
                .get(&route.display_name())
                .unwrap_or(&owned_cache);
            let response = crate::static_site::serve(&route, cache_ref, &path, accept_gzip);
            if response.from_cache {
                self.state
                    .metrics
                    .cache_hits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else if response.status == 200 {
                self.state
                    .metrics
                    .cache_misses
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            ctx.status = response.status;
            let mut header = ResponseHeader::build(response.status, Some(6))?;
            header.insert_header("Content-Type", response.content_type.clone())?;
            header.insert_header("Cache-Control", response.cache_control.clone())?;
            header.insert_header("Content-Length", response.body.len())?;
            header.insert_header("X-Request-Id", ctx.request_id.clone())?;
            if response.from_cache {
                header.insert_header("X-Vongola-Cache", "HIT")?;
            } else {
                header.insert_header("X-Vongola-Cache", "MISS")?;
            }
            if let Some(encoding) = &response.content_encoding {
                header.insert_header("Content-Encoding", encoding.clone())?;
            }
            if route.security_headers {
                insert_security_headers(&mut header)?;
            }
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(Bytes::from(response.body)), true)
                .await?;
            return Ok(true);
        }

        // Chained egress: fetch through the chain, fail closed.
        if !route.chain.is_empty() {
            let mut body = Vec::new();
            while let Ok(Some(chunk)) = session.read_request_body().await {
                body.extend_from_slice(&chunk);
                if body.len() as u64 > route.max_body_bytes {
                    ctx.status = 413;
                    write_json(
                        session,
                        413,
                        serde_json::json!({"error": {"code": "request.body_too_large"}}),
                    )
                    .await;
                    return Ok(true);
                }
            }
            let headers: Vec<(String, String)> = headers_snapshot
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
                .collect();
            let path_and_query = if query.is_empty() {
                path.clone()
            } else {
                format!("{path}?{query}")
            };
            match crate::chain::fetch_via_chain(
                &config,
                &route,
                &method,
                &path_and_query,
                &headers,
                &body,
            )
            .await
            {
                Ok((status, upstream_headers, upstream_body)) => {
                    ctx.status = status;
                    let mut header =
                        ResponseHeader::build(status, Some(upstream_headers.len() + 4))?;
                    for (name, value) in &upstream_headers {
                        let lowered = name.to_lowercase();
                        if lowered == "connection"
                            || lowered == "transfer-encoding"
                            || lowered == "content-length"
                        {
                            continue;
                        }
                        let _ = header.insert_header(name.clone(), value.clone());
                    }
                    header.insert_header("Content-Length", upstream_body.len())?;
                    header.insert_header("X-Request-Id", ctx.request_id.clone())?;
                    if route.security_headers {
                        insert_security_headers(&mut header)?;
                    }
                    session
                        .write_response_header(Box::new(header), false)
                        .await?;
                    session
                        .write_response_body(Some(Bytes::from(upstream_body)), true)
                        .await?;
                }
                Err(error) => {
                    self.state
                        .metrics
                        .chain_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    log::warn!(
                        "chain: route {} failed closed: {}",
                        route.display_name(),
                        error
                    );
                    ctx.status = 502;
                    write_json(
                        session,
                        502,
                        serde_json::json!({"error": {"code": error.code, "hop": error.hop_index, "message": error.message}}),
                    )
                    .await;
                }
            }
            return Ok(true);
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let config = self.state.config_snapshot();
        let Some(route) = config
            .routes
            .iter()
            .find(|r| r.display_name() == ctx.route_name)
        else {
            return Err(pingora::Error::explain(
                pingora::ErrorType::ConnectError,
                "route vanished between filter and peer selection",
            ));
        };
        let Some(upstream) = select_upstream(&self.state, &self.runtime, route) else {
            return Err(pingora::Error::explain(
                pingora::ErrorType::ConnectError,
                "no healthy upstream available",
            ));
        };
        let sni = upstream.sni.clone().unwrap_or_else(|| route.host.clone());
        let mut peer = HttpPeer::new(upstream.address.clone(), upstream.tls, sni);
        peer.options.connection_timeout = Some(std::time::Duration::from_secs(5));
        peer.options.total_connection_timeout = Some(std::time::Duration::from_secs(10));
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        upstream_request.insert_header("X-Request-Id", ctx.request_id.clone())?;
        upstream_request.insert_header("X-Forwarded-Host", ctx.host.clone())?;
        upstream_request.insert_header("X-Forwarded-Proto", "https")?;
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        ctx.status = upstream_response.status.as_u16();
        upstream_response.remove_header("server");
        upstream_response.insert_header("X-Request-Id", ctx.request_id.clone())?;
        let config = self.state.config_snapshot();
        if let Some(route) = config
            .routes
            .iter()
            .find(|r| r.display_name() == ctx.route_name)
            && route.security_headers
        {
            insert_security_headers(upstream_response)?;
        }
        Ok(())
    }

    async fn logging(
        &self,
        session: &mut Session,
        error: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let status = if ctx.status != 0 {
            ctx.status
        } else if error.is_some() {
            502
        } else {
            session
                .response_written()
                .map(|response| response.status.as_u16())
                .unwrap_or(0)
        };
        let latency_ms = ctx.started.elapsed().as_millis() as u64;
        if status != 0 {
            self.state.metrics.record_request(
                if ctx.route_name.is_empty() {
                    "unmatched"
                } else {
                    &ctx.route_name
                },
                status,
                latency_ms,
            );
        }
        log::info!(
            "access: {} {} -> {} in {}ms",
            ctx.request_id,
            ctx.host,
            status,
            latency_ms
        );
    }
}

fn insert_security_headers(header: &mut ResponseHeader) -> Result<()> {
    header.insert_header("Referrer-Policy", "strict-origin-when-cross-origin")?;
    header.insert_header(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    )?;
    header.insert_header("X-Content-Type-Options", "nosniff")?;
    header.insert_header("X-Frame-Options", "DENY")?;
    Ok(())
}

impl VongolaProxy {
    /// Returns Some(true) when the request was fully handled
    /// (redirect written or an error response sent), Some(false)
    /// never, and None when authentication passed.
    async fn check_auth(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        config: &Config,
        route: &Route,
        path: &str,
        query: &str,
    ) -> Option<bool> {
        let authorization = session
            .req_header()
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        // OAuth2: redirect dance + session cookie.
        if let Some(oauth) = &route.auth.oauth2 {
            let state_secret = std::env::var(&oauth.state_secret_env).unwrap_or_default();
            let cookie_header = session
                .req_header()
                .headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if let Some(token) = cookie_value(&cookie_header, crate::oauth::SESSION_COOKIE)
                && crate::auth::check_jwt(
                    state_secret.as_bytes(),
                    None,
                    Some(&format!("Bearer {token}")),
                    now_unix(),
                )
                .is_some()
            {
                return None;
            }
            if path == oauth.redirect_path {
                let params = parse_query(query);
                let code = params.get("code").cloned().unwrap_or_default();
                let state_value = params.get("state").cloned().unwrap_or_default();
                if let Some(return_to) =
                    crate::oauth::verify_state(state_secret.as_bytes(), &state_value, now_unix())
                {
                    let client_secret = std::env::var(&oauth.client_secret_env).unwrap_or_default();
                    let redirect_uri = format!("https://{}{}", ctx.host, oauth.redirect_path);
                    match crate::oauth::exchange_code(
                        &oauth.token_url,
                        &oauth.client_id,
                        &client_secret,
                        &code,
                        &redirect_uri,
                    )
                    .await
                    {
                        Ok(_access_token) => {
                            // The access token is used to mint the
                            // session and is then dropped — never
                            // logged, never stored client-side.
                            let session_jwt = crate::auth::mint_jwt(
                                state_secret.as_bytes(),
                                &serde_json::json!({"exp": now_unix() + 3600, "sub": "oauth2-user"}),
                            );
                            let mut header =
                                ResponseHeader::build(302, Some(3)).expect("response header");
                            let _ = header.insert_header("Location", return_to);
                            let _ = header.insert_header(
                                "Set-Cookie",
                                format!(
                                    "{}={session_jwt}; HttpOnly; Secure; Path=/; SameSite=Lax",
                                    crate::oauth::SESSION_COOKIE
                                ),
                            );
                            let _ = session.write_response_header(Box::new(header), false).await;
                            let _ = session.write_response_body(Some(Bytes::new()), true).await;
                            ctx.status = 302;
                            return Some(true);
                        }
                        Err(message) => {
                            log::warn!("oauth2: token exchange failed: {message}");
                            ctx.status = 502;
                            write_json(
                                session,
                                502,
                                serde_json::json!({"error": {"code": "oauth2.exchange_failed"}}),
                            )
                            .await;
                            return Some(true);
                        }
                    }
                }
                ctx.status = 400;
                write_json(
                    session,
                    400,
                    serde_json::json!({"error": {"code": "oauth2.state_invalid"}}),
                )
                .await;
                return Some(true);
            }
            // Not authenticated: start the dance.
            let return_to = session
                .req_header()
                .uri
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            let state_value =
                crate::oauth::create_state(state_secret.as_bytes(), &return_to, now_unix());
            let redirect_uri = format!("https://{}{}", ctx.host, oauth.redirect_path);
            let location = crate::oauth::authorize_url(
                &oauth.authorize_url,
                &oauth.client_id,
                &redirect_uri,
                &state_value,
            );
            if let Ok(mut header) = ResponseHeader::build(302, Some(2)) {
                let _ = header.insert_header("Location", location);
                let _ = session.write_response_header(Box::new(header), false).await;
                let _ = session.write_response_body(Some(Bytes::new()), true).await;
            }
            ctx.status = 302;
            return Some(true);
        }
        // Basic / JWT.
        let jwt_secret = route
            .auth
            .jwt
            .as_ref()
            .and_then(|jwt| std::env::var(&jwt.secret_env).ok());
        let _ = config;
        if crate::auth::check_route_auth(
            &route.auth,
            authorization.as_deref(),
            jwt_secret.as_deref().map(|s| s.as_bytes()),
            now_unix(),
        ) {
            return None;
        }
        ctx.status = 401;
        if let Ok(mut header) = ResponseHeader::build(401, Some(2)) {
            let _ = header.insert_header("WWW-Authenticate", "Basic realm=\"vongola\"");
            let _ = header.insert_header("Content-Type", "application/json");
            let body = Bytes::from_static(b"{\"error\":{\"code\":\"auth.required\"}}");
            let _ = header.insert_header("Content-Length", body.len());
            let _ = session.write_response_header(Box::new(header), false).await;
            let _ = session.write_response_body(Some(body), true).await;
        }
        Some(true)
    }
}

fn cookie_value(cookie_header: &str, name: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{name}=")) {
            return Some(value.to_string());
        }
    }
    None
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            map.insert(key.to_string(), percent_decode(value));
        }
    }
    map
}

fn percent_decode(text: &str) -> String {
    let bytes = text.replace('+', " ").into_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                out.push(value);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
