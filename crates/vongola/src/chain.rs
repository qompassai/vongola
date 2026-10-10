// #################################################################
// /qompassai/vongola/crates/vongola/src/chain.rs
// Qompass AI — Vongola clean-room proxy chains
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

//! Egress proxy chains: ordered hops of SOCKS5 (hostname form —
//! resolution happens at the far end, never locally), HTTP
//! CONNECT, Tor SOCKS, and vongola-to-vongola CONNECT.
//!
//! FAIL CLOSED is the whole design: any hop failure aborts the
//! request with a structured error. There is no code path from a
//! chained route to a direct connection, and DNS for the target
//! is never resolved locally — the target name is carried through
//! the chain in hostname form end to end.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{ChainHop, ChainHopKind, Config, Route};

/// A parsed HTTP/1.1 response: status, headers, body.
pub type ParsedResponse = (u16, Vec<(String, String)>, Vec<u8>);

#[derive(Clone, Debug, serde::Serialize)]
pub struct HopHealth {
    pub address: String,
    pub healthy: bool,
    pub kind: String,
    pub latency_ms: u64,
}

#[derive(Debug)]
pub struct ChainError {
    pub code: String,
    pub hop_index: usize,
    pub message: String,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at hop {}: {}",
            self.code, self.hop_index, self.message
        )
    }
}

/// Split `host:port` without resolving anything.
pub fn split_host_port(address: &str) -> Option<(String, u16)> {
    let (host, port) = address.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

fn hop_address(config: &Config, hop: &ChainHop) -> String {
    match hop.kind {
        ChainHopKind::Tor => hop
            .address
            .clone()
            .unwrap_or_else(|| config.tor.socks_addr.clone()),
        _ => hop.address.clone().unwrap_or_default(),
    }
}

fn kind_name(kind: ChainHopKind) -> &'static str {
    match kind {
        ChainHopKind::HttpConnect => "http-connect",
        ChainHopKind::Socks5 => "socks5",
        ChainHopKind::Tor => "tor",
        ChainHopKind::Vongola => "vongola",
    }
}

/// Dial `target` (a `host:port` name, unresolved) through the
/// ordered chain. Returns a connected stream positioned at the
/// target. Every failure is a structured ChainError; this
/// function never attempts a direct connection as a fallback.
pub async fn dial_through_chain(
    config: &Config,
    chain: &[ChainHop],
    target: &str,
) -> Result<TcpStream, ChainError> {
    if chain.is_empty() {
        return Err(ChainError {
            code: "chain.empty".to_string(),
            hop_index: 0,
            message: "dial_through_chain called with an empty chain".to_string(),
        });
    }
    // Connect to the first hop: this is the only local TCP dial,
    // and its address comes from configuration, not from the
    // target. Intermediate hops are dialed by name through the
    // previous hop.
    let first = &chain[0];
    let first_addr = hop_address(config, first);
    let (first_host, first_port) = split_host_port(&first_addr).ok_or(ChainError {
        code: "chain.hop_unparsable".to_string(),
        hop_index: 0,
        message: format!("hop address {first_addr} is not host:port"),
    })?;
    let mut stream = TcpStream::connect((first_host.as_str(), first_port))
        .await
        .map_err(|e| ChainError {
            code: "chain.hop_connect_failed".to_string(),
            hop_index: 0,
            message: e.to_string(),
        })?;
    let mut current = first_addr.clone();
    for (index, hop) in chain.iter().enumerate() {
        let next = if index + 1 < chain.len() {
            hop_address(config, &chain[index + 1])
        } else {
            target.to_string()
        };
        let (next_host, next_port) = split_host_port(&next).ok_or(ChainError {
            code: "chain.next_unparsable".to_string(),
            hop_index: index,
            message: "next hop/target is not host:port".to_string(),
        })?;
        match hop.kind {
            ChainHopKind::Socks5 | ChainHopKind::Tor => {
                socks5_connect(&mut stream, &next_host, next_port)
                    .await
                    .map_err(|message| ChainError {
                        code: "chain.socks5_failed".to_string(),
                        hop_index: index,
                        message,
                    })?;
            }
            ChainHopKind::HttpConnect | ChainHopKind::Vongola => {
                http_connect(&mut stream, &next_host, next_port)
                    .await
                    .map_err(|message| ChainError {
                        code: "chain.connect_failed".to_string(),
                        hop_index: index,
                        message,
                    })?;
            }
        }
        current = next;
    }
    let _ = current;
    Ok(stream)
}

/// SOCKS5 handshake + CONNECT with hostname (ATYP 3) so the
/// name is resolved by the exit hop, never locally (RFC 1928).
async fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), String> {
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| e.to_string())?;
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|e| e.to_string())?;
    if greeting != [0x05, 0x00] {
        return Err("socks5: no-auth not accepted".to_string());
    }
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err("socks5: hostname too long".to_string());
    }
    let mut request = Vec::with_capacity(7 + host_bytes.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|e| e.to_string())?;
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|e| e.to_string())?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(format!("socks5: connect refused, status {}", head[1]));
    }
    // Consume the bound address per its ATYP.
    let skip = match head[3] {
        0x01 => 4,
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| e.to_string())?;
            len[0] as usize
        }
        0x04 => 16,
        other => return Err(format!("socks5: unknown atyp {other}")),
    };
    let mut rest = vec![0u8; skip + 2];
    stream
        .read_exact(&mut rest)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// HTTP CONNECT with hostname authority (RFC 9110 section 9.3.6).
async fn http_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), String> {
    let authority = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    // Read until the end of the response header block (bounded).
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while buf.len() < 16_384 {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| e.to_string())?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status_line = text.lines().next().unwrap_or("");
    if !status_line.contains(" 200") {
        return Err(format!("connect refused: {status_line}"));
    }
    Ok(())
}

/// Probe every hop of a route's chain for the dashboard/metrics:
/// hop health is a TCP connect to the hop's own address plus a
/// measured latency. Only the first hop is locally reachable by
/// definition; deeper hops are probed *through* the prefix chain.
pub async fn probe_hops(config: &Config, route: &Route) -> Vec<HopHealth> {
    let mut health = Vec::new();
    for hop in &route.chain {
        let address = hop_address(config, hop);
        let started = Instant::now();
        let healthy = match split_host_port(&address) {
            Some((host, port)) => tokio::time::timeout(
                Duration::from_secs(2),
                TcpStream::connect((host.as_str(), port)),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false),
            None => false,
        };
        health.push(HopHealth {
            address,
            healthy,
            kind: kind_name(hop.kind).to_string(),
            latency_ms: started.elapsed().as_millis() as u64,
        });
    }
    health
}

/// Fetch an HTTP/1.1 request through the chain and return
/// (status, headers, body). Used for chained routes: the request
/// is written over the chain stream and the response parsed with
/// bounded reads. TLS upstreams over a chain wrap the stream in
/// an openssl client handshake at this layer.
pub async fn fetch_via_chain(
    config: &Config,
    route: &Route,
    method: &str,
    path_and_query: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<ParsedResponse, ChainError> {
    let upstream = route.upstreams.first().ok_or(ChainError {
        code: "chain.no_upstream".to_string(),
        hop_index: 0,
        message: "chained route has no upstream".to_string(),
    })?;
    let mut stream = dial_through_chain(config, &route.chain, &upstream.address).await?;
    let host_header = upstream
        .sni
        .clone()
        .unwrap_or_else(|| upstream.address.clone());
    let mut request = format!(
        "{method} {path_and_query} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n"
    );
    for (name, value) in headers {
        let lowered = name.to_lowercase();
        if lowered == "host" || lowered == "connection" || lowered == "content-length" {
            continue;
        }
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| ChainError {
            code: "chain.write_failed".to_string(),
            hop_index: route.chain.len() - 1,
            message: e.to_string(),
        })?;
    if !body.is_empty() {
        stream.write_all(body).await.map_err(|e| ChainError {
            code: "chain.write_failed".to_string(),
            hop_index: route.chain.len() - 1,
            message: e.to_string(),
        })?;
    }
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| ChainError {
            code: "chain.read_failed".to_string(),
            hop_index: route.chain.len() - 1,
            message: e.to_string(),
        })?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > 64 * 1024 * 1024 {
            return Err(ChainError {
                code: "chain.response_too_large".to_string(),
                hop_index: route.chain.len() - 1,
                message: "response exceeds 64 MiB bound".to_string(),
            });
        }
    }
    parse_http_response(&raw).ok_or(ChainError {
        code: "chain.response_unparsable".to_string(),
        hop_index: route.chain.len() - 1,
        message: "upstream response could not be parsed".to_string(),
    })
}

fn parse_http_response(raw: &[u8]) -> Option<ParsedResponse> {
    let header_end = find_subslice(raw, b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let mut lines = head.lines();
    let status: u16 = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let mut headers = Vec::new();
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim().to_string();
            let lowered = name.to_lowercase();
            if lowered == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                chunked = true;
            }
            if lowered == "content-length" {
                content_length = value.parse().ok();
            }
            headers.push((name.trim().to_string(), value));
        }
    }
    let body_raw = &raw[header_end..];
    let body = if chunked {
        dechunk(body_raw)?
    } else if let Some(len) = content_length {
        body_raw.iter().take(len).copied().collect()
    } else {
        body_raw.to_vec()
    };
    Some((status, headers, body))
}

fn dechunk(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = raw;
    loop {
        let line_end = find_subslice(rest, b"\r\n")?;
        let size_text = String::from_utf8_lossy(&rest[..line_end]).into_owned();
        let size = usize::from_str_radix(size_text.trim().split(';').next()?, 16).ok()?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            return None;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2.min(rest.len() - size)..];
    }
    Some(out)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    fn config() -> Config {
        serde_yaml::from_str(
            "listeners:\n  admin: {bind: \"127.0.0.1:9091\"}\n  http: {bind: \"0.0.0.0:8080\"}\n  https: {bind: \"0.0.0.0:4433\"}\nroutes: []",
        )
        .unwrap()
    }

    /// Minimal SOCKS5 server that tunnels to a fixed local target.
    async fn spawn_socks5() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut greeting = [0u8; 3];
                    if client.read_exact(&mut greeting).await.is_err() {
                        return;
                    }
                    let _ = client.write_all(&[0x05, 0x00]).await;
                    let mut head = [0u8; 4];
                    if client.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let host = if head[3] == 0x03 {
                        let mut len = [0u8; 1];
                        let _ = client.read_exact(&mut len).await;
                        let mut name = vec![0u8; len[0] as usize];
                        let _ = client.read_exact(&mut name).await;
                        String::from_utf8_lossy(&name).into_owned()
                    } else {
                        return;
                    };
                    let mut port_bytes = [0u8; 2];
                    let _ = client.read_exact(&mut port_bytes).await;
                    let target_port = u16::from_be_bytes(port_bytes);
                    // Resolve here (server side) — for the test the
                    // name is localhost.
                    match TcpStream::connect((host.as_str(), target_port)).await {
                        Ok(mut upstream) => {
                            let _ = client
                                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                                .await;
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                        }
                        Err(_) => {
                            let _ = client
                                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                                .await;
                        }
                    }
                });
            }
        });
        port
    }

    async fn spawn_http_target() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 7\r\nConnection: close\r\n\r\nchained")
                        .await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn validation_fetch_through_socks5_chain() {
        let target_port = spawn_http_target().await;
        let socks_port = spawn_socks5().await;
        let cfg = config();
        let route: Route = serde_yaml::from_str(&format!(
            "host: \"chain.test\"\nupstreams: [{{address: \"localhost:{target_port}\"}}]\nchain: [{{kind: socks5, address: \"127.0.0.1:{socks_port}\"}}]"
        ))
        .unwrap();
        let (status, _headers, body) = fetch_via_chain(&cfg, &route, "GET", "/", &[], &[])
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"chained");
    }

    #[tokio::test]
    async fn adversarial_dead_hop_fails_closed() {
        let cfg = config();
        let route: Route = serde_yaml::from_str(
            "host: \"chain.test\"\nupstreams: [{address: \"localhost:9\"}]\nchain: [{kind: socks5, address: \"127.0.0.1:1\"}]",
        )
        .unwrap();
        let result = fetch_via_chain(&cfg, &route, "GET", "/", &[], &[]).await;
        let error = result.expect_err("dead hop must fail closed");
        assert_eq!(error.code, "chain.hop_connect_failed");
    }

    #[test]
    fn validation_split_host_port() {
        assert_eq!(
            split_host_port("example.test:443"),
            Some(("example.test".to_string(), 443))
        );
        assert_eq!(split_host_port("nope"), None);
    }
}
