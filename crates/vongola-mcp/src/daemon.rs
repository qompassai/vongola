// #################################################################
// /qompassai/vongola/crates/vongola-mcp/src/daemon.rs
// Qompass AI — vongola-mcp daemon client
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

//! The only data path: HTTP GETs against the running daemon's
//! admin listener (`/api/state`, `/metrics`), resolved from the
//! daemon's own config file on every call. Nothing is cached:
//! when the daemon cannot be read, the caller gets a structured
//! error, never a remembered or invented value.
//!
//! Operator-local by contract: the admin address must be
//! loopback (an unspecified bind such as `0.0.0.0` is dialled
//! on loopback); any other address is refused before a socket is
//! opened, so the operator token never crosses a network on this
//! plain-HTTP path. The token is read from the env var the config
//! names, sent only as a Bearer header, and never echoed.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_TOKEN_ENV: &str = "VONGOLA_OPERATOR_TOKEN";
pub const IO_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, PartialEq)]
pub struct DaemonError {
    pub code: &'static str,
    pub message: String,
}

impl DaemonError {
    fn new(code: &'static str, message: impl Into<String>) -> DaemonError {
        DaemonError {
            code,
            message: message.into(),
        }
    }
}

/// Anything the tools can read daemon surfaces from. The real
/// implementation is `ConfigSource`; tests substitute fixtures.
pub trait Source {
    fn get(&self, path: &str) -> Result<String, DaemonError>;
}

/// Where to dial and which env var holds the token, as read from
/// the daemon config.
#[derive(Debug, PartialEq)]
pub struct Endpoint {
    pub address: SocketAddr,
    pub token_env: String,
}

/// Resolves the endpoint from the config file on every call.
pub struct ConfigSource {
    pub config_path: PathBuf,
}

impl Source for ConfigSource {
    fn get(&self, path: &str) -> Result<String, DaemonError> {
        let endpoint = endpoint_from_file(&self.config_path)?;
        let token = std::env::var(&endpoint.token_env)
            .ok()
            .filter(|token| !token.is_empty());
        http_get(endpoint.address, path, token.as_deref())
    }
}

pub fn endpoint_from_file(path: &Path) -> Result<Endpoint, DaemonError> {
    let file = std::fs::File::open(path).map_err(|e| {
        DaemonError::new(
            "config.unreadable",
            format!("cannot open {}: {e}", path.to_string_lossy()),
        )
    })?;
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| {
            DaemonError::new(
                "config.unreadable",
                format!("cannot read {}: {e}", path.to_string_lossy()),
            )
        })?;
    if text.len() as u64 > MAX_CONFIG_BYTES {
        return Err(DaemonError::new(
            "config.too_large",
            format!("config exceeds {MAX_CONFIG_BYTES} bytes"),
        ));
    }
    endpoint_from_text(&text)
}

/// Read only `listeners.admin.{bind,enabled}` and
/// `admin_token_env`; full validation is the daemon's job.
pub fn endpoint_from_text(text: &str) -> Result<Endpoint, DaemonError> {
    let document: serde_yaml::Value = serde_yaml::from_str(text)
        .map_err(|e| DaemonError::new("config.invalid", format!("config YAML: {e}")))?;
    let admin = document
        .get("listeners")
        .and_then(|listeners| listeners.get("admin"))
        .ok_or_else(|| DaemonError::new("config.invalid", "listeners.admin is missing"))?;
    if admin.get("enabled").and_then(|value| value.as_bool()) == Some(false) {
        return Err(DaemonError::new(
            "config.admin_disabled",
            "listeners.admin.enabled is false; the daemon serves no admin surfaces",
        ));
    }
    let bind = admin
        .get("bind")
        .and_then(|value| value.as_str())
        .ok_or_else(|| DaemonError::new("config.invalid", "listeners.admin.bind is missing"))?;
    let token_env = match document.get("admin_token_env") {
        None => DEFAULT_TOKEN_ENV.to_string(),
        Some(value) => value
            .as_str()
            .ok_or_else(|| DaemonError::new("config.invalid", "admin_token_env must be a string"))?
            .to_string(),
    };
    Ok(Endpoint {
        address: dial_address(bind)?,
        token_env,
    })
}

/// The address to dial for an admin bind: loopback as-is,
/// unspecified mapped to loopback of the same family, anything
/// else refused.
pub fn dial_address(bind: &str) -> Result<SocketAddr, DaemonError> {
    let address: SocketAddr = bind.parse().map_err(|_| {
        DaemonError::new(
            "config.admin_bind_invalid",
            format!("listeners.admin.bind {bind:?} is not an IP:port address"),
        )
    })?;
    let ip = address.ip();
    if ip.is_loopback() {
        return Ok(address);
    }
    if ip.is_unspecified() {
        let loopback = match ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        return Ok(SocketAddr::new(loopback, address.port()));
    }
    Err(DaemonError::new(
        "daemon.not_loopback",
        format!("admin listener {address} is not loopback; vongola-mcp is operator-local only"),
    ))
}

pub fn http_get(
    address: SocketAddr,
    path: &str,
    token: Option<&str>,
) -> Result<String, DaemonError> {
    if !address.ip().is_loopback() {
        return Err(DaemonError::new(
            "daemon.not_loopback",
            format!("{address} is not loopback"),
        ));
    }
    // A control character in the token would split the header
    // block (request smuggling into the admin listener).
    if token.is_some_and(|token| token.chars().any(char::is_control)) {
        return Err(DaemonError::new(
            "config.token_invalid",
            "the operator token contains control characters",
        ));
    }
    let unavailable = |e: std::io::Error| {
        DaemonError::new(
            "daemon.unavailable",
            format!("vongola admin listener at {address}: {e}"),
        )
    };
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT).map_err(unavailable)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(unavailable)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(unavailable)?;
    let mut request =
        format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nAccept: */*\r\n");
    if let Some(token) = token {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).map_err(unavailable)?;
    let raw = read_bounded(&mut stream).map_err(unavailable)?;
    parse_response(&raw)
}

/// Read until EOF or until a complete Content-Length body is in,
/// never past `MAX_RESPONSE_BYTES + 1` bytes.
fn read_bounded(stream: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut raw: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    while raw.len() <= MAX_RESPONSE_BYTES {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);
        if let Some((head_len, Some(length))) = head_and_length(&raw)
            && raw.len() >= head_len + length
        {
            break;
        }
    }
    Ok(raw)
}

/// (header length including the blank line, Content-Length).
fn head_and_length(raw: &[u8]) -> Option<(usize, Option<usize>)> {
    let end = raw.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&raw[..end]);
    let length = head.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    Some((end, length))
}

/// Accept exactly one shape: HTTP/1.x 200 with an identity body.
pub fn parse_response(raw: &[u8]) -> Result<String, DaemonError> {
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(DaemonError::new(
            "daemon.response_too_large",
            format!("response exceeds {MAX_RESPONSE_BYTES} bytes"),
        ));
    }
    let malformed = |message: &str| DaemonError::new("daemon.malformed_response", message);
    let (head_len, length) =
        head_and_length(raw).ok_or_else(|| malformed("no complete HTTP header"))?;
    let head = String::from_utf8_lossy(&raw[..head_len]);
    let status_line = head.lines().next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    let status = parts.next().and_then(|code| code.parse::<u16>().ok());
    if !version.starts_with("HTTP/1.") {
        return Err(malformed("not an HTTP/1.x response"));
    }
    let chunked = head.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && !value.trim().eq_ignore_ascii_case("identity")
        })
    });
    if chunked {
        return Err(DaemonError::new(
            "daemon.unsupported_encoding",
            "transfer-encoded responses are not accepted",
        ));
    }
    match status {
        Some(200) => {}
        Some(401) => {
            return Err(DaemonError::new(
                "daemon.unauthorized",
                "admin listener requires the operator token (set the env var named by admin_token_env)",
            ));
        }
        Some(code) => {
            return Err(DaemonError::new(
                "daemon.http_status",
                format!("admin listener answered HTTP {code}"),
            ));
        }
        None => return Err(malformed("unparseable status line")),
    }
    let body = &raw[head_len..];
    let body = match length {
        Some(length) if body.len() < length => {
            return Err(malformed("body shorter than Content-Length"));
        }
        Some(length) => &body[..length],
        None => body,
    };
    String::from_utf8(body.to_vec()).map_err(|_| malformed("body is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_chunked_and_short_bodies_rejected() {
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(
            parse_response(chunked).unwrap_err().code,
            "daemon.unsupported_encoding"
        );
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        assert_eq!(
            parse_response(short).unwrap_err().code,
            "daemon.malformed_response"
        );
        let garbage = b"SSH-2.0-OpenSSH_9.9\r\n\r\n";
        assert_eq!(
            parse_response(garbage).unwrap_err().code,
            "daemon.malformed_response"
        );
        let mut huge = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        huge.resize(MAX_RESPONSE_BYTES + 1, b'x');
        assert_eq!(
            parse_response(&huge).unwrap_err().code,
            "daemon.response_too_large"
        );
    }

    #[test]
    fn adversarial_daemon_down_is_structured_unavailable() {
        // Bind then drop: the port is (almost surely) closed.
        let address = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let error = http_get(address, "/metrics", Some("never-echoed-token")).unwrap_err();
        assert_eq!(error.code, "daemon.unavailable");
        assert!(!error.message.contains("never-echoed-token"));
    }

    #[test]
    fn adversarial_non_loopback_admin_refused() {
        for bind in ["10.0.0.5:9091", "192.168.1.2:9091", "[2001:db8::1]:9091"] {
            assert_eq!(dial_address(bind).unwrap_err().code, "daemon.not_loopback");
        }
        let error = http_get("10.0.0.5:9091".parse().unwrap(), "/metrics", Some("t")).unwrap_err();
        assert_eq!(error.code, "daemon.not_loopback");
        let error = http_get(
            "127.0.0.1:9".parse().unwrap(),
            "/metrics",
            Some("t\r\nX-Smuggled: 1"),
        )
        .unwrap_err();
        assert_eq!(error.code, "config.token_invalid");
        assert_eq!(
            dial_address("localhost:9091").unwrap_err().code,
            "config.admin_bind_invalid"
        );
    }

    #[test]
    fn adversarial_unauthorized_and_disabled_admin() {
        let reply = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_response(reply).unwrap_err().code,
            "daemon.unauthorized"
        );
        let text = "listeners:\n  admin: {bind: \"127.0.0.1:9091\", enabled: false}\n";
        assert_eq!(
            endpoint_from_text(text).unwrap_err().code,
            "config.admin_disabled"
        );
        assert_eq!(
            endpoint_from_text(": : not yaml [").unwrap_err().code,
            "config.invalid"
        );
    }

    #[test]
    fn validation_endpoint_from_config() {
        let text = "admin_token_env: SMOKE_TOKEN\nlisteners:\n  admin: {bind: \"0.0.0.0:19091\"}\n  http: {bind: \"0.0.0.0:8080\"}\n";
        let endpoint = endpoint_from_text(text).unwrap();
        assert_eq!(endpoint.address, "127.0.0.1:19091".parse().unwrap());
        assert_eq!(endpoint.token_env, "SMOKE_TOKEN");
        let defaulted = endpoint_from_text("listeners:\n  admin: {bind: \"[::]:9091\"}\n").unwrap();
        assert_eq!(defaulted.address, "[::1]:9091".parse().unwrap());
        assert_eq!(defaulted.token_env, DEFAULT_TOKEN_ENV);
    }

    #[test]
    fn validation_get_against_loopback_fixture() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 1024];
            let read = socket.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]).to_string();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .unwrap();
            // Keep the socket open: the client must stop at
            // Content-Length rather than wait for EOF.
            std::thread::sleep(Duration::from_millis(300));
            request
        });
        let body = http_get(address, "/metrics", Some("tok")).unwrap();
        assert_eq!(body, "hello");
        let request = server.join().unwrap();
        assert!(request.starts_with("GET /metrics HTTP/1.1\r\n"));
        assert!(request.contains("Authorization: Bearer tok\r\n"));
    }
}
