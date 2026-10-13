// #################################################################
// /qompassai/vongola/crates/vongola/src/acme.rs
// Qompass AI — Vongola clean-room ACME client (RFC 8555)
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

//! ACME (RFC 8555) client: account registration, order flow,
//! HTTP-01 challenge fulfillment through the shared challenge
//! store (`State::acme_challenges`, served by the HTTP listener),
//! certificate download, hot-swap into the live certificate
//! store, persistence under `<state_dir>/acme/`, and renewal
//! when fewer than 30 days of validity remain.
//!
//! Contracts:
//! - Every network operation is bounded: connect/read deadlines, response-size
//!   caps, poll counts, retry counts, and a total per-order deadline. Nothing
//!   loops forever.
//! - Every failure path leaves the previously installed certificate serving.
//!   Installation is validate -> persist -> swap; a rejected validation step
//!   changes no published state.
//! - The account key and issued keys are EC P-256, stored 0600.
//! - The transport is blocking std+OpenSSL on purpose: the renewal driver runs
//!   it inside `spawn_blocking`, and the dependency surface (and Cargo.lock)
//!   does not grow.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use serde_json::{Value, json};

use crate::cert::CertStore;
use crate::config::Config;
use crate::state::State;

// ---------- Bounds (named, with units) ----------

/// Account key file name inside `<state_dir>/acme/`.
pub const ACCOUNT_KEY_FILENAME: &str = "account.key";
/// Subdirectory of the state dir holding ACME material.
pub const ACME_SUBDIR: &str = "acme";
/// Backoff cap between order attempts, seconds.
pub const BACKOFF_CAP_SECS: u64 = 900;
/// First backoff between order attempts, seconds.
pub const BACKOFF_FIRST_SECS: u64 = 60;
/// Renewal check interval, seconds (6 hours).
pub const CHECK_INTERVAL_SECS: u64 = 21_600;
/// TCP connect deadline, seconds.
pub const CONNECT_TIMEOUT_SECS: u64 = 10;
/// Per-request read/write deadline, seconds.
pub const HTTP_TIMEOUT_SECS: u64 = 30;
/// Attempts per domain group per renewal pass.
pub const MAX_ATTEMPTS_PER_GROUP: u32 = 3;
/// Maximum authorizations per order.
pub const MAX_AUTHZ_PER_ORDER: usize = 20;
/// Maximum header block accepted from a CA, bytes.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Maximum JSON body accepted from a CA, bytes.
pub const MAX_JSON_BYTES: usize = 512 * 1024;
/// badNonce recoveries per signed request.
pub const MAX_NONCE_RETRIES: u32 = 3;
/// Maximum response body accepted (certificate chains), bytes.
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Total deadline for one order flow, seconds (15 minutes).
pub const ORDER_DEADLINE_SECS: u64 = 900;
/// Polls of one authorization or order before giving up.
pub const POLL_MAX_COUNT: u32 = 45;
/// Delay between authorization/order polls, seconds.
pub const POLL_INTERVAL_SECS: u64 = 2;
/// Renew when fewer than this many days of validity remain.
pub const RENEW_THRESHOLD_DAYS: f64 = 30.0;

// ---------- Errors ----------

/// Everything the ACME driver can fail with. CA problem
/// documents keep their type and a bounded detail string;
/// nothing here ever carries key material.
#[derive(Debug)]
pub enum AcmeError {
    /// A renewal pass is already in progress.
    AlreadyRunning,
    /// The CA returned an RFC 7807 problem document.
    Ca {
        detail: String,
        problem_type: String,
        status: u16,
    },
    /// Local configuration cannot drive a flow (bad URL, insecure
    /// transport requested for a non-loopback directory, ...).
    Config(String),
    /// Key generation, signing, or certificate parsing failed.
    Crypto(String),
    /// HTTP completed with an unexpected status and no problem
    /// document.
    Http { message: String, status: u16 },
    /// Local filesystem failure (keys, persisted certificates).
    Io(String),
    /// The CA sent something RFC 8555 does not permit (missing
    /// fields, wrong names in the issued certificate, ...).
    Protocol(String),
    /// TCP/TLS failure talking to the CA.
    Transport(String),
}

impl AcmeError {
    /// Bounded copy of a CA-supplied string: a hostile or broken
    /// CA must not be able to grow logs or error values without
    /// limit.
    fn bounded(text: &str) -> String { text.chars().take(512).collect() }

    fn from_problem(status: u16, body: &[u8]) -> AcmeError {
        if let Ok(value) = serde_json::from_slice::<Value>(body)
            && let Some(problem_type) = value.get("type").and_then(Value::as_str)
            && problem_type.starts_with("urn:ietf:params:acme:error:")
        {
            let detail = value
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("(no detail)");
            return AcmeError::Ca {
                detail: AcmeError::bounded(detail),
                problem_type: problem_type.to_string(),
                status,
            };
        }
        AcmeError::Http {
            message: format!("unexpected HTTP status {status}"),
            status,
        }
    }

    /// True when the CA rejected our anti-replay nonce; the
    /// request may be retried verbatim with a fresh nonce.
    pub fn is_bad_nonce(&self) -> bool {
        matches!(self, AcmeError::Ca { problem_type, .. } if problem_type.ends_with(":badNonce"))
    }

    /// Retry classification for whole-order attempts: transient
    /// CA pressure and transport failures are retryable; account,
    /// validation, and protocol failures are not.
    pub fn is_retryable(&self) -> bool {
        match self {
            AcmeError::Ca {
                problem_type,
                status,
                ..
            } => {
                problem_type.ends_with(":rateLimited")
                    || problem_type.ends_with(":serverInternal")
                    || *status >= 500
            }
            AcmeError::Transport(_) => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::AlreadyRunning => write!(f, "acme: renewal already in progress"),
            AcmeError::Ca {
                detail,
                problem_type,
                status,
            } => write!(f, "acme: CA error {problem_type} (http {status}): {detail}"),
            AcmeError::Config(message) => write!(f, "acme config: {message}"),
            AcmeError::Crypto(message) => write!(f, "acme crypto: {message}"),
            AcmeError::Http { message, status } => write!(f, "acme http {status}: {message}"),
            AcmeError::Io(message) => write!(f, "acme io: {message}"),
            AcmeError::Protocol(message) => write!(f, "acme protocol: {message}"),
            AcmeError::Transport(message) => write!(f, "acme transport: {message}"),
        }
    }
}

impl std::error::Error for AcmeError {}

// ---------- Small helpers ----------

fn b64u_encode(bytes: &[u8]) -> String { URL_SAFE_NO_PAD.encode(bytes) }

#[cfg(test)]
fn b64u_decode(text: &str) -> Result<Vec<u8>, AcmeError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| AcmeError::Protocol(format!("base64url decode: {e}")))
}

/// Host portion of a URL, lowercased, without port. Used only
/// for the loopback checks that gate plaintext HTTP and
/// insecure test-CA modes; never for authorization.
fn url_host(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = host.trim_start_matches('[').split(']').next()?;
    let host = host.split(':').next()?;
    Some(host.to_lowercase())
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// Validate one DNS identifier before it is offered to a CA:
/// LDH labels, bounded length, no empty labels. Rejects
/// wildcards (HTTP-01 cannot prove them) and IP literals.
pub fn validate_domain(domain: &str) -> Result<(), AcmeError> {
    let invalid = |why: &str| AcmeError::Config(format!("domain {domain:?}: {why}"));
    if domain.is_empty() || domain.len() > 253 {
        return Err(invalid("length out of bounds"));
    }
    if domain.contains('*') {
        return Err(invalid("wildcards are not supported by HTTP-01"));
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Err(invalid("IP identifiers are not supported"));
    }
    for label in domain.split('.') {
        let label_ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !label_ok {
            return Err(invalid("malformed label"));
        }
    }
    Ok(())
}

// ---------- HTTP transport ----------

/// One HTTP exchange. Bodies are always fully buffered and
/// size-capped by the transport.
#[derive(Debug)]
pub struct HttpResponse {
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
    pub status: u16,
}

impl HttpResponse {
    /// First header value by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// The CA-facing transport. Production uses [`HttpsTransport`];
/// tests substitute scripted or loopback implementations.
pub trait Transport {
    /// Send one request. `body` is empty for GET/HEAD.
    fn send(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, AcmeError>;
}

/// Blocking HTTP/1.1 over std TCP + OpenSSL. Deliberately
/// minimal: one request per connection (`Connection: close`),
/// Content-Length and chunked responses, hard caps on header
/// and body sizes, deadlines on connect/read/write.
pub struct HttpsTransport {
    /// Extra trust roots (PEM bytes), e.g. a test CA's root.
    pub extra_roots_pem: Vec<u8>,
    /// Skip TLS verification. The client constructor refuses
    /// this for any non-loopback directory URL.
    pub insecure_skip_verify: bool,
}

struct ParsedUrl {
    host: String,
    path_and_query: String,
    port: u16,
    secure: bool,
}

fn parse_url(url: &str) -> Result<ParsedUrl, AcmeError> {
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(AcmeError::Config(format!(
            "URL must be http:// or https://: {url}"
        )));
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| AcmeError::Config("unterminated IPv6 host".to_string()))?;
        let host = &stripped[..end];
        let port = stripped[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(if secure { 443 } else { 80 });
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port_text)) => (
                host.to_string(),
                port_text
                    .parse()
                    .map_err(|_| AcmeError::Config(format!("bad port in URL: {url}")))?,
            ),
            None => (authority.to_string(), if secure { 443 } else { 80 }),
        }
    };
    if host.is_empty() {
        return Err(AcmeError::Config(format!("URL has no host: {url}")));
    }
    Ok(ParsedUrl {
        host,
        path_and_query: path.to_string(),
        port,
        secure,
    })
}

impl HttpsTransport {
    fn connect(&self, url: &ParsedUrl) -> Result<Box<dyn ReadWrite>, AcmeError> {
        let address = (url.host.as_str(), url.port)
            .to_socket_addrs()
            .map_err(|e| AcmeError::Transport(format!("resolve {}: {e}", url.host)))?
            .next()
            .ok_or_else(|| AcmeError::Transport(format!("no address for {}", url.host)))?;
        let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .map_err(|e| AcmeError::Transport(format!("connect {}: {e}", url.host)))?;
        let timeout = Duration::from_secs(HTTP_TIMEOUT_SECS);
        let _ = tcp.set_read_timeout(Some(timeout));
        let _ = tcp.set_write_timeout(Some(timeout));
        if !url.secure {
            return Ok(Box::new(tcp));
        }
        let mut builder = SslConnector::builder(SslMethod::tls())
            .map_err(|e| AcmeError::Crypto(format!("ssl builder: {e}")))?;
        if self.insecure_skip_verify {
            builder.set_verify(SslVerifyMode::NONE);
        } else {
            builder
                .set_default_verify_paths()
                .map_err(|e| AcmeError::Crypto(format!("default verify paths: {e}")))?;
            if !self.extra_roots_pem.is_empty() {
                let store = builder.cert_store_mut();
                for cert in X509::stack_from_pem(&self.extra_roots_pem)
                    .map_err(|e| AcmeError::Crypto(format!("extra roots parse: {e}")))?
                {
                    store
                        .add_cert(cert)
                        .map_err(|e| AcmeError::Crypto(format!("extra root add: {e}")))?;
                }
            }
        }
        let connector = builder.build();
        let stream = connector
            .connect(&url.host, tcp)
            .map_err(|e| AcmeError::Transport(format!("tls to {}: {e}", url.host)))?;
        Ok(Box::new(stream))
    }
}

trait ReadWrite: Read + Write {}
impl ReadWrite for TcpStream {}
impl ReadWrite for openssl::ssl::SslStream<TcpStream> {}

impl Transport for HttpsTransport {
    fn send(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, AcmeError> {
        let parsed = parse_url(url)?;
        if !parsed.secure && !is_loopback_host(&parsed.host) {
            return Err(AcmeError::Config(format!(
                "plaintext http is only permitted to loopback, not {}",
                parsed.host
            )));
        }
        let mut stream = self.connect(&parsed)?;
        let mut request = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\n",
            parsed.path_and_query, parsed.host
        );
        request.push_str("User-Agent: vongola-acme/0.2\r\nConnection: close\r\n");
        if !body.is_empty() || method == "POST" {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        for (name, value) in headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(body))
            .and_then(|()| stream.flush())
            .map_err(|e| AcmeError::Transport(format!("write to {}: {e}", parsed.host)))?;
        read_response(&mut *stream)
    }
}

fn read_response(stream: &mut dyn Read) -> Result<HttpResponse, AcmeError> {
    // Read until the header terminator, bounded.
    let mut raw: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    let header_end = loop {
        if raw.len() >= MAX_HEADER_BYTES {
            return Err(AcmeError::Protocol(
                "response headers exceed cap".to_string(),
            ));
        }
        let read = stream
            .read(&mut byte)
            .map_err(|e| AcmeError::Transport(format!("read headers: {e}")))?;
        if read == 0 {
            return Err(AcmeError::Transport(
                "connection closed inside headers".to_string(),
            ));
        }
        raw.push(byte[0]);
        if raw.ends_with(b"\r\n\r\n") {
            break raw.len();
        }
    };
    let header_text = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let mut lines = header_text.lines();
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| AcmeError::Protocol(format!("bad status line: {status_line}")))?;
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    let probe = HttpResponse {
        body: Vec::new(),
        headers,
        status,
    };
    let body = read_body(stream, &probe)?;
    Ok(HttpResponse {
        body,
        headers: probe.headers,
        status: probe.status,
    })
}

fn read_body(stream: &mut dyn Read, response: &HttpResponse) -> Result<Vec<u8>, AcmeError> {
    let chunked = response
        .header("transfer-encoding")
        .map(|value| value.to_lowercase().contains("chunked"))
        .unwrap_or(false);
    if chunked {
        return read_chunked(stream);
    }
    if let Some(length_text) = response.header("content-length") {
        let length: usize = length_text
            .trim()
            .parse()
            .map_err(|_| AcmeError::Protocol("bad content-length".to_string()))?;
        if length > MAX_RESPONSE_BYTES {
            return Err(AcmeError::Protocol("response body exceeds cap".to_string()));
        }
        let mut body = vec![0u8; length];
        stream
            .read_exact(&mut body)
            .map_err(|e| AcmeError::Transport(format!("read body: {e}")))?;
        return Ok(body);
    }
    // No length and not chunked: the peer promised
    // `Connection: close`, so read to EOF, still capped.
    let mut body: Vec<u8> = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|e| AcmeError::Transport(format!("read body: {e}")))?;
        if read == 0 {
            return Ok(body);
        }
        if body.len() + read > MAX_RESPONSE_BYTES {
            return Err(AcmeError::Protocol("response body exceeds cap".to_string()));
        }
        body.extend_from_slice(&buffer[..read]);
    }
}

fn read_chunked(stream: &mut dyn Read) -> Result<Vec<u8>, AcmeError> {
    let mut body: Vec<u8> = Vec::new();
    loop {
        let line = read_line(stream, 128)?;
        let size_text = line.trim().split(';').next().unwrap_or("");
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| AcmeError::Protocol("bad chunk size".to_string()))?;
        if size == 0 {
            // Trailer section: consume until the blank line.
            loop {
                let trailer = read_line(stream, MAX_HEADER_BYTES)?;
                if trailer.trim().is_empty() {
                    return Ok(body);
                }
            }
        }
        if body.len() + size > MAX_RESPONSE_BYTES {
            return Err(AcmeError::Protocol("response body exceeds cap".to_string()));
        }
        let mut chunk = vec![0u8; size];
        stream
            .read_exact(&mut chunk)
            .map_err(|e| AcmeError::Transport(format!("read chunk: {e}")))?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        stream
            .read_exact(&mut crlf)
            .map_err(|e| AcmeError::Transport(format!("read chunk end: {e}")))?;
        if &crlf != b"\r\n" {
            return Err(AcmeError::Protocol("chunk missing CRLF".to_string()));
        }
    }
}

fn read_line(stream: &mut dyn Read, cap: usize) -> Result<String, AcmeError> {
    let mut line: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if line.len() >= cap {
            return Err(AcmeError::Protocol("line exceeds cap".to_string()));
        }
        let read = stream
            .read(&mut byte)
            .map_err(|e| AcmeError::Transport(format!("read line: {e}")))?;
        if read == 0 {
            return Err(AcmeError::Transport(
                "connection closed mid-line".to_string(),
            ));
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(String::from_utf8_lossy(&line).into_owned());
        }
    }
}

// ---------- JOSE: account key, JWK, JWS ----------

/// An ACME account key: EC P-256, with its JWK and RFC 7638
/// thumbprint precomputed. The private key never leaves this
/// struct except as a PEM written 0600 by the loader.
pub struct AccountKey {
    jwk_json: String,
    pkey: PKey<Private>,
    thumbprint: String,
}

impl AccountKey {
    /// Build from an OpenSSL private key, deriving the public
    /// coordinates and thumbprint.
    pub fn from_pkey(pkey: PKey<Private>) -> Result<AccountKey, AcmeError> {
        let ec_key = pkey
            .ec_key()
            .map_err(|e| AcmeError::Crypto(format!("account key is not EC: {e}")))?;
        let group = ec_key.group();
        let mut x = BigNum::new().map_err(|e| AcmeError::Crypto(format!("bignum: {e}")))?;
        let mut y = BigNum::new().map_err(|e| AcmeError::Crypto(format!("bignum: {e}")))?;
        let mut ctx = openssl::bn::BigNumContext::new()
            .map_err(|e| AcmeError::Crypto(format!("bignum ctx: {e}")))?;
        ec_key
            .public_key()
            .affine_coordinates(group, &mut x, &mut y, &mut ctx)
            .map_err(|e| AcmeError::Crypto(format!("ec coordinates: {e}")))?;
        let x_b64 = b64u_encode(&pad32(&x.to_vec()));
        let y_b64 = b64u_encode(&pad32(&y.to_vec()));
        let jwk_json = jwk_canonical_json(&x_b64, &y_b64);
        let thumbprint = jwk_thumbprint(&jwk_json);
        Ok(AccountKey {
            jwk_json,
            pkey,
            thumbprint,
        })
    }

    /// JWK thumbprint (RFC 7638): the key authorization suffix
    /// and account identity anchor.
    pub fn thumbprint(&self) -> &str { &self.thumbprint }

    /// Sign one JWS for `url`. Exactly one of `kid` /
    /// the embedded JWK is used, per RFC 8555 section 6.2.
    fn sign_jws(
        &self,
        url: &str,
        nonce: &str,
        kid: Option<&str>,
        payload_json: Option<&str>,
    ) -> Result<String, AcmeError> {
        let protected = match kid {
            Some(kid) => json!({
                "alg": "ES256",
                "kid": kid,
                "nonce": nonce,
                "url": url,
            }),
            None => {
                let jwk: Value = serde_json::from_str(&self.jwk_json)
                    .map_err(|e| AcmeError::Crypto(format!("jwk parse: {e}")))?;
                json!({
                    "alg": "ES256",
                    "jwk": jwk,
                    "nonce": nonce,
                    "url": url,
                })
            }
        };
        let protected_b64 = b64u_encode(protected.to_string().as_bytes());
        let payload_b64 = payload_json
            .map(|payload| b64u_encode(payload.as_bytes()))
            .unwrap_or_default();
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let signature = self.sign_es256(signing_input.as_bytes())?;
        Ok(json!({
            "payload": payload_b64,
            "protected": protected_b64,
            "signature": b64u_encode(&signature),
        })
        .to_string())
    }

    /// ES256 signature as raw R || S (32 bytes each), the JWS
    /// encoding — OpenSSL returns DER, so transcode.
    fn sign_es256(&self, message: &[u8]) -> Result<Vec<u8>, AcmeError> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.pkey)
            .map_err(|e| AcmeError::Crypto(format!("signer: {e}")))?;
        signer
            .update(message)
            .map_err(|e| AcmeError::Crypto(format!("sign update: {e}")))?;
        let der = signer
            .sign_to_vec()
            .map_err(|e| AcmeError::Crypto(format!("sign finish: {e}")))?;
        let sig = openssl::ecdsa::EcdsaSig::from_der(&der)
            .map_err(|e| AcmeError::Crypto(format!("ecdsa sig parse: {e}")))?;
        let mut raw = pad32(&sig.r().to_vec());
        raw.extend_from_slice(&pad32(&sig.s().to_vec()));
        Ok(raw)
    }
}

fn pad32(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() >= 32 {
        return bytes[bytes.len() - 32..].to_vec();
    }
    let mut padded = vec![0u8; 32 - bytes.len()];
    padded.extend_from_slice(bytes);
    padded
}

/// Canonical JWK JSON for a P-256 key: members in
/// lexicographic order, no whitespace (RFC 7638 section 3).
fn jwk_canonical_json(x_b64: &str, y_b64: &str) -> String {
    format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x_b64}\",\"y\":\"{y_b64}\"}}")
}

fn jwk_thumbprint(jwk_json: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(jwk_json.as_bytes());
    b64u_encode(&digest)
}

fn generate_p256_key() -> Result<PKey<Private>, AcmeError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| AcmeError::Crypto(format!("ec group: {e}")))?;
    let ec_key =
        EcKey::generate(&group).map_err(|e| AcmeError::Crypto(format!("ec keygen: {e}")))?;
    PKey::from_ec_key(ec_key).map_err(|e| AcmeError::Crypto(format!("pkey wrap: {e}")))
}

/// Load the account key from `<state_dir>/acme/account.key`,
/// creating and persisting it (PEM, 0600) when absent. An
/// existing but unreadable key is an error, never a silent
/// regeneration: a new key means a new ACME account.
pub fn load_or_create_account_key(state_dir: &Path) -> Result<AccountKey, AcmeError> {
    let dir = state_dir.join(ACME_SUBDIR);
    std::fs::create_dir_all(&dir).map_err(|e| AcmeError::Io(format!("create acme dir: {e}")))?;
    let path = dir.join(ACCOUNT_KEY_FILENAME);
    if path.exists() {
        let pem =
            std::fs::read(&path).map_err(|e| AcmeError::Io(format!("read account key: {e}")))?;
        let pkey = PKey::private_key_from_pem(&pem)
            .map_err(|e| AcmeError::Crypto(format!("account key parse: {e}")))?;
        return AccountKey::from_pkey(pkey);
    }
    let pkey = generate_p256_key()?;
    let pem = pkey
        .private_key_to_pem_pkcs8()
        .map_err(|e| AcmeError::Crypto(format!("account key serialize: {e}")))?;
    crate::cert::write_key_0600(&path, &pem)
        .map_err(|e| AcmeError::Io(format!("persist account key: {e}")))?;
    AccountKey::from_pkey(pkey)
}

// ---------- Certificate signing requests ----------

/// Generate a fresh P-256 key for the certificate and a CSR
/// (DER) covering every domain as a SAN. Returns both; the
/// caller persists the key only after the CA issues.
fn generate_csr(domains: &[String]) -> Result<(PKey<Private>, Vec<u8>), AcmeError> {
    let key = generate_p256_key()?;
    let mut name_builder = openssl::x509::X509NameBuilder::new()
        .map_err(|e| AcmeError::Crypto(format!("name builder: {e}")))?;
    name_builder
        .append_entry_by_text("CN", &domains[0])
        .map_err(|e| AcmeError::Crypto(format!("csr cn: {e}")))?;
    let name = name_builder.build();
    let mut builder = openssl::x509::X509ReqBuilder::new()
        .map_err(|e| AcmeError::Crypto(format!("csr builder: {e}")))?;
    builder
        .set_pubkey(&key)
        .map_err(|e| AcmeError::Crypto(format!("csr pubkey: {e}")))?;
    builder
        .set_subject_name(&name)
        .map_err(|e| AcmeError::Crypto(format!("csr subject: {e}")))?;
    let context = builder.x509v3_context(None);
    let mut san = openssl::x509::extension::SubjectAlternativeName::new();
    for domain in domains {
        san.dns(domain);
    }
    let san_ext = san
        .build(&context)
        .map_err(|e| AcmeError::Crypto(format!("csr san: {e}")))?;
    let mut extensions = openssl::stack::Stack::new()
        .map_err(|e| AcmeError::Crypto(format!("csr ext stack: {e}")))?;
    extensions
        .push(san_ext)
        .map_err(|e| AcmeError::Crypto(format!("csr ext push: {e}")))?;
    builder
        .add_extensions(&extensions)
        .map_err(|e| AcmeError::Crypto(format!("csr add san: {e}")))?;
    builder
        .sign(&key, MessageDigest::sha256())
        .map_err(|e| AcmeError::Crypto(format!("csr sign: {e}")))?;
    let request = builder.build();
    let der = request
        .to_der()
        .map_err(|e| AcmeError::Crypto(format!("csr der: {e}")))?;
    Ok((key, der))
}

// ---------- Challenge store ----------

/// The HTTP-01 challenge publication surface. Production uses
/// the shared map in `State`; tests use their own map. The
/// HTTP listener serves exactly what this publishes.
pub trait ChallengeStore: Send + Sync {
    /// Make `token` answer with `key_authorization`.
    fn publish(&self, token: &str, key_authorization: &str);
    /// Withdraw a token (flow finished or failed).
    fn remove(&self, token: &str);
}

impl ChallengeStore for RwLock<BTreeMap<String, String>> {
    fn publish(&self, token: &str, key_authorization: &str) {
        if let Ok(mut map) = self.write() {
            map.insert(token.to_string(), key_authorization.to_string());
        }
    }

    fn remove(&self, token: &str) {
        if let Ok(mut map) = self.write() {
            map.remove(token);
        }
    }
}

/// RAII withdrawal: whatever happens inside a challenge flow,
/// the token does not outlive it.
struct PublishedChallenge<'a> {
    store: &'a dyn ChallengeStore,
    token: String,
}

impl Drop for PublishedChallenge<'_> {
    fn drop(&mut self) { self.store.remove(&self.token); }
}

// ---------- ACME client ----------

struct Directory {
    new_account: String,
    new_nonce: String,
    new_order: String,
}

/// A single-use ACME client session over one transport.
/// Not reusable across orders for different account keys;
/// nonce and account state live here and nowhere else.
pub struct AcmeClient<T: Transport> {
    account_key: AccountKey,
    account_url: Option<String>,
    directory: Directory,
    nonce: Option<String>,
    transport: T,
}

impl<T: Transport> AcmeClient<T> {
    /// Fetch the directory and prepare a session. Refuses an
    /// insecure transport for a non-loopback directory: test
    /// modes must be visibly test-only.
    pub fn connect(
        mut transport: T,
        directory_url: &str,
        account_key: AccountKey,
        insecure_skip_verify: bool,
    ) -> Result<AcmeClient<T>, AcmeError> {
        let host = url_host(directory_url).unwrap_or_default();
        if insecure_skip_verify && !is_loopback_host(&host) {
            return Err(AcmeError::Config(format!(
                "insecure_skip_verify refused for non-loopback directory host {host}"
            )));
        }
        let response = transport.send("GET", directory_url, &[], &[])?;
        if response.status != 200 {
            return Err(AcmeError::from_problem(response.status, &response.body));
        }
        let directory = parse_directory(&response.body)?;
        Ok(AcmeClient {
            account_key,
            account_url: None,
            directory,
            nonce: None,
            transport,
        })
    }

    /// Register (or re-discover) the account for this key.
    /// Returns the account URL (the JWS `kid` from now on).
    pub fn ensure_account(&mut self, email: &str) -> Result<String, AcmeError> {
        if let Some(url) = &self.account_url {
            return Ok(url.clone());
        }
        let payload = json!({
            "contact": [format!("mailto:{email}")],
            "termsOfServiceAgreed": true,
        });
        let url = self.directory.new_account.clone();
        let response = self.post_jws(&url, Some(&payload.to_string()), true)?;
        if response.status != 200 && response.status != 201 {
            return Err(AcmeError::from_problem(response.status, &response.body));
        }
        let location = response
            .header("location")
            .ok_or_else(|| AcmeError::Protocol("newAccount: no Location header".to_string()))?
            .to_string();
        self.account_url = Some(location.clone());
        Ok(location)
    }

    /// Run one complete order for `domains` and return the
    /// issued chain PEM and the freshly generated key PEM.
    /// Challenges are published into `store` for exactly the
    /// duration of each authorization.
    pub fn obtain(
        &mut self,
        domains: &[String],
        store: &dyn ChallengeStore,
        deadline: Instant,
    ) -> Result<(Vec<u8>, Vec<u8>), AcmeError> {
        if domains.is_empty() || domains.len() > MAX_AUTHZ_PER_ORDER {
            return Err(AcmeError::Config(format!(
                "order domain count {} out of bounds",
                domains.len()
            )));
        }
        for domain in domains {
            validate_domain(domain)?;
        }
        let order_url = self.new_order(domains)?;
        let order = self.fetch_order(&order_url)?;
        if order.status == "valid" {
            // We never persist order URLs, so a fresh order
            // cannot legitimately be valid yet — and if one
            // somehow is, we do not hold its key and must not
            // install a certificate we cannot serve.
            return Err(AcmeError::Protocol(
                "new order unexpectedly valid; its key is not held".to_string(),
            ));
        }
        if order.status != "pending" && order.status != "ready" {
            return Err(AcmeError::Protocol(format!(
                "order in unexpected status {}",
                order.status
            )));
        }
        if order.status == "pending" {
            for authz_url in &order.authorizations {
                self.complete_authorization(authz_url, domains, store, deadline)?;
            }
        }
        let ready = self.poll_order(&order_url, deadline)?;
        let (cert_key, csr_der) = generate_csr(domains)?;
        let finalize_payload = json!({ "csr": b64u_encode(&csr_der) });
        let response =
            self.post_jws(&ready.finalize, Some(&finalize_payload.to_string()), false)?;
        if response.status != 200 {
            return Err(AcmeError::from_problem(response.status, &response.body));
        }
        let valid = self.poll_order(&order_url, deadline)?;
        let cert_url = valid
            .certificate
            .ok_or_else(|| AcmeError::Protocol("valid order has no certificate".to_string()))?;
        let chain = self.download_chain(&cert_url, domains, Some(&cert_key))?;
        let key_pem = cert_key
            .private_key_to_pem_pkcs8()
            .map_err(|e| AcmeError::Crypto(format!("certificate key serialize: {e}")))?;
        Ok((chain, key_pem))
    }

    fn new_order(&mut self, domains: &[String]) -> Result<String, AcmeError> {
        let identifiers: Vec<Value> = domains
            .iter()
            .map(|domain| json!({"type": "dns", "value": domain}))
            .collect();
        let payload = json!({ "identifiers": identifiers });
        let url = self.directory.new_order.clone();
        let response = self.post_jws(&url, Some(&payload.to_string()), false)?;
        if response.status != 201 {
            return Err(AcmeError::from_problem(response.status, &response.body));
        }
        response
            .header("location")
            .map(str::to_string)
            .ok_or_else(|| AcmeError::Protocol("newOrder: no Location header".to_string()))
    }

    /// Drive one authorization to `valid`: publish the
    /// HTTP-01 challenge, ask the CA to validate, then poll.
    fn complete_authorization(
        &mut self,
        authz_url: &str,
        domains: &[String],
        store: &dyn ChallengeStore,
        deadline: Instant,
    ) -> Result<(), AcmeError> {
        let authz = self.fetch_authz(authz_url)?;
        if !domains
            .iter()
            .any(|domain| domain.eq_ignore_ascii_case(&authz.identifier))
        {
            return Err(AcmeError::Protocol(format!(
                "authorization identifier {} was not ordered",
                authz.identifier
            )));
        }
        if authz.status == "valid" {
            return Ok(());
        }
        if authz.status != "pending" {
            return Err(AcmeError::Protocol(format!(
                "authorization for {} in status {}",
                authz.identifier, authz.status
            )));
        }
        let challenge = authz
            .http01
            .ok_or_else(|| AcmeError::Protocol("authorization offers no http-01".to_string()))?;
        validate_token(&challenge.token)?;
        let key_authorization = format!("{}.{}", challenge.token, self.account_key.thumbprint());
        store.publish(&challenge.token, &key_authorization);
        let _published = PublishedChallenge {
            store,
            token: challenge.token.clone(),
        };
        let response = self.post_jws(&challenge.url, Some("{}"), false)?;
        if response.status != 200 {
            return Err(AcmeError::from_problem(response.status, &response.body));
        }
        self.poll_authz(authz_url, deadline)
    }

    fn poll_authz(&mut self, authz_url: &str, deadline: Instant) -> Result<(), AcmeError> {
        for poll in 0..POLL_MAX_COUNT {
            check_deadline(deadline, "authorization")?;
            if poll > 0 {
                std::thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
            }
            let authz = self.fetch_authz(authz_url)?;
            match authz.status.as_str() {
                "valid" => return Ok(()),
                "pending" | "processing" => {}
                "invalid" => {
                    return Err(AcmeError::Ca {
                        detail: AcmeError::bounded(&format!(
                            "authorization for {} invalid: {}",
                            authz.identifier,
                            authz.error_detail.as_deref().unwrap_or("(no detail)")
                        )),
                        problem_type: "urn:ietf:params:acme:error:unauthorized".to_string(),
                        status: 403,
                    });
                }
                other => {
                    return Err(AcmeError::Protocol(format!(
                        "authorization in unexpected status {other}"
                    )));
                }
            }
        }
        Err(AcmeError::Protocol(
            "authorization did not resolve within the poll budget".to_string(),
        ))
    }

    fn poll_order(&mut self, order_url: &str, deadline: Instant) -> Result<Order, AcmeError> {
        for _ in 0..POLL_MAX_COUNT {
            check_deadline(deadline, "order")?;
            let order = self.fetch_order(order_url)?;
            match order.status.as_str() {
                "ready" | "valid" => return Ok(order),
                "pending" | "processing" => {
                    std::thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
                }
                "invalid" => {
                    return Err(AcmeError::Protocol(format!(
                        "order invalid: {}",
                        order.error_detail.as_deref().unwrap_or("(no detail)")
                    )));
                }
                other => {
                    return Err(AcmeError::Protocol(format!(
                        "order in unexpected status {other}"
                    )));
                }
            }
        }
        Err(AcmeError::Protocol(
            "order did not resolve within the poll budget".to_string(),
        ))
    }

    fn fetch_authz(&mut self, url: &str) -> Result<Authz, AcmeError> {
        let response = self.post_jws(url, None, false)?;
        if response.status != 200 {
            return Err(AcmeError::from_problem(response.status, &response.body));
        }
        parse_authz(&response.body)
    }

    fn fetch_order(&mut self, url: &str) -> Result<Order, AcmeError> {
        let response = self.post_jws(url, None, false)?;
        if response.status != 200 {
            return Err(AcmeError::from_problem(response.status, &response.body));
        }
        parse_order(&response.body)
    }

    /// Download the issued chain and verify it before anyone
    /// installs it: parses as X.509, covers every requested
    /// name, and (when we generated the key this run) matches
    /// the key that will be persisted beside it.
    fn download_chain(
        &mut self,
        cert_url: &str,
        domains: &[String],
        expected_key: Option<&PKey<Private>>,
    ) -> Result<Vec<u8>, AcmeError> {
        let response = self.post_jws(cert_url, None, false)?;
        if response.status != 200 {
            return Err(AcmeError::from_problem(response.status, &response.body));
        }
        let chain_pem = response.body;
        verify_chain(&chain_pem, domains, expected_key)?;
        Ok(chain_pem)
    }

    /// One signed POST with nonce recovery: a `badNonce`
    /// problem discards the cached nonce and retries the same
    /// request, bounded by MAX_NONCE_RETRIES.
    fn post_jws(
        &mut self,
        url: &str,
        payload_json: Option<&str>,
        use_jwk: bool,
    ) -> Result<HttpResponse, AcmeError> {
        let mut nonce_retries = 0;
        loop {
            let result = self.post_jws_once(url, payload_json, use_jwk);
            match result {
                Err(error) if error.is_bad_nonce() && nonce_retries < MAX_NONCE_RETRIES => {
                    nonce_retries += 1;
                    self.nonce = None;
                }
                other => return other,
            }
        }
    }

    fn post_jws_once(
        &mut self,
        url: &str,
        payload_json: Option<&str>,
        use_jwk: bool,
    ) -> Result<HttpResponse, AcmeError> {
        if self.nonce.is_none() {
            self.refresh_nonce()?;
        }
        let nonce = self.nonce.take().unwrap_or_default();
        let kid = if use_jwk {
            None
        } else {
            Some(
                self.account_url
                    .as_deref()
                    .ok_or_else(|| AcmeError::Protocol("account not registered".to_string()))?,
            )
        };
        let body = self.account_key.sign_jws(url, &nonce, kid, payload_json)?;
        let headers = [(
            "Content-Type".to_string(),
            "application/jose+json".to_string(),
        )];
        let response = self
            .transport
            .send("POST", url, &headers, body.as_bytes())?;
        if let Some(fresh) = response.header("replay-nonce") {
            self.nonce = Some(fresh.to_string());
        }
        if response.status >= 400 {
            return Err(AcmeError::from_problem(response.status, &response.body));
        }
        Ok(response)
    }

    fn refresh_nonce(&mut self) -> Result<(), AcmeError> {
        let url = self.directory.new_nonce.clone();
        let response = self.transport.send("HEAD", &url, &[], &[])?;
        let nonce = response
            .header("replay-nonce")
            .ok_or_else(|| AcmeError::Protocol("newNonce: no Replay-Nonce header".to_string()))?
            .to_string();
        self.nonce = Some(nonce);
        Ok(())
    }
}

fn check_deadline(deadline: Instant, what: &str) -> Result<(), AcmeError> {
    if Instant::now() > deadline {
        return Err(AcmeError::Protocol(format!(
            "{what} exceeded the order deadline"
        )));
    }
    Ok(())
}

fn parse_directory(body: &[u8]) -> Result<Directory, AcmeError> {
    if body.len() > MAX_JSON_BYTES {
        return Err(AcmeError::Protocol(
            "directory exceeds size cap".to_string(),
        ));
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| AcmeError::Protocol(format!("directory parse: {e}")))?;
    let field = |name: &str| -> Result<String, AcmeError> {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| AcmeError::Protocol(format!("directory missing {name}")))
    };
    Ok(Directory {
        new_account: field("newAccount")?,
        new_nonce: field("newNonce")?,
        new_order: field("newOrder")?,
    })
}

struct Challenge {
    token: String,
    url: String,
}

struct Authz {
    error_detail: Option<String>,
    http01: Option<Challenge>,
    identifier: String,
    status: String,
}

fn parse_authz(body: &[u8]) -> Result<Authz, AcmeError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| AcmeError::Protocol(format!("authz parse: {e}")))?;
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let identifier = value
        .get("identifier")
        .and_then(|id| id.get("value"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let mut http01 = None;
    let mut error_detail = None;
    if let Some(challenges) = value.get("challenges").and_then(Value::as_array) {
        for challenge in challenges {
            if let Some(error) = challenge.get("error") {
                error_detail = Some(format!(
                    "{}: {}",
                    error.get("type").and_then(Value::as_str).unwrap_or("error"),
                    error.get("detail").and_then(Value::as_str).unwrap_or("")
                ));
            }
            if challenge.get("type").and_then(Value::as_str) == Some("http-01") {
                http01 = Some(Challenge {
                    token: challenge
                        .get("token")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    url: challenge
                        .get("url")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }
    }
    if let Some(error) = value.get("error") {
        error_detail = Some(format!(
            "{}: {}",
            error.get("type").and_then(Value::as_str).unwrap_or("error"),
            error.get("detail").and_then(Value::as_str).unwrap_or("")
        ));
    }
    Ok(Authz {
        error_detail,
        http01,
        identifier,
        status,
    })
}

struct Order {
    authorizations: Vec<String>,
    certificate: Option<String>,
    error_detail: Option<String>,
    finalize: String,
    status: String,
}

fn parse_order(body: &[u8]) -> Result<Order, AcmeError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| AcmeError::Protocol(format!("order parse: {e}")))?;
    let authorizations = value
        .get("authorizations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let error_detail = value.get("error").map(|error| {
        format!(
            "{}: {}",
            error.get("type").and_then(Value::as_str).unwrap_or("error"),
            error.get("detail").and_then(Value::as_str).unwrap_or("")
        )
    });
    Ok(Order {
        authorizations,
        certificate: value
            .get("certificate")
            .and_then(Value::as_str)
            .map(str::to_string),
        error_detail,
        finalize: value
            .get("finalize")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        status: value
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    })
}

/// Challenge tokens become URL path segments and map keys:
/// accept only the base64url alphabet, bounded length.
fn validate_token(token: &str) -> Result<(), AcmeError> {
    let ok = !token.is_empty()
        && token.len() <= 256
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(AcmeError::Protocol(
            "CA returned a malformed http-01 token".to_string(),
        ))
    }
}

fn verify_chain(
    chain_pem: &[u8],
    domains: &[String],
    expected_key: Option<&PKey<Private>>,
) -> Result<(), AcmeError> {
    if !chain_pem.starts_with(b"-----BEGIN CERTIFICATE-----") {
        return Err(AcmeError::Protocol(
            "certificate download is not PEM".to_string(),
        ));
    }
    let certs = X509::stack_from_pem(chain_pem)
        .map_err(|e| AcmeError::Protocol(format!("certificate parse: {e}")))?;
    let leaf = certs
        .first()
        .ok_or_else(|| AcmeError::Protocol("empty certificate chain".to_string()))?;
    let mut covered: Vec<String> = Vec::new();
    if let Some(sans) = leaf.subject_alt_names() {
        for entry in sans {
            if let Some(dns) = entry.dnsname() {
                covered.push(dns.to_lowercase());
            }
        }
    }
    for domain in domains {
        if !covered.iter().any(|name| name == &domain.to_lowercase()) {
            return Err(AcmeError::Protocol(format!(
                "issued certificate does not cover {domain}"
            )));
        }
    }
    if let Some(key) = expected_key {
        let leaf_public = leaf
            .public_key()
            .map_err(|e| AcmeError::Crypto(format!("leaf public key: {e}")))?;
        let expected_der = key
            .public_key_to_der()
            .map_err(|e| AcmeError::Crypto(format!("key der: {e}")))?;
        let leaf_der = leaf_public
            .public_key_to_der()
            .map_err(|e| AcmeError::Crypto(format!("leaf key der: {e}")))?;
        if leaf_der != expected_der {
            return Err(AcmeError::Protocol(
                "issued certificate does not match the generated key".to_string(),
            ));
        }
    }
    Ok(())
}

// ---------- Renewal management ----------

/// Outcome for one domain group in one renewal pass.
#[derive(Debug, PartialEq)]
pub enum GroupOutcome {
    /// A fresh certificate was installed; fingerprint (hex).
    Installed { fingerprint_sha256: String },
    /// Renewal failed; the previous certificate keeps serving.
    Failed { reason: String },
    /// Current certificate is healthy; nothing to do.
    Skipped,
}

/// Per-group report from one renewal pass.
#[derive(Debug)]
pub struct GroupReport {
    pub domains: Vec<String>,
    pub outcome: GroupOutcome,
}

/// The renewal driver. One instance exists per process; the
/// `in_progress` flag makes concurrent passes impossible —
/// a second caller gets `AlreadyRunning`, never a second
/// order against the CA.
pub struct AcmeManager {
    backoff_first_secs: u64,
    in_progress: AtomicBool,
}

impl Default for AcmeManager {
    fn default() -> Self { AcmeManager::new() }
}

impl AcmeManager {
    pub fn new() -> AcmeManager {
        AcmeManager {
            backoff_first_secs: BACKOFF_FIRST_SECS,
            in_progress: AtomicBool::new(false),
        }
    }

    /// Manager with a custom first-backoff (tests use 0 so
    /// failure paths run at full speed; production uses
    /// BACKOFF_FIRST_SECS).
    #[cfg(test)]
    pub fn with_backoff_first_secs(backoff_first_secs: u64) -> AcmeManager {
        AcmeManager {
            backoff_first_secs,
            in_progress: AtomicBool::new(false),
        }
    }

    fn backoff_for(&self, attempt: u32) -> u64 { backoff_from(self.backoff_first_secs, attempt) }

    /// One pass over every ACME-managed route group. Groups
    /// are independent: one group's failure never blocks or
    /// rolls back another's success.
    pub fn run_once(&self, state: &State) -> Result<Vec<GroupReport>, AcmeError> {
        if self
            .in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(AcmeError::AlreadyRunning);
        }
        let _guard = ResetGuard {
            flag: &self.in_progress,
        };
        let config = state.config_snapshot();
        if !config.lets_encrypt.enabled {
            return Ok(Vec::new());
        }
        let mut reports = Vec::new();
        for domains in managed_groups(&config) {
            let outcome = self.run_group(state, &config, &domains);
            reports.push(GroupReport { domains, outcome });
        }
        Ok(reports)
    }

    fn run_group(&self, state: &State, config: &Config, domains: &[String]) -> GroupOutcome {
        if !group_needs_certificate(state, domains) {
            return GroupOutcome::Skipped;
        }
        let mut last_error: Option<AcmeError> = None;
        for attempt in 0..MAX_ATTEMPTS_PER_GROUP {
            if attempt > 0 {
                std::thread::sleep(Duration::from_secs(self.backoff_for(attempt)));
            }
            match self.obtain_and_install(state, config, domains) {
                Ok(fingerprint) => {
                    return GroupOutcome::Installed {
                        fingerprint_sha256: fingerprint,
                    };
                }
                Err(error) => {
                    let retryable = error.is_retryable();
                    log::warn!(
                        "acme: attempt {} for {} failed: {error}",
                        attempt + 1,
                        domains.join(", ")
                    );
                    last_error = Some(error);
                    if !retryable {
                        break;
                    }
                }
            }
        }
        GroupOutcome::Failed {
            reason: last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unknown failure".to_string()),
        }
    }

    fn obtain_and_install(
        &self,
        state: &State,
        config: &Config,
        domains: &[String],
    ) -> Result<String, AcmeError> {
        let acme = &config.lets_encrypt;
        let account_key = load_or_create_account_key(&config.state_dir)?;
        let extra_roots_pem = match &acme.ca_root_pem {
            Some(path) => Some(
                std::fs::read(path)
                    .map_err(|e| AcmeError::Io(format!("read ca root {:?}: {e}", path)))?,
            ),
            None => None,
        };
        let transport = HttpsTransport {
            extra_roots_pem: extra_roots_pem.unwrap_or_default(),
            insecure_skip_verify: acme.insecure_skip_verify,
        };
        let mut client = AcmeClient::connect(
            transport,
            &acme.directory_url,
            account_key,
            acme.insecure_skip_verify,
        )?;
        client.ensure_account(&acme.email)?;
        let deadline = Instant::now() + Duration::from_secs(ORDER_DEADLINE_SECS);
        let (chain_pem, key_pem) = client.obtain(domains, &state.acme_challenges, deadline)?;
        persist_and_install(state, domains, &chain_pem, &key_pem)
    }
}

struct ResetGuard<'a> {
    flag: &'a AtomicBool,
}

impl Drop for ResetGuard<'_> {
    fn drop(&mut self) { self.flag.store(false, Ordering::SeqCst); }
}

/// Backoff before retry attempt `attempt` (1-based retries):
/// first, 2*first, 4*first, ... capped at BACKOFF_CAP_SECS.
fn backoff_from(first_secs: u64, attempt: u32) -> u64 {
    let shift = attempt.saturating_sub(1).min(10);
    (first_secs << shift).min(BACKOFF_CAP_SECS)
}

/// ACME-managed domain groups: one per route that has no
/// operator-supplied certificate. The primary host leads;
/// additional hosts join the same certificate, mirroring how
/// the certificate store keys entries.
pub fn managed_groups(config: &Config) -> Vec<Vec<String>> {
    let mut groups: Vec<Vec<String>> = Vec::new();
    for route in &config.routes {
        if route.tls_cert.is_some() {
            continue;
        }
        let mut domains = vec![route.host.clone()];
        for extra in &route.additional_hosts {
            if !domains.contains(extra) {
                domains.push(extra.clone());
            }
        }
        if !groups.contains(&domains) {
            groups.push(domains);
        }
    }
    groups
}

/// Decide whether a group needs a (new) certificate: any
/// domain unserved, any serving entry self-signed, any entry
/// inside the renewal threshold, or entries that disagree
/// (a group must converge on ONE certificate covering all
/// its names, e.g. after a bootstrap from per-name certs).
pub fn group_needs_certificate(state: &State, domains: &[String]) -> bool {
    let store = match state.certs.read() {
        Ok(guard) => guard.clone(),
        Err(_) => return true,
    };
    let mut fingerprints: Vec<&str> = Vec::new();
    for domain in domains {
        match store.get(domain) {
            None => return true,
            Some(entry) => {
                if entry.self_signed || entry.days_until_expiry < RENEW_THRESHOLD_DAYS {
                    return true;
                }
                fingerprints.push(entry.fingerprint_sha256.as_str());
            }
        }
    }
    fingerprints.windows(2).any(|pair| pair[0] != pair[1])
}

// ---------- Persistence + hot-swap ----------

fn safe_filename(host: &str) -> String { host.replace(['/', '\\', ':', '*'], "_") }

/// Write the chain and key under `<state_dir>/acme/` (key
/// 0600, atomic rename), then swap entries for every domain
/// in the group into the live store. The listener is never
/// touched; in-flight handshakes keep the Arc they started
/// with. Returns the installed fingerprint.
pub fn persist_and_install(
    state: &State,
    domains: &[String],
    chain_pem: &[u8],
    key_pem: &[u8],
) -> Result<String, AcmeError> {
    let config = state.config_snapshot();
    let dir = config.state_dir.join(ACME_SUBDIR);
    std::fs::create_dir_all(&dir).map_err(|e| AcmeError::Io(format!("acme dir: {e}")))?;
    let primary = safe_filename(&domains[0]);
    write_atomic(&dir.join(format!("{primary}.crt")), chain_pem)?;
    crate::cert::write_key_0600(&dir.join(format!("{primary}.key")), key_pem)
        .map_err(|e| AcmeError::Io(format!("persist cert key: {e}")))?;
    let mut entries: Vec<crate::cert::CertEntry> = Vec::new();
    for domain in domains {
        let entry =
            crate::cert::entry_from_pem(domain, chain_pem.to_vec(), key_pem.to_vec(), false)
                .map_err(AcmeError::Protocol)?;
        entries.push(entry);
    }
    let fingerprint = entries
        .first()
        .map(|entry| entry.fingerprint_sha256.clone())
        .unwrap_or_default();
    let mut guard = state
        .certs
        .write()
        .map_err(|_| AcmeError::Protocol("cert store lock poisoned".to_string()))?;
    let mut merged = guard.entries.clone();
    for entry in entries {
        merged.insert(entry.host.clone(), entry);
    }
    *guard = Arc::new(CertStore { entries: merged });
    Ok(fingerprint)
}

/// Atomic write: temp file in the same directory, then
/// rename, so a crash never leaves a torn certificate.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), AcmeError> {
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, bytes).map_err(|e| AcmeError::Io(format!("write {:?}: {e}", temp)))?;
    std::fs::rename(&temp, path).map_err(|e| AcmeError::Io(format!("rename {:?}: {e}", path)))?;
    Ok(())
}

/// Startup preload: fold certificates persisted by earlier
/// ACME runs (`<state_dir>/acme/*.crt` + sibling `.key`)
/// into the freshly built store, so a restart serves the
/// real certificate immediately instead of waiting for the
/// renewal loop. Entries already present (operator-supplied)
/// always win; entries are keyed by the names the
/// certificate actually covers (its SAN list).
pub fn preload_entries(state_dir: &Path, store: &mut CertStore) {
    let dir = state_dir.join(ACME_SUBDIR);
    let read = match std::fs::read_dir(&dir) {
        Ok(read) => read,
        Err(error) => {
            // A missing directory is the normal first-run
            // state; an existing but unreadable one is an
            // operator error (ownership/permissions) that
            // must never fail silently.
            if dir.exists() {
                log::warn!("acme preload: cannot read {dir:?}: {error}");
            }
            return;
        }
    };
    let mut files: Vec<PathBuf> = read
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().map(|ext| ext == "crt").unwrap_or(false))
        .collect();
    files.sort();
    for cert_path in files {
        let key_path = cert_path.with_extension("key");
        if !key_path.exists() {
            continue;
        }
        let (Ok(chain_pem), Ok(key_pem)) = (std::fs::read(&cert_path), std::fs::read(&key_path))
        else {
            log::warn!("acme preload: cannot read certificate pair for {cert_path:?}");
            continue;
        };
        let Ok(certs) = X509::stack_from_pem(&chain_pem) else {
            log::warn!("acme preload: cannot parse certificate {cert_path:?}");
            continue;
        };
        let Some(leaf) = certs.first() else { continue };
        let Some(sans) = leaf.subject_alt_names() else {
            continue;
        };
        for san in sans {
            let Some(host) = san.dnsname() else { continue };
            let host = host.to_lowercase();
            if store.entries.contains_key(&host) {
                continue;
            }
            if let Ok(entry) =
                crate::cert::entry_from_pem(&host, chain_pem.clone(), key_pem.clone(), false)
            {
                store.entries.insert(host, entry);
            }
        }
    }
}

// ---------- Renewal loop ----------

/// Background driver: one pass immediately at startup (a
/// fresh process may hold no certificate at all), then a
/// pass every CHECK_INTERVAL_SECS. The blocking flow runs
/// in `spawn_blocking`; aborting this task on shutdown is
/// the caller's job, matching the other background tasks.
pub async fn renewal_loop(state: Arc<State>) {
    let manager = Arc::new(AcmeManager::new());
    loop {
        let pass_manager = manager.clone();
        let pass_state = state.clone();
        let joined = tokio::task::spawn_blocking(move || pass_manager.run_once(&pass_state)).await;
        match joined {
            Ok(Ok(reports)) => {
                for report in &reports {
                    match &report.outcome {
                        GroupOutcome::Installed { fingerprint_sha256 } => log::info!(
                            "acme: installed certificate for {} (sha256 {fingerprint_sha256})",
                            report.domains.join(", ")
                        ),
                        GroupOutcome::Failed { reason } => log::warn!(
                            "acme: renewal for {} failed: {reason}",
                            report.domains.join(", ")
                        ),
                        GroupOutcome::Skipped => {}
                    }
                }
            }
            Ok(Err(error)) => log::warn!("acme: renewal pass failed: {error}"),
            Err(join_error) => log::warn!("acme: renewal task join failed: {join_error}"),
        }
        tokio::time::sleep(Duration::from_secs(CHECK_INTERVAL_SECS)).await;
    }
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Mutex;

    use openssl::ec::EcPoint;

    use super::*;

    fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> HttpResponse {
        HttpResponse {
            body: body.as_bytes().to_vec(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            status,
        }
    }

    fn problem(status: u16, problem_type: &str, detail: &str) -> HttpResponse {
        resp(
            status,
            &[("Content-Type", "application/problem+json")],
            &json!({"type": problem_type, "detail": detail}).to_string(),
        )
    }

    fn test_key() -> AccountKey { AccountKey::from_pkey(generate_p256_key().unwrap()).unwrap() }

    fn fresh_store() -> Arc<RwLock<BTreeMap<String, String>>> {
        Arc::new(RwLock::new(BTreeMap::new()))
    }

    fn deadline() -> Instant { Instant::now() + Duration::from_secs(60) }

    // ----- Pure-function validation tests -----

    #[test]
    fn validation_thumbprint_rfc7638_vector() {
        // RFC 7638 section 3.1 worked example (RSA key): the
        // canonical JSON and expected thumbprint are published.
        let canonical = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"}";
        assert_eq!(
            jwk_thumbprint(canonical),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn validation_jwk_and_signature_rfc7515_key() {
        // RFC 7515 appendix A.3 EC key components.
        let x = b64u_decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU").unwrap();
        let y = b64u_decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0").unwrap();
        let d = b64u_decode("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI").unwrap();
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();
        let mut point = EcPoint::new(&group).unwrap();
        point
            .set_affine_coordinates_gfp(
                &group,
                &BigNum::from_slice(&x).unwrap(),
                &BigNum::from_slice(&y).unwrap(),
                &mut ctx,
            )
            .unwrap();
        let ec_key =
            EcKey::from_private_components(&group, &BigNum::from_slice(&d).unwrap(), &point)
                .unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let key = AccountKey::from_pkey(pkey).unwrap();
        assert_eq!(
            key.jwk_json,
            "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}"
        );
        // Sign and verify: raw R||S must verify as ECDSA/SHA-256.
        let raw = key.sign_es256(b"vongola test message").unwrap();
        assert_eq!(raw.len(), 64);
        let sig = openssl::ecdsa::EcdsaSig::from_private_components(
            BigNum::from_slice(&raw[..32]).unwrap(),
            BigNum::from_slice(&raw[32..]).unwrap(),
        )
        .unwrap();
        let der = sig.to_der().unwrap();
        let mut verifier =
            openssl::sign::Verifier::new(MessageDigest::sha256(), &key.pkey).unwrap();
        verifier.update(b"vongola test message").unwrap();
        assert!(verifier.verify(&der).unwrap());
        let mut verifier =
            openssl::sign::Verifier::new(MessageDigest::sha256(), &key.pkey).unwrap();
        verifier.update(b"tampered message").unwrap();
        assert!(!verifier.verify(&der).unwrap());
    }

    #[test]
    fn validation_domain_rules() {
        assert!(validate_domain("qompass.ai").is_ok());
        assert!(validate_domain("www.qompass.ai").is_ok());
        assert!(validate_domain("vongola.test").is_ok());
    }

    #[test]
    fn adversarial_domain_rules_reject() {
        for bad in [
            "*.qompass.ai",
            "127.0.0.1",
            "",
            "-bad.test",
            "bad-.test",
            "a..test",
            "under_score.test",
            "white space.test",
        ] {
            assert!(validate_domain(bad).is_err(), "must reject {bad:?}");
        }
        let long = format!("{}.test", "a".repeat(250));
        assert!(validate_domain(&long).is_err());
    }

    #[test]
    fn validation_backoff_schedule() {
        assert_eq!(backoff_from(BACKOFF_FIRST_SECS, 1), 60);
        assert_eq!(backoff_from(BACKOFF_FIRST_SECS, 2), 120);
        assert_eq!(backoff_from(BACKOFF_FIRST_SECS, 3), 240);
        assert_eq!(backoff_from(BACKOFF_FIRST_SECS, 20), BACKOFF_CAP_SECS);
    }

    #[test]
    fn validation_error_classification() {
        let bad_nonce = AcmeError::from_problem(
            400,
            br#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"x"}"#,
        );
        assert!(bad_nonce.is_bad_nonce());
        assert!(!bad_nonce.is_retryable());
        let rate = AcmeError::from_problem(
            429,
            br#"{"type":"urn:ietf:params:acme:error:rateLimited","detail":"x"}"#,
        );
        assert!(rate.is_retryable());
        let denied = AcmeError::from_problem(
            403,
            br#"{"type":"urn:ietf:params:acme:error:unauthorized","detail":"x"}"#,
        );
        assert!(!denied.is_retryable());
        let garbage = AcmeError::from_problem(502, b"<html>proxy error</html>");
        assert!(matches!(garbage, AcmeError::Http { status: 502, .. }));
        assert!(!garbage.is_bad_nonce());
    }

    #[test]
    fn validation_http_response_parsing() {
        let raw = b"HTTP/1.1 201 Created\r\nLocation: http://ca.test/order/1\r\nReplay-Nonce: n-1\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = Cursor::new(raw.to_vec());
        let response = read_response(&mut cursor).unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(response.header("location"), Some("http://ca.test/order/1"));
        assert_eq!(response.header("REPLAY-NONCE"), Some("n-1"));
        assert_eq!(response.body, b"hello");
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        let mut cursor = Cursor::new(chunked.to_vec());
        let response = read_response(&mut cursor).unwrap();
        assert_eq!(response.body, b"abcde");
    }

    #[test]
    fn adversarial_plaintext_non_loopback_refused() {
        let mut transport = HttpsTransport {
            extra_roots_pem: Vec::new(),
            insecure_skip_verify: false,
        };
        let error = transport
            .send("GET", "http://ca.example.test/dir", &[], &[])
            .unwrap_err();
        assert!(matches!(error, AcmeError::Config(_)), "{error}");
    }

    #[test]
    fn adversarial_token_validation() {
        assert!(validate_token("abc-DEF_123").is_ok());
        for bad in ["", "has/slash", "has.dot", "sp ace", "quo\"te"] {
            assert!(validate_token(bad).is_err(), "must reject {bad:?}");
        }
    }

    // ----- Mock CA -----
    //
    // A state-machine ACME test double speaking enough RFC
    // 8555 to drive the real client: it verifies the JWS
    // protected URL, checks the published key authorization
    // against the account key the client presented, and
    // issues real X.509 certificates (OpenSSL) from the CSR
    // the client actually sent.

    struct MockAuthz {
        domain: String,
        posted_valid: Option<bool>,
    }

    struct MockCa {
        account_thumbprint: Option<String>,
        authzs: Vec<MockAuthz>,
        base: String,
        bad_nonce_once: bool,
        bad_nonce_spent: bool,
        bad_token: bool,
        ca_cert: X509,
        ca_key: PKey<Private>,
        cert_pem: Option<Vec<u8>>,
        challenges: Arc<RwLock<BTreeMap<String, String>>>,
        fail_authz: bool,
        finalized: bool,
        finalize_error: bool,
        new_order_posts: usize,
        nonce_counter: u64,
        wrong_authz_domain: bool,
        wrong_cert_name: bool,
    }

    fn make_ca_key_cert() -> (PKey<Private>, X509) {
        let key = generate_p256_key().unwrap();
        let mut name_builder = openssl::x509::X509NameBuilder::new().unwrap();
        name_builder
            .append_entry_by_text("CN", "Vongola Mock CA")
            .unwrap();
        let name = name_builder.build();
        let mut builder = openssl::x509::X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        let serial =
            openssl::asn1::Asn1Integer::from_bn(&BigNum::from_dec_str("1000").unwrap()).unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
        let not_after = openssl::asn1::Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();
        let basic = openssl::x509::extension::BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .unwrap();
        builder.append_extension(basic).unwrap();
        let key_usage = openssl::x509::extension::KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap();
        builder.append_extension(key_usage).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (key, builder.build())
    }

    impl MockCa {
        fn new(base: &str, challenges: Arc<RwLock<BTreeMap<String, String>>>) -> MockCa {
            let (ca_key, ca_cert) = make_ca_key_cert();
            MockCa {
                account_thumbprint: None,
                authzs: Vec::new(),
                base: base.to_string(),
                bad_nonce_once: false,
                bad_nonce_spent: false,
                bad_token: false,
                ca_cert,
                ca_key,
                cert_pem: None,
                challenges,
                fail_authz: false,
                finalized: false,
                finalize_error: false,
                new_order_posts: 0,
                nonce_counter: 0,
                wrong_authz_domain: false,
                wrong_cert_name: false,
            }
        }

        fn fresh_nonce(&mut self) -> String {
            self.nonce_counter += 1;
            format!("mock-nonce-{}", self.nonce_counter)
        }

        fn with_nonce(&mut self, mut response: HttpResponse) -> HttpResponse {
            let nonce = self.fresh_nonce();
            response.headers.push(("Replay-Nonce".to_string(), nonce));
            response
        }

        fn jws_parts(&self, body: &[u8]) -> (Value, Value) {
            let jws: Value = serde_json::from_slice(body).expect("jws json");
            let protected = b64u_decode(jws["protected"].as_str().unwrap()).unwrap();
            let payload = b64u_decode(jws["payload"].as_str().unwrap()).unwrap();
            let protected_json: Value = serde_json::from_slice(&protected).unwrap();
            let payload_json: Value = if payload.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&payload).unwrap()
            };
            (protected_json, payload_json)
        }

        fn issue(&self, csr_der: &[u8], domains: &[String]) -> Vec<u8> {
            let request = openssl::x509::X509Req::from_der(csr_der).unwrap();
            let pubkey = request.public_key().unwrap();
            let mut builder = openssl::x509::X509Builder::new().unwrap();
            builder.set_version(2).unwrap();
            let serial =
                openssl::asn1::Asn1Integer::from_bn(&BigNum::from_dec_str("2000").unwrap())
                    .unwrap();
            builder.set_serial_number(&serial).unwrap();
            builder.set_subject_name(request.subject_name()).unwrap();
            builder
                .set_issuer_name(self.ca_cert.subject_name())
                .unwrap();
            builder.set_pubkey(&pubkey).unwrap();
            let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
            let not_after = openssl::asn1::Asn1Time::days_from_now(90).unwrap();
            builder.set_not_before(&not_before).unwrap();
            builder.set_not_after(&not_after).unwrap();
            let context = builder.x509v3_context(Some(&self.ca_cert), None);
            let mut san = openssl::x509::extension::SubjectAlternativeName::new();
            for domain in domains {
                san.dns(domain);
            }
            builder
                .append_extension(san.build(&context).unwrap())
                .unwrap();
            builder.sign(&self.ca_key, MessageDigest::sha256()).unwrap();
            let leaf = builder.build();
            let mut pem = leaf.to_pem().unwrap();
            pem.extend_from_slice(&self.ca_cert.to_pem().unwrap());
            pem
        }

        fn order_json(&self) -> String {
            let identifiers: Vec<Value> = self
                .authzs
                .iter()
                .map(|a| json!({"type": "dns", "value": a.domain}))
                .collect();
            let authorizations: Vec<String> = (0..self.authzs.len())
                .map(|i| format!("{}/authz/{}", self.base, i + 1))
                .collect();
            let all_valid = self.authzs.iter().all(|a| a.posted_valid == Some(true));
            let status = if self.finalized {
                "valid"
            } else if all_valid && !self.authzs.is_empty() {
                "ready"
            } else {
                "pending"
            };
            let mut order = json!({
                "status": status,
                "identifiers": identifiers,
                "authorizations": authorizations,
                "finalize": format!("{}/finalize/1", self.base),
            });
            if self.finalized {
                order["certificate"] = json!(format!("{}/cert/1", self.base));
            }
            order.to_string()
        }

        fn handle(&mut self, method: &str, path: &str, body: &[u8]) -> HttpResponse {
            let response = self.dispatch(method, path, body).unwrap_or_else(|r| r);
            if path == "/dir" {
                return response;
            }
            self.with_nonce(response)
        }

        fn dispatch(
            &mut self,
            method: &str,
            path: &str,
            body: &[u8],
        ) -> Result<HttpResponse, HttpResponse> {
            match (method, path) {
                ("GET", "/dir") => Ok(resp(
                    200,
                    &[],
                    &json!({
                        "newNonce": format!("{}/nonce", self.base),
                        "newAccount": format!("{}/new-acct", self.base),
                        "newOrder": format!("{}/new-order", self.base),
                    })
                    .to_string(),
                )),
                ("HEAD", "/nonce") => Ok(resp(200, &[], "")),
                ("POST", "/new-acct") => {
                    let (protected, _payload) = self.jws_parts(body);
                    let jwk = &protected["jwk"];
                    let canonical =
                        jwk_canonical_json(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap());
                    self.account_thumbprint = Some(jwk_thumbprint(&canonical));
                    Ok(resp(
                        201,
                        &[("Location", &format!("{}/acct/1", self.base))],
                        "{}",
                    ))
                }
                ("POST", "/new-order") => {
                    self.new_order_posts += 1;
                    if self.bad_nonce_once && !self.bad_nonce_spent {
                        self.bad_nonce_spent = true;
                        let mut r = problem(
                            400,
                            "urn:ietf:params:acme:error:badNonce",
                            "mock nonce rejection",
                        );
                        let nonce = self.fresh_nonce();
                        r.headers.push(("Replay-Nonce".to_string(), nonce));
                        return Ok(r);
                    }
                    let (_protected, payload) = self.jws_parts(body);
                    self.authzs = payload["identifiers"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|id| MockAuthz {
                            domain: id["value"].as_str().unwrap().to_string(),
                            posted_valid: None,
                        })
                        .collect();
                    let order = self.order_json();
                    Ok(resp(
                        201,
                        &[("Location", &format!("{}/order/1", self.base))],
                        &order,
                    ))
                }
                ("POST", "/order/1") => Ok(resp(200, &[], &self.order_json())),
                ("POST", path) if path.starts_with("/authz/") => {
                    let index: usize = path.trim_start_matches("/authz/").parse().unwrap_or(0);
                    Ok(self.authz_json(index))
                }
                ("POST", path) if path.starts_with("/chal/") => {
                    let index: usize = path.trim_start_matches("/chal/").parse().unwrap_or(0);
                    self.answer_challenge(index);
                    Ok(resp(200, &[], "{}"))
                }
                ("POST", "/finalize/1") => {
                    if self.finalize_error {
                        return Ok(problem(
                            500,
                            "urn:ietf:params:acme:error:serverInternal",
                            "mock finalize failure",
                        ));
                    }
                    let (_protected, payload) = self.jws_parts(body);
                    let csr_der = b64u_decode(payload["csr"].as_str().unwrap()).unwrap();
                    let domains: Vec<String> = if self.wrong_cert_name {
                        vec!["other.test".to_string()]
                    } else {
                        self.authzs.iter().map(|a| a.domain.clone()).collect()
                    };
                    self.cert_pem = Some(self.issue(&csr_der, &domains));
                    self.finalized = true;
                    Ok(resp(200, &[], &self.order_json()))
                }
                ("POST", "/cert/1") => {
                    let pem = self.cert_pem.clone().unwrap_or_default();
                    Ok(HttpResponse {
                        body: pem,
                        headers: vec![(
                            "Content-Type".to_string(),
                            "application/pem-certificate-chain".to_string(),
                        )],
                        status: 200,
                    })
                }
                _ => Ok(problem(
                    404,
                    "urn:ietf:params:acme:error:malformed",
                    "mock: unknown path",
                )),
            }
        }

        fn authz_json(&self, index: usize) -> HttpResponse {
            let Some(authz) = self.authzs.get(index - 1) else {
                return problem(
                    404,
                    "urn:ietf:params:acme:error:malformed",
                    "mock: no such authz",
                );
            };
            let token = if self.bad_token {
                "bad/token!".to_string()
            } else {
                format!("mock-token-{index}")
            };
            let identifier = if self.wrong_authz_domain {
                "not-ordered.test"
            } else {
                &authz.domain
            };
            let (status, error) = match authz.posted_valid {
                Some(true) => ("valid", None),
                Some(false) => (
                    "invalid",
                    Some(json!({
                        "type": "urn:ietf:params:acme:error:connection",
                        "detail": "mock validation failure",
                    })),
                ),
                None => ("pending", None),
            };
            let mut authz_json = json!({
                "status": status,
                "identifier": {"type": "dns", "value": identifier},
                "challenges": [{
                    "type": "http-01",
                    "url": format!("{}/chal/{}", self.base, index),
                    "token": token,
                    "status": status,
                }],
            });
            if let Some(error) = error {
                authz_json["challenges"][0]["error"] = error;
            }
            resp(200, &[], &authz_json.to_string())
        }

        fn answer_challenge(&mut self, index: usize) {
            let token = format!("mock-token-{index}");
            let expected = match &self.account_thumbprint {
                Some(thumbprint) => format!("{token}.{thumbprint}"),
                None => String::new(),
            };
            let published = self
                .challenges
                .read()
                .ok()
                .and_then(|map| map.get(&token).cloned());
            let valid = !self.fail_authz && published.as_deref() == Some(expected.as_str());
            if let Some(authz) = self.authzs.get_mut(index - 1) {
                authz.posted_valid = Some(valid);
            }
        }
    }

    impl Transport for MockCa {
        fn send(
            &mut self,
            method: &str,
            url: &str,
            _headers: &[(String, String)],
            body: &[u8],
        ) -> Result<HttpResponse, AcmeError> {
            let parsed = parse_url(url)?;
            Ok(self.handle(method, &parsed.path_and_query, body))
        }
    }

    fn mock_client() -> (AcmeClient<MockCa>, Arc<RwLock<BTreeMap<String, String>>>) {
        let store = fresh_store();
        let ca = MockCa::new("http://ca.test", store.clone());
        let client = AcmeClient::connect(ca, "http://ca.test/dir", test_key(), false).unwrap();
        (client, store)
    }

    // ----- Flow tests over the mock CA -----

    #[test]
    fn validation_full_order_flow() {
        let (mut client, store) = mock_client();
        client.ensure_account("ops@qompass.ai").unwrap();
        let domains = vec!["vongola.test".to_string(), "www.vongola.test".to_string()];
        let (chain, key_pem) = client.obtain(&domains, &*store, deadline()).unwrap();
        assert!(chain.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
        // Challenges are withdrawn when the flow ends.
        assert!(store.read().unwrap().is_empty());
        assert_eq!(client.transport.new_order_posts, 1);
    }

    #[test]
    fn adversarial_bad_nonce_recovery() {
        let (mut client, store) = mock_client();
        client.transport.bad_nonce_once = true;
        client.ensure_account("ops@qompass.ai").unwrap();
        let domains = vec!["vongola.test".to_string()];
        let result = client.obtain(&domains, &*store, deadline());
        assert!(result.is_ok(), "badNonce must be recovered: {result:?}");
        assert_eq!(client.transport.new_order_posts, 2);
    }

    #[test]
    fn adversarial_authz_invalid_fails_clean() {
        let (mut client, store) = mock_client();
        client.transport.fail_authz = true;
        client.ensure_account("ops@qompass.ai").unwrap();
        let domains = vec!["vongola.test".to_string()];
        let error = client.obtain(&domains, &*store, deadline()).unwrap_err();
        assert!(matches!(error, AcmeError::Ca { .. }), "{error}");
        assert!(
            store.read().unwrap().is_empty(),
            "challenge must be withdrawn"
        );
    }

    #[test]
    fn adversarial_wrong_authz_domain_refused() {
        let (mut client, store) = mock_client();
        client.transport.wrong_authz_domain = true;
        client.ensure_account("ops@qompass.ai").unwrap();
        let domains = vec!["vongola.test".to_string()];
        let error = client.obtain(&domains, &*store, deadline()).unwrap_err();
        assert!(matches!(error, AcmeError::Protocol(_)), "{error}");
        assert!(store.read().unwrap().is_empty());
    }

    #[test]
    fn adversarial_bad_token_refused() {
        let (mut client, store) = mock_client();
        client.transport.bad_token = true;
        client.ensure_account("ops@qompass.ai").unwrap();
        let domains = vec!["vongola.test".to_string()];
        let error = client.obtain(&domains, &*store, deadline()).unwrap_err();
        assert!(matches!(error, AcmeError::Protocol(_)), "{error}");
    }

    #[test]
    fn adversarial_wrong_cert_name_refused() {
        let (mut client, store) = mock_client();
        client.transport.wrong_cert_name = true;
        client.ensure_account("ops@qompass.ai").unwrap();
        let domains = vec!["vongola.test".to_string()];
        let error = client.obtain(&domains, &*store, deadline()).unwrap_err();
        assert!(
            matches!(error, AcmeError::Protocol(ref m) if m.contains("does not cover")),
            "{error}"
        );
    }

    #[test]
    fn adversarial_finalize_ca_error_is_retryable() {
        let (mut client, store) = mock_client();
        client.transport.finalize_error = true;
        client.ensure_account("ops@qompass.ai").unwrap();
        let domains = vec!["vongola.test".to_string()];
        let error = client.obtain(&domains, &*store, deadline()).unwrap_err();
        assert!(error.is_retryable(), "{error}");
    }

    // ----- Loopback integration: real transport, real HTTP -----

    /// Serve a MockCa over a real TCP listener. Returns the
    /// base URL and a stop flag; the thread serves until the
    /// flag is set, handling one connection at a time (the
    /// client is strictly sequential).
    fn serve_mock_ca(
        ca: Arc<Mutex<MockCa>>,
    ) -> (String, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                        let request = read_test_request(&mut stream);
                        let (method, path, body) = parse_test_request(&request);
                        let response = {
                            let mut ca = ca.lock().unwrap();
                            ca.handle(&method, &path, &body)
                        };
                        let mut out = format!(
                            "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                            response.status,
                            response.body.len()
                        );
                        for (name, value) in &response.headers {
                            out.push_str(&format!("{name}: {value}\r\n"));
                        }
                        out.push_str("\r\n");
                        let _ = stream.write_all(out.as_bytes());
                        let _ = stream.write_all(&response.body);
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        (format!("http://127.0.0.1:{port}"), stop, handle)
    }

    fn read_test_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut raw: Vec<u8> = Vec::new();
        let mut buffer = [0u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).unwrap_or(0);
            if read == 0 {
                return raw;
            }
            raw.extend_from_slice(&buffer[..read]);
            if let Some(position) = find_subslice(&raw, b"\r\n\r\n") {
                break position + 4;
            }
        };
        let header_text = String::from_utf8_lossy(&raw[..header_end]).into_owned();
        let length: usize = header_text
            .lines()
            .find_map(|line| {
                line.to_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|value| value.trim().parse().ok())
            })
            .unwrap_or(0);
        while raw.len() < header_end + length {
            let read = stream.read(&mut buffer).unwrap_or(0);
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..read]);
        }
        raw
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn parse_test_request(raw: &[u8]) -> (String, String, Vec<u8>) {
        let header_end = find_subslice(raw, b"\r\n\r\n").map(|p| p + 4).unwrap_or(0);
        let header_text = String::from_utf8_lossy(&raw[..header_end]).into_owned();
        let first = header_text.lines().next().unwrap_or("");
        let mut parts = first.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        (method, path, raw[header_end..].to_vec())
    }

    #[test]
    fn validation_loopback_full_flow_real_transport() {
        let store = fresh_store();
        let ca = Arc::new(Mutex::new(MockCa::new(
            "http://loopback.invalid",
            store.clone(),
        )));
        let (base, stop, thread) = serve_mock_ca(ca.clone());
        {
            let mut guard = ca.lock().unwrap();
            guard.base = base.clone();
        }
        let transport = HttpsTransport {
            extra_roots_pem: Vec::new(),
            insecure_skip_verify: false,
        };
        let directory = format!("{base}/dir");
        let mut client = AcmeClient::connect(transport, &directory, test_key(), false).unwrap();
        client.ensure_account("ops@qompass.ai").unwrap();
        let domains = vec!["vongola.test".to_string(), "www.vongola.test".to_string()];
        let (chain, key_pem) = client.obtain(&domains, &*store, deadline()).unwrap();
        assert!(chain.starts_with(b"-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with(b"-----BEGIN PRIVATE KEY-----"));
        assert!(store.read().unwrap().is_empty());
        stop.store(true, Ordering::SeqCst);
        let _ = thread.join();
    }

    // ----- Manager / state level -----

    fn test_state(route_yaml: &str, acme_yaml: &str) -> (tempfile::TempDir, Arc<State>) {
        let dir = tempfile::tempdir().unwrap();
        let yaml = format!(
            "listeners:\n  admin: {{bind: \"127.0.0.1:9091\"}}\n  http: {{bind: \"0.0.0.0:8080\"}}\n  https: {{bind: \"0.0.0.0:4433\"}}\nstate_dir: \"{}\"\nlets_encrypt:\n{}\nroutes:\n{}",
            dir.path().to_string_lossy(),
            acme_yaml,
            route_yaml
        );
        let config: Config = serde_yaml::from_str(&yaml).unwrap();
        let store = CertStore::build(&config).unwrap();
        let state = State::new(config, dir.path().join("vongola.yaml"), store);
        (dir, state)
    }

    fn rcgen_chain(domains: &[&str], days: i64) -> (Vec<u8>, Vec<u8>) {
        let mut params = rcgen::CertificateParams::new(
            domains.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (
            cert.pem().into_bytes(),
            key_pair.serialize_pem().into_bytes(),
        )
    }

    #[test]
    fn validation_account_key_persisted_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_account_key(dir.path()).unwrap();
        let second = load_or_create_account_key(dir.path()).unwrap();
        assert_eq!(first.thumbprint(), second.thumbprint());
        let key_path = dir.path().join(ACME_SUBDIR).join(ACCOUNT_KEY_FILENAME);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "account key must be 0600");
        }
    }

    #[test]
    fn validation_managed_groups() {
        let config: Config = serde_yaml::from_str(
            "listeners:\n  admin: {bind: \"127.0.0.1:9091\"}\n  http: {bind: \"0.0.0.0:8080\"}\n  https: {bind: \"0.0.0.0:4433\"}\nroutes:\n  - host: \"operated.test\"\n    tls_cert: \"/operator.crt\"\n    tls_key: \"/operator.key\"\n    upstreams: [{address: \"127.0.0.1:9000\"}]\n  - host: \"a.test\"\n    additional_hosts: [\"b.test\", \"a.test\"]\n    upstreams: [{address: \"127.0.0.1:9000\"}]\n  - host: \"a.test\"\n    additional_hosts: [\"b.test\"]\n    upstreams: [{address: \"127.0.0.1:9001\"}]",
        )
        .unwrap();
        let groups = managed_groups(&config);
        assert_eq!(
            groups,
            vec![vec!["a.test".to_string(), "b.test".to_string()]],
            "operator-cert route excluded; duplicate groups deduplicated"
        );
    }

    #[test]
    fn validation_run_once_disabled_is_noop() {
        let (_dir, state) = test_state(
            "  - host: \"a.test\"\n    upstreams: [{address: \"127.0.0.1:9000\"}]",
            "  enabled: false",
        );
        let manager = AcmeManager::new();
        let reports = manager.run_once(&state).unwrap();
        assert!(reports.is_empty());
    }

    #[test]
    fn adversarial_run_once_already_running() {
        let (_dir, state) = test_state(
            "  - host: \"a.test\"\n    upstreams: [{address: \"127.0.0.1:9000\"}]",
            "  enabled: true\n  email: \"ops@qompass.ai\"\n  directory_url: \"https://127.0.0.1:9/dir\"",
        );
        let manager = AcmeManager::new();
        manager.in_progress.store(true, Ordering::SeqCst);
        let error = manager.run_once(&state).unwrap_err();
        assert!(matches!(error, AcmeError::AlreadyRunning), "{error}");
    }

    #[test]
    fn validation_run_once_skips_healthy_certificate() {
        let (_dir, state) = test_state(
            "  - host: \"a.test\"\n    additional_hosts: [\"b.test\"]\n    upstreams: [{address: \"127.0.0.1:9000\"}]",
            "  enabled: true\n  email: \"ops@qompass.ai\"\n  directory_url: \"https://127.0.0.1:9/dir\"",
        );
        let domains = vec!["a.test".to_string(), "b.test".to_string()];
        let (chain, key_pem) = rcgen_chain(&["a.test", "b.test"], 90);
        persist_and_install(&state, &domains, &chain, &key_pem).unwrap();
        assert!(!group_needs_certificate(&state, &domains));
        let manager = AcmeManager::with_backoff_first_secs(0);
        let reports = manager.run_once(&state).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].outcome, GroupOutcome::Skipped);
    }

    #[test]
    fn adversarial_failed_renewal_keeps_previous_certificate() {
        let (_dir, state) = test_state(
            "  - host: \"a.test\"\n    self_signed_fallback: true\n    upstreams: [{address: \"127.0.0.1:9000\"}]",
            "  enabled: true\n  email: \"ops@qompass.ai\"\n  directory_url: \"https://127.0.0.1:9/dir\"",
        );
        let before = state
            .certs
            .read()
            .unwrap()
            .get("a.test")
            .map(|entry| entry.fingerprint_sha256.clone());
        assert!(before.is_some(), "self-signed bootstrap must exist");
        let manager = AcmeManager::with_backoff_first_secs(0);
        let reports = manager.run_once(&state).unwrap();
        assert_eq!(reports.len(), 1);
        assert!(
            matches!(reports[0].outcome, GroupOutcome::Failed { .. }),
            "{:?}",
            reports[0].outcome
        );
        let after = state
            .certs
            .read()
            .unwrap()
            .get("a.test")
            .map(|entry| entry.fingerprint_sha256.clone());
        assert_eq!(
            before, after,
            "failed renewal must not disturb the live cert"
        );
    }

    #[test]
    fn validation_preload_roundtrip_and_operator_wins() {
        let (dir, state) = test_state(
            "  - host: \"a.test\"\n    additional_hosts: [\"b.test\"]\n    upstreams: [{address: \"127.0.0.1:9000\"}]",
            "  enabled: false",
        );
        let domains = vec!["a.test".to_string(), "b.test".to_string()];
        let (chain, key_pem) = rcgen_chain(&["a.test", "b.test"], 90);
        let fingerprint = persist_and_install(&state, &domains, &chain, &key_pem).unwrap();
        // Fresh store, as after a restart: preload must fold
        // the persisted pair back in under both names.
        let config = state.config_snapshot();
        let mut store = CertStore::build(&config).unwrap();
        assert!(store.get("a.test").is_none());
        preload_entries(&config.state_dir, &mut store);
        let entry = store.get("a.test").expect("preloaded entry");
        assert_eq!(entry.fingerprint_sha256, fingerprint);
        assert!(store.get("b.test").is_some());
        // And preloading over an existing entry changes nothing.
        let mut store2 = CertStore::build(&config).unwrap();
        let (other_chain, other_key) = rcgen_chain(&["a.test", "b.test"], 45);
        let other = crate::cert::entry_from_pem("a.test", other_chain, other_key, false).unwrap();
        let other_fingerprint = other.fingerprint_sha256.clone();
        store2.entries.insert("a.test".to_string(), other);
        preload_entries(&config.state_dir, &mut store2);
        assert_eq!(
            store2.get("a.test").unwrap().fingerprint_sha256,
            other_fingerprint,
            "existing entries win over preload"
        );
        let _ = dir;
    }

    #[test]
    fn validation_csr_covers_domains_and_self_verifies() {
        let domains = vec!["a.test".to_string(), "b.test".to_string()];
        let (_key, der) = generate_csr(&domains).unwrap();
        let request = openssl::x509::X509Req::from_der(&der).unwrap();
        let pubkey = request.public_key().unwrap();
        assert!(request.verify(&pubkey).unwrap());
    }

    #[test]
    fn validation_group_needs_certificate_matrix() {
        let (_dir, state) = test_state(
            "  - host: \"a.test\"\n    additional_hosts: [\"b.test\"]\n    upstreams: [{address: \"127.0.0.1:9000\"}]",
            "  enabled: false",
        );
        let domains = vec!["a.test".to_string(), "b.test".to_string()];
        assert!(group_needs_certificate(&state, &domains), "no cert at all");
        let (chain, key_pem) = rcgen_chain(&["a.test", "b.test"], 10);
        persist_and_install(&state, &domains, &chain, &key_pem).unwrap();
        assert!(
            group_needs_certificate(&state, &domains),
            "inside the 30-day threshold"
        );
        let (chain, key_pem) = rcgen_chain(&["a.test", "b.test"], 90);
        persist_and_install(&state, &domains, &chain, &key_pem).unwrap();
        assert!(
            !group_needs_certificate(&state, &domains),
            "healthy at 90 days"
        );
    }
}
