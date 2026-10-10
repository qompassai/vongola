// #################################################################
// /qompassai/vongola/crates/vongola/src/static_site.rs
// Qompass AI — Vongola clean-room static hosting
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

//! Static site serving for hosting-profile routes: safe path
//! resolution under a root, cache rules (fingerprinted assets are
//! immutable, HTML is no-cache), gzip for text types, and a
//! bounded in-memory cache. Path traversal is impossible by
//! construction: the resolved path must stay under the root.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::Route;

pub struct StaticResponse {
    pub body: Vec<u8>,
    pub cache_control: String,
    pub content_encoding: Option<String>,
    pub content_type: String,
    pub from_cache: bool,
    pub status: u16,
}

struct CacheEntry {
    body: Vec<u8>,
    content_type: String,
    stored: Instant,
    ttl: Duration,
}

#[derive(Default)]
pub struct StaticCache {
    entries: Mutex<BTreeMap<String, CacheEntry>>,
    total_bytes: Mutex<usize>,
}

impl StaticCache {
    pub fn new() -> StaticCache { StaticCache::default() }

    fn get(&self, key: &str) -> Option<(Vec<u8>, String)> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        if entry.stored.elapsed() <= entry.ttl {
            Some((entry.body.clone(), entry.content_type.clone()))
        } else {
            None
        }
    }

    fn put(
        &self,
        key: String,
        body: Vec<u8>,
        content_type: String,
        ttl: Duration,
        max_bytes: u64,
        max_entries: usize,
    ) {
        if body.len() as u64 > max_bytes {
            return;
        }
        if let (Ok(mut entries), Ok(mut total)) = (self.entries.lock(), self.total_bytes.lock()) {
            if entries.len() >= max_entries || *total + body.len() > max_bytes as usize {
                entries.clear();
                *total = 0;
            }
            *total += body.len();
            entries.insert(
                key,
                CacheEntry {
                    body,
                    content_type,
                    stored: Instant::now(),
                    ttl,
                },
            );
        }
    }
}

/// Resolve a request path under the root. Returns None for any
/// path that escapes the root, names a dotfile, or is not a file.
pub fn resolve_under_root(root: &Path, url_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(url_path);
    let mut relative = PathBuf::new();
    for component in Path::new(&decoded).components() {
        match component {
            Component::Normal(part) => {
                let text = part.to_string_lossy();
                if text.starts_with('.') {
                    return None;
                }
                relative.push(part);
            }
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    let candidate = root.join(relative);
    if candidate.is_dir() {
        let index = candidate.join("index.html");
        if index.is_file() {
            return Some(index);
        }
        return None;
    }
    if candidate.is_file() {
        return Some(candidate);
    }
    None
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
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

pub fn content_type_for(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("css") => "text/css",
        Some("gif") => "image/gif",
        Some("html") => "text/html",
        Some("ico") => "image/x-icon",
        Some("jpeg" | "jpg") => "image/jpeg",
        Some("js") => "text/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain",
        Some("wasm") => "application/wasm",
        Some("webp") => "image/webp",
        Some("woff2") => "font/woff2",
        Some("xml") => "application/xml",
        _ => "application/octet-stream",
    }
}

fn is_textual(content_type: &str) -> bool {
    content_type.starts_with("text/")
        || content_type == "application/json"
        || content_type == "application/xml"
        || content_type == "image/svg+xml"
}

/// Fingerprinted assets carry a content hash segment (e.g.
/// `app.a1b2c3d4.js`): 8+ hex chars between dots.
fn is_fingerprinted(file_name: &str) -> bool {
    let parts: Vec<&str> = file_name.split('.').collect();
    parts.iter().any(|part| {
        part.len() >= 8 && part.chars().all(|c| c.is_ascii_hexdigit()) && part.len() <= 64
    })
}

pub fn cache_control_for(route: &Route, path: &Path) -> String {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if path.extension().is_some_and(|e| e == "html") {
        "no-cache".to_string()
    } else if is_fingerprinted(name) {
        format!(
            "public, max-age={}, immutable",
            route.cache.immutable_max_age_secs
        )
    } else {
        format!("public, max-age={}", route.cache.max_age_secs)
    }
}

/// Serve one static request. `cache` is the route's cache;
/// returns the response to write downstream.
pub fn serve(
    route: &Route,
    cache: &StaticCache,
    url_path: &str,
    accept_gzip: bool,
) -> StaticResponse {
    let root = route.static_root.clone().unwrap_or_default();
    let resolved = resolve_under_root(&root, url_path).or_else(|| {
        route.spa_fallback.as_ref().and_then(|fallback| {
            let candidate = root.join(fallback);
            if candidate.is_file() {
                Some(candidate)
            } else {
                None
            }
        })
    });
    let Some(path) = resolved else {
        return StaticResponse {
            body: b"not found\n".to_vec(),
            cache_control: "no-store".to_string(),
            content_encoding: None,
            content_type: "text/plain".to_string(),
            from_cache: false,
            status: 404,
        };
    };
    let content_type = content_type_for(&path).to_string();
    let cache_control = cache_control_for(route, &path);
    let cache_key = format!("{}|{}", route.host, url_path);
    let mut from_cache = false;
    let raw = if route.cache.enabled {
        if let Some((body, _)) = cache.get(&cache_key) {
            from_cache = true;
            body
        } else {
            match std::fs::read(&path) {
                Ok(bytes) => {
                    cache.put(
                        cache_key,
                        bytes.clone(),
                        content_type.clone(),
                        Duration::from_secs(route.cache.max_age_secs),
                        route.cache.max_bytes,
                        route.cache.max_entries,
                    );
                    bytes
                }
                Err(_) => {
                    return StaticResponse {
                        body: b"read error\n".to_vec(),
                        cache_control: "no-store".to_string(),
                        content_encoding: None,
                        content_type: "text/plain".to_string(),
                        from_cache: false,
                        status: 500,
                    };
                }
            }
        }
    } else {
        match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                return StaticResponse {
                    body: b"read error\n".to_vec(),
                    cache_control: "no-store".to_string(),
                    content_encoding: None,
                    content_type: "text/plain".to_string(),
                    from_cache: false,
                    status: 500,
                };
            }
        }
    };
    let (body, content_encoding) = if accept_gzip && is_textual(&content_type) && raw.len() > 512 {
        match gzip(&raw) {
            Some(compressed) => (compressed, Some("gzip".to_string())),
            None => (raw, None),
        }
    } else {
        (raw, None)
    };
    StaticResponse {
        body,
        cache_control,
        content_encoding,
        content_type,
        from_cache,
        status: 200,
    }
}

fn gzip(data: &[u8]) -> Option<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).ok()?;
    encoder.finish().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_for(root: &std::path::Path) -> Route {
        let mut route: Route = serde_yaml::from_str("host: \"site.test\"\nupstreams: []").unwrap();
        route.static_root = Some(root.to_path_buf());
        route.upstreams = Vec::new();
        route
    }

    #[test]
    fn adversarial_traversal_blocked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "hi").unwrap();
        assert!(resolve_under_root(dir.path(), "/../secret.txt").is_none());
        assert!(resolve_under_root(dir.path(), "/%2e%2e/secret.txt").is_none());
        assert!(resolve_under_root(dir.path(), "/.git/config").is_none());
    }

    #[test]
    fn validation_index_and_cache_rules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<h1>qompass</h1>").unwrap();
        std::fs::write(dir.path().join("app.a1b2c3d4.js"), "x".repeat(600)).unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let response = serve(&route, &cache, "/", false);
        assert_eq!(response.status, 200);
        assert_eq!(response.cache_control, "no-cache");
        let asset = serve(&route, &cache, "/app.a1b2c3d4.js", true);
        assert!(asset.cache_control.contains("immutable"));
        assert_eq!(asset.content_encoding.as_deref(), Some("gzip"));
    }
}
