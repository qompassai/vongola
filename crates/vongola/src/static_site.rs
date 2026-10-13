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
//! immutable, HTML is no-cache, downloads under `/files/`
//! revalidate on every use), gzip for text types, and a
//! bounded in-memory cache. Path traversal is impossible by
//! construction: the resolved path must stay under the root.
//! File responses carry RFC 9110 validators (a strong content
//! ETag and Last-Modified) with conditional evaluation and
//! single-range support, so clients can revalidate (304) and
//! resume (206) instead of re-downloading.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use crate::config::Route;

pub struct StaticResponse {
    /// Whether a 200/206 file response advertises byte ranges.
    pub accept_ranges: bool,
    pub body: Vec<u8>,
    pub cache_control: String,
    pub content_encoding: Option<String>,
    /// Content-Length override for responses whose body is not
    /// the payload the length must describe (a 304 carries the
    /// selected representation's length, per RFC 9110 8.6).
    /// None means "the body length", the historical behavior.
    pub content_length: Option<usize>,
    /// Content-Range value for 206 and 416 responses.
    pub content_range: Option<String>,
    pub content_type: String,
    /// Strong validator of the selected representation.
    pub etag: Option<String>,
    pub from_cache: bool,
    /// Last-Modified value (IMF-fixdate) for file responses.
    pub last_modified: Option<String>,
    /// Redirect target for canonicalization responses
    /// (directory without trailing slash); None otherwise.
    pub location: Option<String>,
    pub status: u16,
}

/// The slice of request state the static server consults:
/// the encoding preference plus the RFC 9110 conditional and
/// range field values, raw and unvalidated. Validation happens
/// here, at the trust boundary, not at the caller.
pub struct StaticRequest<'a> {
    pub accept_gzip: bool,
    pub if_modified_since: Option<&'a str>,
    pub if_none_match: Option<&'a str>,
    pub if_range: Option<&'a str>,
    pub method: &'a str,
    pub range: Option<&'a str>,
}

/// A response with no validators and no range state:
/// redirects and errors. File responses build their struct
/// directly.
fn bare_response(
    status: u16,
    cache_control: &str,
    content_type: String,
    body: Vec<u8>,
) -> StaticResponse {
    StaticResponse {
        accept_ranges: false,
        body,
        cache_control: cache_control.to_string(),
        content_encoding: None,
        content_length: None,
        content_range: None,
        content_type,
        etag: None,
        from_cache: false,
        last_modified: None,
        location: None,
        status,
    }
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
/// The filesystem candidate for a request path, before any
/// index resolution: root-joined, traversal- and dotfile-safe.
fn candidate_path(root: &Path, url_path: &str) -> Option<PathBuf> {
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
    Some(root.join(relative))
}

pub fn resolve_under_root(root: &Path, url_path: &str) -> Option<PathBuf> {
    let candidate = candidate_path(root, url_path)?;
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
        Some("css") => "text/css; charset=utf-8",
        Some("gif") => "image/gif",
        Some("html") => "text/html; charset=utf-8",
        Some("ico") => "image/x-icon",
        Some("jpeg" | "jpg") => "image/jpeg",
        Some("js") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain; charset=utf-8",
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

/// The Cache-Control value for a served file. Downloads under
/// `/files/` are `public, no-cache`: clients may store them but
/// must revalidate before reuse, so a replaced file (a CV, a
/// release artifact) is picked up on the next view instead of
/// being served stale for the general max-age window.
/// Revalidation is cheap: the validators below answer 304.
pub fn cache_control_for(route: &Route, path: &Path, url_path: &str) -> String {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if url_path.starts_with("/files/") {
        "public, no-cache".to_string()
    } else if path.extension().is_some_and(|e| e == "html") {
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

/// Everything conditional and range evaluation needs about
/// the selected file, gathered once by `serve`.
struct FileContext {
    cache_control: String,
    content_type: String,
    from_cache: bool,
    modified: Option<SystemTime>,
    raw: Vec<u8>,
}

/// Serve one static request. `cache` is the route's cache;
/// returns the response to write downstream.
pub fn serve(
    route: &Route,
    cache: &StaticCache,
    url_path: &str,
    request: &StaticRequest<'_>,
) -> StaticResponse {
    let root = route.static_root.clone().unwrap_or_default();
    // Directory canonicalization: a directory holding an index
    // document is addressed with a trailing slash; redirect
    // there (308), like the reference file server, so relative
    // references resolve against the directory.
    if !url_path.ends_with('/')
        && let Some(candidate) = candidate_path(&root, url_path)
        && candidate.is_dir()
        && candidate.join("index.html").is_file()
    {
        return StaticResponse {
            accept_ranges: false,
            body: Vec::new(),
            cache_control: "no-store".to_string(),
            content_encoding: None,
            content_length: None,
            content_range: None,
            content_type: "text/html; charset=utf-8".to_string(),
            etag: None,
            from_cache: false,
            last_modified: None,
            location: Some(format!("{url_path}/")),
            status: 308,
        };
    }
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
        return bare_response(404, "no-store", String::new(), Vec::new());
    };
    let content_type = content_type_for(&path).to_string();
    let cache_control = cache_control_for(route, &path, url_path);
    let modified = std::fs::metadata(&path)
        .and_then(|meta| meta.modified())
        .ok();
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
                    return bare_response(
                        500,
                        "no-store",
                        "text/plain; charset=utf-8".to_string(),
                        b"read error\n".to_vec(),
                    );
                }
            }
        }
    } else {
        match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                return bare_response(
                    500,
                    "no-store",
                    "text/plain; charset=utf-8".to_string(),
                    b"read error\n".to_vec(),
                );
            }
        }
    };
    file_response(
        request,
        FileContext {
            cache_control,
            content_type,
            from_cache,
            modified,
            raw,
        },
    )
}

/// Build the response for a resolved file: pick the
/// representation (identity when ranging, gzip when accepted
/// and worthwhile), derive its validators, then evaluate the
/// conditionals and the range against them — RFC 9110
/// sections 13 and 14, in that order.
fn file_response(request: &StaticRequest<'_>, file: FileContext) -> StaticResponse {
    let ranging = request.range.is_some() && request.method == "GET";
    let (representation, content_encoding) = if ranging {
        (file.raw, None)
    } else if request.accept_gzip && is_textual(&file.content_type) && file.raw.len() > 512 {
        match gzip(&file.raw) {
            Some(compressed) => (compressed, Some("gzip".to_string())),
            None => (file.raw, None),
        }
    } else {
        (file.raw, None)
    };
    let etag = etag_for(&representation);
    let last_modified = file.modified.map(format_http_date);
    match precondition(request, &etag, file.modified) {
        Precondition::Failed => {
            return StaticResponse {
                accept_ranges: false,
                body: Vec::new(),
                cache_control: "no-store".to_string(),
                content_encoding: None,
                content_length: None,
                content_range: None,
                content_type: String::new(),
                etag: Some(etag),
                from_cache: false,
                last_modified,
                location: None,
                status: 412,
            };
        }
        Precondition::NotModified => {
            return StaticResponse {
                accept_ranges: false,
                body: Vec::new(),
                cache_control: file.cache_control,
                content_encoding: None,
                content_length: Some(representation.len()),
                content_range: None,
                // RFC 9110 section 15.4.5: a 304 carries the
                // Content-Type the corresponding 200 would have
                // carried. Omitting it strands a cache entry that
                // was stored under a stale type: every successful
                // revalidation refreshes the stale type instead of
                // correcting it.
                content_type: file.content_type,
                etag: Some(etag),
                from_cache: file.from_cache,
                last_modified,
                location: None,
                status: 304,
            };
        }
        Precondition::Proceed => {}
    }
    if ranging
        && let Some(header) = request.range
        && if_range_allows(request.if_range, &etag, file.modified)
    {
        match parse_range(header, representation.len() as u64) {
            RangeResult::Ignore => {}
            RangeResult::Slice(start, end) => {
                // parse_range bounds start/end by the
                // representation length, so both fit usize
                // and the slice is in bounds by construction.
                let body = representation[start as usize..=end as usize].to_vec();
                return StaticResponse {
                    accept_ranges: true,
                    body,
                    cache_control: file.cache_control,
                    content_encoding: None,
                    content_length: None,
                    content_range: Some(format!("bytes {start}-{end}/{}", representation.len())),
                    content_type: file.content_type,
                    etag: Some(etag),
                    from_cache: file.from_cache,
                    last_modified,
                    location: None,
                    status: 206,
                };
            }
            RangeResult::Unsatisfiable => {
                return StaticResponse {
                    accept_ranges: false,
                    body: Vec::new(),
                    cache_control: "no-store".to_string(),
                    content_encoding: None,
                    content_length: None,
                    content_range: Some(format!("bytes */{}", representation.len())),
                    content_type: String::new(),
                    etag: Some(etag),
                    from_cache: file.from_cache,
                    last_modified,
                    location: None,
                    status: 416,
                };
            }
        }
    }
    StaticResponse {
        accept_ranges: true,
        body: representation,
        cache_control: file.cache_control,
        content_encoding,
        content_length: None,
        content_range: None,
        content_type: file.content_type,
        etag: Some(etag),
        from_cache: file.from_cache,
        last_modified,
        location: None,
        status: 200,
    }
}

/// Strong validator for one selected representation: the
/// SHA-256 of the exact bytes a 200 would carry, hex-encoded
/// and quoted. Content addressing keeps the tag stable across
/// restarts and independent of mtime granularity; the crate
/// already hashes with sha2 (acme.rs).
fn etag_for(representation: &[u8]) -> String {
    use std::fmt::Write as _;

    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(representation);
    let mut tag = String::with_capacity(66);
    tag.push('"');
    for byte in digest {
        let _ = write!(tag, "{byte:02x}");
    }
    tag.push('"');
    tag
}

enum Precondition {
    /// A precondition failed for a state-changing method.
    Failed,
    /// The client's copy is current: answer 304.
    NotModified,
    /// Serve the representation (possibly ranged).
    Proceed,
}

/// Evaluate If-None-Match, then If-Modified-Since, in the
/// order RFC 9110 section 13.2.2 fixes: when If-None-Match
/// is present, If-Modified-Since is ignored entirely.
fn precondition(
    request: &StaticRequest<'_>,
    etag: &str,
    modified: Option<SystemTime>,
) -> Precondition {
    if let Some(header) = request.if_none_match {
        if if_none_match_matches(header, etag) {
            return if request.method == "GET" || request.method == "HEAD" {
                Precondition::NotModified
            } else {
                Precondition::Failed
            };
        }
        return Precondition::Proceed;
    }
    if (request.method == "GET" || request.method == "HEAD")
        && let Some(header) = request.if_modified_since
        && let Some(since) = parse_http_date(header)
        && let Some(mtime) = modified
        && http_date_seconds(mtime) <= since
    {
        return Precondition::NotModified;
    }
    Precondition::Proceed
}

/// Weak comparison for If-None-Match (RFC 9110 section
/// 8.8.3.2): a candidate matches when its opaque tag equals
/// the current tag, ignoring a weak prefix; "*" matches any
/// current representation.
fn if_none_match_matches(header: &str, etag: &str) -> bool {
    header.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*"
            || candidate == etag
            || candidate
                .strip_prefix("W/")
                .is_some_and(|rest| rest == etag)
    })
}

/// The If-Range gate: the range applies only when the
/// validator still names the current representation. An
/// entity-tag value must match strongly (the exact opaque
/// tag; a weak tag never matches), a date value must equal
/// the Last-Modified second.
fn if_range_allows(header: Option<&str>, etag: &str, modified: Option<SystemTime>) -> bool {
    let Some(value) = header else {
        return true;
    };
    let value = value.trim();
    if value.starts_with('"') || value.starts_with("W/\"") {
        value == etag
    } else {
        match (parse_http_date(value), modified) {
            (Some(when), Some(mtime)) => http_date_seconds(mtime) == when,
            _ => false,
        }
    }
}

enum RangeResult {
    /// Decline the range: serve the whole representation.
    Ignore,
    /// Inclusive byte bounds, within the representation.
    Slice(u64, u64),
    /// Valid range that cannot be satisfied: answer 416.
    Unsatisfiable,
}

/// Parse a single-range Range field value against a
/// representation length (RFC 9110 section 14). Multiple
/// ranges are declined the simple way the RFC allows a
/// server to decline any range: by ignoring the field
/// entirely, which the caller turns into a 200.
fn parse_range(header: &str, len: u64) -> RangeResult {
    let Some(spec) = header
        .trim()
        .split_once('=')
        .and_then(|(unit, rest)| unit.eq_ignore_ascii_case("bytes").then_some(rest))
    else {
        return RangeResult::Ignore;
    };
    if spec.contains(',') {
        return RangeResult::Ignore;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return RangeResult::Ignore;
    };
    if first.is_empty() {
        // Suffix range: the last N bytes.
        let Ok(suffix) = last.parse::<u64>() else {
            return RangeResult::Ignore;
        };
        if suffix == 0 || len == 0 {
            return RangeResult::Unsatisfiable;
        }
        if suffix >= len {
            return RangeResult::Slice(0, len - 1);
        }
        return RangeResult::Slice(len - suffix, len - 1);
    }
    let Ok(start) = first.parse::<u64>() else {
        return RangeResult::Ignore;
    };
    if start >= len {
        return RangeResult::Unsatisfiable;
    }
    if last.is_empty() {
        return RangeResult::Slice(start, len - 1);
    }
    let Ok(end) = last.parse::<u64>() else {
        return RangeResult::Ignore;
    };
    if end < start {
        return RangeResult::Ignore;
    }
    RangeResult::Slice(start, end.min(len - 1))
}

const MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const WEEKDAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const WEEKDAY_NAMES_LONG: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

/// Whole seconds since the Unix epoch, the granularity HTTP
/// dates speak (sub-second parts truncate away).
fn http_date_seconds(time: SystemTime) -> i64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Format a timestamp as an IMF-fixdate, the one date form
/// HTTP senders generate (RFC 9110 section 5.6.1).
fn format_http_date(time: SystemTime) -> String {
    let secs = http_date_seconds(time);
    let days = secs.div_euclid(86_400);
    let day_secs = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let weekday = WEEKDAY_NAMES[((days + 4).rem_euclid(7)) as usize];
    let month_name = MONTH_NAMES[(month - 1) as usize];
    format!(
        "{weekday}, {day:02} {month_name} {year:04} {:02}:{:02}:{:02} GMT",
        day_secs / 3600,
        (day_secs % 3600) / 60,
        day_secs % 60,
    )
}

/// Parse an HTTP-date (RFC 9110 section 5.6.1): IMF-fixdate,
/// the obsolete RFC 850 form, and asctime. Anything else is
/// None and callers ignore the field, as the RFC directs.
/// Returns whole seconds since the Unix epoch.
fn parse_http_date(text: &str) -> Option<i64> {
    parse_imf_fixdate(text)
        .or_else(|| parse_rfc850_date(text))
        .or_else(|| parse_asctime_date(text))
}

fn parse_imf_fixdate(text: &str) -> Option<i64> {
    let mut parts = text.split(' ');
    let weekday = parts.next()?;
    if !is_weekday_name(weekday.strip_suffix(',')?, false) {
        return None;
    }
    let day: u32 = parts.next()?.parse().ok()?;
    let month = month_number(parts.next()?)?;
    let year: i64 = parts.next()?.parse().ok()?;
    let (hour, minute, second) = parse_time_of_day(parts.next()?)?;
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    epoch_seconds(year, month, day, hour, minute, second)
}

fn parse_rfc850_date(text: &str) -> Option<i64> {
    let mut parts = text.split(' ');
    let weekday = parts.next()?;
    if !is_weekday_name(weekday.strip_suffix(',')?, true) {
        return None;
    }
    let mut date = parts.next()?.split('-');
    let day: u32 = date.next()?.parse().ok()?;
    let month = month_number(date.next()?)?;
    let two_digit: i64 = date.next()?.parse().ok()?;
    if date.next().is_some() {
        return None;
    }
    // A two-digit year reads as the most recent matching
    // year; the 1970 pivot is the conventional reading.
    let year = if two_digit >= 70 {
        1900 + two_digit
    } else {
        2000 + two_digit
    };
    let (hour, minute, second) = parse_time_of_day(parts.next()?)?;
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    epoch_seconds(year, month, day, hour, minute, second)
}

fn parse_asctime_date(text: &str) -> Option<i64> {
    // asctime pads a single-digit day with a second space;
    // split_whitespace absorbs that.
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() != 5 || !is_weekday_name(parts[0], false) {
        return None;
    }
    let month = month_number(parts[1])?;
    let day: u32 = parts[2].parse().ok()?;
    let (hour, minute, second) = parse_time_of_day(parts[3])?;
    let year: i64 = parts[4].parse().ok()?;
    epoch_seconds(year, month, day, hour, minute, second)
}

fn parse_time_of_day(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split(':');
    let hour: u32 = parts.next()?.parse().ok()?;
    let minute: u32 = parts.next()?.parse().ok()?;
    let second: u32 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((hour, minute, second))
}

fn is_weekday_name(name: &str, long: bool) -> bool {
    if long {
        WEEKDAY_NAMES_LONG.contains(&name)
    } else {
        WEEKDAY_NAMES.contains(&name)
    }
}

fn month_number(name: &str) -> Option<u32> {
    MONTH_NAMES
        .iter()
        .position(|&month| month == name)
        .map(|index| index as u32 + 1)
}

/// Validate the fields and fold them into epoch seconds.
/// A leap second (60) folds onto 59: HTTP dates cannot
/// name the leap instant distinctly anyway.
fn epoch_seconds(
    year: i64,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<i64> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(
        days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second.min(59)),
    )
}

/// Days since the Unix epoch for a civil date
/// (Howard Hinnant's days-from-civil algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = if shifted >= 0 { shifted } else { shifted - 399 } / 400;
    let year_of_era = shifted - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 } as i64;
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The civil date for days since the Unix epoch
/// (Howard Hinnant's civil-from-days algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_prime + 2) / 5 + 1) as u32;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
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

    fn plain_get() -> StaticRequest<'static> {
        StaticRequest {
            accept_gzip: false,
            if_modified_since: None,
            if_none_match: None,
            if_range: None,
            method: "GET",
            range: None,
        }
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
    fn validation_directory_redirect_and_charset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/index.html"), "<h1>sub</h1>").unwrap();
        std::fs::write(dir.path().join("index.html"), "<h1>root</h1>").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let redirect = serve(&route, &cache, "/sub", &plain_get());
        assert_eq!(redirect.status, 308);
        assert_eq!(redirect.location.as_deref(), Some("/sub/"));
        let inside = serve(&route, &cache, "/sub/", &plain_get());
        assert_eq!(inside.status, 200);
        assert_eq!(inside.content_type, "text/html; charset=utf-8");
        let root = serve(&route, &cache, "/", &plain_get());
        assert_eq!(root.status, 200);
        assert!(root.location.is_none());
    }

    #[test]
    fn validation_not_found_has_empty_body() {
        let dir = tempfile::tempdir().unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let missing = serve(&route, &cache, "/nope", &plain_get());
        assert_eq!(missing.status, 404);
        assert!(missing.body.is_empty());
    }

    #[test]
    fn adversarial_directory_without_index_is_not_redirected() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("bare")).unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let response = serve(&route, &cache, "/bare", &plain_get());
        assert_eq!(response.status, 404);
        assert!(response.location.is_none());
        let traversal = serve(&route, &cache, "/../bare", &plain_get());
        assert_eq!(traversal.status, 404);
        assert!(traversal.location.is_none());
    }

    #[test]
    fn validation_index_and_cache_rules() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "<h1>qompass</h1>").unwrap();
        std::fs::write(dir.path().join("app.a1b2c3d4.js"), "x".repeat(600)).unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let response = serve(&route, &cache, "/", &plain_get());
        assert_eq!(response.status, 200);
        assert_eq!(response.cache_control, "no-cache");
        let gzipped = StaticRequest {
            accept_gzip: true,
            ..plain_get()
        };
        let asset = serve(&route, &cache, "/app.a1b2c3d4.js", &gzipped);
        assert!(asset.cache_control.contains("immutable"));
        assert_eq!(asset.content_encoding.as_deref(), Some("gzip"));
    }

    #[test]
    fn validation_validators_present_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let first = serve(&route, &cache, "/hello.txt", &plain_get());
        assert_eq!(first.status, 200);
        assert!(first.accept_ranges);
        let etag = first.etag.clone().expect("etag on a 200");
        assert!(etag.starts_with('"') && etag.ends_with('"'));
        let stamp = first.last_modified.clone().expect("last-modified on a 200");
        assert!(stamp.ends_with(" GMT"));
        let second = serve(&route, &cache, "/hello.txt", &plain_get());
        assert_eq!(second.etag.as_deref(), Some(etag.as_str()));
        assert_eq!(second.last_modified.as_deref(), Some(stamp.as_str()));
    }

    #[test]
    fn validation_etag_is_content_addressed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "same length A").unwrap();
        std::fs::write(dir.path().join("b.txt"), "same length B").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let a = serve(&route, &cache, "/a.txt", &plain_get());
        let b = serve(&route, &cache, "/b.txt", &plain_get());
        assert_ne!(a.etag, b.etag);
    }

    #[test]
    fn validation_if_none_match_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let first = serve(&route, &cache, "/hello.txt", &plain_get());
        let etag = first.etag.clone().unwrap();
        let mut request = plain_get();
        request.if_none_match = Some(etag.as_str());
        let second = serve(&route, &cache, "/hello.txt", &request);
        assert_eq!(second.status, 304);
        assert!(second.body.is_empty());
        assert_eq!(second.etag.as_deref(), Some(etag.as_str()));
        assert_eq!(second.content_length, Some(first.body.len()));
    }

    #[test]
    fn validation_if_none_match_star() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let mut request = plain_get();
        request.if_none_match = Some("*");
        let response = serve(&route, &cache, "/hello.txt", &request);
        assert_eq!(response.status, 304);
        assert!(response.body.is_empty());
    }

    #[test]
    fn validation_if_modified_since_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let stamp = format_http_date(mtime);
        let mut request = plain_get();
        request.if_modified_since = Some(stamp.as_str());
        let not_modified = serve(&route, &cache, "/hello.txt", &request);
        assert_eq!(not_modified.status, 304);
        let mut old = plain_get();
        old.if_modified_since = Some("Sun, 06 Nov 1994 08:49:37 GMT");
        let modified = serve(&route, &cache, "/hello.txt", &old);
        assert_eq!(modified.status, 200);
        assert_eq!(modified.body, b"hello validators");
    }

    #[test]
    fn validation_ranges() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("digits.txt"), "0123456789").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let mut head = plain_get();
        head.range = Some("bytes=0-3");
        let head_response = serve(&route, &cache, "/digits.txt", &head);
        assert_eq!(head_response.status, 206);
        assert_eq!(head_response.body, b"0123");
        assert_eq!(head_response.content_range.as_deref(), Some("bytes 0-3/10"));
        assert!(head_response.accept_ranges);
        let mut suffix = plain_get();
        suffix.range = Some("bytes=-3");
        let suffix_response = serve(&route, &cache, "/digits.txt", &suffix);
        assert_eq!(suffix_response.status, 206);
        assert_eq!(suffix_response.body, b"789");
        assert_eq!(
            suffix_response.content_range.as_deref(),
            Some("bytes 7-9/10")
        );
        let mut open = plain_get();
        open.range = Some("bytes=8-");
        let open_response = serve(&route, &cache, "/digits.txt", &open);
        assert_eq!(open_response.status, 206);
        assert_eq!(open_response.body, b"89");
        assert_eq!(open_response.content_range.as_deref(), Some("bytes 8-9/10"));
    }

    #[test]
    fn validation_if_range_matching_etag() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("digits.txt"), "0123456789").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let first = serve(&route, &cache, "/digits.txt", &plain_get());
        let etag = first.etag.clone().unwrap();
        let mut request = plain_get();
        request.range = Some("bytes=0-3");
        request.if_range = Some(etag.as_str());
        let response = serve(&route, &cache, "/digits.txt", &request);
        assert_eq!(response.status, 206);
        assert_eq!(response.body, b"0123");
    }

    #[test]
    fn validation_http_date_formats() {
        let epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(format_http_date(epoch), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(
            parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"),
            Some(784_111_777)
        );
        assert_eq!(
            parse_http_date("Sun Nov  6 08:49:37 1994"),
            Some(784_111_777)
        );
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(
            format_http_date(SystemTime::UNIX_EPOCH),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
    }

    #[test]
    fn validation_pdf_content_type() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("doc.pdf"), b"%PDF-1.4 fake").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let response = serve(&route, &cache, "/doc.pdf", &plain_get());
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "application/pdf");
        assert_eq!(response.body, b"%PDF-1.4 fake");
    }

    #[test]
    fn validation_pdf_not_modified_carries_content_type() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("doc.pdf"), b"%PDF-1.4 fake").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let first = serve(&route, &cache, "/doc.pdf", &plain_get());
        assert_eq!(first.status, 200);
        assert_eq!(first.content_type, "application/pdf");
        let etag = first.etag.clone().unwrap();
        let mut request = plain_get();
        request.if_none_match = Some(etag.as_str());
        let second = serve(&route, &cache, "/doc.pdf", &request);
        assert_eq!(second.status, 304);
        assert!(second.body.is_empty());
        // RFC 9110 section 15.4.5: the 304 carries the
        // Content-Type the 200 carried, so a cache entry stored
        // under a stale type is corrected on revalidation
        // instead of being refreshed with the stale type.
        assert_eq!(second.content_type, first.content_type);
        assert_eq!(second.content_type, "application/pdf");
    }

    #[test]
    fn validation_if_modified_since_carries_content_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let first = serve(&route, &cache, "/hello.txt", &plain_get());
        assert_eq!(first.status, 200);
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let stamp = format_http_date(mtime);
        let mut request = plain_get();
        request.if_modified_since = Some(stamp.as_str());
        let not_modified = serve(&route, &cache, "/hello.txt", &request);
        assert_eq!(not_modified.status, 304);
        assert!(not_modified.body.is_empty());
        assert_eq!(not_modified.content_type, first.content_type);
    }

    #[test]
    fn validation_files_path_is_public_no_cache() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("files")).unwrap();
        std::fs::write(dir.path().join("files/doc.pdf"), b"%PDF-1.4 fake").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let response = serve(&route, &cache, "/files/doc.pdf", &plain_get());
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "application/pdf");
        assert_eq!(response.cache_control, "public, no-cache");
    }

    #[test]
    fn validation_other_paths_keep_max_age() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let response = serve(&route, &cache, "/hello.txt", &plain_get());
        assert_eq!(response.status, 200);
        assert_eq!(response.cache_control, "public, max-age=3600");
    }

    #[test]
    fn validation_files_revalidation_carries_content_type() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("files")).unwrap();
        std::fs::write(dir.path().join("files/doc.pdf"), b"%PDF-1.4 fake").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let first = serve(&route, &cache, "/files/doc.pdf", &plain_get());
        assert_eq!(first.status, 200);
        let etag = first.etag.clone().unwrap();
        let mut request = plain_get();
        request.if_none_match = Some(etag.as_str());
        let second = serve(&route, &cache, "/files/doc.pdf", &request);
        assert_eq!(second.status, 304);
        assert!(second.body.is_empty());
        assert_eq!(second.content_type, "application/pdf");
        assert_eq!(second.cache_control, "public, no-cache");
    }

    #[test]
    fn adversarial_files_lookalike_paths_keep_max_age() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("filesx")).unwrap();
        std::fs::write(dir.path().join("filesx/doc.pdf"), b"%PDF-1.4 fake").unwrap();
        std::fs::create_dir_all(dir.path().join("other/files")).unwrap();
        std::fs::write(dir.path().join("other/files/doc.pdf"), b"%PDF-1.4 fake").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        for url in ["/filesx/doc.pdf", "/other/files/doc.pdf"] {
            let response = serve(&route, &cache, url, &plain_get());
            assert_eq!(response.status, 200);
            assert_eq!(response.cache_control, "public, max-age=3600");
        }
    }

    #[test]
    fn adversarial_stale_etag_serves_full_body() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let mut request = plain_get();
        request.if_none_match = Some("\"00000000000000000000000000000000\"");
        let response = serve(&route, &cache, "/hello.txt", &request);
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello validators");
    }

    #[test]
    fn adversarial_weak_and_listed_etags_match_weakly() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let first = serve(&route, &cache, "/hello.txt", &plain_get());
        let etag = first.etag.clone().unwrap();
        let weak = format!("W/{etag}");
        let mut weak_request = plain_get();
        weak_request.if_none_match = Some(weak.as_str());
        let weak_response = serve(&route, &cache, "/hello.txt", &weak_request);
        assert_eq!(weak_response.status, 304);
        let list = format!("\"stale\", {etag}");
        let mut list_request = plain_get();
        list_request.if_none_match = Some(list.as_str());
        let list_response = serve(&route, &cache, "/hello.txt", &list_request);
        assert_eq!(list_response.status, 304);
    }

    #[test]
    fn adversarial_if_none_match_suppresses_if_modified_since() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        let stamp = format_http_date(mtime);
        // A stale tag with a fresh date: the tag wins, serve 200.
        let mut request = plain_get();
        request.if_none_match = Some("\"stale\"");
        request.if_modified_since = Some(stamp.as_str());
        let response = serve(&route, &cache, "/hello.txt", &request);
        assert_eq!(response.status, 200);
        // A matching tag with an ancient date: still 304.
        let first = serve(&route, &cache, "/hello.txt", &plain_get());
        let etag = first.etag.clone().unwrap();
        let mut request = plain_get();
        request.if_none_match = Some(etag.as_str());
        request.if_modified_since = Some("Sun, 06 Nov 1994 08:49:37 GMT");
        let response = serve(&route, &cache, "/hello.txt", &request);
        assert_eq!(response.status, 304);
    }

    #[test]
    fn adversarial_post_with_matching_etag_is_412() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let first = serve(&route, &cache, "/hello.txt", &plain_get());
        let etag = first.etag.clone().unwrap();
        let mut request = plain_get();
        request.method = "POST";
        request.if_none_match = Some(etag.as_str());
        let response = serve(&route, &cache, "/hello.txt", &request);
        assert_eq!(response.status, 412);
        assert!(response.body.is_empty());
    }

    #[test]
    fn adversarial_range_past_eof_is_416() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("digits.txt"), "0123456789").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        for header in ["bytes=10-", "bytes=50-60"] {
            let mut request = plain_get();
            request.range = Some(header);
            let response = serve(&route, &cache, "/digits.txt", &request);
            assert_eq!(response.status, 416, "range {header}");
            assert_eq!(response.content_range.as_deref(), Some("bytes */10"));
            assert!(response.body.is_empty());
        }
    }

    #[test]
    fn adversarial_malformed_ranges_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("digits.txt"), "0123456789").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        for header in [
            "bytes=banana",
            "items=0-3",
            "bytes=5-2",
            "bytes=0-1,4-5",
            "bytes=",
            "bytes=-",
            "bytes=0-3-5",
        ] {
            let mut request = plain_get();
            request.range = Some(header);
            let response = serve(&route, &cache, "/digits.txt", &request);
            assert_eq!(response.status, 200, "range {header}");
            assert_eq!(response.body, b"0123456789", "range {header}");
            assert!(response.content_range.is_none(), "range {header}");
        }
    }

    #[test]
    fn adversarial_suffix_range_covers_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("digits.txt"), "0123456789").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let mut request = plain_get();
        request.range = Some("bytes=-9999");
        let response = serve(&route, &cache, "/digits.txt", &request);
        assert_eq!(response.status, 206);
        assert_eq!(response.body, b"0123456789");
        assert_eq!(response.content_range.as_deref(), Some("bytes 0-9/10"));
    }

    #[test]
    fn adversarial_if_range_stale_serves_full_body() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("digits.txt"), "0123456789").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let mut request = plain_get();
        request.range = Some("bytes=0-3");
        request.if_range = Some("\"stale\"");
        let response = serve(&route, &cache, "/digits.txt", &request);
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"0123456789");
        // A weak tag never satisfies If-Range's strong comparison.
        let first = serve(&route, &cache, "/digits.txt", &plain_get());
        let etag = first.etag.clone().unwrap();
        let weak = format!("W/{etag}");
        let mut weak_request = plain_get();
        weak_request.range = Some("bytes=0-3");
        weak_request.if_range = Some(weak.as_str());
        let weak_response = serve(&route, &cache, "/digits.txt", &weak_request);
        assert_eq!(weak_response.status, 200);
        assert_eq!(weak_response.body, b"0123456789");
    }

    #[test]
    fn adversarial_http_date_garbage_is_none() {
        assert_eq!(parse_http_date("not a date"), None);
        assert_eq!(parse_http_date("Sun, 32 Nov 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Foo 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 25:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 08:49:37 PST"), None);
        // At the serve boundary a garbage date is ignored, not fatal.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), "hello validators").unwrap();
        let route = route_for(dir.path());
        let cache = StaticCache::new();
        let mut request = plain_get();
        request.if_modified_since = Some("garbage");
        let response = serve(&route, &cache, "/hello.txt", &request);
        assert_eq!(response.status, 200);
    }
}
