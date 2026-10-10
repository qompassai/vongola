// #################################################################
// /qompassai/vongola/crates/plugins_api/src/lib.rs
// Qompass AI WASM Plugin API Bindings
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

// The export shims wit-bindgen generates for this crate call unsafe
// C-ABI functions from within generated unsafe functions without inner
// unsafe blocks; edition 2024's unsafe_op_in_unsafe_fn lint rejects
// that shape, and macro-generated code cannot be edited. This crate
// is only a bindings scaffold -- its own code contains no unsafe -- so
// the lint is allowed at crate level for the generated shims.
#![allow(unsafe_op_in_unsafe_fn)]

#[allow(clippy::wildcard_imports)]
use wit::*;

/// A snapshot of the request headers a plugin may inspect.
///
/// Header names are matched case-insensitively (HTTP field names are
/// case-insensitive); when a name appears more than once, the first
/// value wins.
#[derive(Clone, Debug, Default, PartialEq, Ord, Eq, PartialOrd, Hash)]
pub struct Session {
    headers: Vec<(String, String)>,
}

impl Session {
    #[must_use]
    pub fn new(headers: Vec<(String, String)>) -> Self { Self { headers } }

    #[must_use]
    pub fn get_header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    }

    /// Whether this session carries any request headers at all.
    #[must_use]
    pub fn req_header(&self) -> Option<bool> {
        if self.headers.is_empty() {
            None
        } else {
            Some(true)
        }
    }
}

pub trait Plugin: Send + Sync {
    fn new_ctx(ctx: String) -> String;

    fn on_request_filter(
        _session: Session,
        _ctx: Context,
    ) -> impl std::future::Future<Output = Result<bool, ()>> {
        async { Ok(true) }
    }
}

#[derive(Clone, Debug, PartialEq, Ord, Eq, PartialOrd, Hash)]
pub struct Context {}

mod wit {
    wit_bindgen::generate!({
      world: "plugin"
    });
}

wit::export!(Component);

struct Component;

impl wit::Guest for Component {
    fn new_ctx(_ctx: String) -> String { String::from("hello") }

    fn on_request_filter(_session: &wit::Session, _ctx: String) -> Result<bool, ()> { Ok(true) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        Session::new(vec![
            ("Host".to_string(), "example.com".to_string()),
            ("X-Request-Id".to_string(), "abc-123".to_string()),
            ("x-request-id".to_string(), "second-value".to_string()),
        ])
    }

    #[test]
    fn get_header_finds_exact_and_case_insensitive_names() {
        let session = session();
        assert_eq!(session.get_header("Host"), Some("example.com"));
        assert_eq!(session.get_header("host"), Some("example.com"));
        assert_eq!(session.get_header("HOST"), Some("example.com"));
    }

    #[test]
    fn get_header_first_duplicate_wins() {
        assert_eq!(session().get_header("X-Request-Id"), Some("abc-123"));
    }

    #[test]
    fn get_header_missing_or_empty_key_is_none() {
        let session = session();
        assert_eq!(session.get_header("Authorization"), None);
        assert_eq!(session.get_header(""), None);
    }

    #[test]
    fn req_header_reports_presence() {
        assert_eq!(session().req_header(), Some(true));
        assert_eq!(Session::default().req_header(), None);
        assert_eq!(Session::default().get_header("Host"), None);
    }
}
