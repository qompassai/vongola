// #################################################################
// /qompassai/vongola/crates/plugin_request_id/src/lib.rs
// Qompass AI Request-ID Plugin
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

//! The request-id example component: `new_ctx` prefixes the plugin
//! context with a freshly minted `req-<n>` identifier so downstream
//! log lines can be correlated per request. The counter is the only
//! state; it is monotonically increasing for the life of the component
//! instance and wraps are not a correctness concern for an identifier
//! whose only job is uniqueness within a process run.
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn mint_request_id() -> String {
    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("req-{id}")
}

#[must_use]
pub fn new_ctx(ctx: String) -> String { format!("{}:{}", mint_request_id(), ctx) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ctx_prefixes_a_request_id() {
        let ctx = new_ctx("route-a".to_string());
        assert!(ctx.starts_with("req-"));
        assert!(ctx.ends_with(":route-a"));
    }

    #[test]
    fn request_ids_are_unique_per_call() {
        let first = new_ctx("x".to_string());
        let second = new_ctx("x".to_string());
        assert_ne!(first, second);
    }
}
