// #################################################################
// /qompassai/vongola/crates/vongola-ech/tests/status.rs
// Qompass AI — vongola-ech status/attach tests
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

//! Attach + per-connection status tests against real SSL_CTX /
//! SSL objects (no handshake: the pre-handshake states are the
//! exact, deterministic ones).

use vongola_ech::{
    EchStatus, EchStore, HpkeSuite, connection_status, install_ctx_status_callback, retry_config,
    status_counters,
};

/// A real server SSL_CTX from openssl-sys, freed on drop.
struct Ctx(*mut openssl_sys::SSL_CTX);

impl Ctx {
    fn new() -> Ctx {
        // SAFETY: TLS_server_method returns a static method;
        // SSL_CTX_new allocates a context checked before use.
        let ctx = unsafe { openssl_sys::SSL_CTX_new(openssl_sys::TLS_server_method()) };
        assert!(!ctx.is_null(), "SSL_CTX_new");
        Ctx(ctx)
    }

    fn ssl(&self) -> *mut openssl_sys::SSL {
        // SAFETY: self.0 is a live SSL_CTX owned by this guard.
        let ssl = unsafe { openssl_sys::SSL_new(self.0) };
        assert!(!ssl.is_null(), "SSL_new");
        ssl
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // SAFETY: self.0 came from SSL_CTX_new and is freed
        // exactly once, here.
        unsafe { openssl_sys::SSL_CTX_free(self.0) }
    }
}

fn free_ssl(ssl: *mut openssl_sys::SSL) {
    // SAFETY: `ssl` came from SSL_new above and is freed
    // exactly once by the caller of this helper.
    unsafe { openssl_sys::SSL_free(ssl) }
}

#[test]
fn validation_plain_ctx_reports_not_configured() {
    let ctx = Ctx::new();
    let ssl = ctx.ssl();
    // SAFETY: ssl is a live SSL owned by this test.
    let status = unsafe { connection_status(ssl) };
    assert_eq!(status.status, EchStatus::NotConfigured);
    assert_eq!(status.inner_sni, None);
    assert_eq!(status.outer_sni, None);
    free_ssl(ssl);
}

#[test]
fn validation_attached_ctx_reports_not_tried_before_handshake() {
    let mut store = EchStore::new().unwrap();
    store
        .generate("cover.example.test", 0, HpkeSuite::DEFAULT)
        .unwrap();
    let ctx = Ctx::new();
    // SAFETY: ctx.0 is a live SSL_CTX owned by this test; the
    // store is deep-copied by OpenSSL during the call.
    unsafe { store.attach_to_ctx(ctx.0) }.expect("attach must succeed against OpenSSL 4");
    let ssl = ctx.ssl();
    // SAFETY: ssl is a live SSL owned by this test.
    let status = unsafe { connection_status(ssl) };
    assert_eq!(status.status, EchStatus::NotTried);
    free_ssl(ssl);
}

#[test]
fn validation_callback_install_and_counters_readable() {
    let before = status_counters();
    let ctx = Ctx::new();
    // SAFETY: ctx.0 is a live SSL_CTX owned by this test.
    unsafe { install_ctx_status_callback(ctx.0) };
    // No connections were served through this context, so the
    // counters must not move; other tests in this process never
    // complete a handshake either, so equality is the honest
    // assertion (the live movement is proven end-to-end).
    let after = status_counters();
    assert_eq!(after, before);
}

#[test]
fn adversarial_retry_config_on_fresh_connection_is_empty_or_error() {
    let ctx = Ctx::new();
    let ssl = ctx.ssl();
    // SAFETY: ssl is a live SSL owned by this test. No ECH was
    // attempted, so there can be no retry-config payload: the
    // call must yield an empty list (or a structured error),
    // never fabricated bytes.
    match unsafe { retry_config(ssl) } {
        Ok(bytes) => assert!(bytes.is_empty(), "no attempt, no retry-config"),
        Err(err) => assert!(!err.to_string().is_empty()),
    }
    free_ssl(ssl);
}

#[test]
fn adversarial_status_round_trip_codes() {
    for status in [
        EchStatus::Backend,
        EchStatus::BadCall,
        EchStatus::BadName,
        EchStatus::Failed,
        EchStatus::FailedEch,
        EchStatus::FailedEchBadName,
        EchStatus::Grease,
        EchStatus::GreaseEch,
        EchStatus::NotConfigured,
        EchStatus::NotTried,
        EchStatus::Success,
    ] {
        assert_eq!(EchStatus::from_raw(status.to_raw()), status);
    }
    assert_eq!(EchStatus::from_raw(12345), EchStatus::Unknown(12345));
}
