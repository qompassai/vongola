// #################################################################
// /qompassai/vongola/crates/vongola-ech/src/lib.rs
// Qompass AI — Rust bindings for OpenSSL 4.0 ECH (RFC 9849)
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

//! Safe Rust bindings for the Encrypted Client Hello (ECH,
//! RFC 9849) server APIs introduced in OpenSSL 4.0.
//!
//! rust-openssl (openssl-sys 0.9.114 / openssl 0.10.78) ships no
//! ECH symbols at all, so this crate fills exactly that gap,
//! following the upstream layout so it can be upstreamed later
//! with only path changes: `ffi` is the handwritten -sys layer
//! (a transcription of the installed `openssl/ech.h`, which is
//! the contract), and `store` / `status` are the safe layer an
//! `openssl::ech` module would expose.
//!
//! Scope: ECH shared mode only (the only mode OpenSSL 4.0
//! supports), server-first. The safe surface is what a TLS
//! server needs:
//!
//! - [`EchStore`]: create a store, generate a key pair + ECHConfig, load an ECH
//!   PEM file (RFC 9934), serialize the public ECHConfigList for DNS
//!   HTTPS-record publication, and attach the store to an `SSL_CTX`.
//! - [`connection_status`] / [`retry_config`]: per-connection outcome queries
//!   for an established (or failed) handshake.
//! - [`install_ctx_status_callback`] + [`status_counters`]: process-wide
//!   accepted/rejected counters fed by OpenSSL's own ECH callback, for metrics.
//!
//! Requires OpenSSL >= 4.0; the build script refuses anything
//! older. This crate is the one place in the vongola tree where
//! `unsafe` lives: every block carries its invariant.

mod error;
mod ffi;
mod status;
mod store;

pub use error::Error;
pub use status::{
    ConnectionStatus, EchStatus, StatusCounters, connection_status, install_ctx_status_callback,
    retry_config, status_counters,
};
pub use store::{ECH_RFC9849_VERSION, EchStore, EntryInfo, HpkeSuite};
