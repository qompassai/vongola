// #################################################################
// /qompassai/vongola/crates/vongola-ech/src/status.rs
// Qompass AI — per-connection ECH status + outcome counters
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

//! Per-connection ECH outcome queries, plus process-wide
//! accepted/rejected counters fed by OpenSSL's own ECH
//! callback (`SSL_CTX_ech_set_callback`). The callback fires on
//! the server as the ServerHello is constructed; following the
//! API documentation, it branches on
//! [`connection_status`] rather than parsing the log string.

use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Error, check};
use crate::ffi;

/// The outcome of an ECH attempt on one connection, mirroring
/// the `SSL_ech_get1_status` return codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EchStatus {
    /// ECH backend: this connection is the inner leg of a
    /// split-mode deployment (not produced in shared mode).
    Backend,
    /// Bad arguments (a NULL pointer was passed).
    BadCall,
    /// ECH succeeded but the peer's certificate name was bad.
    BadName,
    /// Internal or protocol error.
    Failed,
    /// ECH was attempted and failed; the peer supplied
    /// retry-configs authenticated under a verified name.
    FailedEch,
    /// ECH was attempted and failed; retry-configs were
    /// supplied under an unverified name.
    FailedEchBadName,
    /// The peer sent a GREASE ECH extension.
    Grease,
    /// The peer GREASEd and an ECH retry-config came back.
    GreaseEch,
    /// ECH is not configured on this connection.
    NotConfigured,
    /// ECH was not attempted on this connection.
    NotTried,
    /// ECH succeeded: the inner ClientHello was decrypted.
    Success,
    /// A status code this crate does not know (future OpenSSL).
    Unknown(c_int),
}

impl EchStatus {
    pub fn from_raw(code: c_int) -> EchStatus {
        match code {
            ffi::SSL_ECH_STATUS_BACKEND => EchStatus::Backend,
            ffi::SSL_ECH_STATUS_BAD_CALL => EchStatus::BadCall,
            ffi::SSL_ECH_STATUS_BAD_NAME => EchStatus::BadName,
            ffi::SSL_ECH_STATUS_FAILED => EchStatus::Failed,
            ffi::SSL_ECH_STATUS_FAILED_ECH => EchStatus::FailedEch,
            ffi::SSL_ECH_STATUS_FAILED_ECH_BAD_NAME => EchStatus::FailedEchBadName,
            ffi::SSL_ECH_STATUS_GREASE => EchStatus::Grease,
            ffi::SSL_ECH_STATUS_GREASE_ECH => EchStatus::GreaseEch,
            ffi::SSL_ECH_STATUS_NOT_CONFIGURED => EchStatus::NotConfigured,
            ffi::SSL_ECH_STATUS_NOT_TRIED => EchStatus::NotTried,
            ffi::SSL_ECH_STATUS_SUCCESS => EchStatus::Success,
            other => EchStatus::Unknown(other),
        }
    }

    /// The raw `SSL_ech_get1_status` code.
    pub fn to_raw(self) -> c_int {
        match self {
            EchStatus::Backend => ffi::SSL_ECH_STATUS_BACKEND,
            EchStatus::BadCall => ffi::SSL_ECH_STATUS_BAD_CALL,
            EchStatus::BadName => ffi::SSL_ECH_STATUS_BAD_NAME,
            EchStatus::Failed => ffi::SSL_ECH_STATUS_FAILED,
            EchStatus::FailedEch => ffi::SSL_ECH_STATUS_FAILED_ECH,
            EchStatus::FailedEchBadName => ffi::SSL_ECH_STATUS_FAILED_ECH_BAD_NAME,
            EchStatus::Grease => ffi::SSL_ECH_STATUS_GREASE,
            EchStatus::GreaseEch => ffi::SSL_ECH_STATUS_GREASE_ECH,
            EchStatus::NotConfigured => ffi::SSL_ECH_STATUS_NOT_CONFIGURED,
            EchStatus::NotTried => ffi::SSL_ECH_STATUS_NOT_TRIED,
            EchStatus::Success => ffi::SSL_ECH_STATUS_SUCCESS,
            EchStatus::Unknown(code) => code,
        }
    }
}

/// One connection's ECH outcome: the status plus the inner
/// (decrypted, real) and outer (cover) server names, when the
/// handshake determined them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionStatus {
    pub inner_sni: Option<String>,
    pub outer_sni: Option<String>,
    pub status: EchStatus,
}

/// Snapshot of the process-wide ECH outcome counters fed by
/// the callback installed with
/// [`install_ctx_status_callback`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatusCounters {
    pub accepted: u64,
    pub rejected: u64,
}

static ACCEPTED: AtomicU64 = AtomicU64::new(0);
static REJECTED: AtomicU64 = AtomicU64::new(0);

/// Reads the current counter values. Counters only move once
/// a status callback has been installed on a context that is
/// serving connections.
pub fn status_counters() -> StatusCounters {
    StatusCounters {
        accepted: ACCEPTED.load(Ordering::Relaxed),
        rejected: REJECTED.load(Ordering::Relaxed),
    }
}

/// Queries the ECH outcome of one connection.
///
/// # Safety
/// `ssl` must point at a live `SSL` (a connection whose
/// handshake has progressed far enough for the outcome to be
/// determined) and stay valid for the call.
pub unsafe fn connection_status(ssl: *mut openssl_sys::SSL) -> ConnectionStatus {
    let mut inner: *mut c_char = ptr::null_mut();
    let mut outer: *mut c_char = ptr::null_mut();
    // SAFETY: per this function's caller contract, `ssl` is a
    // live SSL; both out-parameters point at writable storage.
    // NULL out-parameters would be a bad call (the C function
    // requires real pointers), so both are always passed.
    let code = unsafe { ffi::SSL_ech_get1_status(ssl, &mut inner, &mut outer) };
    ConnectionStatus {
        // SAFETY: inner/outer are NULL or owned OpenSSL
        // strings per the get1_status contract; each is taken
        // over (copied + freed) exactly once.
        inner_sni: unsafe { ffi::take_openssl_string(inner) },
        // SAFETY: same contract as above.
        outer_sni: unsafe { ffi::take_openssl_string(outer) },
        status: EchStatus::from_raw(code),
    }
}

/// Installs the crate's ECH outcome callback on an `SSL_CTX`:
/// every completed ECH determination on connections from
/// this context updates [`status_counters`] (accepted on
/// success, rejected when an attempt failed and retry-configs
/// were returned). Other outcomes (no attempt, GREASE) do not
/// move the counters.
///
/// # Safety
/// `ctx` must point at a live `SSL_CTX` that stays valid for
/// the duration of the call. The callback itself is a static
/// function and remains valid for the process lifetime.
pub unsafe fn install_ctx_status_callback(ctx: *mut openssl_sys::SSL_CTX) {
    // SAFETY: per this function's caller contract, `ctx` is a
    // live SSL_CTX; the registered callback is a static extern
    // fn that only calls SSL_ech_get1_status on the SSL it is
    // handed and updates two atomics — it cannot panic and
    // frees everything it is given ownership of.
    unsafe { ffi::SSL_CTX_ech_set_callback(ctx, status_callback) }
}

/// The retry-configs a peer supplied for this connection
/// (binary ECHConfigList), when an ECH attempt failed and the
/// peer offered them. Empty when none were supplied.
///
/// # Safety
/// `ssl` must point at a live `SSL` and stay valid for the
/// call.
pub unsafe fn retry_config(ssl: *mut openssl_sys::SSL) -> Result<Vec<u8>, Error> {
    let mut ec: *mut u8 = ptr::null_mut();
    let mut eclen: usize = 0;
    // SAFETY: per this function's caller contract, `ssl` is a
    // live SSL; both out-parameters point at writable storage.
    let ret = unsafe { ffi::SSL_ech_get1_retry_config(ssl, &mut ec, &mut eclen) };
    check("SSL_ech_get1_retry_config", ret)?;
    if ec.is_null() || eclen == 0 {
        return Ok(Vec::new());
    }
    if eclen > crate::store::MAX_PEM_BYTES {
        // SAFETY: `ec` is an OpenSSL-allocated buffer we own;
        // free it before reporting the bound violation.
        unsafe { ffi::openssl_free(ec as *mut std::os::raw::c_void) };
        return Err(Error::new("retry-config exceeds the size bound"));
    }
    // SAFETY: `ec` points at `eclen` readable bytes allocated
    // by OpenSSL and owned by us; copy them out, then free the
    // original exactly once.
    let bytes = unsafe { std::slice::from_raw_parts(ec, eclen) }.to_vec();
    // SAFETY: same allocation as above, freed exactly once.
    unsafe { ffi::openssl_free(ec as *mut std::os::raw::c_void) };
    Ok(bytes)
}

/// OpenSSL's ECH outcome callback: counts accepted/rejected
/// outcomes. The log string is deliberately not parsed (the
/// API documentation forbids relying on it); the outcome comes
/// from `SSL_ech_get1_status`, as the documentation prescribes.
extern "C" fn status_callback(ssl: *mut openssl_sys::SSL, _str: *const c_char) -> c_uint {
    // SAFETY: OpenSSL invokes this callback with a live SSL
    // during handshake processing; connection_status's contract
    // is satisfied by that guarantee.
    let status = unsafe { connection_status(ssl) };
    match status.status {
        EchStatus::Success => {
            ACCEPTED.fetch_add(1, Ordering::Relaxed);
        }
        EchStatus::FailedEch | EchStatus::FailedEchBadName => {
            REJECTED.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
    0
}
