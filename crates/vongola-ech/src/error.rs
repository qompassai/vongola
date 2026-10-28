// #################################################################
// /qompassai/vongola/crates/vongola-ech/src/error.rs
// Qompass AI — vongola-ech error type
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

//! The crate's error type. Every fallible call returns
//! [`Error`], which drains the calling thread's OpenSSL error
//! queue at failure time so the failure carries the library's
//! own reason strings, not just a status code.

use std::ffi::CStr;
use std::fmt;
use std::os::raw::c_int;

use crate::ffi;

/// A failed ECH operation: the operation that failed plus the
/// OpenSSL error-queue strings captured at that moment.
#[derive(Clone, Debug)]
pub struct Error {
    context: String,
    openssl_errors: Vec<String>,
}

impl Error {
    pub(crate) fn new(context: impl Into<String>) -> Error {
        Error {
            context: context.into(),
            openssl_errors: drain_error_queue(),
        }
    }

    /// The operation that failed, e.g. "OSSL_ECHSTORE_read_pem".
    pub fn context(&self) -> &str { &self.context }

    /// OpenSSL error-queue strings captured at failure time
    /// (empty when OpenSSL queued nothing, e.g. for this
    /// crate's own input validation).
    pub fn openssl_errors(&self) -> &[String] { &self.openssl_errors }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.openssl_errors.is_empty() {
            write!(f, "{}", self.context)
        } else {
            write!(f, "{}: {}", self.context, self.openssl_errors.join("; "))
        }
    }
}

impl std::error::Error for Error {}

/// The ECH C API returns 1 on success and 0 on error; map that
/// onto `Result`, capturing the error queue on failure.
pub(crate) fn check(context: &'static str, ret: c_int) -> Result<(), Error> {
    if ret == 1 {
        Ok(())
    } else {
        Err(Error::new(context))
    }
}

/// Pop every queued OpenSSL error on this thread into strings.
fn drain_error_queue() -> Vec<String> {
    let mut out = Vec::new();
    loop {
        // SAFETY: ERR_get_error pops the calling thread's error
        // queue and returns 0 once the queue is empty.
        let code = unsafe { openssl_sys::ERR_get_error() };
        if code == 0 {
            return out;
        }
        let mut buf = [0u8; 256];
        // SAFETY: `buf` is a writable 256-byte buffer;
        // ERR_error_string_n writes at most 256 bytes including
        // the NUL terminator.
        unsafe {
            ffi::ERR_error_string_n(
                code,
                buf.as_mut_ptr() as *mut std::os::raw::c_char,
                buf.len(),
            );
        }
        let text = CStr::from_bytes_until_nul(&buf)
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        out.push(text);
    }
}
