// #################################################################
// /qompassai/vongola/crates/vongola-ech/src/ffi.rs
// Qompass AI — handwritten ECH FFI declarations
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

//! Handwritten FFI declarations for the OpenSSL 4.0 ECH API.
//!
//! Every signature here is transcribed from the installed
//! `include/openssl/ech.h` of the OpenSSL 4.0.3 build this
//! crate links against (plus `openssl/hpke.h` for the suite
//! struct) — the header is the contract. In upstream
//! rust-openssl terms this module is the `openssl-sys`
//! addition: it declares only what openssl-sys 0.9.114 lacks
//! (the ECH functions, the opaque `OSSL_ECHSTORE` type, and
//! two libcrypto helpers) and reuses openssl-sys types (BIO,
//! EVP_PKEY, OSSL_LIB_CTX, SSL, SSL_CTX) for everything else.

#![allow(dead_code, non_camel_case_types)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar, c_uint, c_ulong, c_void};

use openssl_sys::{BIO, EVP_PKEY, OSSL_LIB_CTX, SSL, SSL_CTX};

/// Opaque ECH store handle (openssl/ech.h). Values are created
/// by `OSSL_ECHSTORE_new`, owned by the holder, freed by
/// `OSSL_ECHSTORE_free`, and deep-copied (not refcounted) into
/// an SSL_CTX by `SSL_CTX_set1_echstore`.
pub enum OSSL_ECHSTORE {}

/// HPKE suite (openssl/hpke.h). The field order is the C struct
/// layout — kem_id, kdf_id, aead_id — and must not be reordered.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct OSSL_HPKE_SUITE {
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
}

/// ECH outcome callback (openssl/ech.h): invoked when the
/// outcome of an ECH attempt has been determined. The `str`
/// argument is a log string; callers must branch on
/// `SSL_ech_get1_status`, never parse the string.
pub type SSL_ech_cb_func = unsafe extern "C" fn(s: *mut SSL, str: *const c_char) -> c_uint;

/// BIO_CTRL_INFO: the BIO_ctrl command behind the C
/// BIO_get_mem_data macro (openssl/bio.h).
pub const BIO_CTRL_INFO: c_int = 3;

/// ECHConfig version for RFC 9849 (openssl/ech.h).
pub const OSSL_ECH_RFC9849_VERSION: u16 = 0xfe0d;
/// `for_retry` value: include entries in retry-configs.
pub const OSSL_ECH_FOR_RETRY: c_int = 1;
/// `for_retry` value: do not include entries in retry-configs.
pub const OSSL_ECH_NO_RETRY: c_int = 0;
/// write/get index selecting every entry (public values only
/// when writing PEM).
pub const OSSL_ECHSTORE_ALL: c_int = -2;
/// write/get index selecting the last entry.
pub const OSSL_ECHSTORE_LAST: c_int = -1;

/// HPKE AEAD identifiers (openssl/hpke.h).
pub const OSSL_HPKE_AEAD_ID_AES_GCM_128: u16 = 0x0001;
pub const OSSL_HPKE_AEAD_ID_AES_GCM_256: u16 = 0x0002;
pub const OSSL_HPKE_AEAD_ID_CHACHA_POLY1305: u16 = 0x0003;
/// HPKE KDF identifiers (openssl/hpke.h).
pub const OSSL_HPKE_KDF_ID_HKDF_SHA256: u16 = 0x0001;
pub const OSSL_HPKE_KDF_ID_HKDF_SHA384: u16 = 0x0002;
pub const OSSL_HPKE_KDF_ID_HKDF_SHA512: u16 = 0x0003;
/// HPKE KEM identifiers (openssl/hpke.h).
pub const OSSL_HPKE_KEM_ID_P256: u16 = 0x0010;
pub const OSSL_HPKE_KEM_ID_P384: u16 = 0x0011;
pub const OSSL_HPKE_KEM_ID_P521: u16 = 0x0012;
pub const OSSL_HPKE_KEM_ID_X25519: u16 = 0x0020;
pub const OSSL_HPKE_KEM_ID_X448: u16 = 0x0021;

/// Return codes from SSL_ech_get1_status (openssl/ech.h).
pub const SSL_ECH_STATUS_BACKEND: c_int = 4;
pub const SSL_ECH_STATUS_BAD_CALL: c_int = -100;
pub const SSL_ECH_STATUS_BAD_NAME: c_int = -102;
pub const SSL_ECH_STATUS_FAILED: c_int = 0;
pub const SSL_ECH_STATUS_FAILED_ECH: c_int = -105;
pub const SSL_ECH_STATUS_FAILED_ECH_BAD_NAME: c_int = -106;
pub const SSL_ECH_STATUS_GREASE: c_int = 2;
pub const SSL_ECH_STATUS_GREASE_ECH: c_int = 3;
pub const SSL_ECH_STATUS_NOT_CONFIGURED: c_int = -103;
pub const SSL_ECH_STATUS_NOT_TRIED: c_int = -101;
pub const SSL_ECH_STATUS_SUCCESS: c_int = 1;

unsafe extern "C" {
    /// The exported free behind the OPENSSL_free macro
    /// (openssl/crypto.h defines the macro over this function
    /// with file/line tracking; both are NULL/0 here).
    pub fn CRYPTO_free(addr: *mut c_void, file: *const c_char, line: c_int);

    /// Renders one queued OpenSSL error (libcrypto).
    pub fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);

    pub fn OSSL_ECHSTORE_downselect(es: *mut OSSL_ECHSTORE, index: c_int) -> c_int;
    pub fn OSSL_ECHSTORE_flush_keys(es: *mut OSSL_ECHSTORE, age: libc::time_t) -> c_int;
    pub fn OSSL_ECHSTORE_free(es: *mut OSSL_ECHSTORE);
    pub fn OSSL_ECHSTORE_get1_info(
        es: *mut OSSL_ECHSTORE,
        index: c_int,
        loaded_secs: *mut libc::time_t,
        public_name: *mut *mut c_char,
        echconfig: *mut *mut c_char,
        has_private: *mut c_int,
        for_retry: *mut c_int,
    ) -> c_int;
    pub fn OSSL_ECHSTORE_new(libctx: *mut OSSL_LIB_CTX, propq: *const c_char)
    -> *mut OSSL_ECHSTORE;
    pub fn OSSL_ECHSTORE_new_config(
        es: *mut OSSL_ECHSTORE,
        echversion: u16,
        max_name_length: u8,
        public_name: *const c_char,
        suite: OSSL_HPKE_SUITE,
    ) -> c_int;
    pub fn OSSL_ECHSTORE_num_entries(es: *const OSSL_ECHSTORE, numentries: *mut c_int) -> c_int;
    pub fn OSSL_ECHSTORE_num_keys(es: *mut OSSL_ECHSTORE, numkeys: *mut c_int) -> c_int;
    pub fn OSSL_ECHSTORE_read_echconfiglist(es: *mut OSSL_ECHSTORE, in_: *mut BIO) -> c_int;
    pub fn OSSL_ECHSTORE_read_pem(es: *mut OSSL_ECHSTORE, in_: *mut BIO, for_retry: c_int)
    -> c_int;
    pub fn OSSL_ECHSTORE_set1_key_and_read_pem(
        es: *mut OSSL_ECHSTORE,
        priv_: *mut EVP_PKEY,
        in_: *mut BIO,
        for_retry: c_int,
    ) -> c_int;
    pub fn OSSL_ECHSTORE_write_pem(es: *mut OSSL_ECHSTORE, index: c_int, out: *mut BIO) -> c_int;

    pub fn SSL_CTX_ech_set_callback(ctx: *mut SSL_CTX, f: SSL_ech_cb_func);
    pub fn SSL_CTX_get1_echstore(ctx: *const SSL_CTX) -> *mut OSSL_ECHSTORE;
    pub fn SSL_CTX_set1_echstore(ctx: *mut SSL_CTX, es: *mut OSSL_ECHSTORE) -> c_int;
    pub fn SSL_ech_get1_retry_config(
        s: *mut SSL,
        ec: *mut *mut c_uchar,
        eclen: *mut usize,
    ) -> c_int;
    pub fn SSL_ech_get1_status(
        s: *mut SSL,
        inner_sni: *mut *mut c_char,
        outer_sni: *mut *mut c_char,
    ) -> c_int;
    pub fn SSL_ech_set_callback(s: *mut SSL, f: SSL_ech_cb_func);
    pub fn SSL_get1_echstore(s: *const SSL) -> *mut OSSL_ECHSTORE;
    pub fn SSL_set1_ech_config_list(ssl: *mut SSL, ecl: *const u8, ecl_len: usize) -> c_int;
    pub fn SSL_set1_echstore(s: *mut SSL, es: *mut OSSL_ECHSTORE) -> c_int;
}

/// Takes ownership of a string OpenSSL allocated (via
/// `OPENSSL_strdup` in the ECH APIs) and converts it to a Rust
/// `String`, freeing the original. `NULL` maps to `None`.
///
/// # Safety
/// `ptr` must be NULL or a NUL-terminated string allocated by
/// OpenSSL that the caller owns and has not freed.
pub(crate) unsafe fn take_openssl_string(ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: per the caller contract above, `ptr` is a valid
    // NUL-terminated OpenSSL string; we copy it, then free the
    // original exactly once.
    let text = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    // SAFETY: `ptr` came from OpenSSL allocation and is freed
    // exactly once, here.
    unsafe { openssl_free(ptr as *mut c_void) };
    Some(text)
}

/// Frees memory allocated by OpenSSL (the OPENSSL_free macro,
/// expanded by hand over CRYPTO_free).
///
/// # Safety
/// `ptr` must be NULL or memory allocated by OpenSSL that the
/// caller owns and has not freed.
pub(crate) unsafe fn openssl_free(ptr: *mut c_void) {
    // SAFETY: per this function's caller contract; CRYPTO_free
    // accepts NULL (a no-op) and otherwise frees OpenSSL
    // allocations. File/line are debug metadata, NULL/0 here.
    unsafe { CRYPTO_free(ptr, std::ptr::null(), 0) }
}
