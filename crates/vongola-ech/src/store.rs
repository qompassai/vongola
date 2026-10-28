// #################################################################
// /qompassai/vongola/crates/vongola-ech/src/store.rs
// Qompass AI — safe OSSL_ECHSTORE wrapper
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

//! [`EchStore`]: the safe wrapper over `OSSL_ECHSTORE`.
//!
//! A store holds ECHConfig entries and their private keys. The
//! lifecycle mirrors the C API: create empty, then either
//! [`EchStore::generate`] a fresh key pair + config or
//! [`EchStore::load_pem`] an existing ECH PEM file (RFC 9934),
//! serialize with [`EchStore::entry_pem`] /
//! [`EchStore::config_list`], and
//! [`EchStore::attach_to_ctx`] to turn ECH on for a listener.
//!
//! Method receivers follow the C header's constness exactly:
//! several nominally read-only operations (`OSSL_ECHSTORE_write_pem`,
//! `OSSL_ECHSTORE_get1_info`, `OSSL_ECHSTORE_num_keys`) take a
//! non-const store in C, so they take `&mut self` here.

use std::ffi::CString;
use std::os::raw::{c_int, c_void};
use std::ptr;

use base64::Engine;

use crate::error::{Error, check};
use crate::ffi;
/// The ECHConfig version this crate generates: RFC 9849.
pub use crate::ffi::OSSL_ECH_RFC9849_VERSION as ECH_RFC9849_VERSION;

/// Hard cap on PEM / ECHConfigList input accepted by the load
/// paths (the largest legal ECHConfigList is ~1500 bytes; the
/// cap leaves generous room for multi-entry PEM files while
/// keeping every load bounded).
pub const MAX_PEM_BYTES: usize = 1024 * 1024;

/// One store entry's public metadata (from
/// `OSSL_ECHSTORE_get1_info`). `display` is OpenSSL's string
/// form of the ECHConfig — for logging, never parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryInfo {
    pub display: String,
    pub for_retry: bool,
    pub has_private: bool,
    pub loaded_secs: u64,
    pub public_name: String,
}

/// An HPKE suite (RFC 9180) for a generated ECHConfig.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpkeSuite {
    pub aead_id: u16,
    pub kdf_id: u16,
    pub kem_id: u16,
}

impl HpkeSuite {
    /// RFC 9849's mandatory-to-implement suite:
    /// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM.
    pub const DEFAULT: HpkeSuite = HpkeSuite {
        aead_id: ffi::OSSL_HPKE_AEAD_ID_AES_GCM_128,
        kdf_id: ffi::OSSL_HPKE_KDF_ID_HKDF_SHA256,
        kem_id: ffi::OSSL_HPKE_KEM_ID_X25519,
    };

    pub const fn new(kem_id: u16, kdf_id: u16, aead_id: u16) -> HpkeSuite {
        HpkeSuite {
            aead_id,
            kdf_id,
            kem_id,
        }
    }

    fn to_ffi(self) -> ffi::OSSL_HPKE_SUITE {
        ffi::OSSL_HPKE_SUITE {
            kem_id: self.kem_id,
            kdf_id: self.kdf_id,
            aead_id: self.aead_id,
        }
    }
}

/// An ECH store: ECHConfig entries plus their private keys.
///
/// Owns the underlying `OSSL_ECHSTORE` and frees it on drop.
/// Stores are deep-copied into an `SSL_CTX` on attach, so a
/// store stays valid and usable after attachment.
pub struct EchStore {
    ptr: *mut ffi::OSSL_ECHSTORE,
}

// SAFETY: an EchStore exclusively owns its OSSL_ECHSTORE; all
// mutation goes through &mut self, so moving the handle to
// another thread cannot create data races. It is deliberately
// not Sync: &self operations are only the const-correct C
// queries, and shared concurrent access is not offered.
unsafe impl Send for EchStore {}

impl EchStore {
    /// Creates an empty store (default library context).
    pub fn new() -> Result<EchStore, Error> {
        // SAFETY: OSSL_ECHSTORE_new with a NULL libctx and NULL
        // property query selects the default library context;
        // the returned pointer is checked before use.
        let ptr = unsafe { ffi::OSSL_ECHSTORE_new(ptr::null_mut(), ptr::null()) };
        if ptr.is_null() {
            return Err(Error::new("OSSL_ECHSTORE_new"));
        }
        Ok(EchStore { ptr })
    }

    /// Attaches this store to an `SSL_CTX`, enabling ECH for
    /// every connection on contexts derived from it. OpenSSL
    /// deep-copies the store; this handle is unaffected.
    ///
    /// # Safety
    /// `ctx` must point at a live `SSL_CTX` that stays valid
    /// for the duration of the call. (In the openssl crate this
    /// is `SslContextBuilder::as_ptr` before the builder is
    /// consumed.)
    pub unsafe fn attach_to_ctx(&self, ctx: *mut openssl_sys::SSL_CTX) -> Result<(), Error> {
        if ctx.is_null() {
            return Err(Error::new("SSL_CTX_set1_echstore: NULL SSL_CTX"));
        }
        // SAFETY: per this function's caller contract, `ctx` is
        // a live SSL_CTX; self.ptr is a live store owned by
        // &self. OpenSSL deep-copies the store, so no lifetime
        // coupling remains after the call.
        let ret = unsafe { ffi::SSL_CTX_set1_echstore(ctx, self.ptr) };
        check("SSL_CTX_set1_echstore", ret)
    }

    /// The publishable ECHConfigList (wire form: a two-byte
    /// length followed by the concatenated ECHConfigs), for
    /// client-side use. For DNS publication and
    /// `openssl s_client -ech_config_list`, use
    /// [`EchStore::config_list_base64`].
    ///
    /// Assembled per entry, NOT via `write_pem(ALL)`: in
    /// OpenSSL 4.0.3 a generated entry's encoding is already a
    /// singleton ECHConfigList, and the ALL form wraps those
    /// encodings in a second length prefix, producing a list
    /// whose first ECHConfig has a bogus version field. (The
    /// per-entry PEM form is correct, so the list is rebuilt
    /// from the entries' bare ECHConfigs — see
    /// `entry_bare_config` for the two serialization shapes.)
    pub fn config_list(&mut self) -> Result<Vec<u8>, Error> {
        let entries = self.num_entries()?;
        if entries == 0 {
            return Err(Error::new("ECH store has no entries to publish"));
        }
        let mut body: Vec<u8> = Vec::new();
        for index in 0..entries {
            body.extend_from_slice(&self.entry_bare_config(index)?);
        }
        let total = u16::try_from(body.len())
            .map_err(|_| Error::new("ECHConfigList exceeds the u16 length bound"))?;
        let mut list = Vec::with_capacity(body.len() + 2);
        list.extend_from_slice(&total.to_be_bytes());
        list.extend_from_slice(&body);
        Ok(list)
    }

    /// The publishable ECHConfigList, base64-encoded: the value
    /// of the `ech=` SvcParam in a DNS HTTPS (type 65) record.
    /// Contains public material only — safe to publish.
    pub fn config_list_base64(&mut self) -> Result<String, Error> {
        let list = self.config_list()?;
        Ok(base64::engine::general_purpose::STANDARD.encode(list))
    }

    /// Discards every entry except `index` (e.g. to retire old
    /// configs after a rotation).
    pub fn downselect(&mut self, index: usize) -> Result<(), Error> {
        // SAFETY: self.ptr is a live store owned by &mut self.
        let ret = unsafe { ffi::OSSL_ECHSTORE_downselect(self.ptr, index_to_c_int(index)?) };
        check("OSSL_ECHSTORE_downselect", ret)
    }

    /// Serializes one entry as an ECH PEM file body (RFC 9934):
    /// its private-key block (when the store holds the key)
    /// followed by its ECHCONFIG block. This is the on-disk
    /// key-file form that `openssl s_server -ech_key` and
    /// [`EchStore::load_pem`] consume. Handle as a secret.
    pub fn entry_pem(&mut self, index: usize) -> Result<Vec<u8>, Error> {
        self.write_pem(index_to_c_int(index)?)
    }

    /// Metadata for one entry.
    pub fn entry_info(&mut self, index: usize) -> Result<EntryInfo, Error> {
        let mut loaded_secs: libc::time_t = 0;
        let mut public_name: *mut std::os::raw::c_char = ptr::null_mut();
        let mut echconfig: *mut std::os::raw::c_char = ptr::null_mut();
        let mut has_private: c_int = 0;
        let mut for_retry: c_int = 0;
        // SAFETY: self.ptr is a live store owned by &mut self;
        // every out-parameter points at writable storage that
        // outlives the call. The two returned strings are
        // OpenSSL-allocated and taken over (copied + freed) by
        // take_openssl_string below, on both success and failure.
        let ret = unsafe {
            ffi::OSSL_ECHSTORE_get1_info(
                self.ptr,
                index_to_c_int(index)?,
                &mut loaded_secs,
                &mut public_name,
                &mut echconfig,
                &mut has_private,
                &mut for_retry,
            )
        };
        // SAFETY: public_name/echconfig are NULL or owned
        // OpenSSL strings per the get1_info contract.
        let public_name = unsafe { ffi::take_openssl_string(public_name) };
        // SAFETY: same contract as above.
        let display = unsafe { ffi::take_openssl_string(echconfig) };
        check("OSSL_ECHSTORE_get1_info", ret)?;
        Ok(EntryInfo {
            display: display.unwrap_or_default(),
            for_retry: for_retry != 0,
            has_private: has_private != 0,
            loaded_secs: u64::try_from(loaded_secs).unwrap_or(0),
            public_name: public_name.unwrap_or_default(),
        })
    }

    /// Drops private keys loaded more than `max_age_secs`
    /// seconds ago (the rotation companion to periodic loads).
    pub fn flush_keys(&mut self, max_age_secs: u64) -> Result<(), Error> {
        let age = libc::time_t::try_from(max_age_secs)
            .map_err(|_| Error::new("max_age_secs out of range"))?;
        // SAFETY: self.ptr is a live store owned by &mut self.
        let ret = unsafe { ffi::OSSL_ECHSTORE_flush_keys(self.ptr, age) };
        check("OSSL_ECHSTORE_flush_keys", ret)
    }

    /// Generates a fresh ECH key pair and a singleton
    /// ECHConfig for `public_name` (RFC 9849 version), appended
    /// to the store. `max_name_length` is the longest inner
    /// server name clients will use (ECH padding); 0 means "no
    /// known maximum" and is the usual choice.
    pub fn generate(
        &mut self,
        public_name: &str,
        max_name_length: u8,
        suite: HpkeSuite,
    ) -> Result<(), Error> {
        validate_public_name(public_name)?;
        let c_name =
            CString::new(public_name).map_err(|_| Error::new("public_name contains a NUL byte"))?;
        // SAFETY: self.ptr is a live store owned by &mut self;
        // c_name is NUL-terminated and outlives the call; the
        // suite is passed by value in the header's C layout.
        let ret = unsafe {
            ffi::OSSL_ECHSTORE_new_config(
                self.ptr,
                ECH_RFC9849_VERSION,
                max_name_length,
                c_name.as_ptr(),
                suite.to_ffi(),
            )
        };
        check("OSSL_ECHSTORE_new_config", ret)
    }

    /// Loads a base64-encoded ECHConfigList (the DNS `ech=`
    /// value) as public-only entries — the client/testing
    /// counterpart of [`EchStore::load_pem`].
    pub fn load_config_list(&mut self, base64_text: &[u8]) -> Result<(), Error> {
        let bio = MemBio::reading(base64_text)?;
        // SAFETY: self.ptr is a live store owned by &mut self;
        // bio is a valid memory BIO over `base64_text`, which
        // outlives the call.
        let ret = unsafe { ffi::OSSL_ECHSTORE_read_echconfiglist(self.ptr, bio.as_ptr()) };
        check("OSSL_ECHSTORE_read_echconfiglist", ret)
    }

    /// Loads an ECH PEM file body (RFC 9934): a private key
    /// plus its ECHConfigList. With `for_retry`, the loaded
    /// configs join the retry-configs a server hands to clients
    /// whose ECH attempt failed.
    pub fn load_pem(&mut self, pem: &[u8], for_retry: bool) -> Result<(), Error> {
        let bio = MemBio::reading(pem)?;
        // SAFETY: self.ptr is a live store owned by &mut self;
        // bio is a valid memory BIO over `pem`, which outlives
        // the call.
        let ret = unsafe {
            ffi::OSSL_ECHSTORE_read_pem(
                self.ptr,
                bio.as_ptr(),
                if for_retry {
                    ffi::OSSL_ECH_FOR_RETRY
                } else {
                    ffi::OSSL_ECH_NO_RETRY
                },
            )
        };
        check("OSSL_ECHSTORE_read_pem", ret)
    }

    /// Number of ECHConfig entries in the store.
    pub fn num_entries(&self) -> Result<usize, Error> {
        let mut count: c_int = 0;
        // SAFETY: self.ptr is a live store; `count` is writable
        // storage that outlives the call.
        let ret = unsafe { ffi::OSSL_ECHSTORE_num_entries(self.ptr, &mut count) };
        check("OSSL_ECHSTORE_num_entries", ret)?;
        usize::try_from(count).map_err(|_| Error::new("OSSL_ECHSTORE_num_entries: negative count"))
    }

    /// Number of private keys in the store. A server store
    /// must hold at least one key to accept ECH.
    pub fn num_keys(&mut self) -> Result<usize, Error> {
        let mut count: c_int = 0;
        // SAFETY: self.ptr is a live store owned by &mut self;
        // `count` is writable storage that outlives the call.
        let ret = unsafe { ffi::OSSL_ECHSTORE_num_keys(self.ptr, &mut count) };
        check("OSSL_ECHSTORE_num_keys", ret)?;
        usize::try_from(count).map_err(|_| Error::new("OSSL_ECHSTORE_num_keys: negative count"))
    }

    /// Serializes the publishable ECHConfigList as a single
    /// ECHCONFIG PEM block. Never contains private keys.
    /// (Synthesized from [`EchStore::config_list`]; see its
    /// documentation for why `write_pem(ALL)` is not used.)
    pub fn public_pem(&mut self) -> Result<Vec<u8>, Error> {
        let base64 = self.config_list_base64()?;
        let mut pem = String::from("-----BEGIN ECHCONFIG-----\n");
        for chunk in base64.as_bytes().chunks(64) {
            // The base64 alphabet is ASCII, so this never loses data.
            pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str("-----END ECHCONFIG-----\n");
        Ok(pem.into_bytes())
    }

    /// One entry's bare ECHConfig in wire form, decoded from
    /// its PEM serialization. OpenSSL 4.0.3 serializes a
    /// generated entry's ECHCONFIG block as a singleton
    /// ECHConfigList (length prefix + config) but a PEM-loaded
    /// entry's block as the bare config, so both shapes are
    /// accepted — each validated against the length fields it
    /// carries. Anything else fails closed.
    fn entry_bare_config(&mut self, index: usize) -> Result<Vec<u8>, Error> {
        let pem = self.entry_pem(index)?;
        let text = String::from_utf8(pem)
            .map_err(|_| Error::new("OSSL_ECHSTORE_write_pem produced non-UTF-8 PEM"))?;
        let body = extract_pem_block(&text, "ECHCONFIG")
            .ok_or_else(|| Error::new("no ECHCONFIG block in entry PEM"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|e| Error::new(format!("ECHConfig base64 decode: {e}")))?;
        if bytes.len() < 4 {
            return Err(Error::new("ECHConfig entry is truncated"));
        }
        if u16::from_be_bytes([bytes[0], bytes[1]]) == ECH_RFC9849_VERSION {
            return validate_bare_config(bytes);
        }
        // Singleton-list form: strip the list length prefix.
        let declared = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if declared != bytes.len() - 2 {
            return Err(Error::new(
                "ECHConfigList entry length prefix does not match its body",
            ));
        }
        validate_bare_config(bytes[2..].to_vec())
    }

    fn write_pem(&mut self, index: c_int) -> Result<Vec<u8>, Error> {
        let mut bio = MemBio::writing()?;
        // SAFETY: self.ptr is a live store owned by &mut self;
        // bio is a valid memory BIO that outlives the call.
        let ret = unsafe { ffi::OSSL_ECHSTORE_write_pem(self.ptr, index, bio.as_ptr()) };
        check("OSSL_ECHSTORE_write_pem", ret)?;
        bio.take_contents()
    }
}

impl Drop for EchStore {
    fn drop(&mut self) {
        // SAFETY: self.ptr came from OSSL_ECHSTORE_new, is
        // exclusively owned by this handle, and is freed
        // exactly once, here.
        unsafe { ffi::OSSL_ECHSTORE_free(self.ptr) }
    }
}

/// Validates a bare ECHConfig: version must be the RFC 9849
/// version and the internal length field must count exactly
/// the contents bytes that follow it.
fn validate_bare_config(bytes: Vec<u8>) -> Result<Vec<u8>, Error> {
    if bytes.len() < 4
        || u16::from_be_bytes([bytes[0], bytes[1]]) != ECH_RFC9849_VERSION
        || u16::from_be_bytes([bytes[2], bytes[3]]) as usize != bytes.len() - 4
    {
        return Err(Error::new("ECHConfig has a bad version or length field"));
    }
    Ok(bytes)
}

/// Extracts and concatenates the base64 body of the first
/// `-----BEGIN <label>-----` block in a PEM text. Anything that
/// is not a base64 character is skipped (line breaks, CR).
fn extract_pem_block(text: &str, label: &str) -> Option<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)? + begin.len();
    let stop = text[start..].find(&end)? + start;
    let mut body = String::new();
    for ch in text[start..stop].chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=') {
            body.push(ch);
        }
    }
    if body.is_empty() { None } else { Some(body) }
}

fn index_to_c_int(index: usize) -> Result<c_int, Error> {
    c_int::try_from(index).map_err(|_| Error::new("ECH store index out of range"))
}

/// Input discipline for generated configs: a public_name is a
/// DNS name of at most 255 bytes (OSSL_ECH_MAX_PUBLICNAME)
/// over the LDH alphabet plus dots.
fn validate_public_name(public_name: &str) -> Result<(), Error> {
    if public_name.is_empty() {
        return Err(Error::new("public_name must not be empty"));
    }
    if public_name.len() > 255 {
        return Err(Error::new("public_name exceeds 255 bytes"));
    }
    let valid = public_name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        && !public_name.starts_with(['.', '-'])
        && !public_name.contains("..");
    if !valid {
        return Err(Error::new(
            "public_name is not a DNS name (LDH letters, digits, '-', '.', '_')",
        ));
    }
    Ok(())
}

/// A memory BIO, the only BIO flavor this crate needs: reads
/// from a byte slice for the load paths, accumulates bytes for
/// the write paths. Freed on drop.
struct MemBio {
    ptr: *mut openssl_sys::BIO,
}

impl MemBio {
    fn as_ptr(&self) -> *mut openssl_sys::BIO { self.ptr }

    fn reading(data: &[u8]) -> Result<MemBio, Error> {
        if data.len() > MAX_PEM_BYTES {
            return Err(Error::new("ECH input exceeds the 1 MiB bound"));
        }
        let len = c_int::try_from(data.len()).map_err(|_| Error::new("ECH input too large"))?;
        // SAFETY: BIO_new_mem_buf borrows `data` (it does not
        // copy); the returned BIO is used only while `data` is
        // alive (the caller's load call) and freed by Drop
        // before `data` can go out of scope.
        let ptr = unsafe { openssl_sys::BIO_new_mem_buf(data.as_ptr() as *const c_void, len) };
        if ptr.is_null() {
            return Err(Error::new("BIO_new_mem_buf"));
        }
        Ok(MemBio { ptr })
    }

    fn take_contents(&mut self) -> Result<Vec<u8>, Error> {
        let mut data: *mut std::os::raw::c_char = ptr::null_mut();
        // SAFETY: BIO_CTRL_INFO is the BIO_get_mem_data macro
        // expanded by hand: it stores the buffer pointer in
        // `data` and returns its length. The buffer is owned by
        // the BIO and stays valid until the BIO is freed or
        // written again; we copy it out immediately.
        let len = unsafe {
            openssl_sys::BIO_ctrl(
                self.ptr,
                ffi::BIO_CTRL_INFO,
                0,
                &mut data as *mut *mut std::os::raw::c_char as *mut c_void,
            )
        };
        if len < 0 || data.is_null() {
            return Err(Error::new("BIO_get_mem_data"));
        }
        let len = usize::try_from(len).map_err(|_| Error::new("BIO length out of range"))?;
        if len > MAX_PEM_BYTES {
            return Err(Error::new("BIO contents exceed the 1 MiB bound"));
        }
        // SAFETY: `data` points at `len` readable bytes owned
        // by the BIO (see above); the slice is copied before
        // the BIO can change.
        let slice = unsafe { std::slice::from_raw_parts(data as *const u8, len) };
        Ok(slice.to_vec())
    }

    fn writing() -> Result<MemBio, Error> {
        // SAFETY: BIO_s_mem returns the static memory BIO
        // method; BIO_new allocates a BIO using it. The result
        // is checked before use and freed by Drop.
        let ptr = unsafe { openssl_sys::BIO_new(openssl_sys::BIO_s_mem()) };
        if ptr.is_null() {
            return Err(Error::new("BIO_new(BIO_s_mem)"));
        }
        Ok(MemBio { ptr })
    }
}

impl Drop for MemBio {
    fn drop(&mut self) {
        // SAFETY: self.ptr came from BIO_new/BIO_new_mem_buf,
        // is exclusively owned here, and is freed exactly once.
        // (BIO_free_all on an unchained BIO frees just it.)
        unsafe { openssl_sys::BIO_free_all(self.ptr) }
    }
}
