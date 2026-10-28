// #################################################################
// /qompassai/vongola/crates/vongola-ech/build.rs
// Qompass AI — vongola-ech build gate
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

//! Build gate: this crate binds the OpenSSL 4.0 ECH API, which
//! does not exist in earlier releases. Fail the build with a
//! precise message instead of surfacing as link errors against
//! the wrong library. The check reads the headers openssl-sys
//! resolved (DEP_OPENSSL_INCLUDE), falling back to
//! $OPENSSL_DIR/include.

use std::path::PathBuf;

fn include_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(dep) = std::env::var("DEP_OPENSSL_INCLUDE") {
        for part in dep.split(';') {
            if !part.is_empty() {
                dirs.push(PathBuf::from(part));
            }
        }
    }
    if let Ok(dir) = std::env::var("OPENSSL_DIR") {
        dirs.push(PathBuf::from(dir).join("include"));
    }
    dirs
}

fn main() {
    println!("cargo:rerun-if-env-changed=DEP_OPENSSL_INCLUDE");
    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
    let dirs = include_dirs();
    let ech_header = dirs
        .iter()
        .map(|dir| dir.join("openssl").join("ech.h"))
        .find(|path| path.exists());
    let Some(ech_header) = ech_header else {
        panic!(
            "vongola-ech requires OpenSSL >= 4.0: openssl/ech.h not found under {dirs:?}. \
             Build against an OpenSSL 4.x installation (OPENSSL_DIR); \
             ECH (RFC 9849) does not exist in OpenSSL 3.x."
        );
    };
    // Belt and braces: the version header beside ech.h must agree.
    let version_header = ech_header.with_file_name("opensslv.h");
    if let Ok(text) = std::fs::read_to_string(&version_header) {
        let major_ok = text.lines().any(|line| {
            line.contains("OPENSSL_VERSION_MAJOR")
                && line
                    .split_whitespace()
                    .last()
                    .and_then(|value| value.parse::<u32>().ok())
                    .is_some_and(|value| value >= 4)
        });
        assert!(
            major_ok,
            "vongola-ech requires OpenSSL >= 4.0: no OPENSSL_VERSION_MAJOR >= 4 in {version_header:?}"
        );
    }
}
