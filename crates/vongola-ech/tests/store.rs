// #################################################################
// /qompassai/vongola/crates/vongola-ech/tests/store.rs
// Qompass AI — vongola-ech store tests
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

//! Store lifecycle tests against the real OpenSSL 4.x library.
//! Names carry the tree convention: `validation_*` for the
//! happy path, `adversarial_*` for hostile inputs.

use vongola_ech::{EchStore, HpkeSuite};

const PUBLIC_NAME: &str = "cover.example.test";

fn generated_store() -> EchStore {
    let mut store = EchStore::new().expect("store");
    store
        .generate(PUBLIC_NAME, 0, HpkeSuite::DEFAULT)
        .expect("generate");
    store
}

#[test]
fn validation_generate_produces_singleton_with_private_key() {
    let mut store = generated_store();
    assert_eq!(store.num_entries().unwrap(), 1);
    assert_eq!(store.num_keys().unwrap(), 1);
    let info = store.entry_info(0).unwrap();
    assert_eq!(info.public_name, PUBLIC_NAME);
    assert!(info.has_private, "generated entry must hold its key");
    assert!(
        info.display.starts_with("[fe0d,"),
        "display string must be the RFC 9849 string form, got {}",
        info.display
    );
}

#[test]
fn validation_pem_round_trip_preserves_config_list() {
    let mut original = generated_store();
    let pem = original.entry_pem(0).unwrap();
    let text = String::from_utf8(pem.clone()).unwrap();
    assert!(text.contains("-----BEGIN PRIVATE KEY-----"), "{text}");
    assert!(text.contains("-----BEGIN ECHCONFIG-----"), "{text}");
    let expected_list = original.config_list_base64().unwrap();

    let mut loaded = EchStore::new().unwrap();
    loaded.load_pem(&pem, true).unwrap();
    assert_eq!(loaded.num_entries().unwrap(), 1);
    assert_eq!(loaded.num_keys().unwrap(), 1);
    assert_eq!(loaded.config_list_base64().unwrap(), expected_list);
    let info = loaded.entry_info(0).unwrap();
    assert!(info.has_private);
    assert!(info.for_retry, "loaded with for_retry=true");
}

#[test]
fn validation_config_list_loads_as_public_only() {
    let mut original = generated_store();
    let base64 = original.config_list_base64().unwrap();
    let mut public = EchStore::new().unwrap();
    public.load_config_list(base64.as_bytes()).unwrap();
    assert_eq!(public.num_entries().unwrap(), 1);
    assert_eq!(public.num_keys().unwrap(), 0, "public list carries no keys");
    let info = public.entry_info(0).unwrap();
    assert!(!info.has_private);
    assert_eq!(info.public_name, PUBLIC_NAME);
}

#[test]
fn validation_config_list_binary_matches_base64_and_length_prefix() {
    let mut store = generated_store();
    let binary = store.config_list().unwrap();
    assert!(binary.len() > 2, "ECHConfigList has a 2-byte prefix + body");
    let declared = u16::from_be_bytes([binary[0], binary[1]]) as usize;
    assert_eq!(
        declared,
        binary.len() - 2,
        "the u16 prefix must count the ECHConfig bytes that follow"
    );
    // RFC 9849 version is the first field of the ECHConfig.
    assert_eq!(&binary[2..4], &[0xfe, 0x0d]);
}

#[test]
fn validation_public_pem_never_contains_private_key() {
    let mut store = generated_store();
    let pem = String::from_utf8(store.public_pem().unwrap()).unwrap();
    assert!(pem.contains("-----BEGIN ECHCONFIG-----"), "{pem}");
    assert!(
        !pem.contains("PRIVATE KEY"),
        "public PEM leaked a key:\n{pem}"
    );
}

#[test]
fn adversarial_load_pem_rejects_garbage() {
    let mut store = EchStore::new().unwrap();
    let err = store
        .load_pem(b"this is not a PEM file at all\x00\x01\x02", true)
        .expect_err("garbage must be rejected");
    assert!(!err.to_string().is_empty());
    assert_eq!(
        store.num_entries().unwrap(),
        0,
        "failed load must not add entries"
    );
}

#[test]
fn adversarial_load_pem_rejects_truncated_pem() {
    let mut original = generated_store();
    let pem = original.entry_pem(0).unwrap();
    let truncated = &pem[..pem.len() / 2];
    let mut store = EchStore::new().unwrap();
    assert!(
        store.load_pem(truncated, true).is_err(),
        "a half-written key file must fail closed"
    );
}

#[test]
fn adversarial_load_config_list_rejects_garbage() {
    let mut store = EchStore::new().unwrap();
    assert!(store.load_config_list(b"!!!not-base64!!!").is_err());
    assert!(
        store.load_config_list(b"AAAA").is_err(),
        "decodes but is not an ECHConfigList"
    );
    assert_eq!(store.num_entries().unwrap(), 0);
}

#[test]
fn adversarial_generate_rejects_bad_public_names() {
    let mut store = EchStore::new().unwrap();
    for bad in [
        "",
        "has space.example",
        "new\nline.example",
        ".leading-dot.example",
        "double..dot.example",
        "slash/example",
    ] {
        assert!(
            store.generate(bad, 0, HpkeSuite::DEFAULT).is_err(),
            "public_name {bad:?} must be rejected"
        );
    }
    let too_long = format!("{}.example", "a".repeat(250));
    assert!(too_long.len() > 255);
    assert!(store.generate(&too_long, 0, HpkeSuite::DEFAULT).is_err());
    assert_eq!(
        store.num_entries().unwrap(),
        0,
        "rejected generates must not append"
    );
}

#[test]
fn adversarial_entry_info_out_of_range() {
    let mut store = generated_store();
    assert!(store.entry_info(7).is_err());
    assert!(store.entry_pem(7).is_err());
}
