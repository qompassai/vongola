// #################################################################
// /qompassai/vongola/crates/vongola/src/stores/certificates.rs
// Qompass AI Certificate Store
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

use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};

#[derive(Debug, Clone)]
pub struct Certificate {
    pub key: PKey<Private>,
    #[allow(clippy::struct_field_names)]
    pub leaf: X509,
    pub chain: Option<X509>,
}

pub type CertificateStore = papaya::HashMap<String, Certificate>;

/// Builds an in-memory self-signed certificate for `domain`.
///
/// This backs the `ssl_certificate.self_signed_on_failure` route
/// option: it is only useful for local development and testing, and
/// is created lazily the first time a handshake needs it (see the
/// certificate callback in the HTTPS proxy). The key is EC P-384 and
/// the certificate is SHA-256 signed with a one-year validity.
pub fn self_signed(domain: &str) -> Result<Certificate, anyhow::Error> {
    let ec_group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1)?;
    let ec_key = openssl::ec::EcKey::generate(&ec_group)?;
    let key = openssl::pkey::PKey::from_ec_key(ec_key)?;
    let mut openssl_cert = openssl::x509::X509Builder::new()?;
    let mut x509_name = openssl::x509::X509NameBuilder::new()?;
    x509_name.append_entry_by_text("CN", domain)?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "Vongola")?;
    let x509_name = x509_name.build();
    let hash = openssl::hash::MessageDigest::sha256();
    let one_year = openssl::asn1::Asn1Time::days_from_now(365)?;
    let today = openssl::asn1::Asn1Time::days_from_now(0)?;
    openssl_cert.set_version(2)?;
    openssl_cert.set_subject_name(&x509_name)?;
    openssl_cert.set_issuer_name(&x509_name)?;
    openssl_cert.set_pubkey(&key)?;
    openssl_cert.set_not_before(&today)?;
    openssl_cert.set_not_after(&one_year)?;
    openssl_cert.sign(&key, hash)?;
    let leaf = openssl_cert.build();
    Ok(Certificate {
        key,
        leaf,
        chain: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_builds_parseable_cert_for_domain() {
        let cert = self_signed("unit-test.invalid").expect("self-signed construction");
        let subject = cert
            .leaf
            .subject_name()
            .entries()
            .next()
            .expect("a CN entry")
            .data()
            .as_utf8()
            .expect("CN is UTF-8")
            .to_string();
        assert_eq!(subject, "unit-test.invalid");
        assert!(cert.chain.is_none());
    }

    #[test]
    fn self_signed_rejects_empty_domain() {
        // OpenSSL refuses an empty CN value; the error must surface as
        // Err, never a panic or a silently empty certificate.
        assert!(self_signed("").is_err());
    }
}
