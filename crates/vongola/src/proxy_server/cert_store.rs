// #################################################################
// /qompassai/vongola/crates/vongola/src/proxy_server/cert_store.rs
// Qompass AI SNI Certificate Store Callback
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

use async_trait::async_trait;
use openssl::ssl::{SniError, SslRef};
use pingora::listeners::TlsAccept;
use pingora::tls::ext;
use pingora::tls::ssl::NameType;

use crate::stores::{self};

/// Provides the correct certificates when performing SSL handshakes
#[derive(Debug, Clone)]
pub struct CertStore {}

impl CertStore {
    pub fn new() -> Self { CertStore {} }

    // This function is called when the servername callback executes
    // It is used to check if the server name is in the certificate store
    // If it is, the handshake continues, otherwise it is aborted
    // and the client is disconnected
    #[allow(clippy::unnecessary_wraps)]
    pub fn sni_callback(ssl_ref: &mut SslRef) -> Result<(), SniError> {
        let servername = ssl_ref.servername(NameType::HOST_NAME).unwrap_or("");
        tracing::debug!("Received SNI: {}", servername);

        // if stores::get_certificate_by_key(servername).is_some() {
        Ok(())
        // }

        // Abort the handshake
        // Err(SniError::ALERT_FATAL)
    }
}

#[async_trait]
impl TlsAccept for CertStore {
    /// This function is called when the SSL handshake is performed
    /// It is used to provide the correct certificate to the client
    /// based on the server name
    async fn certificate_callback(&self, ssl: &mut pingora::tls::ssl::SslRef) {
        // Due to the sni_callback function, we can safely unwrap here
        let host_name = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or_default()
            .to_string();

        let cert = match stores::get_certificate_by_key(&host_name) {
            Some(cert) => cert,
            None => match self_signed_fallback(&host_name) {
                Some(cert) => cert,
                None => {
                    tracing::debug!("No certificate found for host: {:?}", host_name);
                    return;
                }
            },
        };

        if let Err(err) = ext::ssl_use_private_key(ssl, &cert.key) {
            tracing::error!("failed to set private key for {host_name}: {err}");
            return;
        }
        if let Err(err) = ext::ssl_use_certificate(ssl, &cert.leaf) {
            tracing::error!("failed to set certificate for {host_name}: {err}");
            return;
        }

        if let Some(chain) = &cert.chain
            && let Err(err) = ext::ssl_add_chain_cert(ssl, chain)
        {
            tracing::error!("failed to set chain certificate for {host_name}: {err}");
        }
    }
}

/// Creates and stores a self-signed certificate for `host_name` when
/// its route opted in via `ssl_certificate.self_signed_on_failure`.
/// Returns the stored certificate, or None when the route did not opt
/// in or generation failed (the handshake then fails as before).
fn self_signed_fallback(host_name: &str) -> Option<stores::certificates::Certificate> {
    let route = stores::get_route_by_key(host_name)?;
    if !route.self_signed_certificate {
        return None;
    }
    match stores::certificates::self_signed(host_name) {
        Ok(cert) => {
            tracing::info!("created self-signed certificate for {host_name} (route opted in)");
            stores::insert_certificate(host_name.to_string(), cert.clone());
            Some(cert)
        }
        Err(err) => {
            tracing::error!("failed to create self-signed certificate for {host_name}: {err}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::self_signed_fallback;
    use crate::stores;

    fn insert_route(host: &str, self_signed: bool) {
        let container = stores::routes::RouteStoreContainer {
            self_signed_certificate: self_signed,
            ..Default::default()
        };
        stores::insert_route(host.to_string(), container);
    }

    #[test]
    fn fallback_without_route_is_none() {
        assert!(self_signed_fallback("no-route.unit-test.invalid").is_none());
    }

    #[test]
    fn fallback_without_opt_in_is_none() {
        insert_route("opted-out.unit-test.invalid", false);
        assert!(self_signed_fallback("opted-out.unit-test.invalid").is_none());
        assert!(stores::get_certificate_by_key("opted-out.unit-test.invalid").is_none());
    }

    #[test]
    fn fallback_with_opt_in_creates_and_stores() {
        insert_route("opted-in.unit-test.invalid", true);
        let cert = self_signed_fallback("opted-in.unit-test.invalid")
            .expect("opted-in route gets a self-signed certificate");
        let stored = stores::get_certificate_by_key("opted-in.unit-test.invalid")
            .expect("certificate is stored for later handshakes");
        let cn = |c: &stores::certificates::Certificate| {
            c.leaf
                .subject_name()
                .entries()
                .next()
                .expect("a CN entry")
                .data()
                .as_utf8()
                .expect("CN is UTF-8")
                .to_string()
        };
        assert_eq!(cn(&cert), "opted-in.unit-test.invalid");
        assert_eq!(cn(&stored), "opted-in.unit-test.invalid");
    }
}
