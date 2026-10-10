// #################################################################
// /qompassai/vongola/crates/vongola/src/services/letsencrypt/http01.rs
// Qompass AI Http01
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

use std::{
    fs::create_dir_all,
    path::{self, PathBuf},
    sync::Arc,
    time::Duration,
};

use acme_v2::{Account, DirectoryUrl, order::NewOrder, persist::FilePersist};
use anyhow::anyhow;
use async_trait::async_trait;
use openssl::{pkey::PKey, x509::X509};
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::time;
use tracing::info;

use crate::{
    config::Config,
    stores::{self, certificates::Certificate},
};
/// A service that handles the creation of certificates using the Let's Encrypt
/// API
pub struct LetsencryptService {
    pub(crate) config: Arc<Config>,
    // pub(crate) route_store: RouteStore,
    // pub(crate) cert_store: CertificateStore,
}
impl LetsencryptService {
    pub fn new(config: Arc<Config>) -> Self { Self { config } }

    /// Parse a PEM-encoded X509 certificate from a string slice
    fn parse_x509_cert(cert_pem: &str) -> Result<X509, anyhow::Error> {
        Ok(X509::from_pem(cert_pem.as_bytes())?)
    }

    /// Parse a PEM-encoded private key from a string slice
    fn parse_private_key(key_pem: &str) -> Result<PKey<openssl::pkey::Private>, anyhow::Error> {
        Ok(PKey::private_key_from_pem(key_pem.as_bytes())?)
    }

    /// Update global certificate store with new `X509` and `PKey` for the
    /// given domain also considering that the certificate could be a bundle
    /// file.
    fn insert_certificate(domain: &str, bundle: &str, key_pem: &str) -> Result<(), anyhow::Error> {
        let end = "-----END CERTIFICATE-----";
        // Split certificates (leaf and chain) from the bundle
        let split = bundle
            .split_inclusive(end)
            .map(str::trim)
            .collect::<Vec<&str>>();
        let leaf_pem = split.first();
        let chain_pem = split.get(1);
        let Some(leaf) = leaf_pem else {
            return Err(anyhow::anyhow!("Certificate is empty"));
        };
        let leaf = Self::parse_x509_cert(leaf)?;
        let mut chain: Option<X509> = None;

        if let Some(chain_pem) = chain_pem {
            tracing::trace!("chain PEM: {:?}", chain_pem);
            chain = Some(Self::parse_x509_cert(chain_pem)?);
        }
        let key = Self::parse_private_key(key_pem)?;
        stores::insert_certificate(domain.to_string(), Certificate { key, leaf, chain });
        Ok(())
    }

    /// Start an HTTP-01 challenge for a given order
    fn handle_http_01_challenge(order: &mut NewOrder<FilePersist>) -> Result<(), anyhow::Error> {
        for auth in order.authorizations()? {
            let challenge = auth.http_challenge();
            info!("HTTP-01 challenge for domain: {}", auth.domain_name());
            stores::insert_challenge(
                auth.domain_name().to_string(),
                (
                    challenge.http_token().to_string(),
                    challenge.http_proof().to_string(),
                ),
            );
            tracing::info!("HTTP-01 validating (retry: 5s)...");
            challenge.validate(5000)?;
        }
        Ok(())
    }

    /// Creates an in-memory self-signed certificate for a domain if let's
    /// encrypt cannot be used.
    /// Note this is only useful for local development or testing purposes
    /// and should be used sparingly
    fn create_self_signed_certificate(domain: &str, enabled: bool) -> Result<(), anyhow::Error> {
        if !enabled {
            return Ok(());
        }
        tracing::info!("creating an in-memory self-signed certificate for {domain}");
        let cert = stores::certificates::self_signed(domain)?;
        stores::insert_certificate(domain.to_string(), cert);
        Ok(())
    }

    fn get_lets_encrypt_url(&self) -> DirectoryUrl<'_> {
        match self.config.lets_encrypt.staging {
            Some(false) => DirectoryUrl::LetsEncrypt,
            _ => DirectoryUrl::LetsEncryptStaging,
        }
    }

    /// Return the appropriate Let's Encrypt directories for certificates based
    /// on the environment
    fn get_lets_encrypt_directory(&self) -> PathBuf {
        let suffix = match self.config.lets_encrypt.staging {
            Some(false) => "production",
            _ => "staging",
        };
        let path = self.config.paths.lets_encrypt.join(suffix);
        if let Ok(res) = path::absolute(&path) {
            return res;
        }
        path
    }

    /// Create a new order for a domain (HTTP-01 challenge)
    fn create_order_for_domain(
        domain: &str,
        account: &Account<FilePersist>,
    ) -> Result<(), anyhow::Error> {
        let mut order = account.new_order(domain, &[])?;
        let order_csr = loop {
            // Break if we are done confirming validations
            if let Some(csr) = order.confirm_validations() {
                break csr;
            }
            Self::handle_http_01_challenge(&mut order)
                .map_err(|err| anyhow!("Failed to handle HTTP-01 challenge: {err}"))?;
            order.refresh().unwrap_or_default();
        };
        let pkey = acme_v2::create_p384_key();
        let order_cert = order_csr.finalize_pkey(pkey, 5000)?;
        info!("certificate created for order {:?}", order_cert.api_order());
        let cert = order_cert.download_and_save_cert()?;
        Self::insert_certificate(domain, cert.certificate(), cert.private_key())?;
        Ok(())
    }

    /// Watch for route changes and create or update certificates for new routes
    async fn watch_for_route_changes(&self, account: &Account<FilePersist>) {
        let mut interval = time::interval(Duration::from_secs(20));
        loop {
            interval.tick().await;
            tracing::debug!("checking for new routes to create certificates for");
            for (key, value) in &stores::get_routes() {
                if stores::get_certificates().contains_key(key) {
                    continue;
                }
                Self::handle_certificate_for_domain(key, account, value.self_signed_certificate);
            }
        }
    }

    /// Check for certificates expiration and renew them if needed
    async fn check_for_certificates_expiration(&self, account: &Account<FilePersist>) {
        let mut interval = time::interval(Duration::from_secs(
            self.config
                .lets_encrypt
                .renew_interval_secs
                .unwrap_or(84_600),
        ));
        loop {
            tracing::debug!("checking for certificates to renew");
            for (domain, _) in &stores::get_routes() {
                let Ok(Some(cert)) = account.certificate(domain) else {
                    continue;
                };
                let valid_days_left = cert.valid_days_left();
                tracing::info!("certificate for domain {domain} expires in {valid_days_left} days",);
                if valid_days_left > 5 {
                    continue;
                }
                tracing::info!("trying to renew certificate for domain: {domain}");
                Self::create_order_for_domain(domain, account)
                    .map_err(|e| anyhow!("Failed to create order for {domain}: {e}"))
                    .unwrap();
            }
            interval.tick().await;
        }
    }

    fn handle_certificate_for_domain(
        domain: &str,
        account: &Account<FilePersist>,
        self_signed_on_failure: bool,
    ) {
        match account.certificate(domain) {
            Ok(Some(cert)) => {
                if stores::get_certificates().contains_key(domain) {
                    return;
                }
                if let Err(err) =
                    Self::insert_certificate(domain, cert.certificate(), cert.private_key())
                {
                    tracing::error!("failed to insert certificate for domain {domain}: {err}");
                };
            }
            Ok(None) if Self::create_order_for_domain(domain, account).is_err() => {
                Self::create_self_signed_certificate(domain, self_signed_on_failure).ok();
            }
            _ => {}
        }
    }
}
#[async_trait]
impl Service for LetsencryptService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut _shutdown: ShutdownWatch) {
        if self.config.lets_encrypt.enabled.is_some_and(|v| !v) {
            return;
        }
        info!("started LetsEncrypt service");
        let dir = self.get_lets_encrypt_directory();
        let certificates_dir = dir.as_os_str();
        tracing::info!(
            "creating certificates in folder {}",
            certificates_dir.to_string_lossy()
        );
        if create_dir_all(certificates_dir).is_err() {
            tracing::error!(
                "failed to create directory {certificates_dir:?}. Check permissions or make sure that the parent directory exists beforehand."
            );
            return;
        }
        let persist = acme_v2::persist::FilePersist::new(certificates_dir);
        let dir = acme_v2::Directory::from_url(persist, self.get_lets_encrypt_url())
            .expect("failed to create LetsEncrypt directory");
        let account = dir
            .account(&self.config.lets_encrypt.email)
            .expect("failed to create or retrieve existing account");
        let _ = tokio::join!(
            self.watch_for_route_changes(&account),
            self.check_for_certificates_expiration(&account)
        );
    }

    fn name(&self) -> &'static str { "lets_encrypt_service" }

    fn threads(&self) -> Option<usize> { Some(1) }
}
