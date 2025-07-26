// /qompassai/vongola/crates/vongola/src/main.rs
use std::{borrow::Cow, sync::Arc};

use ::pingora::server::Server;
use pingora::services::Service;
use bytes::Bytes;
use clap::crate_version;
use config::{load, LogFormat, RouteHeaderAdd, RouteHeaderRemove, RoutePlugin};
use pingora::{listeners::tls::TlsSettings, proxy::http_proxy_service, server::configuration::Opt};
use proxy_server::cert_store::CertStore;
use services::{logger::ProxyLoggerReceiver, BackgroundFunctionService};
use tracing_subscriber::EnvFilter;

mod cache;
mod channel;
mod config;
mod plugins;
mod proxy_server;
mod server;
mod services;
mod stores;
mod tools;
mod wasm;

#[derive(Clone, Default)]
pub struct MsgRoute {
    host: Cow<'static, str>,
    upstreams: Vec<String>,
    path_matchers: Vec<String>,
    host_headers_add: Vec<RouteHeaderAdd>,
    host_headers_remove: Vec<RouteHeaderRemove>,
    plugins: Vec<RoutePlugin>,

    self_signed_certs: bool,
}

#[derive(Clone)]
pub struct MsgCert {
    _cert: Bytes,
    _key: Bytes,
}

#[derive(Clone)]
pub enum MsgProxy {
    NewRoute(MsgRoute),
    NewCertificate(MsgCert),
    ConfigUpdate(()),
}

#[deny(
    clippy::all,
    clippy::pedantic,
    clippy::perf,
    clippy::correctness,
    clippy::style,
    clippy::suspicious,
    clippy::complexity
)]
fn main() -> Result<(), anyhow::Error> {
    let proxy_config =
        Arc::new(load("/etc/vongola/configs").expect("Failed to load configuration: "));
    let (log_sender, log_receiver) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (sender, mut _receiver) = tokio::sync::broadcast::channel::<MsgProxy>(10);
    // let (appender, _guard) = get_non_blocking_writer(&proxy_config);
    let appender = services::logger::ProxyLog::new(
        log_sender,
        proxy_config.logging.enabled,
        proxy_config.logging.access_logs_enabled,
        proxy_config.logging.error_logs_enabled,
    );
    if proxy_config.logging.format == LogFormat::Json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(EnvFilter::from_default_env())
            .with_max_level(&proxy_config.logging.level)
            .with_writer(appender)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_max_level(&proxy_config.logging.level)
            .with_ansi(proxy_config.logging.path.is_none())
            .with_writer(appender)
            .init();
    };
    let pingora_opts = Opt {
        daemon: proxy_config.daemon,
        upgrade: proxy_config.upgrade,
        conf: None,
        nocapture: false,
        test: false,
    };
    let mut pingora_server = Server::new(Some(pingora_opts))?;
    pingora_server.bootstrap();
    let mut http_public_service = http_proxy_service(
        &pingora_server.configuration,
        proxy_server::http_proxy::HttpLB {},
    );
    let router = proxy_server::https_proxy::Router {};
    let mut https_secure_service = http_proxy_service(&pingora_server.configuration, router);
    http_public_service.add_tcp("0.0.0.0:8080");
    https_secure_service.threads = proxy_config.worker_threads;
    let cert_store = CertStore::new();
    let mut tls_settings = TlsSettings::with_callbacks(Box::new(cert_store)).unwrap();
    tls_settings.enable_h2();
    tls_settings.set_session_cache_mode(SslSessionCacheMode::SERVER);
    tls_settings.set_servername_callback(move |ssl_ref, _| CertStore::sni_callback(ssl_ref));
    https_secure_service.add_tls_with_settings("0.0.0.0:4433", None, tls_settings);
     let mut prometheus_service_http = Service::prometheus_http_service();
     prometheus_service_http.add_tcp("0.0.0.0:9090");
     pingora_server.add_service(prometheus_service_http);
    pingora_server.add_service(BackgroundFunctionService::new(proxy_config.clone(), sender));
    pingora_server.add_service(ProxyLoggerReceiver::new(log_receiver, proxy_config.clone()));
    pingora_server.add_service(http_public_service);
    pingora_server.add_service(https_secure_service);
    tracing::info!(
        version = crate_version!(),
        workers = proxy_config.worker_threads,
        "running on :4433 and :8080"
    );
    pingora_server.run_forever();
}
