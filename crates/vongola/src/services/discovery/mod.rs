// /qompassai/vongola/crates/vongola/src/services/discovery/mod.rs
// Qompass AI Vongola Service Discovery Module
// # Copyright (C) 2025 Qompass AI, All rights reserved
/////////////////////////////////////////////////////////////////
use std::net::ToSocketAddrs;
use std::{borrow::Cow, str::FromStr, sync::Arc, time::Duration};

use async_trait::async_trait;
use http::{HeaderName, HeaderValue};
use openssl::pkey::PKey;
use openssl::x509::X509;
use pingora::lb::{health_check::TcpHealthCheck, selection::RoundRobin, LoadBalancer};
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use tokio::sync::broadcast::Sender;

use crate::config::{Route, RouteCache, RouteUpstream};
use crate::MsgRoute;
use crate::{
    config::{Config, RouteHeader, RouteMatcher, RoutePathMatcher, RoutePlugin},
    stores::{self, routes::RouteStoreContainer},
    MsgProxy,
};
pub struct RoutingService {
    config: Arc<Config>,
    broadcast: Sender<MsgProxy>,
}
impl RoutingService {
    pub fn new(config: Arc<Config>, broadcast: Sender<MsgProxy>) -> Self {
        Self { config, broadcast }
    }

    /// From a given configuration file, create the static load balancing
    /// configuration
    fn add_routes_from_config(&mut self) {
        for route in &self.config.routes {
            let self_signed_cert_on_failure = route
                .ssl_certificate
                .as_ref()
                .and_then(|v| v.self_signed_on_failure);

            if let Err(err) = add_route_ssl_to_store(route) {
                tracing::error!(
                    "failed to add SSL certificate to store for host {:?}: {err}",
                    route.host
                );
            }
            add_route_to_router(
                &route.host,
                route.upstreams.clone(),
                route.match_with.clone(),
                route.headers.as_ref(),
                route.plugins.as_ref(),
                route.cache.as_ref(),
                self_signed_cert_on_failure.unwrap_or(false),
            );

            tracing::debug!("Added route: {}, {:?}", route.host, route.upstreams);
        }
    }

    /// Watch for new routes being added and update the Router Store
    fn watch_for_route_changes(route: MsgRoute) {
        // TODO: refactor
        let mut matcher: Option<RouteMatcher> = None;
        let route_clone = route.path_matchers.clone();
        if !route.path_matchers.is_empty() {
            matcher = Some(RouteMatcher {
                path: Some(RoutePathMatcher {
                    patterns: route_clone.iter().map(|v| Cow::Owned(v.clone())).collect(),
                }),
            });
        }
        let route_header = RouteHeader {
            add: Some(route.host_headers_add),
            remove: Some(route.host_headers_remove),
        };
        let upstreams = route
            .upstreams
            .iter()
            .flat_map(|u| {
                if let Ok(scr) = u.to_socket_addrs() {
                    scr.map(|f| RouteUpstream {
                        ip: Cow::Owned(f.ip().to_string()),
                        port: f.port(),
                        network: None,
                        weight: Some(1),
                        headers: None,
                        sni: None,
                    })
                    .collect::<Vec<_>>()
                } else {
                    vec![]
                }
            })
            .collect::<Vec<_>>();
        add_route_to_router(
            &route.host,
            upstreams,
            matcher,
            Some(&route_header),
            Some(&route.plugins),
            None,
            route.self_signed_certs,
        );
        tracing::debug!(
            "Added route: {}, {:?} self-signed: {}",
            route.host,
            route.upstreams,
            route.self_signed_certs
        );
    }
}
#[async_trait]
impl Service for RoutingService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, _shutdown: ShutdownWatch) {
        self.add_routes_from_config();
        let mut receiver = self.broadcast.subscribe();
        while let Ok(MsgProxy::NewRoute(route)) = receiver.recv().await {
            Self::watch_for_route_changes(route);
        }
    }

    fn name(&self) -> &str { "proxy_service_discovery" }

    fn threads(&self) -> Option<usize> { Some(1) }
}
fn has_new_backend(host: &str, upstream_input: &LoadBalancer<RoundRobin>) -> bool {
    if let Some(route_container) = stores::get_route_by_key(host) {
        let backends = route_container.load_balancer.backends().get_backend();
        let new_backends = upstream_input.backends().get_backend();
        // If upstreams are not the same length, return true (update)
        if backends.len() != new_backends.len() {
            return true;
        }
        !backends.iter().all(|be| new_backends.contains(be))
    } else {
        false
    }
}
/// Adds new routes to the store if there are changes to an existing route or
/// if the host does not exist in the store.
fn add_route_to_router(
    host: &str,
    upstream_input: Vec<RouteUpstream>,
    match_with: Option<RouteMatcher>,
    headers: Option<&RouteHeader>,
    plugins: Option<&Vec<RoutePlugin>>,
    cache: Option<&RouteCache>,
    should_self_sign_cert_on_failure: bool,
) {
    let upstream_str = upstream_input
        .iter()
        .map(|u| format!("{}:{}", u.ip, u.port))
        .collect::<Vec<String>>();
    let Ok(mut upstreams) = LoadBalancer::<RoundRobin>::try_from_iter(upstream_str) else {
        tracing::info!(
            "Could not create upstreams for host: {}, upstreams {:?}",
            host,
            upstream_input
        );
        return;
    };
    if stores::get_route_by_key(host).is_some() && !has_new_backend(host, &upstreams) {
        tracing::debug!("skipping update, no routing changes for host: {}", host);
        return;
    }
    let tcp_health_check = TcpHealthCheck::new();
    upstreams.set_health_check(tcp_health_check);
    upstreams.health_check_frequency = Some(Duration::from_secs(15));
    let mut route_store_container = RouteStoreContainer::new(upstreams);
    route_store_container.self_signed_certificate = should_self_sign_cert_on_failure;
    route_store_container.upstreams = upstream_input;
    route_store_container.cache = cache.cloned();
    if let Some(headers) = headers {
        if let Some(headers) = headers.add.as_ref() {
            route_store_container.host_header_add = headers
                .iter()
                .map(|v| {
                    (
                        HeaderName::from_str(&v.name).unwrap(),
                        HeaderValue::from_str(&v.value).unwrap(),
                    )
                })
                .collect();
        }
        if let Some(to_remove) = headers.remove.as_ref() {
            route_store_container.host_header_remove =
                to_remove.iter().map(|v| v.name.to_string()).collect();
        }
    }
    if let Some(plugins) = plugins {
        for plugin in plugins {
            match plugin.name.as_ref() {
                "oauth2" | "request_id" | "basic_auth" => {
                    route_store_container
                        .plugins
                        .insert(plugin.name.to_string(), plugin.clone());
                }
                _ => {}
            }
        }
    }
    if let Some(match_with) = match_with {
        // Path matchers
        match match_with.path {
            Some(path_matcher) if !path_matcher.patterns.is_empty() => {
                let pattern = path_matcher.patterns;
                route_store_container.path_matcher.with_pattern(&pattern);
            }
            _ => {}
        }
    }
    stores::insert_route(host.to_string(), route_store_container);
}
fn add_route_ssl_to_store(route: &Route) -> Result<(), anyhow::Error> {
    let Some(ssl_path) = route.ssl.as_ref().and_then(|v| v.path.as_ref()) else {
        return Ok(());
    };
    let key_from_file = std::fs::read_to_string(ssl_path.key.as_os_str()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to load private key from file {:?}: {err}",
            ssl_path.key
        )
    })?;
    let pem_from_file = std::fs::read_to_string(ssl_path.pem.as_os_str()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to load certificate from file {:?}: {err}",
            ssl_path.pem
        )
    })?;
    let key = PKey::private_key_from_pem(key_from_file.as_bytes()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to load private key from file {:?}: {err}",
            ssl_path.key
        )
    })?;
    let pem = X509::from_pem(pem_from_file.as_bytes()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to load certificate from file {:?}: {err}",
            ssl_path.pem
        )
    })?;
    stores::insert_certificate(
        route.host.to_string(),
        stores::certificates::Certificate {
            key,
            leaf: pem,
            chain: None,
        },
    );
    Ok(())
}
#[cfg(test)]
mod test {
    use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
    /// Try to resolve the input to a SocketAddr, preferring IPv6 over IPv4.
    /// Prints all resolutions for debugging.
    fn pick_addr<A: ToSocketAddrs>(input: A) -> Option<SocketAddr> {
        let addrs: Vec<_> = match input.to_socket_addrs() {
            Ok(iter) => iter.collect(),
            Err(e) => {
                eprintln!("Error resolving address: {e:?}");
                return None;
            }
        };
        println!("Resolved addresses: {:?}", addrs);
        if let Some(addr) = addrs.iter().find(|a| matches!(a.ip(), IpAddr::V6(_))) {
            println!("Picked IPv6: {:?}", addr);
            Some(*addr)
        } else if let Some(addr) = addrs.iter().find(|a| matches!(a.ip(), IpAddr::V4(_))) {
            println!("Picked IPv4: {:?}", addr);
            Some(*addr)
        } else {
            eprintln!("No IPv4 or IPv6 addresses found!");
            None
        }
    }
    #[test]
    fn test_socket_addr() {
        let addr = "[::1]:8080".parse::<SocketAddr>().unwrap();
        println!("Parsed IPv6 literal: {:?}", addr);
        assert_eq!(
            addr.ip(),
            "::1".parse::<IpAddr>().unwrap(),
            "IPv6 address mismatch"
        );
        assert_eq!(addr.port(), 8080, "IPv6 port mismatch");
        let addr = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
        println!("Parsed IPv4 literal: {:?}", addr);
        assert_eq!(
            addr.ip(),
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            "IPv4 address mismatch"
        );
        assert_eq!(addr.port(), 8080, "IPv4 port mismatch");
    }
    #[test]
    fn test_domain_addr() {
        let domain = "example.com:8080";
        println!("Testing pick_addr with domain `{}`", domain);
        let addr = pick_addr(domain).expect("No address found for example.com");
        println!("pick_addr result: {:?}", addr);
        assert_eq!(addr.port(), 8080, "Expected port 8080 for resolved address");
        match addr.ip() {
            IpAddr::V6(ip6) => println!("Resolved IPv6: {}", ip6),
            IpAddr::V4(ip4) => println!("Resolved IPv4: {}", ip4),
        }
        assert!(
            addr.is_ipv6() || addr.is_ipv4(),
            "Address is neither IPv4 nor IPv6: {:?}",
            addr
        );
    }
}

// #[cfg(test)]
// mod tests {
//     use std::collections::HashMap;

//     use super::*;
//     use crate::stores::routes::RouteStore;

//     fn setup_mock_route_store() -> RouteStore {
//         Arc::new(HashMap::new())
//     }

//     fn setup_route_store_with_entry() -> RouteStore {
//         let store = setup_mock_route_store();
//         let upstreams = vec!["127.0.0.1:8080".to_string(),
// "127.0.0.2:8080".to_string()];

//         let load_balancer =
//
// LoadBalancer::<RoundRobin>::try_from_iter(upstreams.into_iter()).unwrap();
//         store.insert(
//             "example.com".to_string(),
//             RouteStoreContainer::new(load_balancer),
//         );

//         store
//     }

//     #[test]
//     fn test_add_route_to_router_new_route() {
//         let store = setup_mock_route_store();
//         let host = "example.com";
//         let upstreams = vec!["127.0.0.1:8080".to_string()];
//         let matcher = None;
//         let headers = None;
//         let plugins = None;
//         let should_self_sign_cert_on_failure = false;

//         add_route_to_router(
//             &store,
//             host,
//             &upstreams,
//             matcher,
//             headers,
//             plugins,
//             should_self_sign_cert_on_failure,
//         );

//         assert!(store.contains_key(host));
//     }

//     #[test]
//     fn test_add_route_to_router_existing_route_no_changes() {
//         let store = setup_route_store_with_entry();
//         let host = "example.com";
//         let upstreams = vec!["127.0.0.1:8080".to_string()];
//         let matcher = None;
//         let headers = None;
//         let plugins = None;
//         let should_self_sign_cert_on_failure = false;

//         add_route_to_router(
//             &store,
//             host,
//             &upstreams,
//             matcher,
//             headers,
//             plugins,
//             should_self_sign_cert_on_failure,
//         );

//         // Verify the route still exists and no new upstreams were added
//         assert!(store.contains_key(host));
//     }

//     #[test]
//     fn test_has_new_backend_no_change() {
//         let store = setup_route_store_with_entry();
//         let host = "example.com";
//         let upstreams = LoadBalancer::try_from_iter(vec![
//             "127.0.0.1:8080".to_string(),
//             "127.0.0.2:8080".to_string(),
//         ])
//         .unwrap();

//         assert!(!has_new_backend(&store, host, &upstreams));
//     }

//     #[test]
//     fn test_has_new_backend_with_change() {
//         let store = setup_route_store_with_entry();
//         let host = "example.com";
//         let upstreams =
// LoadBalancer::try_from_iter(vec!["127.0.0.3:8080".to_string()]).unwrap();

//         assert!(has_new_backend(&store, host, &upstreams));
//     }

//     #[test]
//     fn test_add_route_to_router_existing_route_with_changes() {
//         let store = setup_route_store_with_entry();
//         let host = "example.com";
//         let upstreams = vec!["127.0.0.3:8080".to_string()];
//         let matcher = None;
//         let headers = None;
//         let plugins = None;
//         let should_self_sign_cert_on_failure = false;

//         add_route_to_router(
//             &store,
//             host,
//             &upstreams,
//             matcher,
//             headers,
//             plugins,
//             should_self_sign_cert_on_failure,
//         );

//         // Verify that the route exists and the upstreams have been updated
//         assert!(store.contains_key(host));
//         let route_container = store.get(host).unwrap();
//         let backends: Vec<String> = route_container
//             .load_balancer
//             .backends()
//             .get_backend()
//             .iter()
//             .map(|backend| backend.addr.to_string())
//             .collect();
//         assert!(backends.contains(&"127.0.0.3:8080".to_string()));
//     }
// }
