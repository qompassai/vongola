// /qompassai/vongola/crates/vongola/src/services/docker/mod.rs
use std::{
    borrow::Cow, collections::HashMap, hash::Hash, net::SocketAddr, str::FromStr, sync::Arc,
    time::Duration,
};
use anyhow::anyhow;
use async_trait::async_trait;
use bollard::{
    query_parameters::{ListContainersOptions, ListContainersOptionsBuilder, ListServicesOptions, ListServicesOptionsBuilder},
    Docker, API_DEFAULT_VERSION,
};
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};
use serde_json::json;
use tokio::sync::broadcast::Sender;
use tracing::{debug, info};
use crate::{
    config::{Config, DockerServiceMode, RouteHeaderAdd, RouteHeaderRemove, RoutePlugin},
    MsgProxy, MsgRoute,
};
/// Based on the provided endpoint, returns the correct Docker client
fn connect_to_docker(endpoint: &str) -> Result<Docker, bollard::errors::Error> {
    if endpoint.starts_with("unix:///") {
        return Docker::connect_with_unix(endpoint, 120, API_DEFAULT_VERSION);
    }
    if endpoint.starts_with("tcp://") || endpoint.starts_with("http") {
        return Docker::connect_with_http(endpoint, 120, API_DEFAULT_VERSION);
    }
    Docker::connect_with_local_defaults()
}
#[derive(Debug, Default)]
pub struct VongolaDockerRoute {
    upstreams: Vec<String>,
    path_matchers: Vec<String>,
    host_header_add: Option<Vec<RouteHeaderAdd>>,
    host_header_remove: Option<Vec<RouteHeaderRemove>>,
    ssl_certificate_self_signed_on_failure: bool,
    plugins: Option<Vec<RoutePlugin>>,
}
impl VongolaDockerRoute {
    pub fn new(upstreams: Vec<String>, path_matchers: Vec<String>) -> Self {
        Self {
            upstreams,
            path_matchers,
            host_header_add: None,
            host_header_remove: None,
            ssl_certificate_self_signed_on_failure: false,
            plugins: None,
        }
    }
}
/// A service that will list all services in a Swarm OR containers through the
/// Docker API and update the route store with the new services.
/// This service will run in a separate thread.
pub struct LabelService {
    config: Arc<Config>,
    inner: Docker,
    sender: Sender<MsgProxy>,
}
impl LabelService {
    pub fn new(config: Arc<Config>, sender: Sender<MsgProxy>) -> Self {
        let endpoint = config.docker.endpoint.as_ref().map(|c| c.clone()).unwrap_or_default();
        let docker = connect_to_docker(&endpoint);
        Self {
            config,
            sender,
            inner: docker
                .map_err(|e| anyhow!("could not connect to the docker daemon: {e}"))
                .unwrap(),
        }
    }
    /// Generate a list of services based on the provided filters
    /// This will returns a mapping between host <> ips for each service
    /// Only works for docker in Swarm mode.
    #[allow(clippy::too_many_lines)]
    async fn list_services<T>(
        &self,
        filters: HashMap<T, Vec<T>>,
    ) -> HashMap<String, VongolaDockerRoute>
    where
        T: Into<String> + Hash + serde::ser::Serialize + Eq,
    {
        let mut host_map = HashMap::<String, VongolaDockerRoute>::new();
        let services = self
            .inner
            .list_services(Some(ListServicesOptions {
                filters,
                status: true,
            }))
            .await;
        if services.is_err() {
            info!("Could not list services {:?}", services.err().unwrap());
            return host_map;
        }
        let services = services.unwrap();
        for service in services {
            let service_id = service.id.unwrap();
            let service_spec = service.spec.clone().unwrap();
            let service_name = service_spec.name.as_ref();
            if service_name.is_none() {
                info!("Service {service_id:?} does not have a name");
                continue;
            }
            let service_name = service_name.unwrap();
            let service_labels = service_spec.labels.as_ref().unwrap();
            let mut proxy_enabled = false;
            let mut proxy_host = "";
            let mut proxy_port = "";
            let mut match_with_path_patterns = vec![];
            let mut route_header_add: Option<Vec<RouteHeaderAdd>> = None;
            let mut route_header_remove: Option<Vec<RouteHeaderRemove>> = None;
            // TEMP: Oauth2 plugin
            let mut oauth2_provider: Option<String> = None;
            let mut oauth2_client_id: Option<String> = None;
            let mut oauth2_client_secret: Option<String> = None;
            let mut oauth2_jwt_secret: Option<String> = None;
            let mut oauth2_validations: Option<serde_json::Value> = None;
            let mut ssl_certificate_self_signed_on_failure = false;
            let mut docker_request_id = false;
            let mut basic_auth_user = None;
            let mut basic_auth_password = None;
            // Map through extra labels
            for (k, v) in service_labels {
                if k.starts_with("vongola.") {
                    // direct values
                    // TODO refactor to be reused for both services and containers
                    match k.as_str() {
                        "vongola.enabled" => proxy_enabled = v == "true",
                        "vongola.host" => proxy_host = v,
                        "vongola.port" => proxy_port = v,
                        k if k.starts_with("vongola.match_with.path.pattern.") => {
                            match_with_path_patterns.push(v.clone());
                        }
                        "vongola.headers.add" => {
                            let deser: Vec<RouteHeaderAdd> =
                                serde_json::from_str(v).unwrap_or(vec![]);

                            route_header_add = Some(deser);
                        }
                        "vongola.headers.remove" => {
                            let deser: Vec<RouteHeaderRemove> =
                                serde_json::from_str(v).unwrap_or(vec![]);

                            route_header_remove = Some(deser);
                        }
                        "vongola.ssl_certificate.self_signed_on_failure" => {
                            ssl_certificate_self_signed_on_failure = v == "true";
                        }
                        "vongola.plugins.oauth2.provider" => oauth2_provider = Some(v.clone()),
                        "vongola.plugins.oauth2.client_id" => oauth2_client_id = Some(v.clone()),
                        "vongola.plugins.oauth2.client_secret" => {
                            oauth2_client_secret = Some(v.clone());
                        }
                        "vongola.plugins.oauth2.jwt_secret" => oauth2_jwt_secret = Some(v.clone()),
                        "vongola.plugins.oauth2.validations" => {
                            oauth2_validations =
                                Some(serde_json::from_str(v).unwrap_or_else(|_| json!([])));
                        }
                        "vongola.plugins.request_id.enabled" => {
                            docker_request_id = v == "true";
                        }
                        "vongola.plugins.basic_auth.user" => basic_auth_user = Some(v.clone()),
                        "vongola.plugins.basic_auth.password" => {
                            basic_auth_password = Some(v.clone());
                        }

                        _ => {}
                    }
                }
            }
            if !proxy_enabled {
                info!(
                    "Service {service_name:?} does not have the label
                    vongola.enabled set to `true`"
                );
                continue;
            }
            if proxy_host.is_empty() || proxy_port.is_empty() {
                info!(
                    "Service {service_name:?} does not have the label
                    vongola.host set to a valid host or vongola.port set to a valid port"
                );
                continue;
            }
            // TODO offer an option to load balance directly to the container IPs
            // of the service instead of through the docker dns
            if !host_map.contains_key(proxy_host) {
                let mut routed = VongolaDockerRoute::default();
                routed
                    .upstreams
                    .push(format!("tasks.{service_name}:{proxy_port}"));
                routed.path_matchers = match_with_path_patterns;
                routed.host_header_add = route_header_add;
                routed.host_header_remove = route_header_remove;
                routed.ssl_certificate_self_signed_on_failure =
                    ssl_certificate_self_signed_on_failure;

                // This part is optional
                let mut plugins: Vec<RoutePlugin> = vec![];
                if let Some(plugin) = Self::get_oauth2_plugin(
                    oauth2_provider,
                    oauth2_client_id,
                    oauth2_client_secret,
                    oauth2_jwt_secret,
                    oauth2_validations,
                ) {
                    plugins.push(plugin);
                }

                if docker_request_id {
                    plugins.push(RoutePlugin {
                        name: Cow::Borrowed("request_id"),
                        config: None,
                    });
                }

                if basic_auth_user.is_some() && basic_auth_password.is_some() {
                    let mut map = HashMap::new();
                    map.insert(Cow::Borrowed("user"), json!(basic_auth_user.unwrap()));
                    map.insert(Cow::Borrowed("pass"), json!(basic_auth_password.unwrap()));

                    plugins.push(RoutePlugin {
                        name: Cow::Borrowed("basic_auth"),
                        config: Some(map),
                    });
                }

                routed.plugins = Some(plugins);
                host_map.insert(proxy_host.to_string(), routed);
            }
        }

        host_map
    }
    /// Generate a list of containers based on the provided filters
    /// This will return a mapping between host <> ips for each container
    /// Does not work for docker in Swarm mode
    async fn list_containers<T>(
        &self,
        filters: HashMap<T, Vec<T>>,
    ) -> HashMap<String, VongolaDockerRoute>
    where
        T: Into<String> + Hash + serde::ser::Serialize + Eq,
    {
        let mut host_map = HashMap::<String, VongolaDockerRoute>::new();
        let containers = self
            .inner
            .list_containers(Some(ListContainersOptions {
                all: false,
                limit: Some(1000),
                filters,
                size: false,
            }))
            .await;

        if containers.is_err() {
            info!("Could not list containers {:?}", containers.err().unwrap());
            return host_map;
        }
        let containers = containers.unwrap();
        for container in containers {
            let container_names = &container.names;
            let container_labels = container.labels.as_ref().unwrap();
            let mut proxy_enabled = false;
            let mut proxy_host = "";
            let mut proxy_port = "";
            let mut match_with_path_patterns = vec![];
            let mut route_header_add: Option<Vec<RouteHeaderAdd>> = None;
            let mut route_header_remove: Option<Vec<RouteHeaderRemove>> = None;
            let mut ssl_certificate_self_signed_on_failure = false;
            // Map through extra labels
            for (k, v) in container_labels {
                if k.starts_with("vongola.") {
                    // direct values
                    match k.as_str() {
                        "vongola.enabled" => proxy_enabled = v == "true",
                        "vongola.host" => proxy_host = v,
                        "vongola.port" => proxy_port = v,
                        "vongola.headers.add" => {
                            let deser: Vec<RouteHeaderAdd> =
                                serde_json::from_str(v).unwrap_or(vec![]);
                            route_header_add = Some(deser);
                        }
                        "vongola.headers.remove" => {
                            let deser: Vec<RouteHeaderRemove> =
                                serde_json::from_str(v).unwrap_or(vec![]);

                            route_header_remove = Some(deser);
                        }
                        "vongola.ssl_certificate.self_signed_on_failure" => {
                            ssl_certificate_self_signed_on_failure = v == "true";
                        }
                        k if k.starts_with("vongola.match_with.path.pattern.") => {
                            match_with_path_patterns.push(v.clone());
                        }
                        _ => {}
                    }
                }
            }
            if !proxy_enabled {
                info!(
                    "Container {container_names:?} does not have the label
                    vongola.enabled set to `true`"
                );
                continue;
            }
            if proxy_port.is_empty() || proxy_host.is_empty() {
                info!(
                    "Container {container_names:?} does not have a
                  `vongola.port` label or a `vongola.host` label"
                );
                continue;
            }
            if !host_map.contains_key(proxy_host) {
                let mut routed = VongolaDockerRoute::new(vec![], match_with_path_patterns);
                routed.host_header_add = route_header_add;
                routed.host_header_remove = route_header_remove;
                routed.ssl_certificate_self_signed_on_failure =
                    ssl_certificate_self_signed_on_failure;
                host_map.insert(proxy_host.to_string(), routed);
            }
            let network_settings = &container.network_settings.as_ref().unwrap();
            let networks = network_settings.networks.as_ref().unwrap();
            for network in networks.values() {
                let ip_on_network = network.ip_address.as_ref().unwrap();
                let ip_plus_port = format!("{ip_on_network}:{proxy_port}");
                let socket_addr = SocketAddr::from_str(&ip_plus_port);
                if ip_on_network.is_empty() || socket_addr.is_err() {
                    debug!("Could not parse the ip address {ip_plus_port} of the container {container_names:?}");
                    continue;
                }
                host_map
                    .get_mut(proxy_host)
                    .unwrap()
                    .upstreams
                    .push(ip_plus_port);
            }
        }
        host_map
    }
    fn get_oauth2_plugin(
        provider: Option<String>,
        client_id: Option<String>,
        client_secret: Option<String>,
        jwt_secret: Option<String>,
        validations: Option<serde_json::Value>,
    ) -> Option<RoutePlugin> {
        if provider.is_none()
            || client_id.is_none()
            || client_secret.is_none()
            || jwt_secret.is_none()
            || validations.is_none()
        {
            return None;
        }
        let mut plugin_hashmap = HashMap::new();
        plugin_hashmap.insert(Cow::Borrowed("client_id"), json!(client_id.unwrap()));
        plugin_hashmap.insert(Cow::Borrowed("provider"), json!(provider.unwrap()));
        plugin_hashmap.insert(
            Cow::Borrowed("client_secret"),
            json!(client_secret.unwrap()),
        );
        plugin_hashmap.insert(Cow::Borrowed("jwt_secret"), json!(jwt_secret.unwrap()));
        plugin_hashmap.insert(Cow::Borrowed("validations"), json!(validations.unwrap()));
        Some(RoutePlugin {
            name: Cow::Borrowed("oauth2"),
            config: Some(plugin_hashmap),
        })
    }
    /// Sends a message to the route discovery service through mspc
    fn send_route_message(&self, hosts: HashMap<String, VongolaDockerRoute>) {
        for (host, value) in hosts {
            // If no upstreams can be found, skip adding the route
            if value.upstreams.is_empty() {
                continue;
            }
            let host_value: Cow<'static, str> = Cow::Owned(host);
            self.sender
                .send(MsgProxy::NewRoute(MsgRoute {
                    host: host_value,
                    upstreams: value.upstreams,
                    path_matchers: value.path_matchers,
                    host_headers_add: value.host_header_add.unwrap_or_else(Vec::new),
                    host_headers_remove: value.host_header_remove.unwrap_or_else(Vec::new),
                    plugins: value.plugins.unwrap_or_else(Vec::new),

                    self_signed_certs: value.ssl_certificate_self_signed_on_failure,
                }))
                .ok();
        }
    }
    async fn get_routes_from_docker(&self) -> HashMap<String, VongolaDockerRoute> {
        let mut filters = HashMap::new();
        filters.insert(
            "label",
            vec!["vongla.enabled=true", "vongola.host", "vongola.port"],
        );

        match self.config.docker.mode {
            DockerServiceMode::Swarm => self.list_services(filters).await,
            DockerServiceMode::Container => self.list_containers(filters).await,
        }
    }
}
#[async_trait]
impl Service for LabelService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, mut _shutdown: ShutdownWatch) {
        if self.config.docker.enabled.is_some_and(|v| !v) {
            // Nothing to do, docker is disabled
            return;
        }
        info!(service = "docker", "Started Docker service");
        let mut interval = tokio::time::interval(Duration::from_secs(
            self.config.docker.interval_secs.unwrap_or(15),
        ));
        interval.tick().await;
        loop {
            interval.tick().await;
            self.send_route_message(self.get_routes_from_docker().await);
        }
    }
    fn name(&self) -> &'static str { "docker_service" }
    fn threads(&self) -> Option<usize> { Some(1) }
}
