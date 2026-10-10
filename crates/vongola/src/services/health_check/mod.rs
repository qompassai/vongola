// #################################################################
// /qompassai/vongola/crates/vongola/src/services/health_check/mod.rs
// Qompass AI Health Check mod
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

use std::time::Duration;

use async_trait::async_trait;
use pingora::{
    server::{ListenFds, ShutdownWatch},
    services::Service,
};

use crate::stores::{self};

/// Health check service that will run health checks on all upstreams
/// And update the route store with the new healthy upstreams.
/// This service will run in a separate thread.
pub struct HealthService {}

impl HealthService {
    pub fn new() -> Self { Self {} }
}

async fn run_health_check_loop() {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.tick().await;

    loop {
        interval.tick().await;

        for (host, route_container) in &stores::get_routes() {
            tracing::trace!("Running health check for host {}", host);

            // clone the route_container
            let route_container = route_container.clone();
            route_container.load_balancer.update().await.ok();
            route_container
                .load_balancer
                .backends()
                .run_health_check(false)
                .await;

            // insert it back into the store
            stores::insert_route(host.clone(), route_container);
        }
    }
}

#[async_trait]
impl Service for HealthService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, _shutdown: ShutdownWatch) {
        tracing::info!("Starting health check service");

        run_health_check_loop().await;
    }

    fn name(&self) -> &str { "health_check_service" }

    fn threads(&self) -> Option<usize> { Some(1) }
}
