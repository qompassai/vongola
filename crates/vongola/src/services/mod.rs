// #################################################################
// /qompassai/vongola/crates/vongola/src/services/mod.rs
// Qompass AI Services mod
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

use std::sync::Arc;

use async_trait::async_trait;
use config::FileWatcherService;
use discovery::RoutingService;
use docker::LabelService;
use letsencrypt::http01::LetsencryptService;
use pingora::server::{ListenFds, ShutdownWatch};
use tokio::sync::broadcast::Sender;

use crate::{MsgProxy, config::Config};

pub mod config;
pub mod discovery;
pub mod docker;
pub mod health_check;
pub mod letsencrypt;
pub mod logger;

/// Exploring: what if we grouped all the services into a single service using a
/// single thread?
pub struct BackgroundFunctionService {
    config: Arc<Config>,
    broadcast: Sender<MsgProxy>,
}

impl BackgroundFunctionService {
    pub fn new(config: Arc<Config>, broadcast: Sender<MsgProxy>) -> Self {
        Self { config, broadcast }
    }
}

#[async_trait]
impl pingora::services::Service for BackgroundFunctionService {
    async fn start_service(&mut self, _fds: Option<ListenFds>, shutdown: ShutdownWatch) {
        let mut routing_service = RoutingService::new(self.config.clone(), self.broadcast.clone());

        let mut health_service = health_check::HealthService::new();
        let mut docker_service = LabelService::new(self.config.clone(), self.broadcast.clone());
        let mut letsencrypt_service = LetsencryptService::new(self.config.clone());
        let mut config_server = FileWatcherService::new(self.config.clone());

        let _ = tokio::join!(
            routing_service.start_service(None, shutdown.clone()),
            health_service.start_service(None, shutdown.clone()),
            config_server.start_service(None, shutdown.clone()),
            docker_service.start_service(None, shutdown.clone()),
            letsencrypt_service.start_service(None, shutdown),
        );
    }

    fn name(&self) -> &str { "background_services" }

    fn threads(&self) -> Option<usize> { Some(1) }
}
