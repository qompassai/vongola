// #################################################################
// /qompassai/vongola/crates/vongola/src/plugins/mod.rs
// Qompass AI Plugins mod
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

use std::{borrow::Cow, collections::HashMap};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use basic_auth::BasicAuth;
use oauth2::Oauth2;
use once_cell::sync::Lazy;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::Session;
use request_id::RequestId;

use crate::{config::RoutePlugin, proxy_server::https_proxy::RouterContext};
pub mod basic_auth;
pub mod jwt;
pub mod oauth2;
pub mod request_id;
pub(crate) struct ProxyPlugins {
    pub basic_auth: Lazy<BasicAuth>,
    pub oauth2: Lazy<Oauth2>,
    pub request_id: Lazy<RequestId>,
}
/// Static plugin registry (plugins that don't generate a new instance for each
/// request)
pub static PLUGINS: Lazy<ProxyPlugins> = Lazy::new(|| ProxyPlugins {
    basic_auth: Lazy::new(BasicAuth::new),
    oauth2: Lazy::new(Oauth2::new),
    request_id: Lazy::new(RequestId::new),
});
/// Get a required configuration value from a plugin config
fn get_required_config(
    plugin_config: &HashMap<Cow<'static, str>, serde_json::Value>,
    key: &str,
) -> Result<String> {
    plugin_config
        .get(key)
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("Missing or invalid {}", key))
}
#[async_trait]
pub trait MiddlewarePlugin {
    /// Create a new state for the middleware
    /// Filter requests based on the middleware's logic
    /// Return false if the request should be allowed to pass through and was
    /// not handled Return true if the request was already handled
    async fn request_filter(
        &self,
        session: &mut Session,
        state: &mut RouterContext,
        config: &RoutePlugin,
    ) -> Result<bool>;
    /// Modify the request before it is sent to the upstream
    ///
    /// Unlike [Self::request_filter()], this filter allows to
    /// change the request headers before it hits your server.
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        state: &mut RouterContext,
    ) -> Result<()>;
    /// Filter responses (from upstream) based on the middleware's logic
    /// Return false if the request should be allowed to pass through and was
    /// not handled Return true if the request was already handled
    async fn response_filter(
        &self,
        session: &mut Session,
        state: &mut RouterContext,
        config: &RoutePlugin,
    ) -> Result<bool>;
    fn upstream_response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        state: &mut RouterContext,
    ) -> Result<()>;
}
