// #################################################################
// /qompassai/vongola/crates/vongola/src/plugins/request_id/mod.rs
// Qompass AI Request Id mod
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

use std::borrow::Cow;

use anyhow::Result;
use async_trait::async_trait;
use pingora::proxy::Session;

use super::MiddlewarePlugin;
use crate::{config::RoutePlugin, proxy_server::https_proxy::RouterContext};

/// A plugin that adds a request ID to the request headers
/// and response headers
pub struct RequestId {}

impl RequestId {
    pub fn new() -> Self { Self {} }
}

#[async_trait]
impl MiddlewarePlugin for RequestId {
    async fn request_filter(
        &self,
        _: &mut Session,
        ctx: &mut RouterContext,
        _: &RoutePlugin,
    ) -> Result<bool> {
        let request_id = uuid::Uuid::new_v4().to_string();
        ctx.extensions
            .insert(Cow::Borrowed("request_id_header"), request_id);

        Ok(false)
    }

    async fn upstream_request_filter(
        &self,
        _: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut RouterContext,
    ) -> Result<()> {
        if let Some(request_id) = ctx.extensions.get("request_id_header") {
            upstream_request.insert_header("x-request-id", request_id)?;
        }
        Ok(())
    }

    fn upstream_response_filter(
        &self,
        _: &mut Session,
        upstream_response: &mut pingora::http::ResponseHeader,
        ctx: &mut RouterContext,
    ) -> Result<()> {
        if let Some(request_id) = ctx.extensions.get("request_id_header") {
            upstream_response.insert_header("x-request-id", request_id)?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _: &mut Session,
        ctx: &mut RouterContext,
        _: &RoutePlugin,
    ) -> Result<bool> {
        ctx.extensions.clear();

        Ok(false)
    }
}
