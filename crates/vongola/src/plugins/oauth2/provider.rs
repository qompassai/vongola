// #################################################################
// /qompassai/vongola/crates/vongola/src/plugins/oauth2/provider.rs
// Qompass AI Provider
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
    borrow::Cow,
    fmt::{Display, Formatter},
};

use super::{github::GithubOauthService, workos::WorkosOauthService};
use crate::plugins::jwt::JwtClaims;
pub struct Provider {
    pub(super) typ: OauthType,
    pub(super) client_id: String,
    pub(super) client_secret: String,
}
impl Provider {
    /// Get the Oauth callback URL for the given provider
    pub fn get_oauth_callback_url(&self, state: &str) -> String {
        match self.typ {
            OauthType::Github => GithubOauthService::get_oauth_callback_url(&self.client_id, state),
            OauthType::Workos => WorkosOauthService::get_oauth_callback_url(&self.client_id, state),
        }
    }

    /// Get the Oauth user from the provider using the provided code
    pub async fn get_oauth_user(&self, code: &str) -> Result<OauthUser, anyhow::Error> {
        match self.typ {
            OauthType::Github => {
                GithubOauthService::get_oauth_user(&self.client_id, &self.client_secret, code).await
            }
            OauthType::Workos => {
                WorkosOauthService::get_oauth_user(&self.client_id, &self.client_secret, code).await
            }
        }
    }
}

#[derive(Debug)]
pub struct OauthUser {
    pub email: Cow<'static, str>,
    pub team_ids: Vec<String>,
    pub organization_ids: Vec<String>,
    pub usernames: Vec<String>,
}

impl From<JwtClaims> for OauthUser {
    fn from(claims: JwtClaims) -> Self {
        Self {
            email: claims.sub,
            team_ids: claims.teams,
            organization_ids: claims.ids,
            usernames: vec![],
        }
    }
}

//
pub enum OauthType {
    Github,
    Workos,
}

impl Display for OauthType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OauthType::Github => write!(f, "github"),
            OauthType::Workos => write!(f, "workos"),
        }
    }
}
