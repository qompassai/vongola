// #################################################################
// /qompassai/vongola/crates/vongola/src/plugins/oauth2/workos.rs
// Qompass AI Workos
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

use serde::Deserialize;

use super::{HTTP_CLIENT, provider::OauthUser};

pub(super) struct WorkosOauthService;

const WORKOS_API_URL: &str = "https://api.workos.com/user_management/authorize";

impl WorkosOauthService {
    /// Get the OAuth callback URL for Workos
    pub fn get_oauth_callback_url(client_id: &str, state: &str) -> String {
        format!(
            "{WORKOS_API_URL}?client_id={client_id}&redirect_uri={}&state={state}&provider=authkit&response_type=code",
            ""
        )
    }

    /// Retrieves the user information from Workos
    pub async fn get_oauth_user(
        client_id: &str,
        client_secret: &str,
        code: &str,
    ) -> Result<OauthUser, anyhow::Error> {
        let response = HTTP_CLIENT
            .post(WORKOS_API_URL)
            .json(&serde_json::json!(
                {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "user-agent": "pingora/0.2.0"
                }
            ))
            .send()
            .await?;
        let body = response.json::<WorkosTokenResponse>().await?;

        Ok(OauthUser {
            email: body.user.email,
            team_ids: vec![],
            organization_ids: vec![],
            usernames: vec![],
        })
    }
}

#[derive(Deserialize)]
struct WorkosTokenResponse {
    // access_token: Cow<'static, str>,
    // refresh_token: Cow<'static, str>,
    user: WorkosUserResponse,
}

#[derive(Deserialize)]
struct WorkosUserResponse {
    // id: Cow<'static, str>,
    email: Cow<'static, str>,
}
