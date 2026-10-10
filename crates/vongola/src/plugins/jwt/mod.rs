// #################################################################
// /qompassai/vongola/crates/vongola/src/plugins/jwt/mod.rs
// Qompass AI Jwt mod
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
    time::{Duration, SystemTime},
};

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, encode};
use serde::{Deserialize, Serialize};

/// Struct that holds the claims for a JWT token
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JwtClaims {
    pub sub: Cow<'static, str>,
    pub exp: usize,
    pub iat: usize,
    pub teams: Vec<String>,
    pub ids: Vec<String>,
    // usernames: Vec<String>,
}

/// Generates a JWT token for the given sub
pub(crate) fn encode_jwt(sub: &str, secret: &[u8]) -> Result<String, anyhow::Error> {
    let start = SystemTime::now();
    let since = start.duration_since(SystemTime::UNIX_EPOCH)?;

    let one_day_in_secs = 60 * 60 * 24;
    let in_one_day = since
        .checked_add(Duration::from_secs(one_day_in_secs))
        .unwrap();

    let claims = JwtClaims {
        sub: Cow::Owned(sub.to_string()),
        exp: usize::try_from(in_one_day.as_secs())?,
        iat: usize::try_from(since.as_secs())?,
        teams: vec![],
        ids: vec![],
        // usernames: vec![],
    };

    Ok(encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )?)
}

/// Decodes a given JWT token
pub(crate) fn decode_jwt(token: &str, secret: &[u8]) -> Result<JwtClaims, anyhow::Error> {
    let data = jsonwebtoken::decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(secret),
        &Validation::default(),
    )?;

    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_jwt_with_secret() {
        let token = encode_jwt("test", b"secret");
        assert!(token.is_ok());
    }
}
