// #################################################################
// /qompassai/vongola/crates/vongola/src/plugins/oauth2/secure_cookie.rs
// Qompass AI Secure Cookie
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

use cookie::{Cookie, SameSite, time::OffsetDateTime};

use super::{COOKIE_NAME, provider::OauthUser};
use crate::plugins::jwt;

/// Creates a secure cookie for the user containing the JWT token
pub(super) fn create_secure_cookie<'a>(
    user: &OauthUser,
    jwt_secret: &str,
    host: &str,
) -> Result<Cookie<'a>, anyhow::Error> {
    let jwt_token = jwt::encode_jwt(&user.email, jwt_secret.as_bytes())?;

    let cookie_domain = extract_cookie_domain(host);
    let expiration = OffsetDateTime::now_utc().checked_add(cookie::time::Duration::days(1));

    Ok(Cookie::build((COOKIE_NAME, jwt_token))
        .secure(true)
        .domain(cookie_domain)
        .path("/")
        .expires(expiration)
        .http_only(true)
        .same_site(SameSite::Lax)
        .build())
}

/// Removes the secure cookie for the user
pub(super) fn _remove_secure_cookie(host: &str) -> Cookie<'static> {
    let cookie_domain = extract_cookie_domain(host);
    Cookie::build((COOKIE_NAME, ""))
        .secure(true)
        .domain(cookie_domain)
        .path("/")
        .expires(OffsetDateTime::now_utc().checked_add(cookie::time::Duration::days(1)))
        .http_only(true)
        .same_site(SameSite::Lax)
        .build()
}

/// Extracts the domain without subdomain
/// This function does not support all possible tlds.
fn extract_cookie_domain(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();

    if parts.len() <= 2 {
        host.to_owned()
    } else {
        parts[parts.len() - 2..].join(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_domain() {
        let host = "example.com";
        let result = extract_cookie_domain(host);
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_domain_with_subdomain() {
        let host = "sub.example.com";
        let result = extract_cookie_domain(host);
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_domain_with_multiple_subdomains() {
        let host = "sub.sub.example.com";
        let result = extract_cookie_domain(host);
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_edge_case_single_part_domain() {
        let host = "localhost";
        let result = extract_cookie_domain(host);
        assert_eq!(result, "localhost");
    }

    #[test]
    fn test_edge_case_empty_string() {
        let host = "";
        let result = extract_cookie_domain(host);
        assert_eq!(result, "");
    }

    #[test]
    fn test_domain_with_unusual_tld() {
        // TODO: fix this use case.
        // We should return the correct domain
        let host = "example.co.uk";
        let result = extract_cookie_domain(host);
        assert_eq!(result, "co.uk");
    }

    #[test]
    fn test_domain_with_longer_tld() {
        let host = "example.london";
        let result = extract_cookie_domain(host);
        assert_eq!(result, "example.london");
    }
}
