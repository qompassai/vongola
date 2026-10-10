// #################################################################
// /qompassai/vongola/crates/vongola/src/stores/mod.rs
// Qompass AI Stores mod
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

use std::hash::RandomState;

use certificates::{Certificate, CertificateStore};
use challenges::ChallengeStore;
use once_cell::sync::Lazy;
use papaya::HashMapRef;
use routes::{RouteStore, RouteStoreContainer};

pub mod cache;
pub mod certificates;
pub mod challenges;
pub mod routes;

// CHALLENGE store
static CHALLENGE_STORE: Lazy<ChallengeStore> = Lazy::new(papaya::HashMap::new);

pub fn get_challenge_by_key(key: &str) -> Option<(String, String)> {
    CHALLENGE_STORE.pin().get(key).cloned()
}

/// Insert given challenge into the store
pub fn insert_challenge(key: String, value: (String, String)) {
    CHALLENGE_STORE.pin().insert(key, value);
}

// ROUTE store
static ROUTE_STORE: Lazy<RouteStore> = Lazy::new(papaya::HashMap::new);

pub fn get_route_by_key(key: &str) -> Option<RouteStoreContainer> {
    ROUTE_STORE.pin().get(key).cloned()
}

pub fn get_routes()
-> HashMapRef<'static, String, RouteStoreContainer, RandomState, seize::OwnedGuard<'static>> {
    ROUTE_STORE.pin_owned()
}

pub fn insert_route(key: String, value: RouteStoreContainer) {
    ROUTE_STORE.pin().insert(key, value);
}

// CERTIFICATE store
static CERTIFICATE_STORE: Lazy<CertificateStore> = Lazy::new(papaya::HashMap::new);

pub fn get_certificate_by_key(key: &str) -> Option<Certificate> {
    CERTIFICATE_STORE.pin().get(key).cloned()
}

pub fn get_certificates()
-> HashMapRef<'static, String, Certificate, RandomState, seize::LocalGuard<'static>> {
    CERTIFICATE_STORE.pin()
}

pub fn insert_certificate(key: String, value: Certificate) {
    CERTIFICATE_STORE.pin().insert(key, value);
}

// Cache Routing store
static CACHE_ROUTING_STORE: Lazy<cache::PathCacheStorage> = Lazy::new(papaya::HashMap::new);

/// Retrieves the cache routing from the store
pub fn get_cache_routing_by_key(key: &str) -> Option<String> {
    CACHE_ROUTING_STORE.pin().get(key).cloned()
}

/// Insert given cache routing into the store if it does not exist
pub fn insert_cache_routing(key: &str, new_value: String, should_override: bool) {
    if CACHE_ROUTING_STORE.pin().get(key).is_some() {
        if should_override {
            CACHE_ROUTING_STORE.pin().insert(key.to_string(), new_value);

            return;
        }

        return;
    }

    CACHE_ROUTING_STORE.pin().insert(key.to_string(), new_value);
}
