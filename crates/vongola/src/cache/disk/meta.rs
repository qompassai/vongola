// #################################################################
// /qompassai/vongola/crates/vongola/src/cache/disk/meta.rs
// Qompass AI Meta
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

use std::{collections::BTreeMap, time::SystemTime};

use http::StatusCode;
use pingora::http::ResponseHeader;
use pingora_cache::CacheMeta;
use serde::{Deserialize, Serialize};

/// `DiskCache` storage metadata with information about the sibling cache file
#[derive(Serialize, Deserialize, Clone)]
pub struct DiskCacheItemMetadata {
    pub status: u16,
    pub created_at: SystemTime,
    pub fresh_until: SystemTime,
    pub stale_while_revalidate_sec: u32,
    pub stale_if_error_sec: u32,

    /// It's converted later on to a `ResponseHeader`
    pub headers: BTreeMap<String, String>,
}

impl DiskCacheItemMetadata {
    /// Converts a `DiskCacheItemMeta` `BTreeMap` to a `ResponseHeader`
    pub fn convert_headers(meta: &DiskCacheItemMetadata) -> ResponseHeader {
        let status_code = StatusCode::from_u16(meta.status).unwrap_or(StatusCode::OK);
        let mut res_headers = ResponseHeader::build(status_code, None).unwrap();

        for (k, v) in &meta.headers {
            res_headers.insert_header(k.to_owned(), v).ok();
        }

        res_headers
    }
}

impl From<&CacheMeta> for DiskCacheItemMetadata {
    /// Converts a `CacheMeta` to a `DiskCacheItemMeta`
    fn from(meta: &CacheMeta) -> Self {
        DiskCacheItemMetadata {
            status: meta.response_header().status.as_u16(),
            created_at: meta.created(),
            fresh_until: meta.fresh_until(),
            stale_while_revalidate_sec: meta.stale_while_revalidate_sec(),
            stale_if_error_sec: meta.stale_if_error_sec(),
            headers: meta
                .headers()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
                .collect(),
        }
    }
}
