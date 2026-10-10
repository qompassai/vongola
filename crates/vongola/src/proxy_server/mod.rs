// #################################################################
// /qompassai/vongola/crates/vongola/src/proxy_server/mod.rs
// Qompass AI Proxy Server mod
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

use std::{collections::BTreeMap, time::Duration};

use pingora::{
    protocols::{ALPN, TcpKeepalive},
    upstreams::peer::PeerOptions,
};

pub mod cert_store;
pub mod http_proxy;
pub mod https_proxy;
pub mod middleware;

/// Default peer options to be used on every upstream connection
const DEFAULT_PEER_OPTIONS: PeerOptions = PeerOptions {
    dscp: None,
    tcp_fast_open: true,
    verify_hostname: true,
    read_timeout: Some(Duration::from_secs(360)),
    connection_timeout: Some(Duration::from_secs(10)),
    tcp_recv_buf: Some(1024 * 8),
    tcp_keepalive: Some(TcpKeepalive {
        count: 10,
        idle: Duration::from_secs(60),
        interval: Duration::from_secs(30),
    }),
    bind_to: None,
    total_connection_timeout: Some(Duration::from_secs(20)),
    idle_timeout: Some(Duration::from_secs(360)),
    write_timeout: Some(Duration::from_secs(60)),
    verify_cert: false,
    alternative_cn: None,
    alpn: ALPN::H2H1,
    ca: None,
    h2_ping_interval: Some(Duration::from_secs(60)),
    max_h2_streams: 2,
    extra_proxy_headers: BTreeMap::new(),
    curves: None,
    second_keyshare: true, // default true and noop when not using PQ curves
    tracer: None,
    custom_l4: None,
};
