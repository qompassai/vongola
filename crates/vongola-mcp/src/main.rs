// #################################################################
// /qompassai/vongola/crates/vongola-mcp/src/main.rs
// Qompass AI — vongola-mcp entry point
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
// #################################################################

//! `vongola-mcp [--config PATH]`: a read-only, operator-local MCP
//! server on stdio. It opens no listener and offers no write
//! tool; its only outbound traffic is loopback GETs to the
//! daemon's admin listener (see `daemon`). stdout carries
//! protocol frames only. Framing is the rmcp SDK behind the era
//! guard (`guard`), modern era only (2026-07-28) since v0.2;
//! frames are bounded at `guard::MAX_LINE_BYTES`.

#![forbid(unsafe_code)]

mod daemon;
mod guard;
mod prometheus;
mod server;
mod tools;

use std::path::PathBuf;

const USAGE: &str = "usage: vongola-mcp [--config PATH]   (default ./vongola.yaml)";

fn main() {
    let mut config_path = PathBuf::from("./vongola.yaml");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => match args.next() {
                Some(value) => config_path = PathBuf::from(value),
                None => {
                    eprintln!("--config needs a path\n{USAGE}");
                    std::process::exit(2);
                }
            },
            "--help" | "-h" => {
                println!("{USAGE}");
                return;
            }
            "--version" => {
                println!("vongola-mcp {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            other => {
                eprintln!("unknown argument: {other}\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    let source = daemon::ConfigSource { config_path };
    if let Err(e) = server::serve_stdio(source) {
        eprintln!("vongola-mcp: stdio failed: {e}");
        std::process::exit(1);
    }
}
