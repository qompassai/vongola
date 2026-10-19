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
//! server on stdio (newline-delimited JSON-RPC 2.0). It opens no
//! listener and offers no write tool; its only outbound traffic is
//! loopback GETs to the daemon's admin listener (see `daemon`).
//! stdout carries protocol frames only. Frames are bounded at
//! `MAX_FRAME_BYTES`; an oversized frame is discarded through its
//! newline and answered with -32600.

#![forbid(unsafe_code)]

mod daemon;
mod prometheus;
mod rpc;
mod tools;

use std::io::{BufRead, Read, Write};
use std::path::PathBuf;

use serde_json::Value;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

const USAGE: &str = "usage: vongola-mcp [--config PATH]   (default ./vongola.yaml)";

enum Frame {
    Eof,
    Line(Vec<u8>),
    Oversized,
}

/// Read one newline-terminated frame of at most `MAX_FRAME_BYTES`.
/// Never holds more than `MAX_FRAME_BYTES + 1` bytes.
fn read_frame(reader: &mut impl BufRead) -> std::io::Result<Frame> {
    let mut line = Vec::new();
    let limit = (MAX_FRAME_BYTES + 1) as u64;
    let read = reader.by_ref().take(limit).read_until(b'\n', &mut line)?;
    if read == 0 {
        return Ok(Frame::Eof);
    }
    if line.last() == Some(&b'\n') || line.len() <= MAX_FRAME_BYTES {
        return Ok(Frame::Line(line));
    }
    // Discard the rest of the oversized frame, bounded per pass.
    loop {
        let mut rest = Vec::new();
        let read = reader.by_ref().take(limit).read_until(b'\n', &mut rest)?;
        if read == 0 || rest.last() == Some(&b'\n') {
            return Ok(Frame::Oversized);
        }
    }
}

fn serve(
    source: &dyn daemon::Source,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> std::io::Result<()> {
    loop {
        let reply: Option<Value> = match read_frame(input)? {
            Frame::Eof => return Ok(()),
            Frame::Oversized => Some(rpc::error_frame(
                Value::Null,
                rpc::INVALID_REQUEST,
                format!("frame exceeds {MAX_FRAME_BYTES} bytes"),
            )),
            Frame::Line(bytes) => match std::str::from_utf8(&bytes) {
                Err(_) => Some(rpc::error_frame(
                    Value::Null,
                    rpc::PARSE_ERROR,
                    "frame is not UTF-8",
                )),
                Ok(text) if text.trim().is_empty() => None,
                Ok(text) => rpc::handle_line(text.trim(), source),
            },
        };
        if let Some(reply) = reply {
            writeln!(output, "{reply}")?;
            output.flush()?;
        }
    }
}

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
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(e) = serve(&source, &mut stdin.lock(), &mut stdout.lock()) {
        eprintln!("vongola-mcp: stdio failed: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::tests::{Fixture, live_fixture};

    fn run(input: &[u8], source: &dyn daemon::Source) -> Vec<Value> {
        let mut output = Vec::new();
        serve(
            source,
            &mut std::io::Cursor::new(input.to_vec()),
            &mut output,
        )
        .unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn adversarial_oversized_and_non_utf8_frames() {
        let mut input = vec![b'{'; MAX_FRAME_BYTES * 2];
        input.push(b'\n');
        input.extend_from_slice(b"\xff\xfe\n");
        input.extend_from_slice(b"{\"id\":7,\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n");
        let frames = run(&input, &live_fixture());
        assert_eq!(frames.len(), 3, "{frames:?}");
        assert_eq!(frames[0]["error"]["code"], rpc::INVALID_REQUEST);
        assert_eq!(frames[1]["error"]["code"], rpc::PARSE_ERROR);
        assert_eq!(frames[2]["id"], 7, "the stream recovers after bad frames");
    }

    #[test]
    fn validation_session_over_stdio() {
        let input = b"{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\"}}\n\
            {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
            \n\
            {\"id\":2,\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}\n\
            {\"id\":3,\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"tls_stats\"}}";
        let frames = run(input, &live_fixture());
        let ids: Vec<i64> = frames.iter().map(|f| f["id"].as_i64().unwrap()).collect();
        assert_eq!(
            ids,
            [1, 2, 3],
            "notification and blank line get no reply; unterminated last frame is served"
        );
        assert_eq!(frames[2]["result"]["structuredContent"]["hybrid_pq"], 3.0);
        let down = Fixture {
            metrics: None,
            state: None,
        };
        let frames = run(b"{\"id\":4,\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"routes_list\"}}\n", &down);
        assert_eq!(frames[0]["result"]["isError"], true);
    }
}
