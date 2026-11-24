// #################################################################
// /qompassai/vongola/crates/vongola-mcp/tests/era.rs
// Qompass AI — vongola-mcp era gates
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

//! Era gates (WS2, D-113): the migrated server speaks the modern
//! MCP era only (2026-07-28). Legacy contact is refused with the
//! designed typed errors and the server survives every refusal;
//! framing failures follow the fleet guard contract (see
//! `src/guard.rs`). Frames are raw strings and responses are
//! correlated by JSON-RPC id (rmcp dispatches pipelined requests
//! concurrently).
//!
//! The server is spawned with `--config` pointing at the repo's
//! example config (admin listener 127.0.0.1:9091); no daemon is
//! running, so tool calls answer with the recorded
//! `daemon.unavailable` tool error — the census smoke shape.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const META: &str = r#""_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientInfo": {"name": "era-test", "version": "0"}, "io.modelcontextprotocol/clientCapabilities": {}}"#;
const LEGACY_META: &str = r#""_meta": {"io.modelcontextprotocol/protocolVersion": "2025-06-18", "io.modelcontextprotocol/clientInfo": {"name": "era-test", "version": "0"}, "io.modelcontextprotocol/clientCapabilities": {}}"#;

fn vongola_bin() -> &'static str { env!("CARGO_BIN_EXE_vongola-mcp") }

fn example_config() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/qompass.yaml")
        .canonicalize()
        .expect("example config exists")
}

struct RawServer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl RawServer {
    fn spawn() -> RawServer {
        let mut child = Command::new(vongola_bin())
            .arg("--config")
            .arg(example_config())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vongola-mcp server");
        let stdin = child.stdin.take().expect("server stdin");
        let stdout = BufReader::new(child.stdout.take().expect("server stdout"));
        RawServer {
            child,
            stdin,
            stdout,
        }
    }

    /// Send raw lines; read exactly `expect` frames. Returns them
    /// in arrival order (callers correlate by id).
    fn exchange(&mut self, lines: &[String], expect: usize) -> Vec<serde_json::Value> {
        for line in lines {
            self.stdin.write_all(line.as_bytes()).expect("write frame");
            self.stdin.write_all(b"\n").expect("write newline");
        }
        self.stdin.flush().expect("flush");
        let mut frames = Vec::new();
        for _ in 0..expect {
            let mut line = String::new();
            let read = self.stdout.read_line(&mut line).expect("read frame");
            assert!(read > 0, "server closed stdout unexpectedly");
            frames.push(serde_json::from_str(&line).expect("server frame is JSON"));
        }
        frames
    }

    fn shutdown(mut self) {
        drop(self.stdin);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    assert!(status.success(), "server exit not clean: {status}");
                    return;
                }
                Ok(None) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "server did not exit on EOF"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
                Err(e) => panic!("wait failed: {e}"),
            }
        }
    }
}

fn by_id(frames: &[serde_json::Value], id: i64) -> &serde_json::Value {
    frames
        .iter()
        .find(|f| f["id"] == serde_json::json!(id))
        .unwrap_or_else(|| panic!("no frame with id {id} in {frames:?}"))
}

fn discover(id: i64) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"server/discover","params":{{{META}}}}}"#)
}

fn initialize(id: i64, version: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"initialize","params":{{"protocolVersion":"{version}","capabilities":{{}},"clientInfo":{{"name":"era-test","version":"0"}}}}}}"#
    )
}

#[test]
fn discover_advertises_only_the_modern_era() {
    let mut srv = RawServer::spawn();
    let frames = srv.exchange(&[discover(1)], 1);
    let result = &by_id(&frames, 1)["result"];
    assert_eq!(
        result["supportedVersions"],
        serde_json::json!(["2026-07-28"])
    );
    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "vongola-mcp"
    );
    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    srv.shutdown();
}

#[test]
fn legacy_initialize_is_refused_and_the_server_survives() {
    let mut srv = RawServer::spawn();
    for (id, version) in [
        (1, "2024-11-05"),
        (2, "2025-03-26"),
        (3, "2025-06-18"),
        (4, "2026-07-28"),
    ] {
        let frames = srv.exchange(&[initialize(id, version)], 1);
        let frame = by_id(&frames, id);
        assert_eq!(frame["error"]["code"], -32022, "{frame}");
        assert_eq!(frame["error"]["data"]["requested"], version);
        assert_eq!(
            frame["error"]["data"]["supported"],
            serde_json::json!(["2026-07-28"])
        );
    }
    // The refusals are not teardowns: a modern session still works.
    let frames = srv.exchange(&[discover(5)], 1);
    assert_eq!(
        by_id(&frames, 5)["result"]["supportedVersions"],
        serde_json::json!(["2026-07-28"])
    );
    srv.shutdown();
}

#[test]
fn tools_list_requires_modern_meta() {
    let mut srv = RawServer::spawn();
    // Legacy _meta: the SDK's per-request version gate refuses.
    let legacy =
        format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{{{LEGACY_META}}}}}"#);
    let frames = srv.exchange(&[legacy], 1);
    let frame = by_id(&frames, 1);
    assert_eq!(frame["error"]["code"], -32022, "{frame}");
    assert_eq!(
        frame["error"]["data"]["supported"],
        serde_json::json!(["2026-07-28"])
    );
    // Modern _meta: the full 5-tool surface, in table order.
    let modern = format!(r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{{META}}}}}"#);
    let frames = srv.exchange(&[modern], 1);
    let tools = by_id(&frames, 2)["result"]["tools"]
        .as_array()
        .expect("tools array")
        .clone();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec![
            "cert_status",
            "log_counters",
            "routes_list",
            "tls_stats",
            "upstream_health"
        ]
    );
    srv.shutdown();
}

#[test]
fn smoke_call_answers_with_the_daemon_unavailable_tool_error() {
    let mut srv = RawServer::spawn();
    // The census smoke: log_counters with no daemon running is a
    // well-formed isError result, not a protocol error.
    let call = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"log_counters","arguments":{{}}, {META}}}}}"#
    );
    let frames = srv.exchange(&[call], 1);
    let frame = by_id(&frames, 1);
    assert!(frame.get("error").is_none(), "{frame}");
    assert_eq!(frame["result"]["isError"], true);
    assert_eq!(
        frame["result"]["structuredContent"]["error"]["code"],
        "daemon.unavailable"
    );
    srv.shutdown();
}

#[test]
fn framing_errors_follow_the_guard_contract() {
    let mut srv = RawServer::spawn();
    let frames = srv.exchange(
        &[
            "this is not json".to_string(),
            "[1,2,3]".to_string(),
            "42".to_string(),
        ],
        3,
    );
    assert_eq!(frames[0]["error"]["code"], -32700);
    assert!(
        frames[0]["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("parse error: "),
        "{frames:?}"
    );
    assert_eq!(frames[1]["error"]["code"], -32600);
    assert_eq!(frames[2]["error"]["code"], -32600);
    // The server survives its own framing errors.
    let frames = srv.exchange(&[discover(9)], 1);
    assert_eq!(
        by_id(&frames, 9)["result"]["supportedVersions"],
        serde_json::json!(["2026-07-28"])
    );
    srv.shutdown();
}

#[test]
fn notifications_are_dropped_unexecuted() {
    let mut srv = RawServer::spawn();
    // A notification-shaped tools/call, then a discover: exactly
    // one frame comes back (the discover response). This surface
    // is read-only, so the drop is a protocol-shape fact here —
    // no response frame is ever produced for a notification.
    let notification = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"log_counters","arguments":{}}}"#
        .to_string();
    let frames = srv.exchange(&[notification, discover(5)], 1);
    assert_eq!(frames.len(), 1);
    assert_eq!(
        by_id(&frames, 5)["result"]["supportedVersions"],
        serde_json::json!(["2026-07-28"])
    );
    srv.shutdown();
}
