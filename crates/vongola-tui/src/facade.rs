//! The facade the UI programs against (DESIGN SS D2).
//!
//! vongola-mcp is a server-only binary crate — there is no library
//! to prefer — so the real implementation is the SS D2 fallback:
//! [`McpStdioFacade`], a bounded synchronous MCP stdio client that
//! spawns the member's own `vongola-mcp` binary and speaks the
//! modern era (2026-07-28) directly: `server/discover` opens the
//! session, every request carries the era `_meta`, and frames are
//! line-bounded at the server's own cap. [`FakeFacade`] is the
//! in-memory scripted implementation every test uses; it records
//! every call so plan mode can prove no call happened.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use serde_json::{Value, json};

use crate::{RESULT_BYTES_MAX, TuiError, is_tool_name};

/// The protocol version both sides speak (modern era only, D-113).
pub const PROTOCOL_VERSION: &str = "2026-07-28";
/// Per-request deadline for one MCP round trip.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum bytes in one inbound MCP line (the server's own cap).
pub const FRAME_BYTES_MAX: usize = 1_048_576;

/// What the Overview screen needs to know about the member.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusInfo {
    /// Server implementation name (`vongola-mcp`).
    pub server_name: String,
    /// Server implementation version.
    pub server_version: String,
    /// Whether the server answered at all.
    pub reachable: bool,
    /// Number of tools the server lists.
    pub tool_count: usize,
    /// Human detail when unreachable (never a fabricated state).
    pub detail: String,
}

/// One tool from the server's `tools/list`.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolInfo {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
}

/// The narrow surface the UI programs against. All five member
/// tools are read-only and argument-free, so `call` takes only a
/// validated tool name.
pub trait VongolaFacade {
    /// Server identity + reachability for the Overview screen.
    fn status(&mut self) -> Result<StatusInfo, TuiError>;
    /// The server's tool list.
    fn tools(&mut self) -> Result<Vec<ToolInfo>, TuiError>;
    /// Call one read-only tool by name.
    fn call(&mut self, tool: &str) -> Result<Value, TuiError>;
}

/// In-memory scripted facade for tests: canned results per tool,
/// a recorded call log, and failure scripting (server death after
/// N calls) for the adversarial cases.
#[derive(Debug, Default)]
pub struct FakeFacade {
    /// Canned result per tool name.
    pub results: BTreeMap<String, Result<Value, String>>,
    /// Every call the UI made, in order.
    pub calls: Vec<String>,
    /// When set, calls after this many successes fail as a dead
    /// server (`backend: simulated server death`).
    pub die_after: Option<usize>,
    successes: usize,
}

impl FakeFacade {
    /// A fake serving one canned success per member tool.
    pub fn healthy() -> FakeFacade {
        let mut results = BTreeMap::new();
        results.insert(
            "cert_status".to_string(),
            Ok(json!({"certificates": [], "expiring_soon": []})),
        );
        results.insert(
            "log_counters".to_string(),
            Ok(json!({"errors_and_warnings": 0.0, "dropped_log_lines": 0.0})),
        );
        results.insert(
            "routes_list".to_string(),
            Ok(json!({"count": 1, "routes": []})),
        );
        results.insert(
            "tls_stats".to_string(),
            Ok(json!({"failures_total": 0.0, "handshakes_total": 4.0})),
        );
        results.insert(
            "upstream_health".to_string(),
            Ok(json!({"up": 1, "down": 0, "unknown": 0})),
        );
        FakeFacade {
            results,
            ..FakeFacade::default()
        }
    }
}

impl VongolaFacade for FakeFacade {
    fn status(&mut self) -> Result<StatusInfo, TuiError> {
        self.calls.push("status".to_string());
        Ok(StatusInfo {
            server_name: "vongola-mcp".to_string(),
            server_version: "1.0.0".to_string(),
            reachable: true,
            tool_count: crate::TOOL_NAMES.len(),
            detail: "fake facade".to_string(),
        })
    }

    fn tools(&mut self) -> Result<Vec<ToolInfo>, TuiError> {
        self.calls.push("tools".to_string());
        Ok(crate::TOOL_NAMES
            .iter()
            .map(|name| ToolInfo {
                name: name.to_string(),
                description: format!("fake {name}"),
            })
            .collect())
    }

    fn call(&mut self, tool: &str) -> Result<Value, TuiError> {
        self.calls.push(format!("call:{tool}"));
        if !is_tool_name(tool) {
            return Err(TuiError::NotFound(format!("unknown tool: {tool}")));
        }
        if let Some(limit) = self.die_after
            && self.successes >= limit
        {
            return Err(TuiError::Backend("simulated server death".to_string()));
        }
        match self.results.get(tool) {
            Some(Ok(value)) => {
                self.successes += 1;
                Ok(value.clone())
            }
            Some(Err(message)) => Err(TuiError::Backend(message.clone())),
            None => Err(TuiError::NotFound(format!("no scripted result for {tool}"))),
        }
    }
}

/// The real facade: an MCP stdio client over a spawned
/// `vongola-mcp` child process. One child per facade, started
/// lazily on first use; a dead child is a typed `Backend` error
/// and the next call retries the spawn once per call, never in a
/// loop.
pub struct McpStdioFacade {
    server_bin: PathBuf,
    config_path: Option<PathBuf>,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    lines: Option<Receiver<std::io::Result<String>>>,
    next_id: u64,
    discovered: Option<(String, String)>,
}

impl McpStdioFacade {
    /// A facade spawning `server_bin` (the member's own
    /// `vongola-mcp`), passing `--config config_path` when given.
    pub fn new(server_bin: PathBuf, config_path: Option<PathBuf>) -> McpStdioFacade {
        McpStdioFacade {
            server_bin,
            config_path,
            child: None,
            stdin: None,
            lines: None,
            next_id: 0,
            discovered: None,
        }
    }

    fn meta(&self) -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {"name": "vongola-tui", "version": env!("CARGO_PKG_VERSION")},
        })
    }

    fn ensure_started(&mut self) -> Result<(), TuiError> {
        if self.child.is_some() {
            return Ok(());
        }
        let mut command = Command::new(&self.server_bin);
        if let Some(config) = &self.config_path {
            command.arg("--config").arg(config);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| TuiError::Backend(format!("cannot spawn {:?}: {e}", self.server_bin)))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| TuiError::Backend("spawned server has no stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| TuiError::Backend("spawned server has no stdout".to_string()))?;
        // A reader thread owns stdout; the channel gives every
        // request a real deadline instead of a blocking read.
        let (sender, receiver) = channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                let outcome = reader.read_line(&mut line);
                let done = match &outcome {
                    Ok(0) | Err(_) => true,
                    Ok(_) => false,
                };
                if sender.send(outcome.map(|_| line)).is_err() || done {
                    return;
                }
            }
        });
        self.child = Some(child);
        self.stdin = Some(stdin);
        self.lines = Some(receiver);
        // Open the modern-era session and verify the peer is the
        // member's own server advertising exactly this era.
        let response = self.request("server/discover", json!({}))?;
        let versions = response
            .pointer("/result/supportedVersions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if !versions
            .iter()
            .any(|v| v.as_str() == Some(PROTOCOL_VERSION))
        {
            self.reset();
            return Err(TuiError::Backend(format!(
                "server does not advertise {PROTOCOL_VERSION}: {versions:?}"
            )));
        }
        let name = response
            .pointer("/result/_meta/io.modelcontextprotocol~1serverInfo/name")
            .and_then(|v| v.as_str())
            .unwrap_or("vongola-mcp")
            .to_string();
        let version = response
            .pointer("/result/_meta/io.modelcontextprotocol~1serverInfo/version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        self.discovered = Some((name, version));
        Ok(())
    }

    fn reset(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.stdin = None;
        self.lines = None;
        self.discovered = None;
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, TuiError> {
        if self.child.is_none() && method != "server/discover" {
            self.ensure_started()?;
        }
        self.next_id += 1;
        let id = self.next_id;
        let mut params = params;
        params["_meta"] = self.meta();
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let line = serde_json::to_string(&frame)
            .map_err(|e| TuiError::Backend(format!("frame encode: {e}")))?;
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| TuiError::Backend("server not started".to_string()))?;
        stdin
            .write_all(line.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush())
            .map_err(|e| {
                TuiError::Backend(format!("server stdin write failed (server died?): {e}"))
            })?;
        let lines = self
            .lines
            .as_ref()
            .ok_or_else(|| TuiError::Backend("server not started".to_string()))?;
        loop {
            let raw = lines
                .recv_timeout(REQUEST_TIMEOUT)
                .map_err(|_| TuiError::Backend("server response timed out".to_string()))?
                .map_err(|e| TuiError::Backend(format!("server stdout read failed: {e}")))?;
            if raw.len() > FRAME_BYTES_MAX {
                return Err(TuiError::Oversized(format!(
                    "server frame exceeds {FRAME_BYTES_MAX} bytes"
                )));
            }
            let value: Value = serde_json::from_str(raw.trim())
                .map_err(|e| TuiError::Backend(format!("server frame is not JSON: {e}")))?;
            if value.get("id").and_then(|v| v.as_u64()) == Some(id) {
                if let Some(error) = value.get("error") {
                    return Err(TuiError::Backend(format!(
                        "protocol error: {}",
                        error
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                    )));
                }
                return Ok(value);
            }
            // A frame for another id: not ours; keep waiting inside
            // the same deadline discipline (bounded by the timeout
            // on the next receive).
        }
    }
}

impl Drop for McpStdioFacade {
    fn drop(&mut self) { self.reset(); }
}

impl VongolaFacade for McpStdioFacade {
    fn status(&mut self) -> Result<StatusInfo, TuiError> {
        match self.ensure_started() {
            Ok(()) => {
                let tools = self.tools()?;
                let (name, version) = self
                    .discovered
                    .clone()
                    .unwrap_or_else(|| ("vongola-mcp".to_string(), "unknown".to_string()));
                Ok(StatusInfo {
                    server_name: name,
                    server_version: version,
                    reachable: true,
                    tool_count: tools.len(),
                    detail: "stdio session open".to_string(),
                })
            }
            Err(err) => Ok(StatusInfo {
                server_name: "vongola-mcp".to_string(),
                server_version: "unknown".to_string(),
                reachable: false,
                tool_count: 0,
                detail: err.to_string(),
            }),
        }
    }

    fn tools(&mut self) -> Result<Vec<ToolInfo>, TuiError> {
        let response = self.request("tools/list", json!({}))?;
        let tools = response
            .pointer("/result/tools")
            .and_then(|v| v.as_array())
            .ok_or_else(|| TuiError::Backend("tools/list result has no tools".to_string()))?;
        Ok(tools
            .iter()
            .filter_map(|tool| {
                Some(ToolInfo {
                    name: tool.get("name")?.as_str()?.to_string(),
                    description: tool
                        .get("description")
                        .and_then(|value| value.as_str())
                        .unwrap_or("")
                        .to_string(),
                })
            })
            .collect())
    }

    fn call(&mut self, tool: &str) -> Result<Value, TuiError> {
        if !is_tool_name(tool) {
            return Err(TuiError::NotFound(format!("unknown tool: {tool}")));
        }
        let response = self.request("tools/call", json!({"name": tool, "arguments": {}}))?;
        let result = response
            .get("result")
            .ok_or_else(|| TuiError::Backend("tools/call result missing".to_string()))?;
        let is_error = result
            .get("isError")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if let Some(structured) = result.get("structuredContent") {
            let text = structured.to_string();
            if text.len() > RESULT_BYTES_MAX {
                return Err(TuiError::Oversized(format!(
                    "tool result exceeds {RESULT_BYTES_MAX} bytes"
                )));
            }
            if is_error {
                let code = structured
                    .pointer("/error/code")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tool.error");
                let message = structured
                    .pointer("/error/message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tool failed");
                return Err(TuiError::Backend(format!("{code}: {message}")));
            }
            return Ok(structured.clone());
        }
        let text = result
            .pointer("/content/0/text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TuiError::Backend("tools/call result has no content".to_string()))?;
        if text.len() > RESULT_BYTES_MAX {
            return Err(TuiError::Oversized(format!(
                "tool result exceeds {RESULT_BYTES_MAX} bytes"
            )));
        }
        let parsed: Value = serde_json::from_str(text)
            .map_err(|e| TuiError::Backend(format!("tool result is not JSON: {e}")))?;
        if is_error {
            let code = parsed
                .pointer("/error/code")
                .and_then(|v| v.as_str())
                .unwrap_or("tool.error");
            let message = parsed
                .pointer("/error/message")
                .and_then(|v| v.as_str())
                .unwrap_or("tool failed");
            return Err(TuiError::Backend(format!("{code}: {message}")));
        }
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_fake_serves_all_five_tools() {
        let mut fake = FakeFacade::healthy();
        let status = fake.status().unwrap();
        assert!(status.reachable);
        assert_eq!(status.tool_count, 5);
        assert_eq!(fake.tools().unwrap().len(), 5);
        for name in crate::TOOL_NAMES {
            assert!(fake.call(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn adversarial_fake_unknown_tool_and_death() {
        let mut fake = FakeFacade::healthy();
        assert!(matches!(
            fake.call("rotate_self_signed"),
            Err(TuiError::NotFound(_))
        ));
        let mut dying = FakeFacade::healthy();
        dying.die_after = Some(1);
        assert!(dying.call("tls_stats").is_ok());
        assert!(matches!(dying.call("tls_stats"), Err(TuiError::Backend(_))));
    }

    #[test]
    fn adversarial_stdio_facade_missing_binary_is_typed() {
        let mut facade = McpStdioFacade::new(PathBuf::from("/nonexistent/vongola-mcp"), None);
        let status = facade.status().unwrap();
        assert!(!status.reachable);
        assert_eq!(status.tool_count, 0);
        assert!(matches!(
            facade.call("tls_stats"),
            Err(TuiError::Backend(_))
        ));
        assert!(matches!(
            facade.call("not_a_tool"),
            Err(TuiError::NotFound(_))
        ));
    }
}
