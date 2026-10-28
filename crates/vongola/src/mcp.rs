// #################################################################
// /qompassai/vongola/crates/vongola/src/mcp.rs
// Qompass AI — Vongola clean-room MCP operator server
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

//! MCP operator server: the same tool table is served over stdio
//! (`vongola mcp`) and over HTTP on the admin listener
//! (`POST /mcp`). Allow/deny is decided from the table before any
//! tool body runs — mutating tools require the operator token,
//! read-only tools require read access, unknown tools are denied.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::auth::OperatorAuth;
use crate::state::State;

#[derive(Clone, Copy, PartialEq)]
pub enum ToolKind {
    Mutating,
    ReadOnly,
}

pub struct ToolSpec {
    pub description: &'static str,
    pub kind: ToolKind,
    pub name: &'static str,
}

/// The complete tool table, alphabetical. Mutating tools are
/// exactly: config_reload, rotate_self_signed.
pub const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        description: "Signed A2A agent card for this node",
        kind: ToolKind::ReadOnly,
        name: "agent_card_get",
    },
    ToolSpec {
        description: "Certificate inventory: hosts, expiry, fingerprints (never key material)",
        kind: ToolKind::ReadOnly,
        name: "cert_inventory",
    },
    ToolSpec {
        description: "Reload configuration from disk and swap atomically",
        kind: ToolKind::Mutating,
        name: "config_reload",
    },
    ToolSpec {
        description: "Current configuration snapshot (secrets are env-referenced, never values)",
        kind: ToolKind::ReadOnly,
        name: "config_snapshot",
    },
    ToolSpec {
        description: "Validate a candidate configuration document",
        kind: ToolKind::ReadOnly,
        name: "config_validate",
    },
    ToolSpec {
        description: "Prometheus metrics text",
        kind: ToolKind::ReadOnly,
        name: "metrics_get",
    },
    ToolSpec {
        description: "NAT mapping status per listener",
        kind: ToolKind::ReadOnly,
        name: "nat_status",
    },
    ToolSpec {
        description: "Regenerate a route's self-signed fallback certificate",
        kind: ToolKind::Mutating,
        name: "rotate_self_signed",
    },
    ToolSpec {
        description: "Configured routes with upstreams and chains",
        kind: ToolKind::ReadOnly,
        name: "route_list",
    },
    ToolSpec {
        description: "Tor status and onion services (addresses only, never keys)",
        kind: ToolKind::ReadOnly,
        name: "tor_status",
    },
    ToolSpec {
        description: "Upstream health map",
        kind: ToolKind::ReadOnly,
        name: "upstream_health",
    },
];

pub fn tool_spec(name: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|tool| tool.name == name)
}

#[derive(Debug)]
pub struct McpError {
    pub code: i64,
    pub message: String,
}

/// Execute one tool call. Authorization is checked from the
/// table first; the body runs only on an explicit allow.
pub fn call_tool(
    state: &Arc<State>,
    auth: &OperatorAuth,
    presented_token: Option<&str>,
    name: &str,
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, McpError> {
    let Some(spec) = tool_spec(name) else {
        return Err(McpError {
            code: -32601,
            message: format!("unknown tool: {name}"),
        });
    };
    let allowed = match spec.kind {
        ToolKind::ReadOnly => auth.can_read(presented_token),
        ToolKind::Mutating => auth.can_mutate(presented_token),
    };
    if !allowed {
        return Err(McpError {
            code: -32001,
            message: format!("tool {name} denied: operator authorization required"),
        });
    }
    run_tool(state, name, arguments)
}

fn run_tool(
    state: &Arc<State>,
    name: &str,
    arguments: &serde_json::Value,
) -> Result<serde_json::Value, McpError> {
    let config = state.config_snapshot();
    match name {
        "agent_card_get" => {
            let host = arguments
                .get("host")
                .and_then(|v| v.as_str())
                .unwrap_or("localhost");
            crate::a2a::signed_card(&config, host, &format!("https://{host}/")).map_err(|message| {
                McpError {
                    code: -32000,
                    message,
                }
            })
        }
        "cert_inventory" => {
            let certs = state.certs.read().map_err(|_| McpError {
                code: -32000,
                message: "cert lock poisoned".to_string(),
            })?;
            Ok(serde_json::json!({"certificates": certs.inventory()}))
        }
        "config_reload" => match state.reload() {
            Ok(bundle) => Ok(serde_json::json!({"bundle_sha256": bundle, "reloaded": true})),
            Err(errors) => Err(McpError {
                code: -32000,
                message: serde_json::to_string(&errors).unwrap_or_default(),
            }),
        },
        "config_snapshot" => Ok(serde_json::to_value(&*config).map_err(|e| McpError {
            code: -32000,
            message: e.to_string(),
        })?),
        "config_validate" => {
            let text = arguments
                .get("yaml")
                .and_then(|v| v.as_str())
                .ok_or(McpError {
                    code: -32602,
                    message: "config_validate needs a `yaml` string argument".to_string(),
                })?;
            match crate::config::Config::parse(text) {
                Ok(_) => Ok(serde_json::json!({"valid": true})),
                Err(errors) => Ok(serde_json::json!({"errors": errors, "valid": false})),
            }
        }
        "metrics_get" => Ok(serde_json::json!({
            "prometheus": state.metrics.render(&state.extra_gauges())
        })),
        "nat_status" => {
            let nat = state.nat.read().map_err(|_| McpError {
                code: -32000,
                message: "nat lock poisoned".to_string(),
            })?;
            Ok(serde_json::json!({"nat": *nat}))
        }
        "rotate_self_signed" => {
            let host = arguments
                .get("host")
                .and_then(|v| v.as_str())
                .ok_or(McpError {
                    code: -32602,
                    message: "rotate_self_signed needs a `host` argument".to_string(),
                })?;
            crate::cert::rotate_self_signed(&config, host).map_err(|message| McpError {
                code: -32000,
                message,
            })?;
            match state.reload() {
                Ok(bundle) => Ok(serde_json::json!({"bundle_sha256": bundle, "rotated": host})),
                Err(errors) => Err(McpError {
                    code: -32000,
                    message: serde_json::to_string(&errors).unwrap_or_default(),
                }),
            }
        }
        "route_list" => Ok(crate::dashboard::state_json(state)
            .get("routes")
            .cloned()
            .unwrap_or(serde_json::Value::Null)),
        "tor_status" => Ok(
            serde_json::json!({"tor": state.tor.read().map(|t| t.clone()).unwrap_or_else(|_| crate::tor::TorStatus::disabled())}),
        ),
        "upstream_health" => {
            let health = state.upstream_health.read().map_err(|_| McpError {
                code: -32000,
                message: "health lock poisoned".to_string(),
            })?;
            Ok(serde_json::json!({"upstream_health": *health}))
        }
        other => Err(McpError {
            code: -32601,
            message: format!("tool {other} has no implementation"),
        }),
    }
}

/// Handle one JSON-RPC request value; returns the response value.
pub fn handle_jsonrpc(
    state: &Arc<State>,
    auth: &OperatorAuth,
    presented_token: Option<&str>,
    request: &serde_json::Value,
) -> serde_json::Value {
    let id = request
        .get("id")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let result = match method {
        "initialize" => Ok(serde_json::json!({
            "capabilities": {"tools": {}},
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "vongola", "version": env!("CARGO_PKG_VERSION")}
        })),
        "notifications/initialized" => return serde_json::Value::Null,
        "ping" => Ok(serde_json::json!({})),
        "tools/call" => {
            let params = request
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            call_tool(state, auth, presented_token, name, &arguments).map(|value| {
                serde_json::json!({
                    "content": [{"text": serde_json::to_string(&value).unwrap_or_default(), "type": "text"}]
                })
            })
        }
        "tools/list" => Ok(serde_json::json!({
            "tools": TOOLS.iter().map(|tool| serde_json::json!({
                "description": tool.description,
                "inputSchema": {"type": "object"},
                "name": tool.name,
            })).collect::<Vec<_>>()
        })),
        other => Err(McpError {
            code: -32601,
            message: format!("unknown method: {other}"),
        }),
    };
    match result {
        Ok(value) => serde_json::json!({"id": id, "jsonrpc": "2.0", "result": value}),
        Err(error) => serde_json::json!({
            "error": {"code": error.code, "message": error.message},
            "id": id,
            "jsonrpc": "2.0"
        }),
    }
}

/// Stdio transport: line-delimited JSON-RPC on stdin/stdout.
/// The presented token is read from the configured env var at
/// launch, so a stdio instance launched by the operator with the
/// token can mutate; without it, mutations are denied here too.
pub async fn serve_stdio(state: Arc<State>, auth: OperatorAuth) {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    let presented = auth.token.clone();
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let Ok(request) = serde_json::from_str::<serde_json::Value>(trimmed) else {
                    continue;
                };
                let response = handle_jsonrpc(&state, &auth, presented.as_deref(), &request);
                if !response.is_null() {
                    let text = serde_json::to_string(&response).unwrap_or_default();
                    let _ = stdout.write_all(format!("{text}\n").as_bytes()).await;
                    let _ = stdout.flush().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cert::CertStore;

    fn test_state() -> Arc<State> {
        let config: crate::config::Config = serde_yaml::from_str(
            "listeners:\n  admin: {bind: \"127.0.0.1:9091\"}\n  http: {bind: \"0.0.0.0:8080\"}\n  https: {bind: \"0.0.0.0:4433\"}\nroutes:\n  - host: \"x.test\"\n    upstreams: [{address: \"127.0.0.1:9000\"}]",
        )
        .unwrap();
        let certs = CertStore::build(&config).unwrap();
        State::new(config, PathBuf::from("vongola.yaml"), certs)
    }

    #[test]
    fn adversarial_unauthenticated_mutation_denied() {
        let state = test_state();
        let auth = OperatorAuth {
            bind_is_loopback: false,
            token: Some("sekret".to_string()),
        };
        let result = call_tool(&state, &auth, None, "config_reload", &serde_json::json!({}));
        assert!(result.is_err());
        let result = call_tool(
            &state,
            &auth,
            Some("Bearer wrong"),
            "rotate_self_signed",
            &serde_json::json!({"host": "x.test"}),
        );
        assert!(result.is_err());
        let result = call_tool(&state, &auth, None, "route_list", &serde_json::json!({}));
        assert!(result.is_err(), "non-loopback read without token denied");
    }

    #[test]
    fn adversarial_unknown_tool_denied() {
        let state = test_state();
        let auth = OperatorAuth {
            bind_is_loopback: true,
            token: None,
        };
        let response = handle_jsonrpc(
            &state,
            &auth,
            None,
            &serde_json::json!({"id": 1, "jsonrpc": "2.0", "method": "tools/call", "params": {"name": "rm_rf", "arguments": {}}}),
        );
        assert!(response.get("error").is_some());
    }

    #[test]
    fn validation_tools_list_and_read_call() {
        let state = test_state();
        let auth = OperatorAuth {
            bind_is_loopback: true,
            token: None,
        };
        let response = handle_jsonrpc(
            &state,
            &auth,
            None,
            &serde_json::json!({"id": 1, "jsonrpc": "2.0", "method": "tools/list"}),
        );
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), TOOLS.len());
        let call = handle_jsonrpc(
            &state,
            &auth,
            None,
            &serde_json::json!({"id": 2, "jsonrpc": "2.0", "method": "tools/call", "params": {"name": "route_list", "arguments": {}}}),
        );
        assert!(call.get("result").is_some(), "{call}");
    }

    #[test]
    fn validation_tool_table_alphabetical() {
        let names: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }
}
