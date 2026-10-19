// #################################################################
// /qompassai/vongola/crates/vongola-mcp/src/rpc.rs
// Qompass AI — vongola-mcp JSON-RPC / MCP dispatch
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

//! One JSON-RPC 2.0 frame in, at most one frame out. Protocol
//! faults get the standard codes (-32700 parse, -32600 invalid
//! request, -32601 unknown method, -32602 invalid params —
//! including an unknown tool name). Notifications (no `id`) never
//! get a reply. Batches are refused: MCP does not use them.
//! A tool that cannot read the daemon still answers the call, as
//! an MCP tool error (`isError: true`) carrying the structured
//! `{code, message}` — the protocol worked, the data is
//! unavailable.

use serde_json::{Value, json};

use crate::daemon::Source;
use crate::tools;

pub const INVALID_PARAMS: i64 = -32602;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const PARSE_ERROR: i64 = -32700;
/// Newest first; the first entry is offered when the client asks
/// for a version this server does not know.
pub const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

pub fn error_frame(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({"error": {"code": code, "message": message.into()}, "id": id, "jsonrpc": "2.0"})
}

fn result_frame(id: Value, result: Value) -> Value {
    json!({"id": id, "jsonrpc": "2.0", "result": result})
}

/// Handle one line of input. `None` means: send nothing.
pub fn handle_line(line: &str, source: &dyn Source) -> Option<Value> {
    let request: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(e) => {
            return Some(error_frame(
                Value::Null,
                PARSE_ERROR,
                format!("parse error: {e}"),
            ));
        }
    };
    handle_value(&request, source)
}

pub fn handle_value(request: &Value, source: &dyn Source) -> Option<Value> {
    let Some(object) = request.as_object() else {
        let message = if request.is_array() {
            "batch requests are not supported"
        } else {
            "request must be a JSON object"
        };
        return Some(error_frame(Value::Null, INVALID_REQUEST, message));
    };
    let id = object.get("id").cloned();
    if let Some(id) = &id
        && !(id.is_string() || id.is_i64() || id.is_u64() || id.is_null())
    {
        return Some(error_frame(
            Value::Null,
            INVALID_REQUEST,
            "id must be a string, an integer, or null",
        ));
    }
    let reply_id = id.clone().unwrap_or(Value::Null);
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(error_frame(
            reply_id,
            INVALID_REQUEST,
            "jsonrpc must be \"2.0\"",
        ));
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return Some(error_frame(
            reply_id,
            INVALID_REQUEST,
            "method must be a string",
        ));
    };
    let outcome = dispatch(method, object.get("params"), source);
    // Notifications are fire-and-forget, errors included.
    id.as_ref()?;
    Some(match outcome {
        Ok(result) => result_frame(reply_id, result),
        Err((code, message)) => error_frame(reply_id, code, message),
    })
}

fn dispatch(
    method: &str,
    params: Option<&Value>,
    source: &dyn Source,
) -> Result<Value, (i64, String)> {
    match method {
        "initialize" => Ok(initialize(params)),
        "notifications/cancelled" | "notifications/initialized" => Ok(Value::Null),
        "ping" => Ok(json!({})),
        "tools/call" => tools_call(params, source),
        "tools/list" => Ok(json!({
            "tools": tools::TOOLS.iter().map(|tool| json!({
                "annotations": {"idempotentHint": true, "openWorldHint": false, "readOnlyHint": true},
                "description": tool.description,
                "inputSchema": {"additionalProperties": false, "properties": {}, "type": "object"},
                "name": tool.name,
            })).collect::<Vec<_>>()
        })),
        other => Err((METHOD_NOT_FOUND, format!("unknown method: {other}"))),
    }
}

fn initialize(params: Option<&Value>) -> Value {
    let requested = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str);
    let version = PROTOCOL_VERSIONS
        .iter()
        .find(|known| Some(**known) == requested)
        .unwrap_or(&PROTOCOL_VERSIONS[0]);
    json!({
        "capabilities": {"tools": {"listChanged": false}},
        "instructions": "Read-only view of a running vongola daemon (routes, certificates, TLS, upstreams, logs). No tool changes anything.",
        "protocolVersion": version,
        "serverInfo": {"name": "vongola-mcp", "version": env!("CARGO_PKG_VERSION")},
    })
}

fn tools_call(params: Option<&Value>, source: &dyn Source) -> Result<Value, (i64, String)> {
    let params = params.and_then(Value::as_object).ok_or((
        INVALID_PARAMS,
        "tools/call needs a params object".to_string(),
    ))?;
    let name = params.get("name").and_then(Value::as_str).ok_or((
        INVALID_PARAMS,
        "tools/call needs a string `name`".to_string(),
    ))?;
    let spec = tools::tool_spec(name).ok_or((INVALID_PARAMS, format!("unknown tool: {name}")))?;
    match params.get("arguments") {
        None | Some(Value::Null) => {}
        Some(Value::Object(arguments)) if arguments.is_empty() => {}
        Some(Value::Object(_)) => {
            return Err((INVALID_PARAMS, format!("{} takes no arguments", spec.name)));
        }
        Some(_) => return Err((INVALID_PARAMS, "arguments must be an object".to_string())),
    }
    Ok(match tools::call(source, spec.name) {
        Ok(value) => json!({
            "content": [{"text": serde_json::to_string_pretty(&value).unwrap_or_default(), "type": "text"}],
            "isError": false,
            "structuredContent": value,
        }),
        Err(error) => {
            let body = json!({"error": {"code": error.code, "message": error.message}});
            json!({
                "content": [{"text": body.to_string(), "type": "text"}],
                "isError": true,
                "structuredContent": body,
            })
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::tests::{Fixture, live_fixture};

    fn down() -> Fixture {
        Fixture {
            metrics: None,
            state: None,
        }
    }

    fn code(frame: &Value) -> i64 { frame["error"]["code"].as_i64().unwrap_or(0) }

    #[test]
    fn adversarial_malformed_frames() {
        for (line, expected) in [
            ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":", PARSE_ERROR),
            ("\u{0}\u{1}garbage", PARSE_ERROR),
            (
                "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}]",
                INVALID_REQUEST,
            ),
            ("42", INVALID_REQUEST),
            ("{\"id\":1,\"method\":\"ping\"}", INVALID_REQUEST),
            (
                "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"ping\"}",
                INVALID_REQUEST,
            ),
            (
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":7}",
                INVALID_REQUEST,
            ),
            (
                "{\"jsonrpc\":\"2.0\",\"id\":{\"x\":1},\"method\":\"ping\"}",
                INVALID_REQUEST,
            ),
            (
                "{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"ping\"}",
                INVALID_REQUEST,
            ),
        ] {
            let frame = handle_line(line, &down()).expect("protocol faults always answer");
            assert_eq!(code(&frame), expected, "{line}: {frame}");
            assert_eq!(frame["jsonrpc"], "2.0");
        }
    }

    #[test]
    fn adversarial_missing_and_bad_params() {
        for params in [
            Value::Null,
            json!("cert_status"),
            json!({}),
            json!({"name": 5}),
            json!({"name": "tls_stats", "arguments": [1]}),
            json!({"name": "tls_stats", "arguments": {"host": "x"}}),
        ] {
            let mut request = json!({"id": 9, "jsonrpc": "2.0", "method": "tools/call"});
            if !params.is_null() {
                request["params"] = params.clone();
            }
            let frame = handle_value(&request, &live_fixture()).unwrap();
            assert_eq!(code(&frame), INVALID_PARAMS, "{params}: {frame}");
            assert_eq!(frame["id"], 9);
        }
    }

    #[test]
    fn adversarial_notifications_never_answered_and_mutations_absent() {
        for request in [
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "method": "no/such/method"}),
            json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "config_reload"}}),
        ] {
            assert!(
                handle_value(&request, &live_fixture()).is_none(),
                "{request}"
            );
        }
        for name in [
            "config_reload",
            "rotate_self_signed",
            "../cert_status",
            "CERT_STATUS",
        ] {
            let request = json!({"id": 1, "jsonrpc": "2.0", "method": "tools/call", "params": {"name": name}});
            let frame = handle_value(&request, &live_fixture()).unwrap();
            assert_eq!(code(&frame), INVALID_PARAMS, "{name}");
        }
        let frame = handle_value(
            &json!({"id": 2, "jsonrpc": "2.0", "method": "resources/write"}),
            &live_fixture(),
        )
        .unwrap();
        assert_eq!(code(&frame), METHOD_NOT_FOUND);
    }

    #[test]
    fn adversarial_daemon_down_error_shape() {
        let request = json!({"id": "a", "jsonrpc": "2.0", "method": "tools/call", "params": {"name": "tls_stats"}});
        let frame = handle_value(&request, &down()).unwrap();
        assert!(
            frame.get("error").is_none(),
            "tool failure is not a protocol error"
        );
        let result = &frame["result"];
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["structuredContent"]["error"]["code"],
            "daemon.unavailable"
        );
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, result["structuredContent"]);
    }

    #[test]
    fn validation_initialize_negotiates_version() {
        let frame = handle_value(
            &json!({"id": 0, "jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}),
            &down(),
        )
        .unwrap();
        assert_eq!(frame["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(frame["result"]["serverInfo"]["name"], "vongola-mcp");
        let frame = handle_value(
            &json!({"id": 0, "jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}),
            &down(),
        )
        .unwrap();
        assert_eq!(frame["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
    }

    #[test]
    fn validation_tools_list_and_call() {
        let list = handle_value(
            &json!({"id": 1, "jsonrpc": "2.0", "method": "tools/list"}),
            &down(),
        )
        .unwrap();
        let tools = list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), tools::TOOLS.len());
        assert!(
            tools
                .iter()
                .all(|t| t["annotations"]["readOnlyHint"] == true)
        );
        for tool in tools::TOOLS {
            let frame = handle_value(
                &json!({"id": 3, "jsonrpc": "2.0", "method": "tools/call", "params": {"name": tool.name, "arguments": {}}}),
                &live_fixture(),
            )
            .unwrap();
            assert_eq!(frame["result"]["isError"], false, "{}: {frame}", tool.name);
            assert!(frame["result"]["structuredContent"]["fetched_at_unix"].is_u64());
        }
    }
}
