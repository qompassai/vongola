// #################################################################
// /qompassai/vongola/crates/vongola-mcp/src/server.rs
// Qompass AI — vongola-mcp rmcp server surface
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

//! The served MCP surface: the five read-only operator tools,
//! on the rmcp SDK behind the era guard ([`crate::guard`]),
//! modern era only (2026-07-28) since v0.2 (D-113).
//!
//! The domain logic — [`crate::tools`] over a [`Source`] — is
//! unchanged from the hand-rolled era; only the framing moved.
//! Tool argument validation and result shaping keep the
//! hand-rolled transport's exact contract: an unknown tool or a
//! non-empty argument object is a protocol error (`-32602`); a
//! tool that cannot read the daemon answers the call as an MCP
//! tool error (`isError: true`) carrying the structured
//! `{code, message}` body — the protocol worked, the data is
//! unavailable.
//!
//! [`Source`]: crate::daemon::Source

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    ServerConfig as RmcpServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::async_rw::AsyncRwTransport;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde_json::{Map, Value, json};

use crate::daemon::{DaemonError, Source};
use crate::guard;
use crate::tools;

/// The instructions text the hand-rolled `initialize` result
/// carried; in the modern era it rides `server/discover`.
pub const INSTRUCTIONS: &str = "Read-only view of a running vongola daemon (routes, certificates, TLS, upstreams, logs). No tool changes anything.";

/// The tool surface as plain JSON, in exactly the shape the
/// hand-rolled `tools/list` emitted (same key set per tool, the
/// argument-free schema, the read-only annotations). This is the
/// parity target: [`rmcp_tools`] converts these values, and the
/// wire payload cannot drift from them.
pub fn tool_definitions() -> Vec<Value> {
    tools::TOOLS
        .iter()
        .map(|tool| {
            json!({
                "annotations": {"idempotentHint": true, "openWorldHint": false, "readOnlyHint": true},
                "description": tool.description,
                "inputSchema": {"additionalProperties": false, "properties": {}, "type": "object"},
                "name": tool.name,
            })
        })
        .collect()
}

/// The served tool surface as rmcp [`Tool`] values, converted
/// from [`tool_definitions`] so the wire payload cannot drift
/// from the hand-written definitions. Conversion failure is a
/// build-time class bug (the definitions are compiled in),
/// surfaced as an internal error, never a silent drop.
fn rmcp_tools() -> Result<Vec<Tool>, String> {
    let mut converted = Vec::new();
    for def in tool_definitions() {
        let tool: Tool =
            serde_json::from_value(def).map_err(|e| format!("tool definition: {e}"))?;
        converted.push(tool);
    }
    Ok(converted)
}

/// Why a tool call did not produce a value: a protocol fault
/// (the caller's error, answered as a JSON-RPC error) or a tool
/// failure (the daemon could not be read, answered as an
/// `isError` result). The hand-rolled transport kept these two
/// channels distinct; so does this one.
pub enum CallError {
    Protocol(ErrorData),
    Tool(DaemonError),
}

/// Run one tool call at the domain level: validate the name and
/// the argument-free contract, then call the tool. This is the
/// whole of what the hand-rolled `tools/call` dispatch did
/// beyond framing.
pub fn call_domain(
    source: &dyn Source,
    name: &str,
    arguments: Option<Map<String, Value>>,
) -> Result<Value, CallError> {
    let spec = tools::tool_spec(name).ok_or_else(|| {
        CallError::Protocol(ErrorData::invalid_params(
            format!("unknown tool: {name}"),
            None,
        ))
    })?;
    match arguments {
        None => {}
        Some(arguments) if arguments.is_empty() => {}
        Some(_) => {
            return Err(CallError::Protocol(ErrorData::invalid_params(
                format!("{} takes no arguments", spec.name),
                None,
            )));
        }
    }
    tools::call(source, spec.name).map_err(CallError::Tool)
}

/// The structured body of a tool failure, identical in the text
/// block and in `structuredContent`, as the hand-rolled
/// transport emitted it.
pub fn tool_error_body(error: &DaemonError) -> Value {
    json!({"error": {"code": error.code, "message": error.message}})
}

/// The rmcp handler: the domain behind the SDK. Tool calls run
/// on a blocking task — a call performs loopback HTTP with
/// multi-second timeouts against the daemon, and that wait must
/// not stall the runtime's event loop (a concurrent `tools/list`
/// or `ping` still answers while a slow daemon read is in
/// flight).
pub struct VongolaHandler<S> {
    source: Arc<S>,
}

impl<S> VongolaHandler<S> {
    /// Wrap a daemon source for SDK serving.
    pub fn new(source: S) -> VongolaHandler<S> {
        VongolaHandler {
            source: Arc::new(source),
        }
    }
}

impl<S: Source + Send + Sync + 'static> ServerHandler for VongolaHandler<S> {
    /// Modern era only: `server/discover` advertises exactly this
    /// one version and the SDK validates every request's `_meta`
    /// against it.
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
    }

    fn get_info(&self) -> RmcpServerConfig {
        RmcpServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "vongola-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = rmcp_tools()
            .map_err(|e| ErrorData::internal_error(format!("internal_error: {e}"), None))?;
        Ok(ListToolsResult {
            tools,
            ..Default::default()
        })
    }

    /// Tool failures stay MCP `isError` results (never RPC
    /// errors), with the same payloads the hand-rolled transport
    /// produced: pretty-printed JSON text + `structuredContent`
    /// on success, the typed `{code, message}` body on failure.
    /// The one addition is the modern spec's `resultType`
    /// discriminator, set by the SDK constructors.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let source = Arc::clone(&self.source);
        let name = request.name.to_string();
        let arguments = request.arguments;
        let outcome =
            tokio::task::spawn_blocking(move || call_domain(&*source, &name, arguments)).await;
        match outcome {
            Ok(Ok(value)) => {
                let text = serde_json::to_string_pretty(&value).unwrap_or_default();
                let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
                result.structured_content = Some(value);
                Ok(result.into())
            }
            Ok(Err(CallError::Tool(error))) => {
                let body = tool_error_body(&error);
                let mut result = CallToolResult::error(vec![ContentBlock::text(body.to_string())]);
                result.structured_content = Some(body);
                Ok(result.into())
            }
            Ok(Err(CallError::Protocol(error))) => Err(error),
            Err(join) => Err(ErrorData::internal_error(
                format!("internal_error: tool task failed: {join}"),
                None,
            )),
        }
    }
}

/// Duplex buffer between the era guard and the SDK service. The
/// SDK consumes incrementally, so this only needs to cover
/// request/response bursts, not whole payloads.
const DUPLEX_BUFFER_BYTES: usize = 1024 * 1024;

/// Serve until stdin EOF: the era guard owns stdio, the SDK
/// service sits behind an in-process duplex, and a pump copies
/// its responses back to stdout through the same lock the guard
/// writes with. The `RunningService` is kept alive on
/// `waiting()` for the whole session — dropping it would close
/// the server after the first request.
async fn serve_modern<S: Source + Send + Sync + 'static>(
    handler: VongolaHandler<S>,
) -> std::io::Result<()> {
    let (client_side, server_side) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
    let (server_read, server_write) = tokio::io::split(server_side);
    let (client_read, client_write) = tokio::io::split(client_side);
    let stdout: guard::SharedStdout = Arc::new(tokio::sync::Mutex::new(tokio::io::stdout()));

    let ordering = guard::Ordering::new();
    let serve = tokio::spawn(async move {
        let transport = AsyncRwTransport::new_server(server_read, server_write);
        match handler.serve(transport).await {
            Ok(running) => running
                .waiting()
                .await
                .map(|_| ())
                .map_err(|e| std::io::Error::other(e.to_string())),
            // The client closed the connection before selecting a
            // lifecycle (a probe, a spawn check, a client that only
            // ever wanted the refusal): bare EOF is a clean end of
            // session, as it was when the transport was hand-rolled.
            Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) => Ok(()),
            Err(e) => Err(std::io::Error::other(e.to_string())),
        }
    });
    let mut pump = tokio::spawn(guard::pump(
        client_read,
        Arc::clone(&stdout),
        Arc::clone(&ordering),
    ));

    // When stdin reaches EOF the guard shuts the duplex write side
    // down, which ends the SDK service; the pump ends when the
    // service's transport drops. The pump wait is bounded as a
    // backstop: a response still in flight when the service ends
    // gets its chance to drain, but a wedged pump cannot hang exit.
    let guard_result = guard::run(tokio::io::stdin(), client_write, stdout, ordering).await;
    let serve_result = match serve.await {
        Ok(result) => result,
        Err(e) => Err(std::io::Error::other(e.to_string())),
    };
    if tokio::time::timeout(std::time::Duration::from_secs(2), &mut pump)
        .await
        .is_err()
    {
        pump.abort();
    }
    guard_result.and(serve_result)
}

/// Run the stdio MCP server until EOF on stdin.
///
/// stdout is the protocol channel — diagnostics go to stderr only.
/// Lines over [`guard::MAX_LINE_BYTES`] are refused by the era
/// guard with a typed error and the server keeps serving. Only
/// the framing runs on the async runtime; the domain is the
/// synchronous [`tools`] layer, called per request.
pub fn serve_stdio<S: Source + Send + Sync + 'static>(source: S) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve_modern(VongolaHandler::new(source)))
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

    fn canonical(value: &Value) -> String {
        fn sort(value: &Value) -> Value {
            match value {
                Value::Object(map) => {
                    let mut entries: Vec<(&String, &Value)> = map.iter().collect();
                    entries.sort_by(|a, b| a.0.cmp(b.0));
                    Value::Object(
                        entries
                            .into_iter()
                            .map(|(k, v)| (k.clone(), sort(v)))
                            .collect(),
                    )
                }
                Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
                other => other.clone(),
            }
        }
        serde_json::to_string(&sort(value)).unwrap()
    }

    #[test]
    fn rmcp_tools_match_definitions() {
        // The SDK-served surface must be the definitions, exactly:
        // same tools, same order, same schemas and annotations
        // under canonical comparison. This is the in-suite half of
        // the migration parity gate (the wire half is the probe).
        let served = serde_json::to_value(rmcp_tools().unwrap()).unwrap();
        assert_eq!(
            canonical(&served),
            canonical(&Value::Array(tool_definitions()))
        );
    }

    #[test]
    fn validation_call_domain_happy_path() {
        for tool in tools::TOOLS {
            let value = call_domain(&live_fixture(), tool.name, None)
                .ok()
                .unwrap_or_else(|| panic!("{} should succeed", tool.name));
            assert!(value["fetched_at_unix"].is_u64(), "{}", tool.name);
            let value = call_domain(&live_fixture(), tool.name, Some(Map::new()))
                .ok()
                .unwrap_or_else(|| panic!("{} should accept empty arguments", tool.name));
            assert!(value["fetched_at_unix"].is_u64(), "{}", tool.name);
        }
    }

    #[test]
    fn adversarial_call_domain_bad_params() {
        let mut args = Map::new();
        args.insert("host".to_string(), json!("x"));
        for (name, arguments) in [
            ("tls_stats", Some(args.clone())),
            ("config_reload", None),
            ("rotate_self_signed", None),
            ("../cert_status", None),
            ("CERT_STATUS", None),
        ] {
            match call_domain(&live_fixture(), name, arguments) {
                Err(CallError::Protocol(error)) => {
                    assert_eq!(error.code, rmcp::model::ErrorCode::INVALID_PARAMS, "{name}");
                }
                other => panic!("{name}: expected protocol error, got {:?}", other.is_ok()),
            }
        }
    }

    #[test]
    fn adversarial_daemon_down_error_shape() {
        // A tool failure is not a protocol error: the domain call
        // surfaces the typed daemon error, and the body the
        // handler emits carries it identically in both blocks.
        match call_domain(&down(), "tls_stats", None) {
            Err(CallError::Tool(error)) => {
                assert_eq!(error.code, "daemon.unavailable");
                let body = tool_error_body(&error);
                assert_eq!(body["error"]["code"], "daemon.unavailable");
                assert!(body["error"]["message"].is_string());
            }
            other => panic!("expected tool error, got {:?}", other.is_ok()),
        }
    }
}
