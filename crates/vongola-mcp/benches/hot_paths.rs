//! Hot-path benchmarks for the `vongola-mcp` MCP server: cold start to discover, tools/list latency, and `routes_list` call latency over one warm stdio session (no daemon running — the structured daemon.unavailable error path). Hand-rolled on std::time; run with `cargo bench --bench hot_paths -p vongola-mcp`.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Spawns for the cold-start workload (bounded, named).
const COLD_STARTS: usize = 10;
/// Warmup requests before each measured loop.
const WARMUP: usize = 20;
/// Measured requests per warm workload (bounded, named).
const MEASURED: usize = 200;
/// Per-response read deadline.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
/// The one protocol era this fleet speaks (D-113).
const PROTOCOL_VERSION: &str = "2026-07-28";

struct Session {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    next_id: u64,
}

impl Session {
    fn spawn(command: &mut Command) -> Session {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn server");
        let stdin = child.stdin.take().expect("server stdin");
        let stdout = child.stdout.take().expect("server stdout");
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx.send(line.clone()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        Session {
            child,
            stdin,
            lines: rx,
            next_id: 0,
        }
    }

    fn request(&mut self, method: &str, extra_params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let mut params = json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientInfo": {"name": "hot-paths-bench", "version": "0"},
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        });
        if let (Some(dst), Some(src)) = (params.as_object_mut(), extra_params.as_object()) {
            for (key, value) in src {
                dst.insert(key.clone(), value.clone());
            }
        }
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let mut line = serde_json::to_string(&frame).expect("encode frame");
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).expect("write frame");
        self.stdin.flush().expect("flush frame");
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timed out awaiting id {id}");
            let raw = self.lines.recv_timeout(remaining).expect("server output");
            let value: Value = serde_json::from_str(&raw).expect("frame is JSON");
            if value["id"] == json!(id) {
                return value;
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn make_command() -> Command {
    let config = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/qompass.yaml")
        .canonicalize()
        .expect("example config exists");
    let mut command = Command::new(env!("CARGO_BIN_EXE_vongola-mcp"));
    command.arg("--config").arg(config);
    command
}

fn report(name: &str, total: Duration, iterations: usize) {
    let per = total.as_secs_f64() / iterations as f64;
    println!(
        "{name}: {iterations} iters, total {:.1} ms, {:.1} us/op, {:.0} ops/s",
        total.as_secs_f64() * 1e3,
        per * 1e6,
        1.0 / per,
    );
}

fn main() {
    // Cold start: spawn -> discover response, per spawn.
    let started = Instant::now();
    for _ in 0..COLD_STARTS {
        let mut session = Session::spawn(&mut make_command());
        let discover = session.request("server/discover", json!({}));
        assert!(
            discover["result"].is_object(),
            "discover failed: {discover}"
        );
    }
    report("cold_start_discover", started.elapsed(), COLD_STARTS);

    // Warm session workloads.
    let mut session = Session::spawn(&mut make_command());
    let discover = session.request("server/discover", json!({}));
    assert!(
        discover["result"].is_object(),
        "discover failed: {discover}"
    );
    for _ in 0..WARMUP {
        let _ = session.request("tools/list", json!({}));
        let _ = session.request(
            "tools/call",
            json!({"name": "routes_list", "arguments": {}}),
        );
    }
    let started = Instant::now();
    for _ in 0..MEASURED {
        let list = session.request("tools/list", json!({}));
        assert!(
            list["result"]["tools"].is_array(),
            "tools/list failed: {list}"
        );
    }
    report("tools_list", started.elapsed(), MEASURED);

    let started = Instant::now();
    for _ in 0..MEASURED {
        let call = session.request(
            "tools/call",
            json!({"name": "routes_list", "arguments": {}}),
        );
        assert!(call["result"].is_object(), "tools/call failed: {call}");
    }
    report("tool_call_routes_list", started.elapsed(), MEASURED);
}
