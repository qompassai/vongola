//! Demonstrates one modern-era stdio session against the built `vongola-mcp` server: server/discover, tools/list, and one read-only `routes_list` call, using the repo's own examples/qompass.yaml config. Expected output: server name/version, the read-only tool names, and the routes result — with no vongola daemon running that is the structured `daemon.unavailable` tool error, which is the designed answer. (This fleet speaks MCP era 2026-07-28 only — sessions open with `server/discover`, not the legacy `initialize` handshake, which the era guard refuses with -32022.)

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Per-response read deadline: a wedged server fails the run instead
/// of hanging it.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
/// The one protocol era this fleet speaks (D-113).
const PROTOCOL_VERSION: &str = "2026-07-28";

/// A spawned server plus a line channel fed by a reader thread, so
/// every read is bounded by `RESPONSE_TIMEOUT`.
struct Session {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    next_id: u64,
}

impl Session {
    fn spawn(mut command: Command) -> Result<Session, String> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn server: {e}"))?;
        let stdin = child.stdin.take().ok_or("server stdin not piped")?;
        let stdout = child.stdout.take().ok_or("server stdout not piped")?;
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
        Ok(Session {
            child,
            stdin,
            lines: rx,
            next_id: 0,
        })
    }

    /// Send one request frame; return the response correlated by id.
    fn request(&mut self, method: &str, extra_params: Value) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        let mut params = json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientInfo": {"name": "stdio-session-example", "version": "0"},
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        });
        if let (Some(dst), Some(src)) = (params.as_object_mut(), extra_params.as_object()) {
            for (key, value) in src {
                dst.insert(key.clone(), value.clone());
            }
        }
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let mut line = serde_json::to_string(&frame).map_err(|e| format!("encode frame: {e}"))?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|()| self.stdin.flush())
            .map_err(|e| format!("write frame: {e}"))?;
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(format!("timed out awaiting response id {id}"));
            }
            let raw = self
                .lines
                .recv_timeout(remaining)
                .map_err(|e| format!("server output closed awaiting id {id}: {e}"))?;
            let value: Value =
                serde_json::from_str(&raw).map_err(|e| format!("non-JSON frame: {e}: {raw}"))?;
            if value["id"] == json!(id) {
                return Ok(value);
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

const BIN_NAME: &str = "vongola-mcp";
const CARGO_BIN_EXE: Option<&str> = option_env!("CARGO_BIN_EXE_vongola-mcp");

/// Locate the built server binary. Order: cargo's `CARGO_BIN_EXE_*`
/// when set, the sibling of this example in the target profile dir
/// (classic layout), then a bounded search of the manifest's target
/// tree (primo's build-dir layout puts final artifacts under
/// `target/<profile>/build/<pkg>/<hash>/out/`).
fn binary_path() -> Result<PathBuf, String> {
    if let Some(path) = CARGO_BIN_EXE {
        return Ok(PathBuf::from(path));
    }
    let bin = BIN_NAME;
    let sibling = std::env::current_exe().ok().and_then(|exe| {
        exe.parent()
            .and_then(|d| d.parent())
            .map(|dir| dir.join(bin))
    });
    if let Some(sibling) = sibling.filter(|path| path.is_file()) {
        return Ok(sibling);
    }
    let target_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target");
    for profile in ["debug", "release"] {
        let direct = target_root.join(profile).join(bin);
        if direct.is_file() {
            return Ok(direct);
        }
        let build_dir = target_root.join(profile).join("build");
        let Ok(packages) = std::fs::read_dir(&build_dir) else {
            continue;
        };
        for package in packages.flatten() {
            let Ok(hashes) = std::fs::read_dir(package.path()) else {
                continue;
            };
            for hash in hashes.flatten() {
                let candidate = hash.path().join("out").join(bin);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(format!(
        "server binary {bin} not found under {} — build the package first (cargo build)",
        target_root.to_string_lossy()
    ))
}

fn run() -> Result<(), String> {
    let binary = binary_path()?;
    // The repo's own example config (admin listener 127.0.0.1:9091);
    // CARGO_MANIFEST_DIR is this crate's directory at build time.
    let config = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/qompass.yaml")
        .canonicalize()
        .map_err(|e| format!("locate examples/qompass.yaml: {e}"))?;
    let mut command = Command::new(&binary);
    command.arg("--config").arg(&config);
    let mut session = Session::spawn(command)?;

    let discover = session.request("server/discover", json!({}))?;
    let info = &discover["result"]["_meta"]["io.modelcontextprotocol/serverInfo"];
    println!(
        "discover: server={} version={} eras={}",
        info["name"].as_str().unwrap_or("?"),
        info["version"].as_str().unwrap_or("?"),
        discover["result"]["supportedVersions"],
    );

    let list = session.request("tools/list", json!({}))?;
    let tools = list["result"]["tools"]
        .as_array()
        .ok_or("tools/list result has no tools array")?;
    println!("tools/list: {} tools", tools.len());
    for tool in tools {
        println!("  - {}", tool["name"].as_str().unwrap_or("?"));
    }

    // Read-only representative call; argument-free by design.
    let call = session.request(
        "tools/call",
        json!({"name": "routes_list", "arguments": {}}),
    )?;
    let result = &call["result"];
    if result.is_null() {
        return Err(format!("tools/call returned an RPC error frame: {call}"));
    }
    let is_error = result["isError"].as_bool().unwrap_or(false);
    let summary = if is_error {
        result["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_owned()
    } else {
        let structured = &result["structuredContent"];
        if structured.is_null() {
            result["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_owned()
        } else {
            structured.to_string()
        }
    };
    let one_line: String = summary.chars().take(240).collect();
    println!("tools/call routes_list: isError={is_error} {one_line}");
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => println!("stdio_session: OK"),
        Err(error) => {
            eprintln!("stdio_session: FAILED: {error}");
            std::process::exit(1);
        }
    }
}
