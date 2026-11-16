//! `vongola-tui` binary: parse args, build the real facade, run.
//!
//! Full-screen ratatui where a TTY exists; the non-TTY line mode
//! (same execute path) when stdout is piped or `--line` is given.
//!
//! Usage: `vongola-tui [--server PATH] [--config PATH]
//! [--triggers PATH] [--audit PATH] [--line] [--auto]`
//! - `--server <path>`: the member's own `vongola-mcp` binary to spawn
//!   (default: `vongola-mcp` on PATH).
//! - `--config <path>`: daemon config passed through to the server.
//! - `--triggers <path>`: trigger rules file (default: `triggers.toml` in the
//!   current directory when present).
//! - `--audit <path>`: JSONL trigger audit log file.
//! - `--line`: force line mode even on a TTY.
//! - `--auto`: start in auto mode (default is plan).

#![forbid(unsafe_code)]

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use vongola_tui::app::{run_fullscreen, run_line_mode};
use vongola_tui::triggers::load_rules;
use vongola_tui::{App, McpStdioFacade, Mode, TriggerEngine};

fn main() -> ExitCode {
    let mut server = PathBuf::from("vongola-mcp");
    let mut config: Option<PathBuf> = None;
    let mut triggers: Option<PathBuf> = None;
    let mut audit: Option<PathBuf> = None;
    let mut force_line = false;
    let mut auto = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut take = |label: &str| -> Result<PathBuf, ExitCode> {
            match args.next() {
                Some(value) => Ok(PathBuf::from(value)),
                None => {
                    eprintln!("vongola-tui: {label} needs a path argument");
                    Err(ExitCode::FAILURE)
                }
            }
        };
        match arg.as_str() {
            "--server" => match take("--server") {
                Ok(value) => server = value,
                Err(code) => return code,
            },
            "--config" => match take("--config") {
                Ok(value) => config = Some(value),
                Err(code) => return code,
            },
            "--triggers" => match take("--triggers") {
                Ok(value) => triggers = Some(value),
                Err(code) => return code,
            },
            "--audit" => match take("--audit") {
                Ok(value) => audit = Some(value),
                Err(code) => return code,
            },
            "--line" => force_line = true,
            "--auto" => auto = true,
            "--help" | "-h" => {
                println!(
                    "vongola-tui [--server <vongola-mcp>] [--config <vongola.yaml>] \
                     [--triggers <triggers.toml>] [--audit <audit.jsonl>] [--line] [--auto]\n\
                     Full-screen console on a TTY; line mode otherwise."
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("vongola-tui: unknown argument '{other}' (see --help)");
                return ExitCode::FAILURE;
            }
        }
    }
    let triggers_path = triggers.or_else(|| {
        let default = PathBuf::from("triggers.toml");
        default.exists().then_some(default)
    });
    let mut engine = TriggerEngine::new(Vec::new());
    if let Some(path) = &triggers_path {
        match load_rules(path) {
            Ok(rules) => engine = TriggerEngine::new(rules),
            Err(err) => {
                eprintln!("vongola-tui: cannot load {path:?}: {err}");
                return ExitCode::FAILURE;
            }
        }
    }
    if let Some(path) = audit {
        engine.set_audit_path(path);
    }
    let facade = McpStdioFacade::new(server, config);
    let mut app = App::with_engine(facade, engine);
    if auto {
        app.mode = Mode::Auto;
    }
    let result = if force_line || !std::io::stdout().is_terminal() {
        run_line_mode(&mut app)
    } else {
        run_fullscreen(&mut app)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("vongola-tui: {err}");
            ExitCode::FAILURE
        }
    }
}
