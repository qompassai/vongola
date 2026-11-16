//! `vongola-tui`: the fleet-pattern terminal console for
//! vongola-mcp (programme D-1562, pattern DESIGN SS D2).
//!
//! vongola-mcp is the read-only operator-instrumentation surface
//! over a running vongola daemon: five argument-free tools
//! (`cert_status`, `log_counters`, `routes_list`, `tls_stats`,
//! `upstream_health`). Every tool is read-only, so this console has
//! no consequential calls: plan/auto staging is implemented honestly
//! as the fleet's universal staging discipline (DESIGN SS D3), not
//! as a safety gate over writes that do not exist.
//!
//! # Layout (DESIGN SS D2)
//!
//! - [`facade`]: the narrow [`facade::VongolaFacade`] trait the UI programs
//!   against. vongola-mcp is a server-only binary (no library crate), so the
//!   real implementation is the DESIGN SS D2 fallback: an MCP stdio client
//!   spawning the member's own server binary. [`facade::FakeFacade`] serves
//!   every test.
//! - [`events`]: the typed event stream the Log screen renders and the trigger
//!   engine consumes.
//! - [`triggers`]: the DESIGN SS D4 rule engine (data rules, bounded
//!   predicates, depth cap, event-hash idempotency, JSONL audit with
//!   `origin_lane` + `content_label` stamped from birth, D-1030).
//! - [`app`]: the screen state machine, plan/auto modes, and the non-TTY line
//!   mode sharing one execute path.
//! - [`panels`] / [`screens`]: pure widget constructors and the plain-data
//!   screen models behind them.
//!
//! # Media honesty (DESIGN SS D5)
//!
//! vongola produces no image, video, or diagram artifacts; it is an
//! operator-instrumentation surface. The Media screen therefore
//! reports `Unavailable`, labelled as such — no rung is faked.
//!
//! # Limits
//!
//! Every queue, buffer, input line, and payload carries a named
//! bound: [`LOG_LINES_MAX`], [`EVENTS_MAX`], [`INPUT_LINE_BYTES_MAX`],
//! [`RESULT_BYTES_MAX`], [`AUDIT_TAIL_MAX`], [`SEEN_KEYS_MAX`].

#![forbid(unsafe_code)]

use std::fmt;

pub mod app;
pub mod events;
pub mod facade;
pub mod panels;
pub mod screens;
pub mod triggers;

pub use app::{App, LineOutcome, Mode, Screen, StagedAction};
pub use events::{Event, EventKind};
pub use facade::{FakeFacade, McpStdioFacade, StatusInfo, ToolInfo, VongolaFacade};
pub use triggers::{TriggerEngine, TriggerRule};

/// Maximum lines retained in the Log / Live buffer (oldest dropped).
pub const LOG_LINES_MAX: usize = 500;
/// Maximum typed events retained on the event stream.
pub const EVENTS_MAX: usize = 256;
/// Maximum bytes in one line-mode input line, newline included.
pub const INPUT_LINE_BYTES_MAX: usize = 8_192;
/// Maximum bytes accepted in one tool result before it is refused
/// as oversized rather than rendered.
pub const RESULT_BYTES_MAX: usize = 1_048_576;
/// Maximum audit lines tailed into the Fleet panel.
pub const AUDIT_TAIL_MAX: usize = 50;
/// Maximum idempotency keys the trigger engine remembers.
pub const SEEN_KEYS_MAX: usize = 1_024;
/// Maximum rules loaded from one `triggers.toml`.
pub const RULES_MAX: usize = 64;
/// Maximum bytes read from one `triggers.toml` file.
pub const RULES_FILE_BYTES_MAX: u64 = 256_000;
/// Hard ceiling on trigger chain depth (DESIGN SS D4).
pub const DEPTH_CEILING: u32 = 2;
/// The member's own tool names, alphabetical — the complete
/// read-only surface of vongola-mcp 1.0.0 (`tools.rs` TOOLS).
pub const TOOL_NAMES: [&str; 5] = [
    "cert_status",
    "log_counters",
    "routes_list",
    "tls_stats",
    "upstream_health",
];

/// Typed failures for the TUI's own operations. Expected failures
/// (bad input, an unreachable server, a refused rule file) are
/// values, never panics; internal invariants use `assert!`.
#[derive(Debug)]
pub enum TuiError {
    /// Caller-supplied input failed validation.
    Invalid(String),
    /// A named entry (tool, screen, rule) does not exist.
    NotFound(String),
    /// The MCP server or a trigger target reported a failure.
    Backend(String),
    /// A payload exceeded its named byte bound.
    Oversized(String),
    /// An I/O failure at the terminal, process, or file boundary.
    Io(std::io::Error),
}

impl fmt::Display for TuiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TuiError::Invalid(msg) => write!(f, "invalid: {msg}"),
            TuiError::NotFound(msg) => write!(f, "not_found: {msg}"),
            TuiError::Backend(msg) => write!(f, "backend: {msg}"),
            TuiError::Oversized(msg) => write!(f, "oversized: {msg}"),
            TuiError::Io(err) => write!(f, "io: {err}"),
        }
    }
}

impl std::error::Error for TuiError {}

impl From<std::io::Error> for TuiError {
    fn from(err: std::io::Error) -> TuiError { TuiError::Io(err) }
}

/// Whether `name` is one of the member's five tools.
pub fn is_tool_name(name: &str) -> bool { TOOL_NAMES.contains(&name) }
