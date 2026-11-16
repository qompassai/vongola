//! The member's screens as plain-data models (DESIGN SS D2):
//! pure constructors over the app's public state, shared by the
//! full-screen draw and the line mode, and rendered through
//! ratatui `TestBackend` in tests.

use crate::app::App;
use crate::facade::VongolaFacade;
use crate::{AUDIT_TAIL_MAX, TOOL_NAMES};

/// Maximum characters in one rendered screen line.
pub const LINE_CHARS_MAX: usize = 200;
/// Maximum lines in one screen model.
pub const PANEL_LINES_MAX: usize = 64;

/// A screen rendered as plain lines (the shared model).
#[derive(Debug, Clone, PartialEq)]
pub struct ScreenModel {
    /// Screen title line.
    pub title: String,
    /// Body lines, each within [`LINE_CHARS_MAX`].
    pub lines: Vec<String>,
}

/// Truncate one line to the named bound, on a char boundary.
pub fn truncate_line(text: &str) -> String {
    if text.chars().count() <= LINE_CHARS_MAX {
        return text.to_string();
    }
    let mut out: String = text.chars().take(LINE_CHARS_MAX - 1).collect();
    out.push('~');
    out
}

fn model(title: String, lines: Vec<String>) -> ScreenModel {
    let lines: Vec<String> = lines
        .into_iter()
        .take(PANEL_LINES_MAX)
        .map(|line| truncate_line(&line))
        .collect();
    ScreenModel { title, lines }
}

/// Overview: member identity, reachability, tool count, mode,
/// trigger-rule count, last events.
pub fn overview_model<F: VongolaFacade>(app: &App<F>) -> ScreenModel {
    let mut lines = Vec::new();
    match &app.status {
        Some(status) => {
            lines.push(format!(
                "server: {} {} ({})",
                status.server_name,
                status.server_version,
                if status.reachable {
                    "reachable"
                } else {
                    "UNREACHABLE"
                }
            ));
            lines.push(format!("detail: {}", status.detail));
            lines.push(format!("tools: {}", status.tool_count));
        }
        None => lines.push("server: not queried yet (run `status`)".to_string()),
    }
    lines.push(format!(
        "mode: {} (plan stages, auto executes)",
        app.mode.name()
    ));
    lines.push("consequential calls: none — all five vongola-mcp tools are read-only".to_string());
    lines.push(format!(
        "trigger rules: {} declared",
        app.engine.rules().len()
    ));
    lines.push(format!("events recorded: {}", app.events.len()));
    if let Some(last) = app.events.back() {
        lines.push(format!("last event: {}", last.describe()));
    }
    model("vongola-tui — Overview".to_string(), lines)
}

/// Workflows: the five read-only operations as a selectable list
/// with the run controls that honestly apply.
pub fn workflows_model<F: VongolaFacade>(app: &App<F>) -> ScreenModel {
    let mut lines = Vec::new();
    lines.push(format!(
        "mode: {} — `run <tool>` {}",
        app.mode.name(),
        if app.mode == crate::Mode::Plan {
            "stages the call for approval"
        } else {
            "executes directly"
        }
    ));
    lines.push(
        "provider: unavailable — vongola routes no model calls (honestly absent, SS D3)"
            .to_string(),
    );
    for (index, name) in TOOL_NAMES.iter().enumerate() {
        let marker = if index == app.selected { ">" } else { " " };
        let description = app
            .tools
            .iter()
            .find(|tool| tool.name == *name)
            .map(|tool| tool.description.as_str())
            .unwrap_or("");
        lines.push(format!("{marker} {name}: {description}"));
    }
    if let Some(staged) = &app.staged {
        lines.push(format!(
            "staged: call {} (approve with `approve`, discard with `abort`)",
            staged.tool
        ));
    }
    model("vongola-tui — Workflows".to_string(), lines)
}

/// Log / Live: the bounded typed event stream plus result lines.
pub fn log_model<F: VongolaFacade>(app: &App<F>) -> ScreenModel {
    let mut lines: Vec<String> = app
        .events
        .iter()
        .map(|event| format!("event: {}", event.describe()))
        .collect();
    lines.extend(app.log.iter().cloned());
    if lines.is_empty() {
        lines.push("(no runs yet)".to_string());
    }
    model("vongola-tui — Log / Live".to_string(), lines)
}

/// Fleet: declared trigger rules with enable state, staged
/// firings, and the audit tail.
pub fn fleet_model<F: VongolaFacade>(app: &App<F>) -> ScreenModel {
    let mut lines = Vec::new();
    lines.push("trigger transport: refusing (no live MCP client wired in rung 1)".to_string());
    for rule in app.engine.rules() {
        lines.push(format!(
            "rule {} [{}] on {} -> {}::{} mode={} lane={}/{}",
            rule.id,
            if rule.enabled { "enabled" } else { "disabled" },
            rule.on.event,
            rule.then.mcp,
            rule.then.tool,
            rule.mode,
            rule.origin_lane,
            rule.content_label,
        ));
    }
    if app.engine.rules().is_empty() {
        lines.push("rules: none declared".to_string());
    }
    for firing in &app.pending_firings {
        lines.push(format!(
            "staged firing: {} -> {}::{} (approve with `approve`)",
            firing.rule_id, firing.mcp, firing.tool
        ));
    }
    lines.push("audit tail:".to_string());
    for line in app.engine.audit_tail().iter().rev().take(AUDIT_TAIL_MAX) {
        lines.push(format!("  {line}"));
    }
    model("vongola-tui — Fleet / MCP".to_string(), lines)
}

/// Media: honestly Unavailable. vongola is an operator
/// instrumentation surface with no image, video, or diagram
/// artifacts (DESIGN SS D5 honesty ladder) — labelled, not faked.
pub fn media_model<F: VongolaFacade>(_app: &App<F>) -> ScreenModel {
    model(
        "vongola-tui — Media".to_string(),
        vec![
            "Media: Unavailable".to_string(),
            "vongola-mcp exposes daemon counters and state only; it produces".to_string(),
            "no image, video, or diagram artifacts to view. No rung is faked:".to_string(),
            "there is no kitty/sixel/half-block rendering here because there".to_string(),
            "is nothing to render.".to_string(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade::FakeFacade;

    #[test]
    fn validation_models_render_all_screens() {
        let mut app = App::new(FakeFacade::healthy());
        app.refresh_status().unwrap();
        for screen in crate::Screen::all() {
            app.screen = screen;
            let rendered = app.model();
            assert!(!rendered.title.is_empty());
            assert!(!rendered.lines.is_empty(), "{}", screen.name());
        }
        let media = media_model(&app);
        assert!(media.lines[0].contains("Unavailable"));
    }

    #[test]
    fn adversarial_truncation_is_char_boundary_safe() {
        let long = "x".repeat(LINE_CHARS_MAX + 50);
        let out = truncate_line(&long);
        assert_eq!(out.chars().count(), LINE_CHARS_MAX);
        let unicode = "é".repeat(LINE_CHARS_MAX + 10);
        assert_eq!(truncate_line(&unicode).chars().count(), LINE_CHARS_MAX);
    }
}
