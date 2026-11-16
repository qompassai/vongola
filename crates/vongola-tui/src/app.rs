//! The screen state machine, the plan/auto staging discipline,
//! and the two run modes (full-screen ratatui + non-TTY line mode)
//! sharing one execute path (DESIGN SS D2).
//!
//! Honesty note: every vongola-mcp tool is read-only and
//! argument-free, so plan mode here is the fleet's universal
//! staging discipline — it stages the exact call and performs no
//! facade call before approval — not a guard over consequential
//! writes. There are none to guard.

use std::collections::VecDeque;
use std::io::{BufRead, Read, Write};
use std::time::Duration;

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::events::Event;
use crate::facade::{StatusInfo, ToolInfo, VongolaFacade};
use crate::screens::ScreenModel;
use crate::triggers::{PendingFiring, RefusingTransport, TriggerEngine, TriggerTransport};
use crate::{
    EVENTS_MAX, INPUT_LINE_BYTES_MAX, LOG_LINES_MAX, RESULT_BYTES_MAX, TuiError, is_tool_name,
    screens,
};

/// The comparable-capability screens (DESIGN SS D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Member identity, reachability, tool count.
    Overview,
    /// The five read-only operations, selectable.
    Workflows,
    /// Bounded scrolling event + result view.
    Log,
    /// Trigger rules, staged firings, audit tail.
    Fleet,
    /// Honestly Unavailable for this member (SS D5).
    Media,
}

impl Screen {
    /// All screens in tab order.
    pub fn all() -> [Screen; 5] {
        [
            Screen::Overview,
            Screen::Workflows,
            Screen::Log,
            Screen::Fleet,
            Screen::Media,
        ]
    }

    /// Display name.
    pub fn name(&self) -> &'static str {
        match self {
            Screen::Overview => "Overview",
            Screen::Workflows => "Workflows",
            Screen::Log => "Log / Live",
            Screen::Fleet => "Fleet",
            Screen::Media => "Media",
        }
    }

    /// Short slug used by line mode (`screen fleet`).
    pub fn slug(&self) -> &'static str {
        match self {
            Screen::Overview => "overview",
            Screen::Workflows => "workflows",
            Screen::Log => "log",
            Screen::Fleet => "fleet",
            Screen::Media => "media",
        }
    }

    /// Parse a screen slug or name (prefixes allowed).
    pub fn parse(text: &str) -> Option<Screen> {
        let text = text.trim().to_ascii_lowercase();
        if text.is_empty() {
            return None;
        }
        Screen::all().into_iter().find(|s| {
            s.slug().starts_with(&text) || s.name().to_ascii_lowercase().starts_with(&text)
        })
    }
}

/// Execution mode for workflow runs and trigger firings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Stage the call, show it, wait for approval.
    Plan,
    /// Execute declared operations directly.
    Auto,
}

impl Mode {
    /// Display name.
    pub fn name(&self) -> &'static str {
        match self {
            Mode::Plan => "plan",
            Mode::Auto => "auto",
        }
    }

    /// Parse `plan` / `auto`.
    pub fn parse(text: &str) -> Option<Mode> {
        match text.trim().to_ascii_lowercase().as_str() {
            "plan" => Some(Mode::Plan),
            "auto" => Some(Mode::Auto),
            _ => None,
        }
    }
}

/// A workflow call staged in plan mode.
#[derive(Debug, Clone, PartialEq)]
pub struct StagedAction {
    /// The tool that will be called on approval.
    pub tool: String,
}

/// The result of executing one line-mode command.
#[derive(Debug, Clone, PartialEq)]
pub struct LineOutcome {
    /// Lines to print.
    pub lines: Vec<String>,
    /// Whether the session should end.
    pub quit: bool,
}

/// The application state machine, generic over the facade so
/// every test runs against the fake.
pub struct App<F: VongolaFacade> {
    /// The facade (real stdio client in the binary, fake in tests).
    pub facade: F,
    /// Current screen.
    pub screen: Screen,
    /// Current execution mode (plan is the default).
    pub mode: Mode,
    /// Last known server status.
    pub status: Option<StatusInfo>,
    /// Last known tool list.
    pub tools: Vec<ToolInfo>,
    /// Selected workflow index into `TOOL_NAMES`.
    pub selected: usize,
    /// The typed event stream (bounded).
    pub events: VecDeque<Event>,
    /// Log / Live lines (bounded).
    pub log: VecDeque<String>,
    /// A workflow call staged in plan mode.
    pub staged: Option<StagedAction>,
    /// The trigger engine.
    pub engine: TriggerEngine,
    /// Plan-mode trigger firings awaiting approval.
    pub pending_firings: Vec<PendingFiring>,
    /// The trigger transport (refusing in the shipped binary).
    pub transport: Box<dyn TriggerTransport>,
}

impl<F: VongolaFacade> App<F> {
    /// A new app in plan mode on the Overview screen, with the
    /// shipped (refusing) trigger transport.
    pub fn new(facade: F) -> App<F> { App::with_engine(facade, TriggerEngine::new(Vec::new())) }

    /// A new app with a pre-loaded trigger engine.
    pub fn with_engine(facade: F, engine: TriggerEngine) -> App<F> {
        App {
            facade,
            screen: Screen::Overview,
            mode: Mode::Plan,
            status: None,
            tools: Vec::new(),
            selected: 0,
            events: VecDeque::new(),
            log: VecDeque::new(),
            staged: None,
            engine,
            pending_firings: Vec::new(),
            transport: Box::new(RefusingTransport),
        }
    }

    /// The current screen as a plain-data model.
    pub fn model(&self) -> ScreenModel {
        match self.screen {
            Screen::Overview => screens::overview_model(self),
            Screen::Workflows => screens::workflows_model(self),
            Screen::Log => screens::log_model(self),
            Screen::Fleet => screens::fleet_model(self),
            Screen::Media => screens::media_model(self),
        }
    }

    fn push_log(&mut self, line: String) {
        self.log.push_back(line);
        while self.log.len() > LOG_LINES_MAX {
            self.log.pop_front();
        }
    }

    fn push_event(&mut self, event: Event) {
        self.events.push_back(event);
        while self.events.len() > EVENTS_MAX {
            self.events.pop_front();
        }
    }

    /// Refresh Overview state from the facade.
    pub fn refresh_status(&mut self) -> Result<(), TuiError> {
        self.status = Some(self.facade.status()?);
        self.tools = self.facade.tools()?;
        Ok(())
    }

    /// Stage or execute a workflow run — the one execute path
    /// both run modes share. Plan mode stages and makes **no**
    /// facade call; auto mode executes immediately.
    pub fn run_workflow(&mut self, tool: &str) -> Result<Vec<String>, TuiError> {
        if !is_tool_name(tool) {
            return Err(TuiError::NotFound(format!("unknown tool: {tool}")));
        }
        if self.mode == Mode::Plan {
            self.staged = Some(StagedAction {
                tool: tool.to_string(),
            });
            return Ok(vec![format!(
                "staged: call {tool} (read-only) — `approve` executes, `abort` discards"
            )]);
        }
        self.execute(tool)
    }

    /// Execute one tool call now: facade call, bounded result,
    /// typed events, trigger evaluation.
    pub fn execute(&mut self, tool: &str) -> Result<Vec<String>, TuiError> {
        self.push_event(Event::started(tool));
        let value = match self.facade.call(tool) {
            Ok(value) => value,
            Err(err) => {
                self.push_event(Event::failed(tool));
                self.push_log(format!("workflow.failed tool={tool}: {err}"));
                return Err(err);
            }
        };
        let serialized = value.to_string();
        if serialized.len() > RESULT_BYTES_MAX {
            self.push_event(Event::failed(tool));
            return Err(TuiError::Oversized(format!(
                "tool result exceeds {RESULT_BYTES_MAX} bytes"
            )));
        }
        let event = Event::completed(tool, value.clone());
        self.push_log(event.describe());
        self.push_event(event.clone());
        let outcomes =
            self.engine
                .evaluate(&event, &mut *self.transport, &mut self.pending_firings);
        for outcome in &outcomes {
            self.push_log(format!("trigger: {outcome:?}"));
        }
        let pretty = serde_json::to_string_pretty(&value)
            .unwrap_or_else(|_| "<unserializable result>".to_string());
        let mut lines: Vec<String> = pretty.lines().map(str::to_string).collect();
        if lines.is_empty() {
            lines.push("null".to_string());
        }
        for line in &lines {
            self.push_log(line.clone());
        }
        Ok(lines)
    }

    /// Approve whatever is staged: a workflow first, then the
    /// oldest staged trigger firing.
    pub fn approve(&mut self) -> Result<Vec<String>, TuiError> {
        if let Some(staged) = self.staged.take() {
            return self.execute(&staged.tool);
        }
        if !self.pending_firings.is_empty() {
            let firing = self.pending_firings.remove(0);
            let outcome = self.engine.fire_pending(&firing, &mut *self.transport);
            self.push_log(format!("trigger firing resolved: {outcome:?}"));
            return Ok(vec![format!("trigger firing: {outcome:?}")]);
        }
        Err(TuiError::Invalid("nothing is staged".to_string()))
    }

    /// Discard whatever is staged without executing anything.
    pub fn abort(&mut self) -> Result<Vec<String>, TuiError> {
        if self.staged.take().is_some() {
            return Ok(vec!["staged workflow discarded".to_string()]);
        }
        if !self.pending_firings.is_empty() {
            let firing = self.pending_firings.remove(0);
            return Ok(vec![format!("staged firing discarded: {}", firing.rule_id)]);
        }
        Err(TuiError::Invalid("nothing is staged".to_string()))
    }

    /// Execute one line-mode command through the shared path.
    pub fn handle_line(&mut self, line: &str) -> Result<LineOutcome, TuiError> {
        if line.len() > INPUT_LINE_BYTES_MAX {
            return Err(TuiError::Oversized(format!(
                "input line exceeds {INPUT_LINE_BYTES_MAX} bytes"
            )));
        }
        let mut parts = line.split_whitespace();
        let command = parts.next().unwrap_or("").to_ascii_lowercase();
        let rest: Vec<&str> = parts.collect();
        let out = |lines: Vec<String>| LineOutcome { lines, quit: false };
        match command.as_str() {
            "" => Ok(out(Vec::new())),
            "quit" | "exit" => Ok(LineOutcome {
                lines: vec!["bye".to_string()],
                quit: true,
            }),
            "help" => Ok(out(vec![
                "commands: status | tools | run <tool> | approve | abort | mode plan|auto"
                    .to_string(),
                "          screen overview|workflows|log|fleet|media | log | fleet | triggers"
                    .to_string(),
                "          enable <rule> | disable <rule> | media | quit".to_string(),
            ])),
            "status" => {
                self.refresh_status()?;
                self.screen = Screen::Overview;
                Ok(out(self.model().lines))
            }
            "tools" => {
                let tools = self.facade.tools()?;
                self.tools = tools.clone();
                Ok(out(tools
                    .iter()
                    .map(|tool| format!("{}: {}", tool.name, tool.description))
                    .collect()))
            }
            "run" => {
                let tool = rest.first().copied().unwrap_or("");
                Ok(out(self.run_workflow(tool)?))
            }
            "approve" => Ok(out(self.approve()?)),
            "abort" => Ok(out(self.abort()?)),
            "mode" => {
                let mode = rest
                    .first()
                    .and_then(|text| Mode::parse(text))
                    .ok_or_else(|| {
                        TuiError::Invalid("mode must be `plan` or `auto`".to_string())
                    })?;
                self.mode = mode;
                Ok(out(vec![format!("mode: {}", mode.name())]))
            }
            "screen" => {
                let screen = rest
                    .first()
                    .and_then(|text| Screen::parse(text))
                    .ok_or_else(|| TuiError::Invalid("unknown screen".to_string()))?;
                self.screen = screen;
                Ok(out(self.model().lines))
            }
            "log" => {
                self.screen = Screen::Log;
                Ok(out(self.model().lines))
            }
            "fleet" | "triggers" => {
                self.screen = Screen::Fleet;
                Ok(out(self.model().lines))
            }
            "media" => {
                self.screen = Screen::Media;
                Ok(out(self.model().lines))
            }
            "enable" | "disable" => {
                let rule_id = rest.first().copied().unwrap_or("");
                self.engine.set_enabled(rule_id, command == "enable")?;
                Ok(out(vec![format!(
                    "rule {rule_id} {}",
                    if command == "enable" {
                        "enabled"
                    } else {
                        "disabled"
                    }
                )]))
            }
            other => Err(TuiError::Invalid(format!(
                "unknown command: {other} (try `help`)"
            ))),
        }
    }
}

/// The non-TTY line mode: read commands from stdin, print
/// outcomes, same execute path as the full-screen loop.
pub fn run_line_mode<F: VongolaFacade>(app: &mut App<F>) -> Result<(), TuiError> {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    loop {
        let mut raw = Vec::new();
        let read = reader
            .by_ref()
            .take((INPUT_LINE_BYTES_MAX + 1) as u64)
            .read_until(b'\n', &mut raw)?;
        if read == 0 {
            return Ok(());
        }
        let line = String::from_utf8_lossy(&raw);
        match app.handle_line(line.trim_end()) {
            Ok(outcome) => {
                for line in &outcome.lines {
                    writeln!(writer, "{line}")?;
                }
                writer.flush()?;
                if outcome.quit {
                    return Ok(());
                }
            }
            Err(err) => {
                writeln!(writer, "error: {err}")?;
                writer.flush()?;
            }
        }
    }
}

/// The full-screen ratatui loop (TTY only; the binary routes
/// non-TTY invocations to line mode). Keys: 1-5 screens, Tab
/// cycles, `m` toggles plan/auto, `r` runs the selected workflow,
/// `a` approves, `x` aborts, Up/Down select, `q` quits.
pub fn run_fullscreen<F: VongolaFacade>(app: &mut App<F>) -> Result<(), TuiError> {
    let mut stdout = std::io::stdout();
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = fullscreen_loop(app, &mut terminal);
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    result
}

fn fullscreen_loop<F: VongolaFacade>(
    app: &mut App<F>,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
) -> Result<(), TuiError> {
    use crossterm::event::{Event as TermEvent, KeyCode, poll, read};
    let _ = app.refresh_status();
    loop {
        let model = app.model();
        terminal.draw(|frame| {
            let area = frame.area();
            crate::panels::draw_model(frame, area, &model);
        })?;
        if !poll(Duration::from_millis(200))? {
            continue;
        }
        let TermEvent::Key(key) = read()? else {
            continue;
        };
        match key.code {
            KeyCode::Char('q') => return Ok(()),
            KeyCode::Char('1') => app.screen = Screen::Overview,
            KeyCode::Char('2') => app.screen = Screen::Workflows,
            KeyCode::Char('3') => app.screen = Screen::Log,
            KeyCode::Char('4') => app.screen = Screen::Fleet,
            KeyCode::Char('5') => app.screen = Screen::Media,
            KeyCode::Tab => {
                let screens = Screen::all();
                let index = screens.iter().position(|s| *s == app.screen).unwrap_or(0);
                app.screen = screens[(index + 1) % screens.len()];
            }
            KeyCode::Char('m') => {
                app.mode = match app.mode {
                    Mode::Plan => Mode::Auto,
                    Mode::Auto => Mode::Plan,
                };
            }
            KeyCode::Up => {
                app.selected = app.selected.saturating_sub(1);
            }
            KeyCode::Down => {
                app.selected = (app.selected + 1).min(crate::TOOL_NAMES.len() - 1);
            }
            KeyCode::Char('r') => {
                let tool = crate::TOOL_NAMES[app.selected];
                let _ = app.run_workflow(tool);
                app.screen = Screen::Log;
            }
            KeyCode::Char('a') => {
                let _ = app.approve();
                app.screen = Screen::Log;
            }
            KeyCode::Char('x') => {
                let _ = app.abort();
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::facade::FakeFacade;

    #[test]
    fn validation_plan_stages_then_approve_executes() {
        let mut app = App::new(FakeFacade::healthy());
        let lines = app.handle_line("run tls_stats").unwrap().lines;
        assert!(lines[0].contains("staged"));
        assert!(app.facade.calls.is_empty(), "plan mode must not call");
        let lines = app.handle_line("approve").unwrap().lines;
        assert!(lines.iter().any(|l| l.contains("handshakes_total")));
        assert_eq!(app.facade.calls, vec!["call:tls_stats".to_string()]);
    }

    #[test]
    fn validation_auto_executes_and_line_mode_answers() {
        let mut app = App::new(FakeFacade::healthy());
        app.handle_line("mode auto").unwrap();
        let outcome = app.handle_line("run upstream_health").unwrap();
        assert!(outcome.lines.iter().any(|l| l.contains("\"down\"")));
        let status = app.handle_line("status").unwrap();
        assert!(status.lines.iter().any(|l| l.contains("vongola-mcp")));
        assert!(app.handle_line("quit").unwrap().quit);
    }

    #[test]
    fn adversarial_approve_after_abort_executes_nothing() {
        let mut app = App::new(FakeFacade::healthy());
        app.handle_line("run cert_status").unwrap();
        app.handle_line("abort").unwrap();
        assert!(app.handle_line("approve").is_err());
        assert!(app.facade.calls.is_empty());
    }

    #[test]
    fn adversarial_unknown_things_are_typed_errors() {
        let mut app = App::new(FakeFacade::healthy());
        assert!(matches!(
            app.handle_line("run rotate_keys"),
            Err(TuiError::NotFound(_))
        ));
        assert!(app.handle_line("screen nowhere").is_err());
        assert!(app.handle_line("mode yolo").is_err());
        assert!(app.handle_line("frobnicate").is_err());
        let big = "x".repeat(INPUT_LINE_BYTES_MAX + 1);
        assert!(matches!(app.handle_line(&big), Err(TuiError::Oversized(_))));
    }

    #[test]
    fn adversarial_server_death_mid_run_recovers() {
        let mut fake = FakeFacade::healthy();
        fake.die_after = Some(1);
        let mut app = App::new(fake);
        app.mode = Mode::Auto;
        assert!(app.execute("tls_stats").is_ok());
        assert!(matches!(
            app.execute("tls_stats"),
            Err(TuiError::Backend(_))
        ));
        // The app is still usable: state machine intact, log bounded.
        assert_eq!(app.screen, Screen::Overview);
        assert!(
            app.events
                .iter()
                .any(|e| e.kind == crate::EventKind::WorkflowFailed)
        );
        let model = app.handle_line("log").unwrap();
        assert!(!model.lines.is_empty());
    }

    #[test]
    fn adversarial_oversized_result_is_refused_not_rendered() {
        let mut fake = FakeFacade::healthy();
        fake.results.insert(
            "routes_list".to_string(),
            Ok(json!({"blob": "x".repeat(RESULT_BYTES_MAX + 1)})),
        );
        let mut app = App::new(fake);
        app.mode = Mode::Auto;
        assert!(matches!(
            app.execute("routes_list"),
            Err(TuiError::Oversized(_))
        ));
    }

    #[test]
    fn validation_log_buffer_stays_bounded() {
        let mut app = App::new(FakeFacade::healthy());
        app.mode = Mode::Auto;
        for _ in 0..80 {
            app.execute("log_counters").unwrap();
        }
        assert!(app.log.len() <= LOG_LINES_MAX);
        assert!(app.events.len() <= EVENTS_MAX);
    }

    #[test]
    fn validation_trigger_fires_through_app_run() {
        use crate::triggers::{FakeTransport, parse_rules};
        let rules = parse_rules(
            "[[rule]]\n\
             id = \"vongola-down-to-bloch-lesson\"\n\
             origin_lane = \"qompass\"\n\
             content_label = \"sfw\"\n\
             on = { event = \"workflow.completed\", where = \"down_count > 0\" }\n\
             then = { mcp = \"bloch\", tool = \"lesson_candidate\", args_from = \"event\" }\n\
             mode = \"auto\"\n\
             idempotency = \"event-hash\"\n\
             max_depth = 1\n",
        )
        .unwrap();
        let mut fake = FakeFacade::healthy();
        fake.results.insert(
            "upstream_health".to_string(),
            Ok(json!({"up": 0, "down": 2, "unknown": 0})),
        );
        let mut app = App::with_engine(fake, TriggerEngine::new(rules));
        app.transport = Box::new(FakeTransport::default());
        app.mode = Mode::Auto;
        app.execute("upstream_health").unwrap();
        let transport = &*app.transport;
        let _ = transport;
        // The firing is visible in the audit tail with birth stamps.
        let tail = app.engine.audit_tail();
        assert!(tail.iter().any(|l| l.contains("\"fired\"")), "{tail:?}");
        assert!(tail.iter().all(|l| l.contains("qompass")));
    }
}
