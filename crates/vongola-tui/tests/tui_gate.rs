//! Integration gates for vongola-tui: line mode end-to-end over
//! the fake facade, plan-mode discipline, and the trigger layer
//! through the app. (Headless `TestBackend` rendering lives in the
//! crate's panel tests.)

use vongola_tui::facade::FakeFacade;
use vongola_tui::triggers::{FakeTransport, TriggerEngine, parse_rules};
use vongola_tui::{App, Mode, Screen, TuiError};

const DOWN_RULE: &str = "[[rule]]\n\
    id = \"vongola-down-to-bloch-lesson\"\n\
    origin_lane = \"qompass\"\n\
    content_label = \"sfw\"\n\
    on = { event = \"workflow.completed\", where = \"down_count > 0\" }\n\
    then = { mcp = \"bloch\", tool = \"lesson_candidate\", args_from = \"event\" }\n\
    mode = \"auto\"\n\
    idempotency = \"event-hash\"\n\
    max_depth = 1\n";

#[test]
fn validation_line_mode_session() {
    let mut app = App::new(FakeFacade::healthy());
    let status = app.handle_line("status").unwrap();
    assert!(status.lines.iter().any(|l| l.contains("reachable")));
    let tools = app.handle_line("tools").unwrap();
    assert_eq!(tools.lines.len(), 5);
    app.handle_line("mode auto").unwrap();
    let run = app.handle_line("run routes_list").unwrap();
    assert!(run.lines.iter().any(|l| l.contains("count")));
    let fleet = app.handle_line("screen fleet").unwrap();
    assert_eq!(app.screen, Screen::Fleet);
    assert!(!fleet.lines.is_empty());
    let media = app.handle_line("media").unwrap();
    assert!(media.lines.iter().any(|l| l.contains("Unavailable")));
}

#[test]
fn validation_plan_mode_proves_no_call_before_approval() {
    let mut app = App::new(FakeFacade::healthy());
    assert_eq!(app.mode, Mode::Plan, "plan is the default");
    app.handle_line("run log_counters").unwrap();
    assert!(
        app.facade.calls.is_empty(),
        "staged run must not touch the facade: {:?}",
        app.facade.calls
    );
    app.handle_line("approve").unwrap();
    assert_eq!(app.facade.calls.len(), 1);
}

#[test]
fn adversarial_staged_trigger_firing_waits_for_approval() {
    let plan_rule = DOWN_RULE.replace("mode = \"auto\"", "mode = \"plan\"");
    let rules = parse_rules(&plan_rule).unwrap();
    let mut fake = FakeFacade::healthy();
    fake.results.insert(
        "upstream_health".to_string(),
        Ok(serde_json::json!({"up": 0, "down": 1, "unknown": 0})),
    );
    let mut app = App::with_engine(fake, TriggerEngine::new(rules));
    let transport = FakeTransport::default();
    app.transport = Box::new(transport);
    app.mode = Mode::Auto;
    app.execute("upstream_health").unwrap();
    assert_eq!(
        app.pending_firings.len(),
        1,
        "plan rule must stage, not fire"
    );
    // Approving resolves the staged firing through the transport.
    let lines = app.approve().unwrap();
    assert!(lines.iter().any(|l| l.contains("trigger firing")));
    assert!(app.pending_firings.is_empty());
}

#[test]
fn adversarial_refusing_transport_firing_is_audited_not_faked() {
    let rules = parse_rules(DOWN_RULE).unwrap();
    let mut fake = FakeFacade::healthy();
    fake.results.insert(
        "upstream_health".to_string(),
        Ok(serde_json::json!({"up": 0, "down": 3, "unknown": 0})),
    );
    // Default transport is the shipped RefusingTransport.
    let mut app = App::with_engine(fake, TriggerEngine::new(rules));
    app.mode = Mode::Auto;
    app.execute("upstream_health").unwrap();
    let tail = app.engine.audit_tail();
    assert!(
        tail.iter().any(|l| l.contains("fire_failed")),
        "refused firing must be audited as failed: {tail:?}"
    );
    assert!(
        !tail
            .iter()
            .any(|l| l.contains("\"fired\"") && !l.contains("fire_failed")),
        "no firing may be reported as delivered: {tail:?}"
    );
}

#[test]
fn adversarial_unknown_tool_never_reaches_facade_in_auto() {
    let mut app = App::new(FakeFacade::healthy());
    app.mode = Mode::Auto;
    assert!(matches!(
        app.run_workflow("exfiltrate"),
        Err(TuiError::NotFound(_))
    ));
    assert!(app.facade.calls.is_empty());
}
