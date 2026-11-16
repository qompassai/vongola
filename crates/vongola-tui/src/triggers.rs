//! The cross-MCP trigger engine (DESIGN SS D4).
//!
//! Rules are data (`triggers.toml`), loaded bounded and validated
//! at startup, listed in the Fleet panel, and disable-able live.
//! Semantics: bounded predicates (comparisons joined by `&&`,
//! no eval), depth cap (rule `max_depth` in 1..=2, hard ceiling
//! [`crate::DEPTH_CEILING`]), idempotency by SHA-256 of
//! (rule id, event payload), and a JSONL audit whose every line
//! carries the rule's `origin_lane` + `content_label` from birth
//! (BLOCH lane law, D-1030). This member's lane is qompass/sfw.
//!
//! Live firing honesty: dispatch goes through the
//! [`TriggerTransport`] seam. The shipped binary wires
//! [`RefusingTransport`] — firings are evaluated, staged or
//! attempted, and audited as `fire_failed` with the reason; no
//! live bloch call is pretended. Wiring the rmcp client transport
//! is the named follow-on, exactly as in the pattern pilot.

use std::collections::{BTreeSet, VecDeque};
use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::events::Event;
use crate::{
    AUDIT_TAIL_MAX, DEPTH_CEILING, RULES_FILE_BYTES_MAX, RULES_MAX, SEEN_KEYS_MAX, TuiError,
};

/// One declared rule, in the DESIGN SS D4 shape.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerRule {
    /// Stable rule id.
    pub id: String,
    /// BLOCH birth stamp: originating lane.
    pub origin_lane: String,
    /// BLOCH birth stamp: content label (`sfw` for this member).
    pub content_label: String,
    /// Event selector + bounded predicate.
    pub on: OnSpec,
    /// Target MCP + tool.
    pub then: ThenSpec,
    /// `auto` fires directly; `plan` stages for approval.
    pub mode: String,
    /// Only `event-hash` is implemented; anything else refuses.
    pub idempotency: String,
    /// Chain depth this rule tolerates (1..=2).
    pub max_depth: u32,
    /// Panel enable state; toggled live, never persisted silently.
    #[serde(skip)]
    pub enabled: bool,
}

/// The `on = { ... }` half of a rule.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnSpec {
    /// Event kind name, e.g. `workflow.completed`.
    pub event: String,
    /// Bounded predicate over named numeric event fields.
    pub where_clause: Option<String>,
}

/// The `then = { ... }` half of a rule. (`where` is a TOML key,
/// renamed because it is a Rust keyword in spirit if not in law.)
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThenSpec {
    /// Target fleet member.
    pub mcp: String,
    /// Target tool.
    pub tool: String,
    /// Only `event` is implemented; anything else refuses.
    pub args_from: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    #[serde(default, rename = "rule")]
    rules: Vec<RawRule>,
}

// TOML spells the predicate key `where`; serde renames it here so
// the file format matches DESIGN SS D4 exactly.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    id: String,
    origin_lane: String,
    content_label: String,
    on: RawOn,
    then: ThenSpec,
    mode: String,
    idempotency: String,
    max_depth: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOn {
    event: String,
    #[serde(rename = "where")]
    where_clause: Option<String>,
}

/// What dispatch does with one firing.
pub trait TriggerTransport {
    /// Fire one call at the target member.
    fn fire(&mut self, mcp: &str, tool: &str, args: &Value) -> Result<Value, TuiError>;
}

/// The shipped transport: refuses, typed and audited. No live MCP
/// client transport is wired in rung 1 (see module docs).
#[derive(Debug, Default)]
pub struct RefusingTransport;

impl TriggerTransport for RefusingTransport {
    fn fire(&mut self, _mcp: &str, _tool: &str, _args: &Value) -> Result<Value, TuiError> {
        Err(TuiError::Backend(
            "no live MCP client transport wired in rung 1".to_string(),
        ))
    }
}

/// A scripted transport for tests; records every firing.
#[derive(Debug, Default)]
pub struct FakeTransport {
    /// Recorded `(mcp, tool, args)` firings.
    pub fired: Vec<(String, String, Value)>,
    /// When set, every firing fails with this message.
    pub fail_with: Option<String>,
}

impl TriggerTransport for FakeTransport {
    fn fire(&mut self, mcp: &str, tool: &str, args: &Value) -> Result<Value, TuiError> {
        self.fired
            .push((mcp.to_string(), tool.to_string(), args.clone()));
        match &self.fail_with {
            Some(message) => Err(TuiError::Backend(message.clone())),
            None => Ok(json!({"accepted": true})),
        }
    }
}

/// The outcome of evaluating one event against the rule set.
#[derive(Debug, Clone, PartialEq)]
pub enum FireOutcome {
    /// The rule fired and the transport accepted.
    Fired {
        /// Rule that fired.
        rule_id: String,
    },
    /// A plan-mode rule matched; the firing awaits approval.
    Staged {
        /// Rule that matched.
        rule_id: String,
    },
    /// The firing was dropped (duplicate, depth, disabled).
    Dropped {
        /// Rule concerned.
        rule_id: String,
        /// Why.
        reason: String,
    },
    /// The transport refused or failed; audited, never hidden.
    Failed {
        /// Rule that fired.
        rule_id: String,
        /// Transport error text.
        reason: String,
    },
}

/// A plan-mode firing awaiting the operator's approval.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingFiring {
    /// Rule that matched.
    pub rule_id: String,
    /// Target member.
    pub mcp: String,
    /// Target tool.
    pub tool: String,
    /// Arguments built from the event.
    pub args: Value,
    /// Birth stamps carried into the audit on resolution.
    pub origin_lane: String,
    /// Birth stamps carried into the audit on resolution.
    pub content_label: String,
    /// Idempotency key, reserved at staging time.
    pub key: String,
}

/// The rule engine: rules + idempotency memory + audit tail.
pub struct TriggerEngine {
    rules: Vec<TriggerRule>,
    seen: BTreeSet<String>,
    seen_order: VecDeque<String>,
    audit: VecDeque<String>,
    audit_path: Option<std::path::PathBuf>,
}

impl TriggerEngine {
    /// An engine over validated rules.
    pub fn new(rules: Vec<TriggerRule>) -> TriggerEngine {
        TriggerEngine {
            rules,
            seen: BTreeSet::new(),
            seen_order: VecDeque::new(),
            audit: VecDeque::new(),
            audit_path: None,
        }
    }

    /// Append audit lines to this JSONL file as well as the tail.
    pub fn set_audit_path(&mut self, path: std::path::PathBuf) { self.audit_path = Some(path); }

    /// The declared rules, in file order.
    pub fn rules(&self) -> &[TriggerRule] { &self.rules }

    /// Toggle one rule's enable state (Fleet panel; live effect).
    pub fn set_enabled(&mut self, rule_id: &str, enabled: bool) -> Result<(), TuiError> {
        let rule = self
            .rules
            .iter_mut()
            .find(|r| r.id == rule_id)
            .ok_or_else(|| TuiError::NotFound(format!("unknown rule: {rule_id}")))?;
        rule.enabled = enabled;
        Ok(())
    }

    /// The bounded audit tail for the Fleet panel.
    pub fn audit_tail(&self) -> Vec<String> { self.audit.iter().cloned().collect() }

    fn audit(&mut self, rule: &TriggerRule, outcome: &str, detail: &str) {
        let line = json!({
            "rule_id": rule.id,
            "origin_lane": rule.origin_lane,
            "content_label": rule.content_label,
            "outcome": outcome,
            "detail": detail,
        })
        .to_string();
        if let Some(path) = &self.audit_path {
            use std::io::Write as _;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                let _ = writeln!(file, "{line}");
            }
        }
        self.audit.push_back(line);
        while self.audit.len() > AUDIT_TAIL_MAX {
            self.audit.pop_front();
        }
    }

    fn remember(&mut self, key: String) {
        if self.seen.insert(key.clone()) {
            self.seen_order.push_back(key);
            while self.seen_order.len() > SEEN_KEYS_MAX {
                if let Some(oldest) = self.seen_order.pop_front() {
                    self.seen.remove(&oldest);
                }
            }
        }
    }

    /// Evaluate one event: every matching rule fires (auto),
    /// stages (plan), drops, or fails — each audited.
    pub fn evaluate(
        &mut self,
        event: &Event,
        transport: &mut dyn TriggerTransport,
        pending: &mut Vec<PendingFiring>,
    ) -> Vec<FireOutcome> {
        let mut outcomes = Vec::new();
        // Rules are cloned up front: firing mutates engine state
        // (audit, idempotency) while iterating.
        for rule in self.rules.clone() {
            if rule.on.event != event.kind.as_str() {
                continue;
            }
            if !predicate_matches(rule.on.where_clause.as_deref(), event) {
                continue;
            }
            if !rule.enabled {
                self.audit(&rule, "dropped", "rule disabled");
                outcomes.push(FireOutcome::Dropped {
                    rule_id: rule.id.clone(),
                    reason: "rule disabled".to_string(),
                });
                continue;
            }
            if event.depth >= rule.max_depth || event.depth >= DEPTH_CEILING {
                self.audit(&rule, "dropped", "depth cap");
                outcomes.push(FireOutcome::Dropped {
                    rule_id: rule.id.clone(),
                    reason: "depth cap".to_string(),
                });
                continue;
            }
            let key = event_hash(&rule.id, event);
            if self.seen.contains(&key) {
                self.audit(&rule, "dropped", "duplicate event (event-hash)");
                outcomes.push(FireOutcome::Dropped {
                    rule_id: rule.id.clone(),
                    reason: "duplicate event".to_string(),
                });
                continue;
            }
            let args = json!({
                "event": event.kind.as_str(),
                "tool": event.tool,
                "numbers": event.numbers,
                "payload": event.payload,
            });
            if rule.mode == "plan" {
                self.remember(key.clone());
                pending.push(PendingFiring {
                    rule_id: rule.id.clone(),
                    mcp: rule.then.mcp.clone(),
                    tool: rule.then.tool.clone(),
                    args,
                    origin_lane: rule.origin_lane.clone(),
                    content_label: rule.content_label.clone(),
                    key,
                });
                self.audit(&rule, "staged", "plan mode: awaiting approval");
                outcomes.push(FireOutcome::Staged {
                    rule_id: rule.id.clone(),
                });
                continue;
            }
            self.remember(key);
            match transport.fire(&rule.then.mcp, &rule.then.tool, &args) {
                Ok(_) => {
                    self.audit(&rule, "fired", "transport accepted");
                    outcomes.push(FireOutcome::Fired {
                        rule_id: rule.id.clone(),
                    });
                }
                Err(err) => {
                    let reason = err.to_string();
                    self.audit(&rule, "fire_failed", &reason);
                    outcomes.push(FireOutcome::Failed {
                        rule_id: rule.id.clone(),
                        reason,
                    });
                }
            }
        }
        outcomes
    }

    /// Execute one staged firing after operator approval.
    pub fn fire_pending(
        &mut self,
        firing: &PendingFiring,
        transport: &mut dyn TriggerTransport,
    ) -> FireOutcome {
        let rule_stub = TriggerRule {
            id: firing.rule_id.clone(),
            origin_lane: firing.origin_lane.clone(),
            content_label: firing.content_label.clone(),
            on: OnSpec {
                event: String::new(),
                where_clause: None,
            },
            then: ThenSpec {
                mcp: firing.mcp.clone(),
                tool: firing.tool.clone(),
                args_from: "event".to_string(),
            },
            mode: "plan".to_string(),
            idempotency: "event-hash".to_string(),
            max_depth: 1,
            enabled: true,
        };
        match transport.fire(&firing.mcp, &firing.tool, &firing.args) {
            Ok(_) => {
                self.audit(&rule_stub, "fired", "staged firing approved");
                FireOutcome::Fired {
                    rule_id: firing.rule_id.clone(),
                }
            }
            Err(err) => {
                let reason = err.to_string();
                self.audit(&rule_stub, "fire_failed", &reason);
                FireOutcome::Failed {
                    rule_id: firing.rule_id.clone(),
                    reason,
                }
            }
        }
    }
}

/// SHA-256 of (rule id, canonical event payload) — the
/// idempotency key. Canonical = sorted keys via `BTreeMap`
/// numbers + serde_json's deterministic object ordering is not
/// relied on; the payload is re-serialized from a sorted walk.
pub fn event_hash(rule_id: &str, event: &Event) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(event.kind.as_str().as_bytes());
    hasher.update(b"\n");
    hasher.update(event.tool.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical(&event.payload).as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let inner: Vec<String> = entries
                .iter()
                .map(|(k, v)| format!("{k}:{}", canonical(v)))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

/// Evaluate a bounded predicate: comparisons
/// (`field > N`, `>=`, `<`, `<=`, `==`) joined by `&&` only.
/// Anything else does not match — there is no eval to escape into.
pub fn predicate_matches(predicate: Option<&str>, event: &Event) -> bool {
    let Some(predicate) = predicate else {
        return true;
    };
    let predicate = predicate.trim();
    if predicate.is_empty() {
        return true;
    }
    predicate.split("&&").all(|clause| {
        let clause = clause.trim();
        for (op, is_op) in [(">=", 0u8), ("<=", 1), ("==", 2), (">", 3), ("<", 4)] {
            let _ = is_op;
            if let Some((field, rhs)) = clause.split_once(op) {
                let field = field.trim();
                let Ok(rhs) = rhs.trim().parse::<f64>() else {
                    return false;
                };
                let Some(lhs) = event.numbers.get(field) else {
                    return false;
                };
                return match op {
                    ">=" => *lhs >= rhs,
                    "<=" => *lhs <= rhs,
                    "==" => (*lhs - rhs).abs() < f64::EPSILON,
                    ">" => *lhs > rhs,
                    "<" => *lhs < rhs,
                    _ => false,
                };
            }
        }
        false
    })
}

/// Load and validate rules from a `triggers.toml` file. Any
/// malformed rule refuses the whole load — a partially applied
/// rule set is hidden behaviour.
pub fn load_rules(path: &Path) -> Result<Vec<TriggerRule>, TuiError> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > RULES_FILE_BYTES_MAX {
        return Err(TuiError::Oversized(format!(
            "triggers file exceeds {RULES_FILE_BYTES_MAX} bytes"
        )));
    }
    let text = std::fs::read_to_string(path)?;
    parse_rules(&text)
}

/// Parse and validate rule text (the loadable core of
/// [`load_rules`], testable without files).
pub fn parse_rules(text: &str) -> Result<Vec<TriggerRule>, TuiError> {
    let file: RulesFile =
        toml::from_str(text).map_err(|e| TuiError::Invalid(format!("triggers.toml: {e}")))?;
    if file.rules.len() > RULES_MAX {
        return Err(TuiError::Oversized(format!(
            "rule count exceeds RULES_MAX {RULES_MAX}"
        )));
    }
    let mut rules = Vec::new();
    for raw in file.rules {
        validate_rule(&raw)?;
        rules.push(TriggerRule {
            id: raw.id,
            origin_lane: raw.origin_lane,
            content_label: raw.content_label,
            on: OnSpec {
                event: raw.on.event,
                where_clause: raw.on.where_clause,
            },
            then: raw.then,
            mode: raw.mode,
            idempotency: raw.idempotency,
            max_depth: raw.max_depth,
            enabled: true,
        });
    }
    Ok(rules)
}

fn validate_rule(raw: &RawRule) -> Result<(), TuiError> {
    let bad = |msg: &str| TuiError::Invalid(format!("rule {}: {msg}", raw.id));
    if raw.id.is_empty() {
        return Err(bad("empty id"));
    }
    if raw.origin_lane.is_empty() || raw.content_label.is_empty() {
        return Err(bad("birth stamps (origin_lane/content_label) are required"));
    }
    if raw.mode != "auto" && raw.mode != "plan" {
        return Err(bad("mode must be auto or plan"));
    }
    if raw.idempotency != "event-hash" {
        return Err(bad("only idempotency = \"event-hash\" is implemented"));
    }
    if raw.then.args_from != "event" {
        return Err(bad("only args_from = \"event\" is implemented"));
    }
    if raw.max_depth == 0 || raw.max_depth > DEPTH_CEILING {
        return Err(bad("max_depth must be within 1..=2"));
    }
    if let Some(predicate) = &raw.on.where_clause {
        // Validate predicate shape at load: fields and operators
        // only; an unparseable predicate refuses the load rather
        // than silently never matching.
        for clause in predicate.split("&&") {
            let clause = clause.trim();
            let ok = [">=", "<=", "==", ">", "<"].iter().any(|op| {
                clause.split_once(op).is_some_and(|(field, rhs)| {
                    !field.trim().is_empty()
                        && field
                            .trim()
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_')
                        && rhs.trim().parse::<f64>().is_ok()
                })
            });
            if !ok {
                return Err(bad("unparseable predicate clause"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ONE_RULE: &str = r#"
[[rule]]
id = "vongola-down-to-bloch-lesson"
origin_lane = "qompass"
content_label = "sfw"
on = { event = "workflow.completed", where = "down_count > 0" }
then = { mcp = "bloch", tool = "lesson_candidate", args_from = "event" }
mode = "auto"
idempotency = "event-hash"
max_depth = 1
"#;

    fn down_event() -> Event {
        Event::completed("upstream_health", json!({"up": 0, "down": 2, "unknown": 0}))
    }

    #[test]
    fn validation_rule_loads_and_fires_with_birth_stamps() {
        let rules = parse_rules(ONE_RULE).unwrap();
        assert_eq!(rules.len(), 1);
        let mut engine = TriggerEngine::new(rules);
        let mut transport = FakeTransport::default();
        let mut pending = Vec::new();
        let outcomes = engine.evaluate(&down_event(), &mut transport, &mut pending);
        assert_eq!(
            outcomes,
            vec![FireOutcome::Fired {
                rule_id: "vongola-down-to-bloch-lesson".to_string()
            }]
        );
        assert_eq!(transport.fired.len(), 1);
        assert_eq!(transport.fired[0].1, "lesson_candidate");
        let audit = engine.audit_tail();
        assert_eq!(audit.len(), 1);
        let line: Value = serde_json::from_str(&audit[0]).unwrap();
        assert_eq!(line["origin_lane"], "qompass");
        assert_eq!(line["content_label"], "sfw");
    }

    #[test]
    fn validation_no_match_and_predicate_bounds() {
        let rules = parse_rules(ONE_RULE).unwrap();
        let mut engine = TriggerEngine::new(rules);
        let mut transport = FakeTransport::default();
        let mut pending = Vec::new();
        let healthy = Event::completed("upstream_health", json!({"up": 3, "down": 0}));
        assert!(
            engine
                .evaluate(&healthy, &mut transport, &mut pending)
                .is_empty()
        );
        assert!(transport.fired.is_empty());
        assert!(predicate_matches(
            Some("down_count >= 2 && error_count < 5"),
            &down_event()
        ));
        assert!(!predicate_matches(Some("down_count >> 2"), &down_event()));
        assert!(!predicate_matches(Some("missing_field > 0"), &down_event()));
    }

    #[test]
    fn adversarial_duplicate_depth_and_disabled_drop() {
        let rules = parse_rules(ONE_RULE).unwrap();
        let mut engine = TriggerEngine::new(rules);
        let mut transport = FakeTransport::default();
        let mut pending = Vec::new();
        let event = down_event();
        engine.evaluate(&event, &mut transport, &mut pending);
        let again = engine.evaluate(&event, &mut transport, &mut pending);
        assert!(matches!(again[0], FireOutcome::Dropped { .. }));
        assert_eq!(transport.fired.len(), 1, "duplicate must not re-fire");

        let mut deep = down_event();
        deep.depth = 1;
        let outcomes = engine.evaluate(&deep, &mut transport, &mut pending);
        assert!(matches!(outcomes[0], FireOutcome::Dropped { .. }));

        engine
            .set_enabled("vongola-down-to-bloch-lesson", false)
            .unwrap();
        let mut other = down_event();
        other.payload = json!({"up": 0, "down": 5});
        let outcomes = engine.evaluate(&other, &mut transport, &mut pending);
        assert!(matches!(outcomes[0], FireOutcome::Dropped { .. }));
        assert_eq!(transport.fired.len(), 1);
    }

    #[test]
    fn adversarial_malformed_rule_files_refuse_at_load() {
        for text in [
            "not toml [",
            &ONE_RULE.replace("mode = \"auto\"", "mode = \"yolo\""),
            &ONE_RULE.replace("max_depth = 1", "max_depth = 3"),
            &ONE_RULE.replace("event-hash", "none"),
            &ONE_RULE.replace("down_count > 0", "down_count >> 0"),
            &ONE_RULE.replace("content_label = \"sfw\"\n", ""),
            &ONE_RULE.replace("idempotency", "bogus_key"),
        ] {
            assert!(parse_rules(text).is_err(), "must refuse: {text}");
        }
    }

    #[test]
    fn adversarial_dead_target_is_failed_and_audited() {
        let rules = parse_rules(ONE_RULE).unwrap();
        let mut engine = TriggerEngine::new(rules);
        let mut transport = FakeTransport {
            fired: Vec::new(),
            fail_with: Some("bloch unreachable".to_string()),
        };
        let mut pending = Vec::new();
        let outcomes = engine.evaluate(&down_event(), &mut transport, &mut pending);
        assert!(matches!(outcomes[0], FireOutcome::Failed { .. }));
        assert!(
            engine
                .audit_tail()
                .iter()
                .any(|line| line.contains("fire_failed"))
        );
    }
}
