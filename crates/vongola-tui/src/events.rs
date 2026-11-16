//! The typed event stream (DESIGN SS D2/D4): the same stream the
//! Log screen renders and the trigger engine consumes. A workflow
//! run emits `started`, then exactly one of `completed` / `failed`;
//! a completed run carries the named numeric fields the trigger
//! predicates read, derived from the tool's own result — never
//! invented.

use std::collections::BTreeMap;

use serde_json::Value;

/// The event kinds this member genuinely produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A workflow run began.
    WorkflowStarted,
    /// A workflow run finished with a result.
    WorkflowCompleted,
    /// A workflow run failed (typed error, app recovers).
    WorkflowFailed,
}

impl EventKind {
    /// The wire name used in rules and audit lines.
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::WorkflowStarted => "workflow.started",
            EventKind::WorkflowCompleted => "workflow.completed",
            EventKind::WorkflowFailed => "workflow.failed",
        }
    }
}

/// One typed event. `depth` is the trigger-chain depth that
/// produced it: operator runs are depth 0; events produced by a
/// triggered call carry their depth so rules can refuse at the cap.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// What happened.
    pub kind: EventKind,
    /// The tool the run called (empty for non-workflow events).
    pub tool: String,
    /// Named numeric fields predicates may read.
    pub numbers: BTreeMap<String, f64>,
    /// The full result payload (completed runs only).
    pub payload: Value,
    /// Trigger-chain depth.
    pub depth: u32,
}

impl Event {
    /// An operator workflow run starting.
    pub fn started(tool: &str) -> Event {
        Event {
            kind: EventKind::WorkflowStarted,
            tool: tool.to_string(),
            numbers: BTreeMap::new(),
            payload: Value::Null,
            depth: 0,
        }
    }

    /// A workflow run that failed before producing a result.
    pub fn failed(tool: &str) -> Event {
        Event {
            kind: EventKind::WorkflowFailed,
            tool: tool.to_string(),
            numbers: BTreeMap::new(),
            payload: Value::Null,
            depth: 0,
        }
    }

    /// A completed run: numeric fields are derived from the
    /// tool's own result shape (vongola-mcp `tools.rs`).
    pub fn completed(tool: &str, payload: Value) -> Event {
        let mut numbers = BTreeMap::new();
        let get = |key: &str| payload.get(key).and_then(|v| v.as_f64());
        match tool {
            "cert_status" => {
                let expiring = payload
                    .get("expiring_soon")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len() as f64)
                    .unwrap_or(0.0);
                numbers.insert("expiring_count".to_string(), expiring);
                numbers.insert("error_count".to_string(), expiring);
            }
            "log_counters" => {
                let errors = get("errors_and_warnings").unwrap_or(0.0);
                numbers.insert("error_count".to_string(), errors);
                numbers.insert(
                    "dropped_count".to_string(),
                    get("dropped_log_lines").unwrap_or(0.0),
                );
            }
            "routes_list" => {
                numbers.insert("route_count".to_string(), get("count").unwrap_or(0.0));
                numbers.insert("error_count".to_string(), 0.0);
            }
            "tls_stats" => {
                let failures = get("failures_total").unwrap_or(0.0);
                numbers.insert("failures_total".to_string(), failures);
                numbers.insert("error_count".to_string(), failures);
            }
            "upstream_health" => {
                let down = get("down").unwrap_or(0.0);
                numbers.insert("down_count".to_string(), down);
                numbers.insert("error_count".to_string(), down);
            }
            _ => {
                numbers.insert("error_count".to_string(), 0.0);
            }
        }
        Event {
            kind: EventKind::WorkflowCompleted,
            tool: tool.to_string(),
            numbers,
            payload,
            depth: 0,
        }
    }

    /// One-line rendering for the Log screen.
    pub fn describe(&self) -> String {
        match self.kind {
            EventKind::WorkflowStarted => format!("workflow.started tool={}", self.tool),
            EventKind::WorkflowFailed => format!("workflow.failed tool={}", self.tool),
            EventKind::WorkflowCompleted => {
                let fields: Vec<String> = self
                    .numbers
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                format!("workflow.completed tool={} {}", self.tool, fields.join(" "))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn validation_completed_derives_named_fields() {
        let event = Event::completed("upstream_health", json!({"up": 2, "down": 1, "unknown": 0}));
        assert_eq!(event.numbers["down_count"], 1.0);
        assert_eq!(event.numbers["error_count"], 1.0);
        let event = Event::completed(
            "cert_status",
            json!({"expiring_soon": ["a.test", "b.test"]}),
        );
        assert_eq!(event.numbers["expiring_count"], 2.0);
    }

    #[test]
    fn adversarial_malformed_payload_counts_zero_without_panic() {
        for payload in [json!(null), json!("text"), json!({"down": "many"})] {
            let event = Event::completed("upstream_health", payload);
            assert_eq!(event.numbers["down_count"], 0.0);
        }
        let event = Event::completed("no_such_tool", json!({}));
        assert_eq!(event.numbers["error_count"], 0.0);
    }
}
