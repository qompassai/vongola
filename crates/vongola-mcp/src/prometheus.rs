// #################################################################
// /qompassai/vongola/crates/vongola-mcp/src/prometheus.rs
// Qompass AI — vongola-mcp Prometheus text parser
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

//! Minimal parser for the Prometheus text exposition format, as
//! far as vongola's `/metrics` uses it: `name{k="v",...} value`
//! sample lines with `\\`, `\"`, `\n` label escapes; comments and
//! blank lines skipped; an optional trailing timestamp ignored.
//! Bounded at `MAX_SAMPLES`. A malformed line fails the whole
//! parse — a half-read registry is not reported as data.

use std::collections::BTreeMap;

pub const MAX_SAMPLES: usize = 200_000;

#[derive(Debug, PartialEq)]
pub struct Sample {
    pub labels: BTreeMap<String, String>,
    pub name: String,
    pub value: f64,
}

impl Sample {
    pub fn label(&self, key: &str) -> Option<&str> { self.labels.get(key).map(String::as_str) }
}

pub fn parse(text: &str) -> Result<Vec<Sample>, String> {
    let mut samples = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if samples.len() == MAX_SAMPLES {
            return Err(format!("more than {MAX_SAMPLES} samples"));
        }
        samples.push(parse_line(line).map_err(|e| format!("line {}: {e}", number + 1))?);
    }
    Ok(samples)
}

fn parse_line(line: &str) -> Result<Sample, String> {
    let name_end = line
        .find(|c: char| c == '{' || c.is_whitespace())
        .ok_or("sample has no value")?;
    let name = &line[..name_end];
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
    {
        return Err(format!("invalid metric name {name:?}"));
    }
    let mut rest = &line[name_end..];
    let mut labels = BTreeMap::new();
    if let Some(after) = rest.strip_prefix('{') {
        let (parsed, remaining) = parse_labels(after)?;
        labels = parsed;
        rest = remaining;
    }
    let value_text = rest
        .split_whitespace()
        .next()
        .ok_or("sample has no value")?;
    Ok(Sample {
        labels,
        name: name.to_string(),
        value: parse_value(value_text)?,
    })
}

/// Parse `k="v",...}`; returns the labels and the text after `}`.
fn parse_labels(text: &str) -> Result<(BTreeMap<String, String>, &str), String> {
    let mut labels = BTreeMap::new();
    let mut chars = text.char_indices().peekable();
    loop {
        while chars.peek().is_some_and(|(_, c)| *c == ',' || *c == ' ') {
            chars.next();
        }
        match chars.peek() {
            Some((index, '}')) => return Ok((labels, &text[index + 1..])),
            None => return Err("unterminated label set".to_string()),
            _ => {}
        }
        let mut key = String::new();
        loop {
            match chars.next() {
                Some((_, '=')) => break,
                Some((_, c)) if c.is_ascii_alphanumeric() || c == '_' => key.push(c),
                _ => return Err("invalid label name".to_string()),
            }
        }
        if !matches!(chars.next(), Some((_, '"'))) {
            return Err(format!("label {key} value is not quoted"));
        }
        let mut value = String::new();
        loop {
            match chars.next() {
                Some((_, '"')) => break,
                Some((_, '\\')) => match chars.next() {
                    Some((_, '\\')) => value.push('\\'),
                    Some((_, '"')) => value.push('"'),
                    Some((_, 'n')) => value.push('\n'),
                    _ => return Err(format!("label {key} has an invalid escape")),
                },
                Some((_, c)) => value.push(c),
                None => return Err(format!("label {key} value is unterminated")),
            }
        }
        if labels.insert(key.clone(), value).is_some() {
            return Err(format!("label {key} repeated"));
        }
    }
}

fn parse_value(text: &str) -> Result<f64, String> {
    match text {
        "+Inf" => Ok(f64::INFINITY),
        "-Inf" => Ok(f64::NEG_INFINITY),
        "NaN" => Ok(f64::NAN),
        _ => text
            .parse::<f64>()
            .map_err(|_| format!("invalid sample value {text:?}")),
    }
}

/// The value of the one sample named `name` whose labels include
/// every `(key, value)` in `labels`.
pub fn value(samples: &[Sample], name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    samples
        .iter()
        .find(|sample| {
            sample.name == name
                && labels
                    .iter()
                    .all(|(key, value)| sample.label(key) == Some(*value))
        })
        .map(|sample| sample.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_malformed_lines_fail_whole_parse() {
        for text in [
            "vongola_up",
            "vongola_up{a=\"1\" 1",
            "vongola_up{a=1} 1",
            "vongola_up{a=\"1\",a=\"2\"} 1",
            "vongola_up{a=\"\\x\"} 1",
            "vongola up 1",
            "vongola_up{} one",
            "bad-name 1",
        ] {
            assert!(parse(&format!("vongola_ok 1\n{text}\n")).is_err(), "{text}");
        }
    }

    #[test]
    fn adversarial_sample_bound() {
        let text = "x 1\n".repeat(MAX_SAMPLES + 1);
        assert!(parse(&text).is_err());
    }

    #[test]
    fn validation_parses_vongola_shapes() {
        let text = "# HELP vongola_up Up.\n# TYPE vongola_up gauge\nvongola_up 1\n\
            vongola_route_requests_total{route=\"a\\\"b\",status_class=\"2xx\"} 7\n\
            vongola_request_latency_ms_bucket{le=\"+Inf\"} 3\n\
            vongola_cert_expiry_seconds{host=\"x.test\"} -12.5\n";
        let samples = parse(text).unwrap();
        assert_eq!(samples.len(), 4);
        assert_eq!(value(&samples, "vongola_up", &[]), Some(1.0));
        assert_eq!(
            value(
                &samples,
                "vongola_route_requests_total",
                &[("route", "a\"b"), ("status_class", "2xx")]
            ),
            Some(7.0)
        );
        assert_eq!(samples[2].label("le"), Some("+Inf"));
        assert_eq!(
            value(
                &samples,
                "vongola_cert_expiry_seconds",
                &[("host", "x.test")]
            ),
            Some(-12.5)
        );
        assert_eq!(value(&samples, "vongola_missing", &[]), None);
    }
}
