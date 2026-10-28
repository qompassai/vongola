# Vongola — Patterns

- Every config knob is wired and has a test; a knob that parses
  but does nothing is a defect.
- Fail closed: chain dial failure = 502, never a direct fallback;
  unknown SNI = failed handshake, never a wrong certificate;
  invalid config = structured errors, never a partial start.
- Secrets travel by environment-variable name only. Log lines
  pass through redaction; OAuth2 codes, tokens, cookies, and
  private keys have no logging code path.
- Tests split roughly half validation, half adversarial, named
  `validation_*` / `adversarial_*`.
- Operator surfaces (admin API, dashboard, MCP) share one auth
  posture: `OperatorAuth` decides allow/deny from a table before
  any tool body runs.
