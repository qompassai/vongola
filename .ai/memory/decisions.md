# Vongola — Decisions

- 2026-10-10 — Clean-room rewrite from a public-surface spec
  (`SPEC.md`) instead of patching the Pingora 0.4 tree. Pingora
  pinned to 0.9.0 (latest on crates.io, verified 2026-10-10).
- 2026-10-10 — YAML is the one canonical config format; HCL is
  import-only with a structured error (SPEC §3, §13).
- 2026-10-10 — TLS: 1.3 only, hybrid PQ groups first
  (SecP384r1MLKEM1024, X25519MLKEM768) via the OpenSSL backend
  on OpenSSL 3.6; pure ML-KEM groups are never offered.
- 2026-10-10 — Tor: external tor daemon over the control
  protocol is the primary onion-service path; Arti evaluated
  and documented as the future embedded option. Exit behavior
  is rejected in config validation — never an exit node.
- 2026-10-10 — OAuth2 state is HMAC-SHA256 integrity-protected
  with a 120 s lifetime (replaces the old obfuscation blob).
- 2026-10-10 — WASM/WIT plugin scaffold and disk response cache
  are spec-cut with reasons (SPEC §13); proxied-response caching
  returns with a dedicated design.
- 2026-10-10 — Homa transport: feasibility assessed (see the
  book's Homa chapter). Not in the default build.
- 2026-10-10 — OpenShell scaffolding (`.openshell/`) was
  originated for this repo: no established estate pattern
  existed at the time (searched phlow, diver, light-show,
  volta). Flagged here so it can be replaced when a canonical
  pattern lands.
