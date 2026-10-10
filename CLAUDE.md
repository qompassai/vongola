# Vongola — Agent Guide (Claude Code)

Clean-room reverse proxy on Pingora 0.9. Read `SPEC.md` first:
it is the behavioral contract, written from public surfaces.

Rules:
- Tiger Style Rust (`#![forbid(unsafe_code)]` discipline, explicit
  contracts, bounded work). Alphabetical order for modules,
  functions, constants, and list entries — dependency order only
  where the language requires it.
- Never weaken the hard rules: Tor never an exit node; proxy
  chains fail closed; TLS 1.3 + hybrid PQ groups only; secrets
  by env-var name only, never logged.
- Tests: roughly half validation, half adversarial, named
  `validation_*` / `adversarial_*`. Run `cargo test`,
  `cargo clippy -- -D warnings`, `cargo fmt --check`, and the
  IDE gate (headless nvim with Matt's diver config: rust-analyzer
  + bacon-ls + crates-lsp, zero LSP errors) before calling a
  stage done.
- Commits: explicit pathspecs, `git diff --cached --stat` first,
  no pushes without Matt's word. Local branch:
  `cleanroom/vongola-20261010`.
- Persistent memory lives in `.ai/memory/` (start at INDEX.md).
