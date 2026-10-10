# OpenCode in vongola

OpenCode reads `opencode.json` at the repo root and the shared
agent guide in `AGENTS.md`. The rules are the same as for every
agent surface here: SPEC.md is the contract, Tiger Style Rust,
alphabetical order, hard rules (never an exit node, chains fail
closed, TLS 1.3 + PQ hybrids only, secrets by env-var name
only), and no pushes without Matt's word.
