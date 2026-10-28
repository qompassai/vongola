# Vongola — Current State

2026-10-10: clean-room rewrite in progress on branch
`cleanroom/vongola-20261010`. The rewrite is implemented fresh
from `SPEC.md` (public surfaces only) against Pingora 0.9.0. The
previous implementation remains untouched on `master`.

Shape: one crate (`crates/vongola`), modules alphabetical —
a2a, admin, auth, cert, chain, config, dashboard, mcp, metrics,
nat, oauth, proxy, state, static_site, tor, upstream.

Standing rules in force: Tiger Style Rust; alphabetical order
everywhere (Matt, 2026-10-10); Tor is never an exit node; proxy
chains fail closed; secrets are referenced by environment
variable name, never stored in config or logs.
