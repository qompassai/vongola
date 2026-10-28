# Agent skills for vongola

This directory mirrors the phlow repo pattern: vendored agent
skills for working on vongola — the clean-room Pingora rewrite —
so any agent (Claude Code or opencode) working in this checkout
gets the same rules without extra setup.

Skills are referenced, not copied, while the rewrite is in
flight: the canonical copies live in the estate skill library
(`~/workspace/skills/`): `tiger-style-rust` (all Rust code),
`tiger-style-nix` (flake.nix / dev shells), `git-wip-guard`
(never destroy uncommitted work). See `.claude/skills/` for the
per-skill pointers.
