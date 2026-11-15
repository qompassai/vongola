# Changelog

All notable changes to vongola are recorded here. The format follows
Keep a Changelog, and the project follows Semantic Versioning (the
semver line of record per the Owner ruling of 2026-11-03; the older
date-stamped tag series is retired as historical snapshots).

## [1.0.0] - 2026-11-15

First stable release of the clean-room implementation.

### Added

- Clean-room reverse proxy and web server on Pingora 0.9, built fresh
  from SPEC.md (public surfaces only): host/path routing, round-robin
  load balancing with TCP health checks, SNI TLS proxying, 308
  redirect listener, static hosting profile for qompass.ai.
- TLS 1.3 with hybrid post-quantum key exchange (SecP384r1MLKEM1024,
  X25519MLKEM768) on system OpenSSL >= 3.5; ACME HTTP-01 challenge
  surface; opt-in per-route self-signed fallback.
- Operator surfaces per SPEC section 11: admin API and live dashboard
  (loopback by default, one bearer-token posture), an in-daemon MCP
  server (nine read-only tools, two token-gated mutating tools), and
  the standalone read-only vongola-mcp server (five tools over the
  daemon's loopback admin surfaces).
- A2A signed Agent Card (Ed25519), NAT traversal, Tor onion services
  (never an exit node; exit behavior rejected in config validation),
  proxy chains that fail closed, Docker/Swarm upstream discovery,
  lean and fleet profiles.
- vongola-ech: Encrypted Client Hello (RFC 9849) FFI binding crate,
  published separately at 0.1.0; builds only against OpenSSL >= 4.0
  and is enabled by the optional ech feature.

### Notes

- The WASM/WIT plugin scaffold and the disk response cache from the
  previous tree are spec-cut with reasons (SPEC section 13); the full
  ACME order/finalize client remains a staged surface for the same
  reason recorded there.

## [0.2.0] - 2026-11-03

- vongola-mcp migrated to rmcp 3.8.0, modern protocol era only
  (2026-07-28); legacy initialize refused with the fleet
  UnsupportedProtocolVersionError.
- vongola-ech declared a workspace member with its own version so it
  can be published to crates.io in its own right; vongola depends on
  it by version and path.
- First MCP Registry record (ai.qompass/vongola) and the first
  .mcpb distribution of vongola-mcp via GitHub releases.
