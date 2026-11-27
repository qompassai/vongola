# Changelog

All notable changes to vongola are recorded here. The format follows
Keep a Changelog, and the project follows Semantic Versioning (the
semver line of record per the Owner ruling of 2026-11-03; the older
date-stamped tag series is retired as historical snapshots).

## [Unreleased]

### Changed

- Lineage adoption (2026-11-23): the lineage that has run in
  production since 2026-10-13 is now `main`. The 1.0.x lineage is
  preserved on the `archive/main-1.0.x-20261123` branch; its
  [1.0.0] entry below is retained as that lineage's history, not
  as a release of this line. This line's version of record is the
  core crate version, 0.2.0.
- Re-ported from the archived lineage onto this line as separately
  gated commits: the ECH stack (`tls.ech` config, the `vongola-ech`
  crate, OpenSSL 4 flake outputs), the standalone `vongola-mcp`
  operator client, the TLS handshake metrics expansion, and the
  rich certificate inventory metadata (subject, issuer, notAfter).
  This line's production behaviour — in-process ACME, full-chain
  certificate serving, per-route `content_security_policy` — is
  unchanged.

## [1.1.1] - 2026-11-27

- `vongola-mcp`: crates.io README fix: the 1.1.0 publish's registry metadata carried the README filename instead of its content, so crates.io rendered the literal text "README.md" and the MCP Registry ownership check could not find the `mcp-name:` marker. This patch re-publishes with the README content carried correctly. No code or tool-surface change.

## [1.1.0] - 2026-11-27

### Added

- `vongola-mcp` 1.1.0: First publication to the MCP Registry as `ai.qompass/vongola` (Registry onboarding scoped by the release sweep record, ~/workspace/release-sweep-20261127/RECORD.md, held item 7). server.json's server version now tracks the `vongola-mcp` package release (1.1.0); the core `vongola` crate line (0.2.0) is unchanged and releases separately.
- `crates/vongola-mcp/README.md` added, carrying the `mcp-name: ai.qompass/vongola` ownership marker the Registry verifies against the crates.io package.
- No tool-surface or behaviour change in `vongola-mcp` from 1.0.1.

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
