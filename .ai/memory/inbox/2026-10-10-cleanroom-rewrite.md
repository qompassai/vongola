# Clean-room rewrite — 2026-10-10

Findings from the rewrite (promote to decisions.md/patterns.md
as they are validated):

- Pingora 0.9 moved Prometheus into a separate crate
  (`pingora-prometheus`); this rewrite keeps its own small
  registry so the metrics contract stays in-tree.
- OpenSSL 3.6.5 on the build host lists `X25519MLKEM768` and
  `SecP384r1MLKEM1024` groups — the ML-KEM-1024 hybrid is
  reachable at the TLS layer without a custom stack.
- The old tree's defects (graceful-shutdown stall, empty metrics
  registry) are regression contracts in SPEC §2/§14 with smoke
  proofs, not just fixes.
