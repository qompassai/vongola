# 2026-10-18 — instrumentation + read-only vongola-mcp

Branch `pax/vongola-mcp-20261018` (off master 5f483d9).

- Brief premise corrected: the registry was not empty (admin
  `/metrics` on 127.0.0.1:9091 already served request/cache/health
  series). Real gaps: no TLS counters, no histograms, route not
  crossed with status class, cert expiry frozen at load time, and
  `vongola mcp` (stdio) reporting its OWN fresh process state —
  zero counters — rather than the daemon's.
- Negotiated group, safe APIs only: `SslRef::peer_tmp_key()` on
  the server. Classical: key id (+ EC curve). Hybrids are
  provider keys (id -1), identified by (bits, size):
  SecP384r1MLKEM1024 = (1024, 1665), X25519MLKEM768 = (768, 1120).
  Measured on OpenSSL 3.6.5; pinned by real-handshake tests in
  cert.rs. NOT yet verified on the flake's OpenSSL 4.0.3 build —
  if `nix build` fails there, that test names the drift.
- Failures: Pingora 0.9 gives no handshake-failure hook. A
  ClientHello callback stores a `HandshakeGuard` in SSL ex-data;
  its Drop (at SSL_free) counts a failure by last stage. Classes
  are stages, not alerts (no safe alert accessor).
- vongola-mcp: workspace member, not default member (the flake
  builds with `--features ech` at the root; a featureless member
  would break that).
