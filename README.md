# Vongola

<a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>

Vongola is Qompass AI's reverse proxy and web server — a
clean-room rewrite on **Pingora 0.9.0**. It hosts **qompass.ai**,
runs on a single small device, and scales across a fleet of
small nodes (NVIDIA Jetson-class dev kits, thin/slim clients)
sharing one versioned configuration bundle.

- **Hosting**: SNI TLS termination, www→apex 308, static hosting
  with cache rules + gzip, proxied routes with health-checked
  round-robin upstreams.
- **Post-quantum TLS**: TLS 1.3 only with ML-KEM hybrid key
  exchange — live-negotiated `X25519MLKEM768` in smoke. Builds
  must link system OpenSSL ≥ 3.5 (see the book's TLS chapter for
  the vendored-OpenSSL trap).
- **Operator surfaces**: MCP server (read-only-first, auth-gated
  mutations), signed A2A Agent Card, populated Prometheus
  metrics, and a live dashboard (NAT, Tor, chains, upstreams,
  certs).
- **NAT traversal**: PCP / NAT-PMP / UPnP IGD, opt-in per
  listener, leased and released on shutdown.
- **Tor onion services**: publish routes as v3 onion services.
  **Vongola is never a Tor exit node** — enforced in config
  validation, not just documented.
- **Proxy chains**: SOCKS5h / HTTP CONNECT / Tor / vongola hops,
  DNS through the chain, fail closed (a dead hop is a 502, never
  a direct fallback).

## Quickstart

```bash
cargo build --release
./target/release/vongola validate-config --config examples/qompass.yaml
./target/release/vongola serve --config examples/lean.yaml
bash scripts/smoke.sh   # full live smoke against loopback fixtures
```

## Documentation

The mdBook in `docs/src` (build with `mdbook build`) covers
architecture, the hosting/lean/fleet profiles, the TLS/PQC
posture with negotiation evidence, MCP/A2A, NAT, Tor, chains,
the dashboard, a configuration reference, the operations
runbook, the Homa and Mojo verdicts, and the feature accounting
against the previous tree. `SPEC.md` is the clean-room contract
the implementation was written against.

## License

Apache-2.0. Copyright 2026 Qompass AI.
