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
  </div>
  <blockquote style="font-size: 1.2em; line-height: 1.8; padding: 25px; background: #f8f9fa; border-left: 6px solid #667eea; border-radius: 8px; margin: 15px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <details>
      <summary style="font-size: 1em; font-weight: bold; padding: 10px; background: #e9ecef; color: #333; border-radius: 5px; cursor: pointer; margin: 10px 0;">
        <strong>📄 We advise you read the script BEFORE running it 😉</strong>
      </summary>
      <pre style="background: #fff; padding: 15px; border-radius: 5px; border: 1px solid #ddd; overflow-x: auto;">
#!/usr/bin/env bash
# /qompassai/vongola/scripts/quickstart.sh
# Qompass AI Quick Start Script
# Copyright (C) 2025 Qompass AI, All rights reserved
####################################################
      </pre>
    </details>
    <p>Or, <a href="https://github.com/qompassai/vongola/blob/main/scripts/quickstart.sh" target="_blank">View the quickstart script</a>.</p>
  </blockquote>
</details>

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
