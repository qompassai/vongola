# Operations and fleet runbook

<details>
<summary>Build and verify</summary>

```bash
cargo build --release          # links system OpenSSL >= 3.5 (see TLS chapter)
cargo test                     # unit suite (validation + adversarial)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
bash scripts/smoke.sh          # full live smoke (loopback fixtures + tor + NAT)
nix build                      # sandbox build, runs the test suite
nix flake check
```

The IDE gate used for this codebase is Matt's own stack:
headless Neovim with the live diver config — rust-analyzer,
bacon-ls running the clippy job, and crates-lsp on the
manifests — at zero error/warning diagnostics.

</details>

<details>
<summary>Run</summary>

```bash
vongola validate-config --config /path/to/config.yaml
vongola serve --config /path/to/config.yaml
vongola mcp --config /path/to/config.yaml   # stdio MCP for local tooling
vongola version
```

Day-2 surfaces: `GET /healthz` and `/metrics` on the admin
listener; the dashboard at `/dashboard`; hot reload via
`POST /api/reload` with the operator token (a failed reload
keeps the running state); self-signed rotation via
`POST /api/rotate-self-signed` or the MCP tool of the same
intent.

Shutdown is SIGTERM: listeners stop, connections drain within
`shutdown_grace_secs`, NAT mappings are released, and the
process exits (smoke measures ~0.1 s on loopback; the cap is
the bound, not the expectation).

</details>

<details>
<summary>Fleet rollout</summary>

1. Bump `bundle_version`, validate the bundle
   (`validate-config`), and record its SHA-256 fingerprint.
2. Roll the same file to every node (any config-sync tool; the
   nodes are shared-nothing and order-independent).
3. Verify convergence on each node's dashboard or
   `config_snapshot` MCP tool: bundle version + fingerprint
   must match across the fleet; Agent Cards carry the same
   fingerprint for peer checks.
4. Front the fleet with anycast or an L4 balancer health-checking
   the admin `/healthz`; no sticky sessions are needed.

ARM64 status: the flake declares `aarch64-linux`; on an x86_64
build host without a remote/ARM builder, `nix build
.#packages.aarch64-linux.default` evaluates but cannot compile
natively — Jetson targets should build on-device or on an ARM
builder. The Rust code has no x86-only dependencies; the gap is
build-host architecture, and it is stated here rather than
papered over.

</details>

<details>
<summary>Troubleshooting shapes</summary>

- **Handshake failures after config change:** `validate-config`
  first; then check the cert inventory (dashboard/MCP) — no cert
  + no `self_signed_fallback` = deliberate failure.
- **TLS negotiated a classical group:** the binary was built
  against vendored or < 3.5 OpenSSL. Rebuild per the TLS
  chapter; `ldd` should show the system `libssl.so.3`.
- **NAT state shows an error:** read `last_error` — gateway
  refusals and SOAP faults are surfaced verbatim. The proxy is
  unaffected.
- **Tor status shows an error:** the daemon is unreachable or
  unauthenticated; publication retries in the background and the
  proxy keeps serving.
- **502s on one route:** check upstream health and, for chained
  routes, hop health on the dashboard — chains fail closed by
  design.

</details>
