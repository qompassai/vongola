# Operations

## Build

```sh
cargo build --release        # or: nix build
```

The toolchain is pinned by `rust-toolchain.toml`
(nightly-2026-09-25, rustc 1.100.0-nightly); the workspace is
edition 2024 with `rust-version = "1.88"` as the declared floor.

## Run

```sh
vongola --config-path /etc/vongola/configs
```

`--config-path` points at a directory of YAML/HCL config files (see
`examples/example.yaml` and `examples/example.hcl`); without it the
fallback path baked into `main.rs` is `/etc/vongola/configs`.
Environment overrides use the `VONGOLA_` prefix with `__` for nesting
(e.g. `VONGOLA__LOGGING__LEVEL=DEBUG`).

## Ports

| Port | Service |
|------|---------|
| 8080 | HTTP → HTTPS redirect (308) |
| 4433 | HTTPS proxy (TLS, SNI, HTTP/2) |
| 9090 | Prometheus-format metrics HTTP |

## Smoke evidence (2026-10, this tree)

With a one-route config (host `smoke.local`, upstream a local static
server, `self_signed_on_failure: true`, Let's Encrypt disabled):
`GET /marker.txt` on :8080 returned `308 -> https://smoke.local/...`;
the same fetch over :4433 completed the TLS handshake (self-signed
certificate created on demand) and returned the upstream body;
:9090 answered 200 with an empty metrics body (see Security →
Named gaps).
