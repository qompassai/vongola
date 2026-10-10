<p align="center">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

# Vongola

A reverse proxy built on [Pingora](https://github.com/cloudflare/pingora):
TLS termination with SNI certificate selection, host/path routing,
response caching, authentication plugins (JWT, OAuth2, basic auth),
Let's Encrypt issuance, and Docker/Swarm discovery.

## Quickstart

```sh
cargo run --release -- --config-path ./examples
# HTTP :8080 redirects to HTTPS; HTTPS proxy on :4433; metrics on :9090
```

Or with Nix: `nix build` / `nix develop` (see the book's Nix chapter).

## Documentation

The full documentation is an mdBook under [`docs/src/`](docs/src/)
(what it is, architecture, contracts and bounds, security model,
operations, Nix usage, and the testing story):

```sh
mdbook build   # renders to book/ (gitignored)
```

<details>
<summary>Toolchain</summary>

Pinned by `rust-toolchain.toml`: nightly-2026-09-25
(rustc 1.100.0-nightly), edition 2024. Gates: `cargo build`,
`cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`,
`mdbook build` — all green; see the book's Testing chapter for the
suite shape and the named gaps (metrics instrumentation, graceful
shutdown timing, OAuth2 state AEAD).

</details>

<details>
<summary>License</summary>

Apache-2.0 — see [LICENSE](LICENSE). Copyright 2026 Qompass AI.

</details>
