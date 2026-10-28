# Architecture

Vongola is one Rust binary on Pingora 0.9.0 (pinned `=0.9.0`,
verified as the latest release on crates.io at build time,
2026-10-10). Pingora provides the server framework, HTTP proxy
machinery, connection pooling, and the OpenSSL-backed TLS
acceptor; everything product-shaped — configuration, routing,
auth, NAT, Tor, chains, MCP/A2A, the dashboard — is vongola code
in a single crate with alphabetically ordered modules.

<details>
<summary>Process layout</summary>

One process, three listeners, one background service:

- **HTTPS listener** — the Pingora proxy service. SNI selects the
  certificate through a `TlsAccept` callback; TLS settings pin
  TLS 1.3 and the configured group allowlist (see the TLS
  chapter). HTTP/2 is enabled.
- **HTTP listener** — a small `ServeHttp` app: 308 redirect to
  HTTPS, ACME HTTP-01 challenge answers, and the Agent Card over
  HTTP.
- **Admin listener** — a `ServeHttp` app for operators:
  `/healthz`, `/metrics`, `/api/state`, `/dashboard`,
  `/api/reload`, `/api/rotate-self-signed`, `/mcp`. Mutations
  require the operator token; nothing here is reachable from the
  public routes.
- **Background service** — upstream health checks and chain
  probes, NAT mapping managers (acquire/renew/release), Tor
  onion publication with retry, and Docker/Swarm discovery.

Subcommands (alphabetical): `mcp` (stdio MCP server), `serve`
(the default), `validate-config`, `version`.

</details>

<details>
<summary>Request path</summary>

`request_filter` decides everything before an upstream is
touched: www→apex 308, route lookup by host + longest path
prefix, the Agent Card path, a Content-Length body bound
(default 16 MiB, per-route override; oversized is a 413), route
auth (basic, JWT, or the OAuth2 dance), static-file service for
hosting routes, and chained fetch for chained routes. Plain
routes select a healthy upstream round-robin; all-known-down is
a 502. `logging` records the access line and metrics — through a
bounded (1024) redacting log pipeline whose drop counter is
itself a metric. Credentials, tokens, and authorization codes
are redacted before any log line is emitted, and a test audits
for secret patterns.

</details>

<details>
<summary>State and reload</summary>

Shared state lives behind locks in one `State` struct: current
config (atomically swapped), the certificate store, ACME
challenges, upstream and chain health, NAT and Tor status,
discovered upstreams, and metrics. `POST /api/reload` (operator
token required) re-reads the config file, rebuilds the
certificate store, and swaps both atomically; a failed reload
keeps the old state and returns the structured errors. The
config's canonical-JSON SHA-256 is the fleet bundle fingerprint
shown on the dashboard and in the Agent Card.

</details>

<details>
<summary>Design rules</summary>

- **Fail closed.** Invalid config, unknown SNI, dead chain hops,
  exit-enabling Tor settings, pure-ML-KEM TLS groups, HCL input:
  all are structured errors, never silent fallbacks.
- **Every knob is wired.** Each config field has a validation or
  behavior test. The cautionary tale from the old tree — a
  parsed-but-unwired flag that made handshakes impossible — is
  why `worker_threads` and `shutdown_grace_secs` are wired into
  `ServerConf` explicitly and proven in smoke.
- **Bounded everything.** Log channel, body sizes, chain length
  (8 hops), cache sizes, response sizes, timeouts. Tiger Style:
  explicit contracts, no hidden behavior, alphabetical order in
  modules, files, functions, and lists.

</details>
