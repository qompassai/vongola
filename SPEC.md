# #################################################################
# /qompassai/vongola/SPEC.md
# Qompass AI — Vongola Clean-Room Specification
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Qompass AI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# #################################################################

# Vongola — Clean-Room Behavior and Interface Specification

This specification was written from public surfaces only: the Pingora
framework's public documentation and crate APIs (Pingora 0.9.0,
crates.io, verified 2026-10-10), the previous tree's published
mdBook/README contracts and example configuration files, the public
protocol specifications cited per section, and black-box behavior
(ports, status codes, redirect semantics). No implementation source
from the previous tree was consulted. The implementation that follows
this spec is original.

## 1. Identity and non-goals

<details>
<summary>What vongola is</summary>

Vongola is a reverse proxy and web server built on Cloudflare's
Pingora framework. It terminates TLS, routes requests by host and
path to upstreams or to local static content, and is operated through
a configuration file, an operator API, an MCP server, and a live
dashboard. It is designed to (a) host the public website qompass.ai,
(b) run lean on a single small device, and (c) run as one of many
identical shared-nothing nodes in a small fleet (NVIDIA Jetson-class
dev kits, thin clients).

Non-goals: vongola is not a Tor exit node (hard rule, §9), not a
general-purpose forward proxy for arbitrary clients, not a
certificate authority, and not a plugin runtime (the previous tree's
WASM/WIT scaffold is spec-cut, §13).

</details>

## 2. Observable network surface

<details>
<summary>Listeners and their contracts</summary>

Alphabetical by role; every listener is config-gated and may be
disabled.

- **Admin listener** (default `127.0.0.1:9091`, loopback unless the
  operator overrides): metrics, dashboard, operator API, MCP-over-HTTP.
  See §10 and §11.
- **HTTP listener** (default `[::]:8080`): every request is answered
  `308 Permanent Redirect` to the same host and path on the HTTPS
  listener, except ACME HTTP-01 challenge paths (§7) and, when
  configured, `/.well-known/agent-card.json` (§12). This listener
  never proxies application traffic.
- **HTTPS listener** (default `[::]:4433`): TLS 1.3 only (§6), SNI
  certificate selection, HTTP/2 and HTTP/1.1, the proxy and static
  hosting data path.
- **Metrics**: served on the admin listener at `/metrics`
  (Prometheus text format). The registry is populated from the first
  request: request counters by route and status class, request
  latency histograms, upstream health gauges, cache counters,
  dropped-log-line counter. An empty registry is a defect.

</details>

## 3. Configuration

<details>
<summary>One canonical format, fail-closed validation</summary>

- Canonical format: **YAML**. HCL files from the previous tree are
  accepted only through an explicit import note: the rewrite does not
  parse HCL (justification in §13); `vongola validate-config`
  reports HCL input as a structured error naming the conversion.
- Environment overrides use the `VONGOLA_` prefix for the operator
  token only; secrets never live in the config file. Auth user
  entries carry SHA-256 password hashes, never plaintext.
- Validation is fail-closed with structured errors
  (`{code, field, message}`): unknown fields are rejected
  (`deny_unknown_fields`), every listener address must parse, every
  route must have at least one upstream or a static root, TLS policy
  must satisfy §6, chain definitions must be acyclic (§8), Tor
  settings must satisfy the never-exit rule (§9), NAT settings are
  per-listener opt-in (§9 in the NAT section, §8 of this spec's
  numbering is chains; see §9/§10 split below).
- Hot reload: `POST /api/reload` (operator-authenticated) and the
  MCP `config_reload` tool re-read the file, re-validate, and swap
  the routing table atomically. A failed reload keeps the old table
  and reports the structured error. In-flight connections are not
  dropped by a reload.
- Every configuration knob has a wiring test: a knob that parses but
  does nothing is a defect by definition here.

</details>

## 4. Routing, upstreams, load balancing, health

<details>
<summary>Data path contract</summary>

- Routes match on exact host (plus optional additional hosts) and
  path patterns (`/api/*` prefix form and exact paths).
- `www.<apex>` redirects to the apex with 308 when the hosting
  profile enables it (§5).
- Upstreams are load-balanced round-robin with connection reuse
  (Pingora pooling) and background TCP health checks (configurable
  interval; unhealthy upstreams are skipped; when all upstreams are
  down the route answers 502 with a structured log line, never a
  panic and never a stale success).
- Request bounds: header count/size and body size are bounded per
  route (`max_body_bytes`, default 10 MiB); oversized requests are
  rejected 413 before reaching an upstream.
- Security headers are added on responses when the route enables
  them (hosting profile default): `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`,
  `X-Frame-Options: DENY` (configurable).
- Request IDs: every request gets `req-<counter>` unless the client
  supplied `X-Request-Id`, which is propagated; the ID is on the
  response and in logs.
- Logs never contain credentials: authorization headers, cookies,
  OAuth2 codes, tokens, and private keys are redacted by
  construction (the logger has no code path that prints them), and
  an adversarial test scans captured log output for secret patterns.

</details>

## 5. Hosting profile (qompass.ai)

<details>
<summary>Static site plus reverse proxy, config-driven</summary>

A route may declare `static_root` instead of upstreams: vongola
serves files from that directory (path traversal is impossible —
normalized paths must stay under the root; dotfiles are not
served), with:

- Cache rules: fingerprinted assets (content-hash in the filename)
  get `Cache-Control: public, max-age=31536000, immutable`; HTML
  gets `no-cache`; everything else gets the route's configured
  `cache_max_age_secs`. An in-memory cache (bounded entries and
  bytes, TTL from the same rules) serves repeat GETs and reports
  `X-Vongola-Cache: HIT|MISS`.
- Compression: gzip for text types when the client offers it.
- `index.html` for directory requests; a configured SPA fallback
  file for unknown paths when enabled; 404 otherwise.
- The qompass.ai reference profile ships as an example config:
  apex + www→apex redirect, static root, `/api/*` proxied to a
  local upstream, security headers on, ACME or operator certs.

</details>

## 6. TLS and post-quantum posture

<details>
<summary>TLS 1.3 only, hybrid PQ key exchange, evidence-based</summary>

- TLS versions below 1.3 are refused at config validation and at
  the handshake (no config can enable them). Cipher policy is an
  allowlist: TLS 1.3 suites only (they are AEAD by construction).
- Key exchange groups, in preference order:
  `SecP384r1MLKEM1024`, `X25519MLKEM768`, `X25519`, `secp256r1`,
  `secp384r1`. The stack evidence: Pingora 0.9's OpenSSL backend on
  OpenSSL 3.6.5, whose group list includes both hybrids (verified
  on the target host with `openssl list -tls-groups`). Pure
  ML-KEM groups are not offered for TLS key exchange (hybrids
  only — a classical break alone or a PQ break alone must not
  suffice).
- Downgrade attempts (TLS 1.2 ClientHello, weak-group-only offers)
  must fail the handshake; the smoke suite captures the actually
  negotiated group with `openssl s_client` and records it.
- Certificates: operator-supplied PEM (cert + key paths) selected
  by exact SNI; a per-route self-signed fallback exists only when
  the route sets `self_signed_fallback: true` (explicit opt-in;
  generated once, persisted under the state directory with 0600 key
  permissions, ECDSA P-384). No certificate for an SNI name and no
  fallback → handshake failure, never a wrong certificate.

</details>

## 7. Certificates and ACME

<details>
<summary>Issuance surface</summary>

- Operator-supplied certificates are the primary path (§6).
- ACME (RFC 8555) HTTP-01: the HTTP listener answers
  `/.well-known/acme-challenge/<token>` from the challenge store;
  the account key and orders live under the state directory
  (0600). Email must be present and must not be a placeholder
  domain (`@example.com` is rejected even when issuance is
  disabled — carried over from the previous tree's published
  validation contract).
- Full ACME client completion is staged: the challenge responder,
  account-key storage, validation, and config surface are part of
  this rewrite; the order/finalize client is accounted in §13.

</details>

## 8. Proxy chains (egress obfuscation / hostile-network defense)

<details>
<summary>Ordered hops, DNS through the chain, fail closed</summary>

- A route or upstream may declare `chain`: an ordered list of hops,
  each one of `socks5` (hostname carried through — SOCKS5h
  semantics, RFC 1928 ATYP 3), `http-connect` (RFC 9110 §9.3.6),
  `tor` (the local Tor SOCKS port, §9), or `vongola` (another
  vongola node's CONNECT endpoint).
- DNS is resolved through the chain only: a chained route never
  performs a local DNS lookup for the upstream name (the name is
  handed to the final hop). A test asserts no local resolution
  occurs (the dialer has no code path for it).
- **Fail closed**: if any hop is unreachable or refuses, the
  request fails 502 with a structured error. There is no direct
  fallback, silent or otherwise; an adversarial test kills the
  first hop and asserts 502 and zero direct connections.
- Config validation rejects malformed hops and cyclic chains
  (a chain that names its own node identity twice, or exceeds
  `max_chain_hops`, default 8).
- Chained nodes do not log inner destinations: logs record route,
  hop count, and outcome — never the chained target host. (The
  node forwarding a connection necessarily sees the next hop; it
  must not record the final destination beyond forwarding need.)
- Dashboard (§11) shows per-route configured chain vs active
  chain, per-hop health and latency from the health checker.
- Honesty bound: chains hide metadata from local observers (an
  evil-twin access point sees only the first hop) and frustrate
  single-point collection. Content integrity rests on TLS 1.3 +
  the PQ hybrid layer (§6), not on chains.

</details>

## 9. Tor onion services — NEVER an exit node

<details>
<summary>Hard rule, enforced in validation</summary>

**Vongola must never operate as a Tor exit node.** Default posture
is client/onion-service only: no relaying at all unless the
operator explicitly configures a non-exit relay.

- A route may declare `onion: {enabled: true, virt_port: 80}`:
  vongola publishes a v3 onion service for that route through the
  Tor daemon's control port (`ADD_ONION NEW:ED25519-V3`,
  Tor control-spec), forwarding the virtual port to the route's
  local listener. The returned private key is persisted by the
  operator's state directory at 0600 (vongola stores the key file
  itself when `persist_key: true`; the key is never logged, never
  in config, never in the dashboard).
- Daemon choice: external `tor` daemon via the control protocol is
  the primary path (mature control surface; tor 0.4.9.x on the
  target host). Arti (2.7.0 on the target host) is evaluated in the
  book: its proxy mode is solid, its onion-service support is
  younger; embedded Arti is a documented future option, not the
  default.
- **Fail-closed validation**: any configuration that would enable
  exit behavior — `tor.exit_relay: true`, an exit policy that
  accepts any port/address, or a torrc fragment containing
  `ExitRelay 1` / non-reject `ExitPolicy` — is a structured config
  error and the process refuses to start. When relaying is enabled
  at all, vongola forces `ExitRelay 0` and `ExitPolicy reject *:*`
  in the torrc it generates. An adversarial test proves the
  rejection.
- Dashboard (§11) shows onion services with their public `.onion`
  addresses and status — never key material.

</details>

## 10. NAT traversal

<details>
<summary>UPnP IGD, NAT-PMP, PCP — config-gated, logged, no silent holes</summary>

Protocols from their public specs: PCP (RFC 6887), NAT-PMP
(RFC 6886), UPnP IGD (WANIPConnection service).

- Per-listener opt-in only: `nat: {enabled: true, protocols:
  [pcp, natpmp, upnp], lease_secs: 3600}` on a listener asks
  vongola to acquire an external mapping for that listener's port.
  Nothing is mapped for listeners without the opt-in.
- Acquisition order: PCP → NAT-PMP → UPnP IGD (SSDP discovery,
  `AddPortMapping`). External address is learned from the mapping
  protocol response (`GetExternalIPAddress` / PCP/NAT-PMP
  external-address opcodes).
- Lifetime management: mappings are renewed at half their granted
  lifetime; renewal failure is a structured status (dashboard +
  metrics gauge), retried with bounded backoff; mappings are
  released on graceful shutdown (`DeletePortMapping` / lifetime-0
  mapping request).
- Failure reporting: gateway absent, gateway refuses (e.g. UPnP
  error 718 conflict, PCP result codes), or unsupported protocol
  are structured states in the NAT status model — never panics,
  never silent retries forever, never a fallback that exposes a
  different port than configured.
- Every mapping action (acquire, renew, release, failure) is
  logged with listener, protocol, external address/port, and
  lifetime — and no credentials (UPnP is used unauthenticated on
  the LAN by design of the protocol; this is stated, not hidden).

</details>

## 11. Operator surfaces: admin API, dashboard, MCP, A2A

<details>
<summary>One auth posture for all operator surfaces</summary>

Auth: a single operator credential — a bearer token supplied via
the `VONGOLA_OPERATOR_TOKEN` environment variable (never in
config, never logged). When no token is configured, mutating
operations are disabled entirely and read-only operator endpoints
serve only on loopback binds. Denials are deterministic: the
allow/deny decision is made from the tool/action table before any
execution.

- **Admin API** (admin listener): `GET /api/state` (full node
  state JSON), `GET /healthz`, `GET /metrics`,
  `POST /api/reload` (mutating), `POST /api/rotate-self-signed`
  (mutating; regenerates a route's self-signed cert).
- **Dashboard**: `GET /dashboard` serves a self-contained page;
  `GET /dashboard/events` is a Server-Sent Events stream pushing a
  state snapshot at a configured interval (default 2 s) with a
  server timestamp on every frame (visible freshness). Panels:
  NAT (mappings, external address, lease remaining, gateway),
  Tor (onion services + addresses, daemon connectivity), chains
  (per-route hops, health, latency), fleet/hosting basics (node
  health, upstream status, certificate expiry). The dashboard is
  never served on public listeners; unauthenticated requests get
  401 (tested).
- **MCP server**: `vongola mcp` runs a stdio JSON-RPC MCP server;
  the same tools are served at `POST /mcp` on the admin listener.
  Read-only tools (default on): `agent_card_get`, `cert_inventory`
  (names, expiry, fingerprints — never key material),
  `config_snapshot`, `config_validate`, `metrics_get`,
  `nat_status`, `route_list`, `tor_status`, `upstream_health`.
  Mutating tools (operator token required, enumerated here):
  `config_reload`, `rotate_self_signed`. Unknown tools and
  unauthenticated mutations are denied before execution (tested).
- **A2A**: when enabled for a route or the node, vongola serves a
  signed Agent Card at `/.well-known/agent-card.json` (Ed25519
  signature over the canonical card JSON; the signing key lives in
  the state directory at 0600 and is generated on first use). The
  card describes the node's hosted services and skills. A2A
  traffic (card discovery and task endpoints on configured
  upstreams) passes through as ordinary routed traffic with A2A
  paths preserved; vongola does not terminate A2A semantics.
  Signing keys are consumed as files — vongola's A2A identity is
  independent of any external key service (volta's domain); an
  operator may drop in a key provisioned elsewhere.

</details>

## 12. Profiles: hosting, lean, fleet

<details>
<summary>Same binary, config-selected posture</summary>

- **Hosting**: §5 with the qompass.ai reference profile.
- **Lean** (`profile: lean`): bounded worker threads (default 2),
  bounded connections, cache disabled unless configured, dashboard
  and MCP still available on loopback. The binary's resident
  memory at idle and under load is measured in the smoke suite
  and recorded in the book (target: tens of MiB, reported as
  measured, not as promised).
- **Fleet** (`profile: fleet`): shared-nothing nodes; the config
  file itself is the versioned bundle (`bundle_version` +
  SHA-256 printed at startup and in `/api/state`, so an operator
  can verify all nodes run the same bundle). Discovery sources
  for upstreams: static lists, peer lists (other nodes' admin
  health endpoints), and Docker/Swarm label discovery (engine API
  over the configured socket/endpoint; labels
  `vongola.host`, `vongola.path_prefix`, `vongola.port`).
  The documented front-of-fleet path is an L4 balancer or anycast
  announcement in front of identical nodes (book chapter; the
  nodes themselves hold no shared state to synchronize).

</details>

## 13. Feature accounting vs the previous tree

<details>
<summary>Kept, cut, and net-new — nothing silently dropped</summary>

Kept, rewritten fresh: 308 redirect listener, SNI TLS proxy,
host/path routing, round-robin LB + TCP health checks, Prometheus
endpoint (defect fixed: registry populated), basic auth, JWT
(HS256) auth, request IDs, self-signed fallback (opt-in per
route), ACME HTTP-01 surface, Docker/Swarm discovery, YAML
config, bounded log channel with drop counter, graceful shutdown
(defect fixed and proven: SIGTERM completes).

Changed with reason: OAuth2 — the authorization-code flow is kept
(redirect, callback, HMAC-SHA256-integrity-protected state with a
120 s lifetime, fixing the previous tree's documented
obfuscation-not-AEAD finding); provider token exchange is kept
for GitHub-compatible endpoints. HCL — import-only note (§3);
YAML is canonical.

Spec-cut with reasons: WASM/WIT plugin scaffold (a scaffold with
no consumers in the published docs; a plugin ABI deserves its
own design, not a carried skeleton); disk response cache
(in-memory cache for static assets covers the hosting contract;
proxied-response caching returns with a dedicated design);
full ACME order/finalize client (challenge surface wired; no
publicly reachable test endpoint exists in the build
environment, and an untested issuance client is worse than an
honest staged surface).

Net-new (this commission): PQ hybrid TLS (§6), MCP operator
server (§11), A2A agent card (§11), NAT traversal (§10), Tor
onion services (§9), proxy chains (§8), dashboard (§11), lean
and fleet profiles (§12), static hosting profile (§5).

</details>

## 14. Shutdown and lifecycle

<details>
<summary>Graceful means graceful, proven</summary>

On SIGTERM/SIGINT the server stops accepting, drains in-flight
requests within a bounded grace period (default 10 s, config
`shutdown_grace_secs`), releases NAT mappings, removes onion
services it created (unless keys/services are configured to
persist), and exits 0. The smoke suite measures SIGTERM-to-exit
and asserts completion well inside the grace bound — the previous
tree's stall (SIGTERM ignored, SIGKILL required) is the named
regression this contract exists to prevent.

</details>
