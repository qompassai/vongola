# Introduction

Vongola is Qompass AI's reverse proxy and web server: a clean-room
rewrite on **Pingora 0.9.0**, built to host **qompass.ai**, to run
on a single small device, and to scale out across a fleet of small
nodes (NVIDIA Jetson-class dev kits, thin/slim clients) that share
one versioned configuration bundle.

The rewrite was specified before it was written. `SPEC.md` at the
repository root is the contract: it was derived from public
surfaces only — Pingora's public documentation and API, the
previous tree's published book and README contracts, the relevant
RFCs (6886 NAT-PMP, 6887 PCP), the UPnP IGD template, and the Tor
control protocol specification.

<details>
<summary>What vongola does</summary>

- HTTP → HTTPS redirect (308), SNI-based certificate selection,
  HTTP/2, static-site hosting with cache rules and compression,
  and reverse proxying with round-robin load balancing and TCP
  health checks.
- TLS 1.3 only, with post-quantum hybrid key exchange
  (ML-KEM hybrids) proven by live negotiation capture.
- Operator surfaces: an MCP server (stdio and HTTP) with
  deterministic allow/deny, a signed A2A Agent Card, Prometheus
  metrics that are populated from the first request, and a live
  operator dashboard.
- NAT traversal (PCP, NAT-PMP, UPnP IGD) — opt-in per listener,
  logged, leased, and released on shutdown.
- Tor onion services for configured routes. **Vongola is never a
  Tor exit node** — see the Tor chapter; the rule is enforced in
  config validation, not just documented.
- Egress proxy chains (SOCKS5/SOCKS5h, HTTP CONNECT, Tor,
  vongola-to-vongola) that fail closed: a dead hop is a 502,
  never a silent direct connection.

</details>

<details>
<summary>The two defects this rewrite had to kill</summary>

The previous tree shipped with two named defects, and both are
requirements here, with live proof in `scripts/smoke.sh`:

1. **Graceful shutdown stalled** (SIGTERM logged, SIGKILL needed).
   The rewrite wires the configured grace period into Pingora's
   `ServerConf` — Pingora's default drain timeout is unbounded,
   which is precisely the trap — and the smoke suite measures a
   complete SIGTERM shutdown in ~0.1 s on loopback.
2. **The metrics registry was empty.** The rewrite's registry is
   rendered unconditionally and instrumented from the start:
   request counts by status class and route, latency sums, cache
   hits/misses, chain failures, dropped log lines, upstream
   health, certificate expiry, NAT and Tor state gauges.

</details>

<details>
<summary>Reading this book</summary>

Chapters follow the deployment story: architecture, then the
three profiles, then each subsystem (TLS, MCP/A2A, NAT, Tor,
chains, dashboard), then the configuration reference and the
operations runbook. The Homa and Mojo chapters record feasibility
verdicts with evidence. The final chapter is the feature
accounting against the previous tree — every old promise is kept,
changed with a reason, or cut with a reason.

</details>
