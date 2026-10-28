# Profiles: hosting, lean, fleet

One binary, three profiles. The profile is a config value
(`profile: hosting | lean | fleet`); profiles change validation
minimums and defaults, not code paths. Example configs live in
`examples/` (`qompass.yaml`, `lean.yaml`, `fleet-node.yaml`) and
are validated by the smoke suite on every run.

<details>
<summary>Hosting — qompass.ai</summary>

The profile that serves qompass.ai: TLS termination with SNI
certificate selection, www→apex 308, a static apex with cache
rules (HTML `no-cache`; fingerprinted assets
`public, max-age=<configured>, immutable`), gzip for text types,
the standard security headers (HSTS, `nosniff`, frame denial,
referrer policy), and proxied API routes behind it. A2A is
enabled so the node publishes its signed Agent Card.

Proven end-to-end in smoke against a fixture site standing in
for the real content: redirect, SNI serving, cache headers,
gzip, the proxied API route, and the card all pass.

</details>

<details>
<summary>Lean — one small device</summary>

For a single on-device node: 2 worker threads, bounded caches,
no heavyweight features on by default. Measured on primo
(x86_64, release build): **~20 MB resident at idle, ~20 MB after
300 requests** — flat. The NAT block ships present in the
example but disabled; enabling it is one explicit opt-in per
listener.

ARM64: the Nix flake declares `aarch64-linux` alongside
`x86_64-linux` for Jetson-class targets; see the operations
chapter for the cross-build status and the honest gap.

</details>

<details>
<summary>Fleet — many identical small nodes</summary>

Fleet nodes are shared-nothing: each runs the same versioned
config bundle (`bundle_version` + the canonical-JSON SHA-256
fingerprint) and serves independently. Upstream sources are
static config, Docker/Swarm label discovery
(`vongola.host` / `vongola.port`), and the peer list
(`fleet_peers`). Nodes can chain through each other (see the
chains chapter), publish onion services, and announce themselves
with signed Agent Cards carrying the bundle fingerprint, so a
peer can verify it is talking to the same configuration.

Proven in smoke: two instances on different ports with
different state directories serve the same fixture as separate
nodes.

The documented path to anycast/L4 in front: nodes are stateless
per request (sessions are JWT cookies, not server state), so a
fleet can sit behind BGP anycast or a simple L4 balancer with
health checks against the admin `/healthz` without sticky
sessions. That layer is infrastructure, not vongola code; the
runbook covers the shape.

</details>
