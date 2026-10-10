# Feature accounting

Every feature the old tree's book and README promised is
accounted for: kept (rewritten clean-room), changed with a
reason, or cut with a reason. Defects are not features and are
listed separately. Net-new capabilities commissioned for the
rewrite close the chapter.

<details>
<summary>Kept — rewritten (17)</summary>

ACME HTTP-01 challenge surface and validation (placeholder
email rejected even when disabled) · basic auth · bounded log
channel (1024, drop counter) · Docker/Swarm label discovery ·
graceful shutdown — now proven, see Defects · HTTP→HTTPS 308 ·
in-memory caching (static profile) · JWT auth · Let's Encrypt
config contract · metrics — now populated, see Defects ·
OAuth2 (GitHub/WorkOS) · Prometheus endpoint · request IDs ·
round-robin LB + TCP health checks · self-signed fallback
(explicit per-route opt-in) · SNI certificate selection ·
YAML config with `VONGOLA_`-style env-sourced secrets.

</details>

<details>
<summary>Changed with reasons (2)</summary>

- **OAuth2 state**: was an obfuscated blob (a documented
  weakness); now base64url(payload) + HMAC-SHA256 with the
  documented 120-second lifetime enforced.
- **Config format**: YAML is canonical. HCL input returns a
  structured error — one parser, one validation surface, no
  function evaluation in config (see Cut).

</details>

<details>
<summary>Cut with reasons (3)</summary>

- **HCL config** — halves the parse/validate/test surface and
  removes HCL function evaluation from the config attack
  surface. Revisit only on demonstrated operator demand.
- **WASM/WIT plugin scaffold** (`plugins_api` in the old tree)
  — a scaffold, not a working plugin system; the auth features
  it gestured at are in-process now. Revisit when a real
  out-of-process plugin need exists.
- **Disk response cache + full ACME order/finalize client** —
  the static profile's in-memory cache covers the hosting need;
  the ACME challenge surface is wired and validation-complete,
  but there is no publicly reachable test endpoint in the build
  environment to prove an issuance flow against, so the client
  is specified, surfaced, and explicitly not claimed. Both are
  named gaps, not silent drops. (An earlier research pass marked
  the disk cache keep-rewrite; implementation-time accounting
  supersedes it — this chapter is the final word.)

</details>

<details>
<summary>Defects — fixed and proven, not kept</summary>

- Graceful-shutdown stall (SIGTERM → SIGKILL, 3/3): **fixed**;
  smoke measures ~0.1 s complete shutdown.
- Empty metrics registry: **fixed**; the registry renders
  populated from boot and counts from the first request.
- OAuth2 authorization code reaching logs: **fixed by
  construction** — the redacting log pipeline plus a smoke log
  audit for secret patterns.
- The old tree's ~102 `unwrap`/`expect` sites in first-party
  code: the rewrite's are confined to startup invariants and
  tests, with clippy `-D warnings` clean.

</details>

<details>
<summary>Net-new in this rewrite (11)</summary>

A2A signed Agent Card · dashboard (live NAT/Tor/chain state) ·
fleet profile (bundle fingerprint, peers) · Homa verdict
(documented negative) · lean profile (measured ~20 MB RSS) ·
MCP operator server (read-only-first, auth-gated mutations) ·
Mojo verdict (documented, one gated proposal) · NAT traversal
(PCP/NAT-PMP/UPnP, live-mapped in smoke) · post-quantum hybrid
TLS (live-negotiated `X25519MLKEM768`) · proxy chains
(fail-closed, live-proven) · Tor onion services (never-exit
enforced; live-published in smoke).

</details>
