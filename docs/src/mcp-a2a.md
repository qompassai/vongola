# MCP and A2A operator surfaces

Vongola operates "MCP/A2A as much as possible": it exposes an
operator MCP server, publishes a signed A2A Agent Card, serves
Agent Card discovery for hosted routes, and proxies A2A-shaped
traffic like any other route traffic.

<details>
<summary>MCP server</summary>

Two transports, one tool table: stdio (`vongola mcp --config …`,
for local tooling and editors) and HTTP (`POST /mcp` on the
admin listener). Tools, alphabetical:

- Read-only: `agent_card_get`, `cert_inventory`,
  `config_snapshot`, `config_validate`, `metrics_get`,
  `nat_status`, `route_list`, `tor_status`, `upstream_health`.
- Mutating: `config_reload`, `rotate_self_signed`.

Authorization is **deterministic and decided before execution**
from the tool table: a mutating tool without the operator token
is denied outright (stdio: the token comes from the configured
env var in the MCP process's environment; HTTP: the admin
auth posture). Smoke proves an unauthenticated `config_reload`
is denied with a structured error while `route_list` answers.
Certificate inventory returns fingerprints and expiry — **never
key material**. The MCP surface is off unless configured: the
HTTP endpoint follows the admin listener's auth, and stdio
exists only when an operator runs the subcommand.

</details>

<details>
<summary>Read-only operator MCP: vongola-mcp</summary>

`vongola mcp` builds its own in-process state, so its counters
and health maps describe that stdio process, not the running
daemon. `vongola-mcp` is the read-only alternative that reports
on the **running daemon**. It is a separate workspace package
and not a default member, so a plain `cargo build` and the
flake's package build are unchanged. Enable it explicitly:

```bash
cargo build --release -p vongola-mcp
target/release/vongola-mcp --config /path/to/vongola.yaml
```

Register it with an MCP client as a stdio server with that
command line. Posture:

- **stdio only.** It opens no listener. Its only outbound traffic
  is HTTP GETs to the daemon's admin listener (`/api/state`,
  `/metrics`), resolved from the config on every call.
- **Operator-local.** The admin bind must be loopback
  (`0.0.0.0` / `[::]` are dialled on loopback); any other
  address is refused before a socket opens, so the operator
  token never crosses a network on this plain-HTTP path. The
  token is read from the env var named by `admin_token_env`
  (default `VONGOLA_OPERATOR_TOKEN`) and sent only as a Bearer
  header. With no token, the daemon's loopback read rule
  applies.
- **Read-only.** Tools, alphabetical: `cert_status`,
  `log_counters`, `routes_list`, `tls_stats`, `upstream_health`.
  None of them takes arguments, and no tool writes. Mutating names
  such as `config_reload` are unknown tools (-32602).
- **Never invented.** Every call fetches fresh data. If the daemon
  is unreachable, the call returns an MCP tool error
  (`isError: true`) whose `structuredContent` is
  `{"error": {"code": "daemon.unavailable", "message": …}}`.
  A series an older daemon does not export is
  `daemon.metric_missing`, not a zero. Rates over zero traffic
  are `null`.

Protocol: newline-delimited JSON-RPC 2.0, frames bounded at
1 MiB. Malformed JSON → -32700, invalid request (including
batches) → -32600, unknown method → -32601, bad params or
unknown tool → -32602. Notifications are never answered.

| Tool | Source | Answer |
|---|---|---|
| `cert_status` | `/api/state` | per SNI: subject, issuer, `not_after` (as `openssl x509 -enddate` prints it), days remaining, `expiring_soon` (< 30 days), `expired` |
| `log_counters` | `/metrics` | lines by level × source, errors+warnings, dropped lines |
| `routes_list` | `/api/state` | routes, upstreams, chains, SNI names |
| `tls_stats` | `/metrics` | handshakes by group, hybrid PQ count, classical fallback + rate, failures by class + rate |
| `upstream_health` | both | up/down/unknown per `route/address`, latency count, mean, p50/p90/p99 bucket bounds |

</details>

<details>
<summary>A2A Agent Card</summary>

With `a2a.enabled`, the node serves a signed Agent Card at
`/.well-known/agent-card.json` (on both the HTTPS proxy and the
HTTP app): name, URL, capabilities, skills, and an Ed25519
signature over the canonical-JSON card. The signing key is
generated per node into the state dir at 0600 and is never
logged or served. The card's extension block carries the node
name, host, and **config bundle version**, tying A2A discovery
to the fleet's configuration fingerprint. Peers verify cards
with the published public key (`verify_card` in the `a2a`
module, exercised by tests).

Hosted A2A agents need nothing special: their card and task
endpoints are ordinary route traffic, with route-level
`a2a_enabled` marking intent in config and listings.

Key custody is deliberately boring: keys are files in the state
dir with 0600 permissions, consumed via config like any
operator-supplied secret — the same shape a fleet node uses for
certificates issued by external tooling (e.g. volta). The builds
are not coupled.

</details>
