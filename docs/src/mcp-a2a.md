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
