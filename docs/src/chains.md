# Proxy chains

Routes can egress through an ordered chain of proxy hops —
for hostile-network defense: an evil-twin access point or a
local traffic collector should see a connection to the first
hop, and nothing else.

<details>
<summary>Chain model</summary>

A route's `chain` is an ordered list of hops, each one of:

- `socks5` — SOCKS5 with the target sent in hostname form
  (ATYP 3): DNS resolves at the far end of the chain, never
  locally. There is deliberately no local-resolution mode.
- `http-connect` — HTTP CONNECT tunneling.
- `tor` — the configured Tor SOCKS address (which is just a
  SOCKS5 hop whose address defaults from the Tor config).
- `vongola` — an HTTP CONNECT hop to another vongola node, so
  fleet nodes chain through each other. A chained node learns
  the next hop it must dial; it does not log the inner
  destination beyond what forwarding requires.

Validation bounds chains to 8 hops, rejects a hop repeated
identically (`chain.cycle_repeat`), and rejects a hop that
points at the node's own listeners (`chain.cycle_self`).

</details>

<details>
<summary>Fail closed — the whole point</summary>

If any hop is down, the route returns a structured **502**.
There is no direct fallback anywhere in the code path: the only
TCP connection vongola opens for a chained route is to the
first configured hop. Smoke proves both halves live: a route
chained through a local SOCKS5 hop fetches its upstream, and
the same route shape with a dead first hop returns 502 instead
of the content. The unit suite adds a mock-SOCKS5 chained fetch
and the adversarial no-fallback case. Chain failures are a
metric (`vongola_chain_failures_total`) and hop health/latency
is probed by the background service and shown on the dashboard.

Chained responses are bounded (32 MiB) and normalized
(dechunked, hop headers stripped) before reaching the client.

</details>

<details>
<summary>What chains do and don't stop — honestly</summary>

Chains protect **metadata against local observers**: the
evil-twin AP sees an encrypted tunnel to hop one; a collector
on the first segment cannot see the destination or the content.
They raise the cost of traffic correlation by splitting
knowledge across hops.

Chains do **not** provide content integrity or confidentiality
by themselves — that is the TLS 1.3 + PQ-hybrid layer's job, and
it composes unchanged: TLS runs end-to-end *through* the chain.
A malicious hop can drop or delay traffic (availability), and a
global observer watching both ends can still attempt timing
correlation; chains are a strong local-defense tool, not an
anonymity network. For anonymity-shaped needs, the `tor` hop
exists — with the never-exit rule applying to this node, not to
the Tor network's own relays.

</details>
