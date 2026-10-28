# Tor onion services

> **Hard rule: vongola is never a Tor exit node.** Not by
> default, not by configuration, not by accident. Exit behavior
> is impossible to enable: config validation rejects it with a
> structured error, the generated torrc posture forces it off,
> and an adversarial test suite proves the rejection paths.

<details>
<summary>What vongola does with Tor</summary>

Vongola talks to a Tor daemon over the control protocol
(`AUTHENTICATE`, `ADD_ONION NEW:ED25519-V3`, `DEL_ONION`) and
publishes a v3 onion service per route that opts in
(`onion.enabled`). Inbound onion traffic lands on a local
listener bound for that route's target. The daemon choice is an
**external tor** (primo ships tor 0.4.9.13): the control
protocol is the stable, documented seam, and it keeps the
tor process's privilege and lifecycle separate from the proxy.
**Arti** (2.7.0 on primo) was evaluated as the embedded
alternative: attractive long-term (Rust-native, no separate
daemon), but its onion-service support and control surface are
still maturing; the external daemon is the supportable choice
today, and the Tor chapter of the spec records the evaluation.

Onion keys persist in the state dir at 0600 when
`onion.persist_key` is on (default), so addresses are stable
across restarts. Keys are never logged and never leave the
state dir. Publication is retried in the background until the
daemon accepts it (the daemon may still be starting); status —
connected, services with addresses, last error — is live on the
dashboard and via MCP `tor_status`.

Live evidence (smoke, primo 2026-10-10): a private tor instance
with a hermetic torrc published
`grrjhb53…q6qd.onion` for the fixture route; the dashboard and
metrics (`vongola_tor_connected 1`,
`vongola_tor_onion_services 1`) reflected it. End-to-end
reachability through the public Tor network depends on daemon
bootstrap and is outside the loopback smoke's claim.

</details>

<details>
<summary>How "never an exit" is enforced</summary>

Three independent layers, each tested:

1. **Validation.** `tor.exit_relay: true` fails with
   `tor.exit_forbidden`. An `exit_policy` other than exactly
   `reject *:*` fails. `torrc_extra` lines containing
   exit-enabling directives fail.
2. **Generated posture.** The torrc lines vongola emits always
   include `ExitRelay 0`, `ExitPolicy reject *:*`, `DirPort 0`,
   `ORPort 0` (unless a non-exit relay is explicitly configured,
   which still cannot exit).
3. **Default posture.** Client/onion-service only. Relaying at
   all is opt-in; exiting is not an option that exists.

The default posture line is logged at publish time so an
operator can see the guarantee in the node's own log:
`tor: enforced posture for this node: DirPort 0; ExitPolicy
reject *:*; ExitRelay 0; ORPort 0`.

</details>
