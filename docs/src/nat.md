# NAT traversal

A vongola node behind NAT can ask the gateway for an external
port mapping — but only when the operator says so, per listener,
in config. **No silent punching of holes:** every mapping action
is config-gated and logged, lease-bound, renewed at half-life,
and released on shutdown.

<details>
<summary>Protocols</summary>

Three protocols, tried in the order the config lists
(`protocols`, default `pcp`, `natpmp`, `upnp`):

- **PCP** (RFC 6887) — MAP opcode over UDP 5351, nonce-bound,
  epoch-checked; the standards-track successor, IPv4/IPv6 and
  CGNAT aware.
- **NAT-PMP** (RFC 6886) — external-address and mapping opcodes
  over UDP 5351; simple, IPv4-only.
- **UPnP IGD** — SSDP discovery, device-description fetch, then
  SOAP `AddPortMapping` / `GetExternalIPAddress` /
  `DeletePortMapping`. SOAP faults are surfaced verbatim as
  structured errors (a 718 conflict reads as a 718 conflict).

The gateway is the default route from `/proc/net/route` unless
overridden. Failure is a structured status, never a crash: the
dashboard shows `state`, `external_addr`, `mapped_port`,
`lease_remaining_secs`, `gateway`, and `last_error` per listener.

</details>

<details>
<summary>Live evidence (primo, 2026-10-10)</summary>

With NAT enabled on the HTTPS listener in the smoke config,
primo's gateway answered NAT-PMP:

- state: `mapped`, external address `67.5.97.235`, mapped port
  18443, metric `vongola_nat_mapped{listener="https"} 1`;
- on SIGTERM the node sent the lifetime-0 release and logged
  `nat: released natpmp mapping on port 18443`.

On a gateway without mapping support the same configuration
produces a structured error in state and the proxy keeps
serving — NAT is an enhancement, never a dependency.

</details>

<details>
<summary>Safety shape</summary>

Mappings exist only while the process runs and renews them;
leases are short by configuration (`lease_secs`), renewal is at
half-life, and shutdown releases synchronously (UDP protocols)
or via the stored control URL (UPnP). The mock-gateway unit test
proves the NAT-PMP wire exchange; codec round-trips pin PCP and
NAT-PMP byte layouts.

</details>
