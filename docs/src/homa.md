# Homa feasibility verdict

**Verdict: Homa does not fit vongola today — not as the public
transport (impossible), and not yet as the internal fleet plane
(no usable implementation surface). It remains a documented
watch item with explicit revisit triggers. Nothing was built;
a documented negative is the deliverable Matt asked for.**

Homa (Ousterhout, "It's Time to Replace TCP in the Datacenter",
arXiv:2210.00714v2) is a message-oriented, receiver-driven
transport implemented as a Linux kernel module, designed for
datacenter RPC tail latency.

<details>
<summary>Why not public traffic</summary>

Browsers will never speak Homa; it is a kernel-module transport
for controlled datacenters and does not traverse NAT or the
public internet. Vongola's public surface is HTTPS from arbitrary
clients, so Homa cannot be the website transport under any
architecture. The only candidate surface ever considered was
fleet-internal traffic on a controlled LAN: peer sync,
dashboard/metrics fan-in, and vongola-to-vongola chain hops.

</details>

<details>
<summary>Evidence gathered on primo (2026-10-10)</summary>

- Kernel `7.2.9-zen1-1-zen`: no `homa` module loaded, and no
  homa entry in the kernel module tree. The upstream module is
  out-of-tree; loading it on a zen kernel means building against
  local headers and accepting an unsigned-module posture.
- A filesystem sweep for Homa artifacts found nothing (only
  unrelated icon files).
- crates.io: the `homa` crate is `0.0.1-canary.0`, described as
  "coming soon" — a placeholder, not a client library. There is
  no maintained Rust binding; a sidecar would bind the C
  userspace API directly and own that FFI surface forever.

</details>

<details>
<summary>Composition problems (even if the module existed)</summary>

- **Attachment point.** Pingora is TCP/TLS-shaped end to end.
  Homa cannot enter Pingora; the only honest shape is a separate
  internal-RPC sidecar plane beside the proxy — a second
  transport to secure, monitor, and operate, for LAN RPC that
  today rides the same authenticated admin/peer channels.
- **Encryption.** Homa has none. The PQ story would need a
  Noise/WireGuard-style overlay or application-level crypto on
  top, re-creating what TLS already gives the TCP path — on a
  transport whose benefit is latency, paid for in exactly the
  budget Homa is meant to save.
- **Fit to hardware.** The fleet is small NVIDIA dev kits and
  thin clients on mixed LANs, not a controlled datacenter
  fabric; Homa's assumptions (kernel control, homogeneous
  low-latency switching) do not hold there.

</details>

<details>
<summary>Revisit triggers</summary>

Reopen this verdict when any of these become true: the Homa
module ships in mainline or in the zen kernel primo runs; a
maintained Rust crate wraps the userspace API; or the fleet
grows a controlled-LAN segment where RPC tail latency is a
measured problem (not a hypothetical one). Until then: TCP/TLS
with the PQ hybrid layer is the fleet transport, and Homa stays
a paper we have read, not a dependency we carry.

</details>
