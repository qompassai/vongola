# Mojo assessment

**Verdict: vongola stays 100% Rust on Pingora. Mojo has no
place in the binary, the request path, or the TLS path.** Its
one honest fit is offline, batch, numerical work beside the
proxy — a gated experiment, not an architecture commitment.
Nothing Mojo was built in this program.

<details>
<summary>Why not the data path</summary>

The proxy core is async networking: tokio, HTTP/1+2, TLS,
connection pooling, load balancing. Mojo has no async HTTP or
networking ecosystem comparable to that stack — its async
surface is unfinished, and there is no production HTTP server,
TLS, or HTTP/2 implementation to build a proxy on. The TLS/PQC
path additionally belongs to audited crypto (OpenSSL) that Mojo
would only wrap at a cost. Both are "no fit", not "not yet".

</details>

<details>
<summary>Where Mojo is genuinely strong — and the estate's evidence</summary>

Mojo's center of gravity is dense numerical kernels (SIMD/GPU).
This estate has measured it: Mojo scoring kernels ran 1.3–1.9×
against PyTorch references with parity inside tolerance, called
from Rust over a C ABI. The same estate also documented the
wall: the MAX *serving* stack did not land as a production path
(CPU-only serving in the attempted configuration, served values
materially off, packaging friction). The pattern is consistent —
Mojo wins on self-contained kernels and walls where a mature
ecosystem is required.

Against the candidates for vongola: config linting is text work
Rust already does better in-process (weak fit); load testing is
I/O-bound orchestration (weak fit); **offline log analytics**
— batch aggregation over access logs — is the one real fit:
dense, numerical, offline, and tolerant of a separate
toolchain.

</details>

<details>
<summary>The one proposal (not built)</summary>

A standalone, offline Mojo log-analytics spike, gated hard:
it must match a Rust reference implementation's outputs on the
same corpus and beat the Rust baseline by ≥ 1.5× end-to-end, or
it is killed and the negative is recorded. It would ship as a
separate tool, never linked into the proxy. Until someone
schedules that spike, the correct amount of Mojo in vongola is
zero — deliberately.

</details>
