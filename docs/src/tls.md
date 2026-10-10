# TLS and post-quantum key exchange

TLS is where vongola's "latest post-quantum" requirement lives,
and it is also where the build tried to lie to us. This chapter
states the posture, the evidence, and the trap.

<details>
<summary>The posture (enforced, not aspirational)</summary>

- **TLS 1.3 only.** Config validation accepts `min_version:
  "1.3"` and nothing else (`tls.version_forbidden`), and the
  acceptor's minimum *and* maximum protocol versions are both
  pinned to TLS 1.3 at startup. Smoke proves a TLS 1.2 attempt
  is refused.
- **Group allowlist.** Permitted: the hybrids
  `SecP384r1MLKEM1024` and `X25519MLKEM768`, plus classical
  `X25519`, `secp256r1`, `secp384r1` as negotiation fallback.
  Pure `MLKEM*` groups are rejected (`tls.pure_mlkem_forbidden`)
  — a pure-PQ group has no classical half to fall back on if the
  new primitive breaks — and a list with no hybrid at all is
  rejected (`tls.no_hybrid_group`). The allowlist is applied to
  the acceptor via the groups list, in config order as server
  preference.
- **Certificates.** Operator PEM pairs per route; unknown SNI
  gets no certificate and the handshake fails (smoke-proven).
  The self-signed fallback is explicit per-route opt-in
  (ECDSA P-384, one year, persisted in the state dir, key 0600).

</details>

<details>
<summary>The evidence (live negotiation, primo 2026-10-10)</summary>

```
$ openssl s_client -connect 127.0.0.1:18443 -servername qompass.local -tls1_3
Negotiated TLS1.3 group: X25519MLKEM768
```

A hybrid ML-KEM group, negotiated end-to-end by the shipped
binary. The client's default group preference selected
`X25519MLKEM768`; the server's list also offers
`SecP384r1MLKEM1024` first. TLS 1.2 and unknown-SNI attempts in
the same run were both refused (`Cipher is (NONE)`).

</details>

<details>
<summary>The vendored-OpenSSL trap (read this before building)</summary>

Pingora 0.9's default build **vendors OpenSSL 3.4.0**, which
predates ML-KEM entirely (hybrids arrived in OpenSSL 3.5). A
vendored build therefore cannot negotiate any PQ group — and
nothing warns you; handshakes just fall back to classical
groups. The first smoke run caught exactly this (TLS 1.2 ECDHE
negotiated, no PQ anywhere).

The fix is a build rule, enforced in the repo:

- `.cargo/config.toml` sets `OPENSSL_NO_VENDOR = "1"`; the Nix
  flake sets the same. Vongola links the **system OpenSSL
  (≥ 3.5 required; primo ships 3.6.5)**, whose group list
  includes both hybrids.
- If the system OpenSSL is older than 3.5, startup fails at the
  groups-list call rather than silently serving classical-only
  TLS. Build hosts must provide OpenSSL ≥ 3.5 headers and
  libraries; the flake's nixpkgs pin does.

HTTP/3: Pingora 0.9's stable server surface is HTTP/1.1 + HTTP/2
(h2 is enabled); there is no HTTP/3 listener in the release, so
vongola does not claim one.

</details>
