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

<details>
<summary>Encrypted Client Hello (ECH) — OpenSSL 4 variant only</summary>

The post-quantum handshake above still leaves one thing in
cleartext: the SNI itself, visible to every on-path observer.
ECH (RFC 9849) closes that: the client encrypts the real
ClientHello (true SNI, ALPN) to a key the server publishes in
DNS, and the outer handshake shows only a cover name.

Vongola implements ECH on the **OpenSSL 4 variant build only**
(`nix build .#vongola-openssl4`). ECH is new in OpenSSL 4.0 —
the 3.5 line does not have it, and neither did the Rust
bindings: the safe binding lives in this tree as the
dedicated `crates/vongola-ech` crate (the one place `unsafe`
FFI is allowed), wired behind the `ech` cargo feature. The
default build does not compile any of it, and refuses —
exit 2, no silent fallback — if a config enables ECH.

Enable it per deployment (one ECH identity per listener):

```yaml
tls:
  ech:
    enabled: true
    key_file: /var/lib/vongola/ech/ech.pem
    public_name: cover.example.test
```

- First start generates the keypair (default RFC 9849 suite:
  X25519 / HKDF-SHA256 / AES-128-GCM) and writes it to
  `key_file` with mode 0600; later starts load it. An
  unreadable or malformed key file fails startup closed.
- The value clients need — the base64 ECHConfigList — is
  written to `<state_dir>/ech/echconfiglist.b64` on every
  start and shown in the dashboard. **Publishing it is the
  operator's step:** put it in the `ech=` parameter of each
  served host's DNS HTTPS (type 65) record. Until that
  record exists, ECH is on but undiscoverable.
- Certificate selection uses the decrypted inner name (the
  public name is a cover and normally has no certificate);
  classical clients are unaffected — ECH is negotiated, not
  required, on the server side.
- Metrics: `vongola_ech_enabled` plus
  `vongola_ech_handshakes_total{result="accepted"}`. There
  is no rejected counter on purpose: when decryption of the
  inner hello fails, OpenSSL deliberately treats the
  connection as GREASE, so a server cannot distinguish a
  rejected attempt from GREASE noise — any "rejected"
  number would be fiction. Rejection is observable where
  the protocol puts it: the client receives authenticated
  retry-configs naming the current public name.

End-to-end proof (`scripts/ech-proof.sh`, 19/19): the
pinned 4.0.3 `s_client` offering the published config gets
`ECH: success: 1` and the fixture over the ECH connection;
a stale config is answered with retry-configs; the config
list is byte-stable across restarts. Full design record:
SPEC.md section 16.

</details>
