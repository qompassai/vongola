# Security Model

## Threat assumptions

Vongola terminates TLS for its configured hosts and proxies to
upstreams that operators control. It is exposed to arbitrary client
input on the request path and to whatever its upstreams return.

## What is enforced

- TLS is the only proxied scheme; the HTTP listener exists solely to
  redirect (308) to HTTPS.
- Certificates are selected strictly by SNI host from the store. The
  self-signed fallback is **opt-in per route**
  (`ssl_certificate.self_signed_on_failure`) and clearly logged when
  it fires; it exists for development and for Let's Encrypt failure
  recovery, not as a silent default.
- The OAuth2 callback no longer logs the authorization code or the
  decrypted state payload (removed in the 2026-10 pass), and malformed
  decrypted state is rejected with a 401 instead of panicking the
  handler (the previous `unwrap()`s on attacker-influenced input were
  a denial-of-service).
- The log pipeline cannot be used to stall the proxy: it is bounded
  and drops with a counter (see Contracts).

## Named gaps

- **OAuth2 state is obfuscation, not authenticated encryption.** The
  state blob is produced with `short_crypt::ShortCrypt` keyed by a
  per-boot random UUID. There is no MAC, so a party that learns the
  key can forge state, and all states die on restart. The 120-second
  expiry check bounds replay. Replacing this with an AEAD construction
  keyed by configured secret material is designed-for but not yet
  implemented — it needs a config/schema decision, and it is recorded
  here rather than papered over.
- **Metrics.** The Prometheus service on :9090 serves an empty
  registry: no request metrics are recorded anywhere in the codebase
  yet.
- **Shutdown.** In smoke testing the process logs service shutdown on
  SIGTERM but the process itself did not exit within 5 s and required
  SIGKILL. Background services appear not to observe the shutdown
  watch promptly; operators should supervise with a kill timeout
  until this is fixed.
