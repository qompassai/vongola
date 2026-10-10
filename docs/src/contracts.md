# Contracts and Bounds

- **Log channel.** The logging pipeline is a bounded channel
  (`services::logger::LOG_CHANNEL_CAPACITY = 1024` lines). Producers
  never block the request path: on a full channel the line is dropped
  and `DROPPED_LOG_LINES` (an `AtomicU64`) is incremented; on a closed
  channel the line is ignored.
- **Configuration validation** (`config/validate.rs`) rejects, among
  others: upstream addresses that fail to parse, a Let's Encrypt email
  that is empty or uses the `@example.com` placeholder (checked even
  when issuance is disabled), and malformed route patterns. `load()`
  returns `Result<Config, figment::Error>`; config errors are fatal at
  startup by design (fail fast, before any listener opens).
- **OAuth2 state.** The OAuth2 plugin's state blob carries a
  timestamp and is rejected once it is older than 120 seconds. See the
  Security chapter for the construction's limits.
- **Certificates.** SNI selection is exact-host against the
  certificate store. A route that sets
  `ssl_certificate.self_signed_on_failure = true` opts into lazy
  creation of a self-signed certificate (EC P-384, SHA-256, one-year
  validity) the first time a handshake finds no certificate; the
  certificate is then stored and reused. Routes without the flag fail
  the handshake when no certificate exists — silence, never a wrong
  certificate.
- **Plugin API.** `plugins_api::Session::get_header` is
  case-insensitive and returns the first value when a header repeats.
  `req_header` reports whether the session carries any headers; the
  richer request model from the original scaffold (a static header
  source) does not exist and is not faked.
