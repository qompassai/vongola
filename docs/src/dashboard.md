# Operator dashboard

The dashboard is served by vongola itself from the admin
listener (`/dashboard`), backed by `GET /api/state`. It is a
single self-contained page — no build step, no external assets —
that polls the state endpoint every 2 seconds and shows the
data's freshness timestamp, flagging itself **STALE** when the
data ages past 5 seconds. Polling was chosen over server-push
because Pingora's `ServeHttp` returns complete responses; a
tight poll with a visible freshness contract is the honest fit.

<details>
<summary>Panels</summary>

- **NAT traversal** — per listener: state, external address,
  mapped port, lease remaining, gateway, last error.
- **Tor onion services** — daemon control address and
  connectivity; each service's route, public onion address, and
  virtual port. (Onion *addresses* are public identifiers and
  are shown; onion **keys** exist only in the state dir at 0600
  and are never rendered.)
- **Proxy chains** — per route: the configured chain and live
  hop health/latency from the background prober.
- **Upstreams and certificates** — health per upstream; per
  host: days to expiry, SHA-256 fingerprint, self-signed flag.
- **Counters** — requests, cache hits/misses, chain failures,
  dropped log lines; node name, profile, and the config bundle
  version + fingerprint at the top.

</details>

<details>
<summary>Access posture</summary>

The dashboard inherits the operator auth posture exactly:
unauthenticated requests get 401 (smoke-proven); reads accept
the operator token, or loopback access when no token is
configured; mutations (reload, rotate) always require the
token, from anywhere. The admin listener binds loopback in
every shipped example; exposing it beyond that is an explicit
operator decision in config, never a default.

</details>
