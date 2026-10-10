# Architecture

The workspace has three crates:

- `crates/vongola` — the server binary and all services.
- `crates/plugins_api` — the WIT (`wit/plugin.wit`) component
  bindings: a `Session` (method, URI, status, ordered headers), a
  `Context` string, and a `Plugin` trait with an `on_request_filter`
  hook. This is a scaffold for out-of-process plugins; the in-process
  plugins under `crates/vongola/src/plugins/` are separate.
- `crates/plugin_request_id` — a small library that mints request IDs
  (`req-<n>` from a process-wide atomic counter) and derives
  context-qualified IDs from them.

Inside the server binary:

- `proxy_server/` — `http_proxy` (redirect to HTTPS), `https_proxy`
  (the `ProxyHttp` implementation: route lookup, plugin execution,
  cache lookup/insertion, upstream selection), `cert_store` (the
  Pingora `TlsAccept` callback that picks a certificate by SNI).
- `stores/` — papaya hash-map stores for routes, certificates, ACME
  challenges, and caches, all behind free functions
  (`get_route_by_key`, `insert_certificate`, ...).
- `services/` — background services: `discovery` (static routes from
  config, plus Docker/Swarm watchers), `letsencrypt` (ACME HTTP-01
  issuance and the self-signed fallback), `logger` (a bounded async
  log pipeline), and health checking.

Request flow (HTTPS): TLS handshake with SNI certificate selection →
route lookup by host → path matcher → request plugins → cache lookup
→ upstream via the route's load balancer → response plugins → cache
insertion if the route enables it.
