# Configuration reference

One canonical format: **YAML**. HCL input is rejected with a
structured error (`config.hcl_not_supported`): one parser and
one validation surface, no function evaluation in config, and
the old tree's dual-format ambiguity removed. Validation is
fail-closed — `deny_unknown_fields` everywhere, structured
errors as `{code, field, message}` — and `vongola
validate-config` checks a file without starting listeners.

<details>
<summary>Top level (alphabetical)</summary>

| Field | Meaning |
|---|---|
| `a2a` | `enabled` — publish the signed Agent Card. |
| `admin_token_env` | Env var holding the operator token (default `VONGOLA_OPERATOR_TOKEN`). |
| `bundle_version` | Fleet bundle version string; fingerprinted with the config. |
| `discovery` | `docker_enabled`, `docker_endpoint`, `interval_secs` for Docker/Swarm label discovery. |
| `fleet_peers` | Peer admin base URLs. |
| `lets_encrypt` | `enabled`, `email` (placeholder emails are rejected, even when disabled), `staging`. Challenge answers are served; see the accounting chapter for the issuance scope note. |
| `listeners` | `admin`, `http`, `https` — each `bind`, `enabled`, and per-listener `nat` (`enabled`, `lease_secs`, `protocols`). |
| `node_name` | This node's name (dashboard, card, logs). |
| `profile` | `fleet`, `hosting` (default), or `lean`. |
| `routes` | The route list (below). |
| `shutdown_grace_secs` | SIGTERM drain cap, wired into Pingora's `ServerConf` (default 10). |
| `state_dir` | Keys, self-signed certs, onion keys (default `./vongola-state`). |
| `tls` | `groups` (allowlist, see the TLS chapter), `min_version` (only `"1.3"`). |
| `tor` | `control_addr`, `control_password_env`, `enabled`, `exit_relay` (must be false), `exit_policy` (only `reject *:*`), `relay`, `socks_addr`, `torrc_extra` (scanned). |
| `worker_threads` | Threads per Pingora service, wired into `ServerConf` (default 4; lean example: 2). |

</details>

<details>
<summary>Routes (alphabetical)</summary>

| Field | Meaning |
|---|---|
| `additional_hosts` | Extra hostnames (e.g. `www.…`) served by this route. |
| `a2a_enabled` | Mark the route as A2A-speaking in listings/cards. |
| `auth` | `basic_users` (name → SHA-256 hex of password), `jwt` (HS256 secret env, issuer, audience), `oauth2` (GitHub/WorkOS: client id/secret envs, redirect URI). OAuth2 state is HMAC-signed with a 120-second lifetime. |
| `cache` | `enabled`, `max_age_secs`, `max_bytes` for the static in-memory cache. |
| `chain` | Ordered hops: `kind` (`http-connect`, `socks5`, `tor`, `vongola`) + `address` (optional for `tor`). |
| `host` | Primary hostname. Route identity is host + path-prefix set. |
| `max_body_bytes` | Request body bound (default 16 MiB); oversized is a 413. |
| `name` | Display name (dashboard, metrics labels). |
| `onion` | `enabled`, `persist_key`, `virt_port` — publish as an onion service (requires `tor.enabled`). |
| `path_prefixes` | Prefixes this route answers; longest match wins (`/` and `/api/*` can split one host). |
| `redirect_www_to_apex` | 308 `www.<host>` → apex. |
| `security_headers` | Standard security header set on responses (default on). |
| `self_signed_fallback` | Explicit opt-in: generate/reuse a self-signed cert when no operator cert exists. Without a cert and without this flag, the handshake fails — by design. |
| `spa_fallback` | Optional SPA index fallback file. |
| `static_root` | Directory for static hosting (mutually exclusive with `upstreams`). |
| `tls_cert_file`, `tls_key_file` | Operator PEM pair for this host. |
| `upstreams` | `address` (`host:port`), optional `sni`, `tls` — round-robin over healthy entries. |

</details>

<details>
<summary>Validation highlights</summary>

Every rule has a test: TLS version and group algebra, Tor
never-exit rejections, chain bounds/cycles/self-reference,
ACME placeholder email, basic-auth hash shape (64 hex), route
shape (upstreams XOR static root; onion requires Tor), profile
minimums (fleet needs a bundle version story and ≥1 worker),
duplicate route keys, unknown fields, and the HCL rejection.

</details>
