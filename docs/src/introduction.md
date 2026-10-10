# Introduction

Vongola is a reverse proxy built on Cloudflare's Pingora framework
(0.4 series). It terminates TLS, routes requests by host and path to
configured upstreams, and layers on caching, authentication plugins,
automatic certificate issuance, and service discovery.

What it is, concretely (from `crates/vongola/src/main.rs` and the
config schema in `crates/vongola/src/config/`):

- An HTTP service on `[::]:8080` that permanently redirects every
  request to HTTPS (308).
- A TLS-terminating HTTP proxy on `[::]:4433` with SNI-based
  certificate selection and HTTP/2.
- A Prometheus-format HTTP service on `[::]:9090` (see the caveat in
  the Testing chapter: the endpoint serves, but the application
  currently records no metrics into the registry).
- Configuration via figment: YAML or HCL files plus `VONGOLA_`
  environment variables, with clap for the command line.

Feature surface: host/path routing with round-robin load balancing
and TCP health checks, in-memory and on-disk response caching,
request plugins (JWT, OAuth2 with GitHub and WorkOS providers, basic
auth, request IDs, and a wasmtime-based JavaScript/WebAssembly plugin
path defined by the `plugins_api` WIT contract), Let's Encrypt
issuance over ACME HTTP-01, and Docker/Swarm label discovery.

Vongola is a standalone proxy. It shares no code with the bunker
Nix-cache server; the kinship is pattern only (both are Rust network
services in the same estate, and both once carried a declared-but-
unimplemented `oqs` dependency — removed here in the 2026-10 pass).
