# Benchmarks — vongola (vongola-mcp)

Measured 2026-11-27 on primo: 13th Gen Intel Core i7-13620H (16 threads), 62 GiB RAM, cargo 1.100.0, by `crates/vongola-mcp/benches/hot_paths.rs` (hand-rolled on `std::time`; warmup 20, measured loops as stated). Primo was under heavy parallel load during the run, so treat these as order-of-magnitude baselines, not lab numbers.

Environment note: no vongola daemon was running, but primo's transmission-daemon web UI answers on the example config's admin address (127.0.0.1:9091, HTTP 301), so `routes_list` calls measure the structured `daemon.http_status` error path rather than `daemon.unavailable`. The same fact makes the pre-existing era test `smoke_call_answers_with_the_daemon_unavailable_tool_error` fail on this machine (it assumes port 9091 is silent); that failure predates and is unrelated to this change.

## Workloads

- `cold_start_discover` — spawn `vongola-mcp --config examples/qompass.yaml`, send `server/discover`, await the correlated response; 10 spawns.
- `tools_list` — `tools/list` over one warm session; 200 iterations.
- `tool_call_routes_list` — read-only, argument-free `routes_list` call over the same warm session; 200 iterations.

## Results (2026-11-27)

| workload | iters | total | per-op | ops/s |
|---|---|---|---|---|
| cold_start_discover | 10 | 58.9 ms | 5.89 ms | 170 |
| tools_list | 200 | 39.3 ms | 196.5 µs | 5,088 |
| tool_call_routes_list | 200 | 179.9 ms | 899.5 µs | 1,112 |

## Example

`crates/vongola-mcp/examples/stdio_session.rs` — one modern-era session (discover, tools/list, `routes_list`) against the repo's own `examples/qompass.yaml`. Run: `cargo run -p vongola-mcp --example stdio_session`.

## Existing examples verification (2026-11-27)

The repo's seven pre-existing examples were kept untouched and verified with the built `vongola validate-config`:

| example | verdict |
|---|---|
| `examples/fleet-node.yaml` | valid (1 route) |
| `examples/lean.yaml` | valid (1 route) |
| `examples/qompass.yaml` | valid (2 routes) |
| `examples/example.yaml` | REJECTED by the current schema: `config.parse_failed`, unknown field `service_name` (pre-existing staleness in the example, recorded here, not silently fixed) |
| `examples/example.hcl` | typed refusal by design: `config.hcl_not_supported` — HCL is import-only in the clean-room rewrite |
| `examples/vongola.hcl` | typed refusal by design: `config.hcl_not_supported` |
| `examples/site/` | static assets referenced by `qompass.yaml`'s `static_root`; not a config |
