# Testing

Gate set (all on primo, pinned nightly):

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
mdbook build
```

## Suite shape

37 tests at the time of writing:

- **Validation (~26)** — config loading from YAML/HCL, defaults and
  environment overrides (`config` module), route-store defaults and
  path matching, logger plumbing, the certificate constructor
  (parseable certificate for a domain), the self-signed fallback's
  happy path.
- **Adversarial (~11)** — placeholder/invalid Let's Encrypt emails,
  unparseable upstreams, malformed OAuth2 state handling, the
  self-signed fallback's negative space: no route → no certificate;
  route without opt-in → no certificate and nothing stored; plugin
  session header edge cases (case folding, duplicates, empty).

Route coverage by name: the full request path is covered by the
binary smoke (Operations chapter) — redirect on :8080, SNI +
self-signed + proxy + upstream body on :4433, metrics listener on
:9090. Individual plugins (JWT, OAuth2 providers, basic auth, WASM)
are covered at module level where they have unit tests; the OAuth2
provider round-trips against GitHub/WorkOS are **not** tested (they
need live third-party credentials) and the WASM plugin host path has
no end-to-end fixture yet — both are named here rather than implied.

## History worth knowing

The 2026-10 finishing pass found the workspace unbuildable as
committed (the root workspace manifest was missing entirely), the
`oqs`/`oqs-sys` dependencies declared but referenced by zero lines of
code, an OAuth2 handler that panicked on malformed state and logged
authorization codes, and an unbounded internal log channel. All are
fixed; the self-signed certificate fallback that the config schema
advertised was wired end-to-end in the same pass.
