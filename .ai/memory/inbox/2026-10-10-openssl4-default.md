# OpenSSL 4.0 promoted to default (2026-10-10)

Matt's ruling (2026-10-10, "OK make 4.0 default"), given in
response to the fold-into-the-ECH-branch option: promote
OpenSSL 4.0 to primary and land the stack together
(spike + ECH + promotion). This supersedes the spike's
keep-as-variant verdict (SPEC section 15) and its follow-up
form ("keep openssl 4.0" = keep as variant, same day,
earlier). Upstreaming the ECH binding to rust-openssl was
NOT part of this ruling — still a separate go, not given.

What changed (branch feat/ech-binding-vongola-20261010, on
top of the ECH commits):

- `flake.nix`: the default package is the former variant
  definition — pinned OpenSSL 4.0.3 derivation,
  `OPENSSL_DIR` at it, `ech` cargo feature enabled.
  `packages.vongola-openssl4` remains, an alias resolving
  to the identical derivation. `packages.openssl4`
  unchanged.
- `Cargo-openssl4.lock` -> `Cargo.lock` (openssl 0.10.78 /
  openssl-sys 0.9.114); the variant lockfile is deleted.
  One lockfile now.
- Docs: SPEC section 15 promotion addendum; section 16
  promotion subsection with the gate record; book TLS
  chapter (ECH section = default build; trap section notes
  the flake pin); ech-proof.sh header wording.

Unchanged by design: the `ech` cargo feature stays opt-in
(plain `cargo build` compiles no shim code and exits 2 on
an ECH-enabled config); ECH stays a runtime config opt-in,
default off; primo's system OpenSSL 3.6.5 untouched.

Gates (primo, promoted tree): default `nix build` binary
links libssl.so.4/libcrypto.so.4 from the openssl-4.0.3
store path, zero 3.5.8 references; in-sandbox suite 63/63.
Cargo test 57/57 default, 63/63 `--features ech`, binding
crate 17/17. Clippy `-D warnings` clean both feature sets;
fmt clean. Smoke 38/0 (default release build, ECH
disabled); ech-proof 19/19. `nix flake check` passed.
Host-side feature builds need
`LD_LIBRARY_PATH=<openssl4>/lib` alongside `OPENSSL_DIR`
(the store lib dir is not on the loader path outside the
nix package) — environment fact, not a defect.

Ownership note: 4.0 is not an LTS line. Until nixpkgs
ships 4.x, each 4.0.x point release is a manual hash-bump
of the flake's openssl4 derivation plus a gate re-run.

This branch lands to master together with the spike + ECH
stack it sits on (fast-forward from c541dca).
