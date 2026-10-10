# OpenSSL 4.0 spike (2026-10-10)

Branch `spike/openssl4-vongola-20261010`. Full findings: SPEC.md
section 15. Summary: `packages.vongola-openssl4` builds the tree
against OpenSSL 4.0.3 (pinned tarball, official SHA256) with a
two-package unlock (openssl 0.10.78, openssl-sys 0.9.114);
tests 51/51 and smoke 38/0 match the 3.5.8 baseline exactly;
default package untouched and re-verified green. ECH (the reason
for 4.0) is blocked at the Rust bindings layer: the C library
exports the full OSSL_ECHSTORE API, but neither rust-openssl
nor pingora-openssl binds any of it. Smallest next step is an
upstream-style binding patch (~10 FFI functions). Recommendation
recorded in SPEC: keep as variant, not default (4.0 is not LTS).
