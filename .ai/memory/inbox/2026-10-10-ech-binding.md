# ECH binding patch (2026-10-10)

Branch `feat/ech-binding-vongola-20261010` (off the OpenSSL 4
spike). Full record: SPEC.md section 16. Summary: ECH (RFC
9849) is implemented for the OpenSSL 4 variant. The binding
lives in a new standalone crate `crates/vongola-ech` (23 FFI
functions transcribed from the built 4.0.3's ech.h, safe
wrapper, build-time gate requiring OpenSSL >= 4 + ech.h) —
the only crate in the tree with unsafe, every block
SAFETY-commented, styled for upstreaming to rust-openssl
(not submitted; Matt's separate call). Vongola wiring: a
fail-closed `tls.ech` config block (enabled / key_file /
public_name), generate-on-first-start with 0600 keys,
inner-SNI certificate selection, dashboard + metrics
surfaces (enabled gauge, accepted counter — deliberately no
rejected counter: server-side, rejections are folded into
the GREASE state by design and are unobservable). Proof:
scripts/ech-proof.sh 19/19 (ECH accepted, retry-configs for
stale clients, classical clients unaffected, config list
stable across restart); smoke stays 38/0 with ECH disabled;
tests 63/63 variant, 57/57 default, 17/17 binding crate;
nix builds green for both packages, flake check passed;
default binary links 3.5.8 and exits 2 on an ECH config.
Seven empirical findings are recorded in SPEC 16 (notably:
write_pem double-wraps, generated stores need a PEM reload
before they decrypt, the status callback must return 1).
Remaining operational steps are Matt's: publish the
ECHConfigList in DNS HTTPS records, rotation cadence,
fleet key distribution. Not pushed.
