# Dependabot lock unfreeze (2026-10-10)

Matt commissioned a single deliberate unfreeze of the
frozen `Cargo.lock` on the strength of a completed
Dependabot triage of all 8 open alerts. The triage found
no alert reachable in this tree (the HIGH openssl
advisory's vulnerable function has zero callers in the
dependency graph); the bumps land anyway because openssl
is a direct dependency at the core of the TLS stack and
"unreachable today" erodes silently as code drifts.

What changed (`Cargo.lock` only; no manifest edits — the
existing caret requirements admitted every target):

- openssl 0.10.78 -> 0.10.81. Clears GHSA-xp3w-r5p5-63rr
  (HIGH, CVE-2026-42327), GHSA-xv59-967r-8726
  (CVE-2026-44662), GHSA-phqj-4mhp-q6mq
  (CVE-2026-45784). Stays inside the OpenSSL-4.x-capable
  line the 4.0.3 promotion set as its floor (0.10.78 was
  a floor, not a pin).
- bytes 1.10.1 -> 1.11.1. Clears GHSA-434x-w66g-qw3r
  (CVE-2026-25541).
- time 0.3.36 -> 0.3.47. Clears GHSA-r6v5-fh4h-64xc
  (CVE-2026-25727).
- ring 0.17.8 -> 0.17.14. Clears GHSA-4p46-pwfr-66x6
  (CVE-2025-4432); floor was 0.17.12.
- rand 0.8.5 -> 0.8.6. Clears GHSA-cq8v-f236-94qc.

Strictly-forced transitive adjustments (nothing else
moved): openssl-sys 0.9.114 -> 0.9.117 (inside the
4.x-capable 0.9 line); time-core 0.1.2 -> 0.1.8,
deranged 0.3.11 -> 0.5.8, num-conv 0.1.0 -> 0.2.2
(time 0.3.47's own dependency cone); cc 1.1.31 ->
1.7.0 with shlex 1.3.0 -> 2.0.1 and find-msvc-tools
0.1.14 added (build-dependency cone of openssl-sys /
ring); spin 0.9.8 removed (ring 0.17.14 dropped it).

Deliberately NOT moved: tokio stays at 1.41.0 exactly.
GHSA-rr8g-9fpq-6wmg (low) remains open by design — the
triage showed it not reachable (the graph's only
broadcast payload is a plain Sync enum), and a
1.41 -> 1.43.1 bump churns the entire async stack
against the frozen-lock discipline. It defers to a
future pingora-stack refresh.

The rand advisory (GHSA-cq8v-f236-94qc) was assessed
not-applicable on two independent grounds (the `log`
feature is not enabled; the custom logger never calls
rand), and the bump to 0.8.6 clears the alert on its
own. If a formal dismissal is ever wanted in the
GitHub UI, that click remains Matt's — no alert was
dismissed via API.

Gates (primo, unfrozen tree): cargo test 57/57
default, 63/63 `--features ech`. Clippy `-D warnings`
clean both feature sets; fmt clean. Smoke 38/0 (ECH
disabled); ech-proof 19/19. `nix build` both packages
(post-promotion both resolve to the same OpenSSL 4.0.3
derivation); the default binary ldd-links libssl.so.4 /
libcrypto.so.4 from the openssl-4.0.3 store path, no
3.x. `nix flake check` passed. IDE gate (headless
nvim, live diver config; rust-analyzer, bacon-ls,
crates-lsp): 0 errors / 0 warnings across all 25 .rs
files and 3 Cargo.toml manifests.
