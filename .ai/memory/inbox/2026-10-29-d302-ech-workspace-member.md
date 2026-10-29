# D-302: vongola-ech is a workspace member (2026-10-29)

Owner ruling D-302 (2026-10-28), prepped sandbox-side on branch
`rename-prep-d302` (commit 7e2e989, based on origin/main 43ec38f;
banked locally — primo was down, push routes via primo on resume):

- Root workspace: `crates/vongola-ech` moved from `exclude` to
  `members` (kept out of `default-members`; it needs OpenSSL >= 4.0).
  Its standalone `[workspace]` table is removed; version stays its
  own 0.1.0.
- `crates/vongola`: the `vongola-ech` dependency now carries
  `version = "0.1"` alongside the path (crates.io rejects path-only).
- SPEC §16 updated to match.
- Publish order for the crates resume: **vongola-ech 0.1.0 first,
  then vongola 0.2.0**. Dry-run evidence (sandbox, OpenSSL 4.0.3
  built from the flake's pinned tarball): ech dry-run PASSES;
  vongola dry-run fails only with "no matching package named
  `vongola-ech` found" from the crates.io index.

Observation (not a D-302 regression): `nat::tests::
validation_natpmp_acquire_against_mock_gateway` times out on
loopback UDP in the sandbox VM — verified failing identically on
pristine origin/main 43ec38f. Re-check on primo before treating
it as a tree defect.
