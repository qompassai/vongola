# APPA policy profile — 2026-10-10

Matt directed (2026-10-10) that the estate's OpenAPPA
adaptation — the pilot at ~/openappa-pilot (appa 0.30.0 @
5060566a, one proven profile, profiles/image/) — be propagated
to vongola, volta and fathom as per-repo APPA policy profiles.

Added for vongola, new files only:

- `policy/appa.toml` — worker policy modeled on the pilot's
  image profile: the claude-code battery included (relative
  include into the pilot tree on primo), root rules for this
  repo. Workflow allows (cargo build/test/clippy/fmt, nix
  build, scripts/smoke.sh, scripts/ech-proof.sh); hard denies
  with attention=["blocked"] (rm -rf, rm -fr, git reset,
  git clean, git push, gh, sudo); secret labels on the state
  dir (vongola-state/, ECH/TLS/onion keys) and the operator
  config vongola.yaml — after a secret read, network sinks
  (curl/wget/nc/ncat/netcat/scp/sftp) and writes outside the
  repo are refused, the repo itself stays the one cleared
  write destination; the mutating MCP tools config_reload and
  rotate_self_signed are ask-tier (attention=["hitl"], both
  name spellings declared).
- `policy/replay/` — 7 .appa trace files, 37 expectations
  (17 allow / 20 deny): workflows, writes, hard denies, and
  the lumen design's adversarial classes — exfiltration,
  label confusion, sink spoofing — plus the MCP ask tier
  (replays as deny: no authority offline).
- `policy/README.md` — what this is, the pinned appa it
  validates against, the exact validation commands, the
  proposal → replay → Matt-approval rule for policy changes,
  and the known expressiveness limits (Bash substring
  selectors, enumerative write coverage).

Gates with the pinned pilot binary: `appa describe --check`
exit 0 (385 declared tools); `appa replay` 7/7 files ok,
37/37 expectations. Policy authoring only — no code changes,
nothing in the repo loads this profile yet; wiring it into a
dispatch path is a separate decision.
