# Vongola OpenAPPA policy profile

The estate's OpenAPPA adaptation, propagated to vongola
(Matt's direction, 2026-10-10). OpenAPPA is a deterministic
information-flow gate that sits under the harness's own
permissions: it tracks the sensitivity label of everything a
dispatched worker has read and decides, before each tool call,
whether that data may flow to the call's destination.

This profile is modeled on the estate pilot's one proven
profile — `~/openappa-pilot/profiles/image/appa.toml`, verdict in
`~/openappa-pilot/PILOT_REPORT.md` — and validates against the
same pinned upstream. It is policy authoring only: no vongola
code reads, loads, or depends on anything in this directory.

## What the profile does

Root rules in `appa.toml` run before the included claude-code
battery. In order:

- **Hard denies** (`attention = ["blocked"]`, no authority can
  permit): `rm -rf`, `rm -fr`, `git reset`, `git clean`,
  `git push`, `gh`, `sudo` — the destructive set the worker
  permission profiles also deny.
- **Network sinks** (`curl`, `wget`, `nc`, `ncat`, `netcat`,
  `scp`, `sftp`) require the session's data to still be
  public-labelled.
- **Secret labels**: reading the state dir (`vongola-state/`,
  which holds ECH, TLS and onion key material) or the operator
  config (`vongola.yaml`) narrows the session audience to
  `self`. PEM key files by extension are narrowed by the
  battery. After such a read, every network sink above is
  refused, and no enumerated write outside the repo is allowed.
- **Ask tier** (`attention = ["hitl"]`): vongola's mutating
  MCP tools `config_reload` and `rotate_self_signed`, declared
  under both the claude-code host spelling
  (`mcp__vongola__<tool>`) and APPA's canonical spelling
  (`mcp/vongola/<tool>`). Live, these surface as an approval
  request on every call.
- **Workflow allows**: `cargo build/clippy/fmt/test`,
  `nix build`, `nix flake check`, `scripts/smoke.sh`,
  `scripts/ech-proof.sh` — label unchanged.
- **Writes**: the repository (`*/workspace/repos/vongola/*`) is
  the one cleared destination — session data of any label may be
  written inside it. Writes and edits to `/etc`, `/home`,
  `/root`, `/tmp` and `/var/tmp` require public-labelled data,
  so secret-labelled content cannot be written back out, and a
  lookalike path (`vongola-evil/`, `vongola2/`) is not the repo.

`replay/` holds the expectations in APPA's `.appa` trace
format, roughly half validation, half adversarial: the workflow
and own-content write cases that must keep working, the
hard-deny set, and the three flow classes from the lumen APPA
design — exfiltration (read the ECH key, then try a network
send), label confusion (read the labelled config, then write
its content to an uncleared path), and sink spoofing (write to
a lookalike cleared destination). 37 expectations: 17 allow,
20 deny. Note that ask-tier calls replay as **deny**: replay
has no human authority to clear attention, which is the honest
offline reading of "ask".

## Validating

Pinned tool: **appa 0.30.0 @ 5060566a**, the pilot build at
`~/openappa-pilot/src/target/debug/appa`. The battery include in
`appa.toml` is a relative path (APPA requires relative
includes) that resolves through primo's layout —
`policy/` → repo → `repos` → `workspace` → home — to
`~/openappa-pilot/src/marketplace/batteries/claude-code/appa.toml`.
If the pilot tree moves, the include moves with it.

From the repo root:

```sh
APPA=~/openappa-pilot/src/target/debug/appa
"$APPA" --version    # appa 0.30.0
"$APPA" describe --config policy/appa.toml --check
"$APPA" replay   --config policy/appa.toml policy/replay/
```

Both gates must exit 0; replay must report every file ok.

## Changing this policy

Policy changes are **proposal → replay → Matt's approval**.
No worker widens its own policy. A change lands only with the
replay expectations that prove it, and both gates green.

## Known expressiveness limits

Named honestly, per the pilot's findings:

- **Bash selectors are substrings.** They cannot see inside a
  command: a one-shot `curl -d @vongola-state/ech/key.pem …`
  carries the file read inside the network call itself, so the
  per-call label never narrows first. The battery's model
  annotator is the runtime layer meant to classify such calls;
  the deterministic layer provably covers the multi-call flow
  (a `Read`/`cat` of secret material, then any send) and the
  enumerated command spellings. A respelling the selectors miss
  (command substitution, a heredoc, an alias) is the same gap
  class the pilot documented.
- **Write coverage is enumerative.** Selectors cannot express
  "any path outside the repo": the uncleared rules enumerate
  `/etc`, `/home`, `/root`, `/tmp` and `/var/tmp`. A write to an
  unenumerated absolute path (say `/srv/…`) falls through to the
  battery's bare `Write` rule with no audience requirement.
- **Coarse sink substrings.** `*nc *` also matches `rsync `
  (intended — it is a network sink) and a bare `sync ` (an
  accepted overreach: it only bites after a secret read).
- Paths are matched **as written**, not resolved: `~`, `..` and
  symlinks spell around path selectors, as the battery's own
  comments note.
