# OpenShell reconciliation — 2026-10-10

Matt ruled (2026-10-10): reconcile both clean-room rewrites'
`.openshell/` directories against the estate pattern the rewrite
agents missed — the OpenShell gateway configuration reference in
the diver configuration (`agents/openshell/CONFIGURATION.md`)
and the operator's active config (`~/.config/openshell/
gateway.toml`, schema version 2).

Delta found in vongola: `.openshell/` held a README claiming an
"originated pattern" and an `openshell.json` that was not an
OpenShell artifact — OpenShell configuration is the
`gateway.toml` TOML schema (version 2); there is no JSON config
in the pattern. The JSON was an agent-permission contract
(deny/require-approval lists) wearing OpenShell's name.

Changes:

- `.openshell/gateway.toml.example` added in the real schema:
  `[openshell] version = 2`, `[openshell.drivers.podman]` with
  the machine gateway's driver values, `[openshell.gateway]`
  with `bind_address = "127.0.0.1:17670"` and
  `compute_driver = "podman"`; mTLS stays the default
  (`disable_tls` present only as a commented warning).
- `.openshell/openshell.json` removed (drop, reason above). Its
  substance was preserved where it belongs: `opencode.json`
  already carried the instructions list, the `rm -rf` deny, and
  the `git push` approval; the entries only the JSON carried —
  `git reset --hard` deny, `git clean -fd` deny, `cargo publish`
  approval — were folded into `opencode.json`'s
  `permission.bash` map. The `shell`/`version` fields had no
  meaning anywhere and were dropped with the file.
- `.openshell/README.md` no longer claims an originated
  pattern; it names the estate pattern as the source and
  records where the JSON contract went.

Validation: the example parses as TOML and carries the schema's
required shape (version 2, podman driver pin, loopback bind);
`opencode.json` still parses as strict JSON after the fold.
Local commits only; landing is Matt's separate word.
