# OpenShell in vongola

This directory follows the estate OpenShell pattern; it is not
an originated design. The pattern's source of truth is
machine-level: the OpenShell gateway configuration reference
kept with the diver configuration at
`agents/openshell/CONFIGURATION.md`, and the operator's active
gateway config at `~/.config/openshell/gateway.toml` (schema
version 2, podman driver pinned, mTLS on by default).

`gateway.toml.example` is that gateway shape carrying vongola's
values, so a vongola development sandbox runs behind the same
gateway conventions as the rest of the estate. It contains no
secrets; real gateway state stays in the operator's home
configuration, and TLS material is auto-generated under
`~/.local/state/openshell/tls/`.

History: this directory was originated independently during the
2026-10-10 clean-room rewrite, before the estate pattern was
located, and was reconciled to the pattern the same day. The
originated `openshell.json` was not an OpenShell artifact at
all — OpenShell configuration is the `gateway.toml` TOML schema,
not JSON — it was an agent-permission contract. Its substance
already lived in `opencode.json` (the instructions list, the
`rm -rf` deny, the `git push` approval); the entries only it
carried (`git reset --hard` and `git clean -fd` denies, the
`cargo publish` approval) were folded into `opencode.json`'s
permission map, and the JSON file was removed.
