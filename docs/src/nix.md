# Nix Flake

`flake.nix` packages the server and provides the development shell.
The Rust toolchain comes from fenix's `fromToolchainFile` against the
repo's own `rust-toolchain.toml`, so the packaged build runs the
exact nightly the gates ran under — nixpkgs' rustc is deliberately
not used.

```sh
nix build                 # packages.default -> vongola binary
nix develop               # shell with the pinned toolchain + mdbook
nix develop --command cargo --version
nix flake check
```

`shell.nix` is the standard flake-compat shim: non-flake
`nix-shell` users land in the same shell the flake defines.

The package build runs through a plain fenix `makeRustPlatform`
`buildRustPackage` with the committed `Cargo.lock`
(`cargoHash = lib.fakeHash` placeholder in the source is replaced by
the lockfile hash flow — see the flake's comments). Native
dependencies (OpenSSL) come from nixpkgs.
