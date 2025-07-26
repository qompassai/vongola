# /qompassai/vongola/flake.nix
# Qompass AI Vongola Nix Flake
# Copyright (C) 2025 Qompass AI, All rights reserved
####################################################
{
  description = "Qompass AI Vongola Nix Flake";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            rust-overlay.overlays.default
          ];
        };
        rustToolchain = pkgs.rust-bin.stable.latest.default;
      in {
        packages = {
          vongola = pkgs.rustPlatform.buildRustPackage {
            pname = "vongola";
            version = "0.1.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = [pkgs.pkgconf];
            buildInputs = [pkgs.openssl pkgs.clang pkgs.cmake pkgs.openssl.dev];
          };
          default = self.packages.${system}.vongola;
        };
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.pkgconf
            pkgs.openssl
            pkgs.clang
            pkgs.cmake
            pkgs.git
            pkgs.curl
            pkgs.gcc
            pkgs.make
          ];
          shellHook = ''
            echo "Welcome to Vongola devshell. Run 'cargo build --release' to build."
          '';
        };
      }
    );
}
