# #################################################################
# /qompassai/vongola/flake.nix
# Qompass AI Flake (Package And Development Shell)
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Qompass AI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
{
  description = "Vongola — a Pingora-based reverse proxy with TLS termination, caching, and authentication plugins";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = {
    self,
    nixpkgs,
    fenix,
    ...
  }: let
    systems = ["x86_64-linux"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      # The toolchain is the repo's own rust-toolchain.toml, supplied
      # by fenix: the packaged build runs the exact pinned nightly
      # (nightly-2026-09-25) the cargo gates ran under.
      toolchain = fenix.packages.${system}.fromToolchainFile {
        file = ./rust-toolchain.toml;
        sha256 = "sha256-3ok3kaNc8lhDSnZ9bZAJwmHgUrdB9CC5m+ZJBwFPWnA=";
      };
      rustPlatform = pkgs.makeRustPlatform {
        cargo = toolchain;
        rustc = toolchain;
      };
    in {
      default = rustPlatform.buildRustPackage {
        pname = "vongola";
        version = "1.0.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;

        nativeBuildInputs = [
          pkgs.cmake
          pkgs.perl
          pkgs.pkg-config
        ];
        buildInputs = [
          pkgs.openssl
          pkgs.zlib
        ];

        # The full test suite is the gate; it runs in the package
        # build as it does on the workstation. (The one historically
        # network-dependent test — a live DNS lookup — was made
        # hermetic at the source; see test_domain_addr.)
        doCheck = true;

        meta = {
          description = "Pingora-based reverse proxy with TLS termination, caching, and authentication plugins";
          license = nixpkgs.lib.licenses.asl20;
          mainProgram = "vongola";
        };
      };
    });

    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      toolchain = fenix.packages.${system}.fromToolchainFile {
        file = ./rust-toolchain.toml;
        sha256 = "sha256-3ok3kaNc8lhDSnZ9bZAJwmHgUrdB9CC5m+ZJBwFPWnA=";
      };
    in {
      default = pkgs.mkShell {
        packages = [
          toolchain
          pkgs.cmake
          pkgs.mdbook
          pkgs.openssl
          pkgs.perl
          pkgs.pkg-config
          pkgs.zlib
        ];
      };
    });

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);
  };
}
