# #################################################################
# /qompassai/vongola/flake.nix
# Qompass AI Nix Flake
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
# #################################################################

{
  description = "Vongola — clean-room reverse proxy and web server on Pingora 0.9";

  inputs = {
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { fenix, nixpkgs, self }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          toolchain = fenix.packages.${system}.fromToolchainFile {
            file = ./rust-toolchain.toml;
            sha256 = "sha256-3ok3kaNc8lhDSnZ9bZAJwmHgUrdB9CC5m+ZJBwFPWnA=";
          };
        in
        {
          default = pkgs.mkShell {
            packages = [
              toolchain
              pkgs.cargo-audit
              pkgs.clang
              pkgs.mdbook
              pkgs.openssl
              pkgs.pkg-config
            ];
            env.OPENSSL_NO_VENDOR = "1";
          };
        });

      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          toolchain = fenix.packages.${system}.fromToolchainFile {
            file = ./rust-toolchain.toml;
            sha256 = "sha256-3ok3kaNc8lhDSnZ9bZAJwmHgUrdB9CC5m+ZJBwFPWnA=";
          };
          rustPlatform = pkgs.makeRustPlatform {
            cargo = toolchain;
            rustc = toolchain;
          };
        in
        {
          default = rustPlatform.buildRustPackage {
            pname = "vongola";
            version = "0.2.0";
            src = ./.;
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = [
              pkgs.autoPatchelfHook
              pkgs.clang
              pkgs.cmake
              pkgs.pkg-config
            ];
            buildInputs = [ pkgs.openssl pkgs.stdenv.cc.cc.lib ];
            env = {
              LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ pkgs.openssl ];
              OPENSSL_NO_VENDOR = "1";
            };
            # The test suite runs inside the sandbox build
            # (doCheck defaults to true for buildRustPackage).
            meta = {
              description = "Clean-room reverse proxy and web server on Pingora 0.9";
              license = pkgs.lib.licenses.asl20;
              mainProgram = "vongola";
            };
          };
        });
    };
}
