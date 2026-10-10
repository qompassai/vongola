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
          # OpenSSL 4.0.3 from the pinned upstream tarball.
          # PROMOTED TO DEFAULT 2026-10-10 by Matt's ruling,
          # superseding the spike's keep-as-variant verdict (SPEC
          # section 15): the default package below links this
          # build. The 4.0 line is the first with ECH (RFC 9849);
          # it is NOT an LTS line, so its point releases are ours
          # to track (hash-bump this derivation) until nixpkgs
          # ships 4.x itself. Tarball SHA256 below is the official
          # checksum from
          # https://www.openssl.org/source/openssl-4.0.3.tar.gz.sha256
          # (325b5c806167c13b40b1ffeadfe0248197c00eccc4cf123ec1e28d2d2fd216d9).
          openssl4 = pkgs.stdenv.mkDerivation {
            pname = "openssl";
            version = "4.0.3";
            src = pkgs.fetchurl {
              url = "https://www.openssl.org/source/openssl-4.0.3.tar.gz";
              sha256 = "sha256-MltcgGFnwTtAsf/q3+AkgZfADszEzxI+weKNLS/SFtk=";
            };
            nativeBuildInputs = [ pkgs.perl ];
            configurePhase = ''
              runHook preConfigure
              perl ./Configure shared --prefix=$out --openssldir=$out/etc/ssl
              runHook postConfigure
            '';
            buildPhase = ''
              runHook preBuild
              make -j$NIX_BUILD_CORES build_sw
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              make install_sw
              runHook postInstall
            '';
            # OpenSSL's own test suite is out of scope for this
            # build; the consumers' gates (cargo test, smoke, the
            # ECH proof) are the check.
            doCheck = false;
            meta = {
              description = "OpenSSL 4.0.3 (pinned build; vongola's default TLS library)";
              license = pkgs.lib.licenses.asl20;
            };
          };
          mkVongola = { buildFeatures ? [ ], extraEnv ? { }, extraPostPatch ? "", lockFile, opensslPkg }:
            rustPlatform.buildRustPackage {
              pname = "vongola";
              version = "0.2.0";
              src = ./.;
              buildFeatures = buildFeatures;
              cargoLock.lockFile = lockFile;
              nativeBuildInputs = [
                pkgs.autoPatchelfHook
                pkgs.clang
                pkgs.cmake
                pkgs.pkg-config
              ];
              buildInputs = [ opensslPkg pkgs.stdenv.cc.cc.lib ];
              postPatch = extraPostPatch;
              env = {
                LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [ opensslPkg ];
                OPENSSL_NO_VENDOR = "1";
              } // extraEnv;
              # The test suite runs inside the sandbox build
              # (doCheck defaults to true for buildRustPackage).
              meta = {
                description = "Clean-room reverse proxy and web server on Pingora 0.9";
                license = pkgs.lib.licenses.asl20;
                mainProgram = "vongola";
              };
            };
          # The default package: linked against the OpenSSL 4.0.3
          # build above, from the unified Cargo.lock (openssl
          # 0.10.78 / openssl-sys 0.9.114 — the first releases
          # with OpenSSL 4.x support), with the `ech` cargo
          # feature enabled (ECH bindings live in
          # crates/vongola-ech). The feature stays opt-in at the
          # cargo level: a plain `cargo build` never compiles
          # that crate, and ECH itself is a runtime config
          # opt-in, default off (SPEC section 16).
          vongolaDefault = mkVongola {
            buildFeatures = [ "ech" ];
            extraEnv = { OPENSSL_DIR = "${openssl4}"; };
            lockFile = ./Cargo.lock;
            opensslPkg = openssl4;
          };
        in
        {
          default = vongolaDefault;
          openssl4 = openssl4;
          # Alias of the default package, kept working: the name
          # predates the 2026-10-10 promotion (it was the spike
          # variant's output) and scripts/docs referenced it.
          vongola-openssl4 = vongolaDefault;
        });
    };
}
