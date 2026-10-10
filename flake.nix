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
          # SPIKE 2026-10-10 (branch spike/openssl4-vongola-20261010):
          # OpenSSL 4.0.3 from the pinned upstream tarball, used ONLY
          # by the vongola-openssl4 variant below. The default package
          # keeps nixpkgs' OpenSSL (3.5.8 in the pinned lock). The 4.0
          # line is the first with ECH (RFC 9849); it is NOT an LTS
          # line. Tarball SHA256 below is the official checksum from
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
            # OpenSSL's own test suite is out of scope for the spike;
            # the consumers' gates (cargo test, smoke) are the check.
            doCheck = false;
            meta = {
              description = "OpenSSL 4.0.3 (spike build for vongola-openssl4)";
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
        in
        {
          default = mkVongola {
            lockFile = ./Cargo.lock;
            opensslPkg = pkgs.openssl;
          };
          openssl4 = openssl4;
          # Variant: same tree, own lockfile (openssl/openssl-sys
          # bumped to the first releases with OpenSSL 4.x support),
          # linked against the OpenSSL 4.0.3 build above, with
          # the `ech` cargo feature enabled (ECH bindings live in
          # crates/vongola-ech; the default package never enables
          # the feature and never compiles that crate).
          vongola-openssl4 = mkVongola {
            buildFeatures = [ "ech" ];
            extraEnv = { OPENSSL_DIR = "${openssl4}"; };
            # buildRustPackage requires the in-tree Cargo.lock to
            # match the lockFile it vendors from; the variant swaps
            # its own lockfile in during patchPhase. The default
            # package is untouched (no postPatch, original lock).
            extraPostPatch = ''
              cp ${./Cargo-openssl4.lock} Cargo.lock
            '';
            lockFile = ./Cargo-openssl4.lock;
            opensslPkg = openssl4;
          };
        });
    };
}
