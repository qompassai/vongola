# #################################################################
# /qompassai/vongola/Containerfile
# Qompass AI Containerfile
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

FROM nixos/nix:2.21.1 AS builder

RUN nix-env -ifA nixpkgs.rustup nixpkgs.cargo nixpkgs.pkg-config nixpkgs.openssl nixpkgs.cmake nixpkgs.clang nixpkgs.git
RUN rustup toolchain install stable && rustup default stable

WORKDIR /app
COPY . /app

RUN cargo build --release

FROM scratch AS runtime
COPY --from=builder /app/target/release/vongola /app/vongola
WORKDIR /app
EXPOSE 8080 4443
ENTRYPOINT ["/app/vongola"]
