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
# #################################################################
# Build:  podman build -t vongola .
# Run:    podman run -v ./config:/config:ro -p 8080:8080 \
#           -p 4433:4433 -p 9090:9090 vongola
# The binary links the system OpenSSL (>= 3.5) for ML-KEM hybrid
# TLS groups, so both stages use a base whose OpenSSL is new
# enough; a scratch runtime cannot work (dynamic libssl).
# NOTE: not built in the 2026-10-10 rewrite program — no
# container daemon was available on the build host. The Nix
# flake is the verified deterministic build.

FROM archlinux:latest AS builder
RUN pacman -Syu --noconfirm base-devel clang openssl pkgconf rustup \
    && rustup toolchain install nightly-2026-09-25 \
    && rustup default nightly-2026-09-25
WORKDIR /app
COPY . /app
RUN cargo build --release

FROM archlinux:latest AS runtime
RUN pacman -Syu --noconfirm openssl ca-certificates \
    && useradd --system --no-create-home vongola
COPY --from=builder /app/target/release/vongola /usr/local/bin/vongola
USER vongola
WORKDIR /
EXPOSE 8080 4433 9090
ENTRYPOINT ["/usr/local/bin/vongola", "serve", "--config", "/config/vongola.yaml"]
