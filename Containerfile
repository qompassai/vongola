# /qompassai/vongola/Containerfile
# Qompass AI Vongola Containerfile
# Copyright (C) 2025 Qompass AI, All rights reserved
####################################################
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
