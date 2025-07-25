FROM archlinux:latest AS builder

RUN pacman -Syu --noconfirm \
  && pacman -S --noconfirm base-devel ca-certificates openssl pkgconf curl git cmake clang make gcc libssl \
  && pacman -Scc --noconfirm
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/$HOME/.cargo/bin:${PATH}"
WORKDIR /app
COPY . /app
RUN cargo build --release
FROM archlinux:base

RUN pacman -Syu --noconfirm && pacman -S --noconfirm ca-certificates && pacman -Scc --noconfirm

COPY --from=builder /app/target/release/vongola /app/vongola

WORKDIR /app
EXPOSE 8080 4443
ENTRYPOINT ["/app/vongola"]
