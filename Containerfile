# Builder Stage
FROM archlinux:latest AS builder

RUN pacman -Syu --noconfirm \
  && pacman -S --noconfirm base-devel ca-certificates openssl pkgconf curl git cmake clang make gcc libssl \
  && pacman -Scc --noconfirm

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app
COPY . /app

# Build the Rust application
RUN cargo build --release

# Runtime Stage
FROM archlinux:base

RUN pacman -Syu --noconfirm && pacman -S --noconfirm ca-certificates && pacman -Scc --noconfirm

COPY --from=builder /app/target/release/vongola /app/vongola

WORKDIR /app
EXPOSE 80 443
ENTRYPOINT ["/app/vongola"]

