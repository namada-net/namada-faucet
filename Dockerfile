FROM lukemathwalker/cargo-chef:latest-rust-1.85-bookworm AS chef
RUN apt-get update && apt-get install -y protobuf-compiler build-essential clang-tools-14 

FROM chef AS planner
WORKDIR /app
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
WORKDIR /app
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y openssl curl ca-certificates
RUN update-ca-certificates

RUN curl -o /app/masp-spend.params -L https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-spend.params\?raw\=true
RUN curl -o /app/masp-output.params -L https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-output.params?raw=true
RUN curl -o /app/masp-convert.params -L https://github.com/anoma/masp-mpc/releases/download/namada-trusted-setup/masp-convert.params?raw=true

ENV NAMADA_MASP_PARAMS_DIR=/app

COPY --from=builder /app/target/release/namada-faucet /app/server

CMD ["./server"]