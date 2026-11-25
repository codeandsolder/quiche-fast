FROM rustlang/rust:nightly@sha256:e430190dec450abb194f0c3d544bb9e21857fbe3ce1b1cdbfaa5080b1c8413d2 as fuzz

WORKDIR /build

COPY rust-toolchain.toml ./
COPY Cargo.lock ./

COPY Cargo.toml Cargo.toml
COPY Makefile Makefile
COPY apps/ ./apps/
COPY fuzz/ ./fuzz/
COPY octets/ ./octets/
COPY qlog/ ./qlog/
COPY quiche/ ./quiche/

RUN apt-get update && apt-get install -y cmake && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-fuzz
RUN make build-fuzz

##
## quiche-libfuzzer: quiche image for fuzzing
##
FROM debian:latest@sha256:3cda3ca472ce45507a5109c6a3907093e24d9ae67d55954c9a07a45665dafba2 as quiche-libfuzzer

LABEL maintainer="alessandro@cloudflare.com"

WORKDIR /home/mayhem/

RUN apt-get update && apt-get install -y ca-certificates llvm && rm -rf /var/lib/apt/lists/*

COPY fuzz/cert.crt ./
COPY fuzz/cert.key ./

COPY --from=fuzz \
     /build/fuzz/target/x86_64-unknown-linux-gnu/release/packet_recv_client \
     /build/fuzz/target/x86_64-unknown-linux-gnu/release/packet_recv_server \
     /build/fuzz/target/x86_64-unknown-linux-gnu/release/packets_recv_server \
     /build/fuzz/target/x86_64-unknown-linux-gnu/release/packets_posths_server \
     /build/fuzz/target/x86_64-unknown-linux-gnu/release/qpack_decode \
     ./
