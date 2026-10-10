FROM rustlang/rust:nightly@sha256:804de53425cd96dad8b6447ee5e8cfae1e0fbd11bd09834030064856609d5027 as fuzz

WORKDIR /build

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
FROM debian:latest@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5 as quiche-libfuzzer

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
