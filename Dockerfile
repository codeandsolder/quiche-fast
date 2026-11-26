FROM rust:1.100.0@sha256:e84068000361bf3d4a5ba2b7647f62893528b1eb9f847d7a23b493f5ce8ea254 AS build

WORKDIR /build

COPY rust-toolchain.toml ./
COPY Cargo.lock ./

COPY Cargo.toml ./
COPY apps/ ./apps/
COPY datagram-socket/ ./datagram-socket/
COPY h3i/ ./h3i/
COPY netlog/ ./netlog/
COPY octets/ ./octets/
COPY qlog/ ./qlog/
COPY qlog-dancer/ ./qlog-dancer/
COPY quiche/ ./quiche/
COPY task-killswitch ./task-killswitch/
COPY tokio-quiche ./tokio-quiche/

# clang and cmake are required by btls-sys to build BoringSSL.
RUN apt-get update && apt-get install -y clang cmake && rm -rf /var/lib/apt/lists/*

RUN cargo build --locked --release --manifest-path apps/Cargo.toml

##
## quiche-base: quiche image for apps
##
FROM debian:latest@sha256:3cda3ca472ce45507a5109c6a3907093e24d9ae67d55954c9a07a45665dafba2 AS quiche-base

RUN apt-get update && apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build \
     /build/target/release/quiche-client \
     /build/target/release/quiche-server \
     /usr/local/bin/

ENV PATH="/usr/local/bin/:${PATH}"
ENV RUST_LOG=info

##
## quiche-qns: quiche image for quic-interop-runner
## https://github.com/marten-seemann/quic-network-simulator
## https://github.com/marten-seemann/quic-interop-runner
##
FROM martenseemann/quic-network-simulator-endpoint:latest@sha256:3b2b9e6fa317da238c8140a7b6d2bf8d4d45a8464b873eecac3ff2a32520b71a AS quiche-qns

WORKDIR /quiche

RUN apt-get update && apt-get install -y wait-for-it && rm -rf /var/lib/apt/lists/*

COPY --from=build \
     /build/target/release/quiche-client \
     /build/target/release/quiche-server \
     /build/apps/run_endpoint.sh \
     ./

ENV RUST_LOG=trace

ENTRYPOINT [ "./run_endpoint.sh" ]
