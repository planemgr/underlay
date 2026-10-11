# Test image: the underlay daemon, the test DHT node and the tools the end-to-end test uses
FROM rust:1.97-slim-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin underlay --example dht_node \
    && cp target/release/underlay target/release/examples/dht_node /usr/local/bin/

FROM debian:trixie-20260918-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping iptables procps wireguard-tools \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/underlay /usr/local/bin/dht_node /usr/local/bin/
COPY e2e/docker/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
