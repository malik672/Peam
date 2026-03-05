# syntax=docker.io/docker/dockerfile:1.7-labs

FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /workspace/lean_eth

FROM chef AS planner
WORKDIR /workspace

# Include manifests and patched path dependencies used by peam.
COPY lean_eth/Cargo.toml lean_eth/Cargo.lock lean_eth/build.rs ./lean_eth/
COPY lean_eth/fiat-shamir ./lean_eth/fiat-shamir
COPY lean_eth/whir-p3 ./lean_eth/whir-p3
COPY ream/vendor ./ream/vendor

RUN cd lean_eth && cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
WORKDIR /workspace

COPY --from=planner /workspace/lean_eth/recipe.json ./lean_eth/recipe.json
COPY --from=planner /workspace/lean_eth/Cargo.toml ./lean_eth/Cargo.toml
COPY --from=planner /workspace/lean_eth/Cargo.lock ./lean_eth/Cargo.lock
COPY --from=planner /workspace/lean_eth/build.rs ./lean_eth/build.rs
COPY --from=planner /workspace/lean_eth/fiat-shamir ./lean_eth/fiat-shamir
COPY --from=planner /workspace/lean_eth/whir-p3 ./lean_eth/whir-p3
COPY --from=planner /workspace/ream/vendor ./ream/vendor

RUN cd lean_eth && cargo chef cook --release --locked --recipe-path recipe.json

COPY lean_eth ./lean_eth
COPY ream/vendor ./ream/vendor

RUN cd lean_eth && cargo build --release --locked --bin peam

FROM ubuntu:24.04 AS runtime

ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_DATE=unknown
ARG IMAGE_SOURCE=https://github.com/leanEthereum/lean_eth

LABEL org.opencontainers.image.title="peam"
LABEL org.opencontainers.image.description="Minimal Lean Consensus client"
LABEL org.opencontainers.image.source=$IMAGE_SOURCE
LABEL org.opencontainers.image.revision=$GIT_COMMIT
LABEL org.opencontainers.image.version=$GIT_BRANCH
LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/lean_eth/target/release/peam /usr/local/bin/peam

ENTRYPOINT ["/usr/local/bin/peam"]
CMD ["--help"]
