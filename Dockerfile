# syntax=docker.io/docker/dockerfile:1.7-labs

FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /workspace

FROM chef AS planner

# Include manifests and local path dependencies used by peam.
COPY Cargo.toml Cargo.lock build.rs ./
COPY fiat-shamir ./fiat-shamir
COPY whir-p3 ./whir-p3

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /workspace/recipe.json ./recipe.json
COPY --from=planner /workspace/Cargo.toml ./Cargo.toml
COPY --from=planner /workspace/Cargo.lock ./Cargo.lock
COPY --from=planner /workspace/build.rs ./build.rs
COPY --from=planner /workspace/fiat-shamir ./fiat-shamir
COPY --from=planner /workspace/whir-p3 ./whir-p3

RUN cargo chef cook --release --locked --recipe-path recipe.json

COPY . .

RUN cargo build --release --locked --bin peam

FROM ubuntu:24.04 AS runtime

ARG GIT_COMMIT=unknown
ARG GIT_BRANCH=unknown
ARG BUILD_DATE=unknown
ARG IMAGE_SOURCE=https://github.com/malik672/Peam

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

COPY --from=builder /workspace/target/release/peam /usr/local/bin/peam

ENTRYPOINT ["/usr/local/bin/peam"]
CMD ["--help"]
