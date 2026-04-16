# syntax=docker.io/docker/dockerfile:1.7-labs

FROM rust:1 AS builder
WORKDIR /workspace

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

RUN set -eux; \
    for attempt in 1 2 3 4 5; do \
        rm -rf /var/lib/apt/lists/*; \
        if apt-get update -o Acquire::Retries=3; then \
            break; \
        fi; \
        if [ "$attempt" -eq 5 ]; then \
            exit 1; \
        fi; \
        sleep 5; \
    done; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/peam /usr/local/bin/peam

ENTRYPOINT ["/usr/local/bin/peam"]
CMD ["--help"]
