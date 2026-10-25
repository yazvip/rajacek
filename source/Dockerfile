# syntax=docker/dockerfile:1.7

FROM rust:1.82-bookworm AS builder
WORKDIR /app

# Copy manifests first to improve dependency cache reuse when source files change.
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations
# Compile-time embedded assets: `src/api.rs` embeds the landing page and OpenAPI document,
# and `src/bank_codes.rs` embeds the bank catalog. All three directories must exist in the
# builder stage before `cargo build` runs.
COPY web ./web
COPY openapi ./openapi
COPY data ./data
RUN cargo build --release --bins

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home rajacek

WORKDIR /app
COPY --from=builder /app/target/release/rajacek-api /usr/local/bin/rajacek-api
COPY --from=builder /app/target/release/rajacek-worker /usr/local/bin/rajacek-worker
COPY web ./web
COPY migrations ./migrations

USER rajacek
EXPOSE 8080
ENV APP_ENV=production \
    BIND_ADDRESS=0.0.0.0:8080

CMD ["rajacek-api"]
