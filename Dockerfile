# syntax=docker/dockerfile:1.7

# --- Rust build (musl static) ---
FROM rust:1.95-alpine AS build
RUN apk add --no-cache musl-dev pkgconfig perl make bash sqlite-static
WORKDIR /src

# Use full source tree (simple layout; cargo-chef adds complexity that is not
# worth it while crate count is small). Docker's layer cache still gives us
# incremental dep rebuilds keyed off Cargo.toml / Cargo.lock.
COPY Cargo.toml Cargo.lock ./
COPY rust-toolchain.toml ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY migrations ./migrations
COPY ui/dist ./ui/dist

ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN rustup target add x86_64-unknown-linux-musl \
 && cargo build --release --target x86_64-unknown-linux-musl -p nsp \
 && strip target/x86_64-unknown-linux-musl/release/nsp

# --- Final image ---
FROM alpine:3.20
RUN apk add --no-cache iproute2 iptables ca-certificates tini \
 && addgroup -S nsp && adduser -S -G nsp -H -D nsp \
 && mkdir -p /work/data /etc/nsp \
 && chown -R nsp:nsp /work
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/nsp /usr/local/bin/nsp

ENV NSP_DB=/work/data/proxy.db \
    NSP_WORK_DIR=/work \
    NSP_JSON_LOGS=true \
    RUST_LOG=info

EXPOSE 80 443 4433 4433/udp 51820/udp
VOLUME ["/work"]

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/nsp"]
CMD ["serve"]
