# syntax=docker/dockerfile:1
FROM rust:1.96-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY src ./src
RUN --mount=type=cache,id=ecochain-license-cargo,target=/usr/local/cargo/registry \
    --mount=type=cache,id=ecochain-license-target,target=/build/target \
    cargo build --locked --release --bins \
    && mkdir /out \
    && cp target/release/license-server target/release/licensectl target/release/license-agent target/release/license-tpm /out/

FROM debian:bookworm-slim AS runtime
RUN groupadd --gid 10001 license \
    && useradd --uid 10001 --gid license --no-create-home license \
    && mkdir /state && chown license:license /state
COPY --from=build /out/license-server /usr/local/bin/license-server
COPY --from=build /out/licensectl /usr/local/bin/licensectl
COPY --from=build /out/license-agent /usr/local/bin/license-agent
COPY --from=build /out/license-tpm /usr/local/bin/license-tpm
USER 10001:10001
WORKDIR /state
EXPOSE 50051
CMD ["license-server", "--help"]
