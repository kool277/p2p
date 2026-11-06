# The reference host and the relay. This builds in the dev profile because the only crypto
# provider so far is the test-only one, which refuses to compile in a release profile.
# An image from this file must never reach production.
FROM rust:1.99-slim AS build
WORKDIR /src
COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev
RUN cargo build -q -p qalqon-axum -p qalqon-relay -p qalqon-ca

FROM debian:12-slim
RUN useradd --system --uid 10001 qalqon && mkdir -p /app /pki /data && chown qalqon /pki /data
COPY --from=build /src/target/debug/qalqon-axum /src/target/debug/qalqon-relay /src/target/debug/qalqon-ca /app/
COPY servers/rust-axum/start-host.sh servers/rust-axum/start-relay.sh /app/
USER qalqon
EXPOSE 8443 9100
