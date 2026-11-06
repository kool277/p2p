# qalqond, to run beside a server that cannot load a library. Share the socket through a
# volume mounted only into the two containers, both running as the same UID. Dev profile,
# for the same reason as servers/rust-axum/Dockerfile.
FROM rust:1.99-slim AS build
WORKDIR /src
COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev
RUN cargo build -q -p qalqond

FROM debian:12-slim
RUN useradd --system --uid 10001 qalqon && mkdir -p /run/qalqon && chown qalqon /run/qalqon && chmod 700 /run/qalqon
COPY --from=build /src/target/debug/qalqond /usr/local/bin/qalqond
USER qalqon
ENTRYPOINT ["qalqond", "serve", "--socket", "/run/qalqon/qalqond.sock"]
