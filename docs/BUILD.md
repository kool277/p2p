# Building

`tools/qalqon-cli` resolves what to build, and it calls each ecosystem's own tool ([ADR-0003](adr/0003-build-orchestrator.md)). It needs only Rust to start, because `cargo qalqon` is an alias in `.cargo/config.toml`.

| Command | What it does |
| --- | --- |
| `cargo qalqon list` | Every client, server and primary pair |
| `cargo qalqon doctor --client <x> --server <y>` | Checks only the toolchains this pair needs, and says how to get the rest |
| `cargo qalqon build --client <x> --server <y>` | Builds only the folders on this pair's path |
| `cargo qalqon dev --client <x> --server <y>` | Runs the host and the relay on loopback, with a fresh development PKI |
| `cargo qalqon test --pair <x>:<y>` | One interop cell, with `cli-rust` at the other end |
| `cargo qalqon test --triple <a>,<b>:<y>` | Two chosen clients through one server |
| `cargo qalqon test --conformance <binding>` | The shared vectors, in that binding's own runtime |
| `cargo qalqon test --primary` | Every primary pair and triple |
| `cargo qalqon package --client <x> --server <y>` | Development artifacts into `dist/<x>+<y>/`. They are unsigned and marked not for release |
| `cargo qalqon new ...` | See `docs/EXTENDING.md` |
| `cargo qalqon manifests [--check]` | Writes `combinations.yaml`, or fails if it is stale |
| `cargo qalqon lint` | Rule 0.4 |
| `cargo run -p idlgen [-- --check]` | Writes every generated surface from the IDL, or fails if one is stale |

## Manifests

Every folder has a `qalqon.yaml`. `combinations.yaml` is generated from them, and CI fails on a hand edit.

```yaml
name: cli-c
kind: client               # core | binding | package | client | server | infra | tool
language: c
delivery: ffi              # rust | ffi | wasm | sidecar
targets: [linux-x64]
depends_on: [bindings/c]
toolchain: { gcc: ">=9" }
build:                     # run from the repository root
  - mkdir -p target/cli-c
  - gcc ... -o target/cli-c/qalqon-cli-c target/debug/libqalqon.a -lpthread -ldl -lm
conformance: <command>     # bindings only
primary_pairs: []          # servers only
owners: [core-team]
```

`build` and `conformance` are additions to the fields in ADR-0003. They hold each folder's commands, so the CLI needs no knowledge of any ecosystem.

## The cache

A folder is rebuilt only when its sources, anything it depends on, `Cargo.lock` or the Rust toolchain change. Stamps live in `.qalqon/cache/<name>-<key>`. So far this is a local cache of what has been built. Sharing built artifacts across targets, and through the Actions cache, is still to do.

## Release builds are refused

The only crypto provider so far is the test-only one, which has a `compile_error!` when debug assertions are off. `cargo build --release` therefore fails for anything that includes it, and CI checks that it still does. The dev profile optimises dependencies, so the speed is usable.
