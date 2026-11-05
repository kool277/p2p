# ADR-0003: Build orchestrator

- **Status:** Proposed, and implemented provisionally. The owner asked to proceed without answering, so this can still change.
- **Date:** 2026-11-05

## Context

A chosen client and server must build without the toolchains of anything else, reuse a cached core, and work the same on a laptop and in CI. The build prompt's default is `just` plus native tools, driven by the `qalqon` CLI, with Bazel documented as the scale-up path. The fill-in block has not expressed a preference, so the default applies.

The prompt leaves three things open, and this ADR proposes an answer to each: the Cargo layout, where mixed-client triples are declared, and how Rust-based bindings reuse the core.

## Decision (proposed)

### 1. The orchestrator

`tools/qalqon-cli` (Rust) resolves what to build and calls each ecosystem's own tool. The `justfile` holds only short shortcuts to the CLI, so no build logic lives there.

| Option | For | Against |
| --- | --- | --- |
| **CLI over native tools (proposed)** | Developers keep the tools they know. Only the chosen pair's toolchains are needed. Small to build | Dependency and cache logic is ours to maintain |
| Bazel | Hermetic, with strong remote caching | Costly to adopt across 10+ ecosystems, and needs rules for each one |
| Nx | Good JavaScript integration | Weak fit for Rust, JVM, Go, .NET and native mobile |

Manifests stay orchestrator-neutral, so a later move to Bazel is mechanical.

### 2. The Cargo layout: one root workspace

A virtual workspace in the root `Cargo.toml` contains `core/*`, `tools/*` and every other Rust folder: `servers/rust-axum`, `clients/cli-rust`, and the Rust parts of `bindings/`. There is one `Cargo.lock` and one target directory. `default-members` is limited to `core/*` and `tools/qalqon-cli`, so a plain `cargo build` stays small. Heavy application crates such as Tauri may be excluded when they arrive, if they slow resolution.

This refines the design's description of `core/` as "the Rust workspace": `core/` stays the only home of protocol code, but the workspace root moves up one level. A single lockfile is what guarantees that all Rust folders compile identical core sources.

`.cargo/config.toml` defines `qalqon = "run -q -p qalqon-cli --"`, so `cargo qalqon` works with no install step. That also solves bootstrapping: all that's needed to get the CLI is Rust.

### 3. Manifests

Every inner folder has a `qalqon.yaml` with the full set of fields from §1.3. The example in the design document omits some of them.

```yaml
name: java-spring
kind: server                  # core | binding | package | client | server | infra | tool
language: java
framework: spring-boot
delivery: ffi                 # rust | ffi | wasm | sidecar
targets: [linux-x64, linux-arm64, containers-x64, containers-arm64]
depends_on: [core/server-core, bindings/java, packages/java/spring-boot-starter, infra/relay]
toolchain: { java: ">=17", gradle: ">=8.5" }
primary_pairs: [web-react, cli-c]
primary_triples: [[web-react, cli-c]]
owners: ["team-backend"]
```

`combinations.yaml` is generated from these files, and CI fails if it differs from the generator's output.

**Refinement while implementing:** manifests also carry `build` and `conformance`, the folder's own commands, so the CLI needs no knowledge of any ecosystem. See `docs/BUILD.md`.

### 4. Mixed-client triples

The design says triples are declared in `combinations.yaml`, but that file is generated and cannot be hand-edited, and the manifest has no field for them. It also says they run nightly in one place and on every PR in another.

The proposal adds an optional `primary_triples` field to a host's manifest. Triples listed there run on every PR, which meets the Phase 3 gate. All other triples, discovered from the manifests, run nightly. This fits both statements.

### 5. The cache

The core is built once per target into `.qalqon/cache/<key>/`, shared with CI through the Actions cache. The key is a hash of the core source tree, `Cargo.lock`, the Rust toolchain version, the target triple, the feature set and the provider library version.

**So far:** `.qalqon/cache` holds stamps keyed by a folder's sources, its dependencies, `Cargo.lock` and the toolchain, so an unchanged folder is not rebuilt. It does not yet store built artifacts or cover several targets. Cargo's own target directory does that work on one machine.

**Refinement to the design:** "all bindings share one set of binaries" holds for bindings that link the C ABI: C, Go, .NET, Dart, Java and Qt. Rust-based bridges (napi-rs, PyO3, wasm-bindgen, UniFFI) statically compile the core into their own artifact, so they cannot link a prebuilt binary. For those, the guarantee is identical source and lockfile, proved at runtime by a matching `qalqon_build_id()` and by the conformance run. The release pipeline checks that all build IDs in a release match.

### 6. CI

GitHub Actions, because the repository now lives on GitHub. Primary pairs run on every PR, the full matrix runs nightly and on release, and rows and columns are discovered from the manifests.

## Consequences

- We maintain a small resolver and cache instead of adopting a build system. `docs/BUILD.md` will document them in Phase 2.
- Moving the workspace root is a small departure from the design's wording and needs your agreement.
- The scale-up path to Bazel stays open: when CI minutes or cache misses become the main cost, generate `BUILD` files from the manifests.

## Inputs needed

The fill-in block's `BUILD ORCHESTRATOR PREFERENCE` and `CI` lines, if you want something other than the default.
