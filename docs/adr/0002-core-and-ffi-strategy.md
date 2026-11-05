# ADR-0002: Core and FFI strategy

- **Status:** Proposed. Needs owner approval. Parts 2 and 6 also depend on the library facts.
- **Date:** 2026-11-05

## Context

One compiled core must serve every language without reimplementation. Rule 0.2 requires approval for the IDL format and the C ABI shape, so both are proposed here. The core design in the build prompt also leaves three questions open, which this ADR answers:

- how a sans-I/O core serves an SDK whose API includes `connect`
- how the Host SPI's stores work when FFI callbacks are restricted
- where platform key storage lives, given that raw key access is forbidden outside `core/`

## Decision (proposed)

### 1. A sans-I/O engine with one runtime layer above it

`core/qalqon-core` stays sans-I/O and builds without an OS. Native SDK builds add a small runtime that drives it with the `qalqon-transport-*` adapters on internal threads. Platforms where the application must own the sockets, such as browsers and mobile libwebrtc, use `ExternalTransport` instead. The core asks the adapter to open links and send frames, and the adapter reports what arrives. See `docs/SDK-API.md`.

### 2. A provider boundary, plus a test-only provider

`core/crypto-provider` defines the trait, and `core/provider-<lib>` holds the only FFI to the library.

This ADR also adds `core/provider-testonly`, built from audited public crates. It lets Phase 1 engine, state-machine and vector work proceed before the library arrives. It carries no compliance claim. A compile-time check refuses to build it in a release profile, and a CI check fails any release artifact that contains it. Vectors produced with it are kept apart from the official ones.

### 3. The IDL is a YAML file in `core/idl/`

`core/idl/qalqon.api.yaml` is the single source of truth. Generators turn it into the UniFFI `.udl`, Rust ABI glue for `cbindgen` to turn into `qalqon.h`, a WIT file, the JSON-RPC schema and `docs/SDK-API.md`.

| Option | For | Against |
| --- | --- | --- |
| **YAML with our own small schema (proposed)** | Can state stable numeric error codes, async behaviour and docs. Every output is generated equally | We own the format and its validator |
| WIT as the source | Existing parser and resource types | No explicit numeric codes, and async is still evolving |
| UniFFI `.udl` as the source | Existing tool | UniFFI is moving towards proc-macros, and it cannot express the JSON-RPC surface well |
| Protobuf or Smithy | Mature | Heavy tooling for about 30 methods, and a poor fit for handle lifetimes |

### 4. The C ABI shape

- Opaque handles with explicit lifetimes: `qalqon_session_t*` is created by a function and released by `qalqon_session_free`.
- Every fallible call returns `qalqon_status_t`, whose values are the IDL's error codes. Results go through out-parameters.
- Bytes from the core are returned in a `qalqon_buffer_t`, which the caller releases with `qalqon_buffer_free`. Bytes into the core are borrowed for the duration of the call.
- No callbacks. Events, frames and host effects are all polled: `qalqon_session_next_event(session, timeout_ms, &event)`. Bindings release the GIL or leave the JVM's critical state while waiting. A wake-up descriptor for event loops is a Phase 2 detail.
- Handles may be shared between threads and are synchronised inside the core.
- Each ABI function wraps its body in `catch_unwind`, so a panic becomes `QALQON_INTERNAL` and never crosses the boundary.
- `qalqon_abi_version()` and `qalqon_build_id()` let a binding detect a mismatched library at load time.
- Keys never cross the boundary as bytes, only as handles. This also covers the zeroization risk in managed runtimes.

### 5. The server core uses the same polling model

The Host SPI's stores cannot be callbacks, because rule §2 forbids callbacks that hold the GIL or the JVM, and blocking store calls would stall event-loop hosts such as Node. `server-core` instead returns effects: "send this frame", "get this user", "append this audit row". The host performs each one and reports the result with `completeEffect`. See `docs/HOST-SPI.md`. This suits async hosts and works unchanged over the sidecar.

### 6. Platform key storage lives in `core/`

No folder is assigned for DPAPI, CNG, Secret Service, Keychain, Secure Enclave, Android Keystore or WebCrypto-wrapped IndexedDB code, and the lint forbids raw key access outside `core/`. The proposal is a `KeyStore` trait in `core/crypto-provider`, with implementations in `core/keystore-<platform>/` chosen by compilation target.

This adds folders to the layout and needs one exception to the `unsafe` rule in §8, because several OS key APIs are only reachable through `unsafe` calls. Those crates would join `core/ffi` and `core/provider-<lib>` as the allowed locations, with each block justified.

### 7. Delivery paths

| Path | Mechanism | Notes |
| --- | --- | --- |
| Native Rust | Crate dependency | `servers/rust-axum`, `clients/cli-rust`, Tauri |
| C ABI through FFI | `core/ffi`, plus napi-rs, PyO3 and UniFFI where a runtime-native bridge is better | C, C++, Qt, Go, Java, .NET, Dart, Node, Python, Kotlin, Swift |
| WebAssembly | `wasm32-unknown-unknown` with wasm-bindgen, in a Worker, and a `wasm32-wasip1` build for embedders | Requires the library to compile to `wasm32` |
| Sidecar | `qalqond` ([ADR-0004](0004-sidecar-ipc.md)) | Anything that can open a socket |

## Consequences

- The SDK API contains additions the build prompt did not list, because the listed methods alone cannot run a session. They are named in `docs/SDK-API.md`.
- Polling adds a little latency compared with direct callbacks, which is measured against the Phase 2 budgets.
- Layout additions: `core/provider-testonly/` and `core/keystore-<platform>/`.

## Alternatives rejected

- **Callbacks across the ABI:** rejected by §2, and hard to make safe across GIL and JVM attachment rules.
- **An async ABI:** there is no common async model across C, Go, Java, Python and .NET. Polling is the common floor, and each binding builds its own idiom on it.
- **No test-only provider:** Phase 1 would then wait entirely on the library. If you prefer that, delete part 2.
