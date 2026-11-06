# Extending Qalqon

Adding a language, framework or operating system is a scaffolding command plus a conformance run, and never a change to `core/`.

## Which delivery path

1. Is it written in Rust? Use the crate.
2. Can it call a C library? Use the C ABI.
3. Can it run WebAssembly? Use the WASM module.
4. Otherwise, use the sidecar. If it can open a socket, it can use Qalqon.

## A new language

```sh
cargo qalqon new binding --lang python --path sidecar
cargo qalqon test --conformance python-sidecar
```

This creates `bindings/python-sidecar/` with a manifest, a client, a README and a conformance harness. Python has a working template for `ffi` and `sidecar`. Any other language gets a generic one, whose conformance fails until you write it, and that is deliberate: a binding counts only when the shared vectors pass in its own runtime.

To finish a binding:

1. Write the idiomatic wrapper. Names and error codes come from `docs/SDK-API.md`, and only the casing changes.
2. Run every file in `tests/conformance/testonly/` through `conformanceRun`.
3. Do not add cryptography. `cargo qalqon lint` fails anything that looks like a handshake step, a key derivation or raw key access.

## A new client framework

```sh
cargo qalqon new client --lang python --framework pyside6
```

Write the adapter and the demo screens from `docs/CLIENT-ADAPTER.md`. Implement its CLI contract, add the client to `CLIENTS` in `tests/interop/interop.py`, then run `cargo qalqon test --pair python-pyside6:rust-axum`.

## A new server framework

```sh
cargo qalqon new server --lang php --framework laravel
```

Implement the effect loop and the four stores from `docs/HOST-SPI.md`, using `core/server-core/migrations/`. Add it to `SERVERS` in `tests/interop/interop.py`, then run `cargo qalqon test --pair cli-rust:php-laravel`.

## A new operating system

```sh
cargo qalqon new target --triple riscv64gc-unknown-linux-gnu --os linux
```

This adds the target to `targets.yaml` and creates a packaging recipe. Then add a CI runner. Platform key storage lives in `core/keystore-<platform>/`.

**Not yet proven:** the build prompt's definition of done asks that a developer who has never seen the repository can do this in under a day. So far it has only been run by the people building it.
