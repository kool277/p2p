# Qalqon

One Rust core, any client, any server. Qalqon is a planned end-to-end encrypted, P2P-first secure channel. Every client and server technology gets its own folder in this repository, and a single command builds only the pair you choose.

> **Status: Phase 2, on a test-only crypto provider.** The core and four clients run and interoperate, but the O'z DSt library has not been supplied, so none of this uses the standard's cryptography. No human cryptographer has reviewed it. Do not rely on it to protect anything. See [`PLAN.md`](PLAN.md).

## The idea

The protocol and cryptography live in one Rust core. Everything else is a thin layer over it, so a React web client with a Spring server and a C client with a Node.js server are two build profiles of the same project. Because every build embeds the same core and speaks the same protocol, any client can talk to any server.

Payload cryptography is meant to go through a library implementing O'z DSt 1105 (cipher), 1106 (hash) and 1092 (signature), aimed at the requirements of O'z DSt 2814:2014. That library has not been supplied yet, so today every build uses `core/provider-testonly`, which refuses to compile in a release profile.

## What works today

Each of these has passed a real interop run through `servers/rust-axum`: enrolment, login, a preferred-direct channel, a relay-forced channel, 1,000 records with a rekey, and the host's audit chain.

| Client | Language | How it reaches the core |
| --- | --- | --- |
| `clients/cli-rust` | Rust | Native crate |
| `clients/cli-c` | C | C ABI |
| `clients/web-react` | JavaScript, in headless Chromium | WebAssembly in a Web Worker |
| `clients/php-cli` | PHP | The `qalqond` sidecar |

## Try it

You need Rust, and `cargo qalqon doctor` says what else a pair needs.

```sh
cargo qalqon list
cargo qalqon test --pair cli-rust:rust-axum
cargo qalqon test --conformance c
cargo qalqon dev --client cli-rust --server rust-axum
```

| Command | What it does |
| --- | --- |
| `cargo qalqon build --client web-react --server rust-axum` | Compiles only this pair |
| `cargo qalqon dev --client cli-c --server rust-axum` | Runs the host and a local relay |
| `cargo qalqon test --pair web-react:rust-axum` | Runs one interop cell |
| `cargo qalqon test --triple web-react,cli-c:rust-axum` | Two different clients through one server |
| `cargo qalqon new binding --lang python --path sidecar` | Scaffolds a new language |
| `cargo qalqon list` | Shows every client, server and primary pair |

## Documents

| Document | What it covers |
| --- | --- |
| [`CLAUDE.md`](CLAUDE.md) | The full design and the build prompt |
| [`PLAN.md`](PLAN.md) | Current status, decisions needed and risks |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | The wire protocol, draft v0 |
| [`docs/SDK-API.md`](docs/SDK-API.md) | The public API, rendered from [`core/idl/qalqon.api.yaml`](core/idl/qalqon.api.yaml) |
| [`docs/HOST-SPI.md`](docs/HOST-SPI.md) | The contract for a server host |
| [`docs/CLIENT-ADAPTER.md`](docs/CLIENT-ADAPTER.md) | The contract for a client framework adapter |
| [`docs/crypto-inventory.md`](docs/crypto-inventory.md) | What the design needs from the crypto library |
| [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) | The O'z DSt 2814:2014 matrix |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How the pieces fit |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md), [`docs/SECURITY.md`](docs/SECURITY.md) | What this protects against, and what it does not |
| [`docs/BUILD.md`](docs/BUILD.md), [`docs/TESTING.md`](docs/TESTING.md) | Building, and how it is checked |
| [`docs/EXTENDING.md`](docs/EXTENDING.md) | Adding a language, a framework or an OS |
| [`docs/SIDECAR.md`](docs/SIDECAR.md), [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | The sidecar, and running a host |
| [`docs/adr/`](docs/adr/) | Decision records |
| [`formal/`](formal/README.md) | The ProVerif models |

## License

No license has been chosen yet, so all rights are reserved by default.
