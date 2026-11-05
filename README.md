# Qalqon

One Rust core, any client, any server. Qalqon is a planned end-to-end encrypted, P2P-first secure channel. Every client and server technology gets its own folder in this repository, and a single command builds only the pair you choose.

> **Status: Phase 0, design only. No code exists yet.** Nothing here has been implemented, tested or audited, so do not rely on it to protect anything. See [`PLAN.md`](PLAN.md) for where things stand.

## The idea

The protocol and cryptography live in one Rust core. Everything else is a thin layer over it, so a React web client with a Spring server and a C client with a Node.js server are two build profiles of the same project. Because every build embeds the same core and speaks the same protocol, any client can talk to any server.

Payload cryptography is intended to go through a library implementing the O'z DSt 1105 (cipher), 1106 (hash) and 1092 (signature) standards, with the design aimed at the cryptographic requirements of O'z DSt 2814:2014. The library has not been chosen in this repository yet.

## Planned commands

None of these work yet. The `qalqon` CLI arrives in Phase 2.

| Command | What it will do |
| --- | --- |
| `qalqon build --client web-react --server java-spring` | Compile only this pair |
| `qalqon dev --client cli-c --server node-express` | Run both with hot reload and a local relay |
| `qalqon test --pair web-react:java-spring` | Run conformance vectors and interop tests for the pair |
| `qalqon list` | Show every client, server and primary pair |

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
| [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) | The O'z DSt 2814:2014 matrix, currently all gaps |
| [`docs/adr/`](docs/adr/) | Decision records |

## License

No license has been chosen yet, so all rights are reserved by default.
