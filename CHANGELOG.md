# Changelog

All notable changes to this project are recorded here, in the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format. Versions come from the `VERSION` file.

## Unreleased

### Added

- The design document and build prompt, in `CLAUDE.md`.
- Phase 0 proposals for the approval gate: the crypto inventory (blocked on the library), ADRs 0001-0004, the protocol draft, the API definition (IDL v0), the SDK API, the Host SPI and the Client Adapter Contract.
- The compliance matrix, the list of build targets and the plan.
- `core/crypto-provider`: the provider trait, key handles, the suite registry, and generic HMAC, HKDF and encrypt-then-MAC over any hash and keystream.
- `core/crypto-ext`: feature-gated X25519, ML-KEM-768 and Argon2id, outside the certified boundary.
- `core/provider-testonly`: a provider from public crates for development. It refuses to compile in a release profile and offers only test-only suites.
- `core/qalqon-core`: the sans-I/O engine: wire format, fragmentation, key schedule, handshake, certificates, CRLs, pins, safety numbers, record layer, rekeying, channels and authenticated close.
- `core/qalqon-audit`: the event schema, the hash chain, signed checkpoints and the keyed digest for failed secrets.
- `core/qalqon-transport`, `-tcp` and `-udp`: the link trait and two adapters.
- `core/keystore-file`: a key store for mounted secrets.
- `core/server-core`: enrolment, login, lockout, rendezvous, signalling relay, revocation, CRLs, policy, audit chaining, metrics and the admin model, driven by polled effects. The reference SQL migration is proposed.
- `tools/qalqon-ca` and `tools/peer-demo`, and `tests/phase1-gate.sh`, which runs two peers as separate processes over TCP and UDP, including with 10% loss.
- `formal/`: ProVerif models of the handshake, with sanity queries and negative controls.
- `tools/idlgen`, generating the API types, C ABI and header, UDL, WIT, JSON-RPC schema, TypeScript types, sidecar dispatch, sidecar clients and `docs/SDK-API.md` from the IDL.
- `core/qalqon-signal`, the client as a sans-I/O state machine, and `core/qalqon-sdk`, the native SDK over it.
- `core/ffi` and `bindings/c`, the C ABI with a C++ wrapper.
- `core/sidecar` (`qalqond`) and `bindings/sidecar-clients`.
- `bindings/wasm`, `core/keystore-webcrypto`, `packages/js/web` and `packages/js/react`.
- `servers/rust-axum`, the reference host, and `infra/relay`, the blind relay.
- `clients/cli-rust`, `clients/cli-c`, `clients/php-cli` and `clients/web-react`.
- `tools/qalqon-cli`, with `list`, `doctor`, `manifests`, `lint`, `build`, `dev`, `test`, `package` and `new`, and `templates/`.
- `tests/interop`, which runs one client x server cell, and `tests/conformance`.
- CI workflows, `infra/coturn`, `infra/compose`, `infra/sidecar-image`, `infra/devcontainer` and the remaining docs.

### Changed

- `docs/PROTOCOL.md`, section 9.2: the encrypt-then-MAC tag now covers the nonce. A known-answer test showed that a changed nonce passed the tag and decrypted to garbage.
- `docs/PROTOCOL.md`: added the test-only suite range, the encoded forms of chains and CRLs, relay grants, and how `ordered` works on a lossy transport.
- The IDL: channel IDs are per session, relays are a link kind, `pollEffect` can wait, `ServerConfig` names every key by reference, and `conformanceRun` is new.

### Fixed

Defects found by testing, before any release:

- `next_timeout` could report a past time forever on strict transports, which would spin a host's event loop.
- A failed identity check reported the unauthenticated hint from rendezvous, rather than what the handshake presented.
- A stranger connecting to a listening direct port could end the call. It now costs a fallback to the relay.
- The first version of the formal model was vacuous, because honest runs never completed. Its sanity queries caught that.
