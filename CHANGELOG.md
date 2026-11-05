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

### Changed

- `docs/PROTOCOL.md`, section 9.2: the encrypt-then-MAC tag now covers the nonce. A known-answer test showed that a changed nonce passed the tag and decrypted to garbage.
- `docs/PROTOCOL.md`: added the test-only suite range, the encoded forms of chains and CRLs, relay grants, and how `ordered` works on a lossy transport.
