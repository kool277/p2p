# Crypto inventory

**Status: blocked. The library has not been supplied, so nothing here describes a real implementation.**

Build-prompt rule 0.1 starts Phase 0 by reading the library. `LIBRARY_NAME`, its location and the rest of the fill-in block in `CLAUDE.md` are still blank. This document therefore records what the design needs from the library and what each answer decides. Every entry in the Library column stays `unknown` until the library has been read, and a blank never means a capability can be assumed.

## What the design needs

Each row is one operation of the `CryptoProvider` trait (build prompt §2).

| Provider operation | Used for | Required construction | Library | If the library lacks it |
| --- | --- | --- | --- | --- |
| `hash` | Transcript hash, audit chain, fingerprints, binary manifest | O'z DSt 1106 | unknown | Blocker, no substitute |
| `mac` | Handshake MACs, encrypt-then-MAC tags | HMAC-1106 (RFC 2104) | unknown | Build from `hash`, which needs the hash's internal block length |
| `hkdf_extract`, `hkdf_expand` | Key schedule | HKDF-1106 (RFC 5869) | unknown | Build from `mac` |
| `aead_seal`, `aead_open` | Records and encrypted handshake fields | The library's AEAD mode, otherwise CTR or the standard's gamma mode plus HMAC-1106 in encrypt-then-MAC | unknown | Blocker if it has neither CTR nor gamma. ECB is forbidden |
| `sign`, `verify` | Handshake authentication, certificates, CRLs, audit checkpoints | O'z DSt 1092 | unknown | Blocker, no substitute |
| `kex_keygen`, `kex_agree` | Forward secrecy | See [ADR-0001](adr/0001-key-agreement.md) | unknown | `crypto-ext`, if the library's rules allow it |
| `random` | Ephemeral keys, handshake randoms, signature nonces | The library's CSPRNG | unknown | Stop and ask. A weak source can leak signing keys |
| `key_wrap`, `key_unwrap` | Protecting keys at rest | The library's key wrap, otherwise `aead_seal` under a key-encryption key | unknown | Use `aead_seal` |

## Facts to read from the library

The protocol uses these as symbolic constants until they are known.

| Fact | Used as | Constraint from the design |
| --- | --- | --- |
| Cipher block length and key length | `BlockLen`, `KeyLen` | `BlockLen` must be at least 16 bytes. Below that, the 2^32 record and 1 GiB rekey limits would need re-deriving, so such a parameter set is rejected |
| Hash output and internal block length | `HashLen`, `HashBlockLen` | `HashLen` must be at least 32 bytes |
| Signature parameter sets and sizes | `SigLen` | Decides the handshake size and whether a single datagram can carry it |
| Whether `sign` hashes its input | Signature input | The protocol signs a context string plus a transcript hash, so this decides how that input is passed |
| How signature nonces are generated | `random` requirements | Decides whether a browser or embedded RNG is safe for signing |
| One-shot or streaming API | Transcript and audit hashing | One-shot is workable because transcripts are bounded, but the binary manifest needs a plan |
| Buffer ownership, thread safety, error reporting | `provider-<lib>` wrapper | Decides the locking and error mapping inside the provider |
| Constant-time status | Timing tests in Phase 1 | Unknown status becomes an open risk in `docs/COMPLIANCE.md` |

## What each answer decides

| Question | Why it matters | Outcome |
| --- | --- | --- |
| What language is the library written in? | The core links it through FFI and must also build for `wasm32` and without an OS | C or C++: FFI, and `wasm32` needs a C-to-WASM build. Rust: a direct dependency. Java, C#, Go or Python: it cannot link into the core for every target, so stop and ask |
| Can it compile to `wasm32`? | Browsers run the core as WebAssembly | If not, web clients cannot do payload crypto through the library, so stop and ask |
| Is the certified boundary frozen? | Each target in `targets.yaml` is a new compilation | Ask the authorised body whether a certificate covers rebuilds for other targets. It may limit the supported targets |
| Does it have key agreement, and may we add one outside it? | Forward secrecy is a MUST | Decided in ADR-0001 |
| Does it support X.509? | The certificate format is a stop-and-ask choice | See `docs/PROTOCOL.md`, section 11 |
| Are official control examples available? | The Phase 1 gate requires known-answer tests from them | Without them, the Phase 1 gate cannot be met as written |
| May the library or its bindings be published? | This repository is public | If not, the library must stay outside the repository, and `provider-<lib>` may need a private home too |

## What stands in for the library today

`core/provider-testonly` implements every operation above, so engine work could proceed. **None of this is the library, and none of it counts towards O'z DSt.**

| Provider operation | Test-only construction |
| --- | --- |
| `hash` | SHA-256 |
| `mac`, `hkdf_*` | The generic HMAC and HKDF in `core/crypto-provider`, which a library with only a hash can also use |
| `aead_*` | AES-256-CTR with HMAC-SHA-256, in encrypt-then-MAC. This exercises the section 9.2 path that a library without an AEAD would take |
| `sign`, `verify` | Ed25519 |
| `kex_*` | X25519 and ML-KEM-768 from `core/crypto-ext` |
| `random` | The operating system, through `getrandom` |
| `key_wrap`, `key_unwrap` | `aead_seal` under a key-encryption key |

Replacing it means writing `core/provider-<lib>`, assigning real suite IDs in `docs/PROTOCOL.md`, section 4, and regenerating `tests/conformance`.

## Needs outside the library

These are not payload cryptography, but they are still cryptographic code outside the library. They need the same approval as the fill-in block's `RULES` line.

| Primitive | Why | Proposed home |
| --- | --- | --- |
| X25519, optional ML-KEM-768 | Hybrid key agreement (ADR-0001) | `core/crypto-ext`, feature-gated |
| Argon2id | Password verification (build prompt §1.6) | `core/crypto-ext`, feature-gated, used only by `server-core` |
