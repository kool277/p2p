# ADR-0001: Key agreement

- **Status:** Proposed. Blocked on the library facts. Only the test-only suites are implemented, which use X25519 and ML-KEM-768 and have no national component.
- **Date:** 2026-11-05

## Context

The channel MUST use fresh ephemeral key agreement in every session (build prompt §1.1). O'z DSt 1092 is a signature standard, and the fill-in block treats key agreement as something the library may not have. The library has not been supplied, so three things are unknown:

- whether it has a DH or KEM primitive
- whether it exposes the group operations behind O'z DSt 1092
- whether a key-agreement primitive may be added outside it (the fill-in block's `RULES` line)

Rule 0.3 forbids silent substitution, so this ADR states what happens in each case.

## Options

| Option | Secret holds if | Code outside the library | Notes |
| --- | --- | --- | --- |
| A. Library DH or KEM | That primitive is sound | None | Only possible if the library has one |
| B. DH in the 1092 group, in `crypto-ext` | Discrete log in that group is hard | Protocol code, and possibly the group arithmetic | Hand-written arithmetic is a constant-time risk |
| C. X25519 alone, in `crypto-ext` | X25519 is sound | All of it | No national-standard component in key agreement |
| D. Hybrid of A or B with X25519, optionally ML-KEM-768 | Any one component is sound | X25519, ML-KEM, possibly B | Recommended by the build prompt |

## Decision (proposed)

Use option D, with the national component chosen by what the library offers.

| Library facts | Key agreement | Action |
| --- | --- | --- |
| Has DH or KEM | Library primitive + X25519 | Proceed once outside primitives are allowed |
| No DH or KEM, but exposes 1092 group operations | 1092-group DH in `crypto-ext` + X25519 | Proceed once outside primitives are allowed |
| No DH or KEM, and no group operations | X25519 alone, or new 1092 arithmetic in Rust | **Stop and ask.** Each choice has a real cost |
| Outside primitives are forbidden | Library primitive alone | **Stop and ask** if the library has none, because the forward-secrecy MUST cannot then be met |

ML-KEM-768 is a separate optional suite, off by default. It adds post-quantum protection against recording traffic now and decrypting it later. It also adds 1,184 bytes to the first handshake message and 1,088 bytes to the second, which pushes those messages past a typical datagram size and requires handshake fragmentation.

### Combining the secrets

Each component's shared secret is concatenated in ascending `kex_id` order and fed as the single input keying material to `HKDF-Extract` with O'z DSt 1106. This follows the concatenation approach in the IETF TLS hybrid design (`draft-ietf-tls-hybrid-design`). Component secrets have fixed lengths per suite, so the concatenation is unambiguous. All public values are in the transcript, which is hashed into every later secret.

### Validating peer values

- X25519: reject an all-zero shared secret (RFC 7748, section 6.1).
- 1092 group: check group membership and reject small-subgroup elements, as the standard or library defines.
- ML-KEM-768: apply the encapsulation key checks in FIPS 203.

### Where the code lives

`CryptoProvider` exposes `kex_keygen` and `kex_agree`. A library primitive is reached through `provider-<lib>`. Everything else is in `core/crypto-ext`, feature-gated and outside the certified boundary. Candidate crates are `x25519-dalek` and RustCrypto's `ml-kem`, chosen at Phase 1 after a `cargo-audit` and `cargo-deny` pass, and checked for `no_std` and `wasm32` builds.

### One long-term key per device

Devices hold only their identity key, and no static key-agreement key. An earlier draft needed one for an IK-style handshake, but that handshake could not meet the first MUST in §1.1. See `docs/PROTOCOL.md`, section 1. Every handshake's key agreement is therefore fully ephemeral.

## Consequences

- Traffic keys depend on code outside the certified boundary whenever `crypto-ext` contributes. Records are still protected only by the library's cipher and hash. Whether this is acceptable under the certification must be confirmed with the authorised body.
- Each extra component adds handshake size and CPU cost. Both are measured after Phase 2.
- The suite registry records the combination, so moving to a library primitive later is a new suite rather than a protocol change.

## Inputs needed

- The library's key-agreement facts and the `RULES` line in the fill-in block.
- A decision on whether ML-KEM-768 should ship in the first release.
