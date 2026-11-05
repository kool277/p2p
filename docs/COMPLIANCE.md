# Compliance matrix: O'z DSt 2814:2014

**This matrix claims no compliance.** Everything here runs on a test-only crypto provider, so no control that depends on O'z DSt 1105, 1106 or 1092 is met, however well the code around it works. The status column says how far each control has come. The date on every open row is 2026-11-05.

Target class: `1Г`, the fill-in block's default, pending your confirmation.

| Status | Meaning |
| --- | --- |
| **Mechanism built** | The control works and has tests, but on the test-only provider. It still needs the certified library |
| **Partial** | Part of the control exists, and the row says what is missing |
| **Gap** | Not implemented |

## Limits of this matrix

- **Clause numbers are unverified.** They are copied from §1.6 of the build prompt. The standard itself is not in this repository, so neither the numbers nor the wording have been checked against it.
- **Class labels need care.** `1В` in the fill-in block is Cyrillic, and `1V` in §1.6 is its Latin spelling. `1B` in §1.6 uses a Latin B and appears to mean `1Б`, a different class. The class column below uses the §1.6 spelling and must be confirmed against the standard.
- **Library rows depend on the library.** Evidence for any row that names `provider-<lib>` also depends on the library's certification status, which is unknown.

## Cryptographic subsystem (Table 1 items 3.2 and 3.4; clauses 5.3-13.3)

| Control | Applies to | Location | Evidence | Status |
| --- | --- | --- | --- | --- |
| Restricted data leaving the control zone is encrypted by the library | All | `core/qalqon-core`, `core/provider-<lib>` (not written) | `core/qalqon-core/tests/records.rs`, and interop runs check that no plaintext reaches the relay or the host's database | **Mechanism built.** Gap until the library arrives |
| Keys are reachable only through access control: per-subject handles, RBAC, audited use | All | `core/crypto-provider`, `core/ffi`, `core/qalqon-sdk` | Keys appear nowhere in the IDL, and `qalqon lint` checks for raw key access outside `core/` | **Partial.** Handles exist. There is no RBAC on key use, and key use is not audited per operation |
| Local store is encrypted at rest | 2A, 1B, 1A | `core/keystore-file`, `core/keystore-webcrypto` | `core/keystore-file` tests | **Partial.** Keys are wrapped. `state.json` (pins, known chains, the audit chain) is not encrypted, and the platform stores are not built |
| Distinct keys per subject or group | 1A | `core/qalqon-core` | Each device has its own identity key, and each session and direction has its own traffic keys | **Mechanism built** |

## Access control (10.1 and 11.1)

| Control | Applies to | Location | Evidence | Status |
| --- | --- | --- | --- | --- |
| User authentication: at least 12 characters enforced (standard floor is 8 alphanumeric), Argon2id, rate limits, optional MFA | All | `core/server-core`, `core/crypto-ext` | `core/server-core/tests/server.rs` | **Partial.** MFA is not implemented: a user with MFA state gets `mfaRequired`, and then `unsupported` |
| Device identity certificates serve as terminal identification | All | `tools/qalqon-ca`, `core/server-core`, `docs/PROTOCOL.md` section 11 | Interop runs, and `core/qalqon-signal/tests/e2e.rs` | **Mechanism built.** The certificate format is an open decision |
| Named resources | All | `core/server-core/src/policy.rs` | Unit tests | **Mechanism built** |
| Access matrix through RBAC or ABAC | All | `core/server-core/src/policy.rs` | Unit tests, and `core/server-core/tests/server.rs` | **Mechanism built** |
| Confidentiality labels with flow control | 1V and up | Not written | None | **Gap** |

## Registration and accounting (10.2 and 11.2)

| Control | Applies to | Location | Evidence | Status |
| --- | --- | --- | --- | --- |
| Tamper-evident audit log of login and logout, session establishment and teardown, key events, access attempts (subject, object, operation, result) and server program starts; hash-chained with 1106, periodically signed, exportable | All | `core/qalqon-audit`, `core/server-core`, `core/qalqon-signal` | Unit tests, and every interop run verifies the host's chain | **Partial.** The chain uses SHA-256 and not 1106. Checkpoints are signed on export, and not yet periodically |
| Privilege changes are logged | 1V and up | `core/server-core` | Audit rows for creating and disabling users and resetting passwords | **Mechanism built** |
| Alarm hook for breach attempts | 1V and up | `core/server-core`, the `alarm` effect | `core/server-core/tests/server.rs` | **Mechanism built** |
| Freed memory is cleared | All | `core/`, through `zeroize` | Code review only | **Partial.** Secrets in Rust are zeroized on drop. Miri has not been run. Plaintext payloads are not zeroized, and managed runtimes keep their own copies of what they receive |
| Failed attempts record the presented identifier and a hash of the presented secret, never the cleartext | All | `core/qalqon-audit`, `core/server-core` | `core/server-core/tests/server.rs` | **Mechanism built,** with the keyed interpretation below |

**Open interpretation:** a plain hash of a presented password turns the audit log into a list that can be guessed offline, including near-misses of real passwords. The code uses a keyed hash (HMAC under a log-specific key held by `server-core`), which still lets auditors correlate repeated attempts. This needs your decision and a check against the standard's wording.

## Integrity (10.4 and 11.4)

| Control | Applies to | Location | Evidence | Status |
| --- | --- | --- | --- | --- |
| Known-answer self-tests at module load | All | `core/provider-testonly`, called by `ServerCore` and `ClientCore` | The core refuses to start if they fail | **Mechanism built.** `provider-<lib>` must run the official control examples |
| 1106 hash of the crypto module and binaries is checked against a signed manifest at start-up | All | Not written | None | **Gap.** `integrityCheckFailed` exists in the API, and nothing raises it yet |
| Signed, reproducible releases with SBOM | All | `.github/workflows/release.yaml` | The workflow refuses to run until a certified provider exists | **Gap** |
| No development tools in production images | All | `servers/rust-axum/Dockerfile` | None | **Gap.** Today's images are explicitly development images |
| Backup and recovery, two copies | All | `docs/OPERATIONS.md` | The audit chain survives a restart in `core/server-core/tests/server.rs` | **Gap.** No restore drill has been run |
| Attack-imitation suite `qalqon-selftest`, in CI and on demand | All | Not written | None | **Gap** |
| Security-administrator role with alerting | All | `core/server-core`, the `alarm` effect | `core/server-core/tests/server.rs` | **Partial.** Alarms work. There is an `admin` role in user records, but administrators are authenticated only by the host's bearer token |

## Sidecar

| Control | Applies to | Location | Evidence | Status |
| --- | --- | --- | --- | --- |
| Local IPC is protected by peer credentials or a per-launch token, and keys never leave the daemon (ADR-0004) | All | `core/sidecar` | Unit tests for `hello` and the token. Interop runs over a Unix socket | **Partial.** `SO_PEERCRED` on Linux. `getpeereid` and Windows named pipes are not built |

## Hosts

Every host inherits the `server-core` rows above and adds its own.

| Host | Control | Evidence | Status |
| --- | --- | --- | --- |
| `servers/rust-axum` | Stores persist through the reference migration, and the audit table is append-only by convention | Interop runs | **Partial.** The migration is proposed, not approved. SQLite does not enforce append-only |
| `servers/rust-axum` | Configuration holds key references, and no key bytes | `core/qalqon-sdk/src/server.rs` | **Mechanism built** |
| `servers/rust-axum` | Administrators are authenticated | A bearer token, compared in constant time | **Partial.** No per-administrator identity |
| `servers/rust-axum` | Platform transport security | It serves plain WebSocket and needs TLS in front. Clients refuse `ws://` except on loopback | **Gap** |
