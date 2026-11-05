# Compliance matrix: O'z DSt 2814:2014

**Status at Phase 0: every row is an explicit, dated gap.** No control is implemented yet, so this matrix records intent only and makes no claim of compliance.

Target class: `1Г`, the fill-in block's default, pending your confirmation.

## Limits of this matrix

- **Clause numbers are unverified.** They are copied from §1.6 of the build prompt. The standard itself is not in this repository, so neither the numbers nor the wording have been checked against it.
- **Class labels need care.** `1В` in the fill-in block is Cyrillic, and `1V` in §1.6 is its Latin spelling. `1B` in §1.6 uses a Latin B and appears to mean `1Б`, a different class. The class column below uses the §1.6 spelling and must be confirmed against the standard.
- **Library rows depend on the library.** Evidence for any row that names `provider-<lib>` also depends on the library's certification status, which is unknown.

## Cryptographic subsystem (Table 1 items 3.2 and 3.4; clauses 5.3-13.3)

| Control | Applies to | Planned location | Evidence | Status |
| --- | --- | --- | --- | --- |
| Restricted data leaving the control zone is encrypted by the library | All | `core/provider-<lib>`, `core/qalqon-core` | Known-answer tests, conformance vectors | Gap, 2026-11-05 |
| Keys are reachable only through access control: per-subject handles, RBAC, audited use | All | `core/crypto-provider`, `core/ffi`, `core/server-core` | Lint report, unit tests | Gap, 2026-11-05 |
| Local store is encrypted at rest | 2A, 1B, 1A | `core/keystore-<platform>` (ADR-0002) | Per-platform tests | Gap, 2026-11-05 |
| Distinct keys per subject or group | 1A | `core/server-core`, `core/qalqon-core` | Tests | Gap, 2026-11-05 |

## Access control (10.1 and 11.1)

| Control | Applies to | Planned location | Evidence | Status |
| --- | --- | --- | --- | --- |
| User authentication: at least 12 characters enforced (standard floor is 8 alphanumeric), Argon2id, rate limits, optional MFA | All | `core/server-core`, `core/crypto-ext` | Tests, selftest suite | Gap, 2026-11-05 |
| Device identity certificates serve as terminal identification | All | `tools/ca`, `core/server-core`, `docs/PROTOCOL.md` section 11 | Interop runs | Gap, 2026-11-05 |
| Named resources | All | `core/server-core` | Tests | Gap, 2026-11-05 |
| Access matrix through RBAC or ABAC | All | `core/server-core` | Tests | Gap, 2026-11-05 |
| Confidentiality labels with flow control | 1V and up | `core/server-core` | Tests | Gap, 2026-11-05 |

## Registration and accounting (10.2 and 11.2)

| Control | Applies to | Planned location | Evidence | Status |
| --- | --- | --- | --- | --- |
| Tamper-evident audit log of login and logout, session establishment and teardown, key events, access attempts (subject, object, operation, result) and server program starts; hash-chained with 1106, periodically signed, exportable | All | `core/qalqon-audit` | Chain verification in every interop run | Gap, 2026-11-05 |
| Privilege changes are logged | 1V and up | `core/qalqon-audit`, `core/server-core` | Tests | Gap, 2026-11-05 |
| Alarm hook for breach attempts | 1V and up | `core/server-core`, Host SPI `alarm` effect | Selftest suite | Gap, 2026-11-05 |
| Freed memory is cleared | All | `core/` (zeroization) | Miri, code review | Gap, 2026-11-05 |
| Failed attempts record the presented identifier and a hash of the presented secret, never the cleartext | All | `core/qalqon-audit`, `core/server-core` | Tests | Gap, 2026-11-05 |

**Open interpretation:** a plain hash of a presented password turns the audit log into a list that can be guessed offline, including near-misses of real passwords. This draft proposes a keyed hash (HMAC-1106 under a log-specific key held by `server-core`), which still lets auditors correlate repeated attempts. This needs your decision and a check against the standard's wording.

## Integrity (10.4 and 11.4)

| Control | Applies to | Planned location | Evidence | Status |
| --- | --- | --- | --- | --- |
| Known-answer self-tests at module load | All | `core/provider-<lib>` | Load-time tests | Gap, 2026-11-05 |
| 1106 hash of the crypto module and binaries is checked against a signed manifest at start-up | All | `tools/selftest`, `core/` | Tamper tests | Gap, 2026-11-05 |
| Signed, reproducible releases with SBOM | All | `.github/workflows`, `tools/packaging` | Reproducible build on two runners | Gap, 2026-11-05 |
| No development tools in production images | All | `infra/`, per-host images | Image scan | Gap, 2026-11-05 |
| Backup and recovery, two copies | All | `docs/OPERATIONS.md`, Host SPI stores | Restore drill | Gap, 2026-11-05 |
| Attack-imitation suite `qalqon-selftest`, in CI and on demand | All | `tools/selftest` | CI report | Gap, 2026-11-05 |
| Security-administrator role with alerting | All | `core/server-core`, Host SPI Admin | Tests | Gap, 2026-11-05 |

## Sidecar

| Control | Applies to | Planned location | Evidence | Status |
| --- | --- | --- | --- | --- |
| Local IPC is protected by peer credentials or a per-launch token, and keys never leave the daemon (ADR-0004) | All | `core/sidecar` | IPC tests | Gap, 2026-11-05 |

## Hosts

Every host inherits the `server-core` rows above and adds its own rows for persistence and configuration when it is built.
