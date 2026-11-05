# Plan

The working plan for the build described in `CLAUDE.md`. It is updated in every commit.

## Where things stand

**Phase 0 is at its gate.** The documents are drafted, no code exists, and no client and server combination builds. Phase 1 cannot start until the decisions below are made.

| Phase | Scope | Gate | State |
| --- | --- | --- | --- |
| 0 | Inventory, ADRs, protocol and API drafts | Owner approval | **Waiting for approval and the library** |
| 1 | `core/`: crypto provider, protocol engine, vectors, formal model, server core | Two Rust peers interoperate over TCP and UDP, and the lemmas are proven | Not started |
| 2 | IDL generators, C ABI, C and WASM bindings, sidecar, `rust-axum`, relay, coturn, `qalqon` CLI, templates | `cli-c`, `web-react` and a sidecar PHP CLI each talk to `rust-axum`, and `qalqon new` scaffolds a passing binding | Not started |
| 3 | Primary pairs | Every primary pair is green on every PR, and the mixed-client triple is green | Not started |
| 4 | Mobile, the full target matrix, per-OS packaging | Android and iOS work against two hosts, and every target produces its artifact | Not started |
| 5 | Remaining hosts, clients and sidecar languages | Every declared folder has a passing nightly cell | Not started |
| 6 | Release pipeline, docs site, hardening, selftest suite | A tagged release installs from the registries alone, and the full matrix is green | Not started |

Phases follow §7 of the build prompt, which is fuller than the Roadmap section of `CLAUDE.md`.

## Decisions needed at this gate

| # | Decision | What it blocks | Recommendation |
| --- | --- | --- | --- |
| 1 | Fill in the fill-in block and say where the library is | The inventory, ADR-0001, suite values, `provider-<lib>` | None: only you know this |
| 2 | Can the library and its bindings be public? | Where `provider-<lib>` lives | Keep the library outside this repository until you have confirmed the licence and what the certification body allows |
| 3 | Allow a test-only crypto provider (ADR-0002, part 2)? | Starting Phase 1 before the library arrives | Yes. It is refused in release builds |
| 4 | Approve or change ADRs 0001-0004 and the v0 drafts, including the refinements below | Phase 1 | Approve, after reconciling with the companion specification |
| 5 | Supply the companion specification and the original diagrams | The protocol freeze | Needed. Do not commit the scanned standard here unless you have the right to publish it |
| 6 | Choose a licence | Anyone reusing this code. With none, all rights are reserved by default | Your choice |
| 7 | Confirm the target class and how the class labels read (`1В`, `1V`, `1B`) | `docs/COMPLIANCE.md` | Check against the standard |
| 8 | Confirm the primary pairs | Phase 3 | `web-react` + `java-spring` and `cli-c` + `node-express`, as the Roadmap assumes |
| 9 | How to record failed login secrets in the audit log | `core/qalqon-audit` | A keyed hash, as explained in `docs/COMPLIANCE.md` |
| 10 | Move the design out of `CLAUDE.md`? | Nothing, but it adds about 16k tokens to every session | Yes, into `docs/design/` |
| 11 | Replace the IK-style handshake with one XX handshake that can omit a cached certificate? | The protocol freeze | Yes. A two-message flow cannot meet the first MUST in §1.1. See `docs/PROTOCOL.md`, section 1 |
| 12 | Must every new device of a known user be re-verified, or should existing devices be able to vouch for new ones? | `docs/PROTOCOL.md`, section 11.4 | Start with re-verifying, because it is simple and safe. It does cost contacts a step each time someone adds a device |

## Refinements to the design, for your approval

Each of these departs from, or fills a gap in, the wording of `CLAUDE.md`.

| Refinement | Where | Why |
| --- | --- | --- |
| Root Cargo workspace instead of a workspace in `core/` | ADR-0003 | All Rust folders must compile identical core sources |
| `primary_triples` manifest field | ADR-0003 | Triples had no valid home, and two sections disagreed on when they run |
| Rust-based bridges compile the core instead of linking a shared binary | ADR-0003 | They cannot link a prebuilt binary, so identical sources are proved by build IDs |
| `core/provider-testonly` | ADR-0002 | Decouples Phase 1 from the library's arrival |
| `core/keystore-<platform>` and an `unsafe` exception for it | ADR-0002 | Platform key storage had no home, and it has to stay inside `core/` |
| Host stores are polled effects, not callbacks | ADR-0002, `docs/HOST-SPI.md` | Callbacks across FFI are restricted, and blocking would stall event-loop hosts |
| A host passes a key reference, not key bytes | `docs/HOST-SPI.md` | A host holding the bytes would break the rule against touching key bytes |
| API additions, such as `enrollDevice` and `acceptChannel` | `docs/SDK-API.md` | The listed methods alone cannot run a session |
| One handshake that can omit a cached certificate, instead of IK | `docs/PROTOCOL.md`, sections 1 and 8 | A two-message flow cannot bind I's signature to the full transcript |
| Pins are per user, so a known user's new device blocks until verified | `docs/PROTOCOL.md`, section 11.4 | Otherwise a malicious server could route calls to a device it invented |
| `seq` is a 16-bit epoch plus a 48-bit counter that never restarts | `docs/PROTOCOL.md`, section 9.3 | Lossy receivers need to know which key a record uses, and a counter that never restarts exposes records deleted around a rekey |
| Self-signed pre-enrolment certificates | `docs/PROTOCOL.md`, section 11.6 | Keeps mutual authentication on every channel, including enrolment |
| `qalqond call` for shell clients | ADR-0004 | `curl` cannot speak framed JSON-RPC |
| Build `clients/cli-rust` in Phase 2 | This plan | It is the peer in every interop test, but no phase names it |

## Assumptions until you say otherwise

| Item | Assumed value | Source |
| --- | --- | --- |
| Target class | `1Г` | Fill-in block default |
| Orchestrator | `just` plus native tools | Fill-in block default |
| CI | GitHub Actions | This repository is on GitHub |
| Sidecar on servers | Allowed | §7 includes it in Phase 2 |
| Minimum versions | Java 17 and 22+, Node 22, Python 3.10, .NET 8, Go 1.22, PHP 8.2, Ruby 3.2, Android API 28, iOS 15 | Fill-in block defaults |
| Registries | Undecided | Needed by Phase 6 |

## Open risks

- **The library could change the design.** Its language, whether it compiles to `wasm32`, and whether its certificate covers rebuilds could each limit the targets. See `docs/crypto-inventory.md`.
- **The protocol is unproven.** It is a new composition of published parts. One AI-assisted review found 17 defects, which are fixed, but the fixes have not been re-reviewed, and there is no formal model or review by a human cryptographer yet. Do not rely on it until Phase 1 is complete.
- **Publishing cryptographic code.** This repository is public. Check what the certification body and local rules allow before `provider-<lib>` is published.
- **The schedule.** The Roadmap gives Phase 2 three weeks, but §7's Phase 2 also includes the IDL generators, the sidecar with PHP and shell clients, `qalqon new` and templates.
- **The toolchain.** `cargo`, `rustc` and `just` are not installed on the current development machine, so they are needed before Phase 1.
