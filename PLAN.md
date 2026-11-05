# Plan

The working plan for the build described in `CLAUDE.md`. It is updated in every commit.

## Where things stand

**Phases 1 and 2 are done as far as they can go without the O'z DSt library.** Their code runs and their interop tests pass, all on `core/provider-testonly`. Nothing here uses the standard's cryptography, so nothing here meets O'z DSt requirements, and a release build is refused.

The owner asked to proceed without answering the decisions below, so this work follows the recommendations in this file. Each of them can still be changed.

| Phase | Scope | Gate | State |
| --- | --- | --- | --- |
| 0 | Inventory, ADRs, protocol and API drafts | Owner approval | Drafts done. The inventory is still blocked on the library |
| 1 | `core/`: crypto provider, protocol engine, vectors, formal model, server core | Two Rust peers interoperate over TCP and UDP, and the lemmas are proven | **Met on the test-only provider, except:** the official control examples need the library. See below |
| 2 | IDL generators, C ABI, C and WASM bindings, sidecar, `rust-axum`, relay, coturn, `qalqon` CLI, templates | `cli-c`, `web-react` and a sidecar PHP CLI each talk to `rust-axum`, and `qalqon new` scaffolds a passing binding | **Met on the test-only provider** |
| 3 | Primary pairs | Every primary pair is green on every PR, and the mixed-client triple is green | Not started. `web-react` + `java-spring` and `cli-c` + `node-express` need `bindings/java`, `bindings/node` and two hosts |
| 4 | Mobile, the full target matrix, per-OS packaging | Android and iOS work against two hosts, and every target produces its artifact | Not started |
| 5 | Remaining hosts, clients and sidecar languages | Every declared folder has a passing nightly cell | Not started |
| 6 | Release pipeline, docs site, hardening, selftest suite | A tagged release installs from the registries alone, and the full matrix is green | Not started, and blocked on the library |

Phases follow §7 of the build prompt, which is fuller than the Roadmap section of `CLAUDE.md`.

## Which combinations have passed an interop run

All on the test-only provider, on Linux x64, on one machine, on loopback. Each run: a fresh host and relay, two enrolled devices, a channel that prefers a direct path, a relay-forced channel, 1,000 records with a rekey, and the host's audit chain. `cargo qalqon test --primary` repeats these.

| Client | Peer | Server | Path when direct is preferred |
| --- | --- | --- | --- |
| `cli-rust` | `cli-rust` | `rust-axum` | Direct (TCP) |
| `cli-c` | `cli-rust` | `rust-axum` | Direct (TCP) |
| `php-cli`, through `qalqond` | `cli-rust` | `rust-axum` | Direct (TCP) |
| `web-react`, in headless Chromium | `cli-rust` | `rust-axum` | Relayed, because native clients do not speak WebRTC yet |
| `web-react` | `cli-c` | `rust-axum` | Relayed, same reason |
| `web-react` | `web-react` | `rust-axum` | Direct (WebRTC) |

The shared vectors pass in C and C++, PHP, shell, the browser's WebAssembly, and scaffolded Python through both the C ABI and the sidecar. `tests/phase1-gate.sh` runs two separate processes over TCP and UDP, including with 10% loss.

## Known gaps

**These matter most, in order.**

1. **No certified library.** Every O'z DSt requirement is unmet until `core/provider-<lib>` exists. The Phase 1 gate's known-answer tests from the official control examples cannot run without it.
2. **No NAT traversal for native clients.** The build prompt's P2P-first MUST is only partly met. Native clients connect directly only to a reachable address, and otherwise use the relay. A browser and a native client always use the relay. The next step is QUIC with hole punching for native peers, or WebRTC on the native side.
3. **No human review.** The protocol is a new composition of published parts, checked by tests, fuzzing, one AI-assisted review and a symbolic model. None of that replaces a cryptographer. Do not rely on it until one has reviewed it.
4. **No TLS on the reference host.** It needs a terminating proxy, and clients refuse `ws://` except on loopback, so `wss://` has not had an interop run.
5. **MFA is not implemented,** and neither are confidentiality labels, the binary integrity check, `qalqon-selftest`, `tools/natsim`, platform key stores, reconnecting after losing the control plane, or WASI.
6. **Not run yet:** Miri and the 90% coverage target. Each fuzz target has had three minutes, against §8's one hour. The Ruby and Elixir sidecar clients are generated but have never run. `bindings/c/CMakeLists.txt` has never run, because CMake is not on this machine. Windows, macOS, iOS and Android have never been built.

## Decisions still open

Work is proceeding on the recommendations below until you say otherwise, except decisions 1, 2 and 6, which only you can make.

| # | Decision | What it blocks | Recommendation |
| --- | --- | --- | --- |
| 1 | Fill in the fill-in block and say where the library is | The inventory, ADR-0001, suite values, `provider-<lib>` | None: only you know this |
| 2 | Can the library and its bindings be public? | Where `provider-<lib>` lives | Keep the library outside this repository until you have confirmed the licence and what the certification body allows |
| 3 | Allow a test-only crypto provider (ADR-0002, part 2)? | Everything built so far | Yes. It is refused in release builds |
| 4 | Approve or change ADRs 0001-0004 and the drafts, including the refinements below | The protocol freeze | Approve, after reconciling with the companion specification |
| 5 | Supply the companion specification and the original diagrams | The protocol freeze | Needed. Do not commit the scanned standard here unless you have the right to publish it |
| 6 | Choose a licence | Anyone reusing this code. With none, all rights are reserved by default | Your choice |
| 7 | Confirm the target class and how the class labels read (`1В`, `1V`, `1B`) | `docs/COMPLIANCE.md` | Check against the standard |
| 8 | Confirm the primary pairs | Phase 3 | `web-react` + `java-spring` and `cli-c` + `node-express`, as the Roadmap assumes |
| 9 | How to record failed login secrets in the audit log | `docs/COMPLIANCE.md` | A keyed hash, as built |
| 10 | Move the design out of `CLAUDE.md`? | Nothing, but it adds about 16k tokens to every session | Yes, into `docs/design/` |
| 11 | Replace the IK-style handshake with one XX handshake that can omit a cached certificate? | The protocol freeze | Yes, as built. A two-message flow cannot meet the first MUST in §1.1, and `formal/negative_ik.pv` shows the attack |
| 12 | Must every new device of a known user be re-verified, or should existing devices be able to vouch for new ones? | `docs/PROTOCOL.md`, section 11.4 | Start with re-verifying, as built, because it is simple and safe. It does cost contacts a step each time someone adds a device |
| 13 | Approve JSON for structured values across the C ABI (ADR-0002, part 4) | The ABI's stability | Yes. A binding needs one decoder, and `send` and `receive` stay raw bytes |
| 14 | Approve the reference SQL schema (`core/server-core/migrations/`) | Other hosts | Yes. Each store is a JSON document plus only the columns a host queries by |

## Refinements to the design, for your approval

Each of these departs from, or fills a gap in, the wording of `CLAUDE.md`.

| Refinement | Where | Why |
| --- | --- | --- |
| Root Cargo workspace instead of a workspace in `core/` | ADR-0003 | All Rust folders must compile identical core sources |
| `primary_triples`, `build` and `conformance` manifest fields | ADR-0003 | Triples had no valid home, and the CLI should know nothing about any ecosystem |
| Rust-based bridges compile the core instead of linking a shared binary | ADR-0003 | They cannot link a prebuilt binary, so identical sources are proved by build IDs |
| `core/provider-testonly` | ADR-0002 | Decouples this work from the library's arrival |
| `core/keystore-<platform>` | ADR-0002 | Platform key storage had no home, and it has to stay inside `core/` |
| `core/qalqon-signal`, `core/qalqon-sdk`, `core/qalqon-api`, `core/qalqon-conformance` | ADR-0002, part 7 | Native SDKs and browsers run the same client logic, and each binding proves itself through one conformance entry point |
| Host stores are polled effects, not callbacks | ADR-0002, `docs/HOST-SPI.md` | Callbacks across FFI are restricted, and blocking would stall event-loop hosts |
| A host passes a key reference, not key bytes | `docs/HOST-SPI.md` | A host holding the bytes would break the rule against touching key bytes |
| API additions, such as `enrollDevice`, `acceptChannel` and `conformanceRun` | `docs/SDK-API.md` | The listed methods alone cannot run a session |
| One handshake that can omit a cached certificate, instead of IK | `docs/PROTOCOL.md`, sections 1 and 8 | A two-message flow cannot bind I's signature to the full transcript |
| Pins are per user, so a known user's new device blocks until verified | `docs/PROTOCOL.md`, section 11.4 | Otherwise a malicious server could route calls to a device it invented |
| `seq` is a 16-bit epoch plus a 48-bit counter that never restarts | `docs/PROTOCOL.md`, section 9.3 | Lossy receivers need to know which key a record uses, and a counter that never restarts exposes records deleted around a rekey |
| The encrypt-then-MAC tag covers the nonce | `docs/PROTOCOL.md`, section 9.2 | A true AEAD binds its nonce. A known-answer test found this |
| Self-signed pre-enrolment certificates | `docs/PROTOCOL.md`, section 11.6 | Keeps mutual authentication on every channel, including enrolment |
| `qalqond client` and `qalqond call` for shell clients | ADR-0004 | `curl` cannot speak framed JSON-RPC, and handles die with their connection |
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
- **Publishing cryptographic code.** This repository is public. Check what the certification body and local rules allow before `provider-<lib>` is published.
- **The formal model's reach.** It assumes perfect primitives and covers the message flow. It does not model the code, record integrity (covered by tests) or the channel layer.
- **The schedule.** The Roadmap's durations assume one engineer plus the agent. Phase 3 needs JVM and Node bridges, each of which adds a native prebuild to the release matrix.
