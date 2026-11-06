# Testing

Everything below runs on the test-only provider. Nothing here shows anything about O'z DSt 1105, 1106 or 1092.

| Layer | What it checks | Run it with |
| --- | --- | --- |
| Known answers | HMAC (RFC 4231), HKDF (RFC 5869), SHA-256, Ed25519 (RFC 8032), X25519 (RFC 7748), AES-CTR against OpenSSL. **The official O'z DSt control examples wait for the library** | `cargo test -p provider-testonly` |
| Specification | A scripted peer written from `docs/PROTOCOL.md`, with its own transcript code, so a disagreement between code and document fails | `cargo test -p qalqon-core --test spec_conformance` |
| Handshake | Tampering with every bit of every message, downgrade, certificates, pins, loss, fragments, amplification | `cargo test -p qalqon-core --test handshake` |
| Records and channels | Replay, deletion, reordering, rekeying, epochs, closure, truncation, limits | `cargo test -p qalqon-core --test records` |
| Properties | Replay window against a model, fragments in any order, garbage at every stage, a hostile network never changing or repeating a message | `cargo test -p qalqon-core --test properties` |
| Server core | Enrolment, login, lockout, rendezvous, revocation, audit failure, tampering, restart | `cargo test -p server-core` |
| End to end, simulated | Two client cores, a real server core and a blind relay on a simulated clock | `cargo test -p qalqon-signal` |
| Two processes | Peers over real TCP and UDP sockets, including 10% loss | `tests/phase1-gate.sh` |
| Vectors | Deterministic files in `tests/conformance/testonly`, run in each runtime | `cargo qalqon test --conformance <binding>` |
| Interop | A fresh host and relay, two enrolled devices, direct and relay-forced channels, 1,000 records with a rekey, the host's audit chain | `cargo qalqon test --pair <client>:<server>` |
| Formal | ProVerif models of the handshake. See `formal/README.md` | `formal/run.sh` |
| Fuzzing | Every network parser, and a session fed attacker bytes at every stage | `cargo +nightly fuzz run --fuzz-dir tools/fuzz <parsers\|session>` |
| Timing | A Welch's t-test between input classes, with controls that show the harness can both see a leak and not invent one | `cargo test -p provider-testonly --test timing -- --ignored --test-threads=1` |
| Rule 0.4 | No protocol or crypto logic outside `core/` | `cargo qalqon lint` |

## Not done yet

- **Miri** and the **90% coverage** target (§8) have not been run.
- **One hour of fuzzing per target** (§8) runs in the nightly workflow. So far each target has had three minutes.
- **`tools/selftest`**, the attack-imitation suite, does not exist yet.
- **`tools/natsim`** does not exist yet, so NAT behaviour is untested.
- **Performance budgets** are not set.
