# Threat model

This covers the design as built. No external party has reviewed it, and it does not yet run on the certified library.

## Assets

Application data in channels, long-term identity keys, session keys, login secrets, and the integrity of the audit logs.

## Attackers and what stops them

| Attacker | Can | Cannot, by design | Evidence |
| --- | --- | --- | --- |
| Network, active | Drop, delay, replay, change frames | Read or undetectably change records. Downgrade the suite. Learn which check failed | `formal/`, `core/qalqon-core/tests/` |
| Relay | See frame sizes and timing, and drop traffic | Read or change records, or impersonate a peer | `formal/`, an interop run checks that the relay sees no plaintext |
| Malicious server | Refuse service. Lie about who is online. Obtain a certificate for anyone | Read data-plane records, or impersonate a user a client has already pinned | `formal/pins.pv`, `core/qalqon-signal/tests/e2e.rs` |
| Stranger who finds a listening direct port | Connect and send junk, which costs a fallback to the relay | Learn anything, or take over the call | `core/qalqon-signal/tests/e2e.rs` |
| Past identity key theft | Impersonate from now on | Read earlier sessions (forward secrecy) | `formal/secrecy_forward.pv` |
| Leak of one session's ephemeral key | Read that session | Impersonate anyone in another session | `formal/ephemeral_leak.pv`, `formal/negative_ik.pv` shows the flow this replaced fails |
| Database administrator on a host | Read user records. Edit the audit table | Edit the audit chain undetected. Learn passwords (Argon2id) or enrolment tokens (hashed) | `core/server-core/tests/server.rs` |

## What is exposed, by design

- **First contact without comparing safety numbers.** A malicious server can substitute someone at first contact, and only comparing safety numbers detects that. `formal/first_contact.pv` confirms this attack, so it stays visible.
- **Metadata.** The server knows who calls whom and when. An observer sees frame sizes, timing and channel IDs.
- **A browser's same-origin script.** It cannot read the wrapped key, but it can ask the core to sign. The browser tier is weaker than a platform key store.
- **The sidecar's same-user processes.** Any process running as the same user can reach `qalqond`.
- **`KEY_CONFIRM` after an ephemeral leak.** It is protected only by that session's keys, so whoever holds them can forge it. I still knows that R signed the transcript.
- **Compromise recovery.** Rekeying protects earlier traffic, but later keys follow from the current secret. Recovering needs a new handshake.

## Not covered

- Side channels beyond the comparison checks in `core/provider-testonly/tests/timing.rs`.
- Traffic analysis, denial of service beyond rate limits, a compromised endpoint, and malicious dependencies beyond pinned versions.
- The certified library itself, which has not been supplied.
