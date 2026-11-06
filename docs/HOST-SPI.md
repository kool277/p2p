# Host SPI

Version v0. **Status: draft, implemented by `core/server-core` and `servers/rust-axum`.**

A host is a thin server program in any language. It owns the socket, the database and the configuration, and it hands every frame to `server-core`. This document is the whole contract a new host must meet. A host is finished when it implements this contract and passes the same interop suite as `servers/rust-axum`, the reference host.

## Who owns what

| The host owns | `server-core` owns |
| --- | --- |
| Accepting the WebSocket upgrade and pumping frames | Handshake and record layer |
| Database access and its migrations | Session registry and rendezvous matching |
| Loading configuration | Policy evaluation and rate limits |
| Authenticating administrators | Audit chaining and signed checkpoints |
| Serving health and metrics endpoints | Password verification, certificate checks and the admin API's meaning |

A host MUST NOT implement a handshake step or derive a key, and it never holds key bytes. A CI lint enforces this (rule 0.4).

## How a host drives `server-core`

The API is in `docs/SDK-API.md`, under `ServerCore`. Nothing calls back across the FFI boundary (ADR-0002, part 5). `server-core` returns *effects*, which the host performs. The same loop works on an event loop, on a thread pool and over the sidecar:

```
on WebSocket upgrade:   connId = core.accept(meta)
on WebSocket frame:     core.onFrame(connId, frame)
on WebSocket close:     core.onClose(connId)
about once a second:    core.tick(nowMs)

on its own thread, or in a loop on the event loop:
    while effect = core.pollEffect(timeoutMs):
        sendFrame       -> write the frame to the socket
        closeConnection -> close the socket
        store           -> run the database operation, then
                           core.completeEffect(effectId, status, record)
        alarm           -> forward to the security administrator's alert channel
```

Store effects may complete in any order, and the host MAY run them concurrently. `onFrame` returns quickly, and Argon2id runs on worker threads in `server-core`. That is why `pollEffect` can wait: a result appears without any call from the host. `adminCall` waits on the stores, so the effect loop must keep running while it does.

## The four stores

Records cross the boundary as JSON documents that `server-core` owns. A host keeps each document as it is and adds only the columns it has to query by, as `core/server-core/migrations/0001_init.sql` shows. **That schema is proposed, not approved:** the database schema is a stop-and-ask choice in the build prompt. Each host applies it with its own tool.

| Store | Operations | Fields |
| --- | --- | --- |
| `UserStore` | `get`, `put`, `list` | `user_id`, `display_name`, `password_hash`, `mfa_state`, `role`, `status`, `failed_attempts`, `locked_until`, `enrollment_tokens` (hashes only), `created_at`, `updated_at` |
| `DeviceStore` | `get`, `put`, `list` (`key` of `user:<id>` narrows it to one user) | `device_id`, `user_id`, `device_name`, `fingerprint`, `cert_chain`, `serial`, `status`, `enrolled_at`, `revoked_at`, `last_seen_at` |
| `PolicyStore` | `get`, `put` | `name`, `version`, `document`, `updated_at` |
| `AuditSink` | `append`, `head`, `range` (`key` is `from,to`, both inclusive) | `seq`, `at`, `subject`, `object`, `operation`, `result`, `detail`, `entry_hash` |

`password_hash` and `mfa_state` are produced and checked by `server-core`. The host stores them as opaque values.

If an `AuditSink` append fails, `server-core` refuses the operation being audited with `auditUnavailable` and raises an alarm. An operation that cannot be logged does not happen.

## Configuration

A host loads these from its own configuration system and passes them to `createServerCore`.

| Setting | Notes |
| --- | --- |
| `identityKeyRef` | A **reference** to the server's identity key, such as `file:/path/to/keys#server` |
| `chain` | The server's certificate chain, whose leaf names this host |
| `caBundle` | Trusted root certificates |
| `issuingKeyRef`, `issuingCertificate` | The issuing CA, if this server issues device certificates. Enrolment fails without it |
| `relayKeyRef` | The key shared with the relays, for grants |
| `auditKeyRef` | The key for hashing secrets presented in failed logins |
| `relayAddresses` | Relay and TURN addresses to give to clients |
| `policy` | The initial policy document. Unset, the default applies |

**Refinement to the design:** the design document says a host's `Config` loads the server identity key. A host written in Java, Node or Python that holds those bytes would break the rule against touching key bytes and could not zeroize them. So the host passes a reference, and `server-core` opens the key itself.

## Health and metrics

| Endpoint | Source | Meaning |
| --- | --- | --- |
| Liveness | `health().live` | The process is running |
| Readiness | `health().ready` | Self-tests passed, the identity key is open and the stores respond |
| Metrics | `metrics().text` | Prometheus text, including handshake failures, direct versus relayed sessions, active sessions and alarm counts |

Metric names are fixed so that dashboards work on every host. `docs/OPERATIONS.md` lists them.

## Admin

The host exposes `https://host/admin` under its own authentication and forwards each authorised request to `adminCall(method, paramsJson)`. The host decides who the caller is, and `server-core` decides what that means and writes the audit row.

| Area | Methods |
| --- | --- |
| Users | `users.list`, `users.create`, `users.disable`, `users.resetPassword` |
| Devices | `devices.list`, `devices.createEnrollmentToken`, `devices.revoke` |
| Revocation | `revocation.publish` |
| Audit | `audit.export`, `audit.verify` |

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `wss://host/qalqon` | The control plane. Platform TLS stays on, and Qalqon runs inside it |
| `https://host/admin` | The admin API |

## Checklist for a new host

1. Run `qalqon new server --lang <x> --framework <y>`.
2. Implement the upgrade and the effect loop above.
3. Implement the four stores and apply the reference migrations with your tool.
4. Load the configuration, and expose the health, metrics and admin endpoints.
5. Pass `qalqon test --pair <client>:<server>`.
