# Operations

**Everything here describes a development deployment, on the test-only provider.** Production operations depend on the certified library and on a real key ceremony, neither of which exists yet.

## Running a host

`cargo qalqon dev --client cli-rust --server rust-axum` runs a host and a relay on loopback with a fresh PKI, and prints what you need. `infra/compose/docker-compose.yaml` does the same in containers, plus coturn.

| Setting (`servers/rust-axum`) | Meaning |
| --- | --- |
| `--listen` | The address to serve on |
| `--db` | The SQLite file |
| `--pki` | A directory from `qalqon-ca` |
| `--host` | The name in the server's certificate. Clients check it against `serverUrl` |
| `--relay` | The relay address to hand to clients |
| `--admin-token-file` | The bearer token for `/admin` |

The reference host serves plain WebSocket. Clients refuse `ws://` anywhere but loopback, so a real deployment must put TLS in front of it. Platform TLS stays on, and Qalqon runs inside it.

## Keys

`qalqon-ca init` creates a root and an issuing CA in `<dir>/keys`, wrapped by `keystore-file` under a KEK in the same directory. That is a development shortcut. A real deployment keeps the root offline, and its key ceremony is **not written yet**.

## Administration

The host authenticates the caller with its bearer token, and the core decides what each call means and writes the audit row. Send JSON to `POST /admin/<method>`.

| Method | Parameters |
| --- | --- |
| `users.create` | `user_id`, `password` (at least 12 characters), optional `role`, `display_name` |
| `users.list`, `users.disable`, `users.resetPassword` | `user_id`, and `password` to reset |
| `devices.createEnrollmentToken` | `user_id`, optional `ttl_ms`. Returns a one-time token |
| `devices.list`, `devices.revoke` | optional `user_id`, or `device_id` to revoke |
| `revocation.publish` | Signs a new CRL now. The core also does this every 12 hours |
| `audit.export`, `audit.verify` | Optional `from`, `to` |

Revoking a device ends its live session, lists it on a new CRL at once, and blocks it from reconnecting.

## Health and metrics

`/healthz`, `/readyz` and `/metrics` (Prometheus text). Metric names are fixed so dashboards work on every host: `qalqon_sessions_active`, `qalqon_sessions_total`, `qalqon_handshake_failures_total`, `qalqon_logins_ok_total`, `qalqon_logins_failed_total`, `qalqon_rendezvous_opened_total`, `qalqon_data_sessions_direct_total`, `qalqon_data_sessions_relayed_total`, `qalqon_alarms_total`, `qalqon_audit_entries`.

Alarms go to the host's alert channel. The reference host writes them to stderr.

## Backup and restore

Back up the database and the key directory separately. The audit chain resumes from its last row after a restart, and `audit.verify` detects a restore that lost rows. A restore drill has **not been run**.
