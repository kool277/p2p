# ADR-0004: Sidecar IPC

- **Status:** Proposed, and implemented provisionally on Unix. The owner asked to proceed without answering, so this can still change.
- **Date:** 2026-11-05

## Context

`qalqond` serves the SDK API to any language that can open a local socket. Rule 0.2 requires approval for the IPC format. The build prompt fixes the broad shape: a Unix domain socket, a named pipe or loopback TCP with a per-launch token, carrying length-prefixed JSON-RPC that mirrors `docs/SDK-API.md`. Peer credentials are checked, the daemon runs as the same user, and keys never leave it. A client library for a new language should be about 200 lines. This ADR fills in the details.

## Decision (proposed)

### Framing

Each frame is a big-endian `u32` length followed by that many bytes of UTF-8 JSON. The maximum frame is 16 MiB. A longer or malformed frame closes the connection.

### Messages

Messages follow JSON-RPC 2.0. Method names are the IDL's, namespaced by interface: `connect`, `session.openChannel`, `channel.send`, `serverCore.pollEffect`. Bytes are standard base64 (RFC 4648). Handles are opaque strings scoped to one IPC connection, and closing the connection closes its handles.

`error.code` is the IDL's numeric error code and `error.data.name` is its name, so every language sees the same codes. The JSON-RPC reserved range is used only for JSON-RPC's own errors, such as a parse failure.

Events are polled with `session.nextEvent`, the same as every other binding. There are no server-initiated notifications, which keeps generated clients small.

### Starting a connection

The first request on a connection must be `qalqond.hello`, and anything else closes it:

```json
{"jsonrpc":"2.0","id":1,"method":"qalqond.hello",
 "params":{"abi":0,"client":"php/0.1.0","token":"<loopback TCP only>"}}
```

The reply carries `abi`, `protocol_version` and `build_id`. A different major `abi` fails with `unsupported`.

### Endpoints and access checks

| Platform | Endpoint | Access check |
| --- | --- | --- |
| Linux | Unix socket in `$XDG_RUNTIME_DIR/qalqon/`, directory mode `0700` | `SO_PEERCRED`: the peer's UID must match the daemon's |
| macOS, FreeBSD | Unix socket in a per-user `0700` directory | `getpeereid()`: same rule (**not built yet**, so only the directory's mode protects it) |
| Windows | Named pipe with a DACL for the current user and `PIPE_REJECT_REMOTE_CLIENTS` (**not built yet**) | Client token's SID must match, using `ImpersonateNamedPipeClient` |
| Anywhere else, or restricted runtimes | Loopback TCP on an ephemeral port | Per-launch token |

The loopback token is 32 random bytes, written to a `0600` file whose path `qalqond` prints at launch, and compared in constant time. It never appears on a command line or in an environment listing.

### As a container beside a server

The daemon shares a Unix socket with the host through a volume mounted only into those two containers, both running as the same UID. If they cannot share a volume, it listens on loopback TCP inside the shared network namespace, with the token mounted as a secret.

### Shell and other minimal clients

`curl` cannot speak length-prefixed JSON-RPC, so `qalqond call <socket> <method> '<json>'` speaks the protocol for a script. This meets the prompt's "curl-style" intent without adding an HTTP server to the daemon.

**Refinement while implementing:** handles die with their connection, so one call per process cannot hold a session. The shell client therefore talks to a long-running `qalqond client <socket>`, which turns JSON lines into framed requests over one connection, through named pipes. `qalqond call` remains for calls that hold no handle.

### Client libraries

Generated from the IDL's JSON-RPC schema. A client library contains framing, `hello`, base64 and one function per method, and nothing else. PHP, Ruby, Elixir and shell come first.

## Alternatives rejected

| Option | Why not |
| --- | --- |
| gRPC | HTTP/2 and protobuf defeat the 200-line target, and support is poor on PHP shared hosting |
| HTTP/1.1 over the socket | Would work with `curl`, but a 4-byte prefix is far simpler, and the prompt specifies framed JSON-RPC |
| MessagePack or a binary frame | Saves the base64 overhead but needs a codec in every client. See the consequences below |

## Consequences

- Base64 adds about 33% to payload bytes, and JSON adds parsing cost. Round-trip time is measured after Phase 2. If the budget is missed, an optional binary frame can be added in a later minor version, negotiated in `hello`.
- Any process running as the same user can reach the daemon. This matches the prompt's model, and `docs/THREAT-MODEL.md` must state it plainly. The daemon protects against other users and remote hosts, not against malware running as that user.
- Plaintext payloads pass through the socket, in the same trust zone as the application.
- `docs/COMPLIANCE.md` gains a row for local IPC protection.
