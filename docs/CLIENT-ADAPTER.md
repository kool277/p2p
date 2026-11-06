# Client Adapter Contract

Version v0. **Status: draft, implemented by `packages/js/react` and the four clients in `clients/`.**

An adapter makes the SDK feel native in one framework. It adds no behaviour of its own. Adding a client framework means writing an adapter, and never means changing `core/`.

## What an adapter must do

1. **Create a session from configuration.** Wrap `connect` and `enrollDevice`.
2. **Surface events in the framework's idiom.** Run the `nextEvent` loop and translate each event.
3. **Expose channels.** Wrap `openChannel`, `acceptChannel`, `send`, `receive` and `close`.
4. **Show peer verification.** Make `verifyPeer` reachable, including the safety number.

## What an adapter must not do

- Implement a handshake step, derive a key or touch key bytes. A CI lint enforces this (rule 0.4).
- Store plaintext beyond what the application asks for.
- Hide `peerIdentityChanged`. It must reach the application, and the default policy blocks the channel until the user re-verifies.
- Retry a failed handshake with weaker settings.
- Change method names or error codes, apart from the language's casing.

## How the idioms map

| Framework | Package | Session and events | Channels |
| --- | --- | --- | --- |
| React | `packages/js/react` | `useQalqonSession` hook | `useChannel` hook |
| Vue | `packages/js/vue` | Composable returning refs | Composable |
| Angular | `packages/js/angular` | Service exposing observables | Service |
| Svelte | `packages/js/svelte` | Store | Store |
| Electron | `packages/js/electron` | IPC bridge, with the session in the main process | Same bridge |
| Qt and QML | `packages/qt` | `Session` QObject with signals | `Channel` QObject |
| Android | `bindings/kotlin` | `Flow` of events, `suspend` calls | Same |
| iOS and macOS | `bindings/swift` | `AsyncSequence` of events, `async` calls | Same |
| Flutter | `packages/dart/flutter` | `Stream` of events | Same |
| .NET MAUI | `bindings/dotnet` | `IAsyncEnumerable` of events | Same |
| C, C++ | `bindings/c` | Poll `qalqon_session_next_event` directly | Direct calls |

## Platforms where the application owns the sockets

Browsers cannot give WebAssembly a socket, and mobile apps run WebRTC through libwebrtc. On those platforms the adapter passes an `ExternalTransport` in `SessionConfig`:

```
while command = transport.pollCommand():
    openLink   -> open a WebSocket, or an RTCPeerConnection with a DataChannel,
                  then transport.linkOpened(linkId, caps)
    sendFrame  -> write the frame to the link
    sendSignal -> give the SDP or ICE data to the WebRTC stack
    closeLink  -> close the link

on incoming frame:            transport.frameReceived(linkId, frame)
on local SDP or ICE data:     transport.signalReceived(linkId, blob)
on link end:                  transport.linkClosed(linkId)
```

Frames are already encrypted when the adapter sees them, so this code handles only ciphertext and connectivity data.

In browsers the core runs in a Web Worker, under a strict Content Security Policy. Key storage is handled inside the core (ADR-0002, part 6), so adapters never handle key bytes. JavaScript holds a non-extractable `CryptoKey` and an opaque wrapped blob.

WebRTC does not exist inside a Worker, so the page owns the `RTCPeerConnection` and passes frames, which are already encrypted, to and from the worker.

## The demo app

Every `clients/` folder has the same screens, so that interop runs can drive them uniformly.

| Screen | SDK calls |
| --- | --- |
| Enrol | `enrollDevice` |
| Log in | `connect` |
| Peers | `verifyPeer` |
| Channel: text and file transfer | `openChannel`, `acceptChannel`, `send`, `receive` |
| Verify peer: safety number | `verifyPeer` |
| Security: rotate keys, export audit, current path | `rotateKeys`, `exportAudit`, `info` |

Automation IDs follow the pattern `qalqon-<screen>-<control>`. Interop tests use Playwright for browsers, Maestro for Android and iOS, and each CLI's own commands elsewhere. CLI clients print events as JSON Lines, so a test can read them.

## The CLI contract

Interop runs drive every client the same way, so a client must offer these commands, directly or through a driver like `tests/interop/web/driver.mjs`.

```
<client> enroll --server <url> --ca <hex file> --data <dir> --token <token>
<client> call   --server <url> --ca <hex file> --data <dir> --user <id> --peer <id> [--records N] [--relay-only]
<client> answer --server <url> --ca <hex file> --data <dir> --user <id> [--relay-only] [--wait-ms N]
```

The password comes from the `QALQON_PASSWORD` environment variable, because arguments are visible to every process on the machine. Output is one JSON object per line.

| Line | When |
| --- | --- |
| `{"enrolled": ...}` | `enroll` succeeded |
| `{"state": "connected"}` | Logged in, so a test can start the caller |
| `{"result": "ok", "records": n, "path": ..., "key_epoch": ..., "peer_status": ..., "safety_number": ..., "audit_entries": n}` | `call` finished. It sends numbered records with at most 64 outstanding, checks each echo, and rotates keys halfway. `answer` reports the same fields, except `key_epoch` and `audit_entries` |
| `{"result": "error", "error": ...}` | It failed, with a non-zero exit |

## Checklist for a new adapter

1. Run `qalqon new client --lang <x> --framework <y>`.
2. Write the idiomatic wrapper and the demo screens.
3. Pass `qalqon test --pair <client>:<server>`.
