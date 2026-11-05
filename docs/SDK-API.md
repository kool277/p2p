# SDK API

API version 0.1.0, protocol version 0.1.

**Status: proposal for the Phase 0 gate.** Nothing is implemented.

**Generated. Do not edit by hand.** This file is rendered from `core/idl/qalqon.api.yaml`, the single source of truth. It was rendered by a one-off script for Phase 0, and the real generator arrives in Phase 2.

Every language and the sidecar expose these names and numeric error codes, changing only the casing. Async calls appear in each language's own idiom: a promise, a coroutine, or a blocking call in C. Keys never appear in this API, only handles and public fingerprints.

## Additions to the build prompt's list

The build prompt names `connect`, `openChannel`, `send`, `receive`, `verifyPeer`, `rotateKeys` and `exportAudit`, plus events. Those alone cannot run a session, so this draft proposes the following additions.

| Addition | Why it is needed |
| --- | --- |
| `enrollDevice` | A device needs a certificate before it can connect, and the interop suite enrols devices first |
| `acceptChannel`, `rejectChannel` | The peer being called has to be able to answer a `channelRequested` event |
| `nextEvent` | Events cross the FFI boundary by polling, because callbacks are restricted (ADR-0002) |
| `Session.close`, `Channel.close` | The protocol requires an authenticated close, so applications need a way to ask for one |
| `Channel.info` | The demo app and interop suite need to see the current path and key epoch |
| `createExternalTransport`, `ExternalTransport` | Browsers and mobile WebRTC own their sockets (ADR-0002) |
| `createServerCore`, `ServerCore` | Every host embeds the server core through this same API (`docs/HOST-SPI.md`) |

## Functions

### `enrollDevice`

Registers this device with a host. Generates the identity key if needed. Async.

| Parameter | Type | Description |
| --- | --- | --- |
| `config` | `SessionConfig` | Connection settings. |
| `request` | `EnrollmentRequest` | The token and device name. |

**Returns:** `EnrollmentResult`

**Errors:** `invalidArgument`, `timeout`, `transportFailed`, `handshakeFailed`, `enrollmentRejected`, `rateLimited`, `keyStoreUnavailable`, `selfTestFailed`, `integrityCheckFailed`

### `connect`

Connects to a host, authenticates and logs in. Runs self-tests on first use. Async.

| Parameter | Type | Description |
| --- | --- | --- |
| `config` | `SessionConfig` | Connection settings. |
| `credentials` | `Credentials` | Login details. |

**Returns:** `Session`

**Errors:** `invalidArgument`, `timeout`, `transportFailed`, `handshakeFailed`, `versionMismatch`, `suiteMismatch`, `peerRevoked`, `authenticationFailed`, `mfaRequired`, `rateLimited`, `notEnrolled`, `keyStoreUnavailable`, `selfTestFailed`, `integrityCheckFailed`, `auditUnavailable`

### `createExternalTransport`

Creates a transport that the application drives. Pass it in SessionConfig before calling connect. Synchronous.

**Returns:** `ExternalTransport`

**Errors:** `unsupported`

### `createServerCore`

Creates the server core inside a host. See docs/HOST-SPI.md. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `config` | `ServerConfig` | The host's configuration. |

**Returns:** `ServerCore`

**Errors:** `invalidArgument`, `keyStoreUnavailable`, `selfTestFailed`, `integrityCheckFailed`

## Interfaces

### `Session`

A logged-in connection to a host. Owns the channels and direct peer sessions.

#### `Session.openChannel`

Opens a channel to a peer, running rendezvous and the end-to-end handshake if needed. Async.

| Parameter | Type | Description |
| --- | --- | --- |
| `peer` | `PeerRef` | Who to connect to. |
| `options` | `ChannelOptions` | What the channel must provide. |

**Returns:** `Channel`

**Errors:** `invalidArgument`, `timeout`, `closed`, `transportFailed`, `transportUnsupported`, `peerUnavailable`, `peerUnreachable`, `handshakeFailed`, `versionMismatch`, `suiteMismatch`, `peerIdentityChanged`, `peerRevoked`, `revocationDataStale`, `accessDenied`, `auditUnavailable`

#### `Session.acceptChannel`

Accepts a channel the peer requested in a channelRequested event. Async.

| Parameter | Type | Description |
| --- | --- | --- |
| `requestId` | `string` | From the event. |

**Returns:** `Channel`

**Errors:** `invalidArgument`, `invalidState`, `timeout`, `closed`, `transportFailed`, `transportUnsupported`, `peerUnreachable`, `handshakeFailed`, `peerIdentityChanged`, `peerRevoked`, `revocationDataStale`, `auditUnavailable`

#### `Session.rejectChannel`

Declines a channel the peer requested. The peer only sees peerUnavailable. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `requestId` | `string` | From the event. |

**Returns:** nothing

**Errors:** `invalidArgument`, `invalidState`, `closed`

#### `Session.verifyPeer`

Returns a peer's identity for display. Given a safety number, compares it in constant time and records the peer as verified if it matches. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `peer` | `PeerRef` | The peer. |
| `safetyNumber` | `string?` | The number the user compared out of band. |

**Returns:** `PeerIdentity`

**Errors:** `invalidArgument`, `closed`, `peerUnavailable`

#### `Session.rotateKeys`

Moves traffic keys to a new epoch in both directions, for one peer or for all. Completes when the peer has moved too. Async.

| Parameter | Type | Description |
| --- | --- | --- |
| `peer` | `PeerRef?` | The peer. Unset, all peers. |

**Returns:** nothing

**Errors:** `invalidState`, `timeout`, `closed`, `auditUnavailable`

#### `Session.exportAudit`

Exports the local audit chain so it can be verified elsewhere. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `request` | `AuditExportRequest` | The range to export. |

**Returns:** `AuditExport`

**Errors:** `invalidArgument`, `closed`, `accessDenied`, `auditUnavailable`

#### `Session.nextEvent`

Waits for the next event. Adapters run this in a loop and translate events into their framework's idiom. Async.

| Parameter | Type | Description |
| --- | --- | --- |
| `timeoutMs` | `u32` | How long to wait. 0 returns at once. |

**Returns:** `Event?`

**Errors:** `closed`

#### `Session.close`

Closes all channels with an authenticated close, then logs out. Async.

**Returns:** nothing

**Errors:** `timeout`

### `Channel`

An encrypted channel to one peer, multiplexed over their end-to-end session.

#### `Channel.send`

Sends one message. The core fragments it if needed. Async.

| Parameter | Type | Description |
| --- | --- | --- |
| `payload` | `bytes` | The plaintext message. |

**Returns:** nothing

**Errors:** `invalidArgument`, `timeout`, `closed`, `transportFailed`, `messageTooLarge`

#### `Channel.receive`

Waits for the next message. Returns nothing if the timeout passes first. Async.

| Parameter | Type | Description |
| --- | --- | --- |
| `timeoutMs` | `u32` | How long to wait. 0 returns at once. |

**Returns:** `bytes?`

**Errors:** `closed`, `transportFailed`, `messageTooLarge`

#### `Channel.info`

Returns the channel's peer, path and key epoch. Synchronous.

**Returns:** `ChannelInfo`

**Errors:** `closed`

#### `Channel.close`

Closes this channel. Other channels to the same peer stay open. Async.

**Returns:** nothing

**Errors:** `timeout`

### `ExternalTransport`

Lets an adapter own the sockets, as browsers and mobile WebRTC require. The adapter polls for commands and reports what happens. Frames are already encrypted, so the adapter never sees keys or plaintext.

#### `ExternalTransport.pollCommand`

Waits for the next command from the core. Async.

| Parameter | Type | Description |
| --- | --- | --- |
| `timeoutMs` | `u32` | How long to wait. 0 returns at once. |

**Returns:** `TransportCommand?`

**Errors:** `closed`

#### `ExternalTransport.linkOpened`

Reports that a link is up. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `linkId` | `u64` | The link. |
| `caps` | `TransportCaps` | What the link can do. |

**Returns:** nothing

**Errors:** `invalidArgument`, `closed`

#### `ExternalTransport.linkClosed`

Reports that a link has ended. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `linkId` | `u64` | The link. |

**Returns:** nothing

**Errors:** `invalidArgument`, `closed`

#### `ExternalTransport.frameReceived`

Hands the core a frame that arrived on a link. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `linkId` | `u64` | The link. |
| `frame` | `bytes` | The frame. |

**Returns:** nothing

**Errors:** `invalidArgument`, `closed`

#### `ExternalTransport.signalReceived`

Hands the core connectivity data from the platform's WebRTC stack. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `linkId` | `u64` | The link. |
| `blob` | `bytes` | Opaque SDP or ICE data. |

**Returns:** nothing

**Errors:** `invalidArgument`, `closed`

### `ServerCore`

The server side of the protocol, embedded by every host. See docs/HOST-SPI.md.

#### `ServerCore.accept`

Registers an accepted WebSocket connection and returns its identifier. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `meta` | `ConnectionMeta` | What the host knows about the connection. |

**Returns:** `u64`

**Errors:** `rateLimited`, `closed`

#### `ServerCore.onFrame`

Hands the core a frame from a connection. Returns quickly. Results surface as effects. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `connId` | `u64` | The connection. |
| `frame` | `bytes` | The frame. |

**Returns:** nothing

**Errors:** `invalidArgument`, `closed`

#### `ServerCore.onClose`

Reports that a connection has ended. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `connId` | `u64` | The connection. |

**Returns:** nothing

**Errors:** `invalidArgument`, `closed`

#### `ServerCore.tick`

Drives timers. Call this about once a second. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `nowMs` | `u64` | The current time, in milliseconds since the Unix epoch. |

**Returns:** nothing

**Errors:** `closed`

#### `ServerCore.pollEffect`

Returns the next thing the host must do, or nothing when there is no work. Synchronous.

**Returns:** `Effect?`

**Errors:** `closed`

#### `ServerCore.completeEffect`

Reports the result of a store effect. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `effectId` | `u64` | From the effect. |
| `status` | `u32` | 0 for success, otherwise an error code from this API. |
| `record` | `bytes?` | The record that was read, as JSON. |

**Returns:** nothing

**Errors:** `invalidArgument`, `closed`

#### `ServerCore.adminCall`

Runs an admin operation after the host has authenticated the caller. See docs/HOST-SPI.md. Synchronous.

| Parameter | Type | Description |
| --- | --- | --- |
| `method` | `string` | The admin method's name. |
| `paramsJson` | `string` | The parameters, as JSON. |

**Returns:** `string`

**Errors:** `invalidArgument`, `accessDenied`, `closed`, `auditUnavailable`

#### `ServerCore.health`

Returns liveness and readiness. Synchronous.

**Returns:** `HealthSnapshot`

**Errors:** none

#### `ServerCore.metrics`

Returns counters, including direct versus relayed sessions and handshake failures. Synchronous.

**Returns:** `MetricsSnapshot`

**Errors:** none

#### `ServerCore.shutdown`

Stops the core and zeroizes its secrets. Synchronous.

**Returns:** nothing

**Errors:** none

## Records

### `KeyStoreConfig`

Selects the key store. Holds references only, never key material.

| Field | Type | Description |
| --- | --- | --- |
| `kind` | `KeyStoreKind` | The kind of store. |
| `uri` | `string?` | The store's location when kind is external. |

### `SessionConfig`

Everything needed to start a client session.

| Field | Type | Description |
| --- | --- | --- |
| `serverUrl` | `string` | The host's control plane, such as wss://host/qalqon. Its host name must match the server's certificate. |
| `caBundle` | `bytes` | The trusted root certificates. |
| `keyStore` | `KeyStoreConfig` | Where this device's keys are held. |
| `dataDir` | `string?` | The directory for pins and the audit chain. Not used on web. |
| `relayPolicy` | `RelayPolicy?` | Defaults to preferDirect. |
| `identityChangePolicy` | `IdentityChangePolicy?` | Defaults to block. |
| `revocationGraceMs` | `u64?` | How long past a CRL's next update new peer sessions are still allowed. Defaults to 72 hours. This is local, and server policy cannot change it. |
| `externalTransport` | `ExternalTransport?` | Set this where the application owns the sockets, such as in a browser. Unset, the SDK uses its built-in transports. |

### `Credentials`

Login details. The secret goes only to the host, inside the Qalqon channel.

| Field | Type | Description |
| --- | --- | --- |
| `userId` | `string` | The user's identifier. |
| `secret` | `bytes` | The user's password. |
| `mfaCode` | `string?` | An MFA code, when required. |

### `EnrollmentRequest`

Registers this device with a host.

| Field | Type | Description |
| --- | --- | --- |
| `enrollmentToken` | `string` | A one-time token from the administrator. |
| `deviceName` | `string` | A human-readable device name. |

### `EnrollmentResult`

The outcome of enrolment.

| Field | Type | Description |
| --- | --- | --- |
| `deviceId` | `string` | The identifier assigned to this device. |
| `fingerprint` | `string` | This device's public fingerprint, in hex. |
| `certificateExpiresAtMs` | `u64` | When the certificate expires, in milliseconds since the Unix epoch. |

### `PeerRef`

Names a peer.

| Field | Type | Description |
| --- | --- | --- |
| `userId` | `string` | The peer's user. |
| `deviceId` | `string?` | A specific device. Unset, the host picks an online device, which the pin check still applies to. |

### `PeerIdentity`

What is known about a peer's identity.

| Field | Type | Description |
| --- | --- | --- |
| `userId` | `string` | The peer's user. |
| `deviceId` | `string` | The peer's device. |
| `fingerprint` | `string` | The peer's public fingerprint, in hex. |
| `safetyNumber` | `string` | 60 digits for both people to compare out of band. |
| `status` | `VerificationStatus` | How far this identity has been checked. |

### `ChannelOptions`

Requirements for a new channel.

| Field | Type | Description |
| --- | --- | --- |
| `label` | `string` | An application-chosen name, at most 255 bytes. |
| `ordered` | `bool` | Messages must arrive in order. |
| `reliable` | `bool` | Messages must not be lost. Fails with transportUnsupported if no transport can do this. |
| `timeoutMs` | `u32?` | How long to wait for the peer. Defaults to 30000. |

### `ChannelInfo`

The current state of a channel.

| Field | Type | Description |
| --- | --- | --- |
| `channelId` | `u16` | The channel's identifier within its session. |
| `peer` | `PeerIdentity` | The peer on the other end. |
| `path` | `PathKind` | The current path. |
| `keyEpoch` | `u16` | The current send key epoch. |

### `AuditExportRequest`

Selects audit events to export.

| Field | Type | Description |
| --- | --- | --- |
| `fromMs` | `u64?` | The start of the range. Unset, from the first event. |
| `toMs` | `u64?` | The end of the range. Unset, to the latest event. |

### `AuditExport`

A verifiable export of the local audit chain.

| Field | Type | Description |
| --- | --- | --- |
| `events` | `bytes` | The events as JSON Lines. |
| `chainHead` | `bytes` | The chain's latest entry. |
| `checkpointSignature` | `bytes` | The signed checkpoint covering chainHead. |

### `TransportCaps`

What an external link can do.

| Field | Type | Description |
| --- | --- | --- |
| `ordered` | `bool` | Frames arrive in order. |
| `reliable` | `bool` | Frames are not lost. |
| `maxFrameLen` | `u32` | The largest frame the link can carry, in bytes. |

### `ServerConfig`

Configuration a host loads and hands to the server core. Holds references only, never key material.

| Field | Type | Description |
| --- | --- | --- |
| `identityKeyRef` | `string` | A reference to the server's identity key: a file path, a PKCS#11 URI or a sealed blob. The core opens it, so the host never holds the key's bytes. |
| `caBundle` | `bytes` | The trusted root certificates. |
| `relayAddresses` | `list<string>` | The relay and TURN addresses to hand to clients. |
| `policy` | `bytes` | The initial policy document, as JSON. |

### `ConnectionMeta`

What a host knows about an accepted connection.

| Field | Type | Description |
| --- | --- | --- |
| `remoteAddress` | `string` | The peer's network address, for audit and rate limits. |

### `HealthSnapshot`

The server core's health, for a host's health endpoints.

| Field | Type | Description |
| --- | --- | --- |
| `live` | `bool` | The core is running. |
| `ready` | `bool` | Self-tests passed, the identity key is open and the stores responded. |
| `detail` | `string` | A short reason when not ready. |

### `MetricsSnapshot`

Counters for a host's metrics endpoint, in Prometheus text format.

| Field | Type | Description |
| --- | --- | --- |
| `text` | `string` | The formatted metrics. |

## Enums

### `RelayPolicy`

How a session reaches a peer.

| Value | Meaning |
| --- | --- |
| `preferDirect` | Try a direct path first and fall back to the blind relay. |
| `directOnly` | Never use the relay. Fail with peerUnreachable if no direct path exists. |
| `relayOnly` | Always use the relay. Interop tests use this to exercise the relay path. |

### `IdentityChangePolicy`

What happens when a peer's identity key differs from its pin.

| Value | Meaning |
| --- | --- |
| `block` | Refuse the session until the user re-verifies. This is the default. |
| `warn` | Raise peerIdentityChanged as an event and continue. |

### `VerificationStatus`

How far a peer's identity has been checked.

| Value | Meaning |
| --- | --- |
| `unverified` | Never seen before, so nothing is pinned yet. |
| `pinned` | Pinned on first use, and not compared out of band. |
| `verified` | The user compared the safety number out of band. |
| `changed` | The identity key differs from the pin, or this is a new device of a user who is already pinned. |

### `SessionState`

The state of a client session.

| Value | Meaning |
| --- | --- |
| `connecting` | The control plane is being established. |
| `connected` | Logged in and ready. |
| `reconnecting` | The control plane was lost and is being restored. |
| `closed` | The session has ended. |

### `PathKind`

How a channel's frames reach the peer.

| Value | Meaning |
| --- | --- |
| `direct` | Peer to peer, with no relay. |
| `relayed` | Through the blind relay, which sees only ciphertext. |

### `KeyStoreKind`

Where long-term keys are held.

| Value | Meaning |
| --- | --- |
| `osDefault` | The platform key store chosen for this target in targets.yaml. |
| `external` | A store named by a URI, such as an HSM. |

### `LinkKind`

What an external transport link connects to.

| Value | Meaning |
| --- | --- |
| `server` | The control plane connection to a host. |
| `peer` | A data plane connection to another client. |

### `Severity`

The severity of an alarm.

| Value | Meaning |
| --- | --- |
| `info` | Informational. |
| `warning` | Needs attention. |
| `critical` | A likely breach attempt or integrity failure. |

### `StoreKind`

Which Host SPI store an effect addresses.

| Value | Meaning |
| --- | --- |
| `user` | UserStore. |
| `device` | DeviceStore. |
| `policy` | PolicyStore. |
| `audit` | AuditSink. |

### `StoreOperation`

The operation a store effect requests.

| Value | Meaning |
| --- | --- |
| `get` | Read one record by key. |
| `put` | Create or replace one record. |
| `list` | Read a page of records, with the cursor in key. |
| `append` | Append one row. AuditSink only. |
| `head` | Read the latest row. AuditSink only. |
| `range` | Read rows in a range, with the bounds in key. AuditSink only. |

## Variants

### `Event`

Something a client session reports. Adapters turn these into hooks, signals, streams and so on.

| Case | Fields | Meaning |
| --- | --- | --- |
| `stateChanged` | `state: SessionState` | The session changed state. |
| `channelRequested` | `requestId: string`, `peer: PeerIdentity`, `options: ChannelOptions` | A peer wants to open a channel. Answer with acceptChannel or rejectChannel. |
| `channelOpened` | `channelId: u16` | A channel is ready. |
| `channelClosed` | `channelId: u16`, `clean: bool` | A channel ended. |
| `messageAvailable` | `channelId: u16` | A channel has a message ready for receive. |
| `peerIdentityChanged` | `peer: PeerIdentity` | A peer's identity key differs from its pin, or a pinned user presented a new device. |
| `pathChanged` | `peer: PeerRef`, `path: PathKind` | A peer's path changed. |
| `keysRotated` | `peer: PeerRef`, `epoch: u16` | Traffic keys moved to a new epoch. |
| `auditAlarm` | `severity: Severity`, `summary: string` | A possible breach attempt was detected. |

### `TransportCommand`

Something the core asks an external transport to do.

| Case | Fields | Meaning |
| --- | --- | --- |
| `openLink` | `linkId: u64`, `kind: LinkKind`, `url: string?` | Open a link. |
| `sendFrame` | `linkId: u64`, `frame: bytes` | Send a frame on a link. |
| `sendSignal` | `linkId: u64`, `blob: bytes` | Deliver connectivity data from the core to the platform's WebRTC stack. |
| `closeLink` | `linkId: u64` | Close a link. |

### `Effect`

Something the server core asks a host to do. See docs/HOST-SPI.md.

| Case | Fields | Meaning |
| --- | --- | --- |
| `sendFrame` | `connId: u64`, `frame: bytes` | Send a frame on a connection. No completion is needed. |
| `closeConnection` | `connId: u64`, `code: u16` | Close a connection. No completion is needed. |
| `store` | `effectId: u64`, `store: StoreKind`, `operation: StoreOperation`, `key: string?`, `record: bytes?` | Perform a store operation, then call completeEffect. |
| `alarm` | `severity: Severity`, `summary: string` | Raise an alarm to the security administrator. No completion is needed. |

## Error codes

| Code | Name | Meaning |
| --- | --- | --- |
| 0 | `ok` | Success. Never raised as an error. |
| 1 | `invalidArgument` | An argument is malformed or out of range. |
| 2 | `invalidState` | The call is not valid in the object's current state. |
| 3 | `timeout` | The operation did not finish in time. |
| 4 | `closed` | The session or channel is closed. |
| 5 | `unsupported` | This build or platform does not support the operation. |
| 6 | `internal` | An internal fault. A panic inside the core surfaces as this code. |
| 100 | `transportFailed` | The transport could not connect or was lost. |
| 101 | `transportUnsupported` | No available transport can satisfy the requested channel options. |
| 102 | `peerUnavailable` | The peer is offline, declined, or hidden by policy. These cases are deliberately not distinguished. |
| 103 | `peerUnreachable` | No path to the peer exists under the current relay policy. |
| 104 | `messageTooLarge` | The message exceeds the reassembly limit. |
| 200 | `handshakeFailed` | The handshake failed. The cause is deliberately not distinguished here; the local audit log records it. |
| 201 | `versionMismatch` | The two sides share no protocol version. |
| 202 | `suiteMismatch` | The two sides share no cipher suite. |
| 203 | `peerIdentityChanged` | The peer's identity key differs from its pin, or a user who is already pinned presented a new device. |
| 204 | `peerRevoked` | The peer's certificate is revoked or expired. |
| 205 | `revocationDataStale` | The local CRL is too old to allow a new session. |
| 300 | `authenticationFailed` | Login failed. Unknown user and wrong secret are deliberately not distinguished. |
| 301 | `mfaRequired` | Login needs an MFA code. Retry with mfaCode set. |
| 302 | `rateLimited` | Too many attempts. Try again later. |
| 303 | `accessDenied` | Policy denies this operation. |
| 304 | `notEnrolled` | This device has no valid certificate. Call enrollDevice first. |
| 305 | `enrollmentRejected` | The enrolment token was rejected. |
| 400 | `keyStoreUnavailable` | The platform key store cannot be reached. |
| 401 | `selfTestFailed` | A known-answer self-test failed at module load, so the module refuses to operate. |
| 402 | `integrityCheckFailed` | A binary does not match the signed manifest. |
| 500 | `auditUnavailable` | The audit log cannot be written, so the audited operation was refused. |
