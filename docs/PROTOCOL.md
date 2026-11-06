# Qalqon Protocol

`PROTOCOL_VERSION` 0.1, draft v0.

**Status: draft, implemented in `core/qalqon-core` against the test-only provider.** Nothing here has run with the certified library. An AI-assisted review of an earlier version found defects, which are fixed here, and `formal/` holds a symbolic model of the handshake, but no human cryptographer has reviewed it. The wire format freezes at Phase 2, and major version 0 makes no compatibility promise.

## 1. Scope

Qalqon is an authenticated, encrypted channel over byte frames. It runs between a client and a server (the control plane) and directly between two clients (the data plane). Both planes use the same handshake and record layer.

The key words MUST, MUST NOT, SHOULD and MAY are used as in BCP 14 (RFC 2119 and RFC 8174). A `§` refers to the build prompt in `CLAUDE.md`, and "section" refers to this document.

### What the build prompt fixes and what this draft proposes

| Fixed by the build prompt (§1.1, §3) | Proposed here, for approval |
| --- | --- |
| Header fields: `magic`, `version`, `suite_id`, `msg_type`, `channel_id` u16, `seq` u64, `length` u16 | Widths of the first four fields and all code points |
| TLV extensions | The extension layout and registry |
| XX-style first contact, IK-style 1-RTT when the peer is known | The exact messages. **This draft replaces IK with an option on the XX handshake**, explained below |
| O'z DSt 1092 signatures over the 1106 transcript hash | The context strings and transcript layout |
| HKDF-1106 key schedule with per-direction labels | The labels and the order of derivation |
| Per-direction keys, 64-bit sequence plus direction in the nonce | Splitting `seq` into a key epoch and a counter that never restarts |
| Rekey at the first of 2^32 records, 1 GiB or 1 hour; 1024-entry replay window; authenticated close | The inner plaintext format, key retention times, channel control messages and retry rules |
| Offline root and online issuing CA, short validity, CRL endpoint, safety numbers | The certificate format, per-user pins and the safety number derivation |

**The companion specification may already settle items in the right column.** It is not in this repository, and §3 says to ask for it rather than guess. These proposals must be reconciled with it before the freeze.

### Why there is no separate IK handshake

The build prompt asks for an IK-style 1-RTT handshake when the peer is known. An earlier version of this draft had one, but IK's two messages cannot meet the first MUST in §1.1, which binds both endpoints' signatures to the full transcript. I's signature would go out in the first message, before R has contributed anything. Anyone who later learned that one ephemeral secret could replay the first message, complete the key exchange and impersonate I until its certificate expired.

So I's signature has to follow R's message, which is the XX flow. All that remains of IK is skipping R's certificate when I already has it. Section 8 does this as an option on XX, much as TLS does with cached information (RFC 7924). I's first data still goes out after one round trip, there is only one handshake to prove, and devices need no second long-term key.

**This departs from the prompt's wording and needs your approval.**

### Why this is "Noise-style", not Noise

The message pattern follows Noise XX. Noise authenticates with static Diffie-Hellman, but O'z DSt 1092 is a signature scheme, so authentication here follows SIGMA-I (Krawczyk, CRYPTO 2003) and the TLS 1.3 handshake (RFC 8446). Noise's security analysis therefore does not carry over, and the handshake must be proved by the formal model in `formal/` (section 15).

## 2. Conventions

- Integers are big-endian. `||` is concatenation.
- `vec8` and `vec16` are byte strings prefixed by a `u8` or `u16` length.
- `H` is the O'z DSt 1106 hash, with output `HashLen` and internal block `HashBlockLen`, in bytes.
- `HMAC` is RFC 2104 over `H`. `HKDF-Extract` and `HKDF-Expand` are RFC 5869 over that `HMAC`.
- `Sign` and `Verify` are O'z DSt 1092.
- `HashLen`, `KeyLen`, `BlockLen` and `SigLen` come from `docs/crypto-inventory.md`. This draft requires `HashLen >= 32` and `BlockLen >= 16`.
- `ctx(name)` is `"qalqon0 " || name || 0x00`. It separates every signature and chained hash by purpose, so a value made for one purpose cannot be reused for another.

## 3. Roles and session lifecycle

For each session one side is the initiator (I) and the other the responder (R). On the control plane the client is I and the server is R. On the data plane the client that requested the rendezvous is I.

| Key | Purpose | Lifetime |
| --- | --- | --- |
| Identity key | O'z DSt 1092 signing key, named in the certificate | Long-term, held by the key store |
| Ephemeral key | One handshake | R zeroizes it once `hs` is derived. I zeroizes it once `XX_RESP` has verified or the handshake has failed, so a spoofed message cannot destroy it |

The session sequence below is **reconstructed**. The diagram it comes from is missing from the design document, which only says that steps 1-7 use client-to-server channels and steps 8-10 use the direct path. Please check it against the original.

| Step | Plane | What happens |
| --- | --- | --- |
| 1 | Control | A opens `wss://host/qalqon` over platform TLS and completes a Qalqon handshake with the server |
| 2 | Control | A logs in. `server-core` evaluates policy and writes an audit row |
| 3 | Control | B does the same |
| 4 | Control | A sends `RENDEZVOUS_OPEN`, naming B |
| 5 | Control | `server-core` checks policy, writes an audit row and delivers `RENDEZVOUS_INCOMING` to B |
| 6 | Control | B replies `RENDEZVOUS_ACCEPT`, and A receives `RENDEZVOUS_READY` |
| 7 | Control | A and B exchange connectivity data in `PEER_SIGNAL` |
| 8 | Data | A transport comes up directly, or through the blind relay if NAT traversal fails |
| 9 | Data | A and B run a Qalqon handshake and check certificates, revocation and pins |
| 10 | Data | A and B exchange records, including rekeys |
| 11 | Both | Either side sends an authenticated `CLOSE`, and both sides write audit rows |

## 4. Cipher suites

A `suite_id` names one complete combination. There is no separate negotiation of parts, and no suite without encryption or without authentication. ECB cannot be expressed.

| `kex_id` | Component | Share sent by I | Share sent by R |
| --- | --- | --- | --- |
| `0x0001` | `nat`: the national component from ADR-0001 | Public value or KEM key | Public value or KEM ciphertext |
| `0x0002` | X25519 | 32 bytes | 32 bytes |
| `0x0003` | ML-KEM-768 | 1,184-byte encapsulation key | 1,088-byte ciphertext |

| `suite_id` (provisional) | Key agreement | Record protection | Hash | Signature |
| --- | --- | --- | --- | --- |
| `0x0000` | Reserved: "not selected yet". Valid only in `XX_INIT`, in its fragments and in `HS_REJECT` | | | |
| `0x0101` | `nat` + X25519 | R | 1106 | 1092 |
| `0x0102` | `nat` + X25519 + ML-KEM-768 | R | 1106 | 1092 |

`suite_id` values from `0xFF00` to `0xFFFF` are for tests and are never offered by a release build, so a test build can never negotiate with a real one. `0xFF01` is X25519, and `0xFF02` is X25519 + ML-KEM-768. Both use AES-256-CTR with HMAC-SHA-256 (section 9.2), SHA-256 and Ed25519, and are provided by `core/provider-testonly`.

`R` is the one record protection method chosen from the inventory: the library's AEAD mode if it has one, otherwise CTR or gamma with HMAC-1106 (section 9.2). A build MUST NOT offer two record protection methods. Final suite values are assigned when ADR-0001 and the inventory are complete.

## 5. Wire format

### 5.1 Header

Every frame starts with this 18-byte header.

| Offset | Size | Field | Value |
| --- | --- | --- | --- |
| 0 | 2 | `magic` | `0x51 0x4C` ("QL") |
| 2 | 1 | `version` | High nibble major, low nibble minor. `0x01` is 0.1 |
| 3 | 2 | `suite_id` | Section 4 |
| 5 | 1 | `msg_type` | Section 5.2 |
| 6 | 2 | `channel_id` | 0 for handshake messages. Section 9.6 for records |
| 8 | 8 | `seq` | 0 for handshake messages. Section 9.3 for records |
| 16 | 2 | `length` | Bytes following the header |

`hdr16(M)` means the first 16 bytes of M's header, which is everything except `length`. Transcripts use `hdr16` because `length` depends on the signature and MAC sizes. The full header is still authenticated as AEAD associated data.

A frame with the wrong `magic`, an unknown `msg_type`, or trailing bytes after `length` is invalid. Invalid frames are dropped on lossy transports and close the session on strict ones (section 5.3).

### 5.2 Message types

| `msg_type` | Name | Direction |
| --- | --- | --- |
| `0x01` | `XX_INIT` | I to R |
| `0x02` | `XX_RESP` | R to I |
| `0x03` | `XX_FINISH` | I to R |
| `0x04` | `HS_REJECT` | R to I, unauthenticated (section 13) |
| `0x05` | `HS_FRAGMENT` | Either (section 5.5) |
| `0x10` | `RECORD` | Either (section 9) |

### 5.3 Transport mapping

| Transport | Framing |
| --- | --- |
| TCP, QUIC stream | Frames are concatenated and split using `length` |
| WebSocket | One frame per binary message |
| UDP, WebRTC DataChannel | One frame per datagram or message |
| Relay | The relay forwards frames without parsing them |

A transport adapter declares whether it is ordered, whether it is reliable, and its maximum frame size. This document calls a transport **strict** if it is both ordered and reliable, and **lossy** otherwise. A reliable but unordered DataChannel counts as lossy, because a retransmission can arrive later than the replay window allows.

### 5.4 Extensions

An extension is `u16 type`, `u16 length`, then the value. Extensions appear in ascending `type` order without duplicates, so each set has one encoding. Bit 15 of `type` marks it critical: an unknown critical extension fails the handshake, and an unknown non-critical one is ignored. Both remain in the transcript.

| `type` | Name | Value | Sent in |
| --- | --- | --- | --- |
| `0x0003` | `padding` | Zero bytes | Any clear handshake body |
| `0x0004` | `known_responder` | 16 bytes (section 8) | `XX_INIT` |
| `0x8001` | `session_role` | `u8`: 1 control plane, 2 data plane | `XX_INIT` |
| `0x8002` | `rendezvous_id` | 16 bytes | `XX_INIT` on the data plane |

R MUST reject a `session_role` that does not match its own role.

On the data plane, R MUST silently drop a first message whose `rendezvous_id` it did not receive from `server-core`, which stops strangers from probing for its certificate. The ID is in the clear, so these limits apply:

- An ID expires 120 seconds after the client receives it.
- R runs at most 4 handshakes at once per ID.
- The first handshake to complete consumes the ID. Any others are abandoned and later first messages are dropped, so a replay cannot replace a live session.

### 5.5 Handshake fragmentation and reliability

If a handshake message exceeds the transport's frame size, it is split into `HS_FRAGMENT` frames with this body:

```
u8  inner_msg_type;
u16 total_len;
u16 offset;
opaque fragment[...];
```

Each fragment's header carries the `suite_id` of the message it belongs to. The reassembled message takes that header with `msg_type = inner_msg_type` and `length = total_len`, and transcripts and associated data always use the reassembled form. A fragment is invalid if it runs past `total_len`, changes `total_len`, or overlaps earlier data with different bytes. A receiver buffers at most 32 KiB per handshake.

On lossy transports, flights are retransmitted as in DTLS 1.3 (RFC 9147, section 5.8), starting at 500 ms and doubling, with a 30-second overall limit:

- I repeats `XX_INIT` until `XX_RESP` arrives, and repeats `XX_FINISH` until any valid record arrives from R.
- R answers a duplicate `XX_INIT` by repeating its stored `XX_RESP`, without signing again.
- R answers a duplicate `XX_FINISH` with a new `KEY_CONFIRM` record, at most once per second.

Strict transports do not retransmit.

To limit amplification on datagram transports, I MUST pad its first message to at least 1,200 bytes, and R MUST NOT send more than 3 times the bytes it has received until the handshake completes (RFC 9000, sections 8.1 and 14.1).

## 6. Key schedule

The schedule follows RFC 8446, section 7.1.

```
HKDF-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)

HkdfLabel = u16(Length) || vec8("qalqon0 " || Label) || vec8(Context)

Derive-Secret(Secret, Label, Transcript) =
    HKDF-Expand-Label(Secret, Label, H(Transcript), HashLen)

salt0 = H(ctx("salt"))
```

The label prefix contains the major version, so different majors can never share keys.

**Key agreement input.** `ee` is the shared secrets of the selected suite's components, concatenated in ascending `kex_id` order (ADR-0001). For a KEM component, I's share is a fresh encapsulation key, and R encapsulates to it and returns the ciphertext.

**Keys from a traffic secret.** For a traffic secret `S`:

```
key = HKDF-Expand-Label(S, "key", "", KeyLen)
iv  = HKDF-Expand-Label(S, "iv",  "", IvLen)
mac = HKDF-Expand-Label(S, "mac", "", HashLen)        // only for section 9.2
fin = HKDF-Expand-Label(S, "finished", "", HashLen)   // only for handshake secrets
```

Secrets labelled `i` protect I-to-R traffic, and secrets labelled `r` protect R-to-I traffic. All secrets MUST be zeroized when no longer needed.

## 7. The handshake

```
Initiator                                          Responder

XX_INIT    random, offers, shares   ------->
                                                   hs = Extract(salt0, ee)
           <-------   XX_RESP  random, shares, {chain_r, sig_r, mac_r}
hs = Extract(salt0, ee)
XX_FINISH  {chain_i, sig_i, mac_i}  ------->
           <-------   RECORD {KEY_CONFIRM}
           <=======    records    =======>

{ } means encrypted under the handshake keys for that direction.
```

### 7.1 Messages

```
struct KeyShare { u16 kex_id; vec16 data; }

XX_INIT body:
    opaque random[32];
    vec8   versions;     // version bytes, most preferred first
    vec8   suites;       // u16 suite ids, most preferred first
    vec16  shares;       // KeyShare list covering every offered suite
    vec16  extensions;

XX_RESP clear part:
    opaque random[32];
    vec16  shares;       // KeyShare list for the selected suite
    vec16  extensions;

XX_RESP encrypted part (under r_hs):
    vec16  chain_r;      // empty if section 8 applies
    vec16  sig_r;
    opaque mac_r[HashLen];

XX_FINISH encrypted part (under i_hs):
    vec16  chain_i;
    vec16  sig_i;
    opaque mac_i[HashLen];
```

The `XX_INIT` header carries I's highest offered version and `suite_id` 0. The `XX_RESP` header carries R's selection, and every later frame repeats it. There is no retry message, so `XX_INIT` already contains shares for everything it offers. I MUST abort if the selection is not in its offers.

The encrypted parts use `seq` 0, the keys from their handshake secret, and associated data of the full header followed by any clear part.

### 7.2 Transcript and derivations

```
T1 = hdr16(XX_INIT) || XX_INIT body
T2 = T1 || hdr16(XX_RESP) || XX_RESP clear part
T3 = T2 || vec16(chain_r)      // always the full chain, even if omitted on the wire
T4 = T3 || vec16(sig_r)
T5 = T4 || mac_r
T6 = T5 || hdr16(XX_FINISH) || vec16(chain_i)
T7 = T6 || vec16(sig_i)
T8 = T7 || mac_i

hs   = HKDF-Extract(salt0, ee)
i_hs = Derive-Secret(hs, "i hs", T2)
r_hs = Derive-Secret(hs, "r hs", T2)

sig_r = Sign(identity_r, ctx("responder signature") || H(T3))
mac_r = HMAC(fin of r_hs, H(T4))
sig_i = Sign(identity_i, ctx("initiator signature") || H(T6))
mac_i = HMAC(fin of i_hs, H(T7))

ms     = HKDF-Extract(Derive-Secret(hs, "derived", ""), zeros(HashLen))
i_ap_0 = Derive-Secret(ms, "i ap", T8)
r_ap_0 = Derive-Secret(ms, "r ap", T8)
session_id = HKDF-Expand-Label(ms, "session id", H(T8), 16)
```

`session_id` is safe to log, and both sides use it to correlate audit rows.

### 7.3 Processing

I processes `XX_RESP` in this order, and R processes `XX_FINISH` in the same way:

1. Derive the keys and open the encrypted part.
2. Validate the peer's chain (section 11.3), without changing any pin.
3. Verify the signature and the MAC.
4. Apply the pin check (section 11.4). A first-contact pin is committed only now.

**Failures are uniform on the wire.** Nothing the peer receives reveals which check failed. Locally, the SDK reports `handshakeFailed`, except for `peerIdentityChanged`, `peerRevoked` and `revocationDataStale`, which the user has to act on. The detail goes to the local audit log.

On a strict transport any failure ends the handshake. On a lossy transport a message that fails to open or verify is ignored, because it may be spoofed, and the handshake fails only when the timer expires, with the last failure's local reason.

I MAY send records immediately after `XX_FINISH`, so I's first data goes out after one round trip. R MUST NOT accept records or send any until it has verified `XX_FINISH`. R MUST then send a `KEY_CONFIRM` record, which tells I that R holds the same transcript and lets I stop retransmitting.

## 8. Known peers: omitting the responder's certificate

If I holds R's chain from an earlier successful handshake with this peer, it MAY add `known_responder` to `XX_INIT`, using its own `random` from that message:

```
known_responder = first 16 bytes of H(random || H(chain_r))
```

Mixing in `random` means a passive observer cannot link sessions to the same responder by this value.

R recomputes this value for its current chain. If it matches, R sends `chain_r` as an empty field in `XX_RESP`. If it does not match, R sends its chain as usual and the handshake continues, so there is no fallback and no extra round trip. Everything else in section 7 is unchanged, and the transcript contains the full chain in both cases.

- I MUST validate its cached chain on every use, as in section 11.3, including expiry and revocation.
- I MUST treat an empty `chain_r` as a failure if it did not send `known_responder`.
- A chain received from a server during rendezvous MUST NOT be used for this. It has to come from a completed handshake.

## 9. Record layer

### 9.1 Record format

A record is the header, with `msg_type` `RECORD`, followed by the ciphertext and tag. `length` is the ciphertext length plus `TagLen`. The associated data is the full 18-byte header.

The nonce is the direction and sequence number, left-padded with zeros to `IvLen` and XORed with `iv`:

```
nonce = iv XOR pad(direction || seq)     // direction: 0x00 I-to-R, 0x01 R-to-I
```

`IvLen` MUST be at least 12 bytes.

### 9.2 Record protection without a library AEAD

If the library has an AEAD mode, it is used directly, and `TagLen` is its tag length. Otherwise records use encrypt-then-MAC with independent keys and `TagLen = HashLen`:

```
ciphertext = CTR-or-gamma(key, nonce, plaintext)
tag = HMAC(mac, u64(len(nonce)) || nonce || u64(len(aad)) || aad || ciphertext)
```

The nonce is authenticated because a true AEAD binds its nonce, and a composition that replaces one has to behave the same way.

For CTR, `IvLen = BlockLen - 4`, and each counter block is `nonce || u32(block_index)` with `block_index` starting at 0. A record is at most 65,535 bytes, so `block_index` cannot wrap. Gamma mode's IV format comes from the inventory. Tags are not truncated. A receiver MUST verify the tag in constant time before decrypting.

### 9.3 Sequence numbers and epochs

```
seq = (epoch << 48) | counter     // epoch: 16 bits, counter: 48 bits
```

The split follows DTLS 1.2 (RFC 6347), with one difference: **`counter` runs for the whole session and does not restart at a rekey.** A deleted record therefore shows up as a gap, even across an epoch change, and one replay window is enough for each direction.

Each direction has its own sequence space, shared across all channels, because all channels in a session use the same traffic keys. A per-channel sequence would reuse nonces. When either field would overflow, the session MUST be replaced by a new handshake.

### 9.4 Receiving a record

1. Check the header, including `version` and `suite_id`.
2. Find the key for `epoch`.
   - Strict: the current epoch only. The receiver moves to the next epoch when it opens `KEY_UPDATE`, so an epoch change without one is rejected.
   - Lossy: the current epoch, an earlier one during its retention time, or up to 16 epochs ahead.
3. Check `counter`.
   - Strict: it must be exactly the next one.
   - Lossy: reject it if it is older than the 1,024-entry window or already seen.
4. Open the record.
5. Only after that succeeds, update the replay window and commit any new epoch.

A failed record closes a strict session with a generic error. On a lossy session it is dropped and counted, and it is never fatal. The peer never learns which step failed.

### 9.5 Rekeying

A sender rotates its own direction before reaching any of these limits in an epoch, including while idle: 2^32 records, 2^30 bytes of plaintext, or 3,600 seconds. It needs no cooperation from the peer. To rotate, it sends `KEY_UPDATE` as its last record under the old keys, moves to the next epoch, and zeroizes the old secret and keys at once.

```
S_next = HKDF-Expand-Label(S, "traffic upd", "", HashLen)
```

On a strict transport the receiver moves when it opens `KEY_UPDATE`, and keeps no old keys. On a lossy transport `KEY_UPDATE` can be lost or overtaken, so the receiver derives forward when it first sees a later epoch and commits only after a record opens. It keeps earlier receive keys for at most 30 seconds. A receiver MAY close a session whose peer exceeds twice a record or byte limit in one epoch.

`KEY_UPDATE` with `update_requested = 1` also asks the peer to rotate. The peer rotates and sends `KEY_UPDATE` with `update_requested = 0`, which needs no reply, so requests cannot loop. A peer serves at most one request per second and defers the rest rather than dropping them, so that repeated requests combine into one rotation. `rotateKeys` sends such a request, and completes when the peer's epoch has advanced.

Rekeying protects earlier traffic if a current key leaks, once the old keys are erased. It does not recover from a compromise, because later keys follow from the current secret. Recovering requires a new handshake.

### 9.6 Inner plaintext

The first byte of a record's plaintext is `inner_type`. The header's `channel_id` is the channel's ID for `DATA` and `CHANNEL_*` records, and 0 for all others.

| `inner_type` | Name | Body |
| --- | --- | --- |
| `0x01` | `DATA` | `u32 message_id; u16 fragment_index; u8 flags` (bit 0: last fragment), then payload |
| `0x02` | `KEY_UPDATE` | `u8 update_requested` |
| `0x03` | `KEY_CONFIRM` | Empty |
| `0x04` | `CHANNEL_OPEN` | `u8 ordered; u8 reliable; vec8 label` |
| `0x05` | `CHANNEL_ACCEPT` | Empty |
| `0x06` | `CHANNEL_REJECT` | `u16 reason` |
| `0x07` | `CHANNEL_CLOSE` | `u16 reason` |
| `0x08` | `PING` | 8 random bytes |
| `0x09` | `PONG` | The same 8 bytes |
| `0x0A` | `CLOSE` | `u16 reason` |
| `0x20` | `CONTROL` | Section 12. Control plane only |

`reason` is one of: 0 `normal`, 1 `protocol_error`, 2 `transport_unsupported`, 3 `message_too_large`, 4 `rejected`, 5 `timeout`, 6 `internal_error`.

A channel's messages are numbered from 0 by `message_id`. An application message larger than one record is split into `DATA` fragments. Reassembly is limited to 16 MiB per message and 64 MiB per session by default, and partial messages on unordered channels time out after 30 seconds.

### 9.7 Authenticated close

A side finishing a session sends `CLOSE`, then zeroizes its send keys. On a strict transport the receiver replies with `CLOSE` and zeroizes its keys. On a lossy transport there is no reply: the sender sends `CLOSE` three times, 200 ms apart and with new sequence numbers, before zeroizing.

If the transport ends without a valid `CLOSE`, or a peer stops answering `PING`, the SDK reports an unclean closure, so an application can detect truncation. Each SDK chooses its own `PING` interval.

### 9.8 Control records on lossy transports

Records can be lost on a lossy transport, so a sender repeats these on the timers in section 5.5, each time as a new record with a new sequence number. After 30 seconds it gives up and reports `timeout`.

| Record | Repeated until | The receiver |
| --- | --- | --- |
| `CHANNEL_OPEN` | `CHANNEL_ACCEPT` or `CHANNEL_REJECT` arrives | Answers a duplicate with the same reply |
| `CHANNEL_CLOSE` | `CHANNEL_CLOSE` arrives for that channel | Answers a duplicate with `CHANNEL_CLOSE` |
| `KEY_UPDATE` with `update_requested = 1` | The peer's epoch advances | Treats it as in section 9.5. Each repeat rotates the sender again, because `KEY_UPDATE` is always the last record under its keys |

A lost `KEY_UPDATE` with `update_requested = 0` needs no repeat, because the first record of the next epoch has the same effect.

## 10. Channels

Channel 0 is the session's control channel and always exists. Application channels use IDs from 1 to 65,535: I allocates odd IDs and R allocates even ones, so the two sides never collide. `channel_id` is in the clear but authenticated.

A channel is opened with `CHANNEL_OPEN` and answered with `CHANNEL_ACCEPT` or `CHANNEL_REJECT`. The core does not retransmit application data, so a channel that requires `reliable` on a lossy transport is rejected with `transportUnsupported`. On a lossy transport, `ordered` is provided by `message_id`: a message older than the last one delivered is discarded, so order is kept and some messages can be lost.

## 11. Certificates and trust

### 11.1 Hierarchy

An offline root signs an online issuing CA, which signs device and server certificates. Proposed default validity is 10 years for the root, 1 year for the issuing CA and 30 days for leaf certificates.

### 11.2 Format (open decision)

The certificate format is a stop-and-ask choice, and it depends on whether the library supports X.509. Without it, the proposal is a small TLV format using the extension rules from section 5.4, which is easy to parse safely without an OS or in WebAssembly:

```
Certificate:
    vec16 tbs;
    vec16 signature;    // Sign(issuer, ctx("certificate") || H(tbs))

tbs extensions, in ascending type order:
    0x8001 format_version   u8
    0x8002 serial           16 bytes
    0x8003 role             u8: 1 root, 2 issuing, 3 server, 4 device, 5 pre-enrolment
    0x8004 subject          vec8 a, vec8 b:
                              role 3: host name, server instance
                              role 4: user_id, device_id
                              roles 1, 2: name, empty
                              role 5: both empty
    0x8005 not_before       u64, milliseconds since the Unix epoch
    0x8006 not_after        u64
    0x8007 sign_public      u16 algorithm, vec16 key
    0x8008 issuer_key_id    16 bytes: first 16 bytes of H(issuer's sign_public key)
```

An encoded chain is its certificates concatenated, leaf first. `sign_public` hashes in fingerprints and key IDs cover the whole encoded value, `u16 algorithm, vec16 key`. Signature algorithm `0xFF01` is Ed25519 in the test-only range, and a build accepts only its own provider's algorithm.

### 11.3 Validating a peer's chain

A chain has exactly two certificates: the leaf, then the issuing CA's certificate. The one exception is a pre-enrolment chain, which is a single self-signed certificate. The root comes from the local CA bundle and is never accepted from the wire.

1. **Shape and signatures.** The leaf's `issuer_key_id` names the issuing certificate, which has role 2, and whose `issuer_key_id` names a role 1 root in the CA bundle. Verify both signatures. Reject any other shape, so a device certificate can never act as a CA.
2. **Times.** Every certificate is within its validity period.
3. **Role.** On the control plane, R is role 3, and I is role 4, or role 5 for enrolment. On the data plane, both are role 4.
4. **Subject.**
   - On the control plane, I checks the host name in R's subject against the host in `serverUrl`.
   - On the control plane, R checks at login: `user_id` in `LOGIN_REQUEST` must equal the certificate's, otherwise login fails with `authenticationFailed`.
   - On the data plane, both sides check the subject against the user, and any device, named at rendezvous.
5. **Revocation.** Section 11.5.
6. **Pin, on the data plane only.** Section 11.4, after the signature and MAC have verified (section 7.3). Servers are not pinned: the CA and host name identify them, and the end-to-end guarantees never rely on trusting a server.

### 11.4 Fingerprints, pins and safety numbers

```
fingerprint = H(ctx("fingerprint") || sign_public)
```

A fingerprint covers the identity key alone, so it survives certificate renewal.

**Pins are per user.** On first contact with a user, a client pins that device: `user_id -> { device_id -> fingerprint }`. A later handshake fails with `peerIdentityChanged` in either of these cases:

- The device's fingerprint differs from its pin.
- The device is new, and that user already has a pin.

The default policy blocks until the user re-verifies with a safety number, and the new device then joins the user's pins. The pin store is local to the device, and the server has no access to it.

New devices have to count as a change because the server assigns device IDs and can choose which device a call reaches. Otherwise it could route a call to a device it invented, and no pin would ever be consulted.

**Safety numbers** let two people compare identities out of band:

```
a, b = the two fingerprints, sorted bytewise
okm  = HKDF-Expand-Label(HKDF-Extract(salt0, a || b), "safety", "", 60)
```

Each 5 bytes of `okm`, read as an integer modulo 100,000, gives one 5-digit group, for 60 digits in total. Both sides compute the same number.

**What this does against a malicious server.** A server authorises enrolment, so it can obtain a valid certificate for any user, even if the issuing CA runs separately. The CA therefore does not stop a malicious server. Pins and safety numbers do. A substitution against a user you already know is blocked by the pin check. A substitution at first contact is detected only if the two people compare safety numbers, so **first contact without comparison is exposed**. Key transparency is out of scope for this version.

### 11.5 Revocation

The issuing CA signs a CRL containing `issuer_key_id`, `this_update`, `next_update` (at most 24 hours later) and the revoked serials: `Sign(issuing CA, ctx("crl") || H(crl body))`. On the wire it is `vec16 body; vec16 signature`, and the body is `opaque issuer_key_id[16]; u64 this_update; u64 next_update; vec16 serials`, where `serials` is 16-byte values with no separators. Clients fetch it over the control plane when connecting and before `next_update`, and cache it.

- **No rollback.** A client MUST reject a CRL older than its cached one, by `this_update`.
- **Fail closed.** A server can withhold a CRL but cannot forge one, so a missing CRL counts as stale. New data-plane sessions fail with `revocationDataStale` once `next_update` is further in the past than `revocationGraceMs` allows (default 72 hours). That setting is local to the client, and server policy cannot change it.
- **First connection.** A client with no CRL yet may complete the control-plane handshake. It MUST then fetch the CRL at once, and close if the server's certificate is listed.
- **Live sessions.** When a new CRL lists the peer of a live session, the client closes that session with `peerRevoked`.

Revoking the issuing CA itself means replacing the CA bundle, because no CRL covers it in this version.

### 11.6 Enrolment

Every channel requires both endpoints to authenticate, including during enrolment. A new device generates its identity key and uses a self-signed certificate with role 5 in an ordinary handshake. `server-core` restricts such a session to `ENROLL_REQUEST` and `CRL_REQUEST`. Clients MUST refuse this role on the data plane. The server issues the real certificate after checking the one-time enrolment token, and the device then reconnects with it.

## 12. Control plane messages

Control messages are `CONTROL` records on channel 0 of a client-to-server session. The body is `u16 control_type`, then fields encoded as extensions (section 5.4). A control message MUST fit in one record.

| `control_type` | Message | Direction | Fields |
| --- | --- | --- | --- |
| `0x0001` | `ENROLL_REQUEST` | C to S | `token`, `device_name` |
| `0x0002` | `ENROLL_RESULT` | S to C | `status`, `chain` on success |
| `0x0003` | `LOGIN_REQUEST` | C to S | `user_id`, `secret`, optional `mfa_code` |
| `0x0004` | `LOGIN_RESULT` | S to C | `status`, optional `retry_after_ms` |
| `0x0005` | `RENDEZVOUS_OPEN` | C to S | `request_id`, `user_id`, optional `device_id`, `channel_options` |
| `0x0006` | `RENDEZVOUS_INCOMING` | S to C | `request_id`, `rendezvous_id`, `user_id`, `device_id`, `chain`, `channel_options`, `relay_grants` |
| `0x0007` | `RENDEZVOUS_ACCEPT` | C to S | `request_id` |
| `0x0008` | `RENDEZVOUS_REJECT` | Either | `request_id` |
| `0x0009` | `RENDEZVOUS_READY` | S to C | `request_id`, `rendezvous_id`, `chain`, `relay_grants` |
| `0x000A` | `PEER_SIGNAL` | Either | `rendezvous_id`, `blob` |
| `0x000B` | `CRL_REQUEST` | C to S | `issuer_key_id` |
| `0x000C` | `CRL_RESPONSE` | S to C | `crl` |
| `0x000D` | `CERT_RENEW_REQUEST` | C to S | None |
| `0x000E` | `CERT_RENEW_RESULT` | S to C | `status`, `chain` on success |
| `0x000F` | `SESSION_REPORT` | C to S | `session_id`, `path`, `counters` |

| `type` | Field | Value |
| --- | --- | --- |
| `0x8101` | `request_id` | 16 bytes |
| `0x8102` | `rendezvous_id` | 16 bytes |
| `0x8103` | `status` | `u16`, an error code from the IDL |
| `0x8104` | `token` | Bytes |
| `0x8105` | `device_name` | UTF-8 |
| `0x8106` | `user_id` | UTF-8 |
| `0x0107` | `device_id` | UTF-8. Non-critical because it is optional in a request |
| `0x8108` | `secret` | Bytes. Never logged |
| `0x0109` | `mfa_code` | UTF-8 |
| `0x010A` | `retry_after_ms` | `u32` |
| `0x810B` | `chain` | Bytes |
| `0x810C` | `channel_options` | `u8 ordered; u8 reliable; vec8 label` |
| `0x810D` | `relay_grants` | Repeated: `vec8 address; vec8 token; u64 expires_at` |
| `0x810E` | `blob` | Bytes: opaque SDP and ICE data |
| `0x810F` | `issuer_key_id` | 16 bytes |
| `0x8110` | `crl` | Bytes |
| `0x8111` | `session_id` | 16 bytes |
| `0x8112` | `path` | `u8`: 1 direct, 2 relayed |
| `0x8113` | `counters` | `u64 records; u64 bytes` |

Both sides of a rendezvous receive `relay_grants`, because either may need the relay. A grant's token is short-lived, and relays forward frames while holding no keys.

`RENDEZVOUS_REJECT` does not say whether a peer is offline, declined or hidden by policy, so a client cannot probe for users.

A `chain` in a rendezvous message is only a hint for showing who is calling. It is never trusted: the handshake authenticates the peer's own chain, and section 8 refuses to use it.

`SESSION_REPORT` is self-reported, so it feeds metrics and never feeds security decisions.

### 12.1 Relay grants

A relay checks a grant with a key it shares with the server, and it holds no session keys. A client's first message to a relay is `opaque rendezvous_id[16]; vec8 token`, and the relay pairs the two clients that present a valid token for the same ID, then forwards frames unchanged.

```
token = u64(expires_at) || HMAC(relay_key, "qalqon0 relay grant" || 0x00 || rendezvous_id || u64(expires_at))
```

## 13. Handshake rejection

`HS_REJECT` has the body `u16 code; opaque echo_random[32]`. The codes are 1 `unsupported_version`, 2 `unsupported_suite` and 3 `busy`. `echo_random` repeats `random` from the `XX_INIT` being rejected, and I ignores a rejection whose echo does not match, so an off-path attacker cannot forge one.

An on-path attacker still can, because it is unauthenticated. A client MUST NOT weaken its offers in response. The only permitted reaction is to fail the attempt.

## 14. Audit chain

```
entry_0 = H(ctx("audit genesis") || fingerprint)
entry_n = H(ctx("audit") || entry_(n-1) || canonical(event_n))
```

An endpoint periodically signs a checkpoint: `Sign(identity, ctx("audit checkpoint") || u64(n) || entry_n)`. `exportAudit` returns the events, the chain head and the latest checkpoint. The event schema, its canonical encoding and the event list from §1.6 are specified with `core/qalqon-audit` in Phase 1.

## 15. Security properties for the formal model

The ProVerif models in `formal/` check these, against an attacker who controls the network and the server. See `formal/README.md`.

1. **Secrecy** of `i_ap_*` and `r_ap_*`.
2. **Forward secrecy:** compromising identity keys after a session does not reveal its traffic keys.
3. **Hybrid secrecy:** secrets hold while any one key agreement component is sound.
4. **Mutual injective agreement** on the transcript, roles and identities. R reaches it on verifying `XX_FINISH`, and I on opening R's `KEY_CONFIRM`.
5. **No impersonation from a leaked ephemeral:** learning one session's ephemeral secret does not let an attacker impersonate that party in any other session. Whoever holds a session's ephemeral can forge that session's `KEY_CONFIRM`, because it is protected only by that session's keys, so item 4's guarantee to I does not hold for a session whose ephemeral leaked. I still knows that R signed the transcript.
6. **Downgrade resistance:** both sides agree on the version, the suite and I's full offer, including `known_responder`.
7. **No identity misbinding** and no key compromise impersonation.
8. **Rekey forward secrecy:** a leak in one epoch does not reveal any epoch whose keys have already been erased. A receiver's retained keys on a lossy transport are not yet erased, so they are excluded for up to 30 seconds.
9. **Record integrity on strict transports:** an insertion, deletion, replay or reordering is always detected, and truncation is always reported as an unclean closure. This one is covered by tests, not by the model.
10. **Server substitution:** for a user already pinned, a certificate the server obtained for a new device or a changed key cannot establish a channel without triggering `peerIdentityChanged`.

Identity hiding is a design goal but is not one of the required lemmas. I's identity is encrypted under forward-secret keys and sent only after R has authenticated. R's identity is exposed to an active attacker who can reach it with a valid `rendezvous_id`.

## 16. Test vectors

`tools/vectors` generates deterministic JSON vectors from the Rust reference, with randomness injected, into `tests/conformance`. They cover `HKDF-Expand-Label`, the key schedule, the handshake byte for byte with and without `known_responder`, record seal and open, replay and epoch handling, and negative cases that every binding must reject.

Today's vectors are in `tests/conformance/testonly` and come from the test-only provider.

## 17. Not in this version

- A two-message handshake, and 0-RTT data (section 1 explains why)
- Session resumption
- Hiding lengths, `channel_id` or timing from an observer
- Group or multi-party channels
- Post-compromise recovery without a new handshake
- Cross-signing of new devices, and key transparency

## 18. Open decisions

| Decision | Depends on |
| --- | --- |
| Replace IK with section 8, as explained in section 1 | Your approval, because the prompt asks for IK |
| Make every new device of a known user block until re-verified, or add cross-signing so an existing device can vouch for a new one | Your choice. Blocking is simple and safe, but each contact has to re-verify whenever someone adds a device |
| Reconcile this draft with the companion specification | You supplying that document |
| Certificate format: TLV or X.509 | Library facts, your choice |
| Final `suite_id` values and whether ML-KEM-768 ships in the first release | ADR-0001 |
| The session sequence in section 3 | The missing diagram |
| A CRL must fit in one control record, about 4,000 revocations | Whether large deployments need paging. Short certificate validity keeps the list small |
| Handshake state tables | Not written. `core/qalqon-core/src/session.rs` is the only statement of them so far |
