# Qalqon Protocol

`PROTOCOL_VERSION` 0.1, draft v0.

**Status: proposal for the Phase 0 gate.** Nothing here is implemented, formally modelled or reviewed by an outside cryptographer. The wire format freezes at Phase 2, and major version 0 makes no compatibility promise.

## 1. Scope

Qalqon is an authenticated, encrypted channel over byte frames. It runs between a client and a server (the control plane) and directly between two clients (the data plane). Both planes use the same handshake and record layer.

The key words MUST, MUST NOT, SHOULD and MAY are used as in BCP 14 (RFC 2119 and RFC 8174).

### What the build prompt fixes and what this draft proposes

| Fixed by the build prompt (§1.1, §3) | Proposed here, for approval |
| --- | --- |
| Header fields: `magic`, `version`, `suite_id`, `msg_type`, `channel_id` u16, `seq` u64, `length` u16 | Widths of the first four fields and all code points |
| TLV extensions | The extension layout and registry |
| XX-style first contact, IK-style 1-RTT when the peer is known | The exact messages, and a static key-agreement key for IK |
| O'z DSt 1092 signatures over the 1106 transcript hash | The context strings and transcript layout |
| HKDF-1106 key schedule with per-direction labels | The labels and the order of derivation |
| Per-direction keys, 64-bit sequence plus direction in the nonce | Splitting `seq` into a key epoch and a counter |
| Rekey at the first of 2^32 records, 1 GiB or 1 hour; 1024-entry replay window; authenticated close | The inner plaintext format, key retention times and channel control messages |
| Offline root and online issuing CA, short validity, CRL endpoint, safety numbers | The certificate format and the safety number derivation |

**The companion specification may already settle items in the right column.** It is not in this repository, and rule 3 of the build prompt says to ask for it rather than guess. These proposals must be reconciled with it before the freeze.

### Why this is "Noise-style", not Noise

The message patterns follow Noise XX and IK. Noise authenticates with static Diffie-Hellman, but O'z DSt 1092 is a signature scheme, so authentication here follows SIGMA-I (Krawczyk, CRYPTO 2003) and the TLS 1.3 handshake (RFC 8446). Noise's security analysis therefore does not carry over, and the handshake as a whole must be proved by the formal model in `formal/` (section 15).

## 2. Conventions

- Integers are big-endian. `||` is concatenation.
- `vec8` and `vec16` are byte strings prefixed by a `u8` or `u16` length.
- `H` is the O'z DSt 1106 hash, with output `HashLen` and internal block `HashBlockLen`, in bytes.
- `HMAC` is RFC 2104 over `H`. `HKDF-Extract` and `HKDF-Expand` are RFC 5869 over that `HMAC`.
- `Sign` and `Verify` are O'z DSt 1092.
- `HashLen`, `KeyLen`, `BlockLen` and `SigLen` come from `docs/crypto-inventory.md`. This draft requires `HashLen >= 32` and `BlockLen >= 16`.

## 3. Roles and session lifecycle

For each session one side is the initiator (I) and the other the responder (R). On the control plane the client is I and the server is R. On the data plane the client that requested the rendezvous is I.

| Key | Purpose | Lifetime |
| --- | --- | --- |
| Identity key | O'z DSt 1092 signing key, named in the device certificate | Long-term, held by the key store |
| Static key-agreement key | Lets a device be an IK responder | Long-term, certified, never the same as the identity key |
| Ephemeral key | One handshake | Zeroized as soon as the handshake secret is derived |

The session sequence below is **reconstructed**. The diagram it comes from is missing from the design document, which only says that steps 1-7 use client-to-server channels and steps 8-10 use the direct path. Please check it against the original.

| Step | Plane | What happens |
| --- | --- | --- |
| 1 | Control | A opens `wss://host/qalqon` over platform TLS and completes a Qalqon handshake with the server |
| 2 | Control | A logs in. `server-core` evaluates policy and writes an audit row |
| 3 | Control | B does the same |
| 4 | Control | A sends `RENDEZVOUS_OPEN`, naming B |
| 5 | Control | `server-core` checks policy, writes an audit row and delivers `RENDEZVOUS_INCOMING` to B |
| 6 | Control | B replies `RENDEZVOUS_ACCEPT`, and A receives `RENDEZVOUS_READY` with B's certificate chain |
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
| `0x0000` | Reserved: "not selected yet", valid only in the `XX_INIT` header | | | |
| `0x0101` | `nat` + X25519 | R | 1106 | 1092 |
| `0x0102` | `nat` + X25519 + ML-KEM-768 | R | 1106 | 1092 |

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
| 6 | 2 | `channel_id` | 0 for handshake messages. Section 10 for records |
| 8 | 8 | `seq` | 0 for handshake messages. Section 9.3 for records |
| 16 | 2 | `length` | Bytes following the header |

`hdr16(M)` means the first 16 bytes of M's header, which is everything except `length`. Transcripts use `hdr16` because `length` depends on the signature and MAC sizes. The full header is still authenticated as AEAD associated data.

A frame with the wrong `magic`, an unknown `msg_type`, or trailing bytes after `length` is invalid. Invalid frames are dropped on datagram transports and close the session on stream transports.

### 5.2 Message types

| `msg_type` | Name | Direction |
| --- | --- | --- |
| `0x01` | `XX_INIT` | I to R |
| `0x02` | `XX_RESP` | R to I |
| `0x03` | `XX_FINISH` | I to R |
| `0x04` | `IK_INIT` | I to R |
| `0x05` | `IK_RESP` | R to I |
| `0x06` | `HS_REJECT` | R to I, unauthenticated (section 13) |
| `0x07` | `HS_FRAGMENT` | Either (section 5.5) |
| `0x10` | `RECORD` | Either (section 9) |

### 5.3 Transport mapping

| Transport | Framing |
| --- | --- |
| TCP, QUIC stream | Frames are concatenated and split using `length` |
| WebSocket | One frame per binary message |
| UDP, WebRTC DataChannel | One frame per datagram or message |
| Relay | The relay forwards frames without parsing them |

A transport adapter declares whether it is ordered, whether it is reliable, and its maximum frame size.

### 5.4 Extensions

An extension is `u16 type`, `u16 length`, then the value. Extensions appear in ascending `type` order without duplicates, so each set has one encoding. Bit 15 of `type` marks it critical: an unknown critical extension fails the handshake, and an unknown non-critical one is ignored. Both remain in the transcript.

| `type` | Name | Value | Sent in |
| --- | --- | --- | --- |
| `0x0003` | `padding` | Zero bytes | Any clear handshake body |
| `0x8001` | `session_role` | `u8`: 1 control plane, 2 data plane | `XX_INIT`, `IK_INIT` |
| `0x8002` | `rendezvous_id` | 16 bytes | `XX_INIT`, `IK_INIT` on the data plane |

R MUST reject a `session_role` that does not match its own role. On the data plane, R MUST silently drop a first message whose `rendezvous_id` it did not receive from `server-core`. This stops strangers from probing for its certificate.

### 5.5 Handshake fragmentation and reliability

If a handshake message exceeds the transport's frame size, it is split into `HS_FRAGMENT` frames with this body:

```
u8  inner_msg_type;
u16 total_len;
u16 offset;
opaque fragment[...];
```

Transcripts and associated data always use the reassembled message. A receiver buffers at most 32 KiB per handshake.

On unreliable transports, flights are retransmitted as in DTLS 1.3 (RFC 9147, section 5.8), starting at 500 ms and doubling, with a 30-second overall limit. A retransmission repeats the same bytes. I repeats `XX_FINISH` until it receives a valid record from R. Reliable transports do not retransmit.

To limit amplification on datagram transports, I MUST pad its first message to at least 1,200 bytes, and R MUST NOT send more than 3 times the bytes it has received until the handshake completes (RFC 9000, sections 8.1 and 14.1).

## 6. Key schedule

The schedule follows RFC 8446, section 7.1.

```
HKDF-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)

HkdfLabel = u16(Length) || vec8("qalqon0 " || Label) || vec8(Context)

Derive-Secret(Secret, Label, Transcript) =
    HKDF-Expand-Label(Secret, Label, H(Transcript), HashLen)

salt0 = H("qalqon0 salt")
```

The label prefix contains the major version, so different majors can never share keys.

**Key agreement input.** `ee` is the shared secrets of the selected suite's components, concatenated in ascending `kex_id` order (ADR-0001), using the two sides' ephemeral shares. `es` is the same combination using I's ephemeral share and R's static key-agreement key.

**Keys from a traffic secret.** For a traffic secret `S`:

```
key = HKDF-Expand-Label(S, "key", "", KeyLen)
iv  = HKDF-Expand-Label(S, "iv",  "", IvLen)
mac = HKDF-Expand-Label(S, "mac", "", HashLen)        // only for section 9.2
fin = HKDF-Expand-Label(S, "finished", "", HashLen)   // only for handshake secrets
```

Secrets labelled `i` protect I-to-R traffic, and secrets labelled `r` protect R-to-I traffic. All secrets MUST be zeroized when no longer needed.

**Signature input.** Each signature covers a context string that prevents reuse in another role:

```
ctx(role) = "qalqon0 " || role || " signature" || 0x00
```

## 7. XX-style handshake (first contact)

```
Initiator                                          Responder

XX_INIT    random, offers, shares   ------->
                                                   hs = Extract(salt0, ee)
           <-------   XX_RESP  random, shares, {chain_r, sig_r, mac_r}
hs = Extract(salt0, ee)
XX_FINISH  {chain_i, sig_i, mac_i}  ------->
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
    vec16  chain_r;
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
T3 = T2 || vec16(chain_r)
T4 = T3 || vec16(sig_r)
T5 = T4 || mac_r
T6 = T5 || hdr16(XX_FINISH) || vec16(chain_i)
T7 = T6 || vec16(sig_i)
T8 = T7 || mac_i

hs   = HKDF-Extract(salt0, ee)
i_hs = Derive-Secret(hs, "i hs", T2)
r_hs = Derive-Secret(hs, "r hs", T2)

sig_r = Sign(identity_r, ctx("responder") || H(T3))
mac_r = HMAC(fin of r_hs, H(T4))
sig_i = Sign(identity_i, ctx("initiator") || H(T6))
mac_i = HMAC(fin of i_hs, H(T7))

ms     = HKDF-Extract(Derive-Secret(hs, "derived", ""), zeros(HashLen))
i_ap_0 = Derive-Secret(ms, "i ap", T8)
r_ap_0 = Derive-Secret(ms, "r ap", T8)
session_id = HKDF-Expand-Label(ms, "session id", H(T8), 16)
```

`session_id` is safe to log, and both sides use it to correlate audit rows.

### 7.3 Processing

I processes `XX_RESP` by deriving keys, opening the encrypted part, validating `chain_r` (section 11.3), then verifying `sig_r` and `mac_r`. R processes `XX_FINISH` the same way. Any failure after key agreement is `handshakeFailed`. It sends nothing that reveals which check failed, and the detail goes only to the local audit log.

I MAY send records immediately after `XX_FINISH`. R MUST NOT accept records or send any until it has verified `XX_FINISH`. R MUST then send a `KEY_CONFIRM` record, which tells I that R holds the same transcript and lets I stop retransmitting.

## 8. IK-style handshake (peer already known)

I already holds R's certificate from an earlier XX handshake or from rendezvous, and that certificate contains a static key-agreement key. The handshake finishes in one round trip.

```
Initiator                                          Responder

IK_INIT    random, key_id, shares,  ------->
           {chain_i, sig_i}                        hs = Extract(.., ee)
           <-------   IK_RESP  random, shares, {sig_r, mac_r}
RECORD     {KEY_CONFIRM}            ------->
           <=======    records    =======>
```

### 8.1 Messages

```
IK_INIT clear part:
    opaque random[32];
    opaque responder_key_id[16];   // first 16 bytes of H(R's leaf certificate)
    vec16  shares;                 // ephemeral shares for the suite in the header, plus
                                   // a ciphertext to R's static key for any KEM component
    vec16  extensions;

IK_INIT encrypted part (under i_ik):
    vec16  chain_i;
    vec16  sig_i;

IK_RESP clear part:
    opaque random[32];
    vec16  shares;
    vec16  extensions;

IK_RESP encrypted part (under r_hs):
    vec16  sig_r;
    opaque mac_r[HashLen];
```

### 8.2 Transcript and derivations

```
ck   = HKDF-Extract(salt0, es)

T1   = hdr16(IK_INIT) || IK_INIT clear part
i_ik = Derive-Secret(ck, "i ik", T1)
T2   = T1 || vec16(chain_i)
sig_i = Sign(identity_i, ctx("initiator") || H(T2))
T3   = T2 || vec16(sig_i)

T4   = T3 || hdr16(IK_RESP) || IK_RESP clear part
hs   = HKDF-Extract(Derive-Secret(ck, "derived", ""), ee)
r_hs = Derive-Secret(hs, "r hs", T4)
sig_r = Sign(identity_r, ctx("responder") || H(T4))
T5   = T4 || vec16(sig_r)
mac_r = HMAC(fin of r_hs, H(T5))
T6   = T5 || mac_r

ms     = HKDF-Extract(Derive-Secret(hs, "derived", ""), zeros(HashLen))
i_ap_0 = Derive-Secret(ms, "i ap", T6)
r_ap_0 = Derive-Secret(ms, "r ap", T6)
session_id = HKDF-Expand-Label(ms, "session id", H(T6), 16)
```

### 8.3 Replay and key confirmation

`IK_INIT` can be replayed, because it contains no contribution from R. A replay gets nowhere without I's ephemeral secret, but R has not yet proved I is present. So:

- I MUST send a `KEY_CONFIRM` record immediately after verifying `IK_RESP`. On unreliable transports it repeats this with a new sequence number, using the timers in section 5.5, until it receives a valid record from R.
- R MUST NOT report the session as established, act on I's identity, or send application data until it has opened a valid record from I. R MUST then reply with its own `KEY_CONFIRM`.

### 8.4 Fallback to XX

If R does not recognise `responder_key_id`, it sends `HS_REJECT` with code `unknown_key`, and I starts again with `XX_INIT`. An attacker can force this by forging the rejection. That costs I's identity some protection from active attackers, but not authentication, because the XX handshake still checks the pin. An IK-to-XX fallback MUST be written to the audit log. A changed identity key is then detected by the pin check in section 11.4.

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
tag = HMAC(mac, u64(len(aad)) || aad || ciphertext)
```

For CTR, `IvLen = BlockLen - 4`, and each counter block is `nonce || u32(block_index)` with `block_index` starting at 0. A record is at most 65,535 bytes, so `block_index` cannot wrap. Gamma mode's IV format comes from the inventory. Tags are not truncated. A receiver MUST verify the tag in constant time before decrypting.

### 9.3 Sequence numbers and epochs

```
seq = (epoch << 48) | counter     // epoch: 16 bits, counter: 48 bits
```

This is the same split as DTLS 1.2 (RFC 6347). Each direction has its own sequence space, shared across all channels, because all channels in a session use the same traffic keys. Using a per-channel sequence would reuse nonces. `counter` starts at 0 in each epoch and is never reused. When epoch 65,535 is exhausted, the session MUST be replaced by a new handshake.

### 9.4 Receiving a record

1. Check the header, including `version` and `suite_id`.
2. Find the key for `epoch`: the current epoch, the next one, or the previous one during its retention time. Anything else is rejected.
3. On an ordered and reliable transport, require exactly the next `counter`. On any other transport, reject a `counter` that is older than the 1,024-entry window or already seen.
4. Open the record.
5. Only after that succeeds, update the replay window and commit any new epoch.

A failed record is dropped on unreliable transports and counted in metrics. On reliable transports it is fatal, and the session closes with a generic error. The peer never learns which step failed.

### 9.5 Rekeying

A sender moves its own direction to the next epoch before reaching any of these limits: 2^32 records, 2^30 bytes of plaintext, or 3,600 seconds in the epoch. It needs no cooperation from the peer.

```
S_next = HKDF-Expand-Label(S, "traffic upd", "", HashLen)
```

`S` and the keys derived from it are zeroized at once on the sending side. A receiver derives the next epoch's keys when it first sees that epoch, and commits only after a record opens successfully. It keeps the previous receive keys for at most 30 seconds on unordered transports, and not at all on ordered ones. A receiver MAY close a session whose peer exceeds twice a record or byte limit in one epoch.

`rotateKeys` moves the local direction and sends `KEY_UPDATE` with `update_requested = 1`, asking the peer to do the same. A peer honours such a request at most once per second.

Rekeying protects earlier traffic if a current key leaks. It does not recover from a compromise, because later keys follow from the current secret. Recovering requires a new handshake.

### 9.6 Inner plaintext

The first byte of a record's plaintext is `inner_type`.

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

An application message larger than one record is split into `DATA` fragments. Reassembly is limited to 16 MiB per message and 64 MiB per session by default, and partial messages on unordered channels time out after 30 seconds.

### 9.7 Authenticated close

A side finishing a session sends `CLOSE`, then zeroizes its send keys. The receiver replies with `CLOSE` and zeroizes its keys. If the transport ends without a `CLOSE`, the SDK reports an unclean closure, so an application can detect truncation.

## 10. Channels

Channel 0 is the session's control channel and always exists. Application channels use IDs from 1 to 65,535: I allocates odd IDs and R allocates even ones, so the two sides never collide. `channel_id` is in the clear but authenticated.

A channel is opened with `CHANNEL_OPEN` and answered with `CHANNEL_ACCEPT` or `CHANNEL_REJECT`. The core does not retransmit, so a channel that requires `reliable` over an unreliable transport is rejected with `transportUnsupported`.

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
    0x0009 kex_static       KeyShare list, present only if the device accepts IK
    0x8001 format_version   u8
    0x8002 serial           16 bytes
    0x8003 role             u8: 1 root, 2 issuing, 3 server, 4 device, 5 pre-enrolment
    0x8004 subject          vec8 user_id, vec8 device_id
    0x8005 not_before       u64, milliseconds since the Unix epoch
    0x8006 not_after        u64
    0x8007 sign_public      u16 algorithm, vec16 key
    0x8008 issuer_key_id    16 bytes
```

A `chain` is the leaf certificate followed by the issuing CA's certificate. The root comes from the local CA bundle and is never accepted from the wire.

### 11.3 Validating a peer's chain

1. Check the signatures up to a root in the CA bundle.
2. Check validity times and that the role fits the plane.
3. Check that the subject matches the identity expected from rendezvous or login.
4. Check the serial against the CRL (section 11.5).
5. Apply the pin check (section 11.4).

### 11.4 Fingerprints, pins and safety numbers

```
fingerprint = H("qalqon0 fingerprint" || 0x00 || sign_public)
```

A fingerprint covers the identity key alone, so it survives certificate renewal. On first contact a client pins `(user_id, device_id) -> fingerprint`. If a later handshake shows a different fingerprint, the session fails with `peerIdentityChanged`, and the default policy blocks until the user re-verifies. The pin store is local to the device, and the server has no access to it.

A safety number lets two people compare identities out of band:

```
a, b = the two fingerprints, sorted bytewise
okm  = HKDF-Expand-Label(HKDF-Extract(salt0, a || b), "safety", "", 60)
```

Each 5 bytes of `okm`, read as an integer modulo 100,000, gives one 5-digit group, for 60 digits in total. Both sides compute the same number.

**Malicious server limits.** A server cannot read or alter data-plane traffic without a valid certificate for the peer. If the same party runs the issuing CA, it could issue one and attack a first contact. Pins detect a later substitution, and only safety numbers detect one at first contact. Operators SHOULD run the issuing CA separately from hosts. Key transparency is out of scope for this version.

### 11.5 Revocation

The issuing CA signs a CRL containing `issuer_key_id`, `this_update`, `next_update` (at most 24 hours later) and the revoked serials. Clients fetch it over the control plane and cache it. A server can withhold a CRL but cannot forge one, so a client MUST refuse new data-plane sessions with `revocationDataStale` once its CRL is more than 72 hours past `next_update`, unless policy says otherwise.

### 11.6 Enrolment

Each channel requires both endpoints to authenticate, including during enrolment. A new device generates its identity key and uses a self-signed certificate with role `pre-enrolment` in an ordinary handshake. `server-core` restricts such a session to `ENROLL_REQUEST` and `CRL_REQUEST`. Clients MUST refuse this role on the data plane. The server issues the real certificate after checking the one-time enrolment token.

## 12. Control plane messages

Control messages are `CONTROL` records on channel 0 of a client-to-server session. The body is `u16 control_type`, then fields encoded as extensions (section 5.4).

| `control_type` | Message | Direction | Fields |
| --- | --- | --- | --- |
| `0x0001` | `ENROLL_REQUEST` | C to S | Token, device name |
| `0x0002` | `ENROLL_RESULT` | S to C | Status, chain |
| `0x0003` | `LOGIN_REQUEST` | C to S | User ID, secret, optional MFA code |
| `0x0004` | `LOGIN_RESULT` | S to C | Status, retry-after |
| `0x0005` | `RENDEZVOUS_OPEN` | C to S | Request ID, peer user, optional peer device, label |
| `0x0006` | `RENDEZVOUS_INCOMING` | S to C | Request ID, `rendezvous_id`, caller, caller's chain |
| `0x0007` | `RENDEZVOUS_ACCEPT` | C to S | Request ID |
| `0x0008` | `RENDEZVOUS_REJECT` | Either | Request ID, reason |
| `0x0009` | `RENDEZVOUS_READY` | S to C | Request ID, `rendezvous_id`, peer's chain, relay grants |
| `0x000A` | `PEER_SIGNAL` | Either | `rendezvous_id`, opaque blob (SDP, ICE candidates) |
| `0x000B` | `CRL_REQUEST` | C to S | Issuer key ID |
| `0x000C` | `CRL_RESPONSE` | S to C | CRL |
| `0x000D` | `CERT_RENEW_REQUEST` | C to S | None |
| `0x000E` | `CERT_RENEW_RESULT` | S to C | Status, chain |
| `0x000F` | `SESSION_REPORT` | C to S | `session_id`, path (direct or relayed), counters |

`RENDEZVOUS_REJECT` does not say whether a peer is offline, declined or hidden by policy, so a client cannot probe for users. A relay grant contains a relay address, a short-lived token and an expiry. Relays forward frames and hold no keys. `SESSION_REPORT` is self-reported, so it feeds metrics and never feeds security decisions.

## 13. Handshake rejection

`HS_REJECT` has the body `u16 code`: 1 `unsupported_version`, 2 `unsupported_suite`, 3 `unknown_key`, 4 `busy`.

It is unauthenticated, so anyone can forge it. A client MUST NOT weaken its offers in response. The only permitted reaction other than failing is the IK-to-XX fallback in section 8.4.

## 14. Audit chain

```
entry_0 = H(ctx("audit genesis") || fingerprint)
entry_n = H(ctx("audit") || entry_(n-1) || canonical(event_n))
```

An endpoint periodically signs a checkpoint: `Sign(identity, ctx("audit checkpoint") || u64(n) || entry_n)`. `exportAudit` returns the events, the chain head and the latest checkpoint. The event schema, its canonical encoding and the event list from build prompt §1.6 are specified with `core/qalqon-audit` in Phase 1.

## 15. Security properties for the formal model

The Tamarin or ProVerif model in `formal/` must prove these for both handshakes, against an attacker who controls the network and the server:

1. **Secrecy** of `i_ap_*` and `r_ap_*`.
2. **Forward secrecy:** compromising identity and static keys after a session does not reveal its traffic keys.
3. **Hybrid secrecy:** secrets hold while any one key agreement component is sound.
4. **Mutual injective agreement** on the transcript, roles and identities. In XX, R reaches it on verifying `XX_FINISH`, and I on opening R's `KEY_CONFIRM`. In IK, I reaches it on verifying `IK_RESP`, and R on opening I's `KEY_CONFIRM`.
5. **Downgrade resistance:** both sides agree on the version, the suite and I's full offer.
6. **No identity misbinding** and no key compromise impersonation.
7. **Rekey forward secrecy:** a leak in epoch n does not reveal any earlier epoch.

Identity hiding is a design goal but is not one of the required lemmas. XX exposes R's identity to an active attacker who can reach it with a valid `rendezvous_id`. IK exposes I's identity if R's static key later leaks.

## 16. Test vectors

`tools/vectors` generates deterministic JSON vectors from the Rust reference, with randomness injected, into `tests/conformance`. They cover `HKDF-Expand-Label`, the key schedule, both handshakes byte for byte, record seal and open, replay and epoch handling, and negative cases that every binding must reject.

## 17. Not in this version

- 0-RTT data and session resumption
- Hiding lengths, `channel_id` or timing from an observer
- Group or multi-party channels
- Post-compromise recovery without a new handshake
- Key transparency

## 18. Open decisions

| Decision | Depends on |
| --- | --- |
| Reconcile this draft with the companion specification | You supplying that document |
| Certificate format: TLV or X.509 | Library facts, your choice |
| Final `suite_id` values and whether ML-KEM-768 ships in the first release | ADR-0001 |
| Whether IK stays, given that it needs a second long-term key per device | Your choice. Without IK, a known peer connects with XX, which takes one more message and resends certificates but needs no extra key |
| The session sequence in section 3 | The missing diagram |
| Handshake state tables | Written with the formal model in Phase 1 |
