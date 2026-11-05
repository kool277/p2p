//! The handshake: `docs/PROTOCOL.md`, sections 7 and 8. These functions are pure
//! steps over one message each. `session.rs` adds retransmission and failure policy.

use crate::cert::{CertError, ValidatedChain, validate_chain};
use crate::error::{ErrorCode, HandshakeFailure};
use crate::schedule::{
    ApplicationSecrets, TrafficKeys, application_secrets, ctx, derive_secret, finished_key,
    record_nonce, salt0, traffic_keys,
};
use crate::session::{PeerInfo, PeerRejection, Plane, SessionConfig};
use crate::wire::{
    Extension, HEADER_LEN, Header, Reader, Writer, encode_extensions, ext, find_extension, msg,
    parse_extensions, parse_frame, reject,
};
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use crypto_provider::suite::{SUITE_NONE, suite_kex};
use crypto_provider::{CryptoProvider, Secret, Zeroizing, ct_eq};

/// I pads its first message to at least this size on datagram transports.
const MIN_FIRST_FRAME: usize = 1200;
const RANDOM_LEN: usize = 32;

const DIRECTION_I_TO_R: u8 = 0;
const DIRECTION_R_TO_I: u8 = 1;

fn generic<T>(detail: &'static str) -> impl FnOnce(T) -> HandshakeFailure {
    move |_| HandshakeFailure::generic(detail)
}

/// What a finished handshake hands to the session.
pub(crate) struct Completed {
    pub version: u8,
    pub suite: u16,
    pub secrets: ApplicationSecrets,
    pub peer: PeerInfo,
    /// I's `XX_FINISH`, which still has to go out.
    pub finish_frame: Option<Vec<u8>>,
}

fn transcript_hash_with(p: &dyn CryptoProvider, context: &str, transcript: &[u8]) -> Vec<u8> {
    let mut input = ctx(context);
    input.extend_from_slice(&p.hash(transcript));
    input
}

fn validate_peer(
    cfg: &mut SessionConfig,
    raw_chain: &[u8],
    now_ms: u64,
) -> Result<ValidatedChain, HandshakeFailure> {
    let validated = validate_chain(
        cfg.provider.as_ref(),
        &cfg.roots,
        raw_chain,
        now_ms,
        cfg.plane,
        &cfg.expectation,
    )
    .map_err(|e| match e {
        CertError::Expired => HandshakeFailure {
            code: ErrorCode::PeerRevoked,
            detail: "a certificate is outside its validity period",
        },
        CertError::Malformed => HandshakeFailure::generic("malformed certificate chain"),
        CertError::Signature => HandshakeFailure::generic("certificate chain does not verify"),
        CertError::Role => HandshakeFailure::generic("certificate role or chain shape not allowed"),
        CertError::Subject => {
            HandshakeFailure::generic("certificate subject is not the expected peer")
        }
        CertError::Crypto(_) => HandshakeFailure::generic("certificate check failed"),
    })?;
    cfg.verifier
        .check_revocation(&validated, now_ms)
        .map_err(rejection)?;
    Ok(validated)
}

fn rejection(r: PeerRejection) -> HandshakeFailure {
    match r {
        PeerRejection::Revoked => HandshakeFailure {
            code: ErrorCode::PeerRevoked,
            detail: "the certificate is revoked",
        },
        PeerRejection::RevocationStale => HandshakeFailure {
            code: ErrorCode::RevocationDataStale,
            detail: "the cached CRL is missing or too old",
        },
        PeerRejection::IdentityChanged => HandshakeFailure {
            code: ErrorCode::PeerIdentityChanged,
            detail: "the identity differs from the pin, or this is a new device of a pinned user",
        },
        PeerRejection::Other(detail) => HandshakeFailure::generic(detail),
    }
}

fn peer_info(
    validated: &ValidatedChain,
    chain: &[u8],
    status: crate::session::PinStatus,
) -> PeerInfo {
    let fields = &validated.leaf.fields;
    PeerInfo {
        role: fields.role,
        subject_a: fields.subject_a.clone(),
        subject_b: fields.subject_b.clone(),
        serial: fields.serial,
        not_after: fields.not_after,
        fingerprint: validated.fingerprint.clone(),
        chain: chain.to_vec(),
        status,
    }
}

fn parse_key_shares(raw: &[u8]) -> Result<Vec<(u16, &[u8])>, HandshakeFailure> {
    let mut r = Reader::new(raw);
    let mut out: Vec<(u16, &[u8])> = Vec::new();
    while !r.is_empty() {
        let id = r.u16().map_err(generic("malformed key share"))?;
        let data = r.vec16().map_err(generic("malformed key share"))?;
        if out.last().is_some_and(|(last, _)| *last >= id) {
            return Err(HandshakeFailure::generic("key shares out of order"));
        }
        out.push((id, data));
    }
    Ok(out)
}

fn check_critical(extensions: &[Extension<'_>], known: &[u16]) -> Result<(), HandshakeFailure> {
    for e in extensions {
        if e.is_critical() && !known.contains(&e.ty) {
            return Err(HandshakeFailure::generic("unknown critical extension"));
        }
    }
    Ok(())
}

fn known_responder_value(p: &dyn CryptoProvider, random: &[u8], chain: &[u8]) -> Vec<u8> {
    let mut input = random.to_vec();
    input.extend_from_slice(&p.hash(chain));
    let mut hash = p.hash(&input);
    hash.truncate(16);
    hash
}

fn seal_encrypted_part(
    p: &dyn CryptoProvider,
    keys: &TrafficKeys,
    direction: u8,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, HandshakeFailure> {
    let nonce = record_nonce(&keys.iv, direction, 0);
    p.aead_seal(&keys.aead, &nonce, aad, plaintext)
        .map_err(generic("sealing a handshake message failed"))
}

fn open_encrypted_part(
    p: &dyn CryptoProvider,
    keys: &TrafficKeys,
    direction: u8,
    aad: &[u8],
    sealed: &[u8],
) -> Result<Secret, HandshakeFailure> {
    let nonce = record_nonce(&keys.iv, direction, 0);
    p.aead_open(&keys.aead, &nonce, aad, sealed)
        .map_err(generic("a handshake message did not open"))
}

/// `(chain, signature, mac)`, the encrypted part of `XX_RESP` and `XX_FINISH`.
fn parse_encrypted_part(
    plain: &[u8],
    hash_len: usize,
) -> Result<(&[u8], &[u8], &[u8]), HandshakeFailure> {
    let bad = "malformed encrypted handshake fields";
    let mut r = Reader::new(plain);
    let chain = r.vec16().map_err(generic(bad))?;
    let signature = r.vec16().map_err(generic(bad))?;
    let mac = r.take(hash_len).map_err(generic(bad))?;
    r.finish().map_err(generic(bad))?;
    Ok((chain, signature, mac))
}

fn encode_encrypted_part(
    chain: &[u8],
    signature: &[u8],
    mac: &[u8],
) -> Result<Vec<u8>, HandshakeFailure> {
    let bad = "a handshake field is too long";
    let mut w = Writer::new();
    w.vec16(chain).map_err(generic(bad))?;
    w.vec16(signature).map_err(generic(bad))?;
    w.bytes(mac);
    Ok(w.buf)
}

fn extract_hs(p: &dyn CryptoProvider, ee: &[u8]) -> Secret {
    p.hkdf_extract(&salt0(p), ee)
}

// ---------------------------------------------------------------------- initiator

/// The initiator between `XX_INIT` and a verified `XX_RESP`. The ephemeral secrets
/// stay here until `XX_RESP` has verified, so a spoofed message cannot destroy them.
pub(crate) struct Initiator {
    random: [u8; RANDOM_LEN],
    ephemeral: Vec<(u16, Secret)>,
    versions: Vec<u8>,
    suites: Vec<u16>,
    t1: Vec<u8>,
    init_frame: Vec<u8>,
    sent_known_responder: bool,
}

/// Creates `XX_INIT`.
pub(crate) fn start(cfg: &SessionConfig) -> Result<Initiator, HandshakeFailure> {
    let p = cfg.provider.as_ref();
    let mut random = [0u8; RANDOM_LEN];
    p.random(&mut random)
        .map_err(generic("the random source failed"))?;

    if cfg.versions.is_empty() || cfg.suites.is_empty() {
        return Err(HandshakeFailure {
            code: ErrorCode::InvalidArgument,
            detail: "no versions or suites to offer",
        });
    }

    // One share for each component of each offered suite.
    let mut kex_ids: Vec<u16> = Vec::new();
    for suite in &cfg.suites {
        let kex = suite_kex(*suite).ok_or(HandshakeFailure::generic("offered an unknown suite"))?;
        kex_ids.extend_from_slice(kex);
    }
    kex_ids.sort_unstable();
    kex_ids.dedup();

    let mut ephemeral = Vec::with_capacity(kex_ids.len());
    let mut shares = Writer::new();
    for id in kex_ids {
        let (own, share) = p.kex_keygen(id).map_err(generic("key generation failed"))?;
        ephemeral.push((id, own));
        shares.u16(id);
        shares
            .vec16(&share)
            .map_err(generic("a key share is too long"))?;
    }

    let mut suites_field = Writer::new();
    for suite in &cfg.suites {
        suites_field.u16(*suite);
    }

    let mut extensions: Vec<(u16, Vec<u8>)> =
        vec![(ext::SESSION_ROLE, vec![cfg.plane.wire_value()])];
    if let Some(id) = &cfg.rendezvous_id {
        extensions.push((ext::RENDEZVOUS_ID, id.to_vec()));
    }
    let sent_known_responder = cfg.cached_peer_chain.is_some();
    if let Some(chain) = &cfg.cached_peer_chain {
        extensions.push((
            ext::KNOWN_RESPONDER,
            known_responder_value(p, &random, chain),
        ));
    }

    let encode_body = |extensions: Vec<(u16, Vec<u8>)>| -> Result<Vec<u8>, HandshakeFailure> {
        let bad = "XX_INIT is too long";
        let mut w = Writer::new();
        w.bytes(&random);
        w.vec8(&cfg.versions).map_err(generic(bad))?;
        w.vec8(&suites_field.buf).map_err(generic(bad))?;
        w.vec16(&shares.buf).map_err(generic(bad))?;
        w.vec16(&encode_extensions(extensions).map_err(generic(bad))?)
            .map_err(generic(bad))?;
        Ok(w.buf)
    };

    let mut body = encode_body(extensions.clone())?;
    if !cfg.transport.is_strict() && HEADER_LEN + body.len() < MIN_FIRST_FRAME {
        // RFC 9000, section 8.1. The extension header itself takes 4 bytes.
        let shortfall = MIN_FIRST_FRAME - HEADER_LEN - body.len();
        let padding = shortfall.saturating_sub(4);
        extensions.push((ext::PADDING, vec![0u8; padding]));
        body = encode_body(extensions)?;
    }

    let length = u16::try_from(body.len()).map_err(generic("XX_INIT is too long"))?;
    let header = Header::handshake(cfg.versions[0], SUITE_NONE, msg::XX_INIT, length);
    let mut t1 = header.hdr16().to_vec();
    t1.extend_from_slice(&body);
    let mut init_frame = header.encode().to_vec();
    init_frame.extend_from_slice(&body);

    Ok(Initiator {
        random,
        ephemeral,
        versions: cfg.versions.clone(),
        suites: cfg.suites.clone(),
        t1,
        init_frame,
        sent_known_responder,
    })
}

impl Initiator {
    pub(crate) fn frame(&self) -> &[u8] {
        &self.init_frame
    }

    pub(crate) fn random(&self) -> &[u8; RANDOM_LEN] {
        &self.random
    }

    /// Processes `XX_RESP` in the order section 7.3 requires. On failure nothing has
    /// changed, so a lossy session can ignore the message and keep waiting.
    pub(crate) fn on_resp(
        &mut self,
        cfg: &mut SessionConfig,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Completed, HandshakeFailure> {
        let provider = cfg.provider.clone();
        let p = provider.as_ref();
        let params = p.params();
        let (header, body) = parse_frame(frame).map_err(generic("malformed XX_RESP"))?;

        // The selection must be something I offered.
        if !self.versions.contains(&header.version) || !self.suites.contains(&header.suite_id) {
            return Err(HandshakeFailure::generic(
                "the responder selected something not offered",
            ));
        }

        let bad = "malformed XX_RESP";
        let mut r = Reader::new(body);
        let _random_r = r.take(RANDOM_LEN).map_err(generic(bad))?;
        let shares_raw = r.vec16().map_err(generic(bad))?;
        let extensions_raw = r.vec16().map_err(generic(bad))?;
        let clear_len = body.len() - r.remaining();
        let sealed = r.rest();
        let clear = &body[..clear_len];

        let extensions = parse_extensions(extensions_raw).map_err(generic(bad))?;
        check_critical(&extensions, &[])?;

        // The shares must be exactly the selected suite's components.
        let suite_components =
            suite_kex(header.suite_id).ok_or(HandshakeFailure::generic("unknown suite"))?;
        let shares = parse_key_shares(shares_raw)?;
        if shares.len() != suite_components.len() {
            return Err(HandshakeFailure::generic("wrong number of key shares"));
        }
        let mut ee = Zeroizing::new(Vec::new());
        for (component, (id, data)) in suite_components.iter().zip(&shares) {
            if component != id {
                return Err(HandshakeFailure::generic(
                    "key share for the wrong component",
                ));
            }
            let own = self
                .ephemeral
                .iter()
                .find(|(e, _)| e == id)
                .ok_or(HandshakeFailure::generic("no ephemeral for this component"))?;
            let shared = p
                .kex_agree(*id, &own.1, data)
                .map_err(generic("key agreement failed"))?;
            ee.extend_from_slice(&shared);
        }

        // T2, then the handshake secrets.
        let mut transcript = self.t1.clone();
        transcript.extend_from_slice(&header.hdr16());
        transcript.extend_from_slice(clear);
        let hs = extract_hs(p, &ee);
        let i_hs =
            derive_secret(p, &hs, "i hs", &transcript).map_err(generic("key schedule failed"))?;
        let r_hs =
            derive_secret(p, &hs, "r hs", &transcript).map_err(generic("key schedule failed"))?;
        let r_keys = traffic_keys(p, &r_hs).map_err(generic("key schedule failed"))?;
        let r_fin = finished_key(p, &r_hs).map_err(generic("key schedule failed"))?;

        // Step 1: open the encrypted part.
        let aad_len = HEADER_LEN + clear_len;
        let plain = open_encrypted_part(p, &r_keys, DIRECTION_R_TO_I, &frame[..aad_len], sealed)?;
        let (chain_on_wire, sig_r, mac_r) = parse_encrypted_part(&plain, params.hash_len)?;

        // An empty chain is only allowed if I asked for it (section 8).
        let chain_r: Vec<u8> = if chain_on_wire.is_empty() {
            if !self.sent_known_responder {
                return Err(HandshakeFailure::generic(
                    "empty chain without known_responder",
                ));
            }
            cfg.cached_peer_chain
                .clone()
                .ok_or(HandshakeFailure::generic("no cached chain"))?
        } else {
            chain_on_wire.to_vec()
        };

        // Step 2: validate the chain, without changing any pin.
        let validated = validate_peer(cfg, &chain_r, now_ms)?;

        // Step 3: verify the signature and the MAC.
        let bad_len = "a handshake field is too long";
        let mut w = Writer::new();
        w.vec16(&chain_r).map_err(generic(bad_len))?;
        transcript.extend_from_slice(&w.buf); // T3
        p.verify(
            &validated.leaf.fields.sign_public,
            &transcript_hash_with(p, "responder signature", &transcript),
            sig_r,
        )
        .map_err(generic("the responder's signature did not verify"))?;

        let mut w = Writer::new();
        w.vec16(sig_r).map_err(generic(bad_len))?;
        transcript.extend_from_slice(&w.buf); // T4
        if !ct_eq(&p.mac(&r_fin, &p.hash(&transcript)), mac_r) {
            return Err(HandshakeFailure::generic(
                "the responder's MAC did not verify",
            ));
        }
        transcript.extend_from_slice(mac_r); // T5

        // Step 4: the pin check. A first-contact pin is committed only now.
        let status = cfg
            .verifier
            .check_pin(&validated, now_ms)
            .map_err(rejection)?;
        let peer = peer_info(&validated, &chain_r, status);

        // XX_FINISH.
        let mut pending = Header::handshake(header.version, header.suite_id, msg::XX_FINISH, 0);
        let mut w = Writer::new();
        w.vec16(&cfg.chain).map_err(generic(bad_len))?;
        transcript.extend_from_slice(&pending.hdr16());
        transcript.extend_from_slice(&w.buf); // T6
        let sig_i = cfg
            .identity
            .sign(&transcript_hash_with(p, "initiator signature", &transcript))
            .map_err(generic("signing failed"))?;
        let mut w = Writer::new();
        w.vec16(&sig_i).map_err(generic(bad_len))?;
        transcript.extend_from_slice(&w.buf); // T7
        let i_fin = finished_key(p, &i_hs).map_err(generic("key schedule failed"))?;
        let mac_i = p.mac(&i_fin, &p.hash(&transcript));
        transcript.extend_from_slice(&mac_i); // T8

        let plaintext = encode_encrypted_part(&cfg.chain, &sig_i, &mac_i)?;
        pending.length =
            u16::try_from(plaintext.len() + params.tag_len).map_err(generic(bad_len))?;
        let encoded = pending.encode();
        let i_keys = traffic_keys(p, &i_hs).map_err(generic("key schedule failed"))?;
        let sealed_finish =
            seal_encrypted_part(p, &i_keys, DIRECTION_I_TO_R, &encoded, &plaintext)?;
        let mut finish_frame = encoded.to_vec();
        finish_frame.extend_from_slice(&sealed_finish);

        let secrets =
            application_secrets(p, &hs, &transcript).map_err(generic("key schedule failed"))?;
        self.ephemeral.clear();

        Ok(Completed {
            version: header.version,
            suite: header.suite_id,
            secrets,
            peer,
            finish_frame: Some(finish_frame),
        })
    }
}

// ---------------------------------------------------------------------- responder

/// What to do with a first message.
pub(crate) enum InitOutcome {
    /// Silently ignore it: its `rendezvous_id` is unknown.
    Drop,
    /// Answer with `HS_REJECT`.
    Reject {
        frame: Vec<u8>,
        failure: HandshakeFailure,
    },
    /// Continue.
    Accept(Box<Responder>),
}

/// The responder between `XX_RESP` and a verified `XX_FINISH`.
pub(crate) struct Responder {
    init_frame: Vec<u8>,
    resp_frame: Vec<u8>,
    version: u8,
    suite: u16,
    t5: Vec<u8>,
    hs: Secret,
    i_hs: Secret,
}

fn encode_reject(version: u8, code: u16, echo: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(&Header::handshake(version, SUITE_NONE, msg::HS_REJECT, 34).encode());
    w.u16(code);
    w.bytes(echo);
    w.buf
}

/// Processes `XX_INIT` and creates `XX_RESP`.
pub(crate) fn on_init(cfg: &SessionConfig, frame: &[u8]) -> Result<InitOutcome, HandshakeFailure> {
    let p = cfg.provider.as_ref();
    let params = p.params();
    let (header, body) = parse_frame(frame).map_err(generic("malformed XX_INIT"))?;
    if header.suite_id != SUITE_NONE {
        return Err(HandshakeFailure::generic("XX_INIT with a selected suite"));
    }

    let bad = "malformed XX_INIT";
    let mut r = Reader::new(body);
    let random_i = r.take(RANDOM_LEN).map_err(generic(bad))?;
    let versions = r.vec8().map_err(generic(bad))?;
    let suites_raw = r.vec8().map_err(generic(bad))?;
    let shares_raw = r.vec16().map_err(generic(bad))?;
    let extensions_raw = r.vec16().map_err(generic(bad))?;
    r.finish().map_err(generic(bad))?;
    let extensions = parse_extensions(extensions_raw).map_err(generic(bad))?;

    // A stranger who does not hold the rendezvous id learns nothing, not even that
    // something is listening (section 5.4).
    if cfg.plane == Plane::Data {
        let presented = find_extension(&extensions, ext::RENDEZVOUS_ID);
        let expected = cfg.rendezvous_id.as_ref().map(|id| id.as_slice());
        let matches = match (presented, expected) {
            (Some(a), Some(b)) => ct_eq(a, b),
            _ => false,
        };
        if !matches {
            return Ok(InitOutcome::Drop);
        }
    }

    check_critical(&extensions, &[ext::SESSION_ROLE, ext::RENDEZVOUS_ID])?;
    match find_extension(&extensions, ext::SESSION_ROLE) {
        Some([role]) if *role == cfg.plane.wire_value() => {}
        _ => return Err(HandshakeFailure::generic("session_role does not match")),
    }
    if cfg.plane == Plane::Control && find_extension(&extensions, ext::RENDEZVOUS_ID).is_some() {
        return Err(HandshakeFailure::generic(
            "rendezvous_id on the control plane",
        ));
    }
    if !versions.contains(&header.version) {
        return Err(HandshakeFailure::generic(
            "the header's version is not in the offer",
        ));
    }

    // Selection: the first of I's preferences that R supports.
    let Some(version) = versions.iter().copied().find(|v| cfg.versions.contains(v)) else {
        return Ok(InitOutcome::Reject {
            frame: encode_reject(header.version, reject::UNSUPPORTED_VERSION, random_i),
            failure: HandshakeFailure {
                code: ErrorCode::VersionMismatch,
                detail: "no common version",
            },
        });
    };
    if suites_raw.len() % 2 != 0 {
        return Err(HandshakeFailure::generic(bad));
    }
    let offered = suites_raw
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]));
    let mut selected = None;
    for suite in offered {
        if suite == SUITE_NONE {
            return Err(HandshakeFailure::generic("offered the reserved suite"));
        }
        if selected.is_none() && cfg.suites.contains(&suite) {
            selected = Some(suite);
        }
    }
    let Some(suite) = selected else {
        return Ok(InitOutcome::Reject {
            frame: encode_reject(header.version, reject::UNSUPPORTED_SUITE, random_i),
            failure: HandshakeFailure {
                code: ErrorCode::SuiteMismatch,
                detail: "no common suite",
            },
        });
    };

    // Key agreement, in ascending kex_id order.
    let components = suite_kex(suite).ok_or(HandshakeFailure::generic("unknown suite"))?;
    let shares_i = parse_key_shares(shares_raw)?;
    let mut ee = Zeroizing::new(Vec::new());
    let mut shares_r = Writer::new();
    for id in components {
        let (_, data) = shares_i
            .iter()
            .find(|(e, _)| e == id)
            .ok_or(HandshakeFailure::generic(
                "no key share for the selected suite",
            ))?;
        let (share, shared) = p
            .kex_respond(*id, data)
            .map_err(generic("key agreement failed"))?;
        ee.extend_from_slice(&shared);
        shares_r.u16(*id);
        shares_r
            .vec16(&share)
            .map_err(generic("a key share is too long"))?;
    }

    // Section 8: omit the chain if I already holds exactly this one.
    let omit_chain = match find_extension(&extensions, ext::KNOWN_RESPONDER) {
        Some(value) => {
            if value.len() != 16 {
                return Err(HandshakeFailure::generic("malformed known_responder"));
            }
            ct_eq(value, &known_responder_value(p, random_i, &cfg.chain))
        }
        None => false,
    };

    let mut random_r = [0u8; RANDOM_LEN];
    p.random(&mut random_r)
        .map_err(generic("the random source failed"))?;

    let bad_len = "a handshake field is too long";
    let mut clear = Writer::new();
    clear.bytes(&random_r);
    clear.vec16(&shares_r.buf).map_err(generic(bad_len))?;
    clear.vec16(&[]).map_err(generic(bad_len))?;

    // T2. The length is not known yet, and hdr16 leaves it out for that reason.
    let mut pending = Header::handshake(version, suite, msg::XX_RESP, 0);
    let mut transcript = header.hdr16().to_vec();
    transcript.extend_from_slice(body); // T1
    transcript.extend_from_slice(&pending.hdr16());
    transcript.extend_from_slice(&clear.buf);

    let schedule_error = "key schedule failed";
    let hs = extract_hs(p, &ee);
    let i_hs = derive_secret(p, &hs, "i hs", &transcript).map_err(generic(schedule_error))?;
    let r_hs = derive_secret(p, &hs, "r hs", &transcript).map_err(generic(schedule_error))?;
    let r_keys = traffic_keys(p, &r_hs).map_err(generic(schedule_error))?;
    let r_fin = finished_key(p, &r_hs).map_err(generic(schedule_error))?;

    let mut w = Writer::new();
    w.vec16(&cfg.chain).map_err(generic(bad_len))?;
    transcript.extend_from_slice(&w.buf); // T3: always the full chain.
    let sig_r = cfg
        .identity
        .sign(&transcript_hash_with(p, "responder signature", &transcript))
        .map_err(generic("signing failed"))?;
    let mut w = Writer::new();
    w.vec16(&sig_r).map_err(generic(bad_len))?;
    transcript.extend_from_slice(&w.buf); // T4
    let mac_r = p.mac(&r_fin, &p.hash(&transcript));
    transcript.extend_from_slice(&mac_r); // T5

    let chain_on_wire: &[u8] = if omit_chain { &[] } else { &cfg.chain };
    let plaintext = encode_encrypted_part(chain_on_wire, &sig_r, &mac_r)?;
    pending.length = u16::try_from(clear.buf.len() + plaintext.len() + params.tag_len)
        .map_err(generic(bad_len))?;
    let encoded = pending.encode();
    let mut aad = encoded.to_vec();
    aad.extend_from_slice(&clear.buf);
    let sealed = seal_encrypted_part(p, &r_keys, DIRECTION_R_TO_I, &aad, &plaintext)?;
    let mut resp_frame = aad;
    resp_frame.extend_from_slice(&sealed);

    Ok(InitOutcome::Accept(Box::new(Responder {
        init_frame: frame.to_vec(),
        resp_frame,
        version,
        suite,
        t5: transcript,
        hs,
        i_hs,
    })))
}

impl Responder {
    pub(crate) fn resp_frame(&self) -> &[u8] {
        &self.resp_frame
    }

    pub(crate) fn init_frame(&self) -> &[u8] {
        &self.init_frame
    }

    /// Processes `XX_FINISH` in the order section 7.3 requires.
    pub(crate) fn on_finish(
        &mut self,
        cfg: &mut SessionConfig,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Completed, HandshakeFailure> {
        let provider = cfg.provider.clone();
        let p = provider.as_ref();
        let params = p.params();
        let (header, sealed) = parse_frame(frame).map_err(generic("malformed XX_FINISH"))?;
        if header.version != self.version || header.suite_id != self.suite {
            return Err(HandshakeFailure::generic(
                "XX_FINISH repeats the wrong selection",
            ));
        }

        // Step 1.
        let schedule_error = "key schedule failed";
        let i_keys = traffic_keys(p, &self.i_hs).map_err(generic(schedule_error))?;
        let plain =
            open_encrypted_part(p, &i_keys, DIRECTION_I_TO_R, &frame[..HEADER_LEN], sealed)?;
        let (chain_i, sig_i, mac_i) = parse_encrypted_part(&plain, params.hash_len)?;

        // Step 2.
        let validated = validate_peer(cfg, chain_i, now_ms)?;

        // Step 3.
        let bad_len = "a handshake field is too long";
        let mut transcript = self.t5.clone();
        transcript.extend_from_slice(&header.hdr16());
        let mut w = Writer::new();
        w.vec16(chain_i).map_err(generic(bad_len))?;
        transcript.extend_from_slice(&w.buf); // T6
        p.verify(
            &validated.leaf.fields.sign_public,
            &transcript_hash_with(p, "initiator signature", &transcript),
            sig_i,
        )
        .map_err(generic("the initiator's signature did not verify"))?;
        let mut w = Writer::new();
        w.vec16(sig_i).map_err(generic(bad_len))?;
        transcript.extend_from_slice(&w.buf); // T7
        let i_fin = finished_key(p, &self.i_hs).map_err(generic(schedule_error))?;
        if !ct_eq(&p.mac(&i_fin, &p.hash(&transcript)), mac_i) {
            return Err(HandshakeFailure::generic(
                "the initiator's MAC did not verify",
            ));
        }
        transcript.extend_from_slice(mac_i); // T8

        // Step 4.
        let status = cfg
            .verifier
            .check_pin(&validated, now_ms)
            .map_err(rejection)?;
        let peer = peer_info(&validated, chain_i, status);

        let secrets =
            application_secrets(p, &self.hs, &transcript).map_err(generic(schedule_error))?;
        Ok(Completed {
            version: self.version,
            suite: self.suite,
            secrets,
            peer,
            finish_frame: None,
        })
    }
}
