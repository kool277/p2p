//! Checks the engine against `docs/PROTOCOL.md` using a scripted peer. The peer
//! rebuilds messages from the text of the specification with its own transcript
//! code, so a disagreement between the code and the document fails here, where a
//! test of the engine against itself could not notice it.
mod common;

use common::*;
use qalqon_core::crypto::suite::{KEX_X25519, SUITE_TESTONLY_X25519};
use qalqon_core::crypto::{CryptoProvider, SigningKey, ct_eq};
use qalqon_core::schedule::{
    ctx, derive_secret, expand_label, finished_key, next_traffic_secret, record_nonce, salt0,
    traffic_keys,
};
use qalqon_core::session::{Plane, Role, TransportCaps};
use qalqon_core::wire::{self, Header, Reader, Writer, msg};
use qalqon_core::{ErrorCode, Event, PeerExpectation, Session};
use std::sync::Arc;

const HDR16: usize = 16;

fn vec16(b: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.vec16(b).unwrap();
    w.buf
}

/// A responder written directly from section 7 of the specification.
struct ScriptedResponder {
    provider: Arc<dyn CryptoProvider>,
    identity: Arc<dyn SigningKey>,
    chain: Vec<u8>,
    /// What goes on the wire in place of `chain_r`. The transcript always has the
    /// full chain.
    chain_on_wire: Vec<u8>,
}

struct RespOutput {
    frame: Vec<u8>,
    transcript_t5: Vec<u8>,
    hs: Vec<u8>,
    i_hs: Vec<u8>,
}

impl ScriptedResponder {
    fn respond(&self, init_frame: &[u8]) -> RespOutput {
        let p = self.provider.as_ref();
        let (init_header, init_body) = wire::parse_frame(init_frame).unwrap();
        assert_eq!(
            init_header.suite_id, 0,
            "section 7.1: XX_INIT carries suite 0"
        );
        assert_eq!(init_header.channel_id, 0);
        assert_eq!(init_header.seq, 0);

        let mut r = Reader::new(init_body);
        let _random = r.take(32).unwrap();
        let versions = r.vec8().unwrap();
        assert_eq!(versions, [wire::VERSION_0_1]);
        let _suites = r.vec8().unwrap();
        let shares = r.vec16().unwrap();
        let _extensions = r.vec16().unwrap();
        r.finish().unwrap();

        // Find I's X25519 share.
        let mut s = Reader::new(shares);
        let mut share_i = None;
        while !s.is_empty() {
            let id = s.u16().unwrap();
            let data = s.vec16().unwrap();
            if id == KEX_X25519 {
                share_i = Some(data);
            }
        }
        let (share_r, ee) = p.kex_respond(KEX_X25519, share_i.unwrap()).unwrap();

        // T1 = hdr16(XX_INIT) || XX_INIT body
        let mut t = init_frame[..HDR16].to_vec();
        t.extend_from_slice(init_body);

        // XX_RESP clear part: random, shares, extensions.
        let mut clear = Writer::new();
        let mut random_r = [0u8; 32];
        p.random(&mut random_r).unwrap();
        clear.bytes(&random_r);
        let mut shares_r = Writer::new();
        shares_r.u16(KEX_X25519);
        shares_r.vec16(&share_r).unwrap();
        clear.vec16(&shares_r.buf).unwrap();
        clear.vec16(&[]).unwrap();

        // T2 = T1 || hdr16(XX_RESP) || XX_RESP clear part
        let hdr = Header::handshake(wire::VERSION_0_1, SUITE_TESTONLY_X25519, msg::XX_RESP, 0);
        t.extend_from_slice(&hdr.hdr16());
        t.extend_from_slice(&clear.buf);

        // hs = HKDF-Extract(salt0, ee); i_hs, r_hs = Derive-Secret(hs, ..., T2)
        let hs = p.hkdf_extract(&p.hash(&ctx("salt")), &ee);
        assert_eq!(salt0(p), p.hash(b"qalqon0 salt\0"), "section 6: salt0");
        let i_hs = derive_secret(p, &hs, "i hs", &t).unwrap();
        let r_hs = derive_secret(p, &hs, "r hs", &t).unwrap();

        // T3 = T2 || vec16(chain_r)
        t.extend_from_slice(&vec16(&self.chain));
        // sig_r = Sign(identity_r, ctx("responder signature") || H(T3))
        let mut signed = b"qalqon0 responder signature\0".to_vec();
        signed.extend_from_slice(&p.hash(&t));
        let sig_r = self.identity.sign(&signed).unwrap();
        // T4 = T3 || vec16(sig_r)
        t.extend_from_slice(&vec16(&sig_r));
        // mac_r = HMAC(fin of r_hs, H(T4))
        let fin = finished_key(p, &r_hs).unwrap();
        let mac_r = p.mac(&fin, &p.hash(&t));
        // T5 = T4 || mac_r
        t.extend_from_slice(&mac_r);

        // The encrypted part: seq 0, keys from r_hs, associated data of the full
        // header followed by the clear part, nonce with direction 1.
        let mut plain = Writer::new();
        plain.vec16(&self.chain_on_wire).unwrap();
        plain.vec16(&sig_r).unwrap();
        plain.bytes(&mac_r);
        let params = p.params();
        let length = clear.buf.len() + plain.buf.len() + params.tag_len;
        let header = Header::handshake(
            wire::VERSION_0_1,
            SUITE_TESTONLY_X25519,
            msg::XX_RESP,
            length as u16,
        );
        let mut aad = header.encode().to_vec();
        aad.extend_from_slice(&clear.buf);
        let keys = traffic_keys(p, &r_hs).unwrap();
        let nonce = record_nonce(&keys.iv, 1, 0);
        let sealed = p.aead_seal(&keys.aead, &nonce, &aad, &plain.buf).unwrap();
        let mut frame = aad;
        frame.extend_from_slice(&sealed);
        RespOutput {
            frame,
            transcript_t5: t,
            hs: hs.to_vec(),
            i_hs: i_hs.to_vec(),
        }
    }
}

fn scripted_setup(pki: &Pki) -> (qalqon_core::SessionConfig, ScriptedResponder) {
    let alice = pki.device("alice", "a1");
    let bob = pki.device("bob", "b1");
    let mut cfg = pki.config(
        Role::Initiator,
        Plane::Data,
        TransportCaps::STREAM,
        &alice,
        PeerExpectation::Peer {
            user_id: "bob".into(),
            device_id: None,
        },
    );
    cfg.suites = vec![SUITE_TESTONLY_X25519];
    let scripted = ScriptedResponder {
        provider: pki.provider.clone(),
        identity: bob.identity.clone(),
        chain: bob.chain.clone(),
        chain_on_wire: bob.chain.clone(),
    };
    (cfg, scripted)
}

#[test]
fn the_engine_accepts_a_responder_written_from_the_specification() {
    let pki = Pki::new();
    let p = pki.provider.clone();
    let (cfg, scripted) = scripted_setup(&pki);
    let mut i = Session::new(cfg, NOW).unwrap();
    let init = i.poll_transmit().unwrap();
    let out = scripted.respond(&init);
    i.handle_frame(NOW, &out.frame);
    let event = i.poll_event().unwrap();
    assert!(matches!(event, Event::Established { .. }), "{event:?}");

    // XX_FINISH, parsed by the specification's rules.
    let finish = i.poll_transmit().unwrap();
    let (header, sealed) = wire::parse_frame(&finish).unwrap();
    assert_eq!(header.msg_type, msg::XX_FINISH);
    let keys = traffic_keys(p.as_ref(), &out.i_hs).unwrap();
    let nonce = record_nonce(&keys.iv, 0, 0);
    let plain = p
        .aead_open(&keys.aead, &nonce, &finish[..wire::HEADER_LEN], sealed)
        .unwrap();
    let mut r = Reader::new(&plain);
    let chain_i = r.vec16().unwrap();
    let sig_i = r.vec16().unwrap();
    let mac_i = r.take(32).unwrap();
    r.finish().unwrap();

    // T6 = T5 || hdr16(XX_FINISH) || vec16(chain_i)
    let mut t = out.transcript_t5.clone();
    t.extend_from_slice(&finish[..HDR16]);
    t.extend_from_slice(&vec16(chain_i));
    let leaf = qalqon_core::cert::parse_many(p.as_ref(), chain_i)
        .unwrap()
        .remove(0);
    let mut signed = ctx("initiator signature");
    signed.extend_from_slice(&p.hash(&t));
    p.verify(&leaf.fields.sign_public, &signed, sig_i)
        .expect("sig_i per section 7.2");
    // T7 = T6 || vec16(sig_i)
    t.extend_from_slice(&vec16(sig_i));
    let fin = finished_key(p.as_ref(), &out.i_hs).unwrap();
    assert!(
        ct_eq(&p.mac(&fin, &p.hash(&t)), mac_i),
        "mac_i per section 7.2"
    );
    // T8 = T7 || mac_i
    t.extend_from_slice(mac_i);

    // The application secrets per section 7.2 must match: KEY_CONFIRM sealed by hand
    // under r_ap_0 must open at I, and I's first record must open here.
    let derived = derive_secret(p.as_ref(), &out.hs, "derived", &[]).unwrap();
    let ms = p.hkdf_extract(&derived, &[0u8; 32]);
    let r_ap = derive_secret(p.as_ref(), &ms, "r ap", &t).unwrap();
    let i_ap = derive_secret(p.as_ref(), &ms, "i ap", &t).unwrap();
    let session_id = expand_label(p.as_ref(), &ms, "session id", &p.hash(&t), 16).unwrap();
    assert_eq!(i.session_id().unwrap().as_slice(), session_id.as_slice());

    // A hand-sealed KEY_CONFIRM: inner type 0x03, epoch 0, counter 0.
    let header = Header {
        version: wire::VERSION_0_1,
        suite_id: SUITE_TESTONLY_X25519,
        msg_type: msg::RECORD,
        channel_id: 0,
        seq: 0,
        length: (1 + p.params().tag_len) as u16,
    };
    let encoded = header.encode();
    let keys = traffic_keys(p.as_ref(), &r_ap).unwrap();
    let nonce = record_nonce(&keys.iv, 1, 0);
    let sealed = p.aead_seal(&keys.aead, &nonce, &encoded, &[0x03]).unwrap();
    let mut frame = encoded.to_vec();
    frame.extend_from_slice(&sealed);
    i.handle_frame(NOW, &frame);
    assert_eq!(i.poll_event(), Some(Event::PeerConfirmed));

    // A record from I opens under i_ap_0 with direction 0, and PING has the form the
    // specification gives.
    i.ping(NOW).unwrap();
    let ping = i.poll_transmit().unwrap();
    let (header, sealed) = wire::parse_frame(&ping).unwrap();
    assert_eq!(header.seq, 0);
    let keys = traffic_keys(p.as_ref(), &i_ap).unwrap();
    let nonce = record_nonce(&keys.iv, 0, header.seq);
    let plain = p
        .aead_open(&keys.aead, &nonce, &ping[..wire::HEADER_LEN], sealed)
        .unwrap();
    assert_eq!(plain[0], 0x08);
    assert_eq!(plain.len(), 9);

    // Section 9.5: S_next derives the next epoch's keys.
    let next = next_traffic_secret(p.as_ref(), &i_ap).unwrap();
    assert_eq!(
        next.as_slice(),
        expand_label(p.as_ref(), &i_ap, "traffic upd", &[], 32)
            .unwrap()
            .as_slice()
    );
}

#[test]
fn an_empty_chain_without_known_responder_is_refused() {
    // Section 8: I MUST treat an empty chain_r as a failure if it did not send
    // known_responder. The scripted responder signs correctly over the full chain,
    // so every other check would pass.
    let pki = Pki::new();
    let (cfg, mut scripted) = scripted_setup(&pki);
    scripted.chain_on_wire = Vec::new();
    let mut i = Session::new(cfg, NOW).unwrap();
    let init = i.poll_transmit().unwrap();
    let out = scripted.respond(&init);
    i.handle_frame(NOW, &out.frame);
    match i.poll_event() {
        Some(Event::HandshakeFailed(f)) => {
            assert_eq!(f.code, ErrorCode::HandshakeFailed);
            assert_eq!(f.detail, "empty chain without known_responder");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn an_omitted_chain_is_accepted_when_i_asked_for_it() {
    let pki = Pki::new();
    let (mut cfg, mut scripted) = scripted_setup(&pki);
    cfg.cached_peer_chain = Some(scripted.chain.clone());
    scripted.chain_on_wire = Vec::new();
    let mut i = Session::new(cfg, NOW).unwrap();
    let init = i.poll_transmit().unwrap();
    let out = scripted.respond(&init);
    i.handle_frame(NOW, &out.frame);
    assert!(matches!(i.poll_event(), Some(Event::Established { .. })));
}

#[test]
fn a_cached_chain_is_still_validated_on_every_use() {
    // Section 8: I validates the cached chain every time, including expiry. Here the
    // scripted responder holds the right key, but the cached certificate has expired.
    let pki = Pki::new();
    let (mut cfg, mut scripted) = scripted_setup(&pki);
    let expired = pki.leaf_times(
        qalqon_core::cert::role::DEVICE,
        "bob",
        "b1",
        scripted.identity.as_ref(),
        NOW - 2 * DAY,
        NOW - DAY,
    );
    cfg.cached_peer_chain = Some(expired.clone());
    scripted.chain = expired;
    scripted.chain_on_wire = Vec::new();
    let mut i = Session::new(cfg, NOW).unwrap();
    let init = i.poll_transmit().unwrap();
    let out = scripted.respond(&init);
    i.handle_frame(NOW, &out.frame);
    match i.poll_event() {
        Some(Event::HandshakeFailed(f)) => assert_eq!(f.code, ErrorCode::PeerRevoked),
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn a_signature_over_the_wrong_context_is_refused() {
    // The signature must bind ctx("responder signature"). One made for the
    // initiator's context must not pass, which is what the separation is for.
    let pki = Pki::new();
    let (cfg, scripted) = scripted_setup(&pki);
    let mut i = Session::new(cfg, NOW).unwrap();
    let init = i.poll_transmit().unwrap();

    struct WrongContext(Arc<dyn SigningKey>);
    impl SigningKey for WrongContext {
        fn public_key(&self) -> &qalqon_core::crypto::PublicKey {
            self.0.public_key()
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, qalqon_core::crypto::CryptoError> {
            let mut changed = message.to_vec();
            let swap = b"qalqon0 responder signature\0";
            assert!(changed.starts_with(swap));
            changed.splice(
                ..swap.len(),
                b"qalqon0 initiator signature\0".iter().copied(),
            );
            self.0.sign(&changed)
        }
        fn export_secret(&self) -> Option<qalqon_core::crypto::Secret> {
            None
        }
    }
    let wrong = ScriptedResponder {
        provider: scripted.provider.clone(),
        identity: Arc::new(WrongContext(scripted.identity.clone())),
        chain: scripted.chain.clone(),
        chain_on_wire: scripted.chain.clone(),
    };
    let out = wrong.respond(&init);
    i.handle_frame(NOW, &out.frame);
    match i.poll_event() {
        Some(Event::HandshakeFailed(f)) => {
            assert_eq!(f.detail, "the responder's signature did not verify");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn hkdf_label_layout_matches_section_6() {
    // HkdfLabel = u16(Length) || vec8("qalqon0 " || Label) || vec8(Context)
    let pki = Pki::new();
    let p = pki.provider.as_ref();
    let secret = [0x11u8; 32];
    let mut info = vec![0x00, 0x20];
    info.push((8 + 3) as u8);
    info.extend_from_slice(b"qalqon0 key");
    info.push(2);
    info.extend_from_slice(&[0xAA, 0xBB]);
    let expected = p.hkdf_expand(&secret, &info, 32).unwrap();
    let got = expand_label(p, &secret, "key", &[0xAA, 0xBB], 32).unwrap();
    assert_eq!(got.as_slice(), expected.as_slice());
}

#[test]
fn the_record_nonce_matches_section_9_1() {
    let iv = [0x10u8; 12];
    let seq = 0x0001_0000_0000_0005u64;
    let nonce = record_nonce(&iv, 1, seq);
    // pad(direction || seq): 3 zero bytes, the direction, then the 8-byte sequence.
    let mut expected = [0u8; 12];
    expected[3] = 1;
    expected[4..].copy_from_slice(&seq.to_be_bytes());
    for (e, i) in expected.iter_mut().zip(iv) {
        *e ^= i;
    }
    assert_eq!(nonce, expected);
}

#[test]
fn the_safety_number_is_symmetric_and_has_sixty_digits() {
    use qalqon_core::pins::safety_number;
    let pki = Pki::new();
    let p = pki.provider.as_ref();
    let a = p.hash(b"device a");
    let b = p.hash(b"device b");
    let one = safety_number(p, &a, &b).unwrap();
    let two = safety_number(p, &b, &a).unwrap();
    assert_eq!(one, two);
    assert_eq!(one.len(), 60);
    assert!(one.bytes().all(|c| c.is_ascii_digit()));
    assert_ne!(one, safety_number(p, &a, &p.hash(b"device c")).unwrap());
}

#[test]
fn every_error_code_matches_the_idl() {
    let idl = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../idl/qalqon.api.yaml"
    ))
    .unwrap();
    let mut seen = 0;
    for code in qalqon_core::error::ALL_CODES {
        let expected = format!("{}:", code.name());
        let line = idl
            .lines()
            .find(|l| l.trim_start().starts_with(&expected) && l.contains("code:"))
            .unwrap_or_else(|| panic!("{} is not in the IDL", code.name()));
        assert!(line.contains(&format!("code: {},", code.code())), "{line}");
        seen += 1;
    }
    let in_idl = idl.lines().filter(|l| l.contains("{code:")).count();
    assert_eq!(
        seen, in_idl,
        "the IDL and the engine list different error codes"
    );
}

/// A session established against the scripted responder, plus what is needed to
/// seal arbitrary records as that responder.
struct Scripted {
    session: Session,
    provider: Arc<dyn CryptoProvider>,
    r_ap: Vec<u8>,
    counter: u64,
}

impl Scripted {
    fn new(transport: TransportCaps) -> Self {
        let pki = Pki::new();
        let (mut cfg, scripted) = scripted_setup(&pki);
        cfg.transport = transport;
        let p = pki.provider.clone();
        let mut session = Session::new(cfg, NOW).unwrap();
        let init = session.poll_transmit().unwrap();
        let out = scripted.respond(&init);
        session.handle_frame(NOW, &out.frame);
        assert!(matches!(
            session.poll_event(),
            Some(Event::Established { .. })
        ));
        let finish = session.poll_transmit().unwrap();
        let (_, sealed) = wire::parse_frame(&finish).unwrap();
        let keys = traffic_keys(p.as_ref(), &out.i_hs).unwrap();
        let nonce = record_nonce(&keys.iv, 0, 0);
        let plain = p
            .aead_open(&keys.aead, &nonce, &finish[..wire::HEADER_LEN], sealed)
            .unwrap();
        let mut t = out.transcript_t5.clone();
        t.extend_from_slice(&finish[..HDR16]);
        let mut r = Reader::new(&plain);
        t.extend_from_slice(&vec16(r.vec16().unwrap()));
        t.extend_from_slice(&vec16(r.vec16().unwrap()));
        t.extend_from_slice(r.take(32).unwrap());
        let derived = derive_secret(p.as_ref(), &out.hs, "derived", &[]).unwrap();
        let ms = p.hkdf_extract(&derived, &[0u8; 32]);
        let r_ap = derive_secret(p.as_ref(), &ms, "r ap", &t).unwrap().to_vec();
        let mut scripted = Scripted {
            session,
            provider: p,
            r_ap,
            counter: 0,
        };
        scripted.seal_and_deliver(0, &[0x03]); // KEY_CONFIRM
        assert_eq!(scripted.session.poll_event(), Some(Event::PeerConfirmed));
        scripted
    }

    fn seal_and_deliver(&mut self, channel_id: u16, plaintext: &[u8]) {
        let p = self.provider.as_ref();
        let header = Header {
            version: wire::VERSION_0_1,
            suite_id: SUITE_TESTONLY_X25519,
            msg_type: msg::RECORD,
            channel_id,
            seq: self.counter,
            length: (plaintext.len() + p.params().tag_len) as u16,
        };
        self.counter += 1;
        let encoded = header.encode();
        let keys = traffic_keys(p, &self.r_ap).unwrap();
        let nonce = record_nonce(&keys.iv, 1, header.seq);
        let sealed = p
            .aead_seal(&keys.aead, &nonce, &encoded, plaintext)
            .unwrap();
        let mut frame = encoded.to_vec();
        frame.extend_from_slice(&sealed);
        self.session.handle_frame(NOW, &frame);
    }

    fn closed_uncleanly(&mut self) -> bool {
        while let Some(event) = self.session.poll_event() {
            if matches!(event, Event::Closed { clean: false, .. }) {
                return true;
            }
        }
        false
    }
}

/// Authenticated but invalid records. A strict session ends, and the peer learns
/// only that it failed. Each case is the plaintext a malicious peer would seal.
#[test]
fn authenticated_but_invalid_records_close_a_strict_session() {
    let cases: [(&str, u16, &[u8]); 11] = [
        ("empty record", 0, &[]),
        ("unknown inner type", 0, &[0x7F]),
        ("KEY_CONFIRM on a channel", 3, &[0x03]),
        ("KEY_CONFIRM with a body", 0, &[0x03, 0x00]),
        ("DATA on channel 0", 0, &[0x01, 0, 0, 0, 0, 0, 0, 1, b'x']),
        (
            "DATA for an unknown channel",
            9,
            &[0x01, 0, 0, 0, 0, 0, 0, 1, b'x'],
        ),
        (
            "CHANNEL_OPEN with this side's ID parity",
            3,
            &[0x04, 0, 0, 0],
        ),
        ("CHANNEL_OPEN with a non-boolean flag", 2, &[0x04, 7, 0, 0]),
        ("KEY_UPDATE with a bad flag", 0, &[0x02, 2]),
        ("CLOSE that is too short", 0, &[0x0A, 0]),
        ("CONTROL on the data plane", 0, &[0x20, 0, 1]),
    ];
    for (name, channel, plaintext) in cases {
        let mut s = Scripted::new(TransportCaps::STREAM);
        s.seal_and_deliver(channel, plaintext);
        assert!(s.closed_uncleanly(), "{name} did not close the session");
    }
}

#[test]
fn authenticated_but_invalid_records_are_only_dropped_on_a_lossy_session() {
    let mut s = Scripted::new(TransportCaps::DATAGRAM);
    s.seal_and_deliver(0, &[0x7F]);
    assert!(s.session.is_established());
    assert!(s.session.stats().frames_dropped >= 1);
}

#[test]
fn a_valid_peer_channel_with_the_right_parity_is_offered() {
    let mut s = Scripted::new(TransportCaps::STREAM);
    let mut open = vec![0x04, 1, 1];
    open.push(4);
    open.extend_from_slice(b"chat");
    s.seal_and_deliver(2, &open);
    assert_eq!(
        s.session.poll_event(),
        Some(Event::ChannelRequested {
            channel_id: 2,
            options: qalqon_core::ChannelOptions {
                ordered: true,
                reliable: true,
                label: "chat".into()
            },
        })
    );
}

#[test]
fn a_responder_refuses_records_before_xx_finish_has_verified() {
    let pki = Pki::new();
    let (a, b) = pki.data_pair(TransportCaps::DATAGRAM);
    let mut link = Link::new(a, b);
    // XX_INIT reaches R, XX_RESP reaches I, and XX_FINISH is held back. I may send
    // records at once, but R must not accept them.
    let init = link.a.poll_transmit().unwrap();
    link.b.handle_frame(NOW, &init);
    let resp = link.b.poll_transmit().unwrap();
    link.a.handle_frame(NOW, &resp);
    let _held_finish = link.a.poll_transmit().unwrap();
    link.a.ping(NOW).unwrap();
    let ping = link.a.poll_transmit().unwrap();
    link.b.handle_frame(NOW, &ping);
    assert!(
        link.b.poll_transmit().is_none(),
        "R answered a record before verifying XX_FINISH"
    );
    assert!(!link.b.is_established());
}

#[test]
fn the_initiator_does_not_confirm_until_it_opens_a_record() {
    // Section 15, item 4: I reaches agreement only on opening R's KEY_CONFIRM. A
    // forged record must not count.
    let pki = Pki::new();
    let (cfg, scripted) = scripted_setup(&pki);
    let mut i = Session::new(cfg, NOW).unwrap();
    let init = i.poll_transmit().unwrap();
    let out = scripted.respond(&init);
    i.handle_frame(NOW, &out.frame);
    assert!(matches!(i.poll_event(), Some(Event::Established { .. })));
    let header = Header {
        version: wire::VERSION_0_1,
        suite_id: SUITE_TESTONLY_X25519,
        msg_type: msg::RECORD,
        channel_id: 0,
        seq: 0,
        length: 33,
    };
    let mut forged = header.encode().to_vec();
    forged.extend_from_slice(&[0u8; 33]);
    i.handle_frame(NOW, &forged);
    assert!(!matches!(i.poll_event(), Some(Event::PeerConfirmed)));
}
