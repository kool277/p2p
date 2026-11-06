//! The handshake against itself and against an attacker on the wire.

mod common;

use common::*;
use provider_testonly::TestOnlyProvider;
use qalqon_core::cert::role;
use qalqon_core::crypto::suite::{SUITE_TESTONLY_X25519, SUITE_TESTONLY_X25519_ML_KEM_768};
use qalqon_core::session::{Plane, Role, TransportCaps};
use qalqon_core::wire::{self, msg};
use qalqon_core::{ErrorCode, Event, HandshakeFailure, PeerExpectation, Session};
use std::sync::Arc;

fn failure(events: &[Event]) -> Option<HandshakeFailure> {
    events.iter().find_map(|e| match e {
        Event::HandshakeFailed(f) => Some(*f),
        _ => None,
    })
}

#[test]
fn strict_handshake_completes_and_agrees() {
    let pki = Pki::new();
    let (a, b) = pki.data_pair(TransportCaps::STREAM);
    let mut link = Link::new(a, b);
    link.pump();
    assert!(
        established(&link),
        "{:?} / {:?}",
        link.a_events,
        link.b_events
    );
    assert_eq!(link.a.session_id(), link.b.session_id());
    assert!(
        link.a_events.contains(&Event::PeerConfirmed),
        "I must see KEY_CONFIRM"
    );
    assert_eq!(link.a.peer().unwrap().subject_a, "bob");
    assert_eq!(link.b.peer().unwrap().subject_a, "alice");
}

#[test]
fn control_plane_checks_the_host_name() {
    let pki = Pki::new();
    let server = pki.server("qalqon.example");
    let device = pki.device("alice", "a1");
    let good = pki.config(
        Role::Initiator,
        Plane::Control,
        TransportCaps::STREAM,
        &device,
        PeerExpectation::Server {
            host: "QALQON.example".into(),
        },
    );
    let r = pki.config(
        Role::Responder,
        Plane::Control,
        TransportCaps::STREAM,
        &server,
        PeerExpectation::Client,
    );
    let mut link = Link::new(good, r);
    link.pump();
    assert!(established(&link));

    let bad = pki.config(
        Role::Initiator,
        Plane::Control,
        TransportCaps::STREAM,
        &device,
        PeerExpectation::Server {
            host: "evil.example".into(),
        },
    );
    let r = pki.config(
        Role::Responder,
        Plane::Control,
        TransportCaps::STREAM,
        &server,
        PeerExpectation::Client,
    );
    let mut link = Link::new(bad, r);
    link.pump();
    assert_eq!(
        failure(&link.a_events).unwrap().code,
        ErrorCode::HandshakeFailed
    );
}

#[test]
fn a_device_certificate_cannot_pose_as_a_server() {
    let pki = Pki::new();
    let server = pki.device("qalqon.example", "instance-1");
    let device = pki.device("alice", "a1");
    let i = pki.config(
        Role::Initiator,
        Plane::Control,
        TransportCaps::STREAM,
        &device,
        PeerExpectation::Server {
            host: "qalqon.example".into(),
        },
    );
    let r = pki.config(
        Role::Responder,
        Plane::Control,
        TransportCaps::STREAM,
        &server,
        PeerExpectation::Client,
    );
    let mut link = Link::new(i, r);
    link.pump();
    assert!(failure(&link.a_events).is_some());
}

#[test]
fn pre_enrolment_is_allowed_on_the_control_plane_and_refused_on_the_data_plane() {
    let pki = Pki::new();
    let p = pki.provider.as_ref();
    let server = pki.server("qalqon.example");
    let key = p.generate_signing_key().unwrap();
    let chain = qalqon_core::cert::pre_enrolment(p, key.as_ref(), NOW - DAY, NOW + DAY).unwrap();
    let device = Endpoint {
        identity: Arc::from(key),
        chain,
    };

    let i = pki.config(
        Role::Initiator,
        Plane::Control,
        TransportCaps::STREAM,
        &device,
        PeerExpectation::Server {
            host: "qalqon.example".into(),
        },
    );
    let r = pki.config(
        Role::Responder,
        Plane::Control,
        TransportCaps::STREAM,
        &server,
        PeerExpectation::Client,
    );
    let mut link = Link::new(i, r);
    link.pump();
    assert!(established(&link));
    assert_eq!(link.b.peer().unwrap().role, role::PRE_ENROLMENT);

    let bob = pki.device("bob", "b1");
    let i = pki.config(
        Role::Initiator,
        Plane::Data,
        TransportCaps::STREAM,
        &device,
        PeerExpectation::Peer {
            user_id: "bob".into(),
            device_id: None,
        },
    );
    let r = pki.config(
        Role::Responder,
        Plane::Data,
        TransportCaps::STREAM,
        &bob,
        PeerExpectation::Peer {
            user_id: "".into(),
            device_id: None,
        },
    );
    let mut link = Link::new(i, r);
    link.pump();
    assert!(
        failure(&link.b_events).is_some(),
        "R must refuse a pre-enrolment certificate"
    );
}

#[test]
fn an_expired_certificate_reports_peer_revoked() {
    let pki = Pki::new();
    let key = pki.provider.generate_signing_key().unwrap();
    let chain = pki.leaf_times(
        role::DEVICE,
        "bob",
        "b1",
        key.as_ref(),
        NOW - 2 * DAY,
        NOW - DAY,
    );
    let bob = Endpoint {
        identity: Arc::from(key),
        chain,
    };
    let alice = pki.device("alice", "a1");
    let i = pki.config(
        Role::Initiator,
        Plane::Data,
        TransportCaps::STREAM,
        &alice,
        PeerExpectation::Peer {
            user_id: "bob".into(),
            device_id: None,
        },
    );
    let r = pki.config(
        Role::Responder,
        Plane::Data,
        TransportCaps::STREAM,
        &bob,
        PeerExpectation::Peer {
            user_id: "alice".into(),
            device_id: None,
        },
    );
    let mut link = Link::new(i, r);
    link.pump();
    assert_eq!(
        failure(&link.a_events).unwrap().code,
        ErrorCode::PeerRevoked
    );
}

#[test]
fn a_certificate_from_another_ca_is_refused() {
    let pki = Pki::new();
    let other = Pki::new();
    let bob = other.device("bob", "b1");
    let alice = pki.device("alice", "a1");
    let i = pki.config(
        Role::Initiator,
        Plane::Data,
        TransportCaps::STREAM,
        &alice,
        PeerExpectation::Peer {
            user_id: "bob".into(),
            device_id: None,
        },
    );
    let r = pki.config(
        Role::Responder,
        Plane::Data,
        TransportCaps::STREAM,
        &bob,
        PeerExpectation::Peer {
            user_id: "alice".into(),
            device_id: None,
        },
    );
    let mut link = Link::new(i, r);
    link.pump();
    assert_eq!(
        failure(&link.a_events).unwrap().code,
        ErrorCode::HandshakeFailed
    );
}

#[test]
fn the_wrong_user_at_rendezvous_is_refused() {
    let pki = Pki::new();
    let (mut a, b) = pki.data_pair(TransportCaps::STREAM);
    a.expectation = PeerExpectation::Peer {
        user_id: "carol".into(),
        device_id: None,
    };
    let mut link = Link::new(a, b);
    link.pump();
    assert!(failure(&link.a_events).is_some());
}

/// Runs one handshake, flipping one bit in one byte of one message on the way.
fn handshake_with_flip(pki: &Pki, message: usize, byte: usize, bit: u8) -> bool {
    let (a, b) = pki.data_pair(TransportCaps::STREAM);
    let mut link = Link::new(a, b);
    let mut sent = 0usize;
    for _ in 0..8 {
        let mut moved = false;
        while let Some(mut frame) = link.a.poll_transmit() {
            if sent == message {
                frame[byte] ^= bit;
            }
            sent += 1;
            link.b.handle_frame(link.now, &frame);
            moved = true;
        }
        while let Some(mut frame) = link.b.poll_transmit() {
            if sent == message {
                frame[byte] ^= bit;
            }
            sent += 1;
            link.a.handle_frame(link.now, &frame);
            moved = true;
        }
        if !moved {
            break;
        }
    }
    link.pump();
    established(&link) && link.a.session_id() == link.b.session_id()
}

#[test]
fn flipping_any_bit_of_any_handshake_message_stops_the_handshake() {
    let pki = Pki::new();
    // XX_INIT, XX_RESP and XX_FINISH, in the order they cross the wire.
    let (a, b) = pki.data_pair(TransportCaps::STREAM);
    let mut clean = Link::new(a, b);
    clean.pump();
    let lengths = [
        clean.frames_a_to_b[0].len(),
        clean.frames_b_to_a[0].len(),
        clean.frames_a_to_b[1].len(),
    ];
    assert!(
        handshake_with_flip(&pki, 99, 0, 1),
        "a run with no flip must succeed"
    );
    for (message, length) in lengths.into_iter().enumerate() {
        for byte in 0..length {
            let bit = 1u8 << (byte % 8);
            assert!(
                !handshake_with_flip(&pki, message, byte, bit),
                "flipping bit {bit:#x} of byte {byte} in message {message} still established"
            );
        }
    }
}

#[test]
fn downgrade_of_the_offered_suites_is_detected() {
    // An attacker removes the stronger suite from XX_INIT. The offer is in the
    // transcript, so the two sides derive different keys.
    let pki = Pki::new();
    let (mut a, mut b) = pki.data_pair(TransportCaps::STREAM);
    a.suites = vec![SUITE_TESTONLY_X25519_ML_KEM_768, SUITE_TESTONLY_X25519];
    b.suites = vec![SUITE_TESTONLY_X25519_ML_KEM_768, SUITE_TESTONLY_X25519];
    let mut link = Link::new(a, b);

    let mut init = link.a.poll_transmit().unwrap();
    // Random is 32 bytes after the 18-byte header, then vec8 versions (1 + 1), then
    // vec8 suites: length 4, 0xFF02, 0xFF01. Swap the two, which selects the weak one.
    let suites_at = 18 + 32 + 2;
    assert_eq!(init[suites_at], 4);
    assert_eq!(
        &init[suites_at + 1..suites_at + 5],
        &[0xFF, 0x02, 0xFF, 0x01]
    );
    init[suites_at + 2] = 0x01;
    init[suites_at + 4] = 0x02;
    link.b.handle_frame(link.now, &init);
    link.pump();
    assert!(
        failure(&link.a_events).is_some(),
        "the changed offer must fail the handshake"
    );
    assert!(!established(&link));
}

#[test]
fn hybrid_suite_completes() {
    let pki = Pki::new();
    let (mut a, mut b) = pki.data_pair(TransportCaps::STREAM);
    a.suites = vec![SUITE_TESTONLY_X25519_ML_KEM_768];
    b.suites = vec![SUITE_TESTONLY_X25519_ML_KEM_768];
    let mut link = Link::new(a, b);
    link.pump();
    assert!(established(&link));
    assert!(link.a_events.iter().any(
        |e| matches!(e, Event::Established { suite, .. } if *suite == SUITE_TESTONLY_X25519_ML_KEM_768)
    ));
}

#[test]
fn no_common_suite_is_rejected_with_a_matching_echo() {
    let pki = Pki::new();
    let (mut a, mut b) = pki.data_pair(TransportCaps::STREAM);
    a.suites = vec![SUITE_TESTONLY_X25519];
    b.suites = vec![SUITE_TESTONLY_X25519_ML_KEM_768];
    let mut link = Link::new(a, b);
    link.pump();
    assert_eq!(
        failure(&link.a_events).unwrap().code,
        ErrorCode::SuiteMismatch
    );
    assert_eq!(
        failure(&link.b_events).unwrap().code,
        ErrorCode::SuiteMismatch
    );
}

#[test]
fn no_common_version_is_rejected() {
    let pki = Pki::new();
    let (mut a, mut b) = pki.data_pair(TransportCaps::STREAM);
    a.versions = vec![0x02];
    b.versions = vec![0x01];
    let mut link = Link::new(a, b);
    link.pump();
    assert_eq!(
        failure(&link.a_events).unwrap().code,
        ErrorCode::VersionMismatch
    );
}

#[test]
fn a_forged_rejection_without_the_echo_is_ignored_on_a_lossy_transport() {
    let pki = Pki::new();
    let (a, b) = pki.data_pair(TransportCaps::DATAGRAM);
    let mut link = Link::new(a, b);
    let header = wire::Header::handshake(wire::VERSION_0_1, 0, msg::HS_REJECT, 34);
    let mut forged = header.encode().to_vec();
    forged.extend_from_slice(&2u16.to_be_bytes());
    forged.extend_from_slice(&[0u8; 32]);
    link.a.handle_frame(link.now, &forged);
    link.pump();
    assert!(
        established(&link),
        "a forged rejection must not stop the handshake"
    );
}

#[test]
fn an_unknown_rendezvous_id_gets_no_answer_at_all() {
    let pki = Pki::new();
    let (mut a, b) = pki.data_pair(TransportCaps::DATAGRAM);
    a.rendezvous_id = Some([1; 16]);
    let mut link = Link::new(a, b);
    let init = link.a.poll_transmit().unwrap();
    link.b.handle_frame(link.now, &init);
    assert!(
        link.b.poll_transmit().is_none(),
        "a stranger must learn nothing"
    );
    assert!(link.b.peer().is_none());
}

#[test]
fn a_session_role_mismatch_is_refused() {
    let pki = Pki::new();
    let server = pki.server("qalqon.example");
    let device = pki.device("alice", "a1");
    // I thinks this is the control plane, R thinks it is the data plane. R has no
    // rendezvous id from I, so it stays silent.
    let i = pki.config(
        Role::Initiator,
        Plane::Control,
        TransportCaps::STREAM,
        &device,
        PeerExpectation::Server {
            host: "qalqon.example".into(),
        },
    );
    let r = pki.config(
        Role::Responder,
        Plane::Data,
        TransportCaps::STREAM,
        &server,
        PeerExpectation::Peer {
            user_id: "alice".into(),
            device_id: None,
        },
    );
    let mut link = Link::new(i, r);
    link.pump();
    assert!(!established(&link));
}

#[test]
fn known_responder_omits_the_chain_and_matches_the_same_transcript_rules() {
    let pki = Pki::new();
    let (a, b) = pki.data_pair(TransportCaps::STREAM);
    let responder_chain = b.chain.clone();

    // First contact, to learn how long XX_RESP is with the chain.
    let mut full = Link::new(a, b);
    full.pump();
    assert!(established(&full));
    let full_len = full.frames_b_to_a[0].len();
    let cached = full.a.peer().unwrap().chain.clone();
    assert_eq!(cached, responder_chain);

    // Now with the cached chain.
    let (mut a, mut b) = pki.data_pair(TransportCaps::STREAM);
    b.chain = responder_chain.clone();
    b.identity = {
        // Reuse the same identity by rebuilding the first pair's keys is not possible
        // here, so give R a fresh key and chain and cache that instead.
        let key = pki.provider.generate_signing_key().unwrap();
        b.chain = pki.leaf(role::DEVICE, "bob", "b1", key.as_ref());
        a.cached_peer_chain = Some(b.chain.clone());
        Arc::from(key)
    };
    let mut known = Link::new(a, b);
    known.pump();
    assert!(established(&known), "{:?}", known.a_events);
    assert!(
        known.frames_b_to_a[0].len() < full_len,
        "XX_RESP must omit the chain"
    );
    assert_eq!(known.a.session_id(), known.b.session_id());
}

#[test]
fn a_stale_cached_chain_falls_back_to_the_full_chain_with_no_extra_round_trip() {
    let pki = Pki::new();
    let (mut a, b) = pki.data_pair(TransportCaps::STREAM);
    let old_key = pki.provider.generate_signing_key().unwrap();
    a.cached_peer_chain = Some(pki.leaf(role::DEVICE, "bob", "b1", old_key.as_ref()));
    let mut link = Link::new(a, b);
    link.pump();
    assert!(established(&link));
    assert_eq!(
        link.frames_a_to_b
            .iter()
            .filter(|f| f[5] == msg::XX_INIT)
            .count(),
        1
    );
    assert_eq!(
        link.frames_b_to_a
            .iter()
            .filter(|f| f[5] == msg::XX_RESP)
            .count(),
        1
    );
}

#[test]
fn pins_block_a_changed_key_and_a_new_device_and_commit_only_after_verification() {
    let pki = Pki::new();
    let pins = PinVerifier::default();

    // First contact pins bob's device.
    let (mut a, b) = pki.data_pair(TransportCaps::STREAM);
    a.verifier = Box::new(pins.clone());
    let mut link = Link::new(a, b);
    link.pump();
    assert!(established(&link));
    assert_eq!(
        link.a.peer().unwrap().status,
        qalqon_core::PinStatus::Pinned
    );

    // The same device with a different key, as a substituting server would obtain.
    let (mut a, b) = pki.data_pair(TransportCaps::STREAM);
    a.verifier = Box::new(pins.clone());
    let mut link = Link::new(a, b);
    link.pump();
    assert_eq!(
        failure(&link.a_events).unwrap().code,
        ErrorCode::PeerIdentityChanged
    );

    // A new device of the same user, which the server could have invented.
    let (mut a, _) = pki.data_pair(TransportCaps::STREAM);
    let other = pki.device("bob", "b2");
    let b = pki.config(
        Role::Responder,
        Plane::Data,
        TransportCaps::STREAM,
        &other,
        PeerExpectation::Peer {
            user_id: "alice".into(),
            device_id: None,
        },
    );
    a.expectation = PeerExpectation::Peer {
        user_id: "bob".into(),
        device_id: None,
    };
    a.verifier = Box::new(pins.clone());
    let mut link = Link::new(a, b);
    link.pump();
    assert_eq!(
        failure(&link.a_events).unwrap().code,
        ErrorCode::PeerIdentityChanged
    );
    assert!(pins.table.lock().unwrap().get("bob", "b2").is_none());
}

#[test]
fn a_failed_signature_does_not_change_a_pin() {
    // A first-contact pin is committed only after the signature and MAC verify. R
    // presents someone else's chain without holding the key.
    let pki = Pki::new();
    let pins = PinVerifier::default();
    let bob_real = pki.device("bob", "b1");
    let (mut a, mut b) = pki.data_pair(TransportCaps::STREAM);
    a.verifier = Box::new(pins.clone());
    b.chain = bob_real.chain.clone(); // But b.identity is a different key.
    let mut link = Link::new(a, b);
    link.pump();
    assert!(failure(&link.a_events).is_some());
    assert!(
        pins.table.lock().unwrap().get("bob", "b1").is_none(),
        "no pin may be committed"
    );
}

#[test]
fn a_seeded_handshake_is_reproducible() {
    let run = || {
        let provider: Arc<TestOnlyProvider> = Arc::new(TestOnlyProvider::seeded(b"vectors"));
        let pki = Pki::with_provider(provider);
        let (a, b) = pki.data_pair(TransportCaps::STREAM);
        let mut link = Link::new(a, b);
        link.pump();
        (
            link.a.session_id(),
            link.frames_a_to_b.clone(),
            link.frames_b_to_a.clone(),
        )
    };
    assert_eq!(run(), run());
}

#[test]
fn identical_randomness_does_not_leak_into_different_sessions() {
    let pki = Pki::new();
    let (a1, b1) = pki.data_pair(TransportCaps::STREAM);
    let (a2, b2) = pki.data_pair(TransportCaps::STREAM);
    let mut one = Link::new(a1, b1);
    let mut two = Link::new(a2, b2);
    one.pump();
    two.pump();
    assert_ne!(one.a.session_id(), two.a.session_id());
}

#[test]
fn lossy_handshake_survives_loss_and_duplication() {
    let pki = Pki::new();
    let (a, b) = pki.data_pair(TransportCaps::DATAGRAM);
    let mut link = Link::new(a, b);
    // Lose the first XX_INIT and first XX_RESP, and duplicate everything else.
    let mut lost_init = false;
    let mut lost_resp = false;
    link.fate = Box::new(move |frame| match frame[5] {
        msg::XX_INIT if !lost_init => {
            lost_init = true;
            FrameFate::Drop
        }
        msg::XX_RESP if !lost_resp => {
            lost_resp = true;
            FrameFate::Drop
        }
        _ => FrameFate::Duplicate,
    });
    link.advance(5000);
    assert!(
        established(&link),
        "{:?} / {:?}",
        link.a_events,
        link.b_events
    );
    assert!(link.a_events.contains(&Event::PeerConfirmed));
}

#[test]
fn lossy_handshake_repeats_xx_finish_until_a_record_arrives() {
    let pki = Pki::new();
    let (a, b) = pki.data_pair(TransportCaps::DATAGRAM);
    let mut link = Link::new(a, b);
    // Lose the first KEY_CONFIRM. I must repeat XX_FINISH, and R must confirm again.
    let mut lost_confirm = false;
    link.fate = Box::new(move |frame| {
        if frame[5] == msg::RECORD && !lost_confirm {
            lost_confirm = true;
            FrameFate::Drop
        } else {
            FrameFate::Deliver
        }
    });
    link.pump();
    assert!(!link.a_events.contains(&Event::PeerConfirmed));
    link.advance(3000);
    assert!(
        link.a_events.contains(&Event::PeerConfirmed),
        "{:?}",
        link.a_events
    );
}

#[test]
fn a_spoofed_xx_resp_on_a_lossy_transport_does_not_kill_the_handshake() {
    let pki = Pki::new();
    let (a, b) = pki.data_pair(TransportCaps::DATAGRAM);
    let mut link = Link::new(a, b);
    let header =
        wire::Header::handshake(wire::VERSION_0_1, SUITE_TESTONLY_X25519, msg::XX_RESP, 100);
    let mut spoofed = header.encode().to_vec();
    spoofed.extend_from_slice(&[0x42u8; 100]);
    link.a.handle_frame(link.now, &spoofed);
    link.pump();
    assert!(established(&link), "{:?}", link.a_events);
}

#[test]
fn a_handshake_with_no_answer_times_out() {
    let pki = Pki::new();
    let (a, b) = pki.data_pair(TransportCaps::DATAGRAM);
    let mut link = Link::new(a, b);
    link.fate = Box::new(|_| FrameFate::Drop);
    link.advance(31_000);
    assert_eq!(failure(&link.a_events).unwrap().code, ErrorCode::Timeout);
    assert!(link.a.is_closed());
}

#[test]
fn the_first_datagram_is_padded_and_the_responder_stays_under_the_amplification_limit() {
    let pki = Pki::new();
    let (a, b) = pki.data_pair(TransportCaps::DATAGRAM);
    let mut link = Link::new(a, b);
    link.pump();
    assert!(
        link.frames_a_to_b[0].len() >= 1200,
        "got {}",
        link.frames_a_to_b[0].len()
    );
    let before_finish: usize = link.frames_b_to_a.iter().take(1).map(Vec::len).sum();
    assert!(before_finish <= 3 * link.frames_a_to_b[0].len());
}

#[test]
fn the_amplification_limit_holds_back_a_large_response() {
    // A spoofed source sends one small frame: a hybrid XX_INIT cut down so that R has
    // received far less than a third of what it would send.
    let pki = Pki::new();
    let (mut a, mut b) = pki.data_pair(TransportCaps {
        ordered: false,
        reliable: false,
        max_frame_len: 600,
    });
    a.suites = vec![SUITE_TESTONLY_X25519_ML_KEM_768];
    b.suites = vec![SUITE_TESTONLY_X25519_ML_KEM_768];
    let mut i = Session::new(a, NOW).unwrap();
    let mut r = Session::new(b, NOW).unwrap();
    let mut received = 0usize;
    let mut sent = 0usize;
    while let Some(frame) = i.poll_transmit() {
        received += frame.len();
        r.handle_frame(NOW, &frame);
    }
    while let Some(frame) = r.poll_transmit() {
        sent += frame.len();
    }
    assert!(sent <= 3 * received, "sent {sent}, received {received}");
}

#[test]
fn fragmented_handshake_completes_when_fragments_are_small_reordered_and_duplicated() {
    let pki = Pki::new();
    let caps = TransportCaps {
        ordered: false,
        reliable: false,
        max_frame_len: 300,
    };
    let (mut a, mut b) = pki.data_pair(caps);
    a.suites = vec![SUITE_TESTONLY_X25519_ML_KEM_768];
    b.suites = vec![SUITE_TESTONLY_X25519_ML_KEM_768];
    let mut link = Link::new(a, b);
    let mut n = 0u32;
    link.fate = Box::new(move |_| {
        n += 1;
        match n % 5 {
            1 => FrameFate::Delay,
            2 => FrameFate::Duplicate,
            _ => FrameFate::Deliver,
        }
    });
    link.advance(20_000);
    assert!(
        established(&link),
        "{:?} / {:?}",
        link.a_events,
        link.b_events
    );
    assert!(link.frames_a_to_b.iter().any(|f| f[5] == msg::HS_FRAGMENT));
}

#[test]
fn a_fragment_that_changes_earlier_bytes_is_invalid() {
    use qalqon_core::frag::{Reassembler, fragment};
    let header = wire::Header::handshake(1, 0, msg::XX_INIT, 100);
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(&[7u8; 100]);
    let parts = fragment(&frame, 60).unwrap();
    assert!(parts.len() > 1);
    let mut r = Reassembler::new();
    let (h0, b0) = wire::parse_frame(&parts[0]).unwrap();
    assert!(r.push(&h0, b0).unwrap().is_none());
    let mut changed = parts[0].clone();
    *changed.last_mut().unwrap() ^= 1;
    let (h1, b1) = wire::parse_frame(&changed).unwrap();
    assert!(r.push(&h1, b1).is_err());
}
