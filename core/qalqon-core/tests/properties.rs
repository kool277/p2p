//! Property tests: what must hold for every input, not only the ones written by hand.

mod common;

use common::*;
use proptest::prelude::*;
use qalqon_core::control::ControlMessage;
use qalqon_core::crl::Crl;
use qalqon_core::frag::{Reassembler, fragment};
use qalqon_core::record::ReplayWindow;
use qalqon_core::session::{Limits, Plane, Role, TransportCaps};
use qalqon_core::wire::{self, FrameDecoder, Header, msg};
use qalqon_core::{ChannelOptions, Event, PeerExpectation, Session};
use std::collections::HashSet;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The window against a plain model: a set of everything seen.
    #[test]
    fn the_replay_window_agrees_with_a_simple_model(counters in prop::collection::vec(0u64..5000, 1..400)) {
        let mut window = ReplayWindow::default();
        let mut seen = HashSet::new();
        let mut top = 0u64;
        for c in counters {
            let fresh_in_window = !seen.contains(&c) && (c >= top || top - c <= 1024);
            prop_assert_eq!(window.check(c), fresh_in_window, "counter {} with top {}", c, top);
            if window.check(c) {
                window.update(c);
                seen.insert(c);
                top = top.max(c + 1);
            }
        }
    }

    /// Reassembly gives back the message whatever order the fragments come in.
    #[test]
    fn fragments_reassemble_in_any_order(
        body in prop::collection::vec(any::<u8>(), 1..5000),
        max_frame in 40usize..600,
        seed in any::<u64>(),
    ) {
        let header = Header::handshake(1, 0, msg::XX_INIT, body.len() as u16);
        let mut frame = header.encode().to_vec();
        frame.extend_from_slice(&body);
        let mut parts = fragment(&frame, max_frame).unwrap();
        // A message that fits in one frame is returned unchanged, with no fragments.
        if frame.len() <= max_frame {
            prop_assert_eq!(parts, vec![frame]);
            return Ok(());
        }
        prop_assert!(parts.iter().all(|p| p.len() <= max_frame));
        // A cheap shuffle, plus a duplicate of the first part.
        let n = parts.len();
        for i in 0..n {
            parts.swap(i, (seed.wrapping_mul(i as u64 + 1) % n as u64) as usize);
        }
        parts.push(parts[0].clone());
        let mut r = Reassembler::new();
        let mut done = None;
        for part in &parts {
            let (h, b) = wire::parse_frame(part).unwrap();
            if let Some(whole) = r.push(&h, b).unwrap() {
                done = Some(whole);
                break;
            }
        }
        prop_assert_eq!(done, Some(frame));
    }

    /// Malformed input is an error, never a panic.
    #[test]
    fn parsers_never_panic(data in prop::collection::vec(any::<u8>(), 0..2000)) {
        let p = provider_testonly::TestOnlyProvider::new();
        let _ = wire::parse_frame(&data);
        let _ = wire::parse_extensions(&data);
        let _ = qalqon_core::cert::parse_many(&p, &data);
        let _ = ControlMessage::decode(&data);
        let _ = qalqon_core::control::parse_grants(&data);
        let _ = qalqon_core::control::parse_channel_options(&data);
        let _ = qalqon_core::relay::parse_join(&data);
        let key = qalqon_core::crypto::PublicKey { algorithm: 0xFF01, key: vec![1; 32] };
        let _ = Crl::verify(&p, &key, &data);
        let mut decoder = FrameDecoder::new();
        decoder.push(&data);
        while let Ok(Some(_)) = decoder.next_frame() {}
    }
}

fn pki_and_pair(transport: TransportCaps, limits: Limits) -> (Session, Session) {
    let pki = Pki::new();
    let (mut a, mut b) = pki.data_pair(transport);
    a.limits = limits;
    b.limits = limits;
    (Session::new(a, NOW).unwrap(), Session::new(b, NOW).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Random bytes at any stage of a session never panic, and on a lossy session they
    /// never stop it either.
    #[test]
    fn a_lossy_session_survives_garbage_at_every_stage(
        garbage in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..300), 0..24),
    ) {
        let (mut i, mut r) = pki_and_pair(TransportCaps::DATAGRAM, Limits::default());
        let mut feed = garbage.into_iter();
        for _ in 0..6 {
            if let Some(junk) = feed.next() {
                i.handle_frame(NOW, &junk);
                r.handle_frame(NOW, &junk);
            }
            while let Some(frame) = i.poll_transmit() {
                r.handle_frame(NOW, &frame);
            }
            while let Some(frame) = r.poll_transmit() {
                i.handle_frame(NOW, &frame);
            }
        }
        for junk in feed {
            i.handle_frame(NOW, &junk);
            r.handle_frame(NOW, &junk);
        }
        prop_assert!(i.is_established());
        prop_assert!(r.is_established());
    }

    /// Every header bit counts: garbage shaped like a real record, with valid magic and
    /// type, still never opens.
    #[test]
    fn a_forged_record_never_delivers(
        channel in any::<u16>(),
        seq in any::<u64>(),
        body in prop::collection::vec(any::<u8>(), 33..300),
    ) {
        let (mut i, mut r) = pki_and_pair(TransportCaps::DATAGRAM, Limits::default());
        for _ in 0..4 {
            while let Some(frame) = i.poll_transmit() {
                r.handle_frame(NOW, &frame);
            }
            while let Some(frame) = r.poll_transmit() {
                i.handle_frame(NOW, &frame);
            }
        }
        while r.poll_event().is_some() {}
        let header = Header {
            version: wire::VERSION_0_1,
            suite_id: qalqon_core::crypto::suite::SUITE_TESTONLY_X25519,
            msg_type: msg::RECORD,
            channel_id: channel,
            seq,
            length: body.len() as u16,
        };
        let mut frame = header.encode().to_vec();
        frame.extend_from_slice(&body);
        r.handle_frame(NOW, &frame);
        prop_assert_eq!(r.poll_event(), None);
    }

    /// Over a network that drops, duplicates and reorders, with rekeys throughout:
    /// a message is delivered at most once, unchanged, and nothing invented appears.
    #[test]
    fn a_hostile_network_cannot_change_or_repeat_messages(
        fates in prop::collection::vec(0u8..10, 1..64),
        count in 1usize..120,
        rekey_after in 4u64..30,
    ) {
        let limits = Limits { rekey_records: rekey_after, ..Limits::default() };
        let pki = Pki::new();
        let (mut a, mut b) = pki.data_pair(TransportCaps::DATAGRAM);
        a.limits = limits;
        b.limits = limits;
        let mut link = Link::new(a, b);
        link.advance(100);
        prop_assert!(established(&link));
        let id = link.a.open_channel(link.now, ChannelOptions { ordered: false, reliable: false, label: "p".into() }).unwrap();
        link.pump();
        link.b.accept_channel(link.now, id).unwrap();
        link.pump();
        prop_assert!(link.a_events.iter().any(|e| matches!(e, Event::ChannelOpened { .. })), "the channel did not open");

        let mut index = 0usize;
        link.fate = Box::new(move |_| {
            index += 1;
            match fates[index % fates.len()] {
                0 | 1 => FrameFate::Drop,
                2 => FrameFate::Duplicate,
                3 => FrameFate::Delay,
                _ => FrameFate::Deliver,
            }
        });
        for n in 0..count {
            link.a.send(link.now, id, format!("message {n}").as_bytes()).unwrap();
            link.pump();
            if n % 7 == 0 {
                link.advance(5);
            }
        }
        link.advance(2000);

        let received = link.messages_at_b();
        let mut seen = HashSet::new();
        for (channel, payload) in received {
            prop_assert_eq!(channel, id);
            let text = String::from_utf8(payload).unwrap();
            let number: usize = text.strip_prefix("message ").unwrap().parse().unwrap();
            prop_assert!(number < count, "an invented message: {}", text);
            prop_assert!(seen.insert(number), "delivered twice: {}", text);
        }
        prop_assert!(link.a.is_established());
        prop_assert!(link.b.is_established());
    }
}

#[test]
fn a_session_built_for_each_role_needs_the_matching_certificate_role() {
    // The role check is on the validated chain, whichever way a peer is configured.
    let pki = Pki::new();
    let server = pki.server("host");
    let client = pki.device("alice", "a1");
    let i = pki.config(
        Role::Initiator,
        Plane::Data,
        TransportCaps::STREAM,
        &client,
        PeerExpectation::Peer { user_id: "host".into(), device_id: None },
    );
    let r = pki.config(
        Role::Responder,
        Plane::Data,
        TransportCaps::STREAM,
        &server,
        PeerExpectation::Peer { user_id: "alice".into(), device_id: None },
    );
    let mut link = Link::new(i, r);
    link.pump();
    assert!(!established(&link), "a server certificate must not work on the data plane");
}
