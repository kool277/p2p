//! The record layer, channels, rekeying and closure, against section 9 and 10.

mod common;

use common::*;
use qalqon_core::session::{Limits, TransportCaps};
use qalqon_core::wire::{self, FrameDecoder, msg, reason};
use qalqon_core::{ChannelOptions, ErrorCode, Event};
use std::collections::HashSet;

fn opened(transport: TransportCaps, limits: Limits) -> Link {
    let pki = Pki::new();
    let (mut a, mut b) = pki.data_pair(transport);
    a.limits = limits;
    b.limits = limits;
    let mut link = Link::new(a, b);
    link.pump();
    assert!(
        established(&link),
        "{:?} / {:?}",
        link.a_events,
        link.b_events
    );
    link
}

fn strict() -> Link {
    opened(TransportCaps::STREAM, Limits::default())
}

fn lossy() -> Link {
    opened(TransportCaps::DATAGRAM, Limits::default())
}

fn closed_clean(events: &[Event]) -> Option<bool> {
    events.iter().find_map(|e| match e {
        Event::Closed { clean, .. } => Some(*clean),
        _ => None,
    })
}

#[test]
fn messages_cross_in_both_directions() {
    let mut link = strict();
    let id = open_channel(&mut link, true, true);
    link.a.send(link.now, id, b"hello from a").unwrap();
    link.b.send(link.now, id, b"hello from b").unwrap();
    link.pump();
    assert_eq!(link.messages_at_b(), [(id, b"hello from a".to_vec())]);
    assert_eq!(link.messages_at_a(), [(id, b"hello from b".to_vec())]);
}

#[test]
fn empty_and_large_messages_are_fragmented_and_reassembled() {
    let mut link = strict();
    let id = open_channel(&mut link, true, true);
    let big: Vec<u8> = (0..1_000_000u32).map(|i| i as u8).collect();
    link.a.send(link.now, id, b"").unwrap();
    link.a.send(link.now, id, &big).unwrap();
    link.pump();
    let got = link.messages_at_b();
    assert_eq!(got.len(), 2);
    assert!(got[0].1.is_empty());
    assert_eq!(got[1].1, big);
    assert!(
        link.frames_a_to_b
            .iter()
            .all(|f| f.len() <= wire::MAX_FRAME)
    );
}

#[test]
fn frames_respect_the_transport_limit() {
    let caps = TransportCaps {
        ordered: false,
        reliable: false,
        max_frame_len: 512,
    };
    let mut link = opened(caps, Limits::default());
    let id = open_channel(&mut link, false, false);
    let big = vec![0x5a; 100_000];
    link.a.send(link.now, id, &big).unwrap();
    link.pump();
    assert_eq!(link.messages_at_b(), [(id, big)]);
    assert!(link.frames_a_to_b.iter().all(|f| f.len() <= 512));
}

#[test]
fn sequence_numbers_never_repeat_in_a_direction() {
    let limits = Limits {
        rekey_records: 16,
        ..Limits::default()
    };
    let mut link = opened(TransportCaps::STREAM, limits);
    let id = open_channel(&mut link, true, true);
    for i in 0..200u32 {
        link.a.send(link.now, id, &i.to_be_bytes()).unwrap();
    }
    link.pump();
    let mut seen = HashSet::new();
    for frame in link.frames_a_to_b.iter().filter(|f| f[5] == msg::RECORD) {
        let header = wire::Header::parse(frame).unwrap();
        assert!(seen.insert(header.seq), "seq {:#x} repeated", header.seq);
    }
    // The counter never restarts, so a deleted record shows up even across a rekey.
    let mut counters: Vec<u64> = seen.iter().map(|s| s & 0xFFFF_FFFF_FFFF).collect();
    counters.sort_unstable();
    assert_eq!(counters, (0..counters.len() as u64).collect::<Vec<_>>());
    assert!(
        link.a.send_epoch().unwrap() > 5,
        "this should have rotated many times"
    );
}

#[test]
fn tampering_closes_a_strict_session_uncleanly() {
    let mut link = strict();
    let id = open_channel(&mut link, true, true);
    link.a.send(link.now, id, b"x").unwrap();
    let mut frame = link.a.poll_transmit().unwrap();
    let last = frame.len() - 1;
    frame[last] ^= 1;
    link.b.handle_frame(link.now, &frame);
    link.pump();
    assert_eq!(closed_clean(&link.b_events), Some(false));
    assert!(link.b.is_closed());
}

#[test]
fn every_bit_of_a_record_is_authenticated() {
    let pki = Pki::new();
    let (a, b) = pki.data_pair(TransportCaps::DATAGRAM);
    let mut link = Link::new(a, b);
    link.pump();
    let id = open_channel(&mut link, false, false);
    link.a.send(link.now, id, b"protected payload").unwrap();
    let frame = link.a.poll_transmit().unwrap();
    for byte in 0..frame.len() {
        let mut changed = frame.clone();
        changed[byte] ^= 0x01;
        link.b.handle_frame(link.now, &changed);
    }
    link.pump();
    assert!(
        link.messages_at_b().is_empty(),
        "a changed record was accepted"
    );
    link.b.handle_frame(link.now, &frame);
    link.pump();
    assert_eq!(link.messages_at_b().len(), 1);
}

#[test]
fn a_strict_session_detects_replay_deletion_and_reordering() {
    for attack in ["replay", "delete", "reorder"] {
        let mut link = strict();
        let id = open_channel(&mut link, true, true);
        link.a.send(link.now, id, b"one").unwrap();
        link.a.send(link.now, id, b"two").unwrap();
        let first = link.a.poll_transmit().unwrap();
        let second = link.a.poll_transmit().unwrap();
        match attack {
            "replay" => {
                link.b.handle_frame(link.now, &first);
                link.b.handle_frame(link.now, &first);
            }
            "delete" => link.b.handle_frame(link.now, &second),
            _ => {
                link.b.handle_frame(link.now, &second);
                link.b.handle_frame(link.now, &first);
            }
        }
        link.pump();
        assert_eq!(
            closed_clean(&link.b_events),
            Some(false),
            "{attack} was not detected"
        );
    }
}

#[test]
fn a_deleted_record_is_detected_across_a_rekey() {
    // Section 9.3: the counter runs across epochs, so deleting the last records of
    // an epoch cannot be hidden by the epoch change.
    let mut link = strict();
    let id = open_channel(&mut link, true, true);
    link.a.send(link.now, id, b"will be deleted").unwrap();
    let _deleted = link.a.poll_transmit().unwrap();
    link.a.rotate_keys(link.now).unwrap();
    let update = link.a.poll_transmit().unwrap();
    link.b.handle_frame(link.now, &update);
    link.pump();
    assert_eq!(closed_clean(&link.b_events), Some(false));
}

#[test]
fn deleting_key_update_is_detected() {
    let mut link = strict();
    let id = open_channel(&mut link, true, true);
    link.a.rotate_keys(link.now).unwrap();
    let _deleted_update = link.a.poll_transmit().unwrap();
    link.a.send(link.now, id, b"under the new keys").unwrap();
    let next = link.a.poll_transmit().unwrap();
    link.b.handle_frame(link.now, &next);
    link.pump();
    assert_eq!(closed_clean(&link.b_events), Some(false));
}

#[test]
fn a_lossy_session_ignores_replays_and_keeps_going() {
    let mut link = lossy();
    let id = open_channel(&mut link, false, false);
    link.a.send(link.now, id, b"one").unwrap();
    let frame = link.a.poll_transmit().unwrap();
    link.b.handle_frame(link.now, &frame);
    link.b.handle_frame(link.now, &frame);
    link.b.handle_frame(link.now, &[0xFF; 40]);
    link.pump();
    assert_eq!(link.messages_at_b().len(), 1);
    assert!(link.b.is_established());
    assert!(link.b.stats().frames_dropped >= 2);
}

#[test]
fn lossy_reordering_delivers_all_on_an_unordered_channel_and_drops_late_on_an_ordered_one() {
    for ordered in [false, true] {
        let mut link = lossy();
        let id = open_channel(&mut link, ordered, false);
        link.a.send(link.now, id, b"one").unwrap();
        link.a.send(link.now, id, b"two").unwrap();
        let first = link.a.poll_transmit().unwrap();
        let second = link.a.poll_transmit().unwrap();
        link.b.handle_frame(link.now, &second);
        link.b.handle_frame(link.now, &first);
        link.pump();
        let got: Vec<Vec<u8>> = link.messages_at_b().into_iter().map(|(_, m)| m).collect();
        if ordered {
            assert_eq!(
                got,
                [b"two".to_vec()],
                "an ordered channel must not deliver late"
            );
        } else {
            assert_eq!(got, [b"two".to_vec(), b"one".to_vec()]);
        }
    }
}

#[test]
fn the_replay_window_refuses_records_older_than_1024_entries() {
    let mut link = lossy();
    let id = open_channel(&mut link, false, false);
    link.a.send(link.now, id, b"old").unwrap();
    let old = link.a.poll_transmit().unwrap();
    let mut last = None;
    for _ in 0..1030 {
        link.a.send(link.now, id, b"new").unwrap();
        last = link.a.poll_transmit();
    }
    link.b.handle_frame(link.now, &last.unwrap());
    link.pump();
    let count = link.messages_at_b().len();
    link.b.handle_frame(link.now, &old);
    link.pump();
    assert_eq!(
        link.messages_at_b().len(),
        count,
        "a record outside the window was accepted"
    );
}

#[test]
fn rekeying_by_record_count_keeps_data_flowing() {
    let limits = Limits {
        rekey_records: 32,
        ..Limits::default()
    };
    let mut link = opened(TransportCaps::STREAM, limits);
    let id = open_channel(&mut link, true, true);
    for i in 0..1000u32 {
        link.a.send(link.now, id, &i.to_be_bytes()).unwrap();
    }
    link.pump();
    let got = link.messages_at_b();
    assert_eq!(got.len(), 1000);
    for (i, (_, m)) in got.iter().enumerate() {
        assert_eq!(m, &(i as u32).to_be_bytes());
    }
    let epoch = link.a.send_epoch().unwrap();
    assert!(epoch >= 30, "epoch {epoch}");
    assert_eq!(link.b.recv_epoch(), Some(epoch));
}

#[test]
fn rekeying_by_bytes_and_by_time_including_while_idle() {
    let limits = Limits {
        rekey_bytes: 1024,
        ..Limits::default()
    };
    let mut link = opened(TransportCaps::STREAM, limits);
    let id = open_channel(&mut link, true, true);
    for _ in 0..8 {
        link.a.send(link.now, id, &[0u8; 1000]).unwrap();
    }
    link.pump();
    assert!(
        link.a.send_epoch().unwrap() >= 7,
        "epoch {:?}",
        link.a.send_epoch()
    );
    assert_eq!(link.messages_at_b().len(), 8);

    let limits = Limits {
        rekey_ms: 1000,
        ..Limits::default()
    };
    let mut link = opened(TransportCaps::STREAM, limits);
    assert_eq!(link.a.send_epoch(), Some(0));
    link.advance(3500);
    assert!(
        link.a.send_epoch().unwrap() >= 3,
        "an idle sender must still rotate"
    );
    assert!(link.b.send_epoch().unwrap() >= 3);
    assert_eq!(link.a.recv_epoch(), link.b.send_epoch());
}

#[test]
fn the_limits_can_be_lowered_but_never_raised_above_the_protocol_maximum() {
    let limits = Limits {
        rekey_records: u64::MAX,
        rekey_bytes: u64::MAX,
        rekey_ms: u64::MAX,
        ..Limits::default()
    };
    let mut link = opened(TransportCaps::STREAM, limits);
    let d = Limits::default();
    link.now += d.rekey_ms;
    link.a.handle_timeout(link.now);
    link.pump();
    assert_eq!(
        link.a.send_epoch(),
        Some(1),
        "the one-hour limit must still apply"
    );
}

#[test]
fn a_lossy_receiver_follows_a_lost_key_update_and_keeps_old_keys_for_30_seconds() {
    fn scenario(wait_ms: u64) -> usize {
        let mut link = lossy();
        let id = open_channel(&mut link, false, false);
        // A record from the old epoch, held back past the rotation.
        link.a.send(link.now, id, b"late").unwrap();
        let late = link.a.poll_transmit().unwrap();
        link.a.rotate_send(link.now).unwrap();
        let _lost_update = link.a.poll_transmit().unwrap();
        link.a.send(link.now, id, b"new epoch").unwrap();
        let new_epoch = link.a.poll_transmit().unwrap();

        link.b.handle_frame(link.now, &new_epoch);
        link.pump();
        assert_eq!(
            link.b.recv_epoch(),
            Some(1),
            "the receiver must derive forward"
        );
        assert_eq!(link.messages_at_b().len(), 1);

        link.now += wait_ms;
        link.b.handle_timeout(link.now);
        link.b.handle_frame(link.now, &late);
        link.pump();
        link.messages_at_b().len()
    }
    assert_eq!(
        scenario(29_000),
        2,
        "the old epoch must open during the retention time"
    );
    assert_eq!(scenario(31_000), 1, "a retained key outlived its time");
}

#[test]
fn a_forged_future_epoch_changes_nothing_at_the_receiver() {
    // Section 9.4: a new epoch is committed only after a record opens.
    let mut link = lossy();
    let id = open_channel(&mut link, false, false);
    link.a.rotate_send(link.now).unwrap();
    let _lost = link.a.poll_transmit().unwrap();
    link.a.send(link.now, id, b"real").unwrap();
    let mut forged = link.a.poll_transmit().unwrap();
    let real = forged.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    link.b.handle_frame(link.now, &forged);
    assert_eq!(
        link.b.recv_epoch(),
        Some(0),
        "a forged record must not move the epoch"
    );
    link.b.handle_frame(link.now, &real);
    assert_eq!(link.b.recv_epoch(), Some(1));
}

#[test]
fn a_lossy_receiver_accepts_16_epochs_ahead_but_not_17() {
    for (rotations, accepted) in [(16u32, true), (17, false)] {
        let mut link = lossy();
        let id = open_channel(&mut link, false, false);
        for _ in 0..rotations {
            link.a.rotate_send(link.now).unwrap();
            while link.a.poll_transmit().is_some() {} // Every KEY_UPDATE is lost.
        }
        link.a.send(link.now, id, b"far ahead").unwrap();
        let frame = link.a.poll_transmit().unwrap();
        link.b.handle_frame(link.now, &frame);
        link.pump();
        assert_eq!(
            !link.messages_at_b().is_empty(),
            accepted,
            "{rotations} epochs ahead"
        );
    }
}

#[test]
fn rotate_keys_moves_both_directions_and_completes() {
    let mut link = strict();
    link.a.rotate_keys(link.now).unwrap();
    link.pump();
    assert_eq!(link.a.send_epoch(), Some(1));
    assert_eq!(link.b.send_epoch(), Some(1));
    assert!(link.a_events.contains(&Event::RotationComplete));
    assert!(link.a.is_established() && link.b.is_established());
}

#[test]
fn rotate_requests_do_not_loop_and_combine_within_a_second() {
    let mut link = strict();
    link.a.rotate_keys(link.now).unwrap();
    link.pump();
    let frames = link.frames_a_to_b.len() + link.frames_b_to_a.len();
    link.pump();
    assert_eq!(
        link.frames_a_to_b.len() + link.frames_b_to_a.len(),
        frames,
        "requests must not loop"
    );

    // Three requests inside a second: one served now, the rest deferred into one more.
    link.a.rotate_keys(link.now).unwrap();
    link.pump();
    let served_before = link.b.send_epoch().unwrap();
    link.a.rotate_keys(link.now).unwrap();
    link.pump();
    assert_eq!(
        link.b.send_epoch().unwrap(),
        served_before,
        "must defer within the second"
    );
    link.advance(1100);
    assert_eq!(
        link.b.send_epoch().unwrap(),
        served_before + 1,
        "must serve the deferred request"
    );
}

#[test]
fn a_lost_rotation_request_is_repeated_on_a_lossy_transport() {
    let mut link = lossy();
    let id = open_channel(&mut link, false, false);
    let _ = id;
    link.a.rotate_keys(link.now).unwrap();
    while link.a.poll_transmit().is_some() {}
    link.advance(2000);
    assert!(
        link.a_events.contains(&Event::RotationComplete),
        "{:?}",
        link.a_events
    );
    assert!(link.b.send_epoch().unwrap() >= 1);
}

#[test]
fn a_rotation_the_peer_never_answers_times_out() {
    let mut link = lossy();
    link.fate = Box::new(|_| FrameFate::Drop);
    link.a.rotate_keys(link.now).unwrap();
    link.advance(31_000);
    assert!(link.a_events.contains(&Event::RotationTimedOut));
}

#[test]
fn a_strict_close_is_clean_on_both_sides() {
    let mut link = strict();
    link.a.close(link.now, reason::NORMAL);
    link.pump();
    assert_eq!(closed_clean(&link.a_events), Some(true));
    assert_eq!(closed_clean(&link.b_events), Some(true));
    assert!(link.a.is_closed() && link.b.is_closed());
}

#[test]
fn truncation_is_reported_as_an_unclean_close() {
    let mut link = strict();
    let id = open_channel(&mut link, true, true);
    link.a.send(link.now, id, b"one").unwrap();
    link.pump();
    link.b.on_transport_closed(link.now);
    link.pump();
    assert_eq!(closed_clean(&link.b_events), Some(false));
}

#[test]
fn a_close_with_no_reply_is_unclean_after_the_timeout() {
    let mut link = strict();
    link.fate = Box::new(|_| FrameFate::Drop);
    link.a.close(link.now, reason::NORMAL);
    link.advance(6000);
    assert_eq!(closed_clean(&link.a_events), Some(false));
}

#[test]
fn a_lossy_close_sends_three_times_with_new_sequence_numbers() {
    let mut link = lossy();
    let before = link.frames_a_to_b.len();
    link.fate = Box::new(|_| FrameFate::Drop);
    link.a.close(link.now, reason::NORMAL);
    link.advance(1000);
    let sent = &link.frames_a_to_b[before..];
    assert_eq!(sent.len(), 3);
    let seqs: HashSet<u64> = sent
        .iter()
        .map(|f| wire::Header::parse(f).unwrap().seq)
        .collect();
    assert_eq!(seqs.len(), 3);
    assert_eq!(closed_clean(&link.a_events), Some(true));
}

#[test]
fn channels_are_independent_and_use_the_right_id_parity() {
    let mut link = strict();
    let one = open_channel(&mut link, true, true);
    let two = open_channel(&mut link, true, true);
    assert_eq!(one % 2, 1);
    assert_eq!(two % 2, 1);
    assert_ne!(one, two);

    let from_b = link
        .b
        .open_channel(
            link.now,
            ChannelOptions {
                ordered: true,
                reliable: true,
                label: "b".into(),
            },
        )
        .unwrap();
    assert_eq!(from_b % 2, 0);
    link.pump();
    link.a.accept_channel(link.now, from_b).unwrap();
    link.pump();

    link.a.close_channel(link.now, one, reason::NORMAL).unwrap();
    link.pump();
    assert!(link.b_events.iter().any(
        |e| matches!(e, Event::ChannelClosed { channel_id, clean: true, .. } if *channel_id == one)
    ));
    assert_eq!(link.a.send(link.now, one, b"x"), Err(ErrorCode::Closed));
    link.a.send(link.now, two, b"still open").unwrap();
    link.b.send(link.now, from_b, b"this too").unwrap();
    link.pump();
    assert_eq!(link.messages_at_b(), [(two, b"still open".to_vec())]);
    assert_eq!(link.messages_at_a(), [(from_b, b"this too".to_vec())]);
}

#[test]
fn a_reliable_channel_on_a_lossy_transport_is_refused() {
    let mut link = lossy();
    let refused = link.a.open_channel(
        link.now,
        ChannelOptions {
            ordered: true,
            reliable: true,
            label: "x".into(),
        },
    );
    assert_eq!(refused, Err(ErrorCode::TransportUnsupported));
}

#[test]
fn channel_open_and_close_repeat_on_a_lossy_transport_without_an_echo_storm() {
    let mut link = lossy();
    let mut dropped = 0;
    link.fate = Box::new(move |_| {
        dropped += 1;
        if dropped <= 2 {
            FrameFate::Drop
        } else {
            FrameFate::Deliver
        }
    });
    let id = link
        .a
        .open_channel(
            link.now,
            ChannelOptions {
                ordered: false,
                reliable: false,
                label: "x".into(),
            },
        )
        .unwrap();
    link.advance(2000);
    link.b.accept_channel(link.now, id).unwrap();
    link.advance(2000);
    assert!(
        link.a_events
            .iter()
            .any(|e| matches!(e, Event::ChannelOpened { .. })),
        "{:?}",
        link.a_events
    );

    let mut dropped = 0;
    link.fate = Box::new(move |_| {
        dropped += 1;
        if dropped == 1 {
            FrameFate::Drop
        } else {
            FrameFate::Deliver
        }
    });
    link.a.close_channel(link.now, id, reason::NORMAL).unwrap();
    link.advance(3000);
    let closed = |events: &[Event]| {
        events
            .iter()
            .filter(|e| matches!(e, Event::ChannelClosed { .. }))
            .count()
    };
    assert_eq!(closed(&link.a_events), 1);
    assert_eq!(closed(&link.b_events), 1);
    let frames = link.frames_a_to_b.len() + link.frames_b_to_a.len();
    link.advance(10_000);
    assert_eq!(
        link.frames_a_to_b.len() + link.frames_b_to_a.len(),
        frames,
        "close must not echo forever"
    );
}

#[test]
fn a_channel_nobody_answers_times_out() {
    let mut link = lossy();
    let id = link
        .a
        .open_channel(
            link.now,
            ChannelOptions {
                ordered: false,
                reliable: false,
                label: "x".into(),
            },
        )
        .unwrap();
    link.advance(31_000);
    assert!(link.a_events.iter().any(
        |e| matches!(e, Event::ChannelRejected { channel_id, reason: r } if *channel_id == id && *r == reason::TIMEOUT)
    ));
}

#[test]
fn control_records_are_refused_on_the_data_plane() {
    let mut link = strict();
    assert_eq!(
        link.a.send_control(link.now, b"x"),
        Err(ErrorCode::InvalidState)
    );
}

#[test]
fn messages_over_the_limit_are_refused_by_the_sender_and_the_receiver() {
    let limits = Limits {
        max_message: 4096,
        ..Limits::default()
    };
    let mut link = opened(TransportCaps::STREAM, limits);
    let id = open_channel(&mut link, true, true);
    assert_eq!(
        link.a.send(link.now, id, &[0u8; 4097]),
        Err(ErrorCode::MessageTooLarge)
    );

    // A sender with a higher limit than the receiver's.
    let pki = Pki::new();
    let (a, mut b) = pki.data_pair(TransportCaps::STREAM);
    b.limits = limits;
    let mut link = Link::new(a, b);
    link.pump();
    let id = open_channel(&mut link, true, true);
    link.a.send(link.now, id, &vec![0u8; 200_000]).unwrap();
    link.pump();
    assert!(link.b_events.iter().any(
        |e| matches!(e, Event::ChannelClosed { reason: r, clean: false, .. } if *r == reason::MESSAGE_TOO_LARGE)
    ), "{:?}", link.b_events.last());
}

#[test]
fn a_partial_message_on_a_lossy_transport_times_out_and_frees_its_memory() {
    let caps = TransportCaps {
        ordered: false,
        reliable: false,
        max_frame_len: 300,
    };
    let mut link = opened(caps, Limits::default());
    let id = open_channel(&mut link, false, false);
    link.a.send(link.now, id, &[1u8; 1000]).unwrap();
    let first = link.a.poll_transmit().unwrap();
    while link.a.poll_transmit().is_some() {}
    link.b.handle_frame(link.now, &first);
    let before = link.b.next_timeout().unwrap();
    assert!(before <= link.now + 30_000);
    link.now += 30_000;
    link.b.handle_timeout(link.now);
    link.pump();
    assert!(link.messages_at_b().is_empty());
    // Sending the same message again delivers it, which shows the state was cleared.
    link.a.send(link.now, id, b"next").unwrap();
    link.pump();
    assert_eq!(link.messages_at_b().len(), 1);
}

#[test]
fn keepalive_answers_ping_and_notices_a_dead_peer() {
    let limits = Limits {
        keepalive_ms: Some(1000),
        ..Limits::default()
    };
    let mut link = opened(TransportCaps::STREAM, limits);
    link.advance(5000);
    assert!(link.a.is_established() && link.b.is_established());
    link.fate = Box::new(|_| FrameFate::Drop);
    link.advance(5000);
    assert_eq!(closed_clean(&link.a_events), Some(false));
}

#[test]
fn frame_decoder_splits_a_byte_stream_however_it_arrives() {
    let mut link = strict();
    let id = open_channel(&mut link, true, true);
    link.a.send(link.now, id, b"one").unwrap();
    link.a.send(link.now, id, b"two").unwrap();
    let first = link.a.poll_transmit().unwrap();
    let second = link.a.poll_transmit().unwrap();
    let mut stream = first.clone();
    stream.extend_from_slice(&second);

    let mut decoder = FrameDecoder::new();
    let mut out = Vec::new();
    for byte in &stream {
        decoder.push(&[*byte]);
        while let Some(frame) = decoder.next_frame().unwrap() {
            out.push(frame);
        }
    }
    assert_eq!(out, [first, second]);

    let mut bad = FrameDecoder::new();
    bad.push(b"HTTP/1.1 400");
    assert!(bad.next_frame().is_err());
}

#[test]
fn the_engine_never_panics_on_a_closed_session() {
    let mut link = strict();
    link.a.close(link.now, reason::NORMAL);
    link.pump();
    assert_eq!(link.a.send(link.now, 1, b"x"), Err(ErrorCode::Closed));
    link.a.handle_frame(link.now, &[1, 2, 3]);
    link.a.handle_timeout(link.now + 1_000_000);
    link.a.close(link.now, reason::NORMAL);
    assert!(link.a.next_timeout().is_none());
}
