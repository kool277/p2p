//! Two Rust peers over real sockets, for the Phase 1 gate: "two Rust peers interoperate
//! over TCP and UDP". Each is its own process.
//!
//! ```text
//! peer-demo listen  <tcp|udp> <addr> <pki-dir> <me> <peer> [options]
//! peer-demo connect <tcp|udp> <addr> <pki-dir> <me> <peer> [options]
//! ```
//!
//! `<me>` and `<peer>` are `user/device`. Options: `--records N`, `--rekey-after N`,
//! `--loss PERCENT` (drops outgoing frames on purpose). The initiator sends `N` numbered
//! messages, the responder echoes each one, and both print one JSON summary. The exit
//! code is 0 only if the session ended cleanly and the checks passed.

use crypto_provider::{CryptoProvider, from_hex, to_hex};

/// Records allowed in flight. UDP has no flow control, so without this a fast sender
/// simply overruns the receiver's socket buffer.
const WINDOW: u32 = 64;
/// How long a full window may sit without an echo before its records count as lost.
const STALL_MS: u64 = 100;
use provider_testonly::TestOnlyProvider;
use qalqon_core::cert;
use qalqon_core::session::{Limits, Plane, Role, SessionConfig};
use qalqon_core::wire::reason;
use qalqon_core::{ChannelOptions, Event, PeerExpectation, Session, UncheckedPeers};
use qalqon_transport::{Link, now_ms};
use qalqon_transport_tcp::TcpLink;
use qalqon_transport_udp::UdpLink;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Drops outgoing frames, deterministically, to exercise a lossy transport.
struct Lossy<L> {
    inner: L,
    percent: u32,
    counter: u32,
}

impl<L: Link> Link for Lossy<L> {
    fn caps(&self) -> qalqon_core::session::TransportCaps {
        self.inner.caps()
    }
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.counter = self.counter.wrapping_add(1);
        // A multiplier that spreads the counter over 0..100.
        if self.counter.wrapping_mul(2_654_435_761) % 100 < self.percent {
            return Ok(());
        }
        self.inner.send(frame)
    }
    fn recv(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        self.inner.recv(timeout)
    }
}

struct Options {
    records: u32,
    rekey_after: u64,
    loss: u32,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        records: 1000,
        rekey_after: 1 << 32,
        loss: 0,
    };
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let number: u64 = value
            .parse()
            .map_err(|_| format!("{flag}: {value} is not a number"))?;
        match flag.as_str() {
            "--records" => options.records = number as u32,
            "--rekey-after" => options.rekey_after = number,
            "--loss" => options.loss = number as u32,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    Ok(options)
}

fn read_hex(path: &Path) -> Result<Vec<u8>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    from_hex(text.trim()).ok_or_else(|| format!("{} is not hex", path.display()))
}

fn run() -> Result<bool, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [mode, transport, addr, pki, me, peer, rest @ ..] = args.as_slice() else {
        return Err(
            "usage: peer-demo <listen|connect> <tcp|udp> <addr> <pki-dir> <me> <peer> [options]"
                .into(),
        );
    };
    let options = parse_options(rest)?;
    let (my_user, my_device) = me.split_once('/').ok_or("<me> must be user/device")?;
    let (peer_user, peer_device) = peer.split_once('/').ok_or("<peer> must be user/device")?;
    let is_initiator = match mode.as_str() {
        "connect" => true,
        "listen" => false,
        _ => return Err(format!("unknown mode {mode}")),
    };

    let provider: Arc<dyn CryptoProvider> = Arc::new(TestOnlyProvider::new());
    let dir = Path::new(pki);
    let key_bytes = read_hex(&dir.join(format!("device-{my_user}-{my_device}.key")))?;
    let identity = provider
        .import_signing_key(&key_bytes)
        .map_err(|e| e.to_string())?;
    let chain = read_hex(&dir.join(format!("device-{my_user}-{my_device}.chain")))?;
    let roots = cert::parse_many(provider.as_ref(), &read_hex(&dir.join("root.cert"))?)
        .map_err(|e| format!("{e:?}"))?;

    let mut link: Box<dyn Link> = match transport.as_str() {
        "tcp" if is_initiator => {
            let stream = connect_tcp(addr)?;
            Box::new(TcpLink::new(stream).map_err(|e| e.to_string())?)
        }
        "tcp" => {
            let listener = TcpListener::bind(addr).map_err(|e| e.to_string())?;
            let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
            Box::new(TcpLink::new(stream).map_err(|e| e.to_string())?)
        }
        "udp" => {
            let socket = if is_initiator {
                let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
                socket.connect(addr).map_err(|e| e.to_string())?;
                socket
            } else {
                let socket = UdpSocket::bind(addr).map_err(|e| e.to_string())?;
                // Learn the peer's address from its first datagram.
                let mut first = [0u8; 2048];
                socket
                    .set_read_timeout(Some(Duration::from_secs(30)))
                    .map_err(|e| e.to_string())?;
                let (_, from) = socket.peek_from(&mut first).map_err(|e| e.to_string())?;
                socket.connect(from).map_err(|e| e.to_string())?;
                socket
            };
            Box::new(Lossy {
                inner: UdpLink::new(socket),
                percent: options.loss,
                counter: 0,
            })
        }
        _ => return Err(format!("unknown transport {transport}")),
    };

    let strict = link.caps().is_strict();
    let mut session = Session::new(
        SessionConfig {
            provider: provider.clone(),
            role: if is_initiator {
                Role::Initiator
            } else {
                Role::Responder
            },
            plane: Plane::Data,
            transport: link.caps(),
            identity: Arc::from(identity),
            chain,
            roots,
            expectation: PeerExpectation::Peer {
                user_id: peer_user.into(),
                device_id: Some(peer_device.into()),
            },
            verifier: Box::new(UncheckedPeers),
            versions: SessionConfig::default_versions(),
            suites: provider.suites().to_vec(),
            cached_peer_chain: None,
            rendezvous_id: Some([0x42; 16]),
            limits: Limits {
                rekey_records: options.rekey_after,
                ..Limits::default()
            },
        },
        now_ms(),
    )
    .map_err(|f| format!("{}: {}", f.code.name(), f.detail))?;

    // One channel. Strict transports get a reliable, ordered one.
    let mut channel = None;
    let mut next_to_send = 0u32;
    let mut received = BTreeSet::new();
    let mut echoes = BTreeSet::new();
    let mut failure: Option<String> = None;
    let mut clean_close = None;
    let mut last_progress = now_ms();
    let mut written_off = 0u32;
    let mut session_id = None;
    let mut suite = 0u16;
    let mut peer_seen = None;
    let quiet_limit = if strict { 15_000 } else { 1_000 };

    let give_up_at = now_ms() + 120_000;
    let finished = loop {
        qalqon_transport::flush(&mut session, link.as_mut()).map_err(|e| e.to_string())?;
        while let Some(event) = session.poll_event() {
            match event {
                Event::Established {
                    peer,
                    session_id: id,
                    suite: selected,
                    ..
                } => {
                    session_id = Some(id);
                    suite = selected;
                    peer_seen = Some(format!("{}/{}", peer.subject_a, peer.subject_b));
                    if is_initiator {
                        let options = ChannelOptions {
                            ordered: strict,
                            reliable: strict,
                            label: "demo".into(),
                        };
                        channel = Some(
                            session
                                .open_channel(now_ms(), options)
                                .map_err(|e| e.name().to_string())?,
                        );
                    }
                }
                Event::ChannelRequested { channel_id, .. } => {
                    session
                        .accept_channel(now_ms(), channel_id)
                        .map_err(|e| e.name().to_string())?;
                    channel = Some(channel_id);
                }
                Event::ChannelRejected { reason, .. } => {
                    failure = Some(format!("channel rejected: {reason}"))
                }
                Event::Message {
                    channel_id,
                    payload,
                } => {
                    last_progress = now_ms();
                    if is_initiator {
                        echoes.insert(number(&payload)?);
                    } else {
                        received.insert(number(&payload)?);
                        session
                            .send(now_ms(), channel_id, &payload)
                            .map_err(|e| e.name().to_string())?;
                    }
                }
                Event::HandshakeFailed(f) => {
                    failure = Some(format!("{}: {}", f.code.name(), f.detail))
                }
                Event::Closed { clean, .. } => clean_close = Some(clean),
                _ => {}
            }
        }
        qalqon_transport::flush(&mut session, link.as_mut()).map_err(|e| e.to_string())?;
        if session.is_closed() {
            break true;
        }
        if now_ms() > give_up_at {
            failure = Some("the run took too long".into());
            break false;
        }

        if let (true, Some(id), true) = (is_initiator, channel, session.is_established()) {
            let in_flight = |sent: u32, written: u32, echoes: &BTreeSet<u32>| {
                sent - (echoes.len() as u32).min(sent) - written
            };
            if !strict
                && in_flight(next_to_send, written_off, &echoes) >= WINDOW
                && now_ms().saturating_sub(last_progress) > STALL_MS
            {
                written_off += in_flight(next_to_send, written_off, &echoes);
                last_progress = now_ms();
            }
            while next_to_send < options.records
                && in_flight(next_to_send, written_off, &echoes) < WINDOW
            {
                let payload = format!("record {next_to_send:06} {}", "x".repeat(64));
                match session.send(now_ms(), id, payload.as_bytes()) {
                    Ok(()) => next_to_send += 1,
                    // The channel opens a moment after the handshake.
                    Err(qalqon_core::ErrorCode::Closed) => break,
                    Err(e) => return Err(e.name().to_string()),
                }
            }
            let all_echoed = echoes.len() as u32 == options.records;
            let quiet = now_ms().saturating_sub(last_progress) > quiet_limit;
            if next_to_send == options.records && (all_echoed || (!strict && quiet)) {
                session.close(now_ms(), reason::NORMAL);
            }
        }
        qalqon_transport::flush(&mut session, link.as_mut()).map_err(|e| e.to_string())?;

        // Wait for the next frame, then take everything already queued.
        let now = now_ms();
        let mut wait = session
            .next_timeout()
            .map_or(5, |t| t.saturating_sub(now))
            .clamp(1, 5);
        loop {
            match link.recv(Duration::from_millis(wait)) {
                Ok(Some(frame)) => {
                    session.handle_frame(now_ms(), &frame);
                    wait = 1;
                }
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    session.on_transport_closed(now_ms());
                    break;
                }
                Err(e) => return Err(e.to_string()),
            }
            if session.is_closed() {
                break;
            }
        }
        session.handle_timeout(now_ms());
    };
    let _ = qalqon_transport::flush(&mut session, link.as_mut());

    let stats = session.stats();
    let delivered = if is_initiator {
        echoes.len()
    } else {
        received.len()
    } as u32;
    // With no loss everything arrives. With loss, an echo has to survive both ways.
    let lost_both_ways = 2 * options.loss.min(50);
    let required = options.records * (100 - lost_both_ways) / 100 * 3 / 4;
    let required = if options.loss == 0 {
        options.records
    } else {
        required
    };
    let right_peer = peer_seen.as_deref() == Some(peer.as_str());
    let rotated = stats.keys_rotated > 0 || options.rekey_after >= 1 << 32;
    let passed = finished
        && failure.is_none()
        && clean_close == Some(true)
        && delivered >= required
        && right_peer
        && rotated;
    println!(
        "{{\"mode\":\"{mode}\",\"transport\":\"{transport}\",\"provider\":\"{}\",\"passed\":{passed},\"session_id\":\"{}\",\"suite\":{suite},\"peer\":{:?},\"records_expected\":{},\"delivered\":{delivered},\"required\":{required},\"keys_rotated\":{},\"records_sent\":{},\"records_received\":{},\"frames_dropped\":{},\"clean_close\":{},\"failure\":{}}}",
        provider.name(),
        session_id.map_or(String::new(), |id| to_hex(&id)),
        peer_seen.unwrap_or_default(),
        options.records,
        stats.keys_rotated,
        stats.records_sent,
        stats.records_received,
        stats.frames_dropped,
        clean_close.map_or("null".to_string(), |c| c.to_string()),
        failure
            .as_ref()
            .map_or("null".to_string(), |f| format!("{f:?}")),
    );
    Ok(passed)
}

fn connect_tcp(addr: &str) -> Result<TcpStream, String> {
    let mut last = None;
    for _ in 0..100 {
        match TcpStream::connect(addr) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "could not connect to {addr}: {}",
        last.map_or(String::new(), |e| e.to_string())
    ))
}

fn number(payload: &[u8]) -> Result<u32, String> {
    let text = std::str::from_utf8(payload).map_err(|_| "a message is not text")?;
    text.split(' ')
        .nth(1)
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("unexpected message: {text}"))
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("peer-demo: {e}");
            std::process::exit(2);
        }
    }
}
