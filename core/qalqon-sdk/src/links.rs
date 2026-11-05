//! The built-in transports: WebSocket to a server or relay, and direct TCP to a peer.
//!
//! Each link has a thread that owns its socket. Direct connections use TCP candidates
//! from `PEER_SIGNAL`. There is no NAT hole punching here yet, so a peer behind a NAT is
//! reached through the relay. QUIC or WebRTC is the path to a real direct connection
//! across NATs, and `PLAN.md` records it as an open item.

use crate::Shared;
use crate::now_ms;
use qalqon_api as api;
use qalqon_api::TransportCommand;
use qalqon_core::wire::FrameDecoder;
use serde_json::json;
use std::collections::HashMap;
use std::io::{ErrorKind as IoKind, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

const STREAM_CAPS: api::TransportCaps = api::TransportCaps {
    ordered: true,
    reliable: true,
    max_frame_len: 65_553,
};
const WS_POLL: Duration = Duration::from_millis(2);
const DIRECT_ACCEPT_WINDOW: Duration = Duration::from_secs(10);

enum Outbound {
    Frame(Vec<u8>),
    Signal(Vec<u8>),
    Close,
}

#[derive(Default)]
pub(crate) struct LinkTable {
    links: Mutex<HashMap<u64, Sender<Outbound>>>,
}

impl LinkTable {
    pub(crate) fn any_open(&self) -> bool {
        !self
            .links
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    fn insert(&self, id: u64, sender: Sender<Outbound>) {
        self.links
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, sender);
    }

    fn remove(&self, id: u64) {
        self.links
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }

    fn send(&self, id: u64, message: Outbound) {
        if let Some(sender) = self
            .links
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
        {
            let _ = sender.send(message);
        }
    }
}

fn report_opened(shared: &Shared, link: u64) {
    shared.lock().link_opened(now_ms(), link, STREAM_CAPS);
    shared.poke();
}

fn report_closed(shared: &Shared, link: u64) {
    shared.links.remove(link);
    shared.lock().link_closed(now_ms(), link);
    shared.poke();
}

fn report_frame(shared: &Shared, link: u64, frame: &[u8]) {
    shared.lock().frame_received(now_ms(), link, frame);
    shared.poke();
}

/// Performs one command from the core. Nothing here blocks, because each link does its
/// own waiting on its own thread.
pub(crate) fn perform(shared: &Arc<Shared>, command: TransportCommand) {
    match command {
        TransportCommand::OpenLink {
            link_id,
            kind,
            url,
            initiator,
        } => {
            let (sender, receiver) = channel();
            shared.links.insert(link_id, sender);
            let shared = shared.clone();
            let spawned = std::thread::Builder::new()
                .name(format!("qalqon-link-{link_id}"))
                .spawn(move || match kind {
                    api::LinkKind::Server | api::LinkKind::Relay => {
                        run_websocket(&shared, link_id, url.unwrap_or_default(), receiver);
                    }
                    api::LinkKind::Peer if initiator => {
                        run_direct_initiator(&shared, link_id, receiver)
                    }
                    api::LinkKind::Peer => run_direct_responder(&shared, link_id, receiver),
                });
            debug_assert!(spawned.is_ok());
        }
        TransportCommand::SendFrame { link_id, frame } => {
            shared.links.send(link_id, Outbound::Frame(frame))
        }
        TransportCommand::SendSignal { link_id, blob } => {
            shared.links.send(link_id, Outbound::Signal(blob))
        }
        TransportCommand::CloseLink { link_id } => shared.links.send(link_id, Outbound::Close),
    }
}

fn set_read_timeout(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    timeout: Duration,
) -> std::io::Result<()> {
    match socket.get_mut() {
        MaybeTlsStream::Plain(stream) => stream.set_read_timeout(Some(timeout)),
        MaybeTlsStream::Rustls(stream) => stream.sock.set_read_timeout(Some(timeout)),
        _ => Ok(()),
    }
}

fn set_nodelay(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>) {
    let stream = match socket.get_mut() {
        MaybeTlsStream::Plain(stream) => stream,
        MaybeTlsStream::Rustls(stream) => &stream.sock,
        _ => return,
    };
    let _ = stream.set_nodelay(true);
}

fn run_websocket(shared: &Arc<Shared>, link: u64, url: String, outbound: Receiver<Outbound>) {
    let mut socket = match tungstenite::connect(url.as_str()) {
        Ok((socket, _)) => socket,
        Err(_) => return report_closed(shared, link),
    };
    set_nodelay(&mut socket);
    if set_read_timeout(&mut socket, WS_POLL).is_err() {
        return report_closed(shared, link);
    }
    report_opened(shared, link);
    loop {
        let mut pending = false;
        loop {
            match outbound.try_recv() {
                Ok(Outbound::Frame(frame)) => {
                    if socket.write(Message::binary(frame)).is_err() {
                        return report_closed(shared, link);
                    }
                    pending = true;
                }
                Ok(Outbound::Signal(_)) => {}
                Ok(Outbound::Close) | Err(TryRecvError::Disconnected) => {
                    let _ = socket.close(None);
                    let _ = socket.flush();
                    return report_closed(shared, link);
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        if pending && socket.flush().is_err() {
            return report_closed(shared, link);
        }
        match socket.read() {
            Ok(Message::Binary(frame)) => report_frame(shared, link, &frame),
            Ok(Message::Close(_)) => return report_closed(shared, link),
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), IoKind::WouldBlock | IoKind::TimedOut) => {}
            Err(_) => return report_closed(shared, link),
        }
    }
}

/// The addresses this machine might be reachable on.
fn local_addresses() -> Vec<IpAddr> {
    let mut out = vec![IpAddr::from([127, 0, 0, 1])];
    // Connecting a UDP socket sends nothing, and it shows which address routes out.
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0")
        && socket.connect("192.0.2.1:9").is_ok()
        && let Ok(address) = socket.local_addr()
        && !address.ip().is_unspecified()
        && !out.contains(&address.ip())
    {
        out.push(address.ip());
    }
    out
}

fn run_direct_responder(shared: &Arc<Shared>, link: u64, outbound: Receiver<Outbound>) {
    let Ok(listener) = TcpListener::bind("0.0.0.0:0") else {
        return report_closed(shared, link);
    };
    let Ok(port) = listener.local_addr().map(|a| a.port()) else {
        return report_closed(shared, link);
    };
    if listener.set_nonblocking(true).is_err() {
        return report_closed(shared, link);
    }
    let candidates: Vec<String> = local_addresses()
        .into_iter()
        .map(|ip| format!("{ip}:{port}"))
        .collect();
    let blob = json!({ "tcp": candidates }).to_string();
    shared
        .lock()
        .signal_received(now_ms(), link, blob.as_bytes());
    shared.poke();

    let deadline = Instant::now() + DIRECT_ACCEPT_WINDOW;
    let mut held_frames = Vec::new();
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == IoKind::WouldBlock => {}
            Err(_) => return report_closed(shared, link),
        }
        loop {
            match outbound.try_recv() {
                Ok(Outbound::Frame(frame)) => held_frames.push(frame),
                Ok(Outbound::Signal(_)) => {}
                Ok(Outbound::Close) | Err(TryRecvError::Disconnected) => {
                    return report_closed(shared, link);
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        if Instant::now() >= deadline {
            return report_closed(shared, link);
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    run_stream(shared, link, stream, outbound, held_frames);
}

fn run_direct_initiator(shared: &Arc<Shared>, link: u64, outbound: Receiver<Outbound>) {
    let deadline = Instant::now() + DIRECT_ACCEPT_WINDOW;
    let mut held_frames = Vec::new();
    let stream = 'waiting: loop {
        match outbound.recv_timeout(Duration::from_millis(50)) {
            Ok(Outbound::Signal(blob)) => {
                let Ok(signal) = serde_json::from_slice::<serde_json::Value>(&blob) else {
                    continue;
                };
                let Some(candidates) = signal["tcp"].as_array() else {
                    continue;
                };
                for candidate in candidates.iter().filter_map(|c| c.as_str()) {
                    let Ok(address) = candidate.parse() else {
                        continue;
                    };
                    if let Ok(stream) =
                        TcpStream::connect_timeout(&address, Duration::from_millis(800))
                    {
                        break 'waiting stream;
                    }
                }
                return report_closed(shared, link);
            }
            Ok(Outbound::Frame(frame)) => held_frames.push(frame),
            Ok(Outbound::Close) => return report_closed(shared, link),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return report_closed(shared, link);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
        if Instant::now() >= deadline {
            return report_closed(shared, link);
        }
    };
    run_stream(shared, link, stream, outbound, held_frames);
}

/// A connected direct link. Qalqon authenticates the peer on top of this socket, so
/// connecting to it proves nothing and reveals nothing (section 5.4).
fn run_stream(
    shared: &Arc<Shared>,
    link: u64,
    mut stream: TcpStream,
    outbound: Receiver<Outbound>,
    held: Vec<Vec<u8>>,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_nonblocking(false);
    if stream.set_read_timeout(Some(WS_POLL)).is_err() {
        return report_closed(shared, link);
    }
    report_opened(shared, link);
    for frame in held {
        if stream.write_all(&frame).is_err() {
            return report_closed(shared, link);
        }
    }
    let mut decoder = FrameDecoder::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        loop {
            match outbound.try_recv() {
                Ok(Outbound::Frame(frame)) => {
                    if stream.write_all(&frame).is_err() {
                        return report_closed(shared, link);
                    }
                }
                Ok(Outbound::Signal(_)) => {}
                Ok(Outbound::Close) | Err(TryRecvError::Disconnected) => {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return report_closed(shared, link);
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        match stream.read(&mut buffer) {
            Ok(0) => return report_closed(shared, link),
            Ok(n) => {
                decoder.push(&buffer[..n]);
                loop {
                    match decoder.next_frame() {
                        Ok(Some(frame)) => report_frame(shared, link, &frame),
                        Ok(None) => break,
                        Err(_) => return report_closed(shared, link),
                    }
                }
            }
            Err(e) if matches!(e.kind(), IoKind::WouldBlock | IoKind::TimedOut) => {}
            Err(_) => return report_closed(shared, link),
        }
    }
}
