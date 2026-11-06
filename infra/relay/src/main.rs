//! The blind relay (build prompt §1.1). It forwards frames it cannot decrypt and holds
//! no session keys. Its only secret is the key it shares with the server for checking
//! grants, which is opened by reference.
//!
//! ```text
//! qalqon-relay --listen 127.0.0.1:9100 --relay-key file:/path/to/keys#relay
//! ```
//!
//! A client's first WebSocket message is `rendezvous_id[16]; vec8 token`. Once two
//! clients with valid grants hold the same ID, each receives one byte, `0x01`, and from
//! then on every message from one goes to the other unchanged.

use crypto_provider::{CryptoProvider, KeyStore};
use qalqon_core::relay;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tungstenite::Message;

const JOIN_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(2);
const MAX_FRAME: usize = 18 + 65_535;
const MAX_ROOMS: usize = 100_000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Whoever joined first waits here, until the second arrives.
type Waiting = (u64, Sender<Message>, Sender<Sender<Message>>);

#[derive(Default)]
struct Rooms {
    waiting: Mutex<HashMap<[u8; 16], Waiting>>,
    next: Mutex<u64>,
}

fn handle(
    stream: TcpStream,
    rooms: Arc<Rooms>,
    provider: Arc<dyn CryptoProvider>,
    key: Arc<Vec<u8>>,
) {
    let _ = stream.set_nodelay(true);
    if stream.set_read_timeout(Some(JOIN_TIMEOUT)).is_err() {
        return;
    }
    let Ok(mut socket) = tungstenite::accept(stream) else {
        return;
    };

    let id = loop {
        match socket.read() {
            Ok(Message::Binary(join)) => {
                let Ok((id, token)) = relay::parse_join(&join) else {
                    return;
                };
                if !relay::check_token(provider.as_ref(), &key, &id, token, now_ms()) {
                    return;
                }
                break id;
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
            _ => return,
        }
    };

    // This connection's own outbox, and a way to learn the other side's.
    let (to_me, my_outbox) = channel::<Message>();
    let (peer_sender_tx, peer_sender_rx) = channel::<Sender<Message>>();
    let my_number = {
        let mut next = rooms.next.lock().unwrap_or_else(|e| e.into_inner());
        *next += 1;
        *next
    };
    {
        let mut waiting = rooms.waiting.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, first_outbox, first_tell)) = waiting.remove(&id) {
            let _ = first_tell.send(to_me.clone());
            let _ = peer_sender_tx.send(first_outbox);
        } else {
            if waiting.len() >= MAX_ROOMS {
                return;
            }
            waiting.insert(id, (my_number, to_me.clone(), peer_sender_tx));
        }
    }

    // Wait to be paired, while noticing if this client goes away.
    let inner_read_timeout =
        |s: &mut tungstenite::WebSocket<TcpStream>, d| s.get_mut().set_read_timeout(Some(d));
    if inner_read_timeout(&mut socket, POLL).is_err() {
        return;
    }
    let started = now_ms();
    let peer = loop {
        if let Ok(peer) = peer_sender_rx.try_recv() {
            break peer;
        }
        let gone = match socket.read() {
            Ok(Message::Close(_)) => true,
            Ok(_) => false,
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                false
            }
            Err(_) => true,
        };
        if gone || now_ms().saturating_sub(started) > JOIN_TIMEOUT.as_millis() as u64 {
            let mut waiting = rooms.waiting.lock().unwrap_or_else(|e| e.into_inner());
            if waiting.get(&id).is_some_and(|(n, _, _)| *n == my_number) {
                waiting.remove(&id);
            }
            return;
        }
    };
    if socket.write(Message::binary(vec![1u8])).is_err() || socket.flush().is_err() {
        return;
    }

    // Forward until either side ends. Frames are never parsed.
    loop {
        let mut wrote = false;
        while let Ok(message) = my_outbox.try_recv() {
            if socket.write(message).is_err() {
                return;
            }
            wrote = true;
        }
        if wrote && socket.flush().is_err() {
            return;
        }
        match socket.read() {
            Ok(Message::Binary(frame)) => {
                if frame.len() > MAX_FRAME || peer.send(Message::Binary(frame)).is_err() {
                    return;
                }
            }
            Ok(Message::Close(_)) => {
                let _ = peer.send(Message::Close(None));
                return;
            }
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => {
                let _ = peer.send(Message::Close(None));
                return;
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let (Some(listen), Some(key_ref)) = (value("--listen"), value("--relay-key")) else {
        eprintln!("usage: qalqon-relay --listen <addr> --relay-key file:<dir>#<label>");
        std::process::exit(2);
    };
    let provider = qalqon_sdk::provider();
    let Some((location, label)) = key_ref.split_once('#') else {
        eprintln!("--relay-key must look like file:<dir>#<label>");
        std::process::exit(2);
    };
    let path = location.strip_prefix("file:").unwrap_or(location);
    let store = keystore_file::FileKeyStore::open(path).unwrap_or_else(|e| {
        eprintln!("cannot open the key store: {e:?}");
        std::process::exit(1);
    });
    let key = store
        .secret(provider.as_ref(), label, 32)
        .unwrap_or_else(|e| {
            eprintln!("cannot open the relay key: {e:?}");
            std::process::exit(1);
        });
    let key = Arc::new(key.to_vec());
    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("cannot listen on {listen}: {e}");
        std::process::exit(1);
    });
    eprintln!(
        "qalqon-relay listening on {listen} (provider: {})",
        provider.name()
    );
    let rooms = Arc::new(Rooms::default());
    for stream in listener.incoming().flatten() {
        let rooms = rooms.clone();
        let provider = provider.clone();
        let key = key.clone();
        std::thread::spawn(move || handle(stream, rooms, provider, key));
    }
}
