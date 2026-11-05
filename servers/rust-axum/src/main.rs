//! The reference host. It owns the socket, the database and the configuration, and hands
//! every frame to the server core, as `docs/HOST-SPI.md` describes. There is no protocol
//! logic and no key material here.
//!
//! ```text
//! qalqon-axum --listen 127.0.0.1:8443 --db ./qalqon.sqlite --pki ./pki --host localhost \
//!             --relay ws://127.0.0.1:9100/ --admin-token-file ./admin.token
//! ```
//!
//! `--pki` is a directory from `qalqon-ca`. This host serves plain WebSocket, so run it
//! behind TLS anywhere but loopback. Platform TLS must stay on in production.

mod store;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{any, get, post};
use futures_util::{SinkExt, StreamExt};
use qalqon_sdk::api;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

enum ToClient {
    Frame(Vec<u8>),
    Close,
}

#[derive(Clone)]
struct Host {
    core: qalqon_sdk::ServerCore,
    clients: Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<ToClient>>>>,
    admin_token: Arc<String>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// The effect loop: the whole of what the core asks of a host.
fn run_effects(host: Host, mut stores: store::Stores) {
    loop {
        match host.core.poll_effect(1000) {
            Ok(Some(api::Effect::SendFrame { conn_id, frame })) => {
                if let Some(client) = host.clients.lock().unwrap_or_else(|e| e.into_inner()).get(&conn_id) {
                    let _ = client.send(ToClient::Frame(frame));
                }
            }
            Ok(Some(api::Effect::CloseConnection { conn_id, .. })) => {
                if let Some(client) = host.clients.lock().unwrap_or_else(|e| e.into_inner()).get(&conn_id) {
                    let _ = client.send(ToClient::Close);
                }
            }
            Ok(Some(api::Effect::Store { effect_id, store, operation, key, record })) => {
                let (status, record) = stores.perform(store, operation, key, record);
                let _ = host.core.complete_effect(effect_id, status, record);
            }
            Ok(Some(api::Effect::Alarm { severity, summary })) => {
                eprintln!("ALARM {severity:?}: {summary}");
            }
            Ok(None) => {}
            Err(_) => return,
        }
    }
}

async fn qalqon_socket(
    State(host): State<Host>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.max_message_size(18 + 65_535).on_upgrade(move |socket| serve_socket(host, socket, remote))
}

async fn serve_socket(host: Host, socket: WebSocket, remote: SocketAddr) {
    let meta = api::ConnectionMeta { remote_address: remote.to_string() };
    let Ok(conn_id) = host.core.accept(meta) else { return };
    let (sender, mut outbox) = mpsc::unbounded_channel();
    host.clients.lock().unwrap_or_else(|e| e.into_inner()).insert(conn_id, sender);
    let (mut write, mut read) = socket.split();
    let writer = tokio::spawn(async move {
        while let Some(message) = outbox.recv().await {
            match message {
                ToClient::Frame(frame) => {
                    if write.send(Message::Binary(frame.into())).await.is_err() {
                        break;
                    }
                }
                ToClient::Close => {
                    let _ = write.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    });
    while let Some(Ok(message)) = read.next().await {
        match message {
            Message::Binary(frame) => {
                if host.core.on_frame(conn_id, &frame).is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    host.clients.lock().unwrap_or_else(|e| e.into_inner()).remove(&conn_id);
    let _ = host.core.on_close(conn_id);
    writer.abort();
}

async fn healthz(State(host): State<Host>) -> impl IntoResponse {
    match host.core.health() {
        Ok(h) if h.live => (StatusCode::OK, "live".to_string()),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "stopped".to_string()),
    }
}

async fn readyz(State(host): State<Host>) -> impl IntoResponse {
    match host.core.health() {
        Ok(h) if h.ready => (StatusCode::OK, "ready".to_string()),
        Ok(h) => (StatusCode::SERVICE_UNAVAILABLE, h.detail),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
    }
}

async fn metrics(State(host): State<Host>) -> impl IntoResponse {
    match host.core.metrics() {
        Ok(m) => (StatusCode::OK, m.text),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
    }
}

/// The host decides who the caller is, and the core decides what the call means.
async fn admin(
    State(host): State<Host>,
    Path(method): Path<String>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !qalqon_sdk::constant_time_eq(presented.as_bytes(), host.admin_token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "unauthorized".to_string());
    }
    let core = host.core.clone();
    match tokio::task::spawn_blocking(move || core.admin_call(&method, &body)).await {
        Ok(Ok(result)) => (StatusCode::OK, result),
        Ok(Err(e)) => (StatusCode::BAD_REQUEST, e.to_string()),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal".to_string()),
    }
}

fn read_hex_file(path: &std::path::Path) -> Vec<u8> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read {}: {e}", path.display());
        std::process::exit(1);
    });
    hex::decode(text.trim()).unwrap_or_else(|_| {
        eprintln!("{} is not hex", path.display());
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
    let (Some(listen), Some(db), Some(pki), Some(host_name), Some(token_file)) =
        (value("--listen"), value("--db"), value("--pki"), value("--host"), value("--admin-token-file"))
    else {
        eprintln!("usage: qalqon-axum --listen <addr> --db <file> --pki <dir> --host <name> --admin-token-file <file> [--relay <url>]");
        std::process::exit(2);
    };
    let pki = std::path::PathBuf::from(pki);
    let keys = format!("file:{}", pki.join("keys").display());
    let admin_token = std::fs::read_to_string(&token_file).unwrap_or_else(|e| {
        eprintln!("cannot read {token_file}: {e}");
        std::process::exit(1);
    });
    let config = api::ServerConfig {
        identity_key_ref: format!("{keys}#server-{host_name}"),
        chain: read_hex_file(&pki.join(format!("server-{host_name}.chain"))),
        ca_bundle: read_hex_file(&pki.join("root.cert")),
        issuing_key_ref: Some(format!("{keys}#issuing")),
        issuing_certificate: Some(read_hex_file(&pki.join("issuing.cert"))),
        relay_key_ref: format!("{keys}#relay"),
        audit_key_ref: format!("{keys}#audit-log"),
        relay_addresses: value("--relay").into_iter().collect(),
        policy: None,
    };
    let core = qalqon_sdk::create_server_core(config).unwrap_or_else(|e| {
        eprintln!("cannot create the server core: {e}");
        std::process::exit(1);
    });
    let stores = store::Stores::open(&db).unwrap_or_else(|e| {
        eprintln!("cannot open the database: {e}");
        std::process::exit(1);
    });
    let host = Host {
        core: core.clone(),
        clients: Arc::default(),
        admin_token: Arc::new(admin_token.trim().to_string()),
    };

    let effects = host.clone();
    std::thread::Builder::new()
        .name("effects".into())
        .spawn(move || run_effects(effects, stores))
        .expect("spawn the effect loop");

    let ticking = core.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(250));
        loop {
            interval.tick().await;
            if ticking.tick(now_ms()).is_err() {
                return;
            }
        }
    });

    let app = Router::new()
        .route("/qalqon", any(qalqon_socket))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/admin/{method}", post(admin))
        .with_state(host);
    let listener = tokio::net::TcpListener::bind(&listen).await.unwrap_or_else(|e| {
        eprintln!("cannot listen on {listen}: {e}");
        std::process::exit(1);
    });
    eprintln!("qalqon-axum listening on {listen} (provider: {})", qalqon_sdk::provider_name());
    let served = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    if let Err(e) = served {
        eprintln!("the server stopped: {e}");
    }
    let _ = core.shutdown();
}
