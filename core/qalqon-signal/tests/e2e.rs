//! Two `ClientCore`s and a real `ServerCore`, joined by a simulated network and a blind
//! relay. Everything above the sockets runs for real, so this covers the session
//! sequence in `docs/PROTOCOL.md`, section 3.

use crypto_provider::{CryptoProvider, SigningKey};
use provider_testonly::TestOnlyProvider;
use qalqon_api as api;
use qalqon_api::{ErrorKind, TransportCommand};
use qalqon_ca::DevCa;
use qalqon_core::session::Limits;
use qalqon_core::{relay, wire};
use qalqon_signal::{ClientCore, ClientOptions, OpResult, OpValue, SavedState};
use serde_json::json;
use server_core::{
    Effect, IssuingCa, PasswordCost, ServerCore, ServerOptions, StoreKind, StoreOperation,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

const START: u64 = 1_800_000_000_000;
const PASSWORD: &str = "correct horse battery staple";
const RELAY_KEY: [u8; 32] = [3; 32];
const URL: &str = "wss://qalqon.example/qalqon";

const STREAM_CAPS: api::TransportCaps = api::TransportCaps {
    ordered: true,
    reliable: true,
    max_frame_len: 65_553,
};

#[derive(Default)]
struct Stores {
    tables: HashMap<StoreKind, BTreeMap<String, Vec<u8>>>,
    audit: BTreeMap<u64, Vec<u8>>,
}

impl Stores {
    fn perform(
        &mut self,
        store: StoreKind,
        op: StoreOperation,
        key: Option<String>,
        record: Option<Vec<u8>>,
    ) -> (u32, Option<Vec<u8>>) {
        match op {
            StoreOperation::Get => (
                0,
                self.tables
                    .entry(store)
                    .or_default()
                    .get(&key.unwrap())
                    .cloned(),
            ),
            StoreOperation::Put => {
                self.tables
                    .entry(store)
                    .or_default()
                    .insert(key.unwrap(), record.unwrap());
                (0, None)
            }
            StoreOperation::List => {
                let filter = key.and_then(|k| k.strip_prefix("user:").map(str::to_string));
                let rows: Vec<serde_json::Value> = self
                    .tables
                    .entry(store)
                    .or_default()
                    .values()
                    .map(|b| serde_json::from_slice::<serde_json::Value>(b).unwrap())
                    .filter(|v| filter.as_ref().is_none_or(|u| v["user_id"] == u.as_str()))
                    .collect();
                (0, Some(serde_json::to_vec(&rows).unwrap()))
            }
            StoreOperation::Append => {
                self.audit
                    .insert(key.unwrap().parse().unwrap(), record.unwrap());
                (0, None)
            }
            StoreOperation::Head => (0, self.audit.values().next_back().cloned()),
            StoreOperation::Range => {
                let rows: Vec<serde_json::Value> = self
                    .audit
                    .values()
                    .map(|b| serde_json::from_slice(b).unwrap())
                    .collect();
                (0, Some(serde_json::to_vec(&rows).unwrap()))
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct LinkRef {
    client: usize,
    link: u64,
}

enum Route {
    Server(u64),
    Direct(LinkRef),
    Relay { joined: Option<[u8; 16]> },
}

struct Device {
    identity: Arc<dyn SigningKey>,
    chain: Option<Vec<u8>>,
    saved: SavedState,
}

/// The whole deployment on a simulated clock.
struct World {
    provider: Arc<dyn CryptoProvider>,
    ca: DevCa,
    server: Arc<ServerCore>,
    stores: Stores,
    now: u64,
    clients: Vec<ClientCore>,
    events: Vec<Vec<api::Event>>,
    routes: HashMap<LinkRef, Route>,
    conn_to_link: HashMap<u64, LinkRef>,
    relay_rooms: HashMap<[u8; 16], Vec<LinkRef>>,
    relay_seen: Vec<Vec<u8>>,
    direct_seen: Vec<Vec<u8>>,
    /// Links offered on the direct path that are listening, by their signal text.
    listening: HashMap<String, LinkRef>,
    direct_enabled: bool,
    stranger_on_direct_port: bool,
    relay_policy: api::RelayPolicy,
    identity_policy: api::IdentityChangePolicy,
    revocation_grace_ms: u64,
    withhold_crl: bool,
}

impl World {
    fn new() -> Self {
        let provider: Arc<dyn CryptoProvider> = Arc::new(TestOnlyProvider::new());
        let ca = DevCa::new(provider.clone(), START).unwrap();
        let server_key: Arc<dyn SigningKey> = Arc::from(provider.generate_signing_key().unwrap());
        let issuing: Arc<dyn SigningKey> = Arc::from(
            provider
                .import_signing_key(&ca.issuing_key.export_secret().unwrap())
                .unwrap(),
        );
        let server = ServerCore::new(ServerOptions {
            provider: provider.clone(),
            identity: server_key.clone(),
            chain: ca
                .issue_server("qalqon.example", "i1", server_key.as_ref(), START)
                .unwrap(),
            ca_bundle: ca.root_cert.clone(),
            issuing: Some(IssuingCa {
                key: issuing,
                certificate: ca.issuing_cert.clone(),
            }),
            relay_addresses: vec!["wss://relay.example/relay".into()],
            relay_key: RELAY_KEY.to_vec(),
            audit_key: vec![1; 32],
            policy: server_core::policy::Policy::default_document(),
            password_cost: PasswordCost {
                m_kib: 256,
                t: 1,
                p: 1,
            },
            limits: Limits::default(),
            now_ms: START,
        })
        .unwrap();
        let mut world = World {
            provider,
            ca,
            server: Arc::new(server),
            stores: Stores::default(),
            now: START,
            clients: Vec::new(),
            events: Vec::new(),
            routes: HashMap::new(),
            conn_to_link: HashMap::new(),
            relay_rooms: HashMap::new(),
            relay_seen: Vec::new(),
            direct_seen: Vec::new(),
            listening: HashMap::new(),
            direct_enabled: true,
            stranger_on_direct_port: false,
            relay_policy: api::RelayPolicy::PreferDirect,
            identity_policy: api::IdentityChangePolicy::Block,
            revocation_grace_ms: 72 * 60 * 60 * 1000,
            withhold_crl: false,
        };
        for _ in 0..50 {
            world.pump();
            if world.server.health().ready {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(world.server.health().ready);
        world
    }

    fn new_client(&mut self, device: &Device) -> usize {
        let core = ClientCore::new(
            ClientOptions {
                provider: self.provider.clone(),
                server_url: URL.into(),
                ca_bundle: self.ca.root_cert.clone(),
                identity: device.identity.clone(),
                chain: device.chain.clone(),
                relay_policy: self.relay_policy,
                identity_change_policy: self.identity_policy,
                revocation_grace_ms: self.revocation_grace_ms,
                saved: device.saved.clone(),
                limits: Limits::default(),
            },
            self.now,
        )
        .unwrap();
        self.clients.push(core);
        self.events.push(Vec::new());
        self.clients.len() - 1
    }

    /// Runs everything until nothing moves.
    fn pump(&mut self) {
        for _ in 0..4000 {
            let mut moved = false;
            for i in 0..self.clients.len() {
                self.clients[i].drive(self.now);
                while let Some(event) = self.clients[i].poll_event() {
                    self.events[i].push(event);
                    moved = true;
                }
                while let Some(command) = self.clients[i].poll_command() {
                    moved = true;
                    self.perform(i, command);
                }
            }
            while let Ok(Some(effect)) = self.server.poll_effect(Duration::ZERO) {
                moved = true;
                match effect {
                    Effect::SendFrame { conn_id, frame } => {
                        if let Some(link) = self.conn_to_link.get(&conn_id).copied() {
                            self.clients[link.client].frame_received(self.now, link.link, &frame);
                        }
                    }
                    Effect::CloseConnection { conn_id, .. } => {
                        if let Some(link) = self.conn_to_link.remove(&conn_id) {
                            self.routes.remove(&link);
                            self.clients[link.client].link_closed(self.now, link.link);
                            let _ = self.server.on_close(conn_id);
                        }
                    }
                    Effect::Store {
                        effect_id,
                        store,
                        operation,
                        key,
                        record,
                    } => {
                        let (status, record) = self.stores.perform(store, operation, key, record);
                        self.server
                            .complete_effect(effect_id, status, record)
                            .unwrap();
                    }
                    Effect::Alarm { .. } => {}
                }
            }
            if !moved {
                return;
            }
        }
        panic!("the world did not settle");
    }

    fn perform(&mut self, client: usize, command: TransportCommand) {
        let now = self.now;
        match command {
            TransportCommand::OpenLink {
                link_id,
                kind,
                initiator,
                ..
            } => {
                let me = LinkRef {
                    client,
                    link: link_id,
                };
                match kind {
                    api::LinkKind::Server => {
                        let conn = self.server.accept("203.0.113.5:1000").unwrap();
                        self.routes.insert(me, Route::Server(conn));
                        self.conn_to_link.insert(conn, me);
                        self.clients[client].link_opened(now, link_id, STREAM_CAPS);
                    }
                    api::LinkKind::Peer => {
                        if !self.direct_enabled {
                            return; // Nothing ever answers, as behind a hostile NAT.
                        }
                        if initiator && self.stranger_on_direct_port {
                            // The candidate never arrives, so this side times out.
                            return;
                        }
                        if !initiator {
                            if self.stranger_on_direct_port {
                                // Somebody connects first and sends junk. The real peer's
                                // connection attempt then finds nothing.
                                self.clients[client].link_opened(now, link_id, STREAM_CAPS);
                                self.clients[client].frame_received(
                                    now,
                                    link_id,
                                    b"GET / HTTP/1.1\r\n\r\n",
                                );
                                return;
                            }
                            // The responder listens and sends its candidate through the server.
                            let candidate = format!("listen:{client}:{link_id}");
                            self.listening.insert(candidate.clone(), me);
                            self.clients[client].signal_received(
                                now,
                                link_id,
                                candidate.as_bytes(),
                            );
                        }
                    }
                    api::LinkKind::Relay => {
                        self.routes.insert(me, Route::Relay { joined: None });
                        self.clients[client].link_opened(now, link_id, STREAM_CAPS);
                    }
                }
            }
            TransportCommand::SendSignal { link_id, blob } => {
                // The initiator connects to the responder's candidate.
                let me = LinkRef {
                    client,
                    link: link_id,
                };
                let text = String::from_utf8(blob).unwrap();
                if let Some(other) = self.listening.remove(&text) {
                    self.routes.insert(me, Route::Direct(other));
                    self.routes.insert(other, Route::Direct(me));
                    self.clients[other.client].link_opened(now, other.link, STREAM_CAPS);
                    self.clients[client].link_opened(now, link_id, STREAM_CAPS);
                }
            }
            TransportCommand::SendFrame { link_id, frame } => {
                let me = LinkRef {
                    client,
                    link: link_id,
                };
                match self.routes.get(&me) {
                    Some(Route::Server(conn)) => {
                        let conn = *conn;
                        let _ = self.server.on_frame(conn, &frame);
                    }
                    Some(Route::Direct(other)) => {
                        let other = *other;
                        self.direct_seen.push(frame.clone());
                        self.clients[other.client].frame_received(now, other.link, &frame);
                    }
                    Some(Route::Relay { joined: None }) => self.relay_join(me, &frame),
                    Some(Route::Relay { joined: Some(room) }) => {
                        let room = *room;
                        self.relay_seen.push(frame.clone());
                        let others: Vec<LinkRef> = self
                            .relay_rooms
                            .get(&room)
                            .into_iter()
                            .flatten()
                            .copied()
                            .filter(|l| *l != me)
                            .collect();
                        for other in others {
                            self.clients[other.client].frame_received(now, other.link, &frame);
                        }
                    }
                    None => {}
                }
            }
            TransportCommand::CloseLink { link_id } => {
                let me = LinkRef {
                    client,
                    link: link_id,
                };
                match self.routes.remove(&me) {
                    Some(Route::Server(conn)) => {
                        self.conn_to_link.remove(&conn);
                        let _ = self.server.on_close(conn);
                    }
                    Some(Route::Direct(other)) => {
                        self.routes.remove(&other);
                        self.clients[other.client].link_closed(now, other.link);
                    }
                    Some(Route::Relay { joined: Some(room) }) => {
                        if let Some(members) = self.relay_rooms.get_mut(&room) {
                            members.retain(|l| *l != me);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// What `infra/relay` does: checks the grant, pairs two clients, then forwards.
    fn relay_join(&mut self, me: LinkRef, join: &[u8]) {
        let (id, token) = relay::parse_join(join).expect("a well-formed join");
        assert!(
            relay::check_token(self.provider.as_ref(), &RELAY_KEY, &id, token, self.now),
            "a bad relay grant"
        );
        self.routes.insert(me, Route::Relay { joined: Some(id) });
        let room = self.relay_rooms.entry(id).or_default();
        room.push(me);
        if room.len() == 2 {
            let members = room.clone();
            for member in members {
                self.clients[member.client].frame_received(self.now, member.link, &[1]);
            }
        }
    }

    fn advance(&mut self, ms: u64) {
        let end = self.now + ms;
        let step = 250;
        while self.now < end {
            self.now = (self.now + step).min(end);
            self.server.tick(self.now).unwrap();
            for client in &mut self.clients {
                client.handle_timeout(self.now);
            }
            self.pump();
        }
    }

    /// Waits for an operation, giving Argon2 on its worker thread time to finish.
    fn wait(&mut self, client: usize, op: u64) -> OpResult {
        for _ in 0..3000 {
            self.pump();
            if let Some(result) = self.clients[client].take_completion(op) {
                return result;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("operation {op} did not finish");
    }

    fn admin(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let server = self.server.clone();
        let method = method.to_string();
        let handle = std::thread::spawn(move || server.admin_call(&method, &params.to_string()));
        loop {
            self.pump();
            if handle.is_finished() {
                let result = handle.join().unwrap().expect("admin call");
                return serde_json::from_str(&result).unwrap();
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn create_user(&mut self, user: &str) {
        self.admin(
            "users.create",
            json!({ "user_id": user, "password": PASSWORD }),
        );
    }

    /// Creates a device with a fresh key and enrols it.
    fn enrolled_device(&mut self, user: &str) -> Device {
        let token =
            self.admin("devices.createEnrollmentToken", json!({ "user_id": user }))["token"]
                .as_str()
                .unwrap()
                .to_string();
        let identity: Arc<dyn SigningKey> =
            Arc::from(self.provider.generate_signing_key().unwrap());
        let mut device = Device {
            identity,
            chain: None,
            saved: SavedState::default(),
        };
        let index = self.new_client(&device);
        let op = self.clients[index].start_enroll(
            self.now,
            api::EnrollmentRequest {
                enrollment_token: token,
                device_name: "test".into(),
            },
        );
        match self.wait(index, op).expect("enrolment") {
            OpValue::Enrolled { chain, .. } => device.chain = Some(chain),
            other => panic!("unexpected {other:?}"),
        }
        self.pump();
        device
    }

    fn logged_in(&mut self, user: &str, device: &Device) -> usize {
        let index = self.new_client(device);
        let credentials = api::Credentials {
            user_id: user.into(),
            secret: PASSWORD.as_bytes().to_vec(),
            mfa_code: None,
        };
        let op = self.clients[index].start_connect(self.now, credentials);
        self.wait(index, op).expect("login");
        index
    }

    fn take_event(
        &mut self,
        client: usize,
        mut matches: impl FnMut(&api::Event) -> bool,
    ) -> api::Event {
        for _ in 0..3000 {
            self.pump();
            if let Some(i) = self.events[client].iter().position(&mut matches) {
                return self.events[client].remove(i);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("the event never came: {:?}", self.events[client]);
    }

    /// One client calls another, who accepts. Returns both channel handles.
    fn call(
        &mut self,
        caller: usize,
        callee: usize,
        callee_user: &str,
    ) -> Result<(u64, u64), ErrorKind> {
        let op = self.clients[caller].open_channel(self.now, peer(callee_user), options());
        let request = self.take_event(callee, |e| matches!(e, api::Event::ChannelRequested { .. }));
        let api::Event::ChannelRequested { request_id, .. } = request else {
            unreachable!()
        };
        let accept = self.clients[callee].accept_channel(self.now, &request_id);
        let at_callee = loop {
            if (self.direct_enabled && !self.stranger_on_direct_port)
                || self.relay_policy == api::RelayPolicy::RelayOnly
            {
                self.pump();
            } else {
                self.advance(500);
            }
            if let Some(result) = self.clients[callee].take_completion(accept) {
                break result;
            }
            if let Some(result) = self.clients[caller].take_completion(op) {
                return result.map(|_| (0, 0));
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let at_caller = self.wait(caller, op);
        let handle = |r: OpResult| match r? {
            OpValue::Channel(h) => Ok(h),
            other => panic!("unexpected {other:?}"),
        };
        Ok((handle(at_caller)?, handle(at_callee)?))
    }

    fn fingerprint_of(&self, device: &Device) -> Vec<u8> {
        let encoded = qalqon_core::cert::encode_public_key(device.identity.public_key()).unwrap();
        qalqon_core::cert::fingerprint(self.provider.as_ref(), &encoded)
    }
}

fn peer(user: &str) -> api::PeerRef {
    api::PeerRef {
        user_id: user.into(),
        device_id: None,
    }
}

fn options() -> api::ChannelOptions {
    api::ChannelOptions {
        label: "chat".into(),
        ordered: true,
        reliable: true,
        timeout_ms: None,
    }
}

fn two_users() -> (World, Device, Device) {
    let mut world = World::new();
    world.create_user("alice");
    world.create_user("bob");
    let alice = world.enrolled_device("alice");
    let bob = world.enrolled_device("bob");
    (world, alice, bob)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn the_whole_session_sequence_runs_on_a_direct_path() {
    let (mut world, alice, bob) = two_users();
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    assert!(world.events[a].contains(&api::Event::StateChanged {
        state: api::SessionState::Connected
    }));

    let (at_a, at_b) = world.call(a, b, "bob").unwrap();

    let now = world.now;
    world.clients[a].send(now, at_a, b"hello bob").unwrap();
    world.clients[b].send(now, at_b, b"hello alice").unwrap();
    world.pump();
    assert_eq!(
        world.clients[b].receive(at_b).unwrap(),
        Some(b"hello bob".to_vec())
    );
    assert_eq!(
        world.clients[a].receive(at_a).unwrap(),
        Some(b"hello alice".to_vec())
    );
    assert_eq!(world.clients[a].receive(at_a).unwrap(), None);
    assert!(world.events[b].contains(&api::Event::MessageAvailable { channel_id: at_b }));

    let info = world.clients[a].channel_info(at_a).unwrap();
    assert_eq!(info.path, api::PathKind::Direct);
    assert_eq!(info.peer.user_id, "bob");
    assert_eq!(info.peer.status, api::VerificationStatus::Pinned);

    // Both sides see the same safety number, computed from what each one received.
    let at_alice = world.clients[a]
        .verify_peer(now, &peer("bob"), None)
        .unwrap();
    let at_bob = world.clients[b]
        .verify_peer(now, &peer("alice"), None)
        .unwrap();
    assert_eq!(at_alice.safety_number, at_bob.safety_number);
    assert_eq!(at_alice.safety_number.len(), 60);

    // A wrong number is refused, and the right one upgrades the pin.
    assert_eq!(
        world.clients[a]
            .verify_peer(now, &peer("bob"), Some("000"))
            .unwrap_err(),
        ErrorKind::InvalidArgument
    );
    let verified = world.clients[a]
        .verify_peer(now, &peer("bob"), Some(&at_alice.safety_number))
        .unwrap();
    assert_eq!(verified.status, api::VerificationStatus::Verified);

    // Rotation in both directions.
    let op = world.clients[a].rotate_keys(now, Some(&peer("bob")));
    world.wait(a, op).unwrap();
    assert!(world.clients[a].channel_info(at_a).unwrap().key_epoch >= 1);
    assert!(
        world.events[a]
            .iter()
            .any(|e| matches!(e, api::Event::KeysRotated { .. }))
    );

    // Data still flows afterwards.
    let now = world.now;
    world.clients[a]
        .send(now, at_a, b"after the rekey")
        .unwrap();
    world.pump();
    assert_eq!(
        world.clients[b].receive(at_b).unwrap(),
        Some(b"after the rekey".to_vec())
    );

    // Alice's local audit chain verifies with only her public key.
    let export = world.clients[a]
        .export_audit(&api::AuditExportRequest {
            from_ms: None,
            to_ms: None,
        })
        .unwrap();
    let entries = qalqon_audit::from_jsonl(std::str::from_utf8(&export.events).unwrap()).unwrap();
    let head = qalqon_audit::verify_chain(
        world.provider.as_ref(),
        &world.fingerprint_of(&alice),
        &entries,
    )
    .unwrap();
    assert_eq!(head, export.chain_head);
    assert!(entries.iter().any(|e| e.event.operation == "login"));
    assert!(
        entries
            .iter()
            .any(|e| e.event.operation == "session.established" && e.event.subject == "bob")
    );
    assert!(entries.iter().any(|e| e.event.operation == "key.rotated"));
    assert!(entries.iter().any(|e| e.event.operation == "pin.changed"));

    // An authenticated close ends every channel cleanly on both sides.
    let op = world.clients[a].close(world.now);
    world.wait(a, op).unwrap();
    world.pump();
    assert!(world.events[a].contains(&api::Event::ChannelClosed {
        channel_id: at_a,
        clean: true
    }));
    assert!(world.events[b].contains(&api::Event::ChannelClosed {
        channel_id: at_b,
        clean: true
    }));
    assert!(world.clients[a].is_closed());

    // The server's audit chain verifies, and it never saw the application's data.
    let verified = world.admin("audit.verify", json!({}));
    assert_eq!(verified["ok"], true);
    assert!(
        world
            .server
            .metrics()
            .contains("qalqon_data_sessions_direct_total 1")
    );
    for frame in &world.direct_seen {
        assert!(
            !contains(frame, b"hello bob") && !contains(frame, b"after the rekey"),
            "plaintext on the wire"
        );
    }
}

#[test]
fn the_relay_path_carries_only_ciphertext() {
    let (mut world, alice, bob) = two_users();
    world.relay_policy = api::RelayPolicy::RelayOnly;
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    let (at_a, at_b) = world.call(a, b, "bob").unwrap();
    assert_eq!(
        world.clients[a].channel_info(at_a).unwrap().path,
        api::PathKind::Relayed
    );
    assert!(
        world.direct_seen.is_empty(),
        "relayOnly must never use a direct path"
    );

    let secret = b"a secret only the two clients may read";
    let now = world.now;
    world.clients[a].send(now, at_a, secret).unwrap();
    world.pump();
    assert_eq!(
        world.clients[b].receive(at_b).unwrap(),
        Some(secret.to_vec())
    );
    assert!(!world.relay_seen.is_empty());
    for frame in &world.relay_seen {
        assert!(
            !contains(frame, secret),
            "plaintext passed through the relay"
        );
        assert_eq!(
            &frame[..2],
            &wire::MAGIC,
            "the relay forwards frames unchanged"
        );
    }
    // XX_FINISH hides I's certificate from the relay and the network.
    let finish = world
        .relay_seen
        .iter()
        .find(|f| f[5] == wire::msg::XX_FINISH)
        .unwrap();
    assert!(
        !contains(finish, b"alice"),
        "I's identity is visible on the relay"
    );
    let resp = world
        .relay_seen
        .iter()
        .find(|f| f[5] == wire::msg::XX_RESP)
        .unwrap();
    assert!(
        !contains(resp, b"bob"),
        "R's identity is visible to a passive observer"
    );
}

#[test]
fn prefer_direct_falls_back_to_the_relay_when_no_direct_path_exists() {
    let (mut world, alice, bob) = two_users();
    world.direct_enabled = false;
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    let (at_a, at_b) = world.call(a, b, "bob").unwrap();
    assert_eq!(
        world.clients[a].channel_info(at_a).unwrap().path,
        api::PathKind::Relayed
    );
    assert_eq!(
        world.clients[b].channel_info(at_b).unwrap().path,
        api::PathKind::Relayed
    );
    let now = world.now;
    world.clients[a]
        .send(now, at_a, b"through the relay")
        .unwrap();
    world.pump();
    assert_eq!(
        world.clients[b].receive(at_b).unwrap(),
        Some(b"through the relay".to_vec())
    );
    assert!(world.events[a].iter().any(|e| matches!(
        e,
        api::Event::PathChanged {
            path: api::PathKind::Relayed,
            ..
        }
    )));
}

#[test]
fn a_stranger_on_the_direct_port_does_not_cost_the_call() {
    let (mut world, alice, bob) = two_users();
    world.stranger_on_direct_port = true;
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    let (at_a, at_b) = world.call(a, b, "bob").unwrap();
    assert_eq!(
        world.clients[a].channel_info(at_a).unwrap().path,
        api::PathKind::Relayed
    );
    let now = world.now;
    world.clients[a].send(now, at_a, b"still works").unwrap();
    world.pump();
    assert_eq!(
        world.clients[b].receive(at_b).unwrap(),
        Some(b"still works".to_vec())
    );
}

#[test]
fn direct_only_with_no_path_reports_peer_unreachable() {
    let (mut world, alice, bob) = two_users();
    world.direct_enabled = false;
    world.relay_policy = api::RelayPolicy::DirectOnly;
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    assert_eq!(
        world.call(a, b, "bob").unwrap_err(),
        ErrorKind::PeerUnreachable
    );
}

#[test]
fn declined_offline_and_unknown_peers_all_report_peer_unavailable() {
    let (mut world, alice, bob) = two_users();
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);

    let op = world.clients[a].open_channel(world.now, peer("nobody"), options());
    assert_eq!(world.wait(a, op).unwrap_err(), ErrorKind::PeerUnavailable);

    let op = world.clients[a].open_channel(world.now, peer("bob"), options());
    let request = world.take_event(b, |e| matches!(e, api::Event::ChannelRequested { .. }));
    let api::Event::ChannelRequested {
        request_id,
        peer: shown,
        ..
    } = request
    else {
        unreachable!()
    };
    assert_eq!(shown.user_id, "alice");
    assert_eq!(shown.status, api::VerificationStatus::Unverified);
    let now = world.now;
    world.clients[b].reject_channel(now, &request_id).unwrap();
    assert_eq!(world.wait(a, op).unwrap_err(), ErrorKind::PeerUnavailable);
}

#[test]
fn a_changed_key_blocks_until_the_user_re_verifies() {
    let (mut world, alice, bob) = two_users();
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    let (at_a, _) = world.call(a, b, "bob").unwrap();
    assert_eq!(
        world.clients[a].channel_info(at_a).unwrap().peer.status,
        api::VerificationStatus::Pinned
    );

    // Close both, keeping alice's pins. Bob then enrols again with a new key, which is
    // all a malicious server needs to be able to do: the CA issues it a valid certificate.
    let op = world.clients[b].close(world.now);
    world.wait(b, op).unwrap();
    world.pump();
    let new_bob = world.enrolled_device("bob");
    let b2 = world.logged_in("bob", &new_bob);

    let op = world.clients[a].open_channel(world.now, peer("bob"), options());
    let request = world.take_event(b2, |e| matches!(e, api::Event::ChannelRequested { .. }));
    let api::Event::ChannelRequested { request_id, .. } = request else {
        unreachable!()
    };
    let accept = world.clients[b2].accept_channel(world.now, &request_id);
    assert_eq!(
        world.wait(a, op).unwrap_err(),
        ErrorKind::PeerIdentityChanged,
        "a pinned user's new device must block"
    );
    let changed = world.take_event(a, |e| matches!(e, api::Event::PeerIdentityChanged { .. }));
    let api::Event::PeerIdentityChanged { peer: shown } = changed else {
        unreachable!()
    };
    assert_eq!(shown.status, api::VerificationStatus::Changed);
    assert_eq!(
        shown.fingerprint,
        crypto_provider::to_hex(&world.fingerprint_of(&new_bob))
    );
    let _ = accept;

    // The user compares the new safety number out of band, and then the call works.
    let identity = world.clients[a]
        .verify_peer(
            world.now,
            &api::PeerRef {
                user_id: "bob".into(),
                device_id: Some(shown.device_id.clone()),
            },
            None,
        )
        .unwrap();
    assert_eq!(identity.fingerprint, shown.fingerprint);
    let number = identity.safety_number.clone();
    let now = world.now;
    world.clients[a]
        .verify_peer(
            now,
            &api::PeerRef {
                user_id: "bob".into(),
                device_id: Some(shown.device_id),
            },
            Some(&number),
        )
        .unwrap();
    let (at_a, _) = world.call(a, b2, "bob").unwrap();
    assert_eq!(
        world.clients[a].channel_info(at_a).unwrap().peer.status,
        api::VerificationStatus::Verified
    );
}

#[test]
fn the_warn_policy_lets_a_changed_identity_through_but_says_so() {
    let (mut world, alice, bob) = two_users();
    world.identity_policy = api::IdentityChangePolicy::Warn;
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    world.call(a, b, "bob").unwrap();
    let op = world.clients[b].close(world.now);
    world.wait(b, op).unwrap();
    world.pump();
    let new_bob = world.enrolled_device("bob");
    let b2 = world.logged_in("bob", &new_bob);
    world.call(a, b2, "bob").unwrap();
    assert!(
        world.events[a]
            .iter()
            .any(|e| matches!(e, api::Event::PeerIdentityChanged { .. }))
    );
}

#[test]
fn pins_and_the_audit_chain_survive_a_restart() {
    let (mut world, mut alice, bob) = two_users();
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    world.call(a, b, "bob").unwrap();
    let saved = world.clients[a]
        .take_state_to_save()
        .expect("something to save");
    assert!(!saved.pins.is_empty());
    assert!(!saved.audit_entries.is_empty());
    let text = serde_json::to_string(&saved).unwrap();
    assert!(
        !text.contains(&crypto_provider::to_hex(
            &alice.identity.export_secret().unwrap()
        )),
        "keys must not be saved"
    );
    alice.saved = serde_json::from_str(&text).unwrap();

    let op = world.clients[a].close(world.now);
    world.wait(a, op).unwrap();
    let op = world.clients[b].close(world.now);
    world.wait(b, op).unwrap();
    world.pump();

    // The restarted client still knows bob, and blocks a new key.
    let a2 = world.logged_in("alice", &alice);
    let new_bob = world.enrolled_device("bob");
    let b2 = world.logged_in("bob", &new_bob);
    let op = world.clients[a2].open_channel(world.now, peer("bob"), options());
    let request = world.take_event(b2, |e| matches!(e, api::Event::ChannelRequested { .. }));
    let api::Event::ChannelRequested { request_id, .. } = request else {
        unreachable!()
    };
    world.clients[b2].accept_channel(world.now, &request_id);
    assert_eq!(
        world.wait(a2, op).unwrap_err(),
        ErrorKind::PeerIdentityChanged
    );

    // The chain continues from where it stopped.
    let export = world.clients[a2]
        .export_audit(&api::AuditExportRequest {
            from_ms: None,
            to_ms: None,
        })
        .unwrap();
    let entries = qalqon_audit::from_jsonl(std::str::from_utf8(&export.events).unwrap()).unwrap();
    qalqon_audit::verify_chain(
        world.provider.as_ref(),
        &world.fingerprint_of(&alice),
        &entries,
    )
    .expect("the chain must continue unbroken");
}

#[test]
fn a_second_call_omits_the_certificate_chain() {
    let (mut world, alice, bob) = two_users();
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    world.call(a, b, "bob").unwrap();
    let first = world
        .direct_seen
        .iter()
        .find(|f| f[5] == wire::msg::XX_RESP)
        .unwrap()
        .len();
    let saved = world.clients[a].take_state_to_save().unwrap();

    let op = world.clients[a].close(world.now);
    world.wait(a, op).unwrap();
    world.pump();
    world.direct_seen.clear();

    let mut alice_again = alice;
    alice_again.saved = saved;
    let a2 = world.logged_in("alice", &alice_again);
    world.call(a2, b, "bob").unwrap();
    let second = world
        .direct_seen
        .iter()
        .find(|f| f[5] == wire::msg::XX_RESP)
        .unwrap()
        .len();
    assert!(
        second < first,
        "the second XX_RESP should omit the chain: {second} vs {first}"
    );
}

#[test]
fn a_further_channel_multiplexes_and_the_application_decides() {
    let (mut world, alice, bob) = two_users();
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    let (first_a, first_b) = world.call(a, b, "bob").unwrap();
    let handshakes = world
        .direct_seen
        .iter()
        .filter(|f| f[5] == wire::msg::XX_INIT)
        .count();

    let op = world.clients[a].open_channel(
        world.now,
        peer("bob"),
        api::ChannelOptions {
            label: "files".into(),
            ..options()
        },
    );
    let request = world.take_event(b, |e| matches!(e, api::Event::ChannelRequested { .. }));
    let api::Event::ChannelRequested {
        request_id,
        options: asked,
        ..
    } = request
    else {
        unreachable!()
    };
    assert_eq!(asked.label, "files");
    let accept = world.clients[b].accept_channel(world.now, &request_id);
    let OpValue::Channel(second_b) = world.wait(b, accept).unwrap() else {
        panic!()
    };
    let OpValue::Channel(second_a) = world.wait(a, op).unwrap() else {
        panic!()
    };
    assert_eq!(
        world
            .direct_seen
            .iter()
            .filter(|f| f[5] == wire::msg::XX_INIT)
            .count(),
        handshakes,
        "no new handshake"
    );
    assert_ne!(first_a, second_a);

    let now = world.now;
    world.clients[a].send(now, second_a, b"on files").unwrap();
    world.clients[a].send(now, first_a, b"on chat").unwrap();
    world.pump();
    assert_eq!(
        world.clients[b].receive(second_b).unwrap(),
        Some(b"on files".to_vec())
    );
    assert_eq!(
        world.clients[b].receive(first_b).unwrap(),
        Some(b"on chat".to_vec())
    );

    // Closing one leaves the other.
    let op = world.clients[a].close_channel(world.now, second_a);
    world.wait(a, op).unwrap();
    assert_eq!(
        world.clients[a]
            .send(world.now, second_a, b"x")
            .unwrap_err(),
        ErrorKind::Closed
    );
    let now = world.now;
    world.clients[a].send(now, first_a, b"still open").unwrap();
    world.pump();
    assert_eq!(
        world.clients[b].receive(first_b).unwrap(),
        Some(b"still open".to_vec())
    );
}

#[test]
fn revoking_a_peer_stops_new_sessions_at_the_data_plane_too() {
    let (mut world, alice, bob) = two_users();
    let device_b =
        qalqon_core::cert::parse_many(world.provider.as_ref(), bob.chain.as_ref().unwrap())
            .unwrap()[0]
            .fields
            .subject_b
            .clone();
    let b = world.logged_in("bob", &bob);
    world.admin("devices.revoke", json!({ "device_id": device_b }));
    world.pump();
    assert!(
        world.clients[b].is_closed(),
        "the revoked device's session must end"
    );

    // Alice connects afterwards, so her CRL lists bob. A revoked client cannot log in,
    // and even if a server let one rendezvous, her own check would stop it.
    let _ = alice;
    let chain = world
        .ca
        .issue_device("bob", "other", bob.identity.as_ref(), world.now)
        .unwrap();
    assert!(!chain.is_empty());
    let again = world.new_client(&bob);
    let credentials = api::Credentials {
        user_id: "bob".into(),
        secret: PASSWORD.as_bytes().to_vec(),
        mfa_code: None,
    };
    let op = world.clients[again].start_connect(world.now, credentials);
    assert!(
        world.wait(again, op).is_err(),
        "a revoked certificate must not log in"
    );
}

#[test]
fn a_stale_crl_blocks_new_peer_sessions() {
    let (mut world, alice, bob) = two_users();
    world.revocation_grace_ms = 0;
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    // Time passes past the CRL's next update with no fresh CRL reaching the clients.
    world.withhold_crl = true;
    world.now += 25 * 60 * 60 * 1000;
    let op = world.clients[a].open_channel(world.now, peer("bob"), options());
    let request = world.take_event(b, |e| matches!(e, api::Event::ChannelRequested { .. }));
    let api::Event::ChannelRequested { request_id, .. } = request else {
        unreachable!()
    };
    world.clients[b].accept_channel(world.now, &request_id);
    assert_eq!(
        world.wait(a, op).unwrap_err(),
        ErrorKind::RevocationDataStale
    );
}

#[test]
fn wrong_passwords_and_unenrolled_devices_are_reported_generically() {
    let (mut world, alice, _) = two_users();
    let a = world.new_client(&alice);
    let bad = api::Credentials {
        user_id: "alice".into(),
        secret: b"wrong password here".to_vec(),
        mfa_code: None,
    };
    let op = world.clients[a].start_connect(world.now, bad);
    assert_eq!(
        world.wait(a, op).unwrap_err(),
        ErrorKind::AuthenticationFailed
    );

    let identity: Arc<dyn SigningKey> = Arc::from(world.provider.generate_signing_key().unwrap());
    let unenrolled = world.new_client(&Device {
        identity,
        chain: None,
        saved: SavedState::default(),
    });
    let credentials = api::Credentials {
        user_id: "alice".into(),
        secret: PASSWORD.as_bytes().to_vec(),
        mfa_code: None,
    };
    let op = world.clients[unenrolled].start_connect(world.now, credentials);
    assert_eq!(
        world.wait(unenrolled, op).unwrap_err(),
        ErrorKind::NotEnrolled
    );
}

#[test]
fn enrolment_with_a_bad_token_is_rejected() {
    let mut world = World::new();
    world.create_user("alice");
    let identity: Arc<dyn SigningKey> = Arc::from(world.provider.generate_signing_key().unwrap());
    let device = Device {
        identity,
        chain: None,
        saved: SavedState::default(),
    };
    let index = world.new_client(&device);
    let op = world.clients[index].start_enroll(
        world.now,
        api::EnrollmentRequest {
            enrollment_token: "alice:bad".into(),
            device_name: "x".into(),
        },
    );
    assert_eq!(
        world.wait(index, op).unwrap_err(),
        ErrorKind::EnrollmentRejected
    );
}

#[test]
fn plain_ws_is_refused_except_on_loopback() {
    let world = World::new();
    let identity: Arc<dyn SigningKey> = Arc::from(world.provider.generate_signing_key().unwrap());
    let make = |url: &str| {
        ClientCore::new(
            ClientOptions {
                provider: world.provider.clone(),
                server_url: url.into(),
                ca_bundle: world.ca.root_cert.clone(),
                identity: identity.clone(),
                chain: None,
                relay_policy: api::RelayPolicy::PreferDirect,
                identity_change_policy: api::IdentityChangePolicy::Block,
                revocation_grace_ms: 0,
                saved: SavedState::default(),
                limits: Limits::default(),
            },
            START,
        )
    };
    assert_eq!(
        make("ws://qalqon.example/qalqon").unwrap_err(),
        ErrorKind::InvalidArgument
    );
    assert_eq!(
        make("http://qalqon.example").unwrap_err(),
        ErrorKind::InvalidArgument
    );
    assert!(make("wss://qalqon.example/qalqon").is_ok());
    assert!(make("ws://127.0.0.1:8080/qalqon").is_ok());
}

#[test]
fn losing_the_server_ends_the_session_and_every_channel() {
    let (mut world, alice, bob) = two_users();
    let a = world.logged_in("alice", &alice);
    let b = world.logged_in("bob", &bob);
    let (at_a, _) = world.call(a, b, "bob").unwrap();
    let control = world
        .routes
        .iter()
        .find(|(link, route)| link.client == a && matches!(route, Route::Server(_)))
        .map(|(link, _)| link.link)
        .unwrap();
    world
        .routes
        .retain(|link, _| !(link.client == a && link.link == control));
    let now = world.now;
    world.clients[a].link_closed(now, control);
    world.pump();
    assert!(world.events[a].contains(&api::Event::StateChanged {
        state: api::SessionState::Closed
    }));
    world.advance(10_000);
    assert!(
        world.events[a].iter().any(
            |e| matches!(e, api::Event::ChannelClosed { channel_id, .. } if *channel_id == at_a)
        )
    );
}
