//! `server-core` driven the way a host drives it, against real client sessions.

use crypto_provider::{CryptoProvider, SigningKey, to_hex};
use provider_testonly::TestOnlyProvider;
use qalqon_audit::AuditEntry;
use qalqon_ca::DevCa;
use qalqon_core::cert;
use qalqon_core::control::{ControlMessage, field, kind, parse_channel_options, parse_grants};
use qalqon_core::crl::Crl;
use qalqon_core::relay;
use qalqon_core::session::{Limits, Plane, Role, SessionConfig, TransportCaps};
use qalqon_core::{ErrorCode, Event, PeerExpectation, Session, UncheckedPeers};
use serde_json::{Value, json};
use server_core::policy::Policy;
use server_core::{
    Effect, IssuingCa, PasswordCost, ServerCore, ServerOptions, Severity, StoreKind, StoreOperation,
};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const NOW: u64 = 1_800_000_000_000;
const HOST: &str = "qalqon.example";
const GOOD_PASSWORD: &str = "correct horse battery staple";

/// The four stores, as a reference host keeps them.
#[derive(Default)]
struct Stores {
    users: BTreeMap<String, Vec<u8>>,
    devices: BTreeMap<String, Vec<u8>>,
    policies: BTreeMap<String, Vec<u8>>,
    audit: BTreeMap<u64, Vec<u8>>,
    fail_audit: bool,
}

impl Stores {
    fn perform(
        &mut self,
        store: StoreKind,
        op: StoreOperation,
        key: Option<String>,
        record: Option<Vec<u8>>,
    ) -> (u32, Option<Vec<u8>>) {
        let table = match store {
            StoreKind::User => Some(&mut self.users),
            StoreKind::Device => Some(&mut self.devices),
            StoreKind::Policy => Some(&mut self.policies),
            StoreKind::Audit => None,
        };
        match (store, op) {
            (_, StoreOperation::Get) => (0, table.unwrap().get(&key.unwrap()).cloned()),
            (_, StoreOperation::Put) => {
                table.unwrap().insert(key.unwrap(), record.unwrap());
                (0, None)
            }
            (_, StoreOperation::List) => {
                let filter = key.and_then(|k| k.strip_prefix("user:").map(str::to_string));
                let rows: Vec<Value> = table
                    .unwrap()
                    .values()
                    .map(|b| serde_json::from_slice::<Value>(b).unwrap())
                    .filter(|v| filter.as_ref().is_none_or(|u| v["user_id"] == u.as_str()))
                    .collect();
                (0, Some(serde_json::to_vec(&rows).unwrap()))
            }
            (StoreKind::Audit, StoreOperation::Append) => {
                if self.fail_audit {
                    return (ErrorCode::AuditUnavailable.code(), None);
                }
                self.audit
                    .insert(key.unwrap().parse().unwrap(), record.unwrap());
                (0, None)
            }
            (StoreKind::Audit, StoreOperation::Head) => {
                (0, self.audit.values().next_back().cloned())
            }
            (StoreKind::Audit, StoreOperation::Range) => {
                let key = key.unwrap();
                let (from, to) = key.split_once(',').unwrap();
                let (from, to): (u64, u64) = (from.parse().unwrap(), to.parse().unwrap());
                let rows: Vec<Value> = self
                    .audit
                    .range(from..=to)
                    .map(|(_, b)| serde_json::from_slice::<Value>(b).unwrap())
                    .collect();
                (0, Some(serde_json::to_vec(&rows).unwrap()))
            }
            _ => panic!("unexpected store operation {store:?} {op:?}"),
        }
    }
}

type Outboxes = Arc<Mutex<HashMap<u64, VecDeque<Vec<u8>>>>>;

/// A host: an effect loop on its own thread, as `docs/HOST-SPI.md` describes.
struct TestHost {
    core: Arc<ServerCore>,
    stores: Arc<Mutex<Stores>>,
    outboxes: Outboxes,
    closed: Arc<Mutex<Vec<u64>>>,
    alarms: Arc<Mutex<Vec<(Severity, String)>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    provider: Arc<dyn CryptoProvider>,
    ca: Arc<DevCa>,
    roots: Vec<u8>,
    server_key: Arc<dyn SigningKey>,
    relay_key: Vec<u8>,
}

impl Drop for TestHost {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.core.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn options(
    provider: &Arc<dyn CryptoProvider>,
    ca: &DevCa,
    server_key: &Arc<dyn SigningKey>,
    relay_key: &[u8],
    issuing_key: Arc<dyn SigningKey>,
    policy: Value,
) -> ServerOptions {
    ServerOptions {
        provider: provider.clone(),
        identity: server_key.clone(),
        chain: ca
            .issue_server(HOST, "i1", server_key.as_ref(), NOW)
            .unwrap(),
        ca_bundle: ca.root_cert.clone(),
        issuing: Some(IssuingCa {
            key: issuing_key,
            certificate: ca.issuing_cert.clone(),
        }),
        relay_addresses: vec!["wss://relay.example/relay".into()],
        relay_key: relay_key.to_vec(),
        audit_key: vec![7; 32],
        policy,
        password_cost: PasswordCost {
            m_kib: 256,
            t: 1,
            p: 1,
        },
        limits: Limits::default(),
        now_ms: NOW,
    }
}

impl TestHost {
    fn start() -> Self {
        Self::start_with_policy(Policy::default_document())
    }

    fn start_with_policy(policy: Value) -> Self {
        let provider: Arc<dyn CryptoProvider> = Arc::new(TestOnlyProvider::new());
        let ca = DevCa::new(provider.clone(), NOW).unwrap();
        let server_key: Arc<dyn SigningKey> = Arc::from(provider.generate_signing_key().unwrap());
        let issuing_secret = ca.issuing_key.export_secret().unwrap();
        let issuing_key: Arc<dyn SigningKey> =
            Arc::from(provider.import_signing_key(&issuing_secret).unwrap());
        let relay_key = vec![9u8; 32];
        let core = ServerCore::new(options(
            &provider,
            &ca,
            &server_key,
            &relay_key,
            issuing_key,
            policy,
        ))
        .unwrap();
        let roots = ca.root_cert.clone();
        let mut host = TestHost {
            core: Arc::new(core),
            stores: Arc::default(),
            outboxes: Arc::default(),
            closed: Arc::default(),
            alarms: Arc::default(),
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
            provider,
            ca: Arc::new(ca),
            roots,
            server_key,
            relay_key,
        };
        host.spawn_loop();
        host.wait_ready();
        host
    }

    fn spawn_loop(&mut self) {
        let core = self.core.clone();
        let stores = self.stores.clone();
        let outboxes = self.outboxes.clone();
        let closed = self.closed.clone();
        let alarms = self.alarms.clone();
        let stop = self.stop.clone();
        self.thread = Some(std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match core.poll_effect(Duration::from_millis(5)) {
                    Ok(Some(Effect::SendFrame { conn_id, frame })) => {
                        outboxes
                            .lock()
                            .unwrap()
                            .entry(conn_id)
                            .or_default()
                            .push_back(frame);
                    }
                    Ok(Some(Effect::CloseConnection { conn_id, .. })) => {
                        closed.lock().unwrap().push(conn_id)
                    }
                    Ok(Some(Effect::Store {
                        effect_id,
                        store,
                        operation,
                        key,
                        record,
                    })) => {
                        let (status, record) = stores
                            .lock()
                            .unwrap()
                            .perform(store, operation, key, record);
                        let _ = core.complete_effect(effect_id, status, record);
                    }
                    Ok(Some(Effect::Alarm { severity, summary })) => {
                        alarms.lock().unwrap().push((severity, summary))
                    }
                    Ok(None) => {}
                    Err(_) => return,
                }
            }
        }));
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.core.health().ready {
            assert!(
                Instant::now() < deadline,
                "not ready: {:?}",
                self.core.health()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn admin(&self, method: &str, params: Value) -> Result<Value, ErrorCode> {
        self.core
            .admin_call(method, &params.to_string())
            .map(|s| serde_json::from_str(&s).unwrap())
    }

    fn create_user(&self, user: &str) {
        self.admin(
            "users.create",
            json!({ "user_id": user, "password": GOOD_PASSWORD }),
        )
        .unwrap();
    }

    fn token(&self, user: &str) -> String {
        self.admin("devices.createEnrollmentToken", json!({ "user_id": user }))
            .unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// A client with a fresh key and a pre-enrolment certificate.
    fn pre_enrolment_client(&self) -> Client {
        let key: Arc<dyn SigningKey> = Arc::from(self.provider.generate_signing_key().unwrap());
        let chain = cert::pre_enrolment(
            self.provider.as_ref(),
            key.as_ref(),
            NOW - 1000,
            NOW + 86_400_000,
        )
        .unwrap();
        self.connect(key, chain)
    }

    fn connect(&self, key: Arc<dyn SigningKey>, chain: Vec<u8>) -> Client {
        let p = self.provider.as_ref();
        let conn_id = self.core.accept("203.0.113.9:4000").unwrap();
        let session = Session::new(
            SessionConfig {
                provider: self.provider.clone(),
                role: Role::Initiator,
                plane: Plane::Control,
                transport: TransportCaps::STREAM,
                identity: key.clone(),
                chain: chain.clone(),
                roots: cert::parse_many(p, &self.roots).unwrap(),
                expectation: PeerExpectation::Server { host: HOST.into() },
                verifier: Box::new(UncheckedPeers),
                versions: SessionConfig::default_versions(),
                suites: p.suites().to_vec(),
                cached_peer_chain: None,
                rendezvous_id: None,
                limits: Limits::default(),
            },
            NOW,
        )
        .unwrap();
        let mut client = Client {
            core: self.core.clone(),
            outboxes: self.outboxes.clone(),
            conn_id,
            session,
            key,
            chain,
            inbox: VecDeque::new(),
            closed: false,
        };
        client.wait_established();
        client
    }

    /// Runs enrolment, then reconnects with the real certificate.
    fn enrolled_client(&self, user: &str) -> Client {
        let token = self.token(user);
        let mut pre = self.pre_enrolment_client();
        let chain = pre.enroll(&token).expect("enrolment");
        let key = pre.key.clone();
        pre.hang_up();
        self.connect(key, chain)
    }

    fn logged_in(&self, user: &str) -> Client {
        let mut client = self.enrolled_client(user);
        assert_eq!(client.login(user, GOOD_PASSWORD), ErrorCode::Ok);
        client
    }

    fn audit_rows(&self) -> Vec<AuditEntry> {
        self.stores
            .lock()
            .unwrap()
            .audit
            .values()
            .map(|b| serde_json::from_slice(b).unwrap())
            .collect()
    }

    fn server_fingerprint(&self) -> Vec<u8> {
        let encoded = cert::encode_public_key(self.server_key.public_key()).unwrap();
        cert::fingerprint(self.provider.as_ref(), &encoded)
    }
}

struct Client {
    core: Arc<ServerCore>,
    outboxes: Outboxes,
    conn_id: u64,
    session: Session,
    key: Arc<dyn SigningKey>,
    chain: Vec<u8>,
    inbox: VecDeque<ControlMessage>,
    closed: bool,
}

impl Client {
    fn pump(&mut self) {
        while let Some(frame) = self.session.poll_transmit() {
            let _ = self.core.on_frame(self.conn_id, &frame);
        }
        let frames: Vec<Vec<u8>> = self
            .outboxes
            .lock()
            .unwrap()
            .entry(self.conn_id)
            .or_default()
            .drain(..)
            .collect();
        for frame in frames {
            self.session.handle_frame(NOW, &frame);
        }
        while let Some(event) = self.session.poll_event() {
            match event {
                Event::Control { body } => {
                    self.inbox.push_back(ControlMessage::decode(&body).unwrap())
                }
                Event::Closed { .. } => self.closed = true,
                _ => {}
            }
        }
    }

    fn wait_until(&mut self, what: &str, mut done: impl FnMut(&mut Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.pump();
            if done(self) {
                return;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn wait_established(&mut self) {
        self.wait_until("the handshake", |c| {
            c.session.is_established() && c.session.peer().is_some()
        });
    }

    fn wait_control(&mut self, expected: u16) -> ControlMessage {
        let mut found = None;
        self.wait_until("a control message", |c| {
            if let Some(i) = c.inbox.iter().position(|m| m.kind == expected) {
                found = c.inbox.remove(i);
                return true;
            }
            false
        });
        found.unwrap()
    }

    fn send(&mut self, message: &ControlMessage) {
        self.session
            .send_control(NOW, &message.encode().unwrap())
            .unwrap();
        self.pump();
    }

    fn enroll(&mut self, token: &str) -> Result<Vec<u8>, ErrorCode> {
        self.send(
            &ControlMessage::new(kind::ENROLL_REQUEST)
                .with_str(field::TOKEN, token)
                .with_str(field::DEVICE_NAME, "laptop"),
        );
        let result = self.wait_control(kind::ENROLL_RESULT);
        match ErrorCode::from_code(u32::from(result.get_u16(field::STATUS).unwrap())).unwrap() {
            ErrorCode::Ok => Ok(result.get(field::CHAIN).unwrap().to_vec()),
            code => Err(code),
        }
    }

    fn login(&mut self, user: &str, password: &str) -> ErrorCode {
        self.send(
            &ControlMessage::new(kind::LOGIN_REQUEST)
                .with_str(field::USER_ID, user)
                .with_str(field::SECRET, password),
        );
        let result = self.wait_control(kind::LOGIN_RESULT);
        ErrorCode::from_code(u32::from(result.get_u16(field::STATUS).unwrap())).unwrap()
    }

    fn hang_up(&mut self) {
        self.session.close(NOW, 0);
        self.pump();
        let _ = self.core.on_close(self.conn_id);
    }

    fn device_id(&self) -> String {
        let p = TestOnlyProvider::new();
        cert::parse_many(&p, &self.chain).unwrap()[0]
            .fields
            .subject_b
            .clone()
    }
}

fn options_field() -> Vec<u8> {
    qalqon_core::control::encode_channel_options(true, true, "chat").unwrap()
}

fn open_rendezvous(from: &mut Client, to_user: &str, request: u8) {
    from.send(
        &ControlMessage::new(kind::RENDEZVOUS_OPEN)
            .with(field::REQUEST_ID, &[request; 16])
            .with_str(field::USER_ID, to_user)
            .with(field::CHANNEL_OPTIONS, &options_field()),
    );
}

#[test]
fn startup_is_audited_and_health_reports_ready() {
    let host = TestHost::start();
    assert!(host.core.health().live);
    assert!(host.core.health().ready);
    let rows = host.audit_rows();
    assert_eq!(rows[0].event.operation, "server.start");
    assert!(
        host.core
            .metrics()
            .contains("qalqon_handshake_failures_total 0")
    );
}

#[test]
fn enrolment_issues_a_chain_once_per_token() {
    let host = TestHost::start();
    host.create_user("alice");
    let token = host.token("alice");

    let mut first = host.pre_enrolment_client();
    let chain = first.enroll(&token).unwrap();
    let parsed = cert::parse_many(host.provider.as_ref(), &chain).unwrap();
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].fields.subject_a, "alice");
    assert_eq!(parsed[0].fields.role, cert::role::DEVICE);
    assert_eq!(
        parsed[0].fields.sign_public,
        *first.key.public_key(),
        "the certificate must name the client's own key"
    );

    let mut second = host.pre_enrolment_client();
    assert_eq!(
        second.enroll(&token),
        Err(ErrorCode::EnrollmentRejected),
        "a token works once"
    );

    let mut third = host.pre_enrolment_client();
    assert_eq!(
        third.enroll("alice:ffff"),
        Err(ErrorCode::EnrollmentRejected)
    );
    assert_eq!(
        third.enroll("nobody:ffff"),
        Err(ErrorCode::EnrollmentRejected)
    );
    assert_eq!(
        third.enroll("no-separator"),
        Err(ErrorCode::EnrollmentRejected)
    );

    let stored = host
        .stores
        .lock()
        .unwrap()
        .users
        .get("alice")
        .cloned()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&stored).contains(&token),
        "the store must hold only a hash"
    );
}

#[test]
fn a_pre_enrolment_session_can_only_enrol_and_fetch_the_crl() {
    let host = TestHost::start();
    host.create_user("alice");
    let mut client = host.pre_enrolment_client();
    client.send(&ControlMessage::new(kind::CRL_REQUEST).with(field::ISSUER_KEY_ID, &[0; 16]));
    assert!(
        client
            .wait_control(kind::CRL_RESPONSE)
            .get(field::CRL)
            .is_some()
    );

    client.send(
        &ControlMessage::new(kind::LOGIN_REQUEST)
            .with_str(field::USER_ID, "alice")
            .with_str(field::SECRET, GOOD_PASSWORD),
    );
    client.wait_until("the server to close the session", |c| c.closed);
}

#[test]
fn login_succeeds_and_failures_do_not_say_why() {
    let host = TestHost::start();
    host.create_user("alice");
    let mut client = host.enrolled_client("alice");
    assert_eq!(
        client.login("alice", "wrong password here"),
        ErrorCode::AuthenticationFailed
    );
    assert_eq!(
        client.login("nobody", GOOD_PASSWORD),
        ErrorCode::AuthenticationFailed
    );
    assert_eq!(client.login("alice", GOOD_PASSWORD), ErrorCode::Ok);
    assert!(host.core.metrics().contains("qalqon_logins_ok_total 1"));
}

#[test]
fn a_failed_login_logs_a_keyed_digest_and_never_the_secret() {
    let host = TestHost::start();
    host.create_user("alice");
    let mut client = host.enrolled_client("alice");
    let attempt = "this-is-a-guess-at-a-password";
    assert_eq!(
        client.login("alice", attempt),
        ErrorCode::AuthenticationFailed
    );

    let rows = host.audit_rows();
    let row = rows
        .iter()
        .rev()
        .find(|r| r.event.operation == "login")
        .unwrap();
    assert_eq!(row.event.result, "authenticationFailed");
    assert_eq!(row.event.object, "alice");
    let digest = qalqon_audit::secret_digest(host.provider.as_ref(), &[7; 32], attempt.as_bytes());
    assert!(row.event.detail.contains(&digest), "{}", row.event.detail);
    for row in &rows {
        assert!(
            !serde_json::to_string(row).unwrap().contains(attempt),
            "the secret is in the audit log"
        );
    }
}

#[test]
fn repeated_failures_lock_the_account_and_raise_an_alarm() {
    let host = TestHost::start();
    host.create_user("alice");
    let mut client = host.enrolled_client("alice");
    for _ in 0..5 {
        assert_eq!(
            client.login("alice", "wrong password here"),
            ErrorCode::AuthenticationFailed
        );
    }
    assert_eq!(
        client.login("alice", GOOD_PASSWORD),
        ErrorCode::RateLimited,
        "the account must be locked"
    );
    assert!(
        host.alarms
            .lock()
            .unwrap()
            .iter()
            .any(|(s, m)| *s == Severity::Warning && m.contains("alice"))
    );
}

#[test]
fn a_certificate_for_another_user_cannot_log_in_with_their_password() {
    let host = TestHost::start();
    host.create_user("alice");
    host.create_user("bob");
    let mut alice = host.enrolled_client("alice");
    assert_eq!(
        alice.login("bob", GOOD_PASSWORD),
        ErrorCode::AuthenticationFailed
    );
}

#[test]
fn a_certificate_the_store_does_not_know_cannot_log_in() {
    // A valid certificate from the CA, for a device the server never enrolled.
    let host = TestHost::start();
    host.create_user("alice");
    let key: Arc<dyn SigningKey> = Arc::from(host.provider.generate_signing_key().unwrap());
    let chain = host
        .ca
        .issue_device("alice", "invented", key.as_ref(), NOW)
        .unwrap();
    let mut client = host.connect(key, chain);
    assert_eq!(client.login("alice", GOOD_PASSWORD), ErrorCode::NotEnrolled);
}

#[test]
fn an_unauthenticated_session_cannot_use_rendezvous() {
    let host = TestHost::start();
    host.create_user("alice");
    host.create_user("bob");
    let _bob = host.logged_in("bob");
    let mut alice = host.enrolled_client("alice");
    open_rendezvous(&mut alice, "bob", 1);
    alice.wait_until("the server to close the session", |c| c.closed);
}

#[test]
fn rendezvous_connects_two_clients_and_forwards_signals() {
    let host = TestHost::start();
    host.create_user("alice");
    host.create_user("bob");
    let mut alice = host.logged_in("alice");
    let mut bob = host.logged_in("bob");

    open_rendezvous(&mut alice, "bob", 1);
    let incoming = bob.wait_control(kind::RENDEZVOUS_INCOMING);
    assert_eq!(incoming.get_str(field::USER_ID), Some("alice"));
    assert_eq!(
        incoming.get_str(field::DEVICE_ID).unwrap(),
        alice.device_id()
    );
    assert_eq!(incoming.get(field::CHAIN).unwrap(), alice.chain.as_slice());
    let (ordered, reliable, label) =
        parse_channel_options(incoming.get(field::CHANNEL_OPTIONS).unwrap()).unwrap();
    assert!(ordered && reliable);
    assert_eq!(label, "chat");
    let rendezvous_id = incoming.get_id(field::RENDEZVOUS_ID).unwrap();

    bob.send(&ControlMessage::new(kind::RENDEZVOUS_ACCEPT).with(field::REQUEST_ID, &[1; 16]));
    let ready = alice.wait_control(kind::RENDEZVOUS_READY);
    assert_eq!(ready.get_id(field::RENDEZVOUS_ID), Some(rendezvous_id));
    assert_eq!(ready.get(field::CHAIN).unwrap(), bob.chain.as_slice());

    // Both sides get a grant that the relay can check.
    let grants = parse_grants(ready.get(field::RELAY_GRANTS).unwrap()).unwrap();
    assert_eq!(grants[0].address, "wss://relay.example/relay");
    assert!(relay::check_token(
        host.provider.as_ref(),
        &host.relay_key,
        &rendezvous_id,
        &grants[0].token,
        NOW
    ));
    assert!(!relay::check_token(
        host.provider.as_ref(),
        &host.relay_key,
        &[0; 16],
        &grants[0].token,
        NOW
    ));
    assert!(!relay::check_token(
        host.provider.as_ref(),
        &host.relay_key,
        &rendezvous_id,
        &grants[0].token,
        grants[0].expires_at + 1
    ));

    alice.send(
        &ControlMessage::new(kind::PEER_SIGNAL)
            .with(field::RENDEZVOUS_ID, &rendezvous_id)
            .with(field::BLOB, b"sdp offer"),
    );
    assert_eq!(
        bob.wait_control(kind::PEER_SIGNAL)
            .get(field::BLOB)
            .unwrap(),
        b"sdp offer"
    );
    bob.send(
        &ControlMessage::new(kind::PEER_SIGNAL)
            .with(field::RENDEZVOUS_ID, &rendezvous_id)
            .with(field::BLOB, b"sdp answer"),
    );
    assert_eq!(
        alice
            .wait_control(kind::PEER_SIGNAL)
            .get(field::BLOB)
            .unwrap(),
        b"sdp answer"
    );
}

#[test]
fn a_third_party_cannot_signal_into_a_rendezvous() {
    let host = TestHost::start();
    for user in ["alice", "bob", "mallory"] {
        host.create_user(user);
    }
    let mut alice = host.logged_in("alice");
    let mut bob = host.logged_in("bob");
    let mut mallory = host.logged_in("mallory");
    open_rendezvous(&mut alice, "bob", 2);
    let incoming = bob.wait_control(kind::RENDEZVOUS_INCOMING);
    let id = incoming.get_id(field::RENDEZVOUS_ID).unwrap();
    mallory.send(
        &ControlMessage::new(kind::PEER_SIGNAL)
            .with(field::RENDEZVOUS_ID, &id)
            .with(field::BLOB, b"evil"),
    );
    mallory.wait_until("the server to close the session", |c| c.closed);
    bob.pump();
    assert!(!bob.inbox.iter().any(|m| m.kind == kind::PEER_SIGNAL));
}

#[test]
fn offline_declined_and_denied_all_look_the_same_to_the_caller() {
    let policy = json!({
        "roles": { "user": ["login", "enroll", "rendezvous", "renew"] },
        "deny": [ { "subject": "alice", "operation": "rendezvous", "object": "user:hidden" } ]
    });
    let host = TestHost::start_with_policy(policy);
    for user in ["alice", "bob", "hidden", "offline"] {
        host.create_user(user);
    }
    let mut alice = host.logged_in("alice");
    let mut bob = host.logged_in("bob");
    let mut hidden = host.logged_in("hidden");

    open_rendezvous(&mut alice, "offline", 3);
    let offline = alice.wait_control(kind::RENDEZVOUS_REJECT);

    open_rendezvous(&mut alice, "hidden", 4);
    let denied = alice.wait_control(kind::RENDEZVOUS_REJECT);
    hidden.pump();
    assert!(
        hidden.inbox.is_empty(),
        "a denied rendezvous must not reach its target"
    );

    open_rendezvous(&mut alice, "bob", 5);
    bob.wait_control(kind::RENDEZVOUS_INCOMING);
    bob.send(&ControlMessage::new(kind::RENDEZVOUS_REJECT).with(field::REQUEST_ID, &[5; 16]));
    let declined = alice.wait_control(kind::RENDEZVOUS_REJECT);

    // Identical except for the request id each one echoes.
    for message in [offline, denied, declined] {
        let body = message.encode().unwrap();
        assert_eq!(
            body.len(),
            2 + 4 + 16,
            "the rejection must carry nothing but the request id"
        );
    }

    // The audit log, unlike the caller, knows which it was.
    let rows = host.audit_rows();
    assert!(
        rows.iter()
            .any(|r| r.event.object == "user:hidden" && r.event.result == "accessDenied")
    );
    assert!(
        rows.iter()
            .any(|r| r.event.object == "user:offline" && r.event.result == "peerUnavailable")
    );
}

#[test]
fn revoking_a_device_ends_its_session_lists_it_on_the_crl_and_blocks_reconnection() {
    let host = TestHost::start();
    host.create_user("alice");
    let mut alice = host.logged_in("alice");
    let device_id = alice.device_id();
    let serial = cert::parse_many(host.provider.as_ref(), &alice.chain).unwrap()[0]
        .fields
        .serial;

    let issuing = host.ca.issuing_key.public_key().clone();
    alice.send(&ControlMessage::new(kind::CRL_REQUEST).with(field::ISSUER_KEY_ID, &[0; 16]));
    let before = Crl::verify(
        host.provider.as_ref(),
        &issuing,
        alice
            .wait_control(kind::CRL_RESPONSE)
            .get(field::CRL)
            .unwrap(),
    )
    .unwrap();
    assert!(!before.is_revoked(&serial));

    host.admin("devices.revoke", json!({ "device_id": device_id }))
        .unwrap();
    alice.wait_until("the session to close", |c| c.closed);

    // A new connection with the revoked certificate is refused.
    let mut again = host.connect(alice.key.clone(), alice.chain.clone());
    again.wait_until("the server to refuse", |c| c.closed);

    let mut fresh = host.pre_enrolment_client();
    fresh.send(&ControlMessage::new(kind::CRL_REQUEST).with(field::ISSUER_KEY_ID, &[0; 16]));
    let after = Crl::verify(
        host.provider.as_ref(),
        &issuing,
        fresh
            .wait_control(kind::CRL_RESPONSE)
            .get(field::CRL)
            .unwrap(),
    )
    .unwrap();
    assert!(after.is_revoked(&serial));
    assert!(
        after.this_update > before.this_update,
        "a newer CRL must replace the cached one"
    );
}

#[test]
fn a_store_failure_on_audit_refuses_the_operation_and_raises_an_alarm() {
    let host = TestHost::start();
    host.create_user("alice");
    let mut client = host.enrolled_client("alice");
    let position_before = host.core.audit_position();

    host.stores.lock().unwrap().fail_audit = true;
    client.send(
        &ControlMessage::new(kind::LOGIN_REQUEST)
            .with_str(field::USER_ID, "alice")
            .with_str(field::SECRET, GOOD_PASSWORD),
    );
    client.wait_until("the server to refuse the login", |c| c.closed);

    assert!(
        host.alarms
            .lock()
            .unwrap()
            .iter()
            .any(|(s, m)| *s == Severity::Critical && m.contains("audit"))
    );
    assert_eq!(
        host.core.audit_position(),
        position_before,
        "a failed append must not move the chain"
    );
    assert!(host.core.metrics().contains("qalqon_logins_ok_total 0"));
}

#[test]
fn the_audit_log_verifies_and_tampering_is_detected() {
    let host = TestHost::start();
    host.create_user("alice");
    let mut client = host.enrolled_client("alice");
    assert_eq!(client.login("alice", GOOD_PASSWORD), ErrorCode::Ok);

    let verified = host.admin("audit.verify", json!({})).unwrap();
    assert_eq!(verified["ok"], true, "{verified}");

    // The exported chain verifies from its genesis with only the server's public key.
    let export = host.admin("audit.export", json!({})).unwrap();
    let entries: Vec<AuditEntry> = serde_json::from_value(export["entries"].clone()).unwrap();
    let checkpoint: qalqon_audit::Checkpoint =
        serde_json::from_value(export["checkpoint"].clone()).unwrap();
    qalqon_audit::verify_chain(host.provider.as_ref(), &host.server_fingerprint(), &entries)
        .unwrap();
    qalqon_audit::verify_checkpoint(
        host.provider.as_ref(),
        host.server_key.public_key(),
        &checkpoint,
        &entries,
    )
    .unwrap();

    // An administrator with database access edits one row.
    {
        let mut stores = host.stores.lock().unwrap();
        let (seq, row) = stores
            .audit
            .iter()
            .next()
            .map(|(k, v)| (*k, v.clone()))
            .unwrap();
        let mut value: Value = serde_json::from_slice(&row).unwrap();
        value["subject"] = json!("someone else");
        stores
            .audit
            .insert(seq, serde_json::to_vec(&value).unwrap());
    }
    let verified = host.admin("audit.verify", json!({})).unwrap();
    assert_eq!(verified["ok"], false);
    assert!(
        host.alarms
            .lock()
            .unwrap()
            .iter()
            .any(|(s, _)| *s == Severity::Critical)
    );
}

#[test]
fn deleting_the_newest_audit_rows_is_detected() {
    let host = TestHost::start();
    host.create_user("alice");
    host.create_user("bob");
    {
        let mut stores = host.stores.lock().unwrap();
        let last = *stores.audit.keys().next_back().unwrap();
        stores.audit.remove(&last);
    }
    assert_eq!(host.admin("audit.verify", json!({})).unwrap()["ok"], false);
}

#[test]
fn a_restart_resumes_the_audit_chain_and_keeps_revocations() {
    let mut host = TestHost::start();
    host.create_user("alice");
    let mut alice = host.logged_in("alice");
    let device_id = alice.device_id();
    let serial = cert::parse_many(host.provider.as_ref(), &alice.chain).unwrap()[0]
        .fields
        .serial;
    host.admin("devices.revoke", json!({ "device_id": device_id }))
        .unwrap();
    alice.hang_up();
    let (seq_before, head_before) = host.core.audit_position();

    // The same stores and keys, with a new core.
    host.stop.store(true, Ordering::SeqCst);
    host.core.shutdown();
    host.thread.take().unwrap().join().unwrap();
    let issuing_secret = host.ca.issuing_key.export_secret().unwrap();
    let issuing_key: Arc<dyn SigningKey> =
        Arc::from(host.provider.import_signing_key(&issuing_secret).unwrap());
    let core = ServerCore::new(options(
        &host.provider,
        &host.ca,
        &host.server_key,
        &host.relay_key,
        issuing_key,
        Policy::default_document(),
    ))
    .unwrap();
    host.core = Arc::new(core);
    host.stop = Arc::new(AtomicBool::new(false));
    host.spawn_loop();
    host.wait_ready();

    let (seq_after, _) = host.core.audit_position();
    assert!(seq_after > seq_before, "the chain must continue");
    let rows = host.audit_rows();
    assert_eq!(rows[seq_before as usize - 1].entry_hash, head_before);
    assert_eq!(
        host.admin("audit.verify", json!({})).unwrap()["ok"],
        true,
        "the chain must not fork at a restart"
    );

    let mut fresh = host.pre_enrolment_client();
    fresh.send(&ControlMessage::new(kind::CRL_REQUEST).with(field::ISSUER_KEY_ID, &[0; 16]));
    let crl = Crl::verify(
        host.provider.as_ref(),
        host.ca.issuing_key.public_key(),
        fresh
            .wait_control(kind::CRL_RESPONSE)
            .get(field::CRL)
            .unwrap(),
    )
    .unwrap();
    assert!(
        crl.is_revoked(&serial),
        "a revocation must survive a restart"
    );
}

#[test]
fn passwords_shorter_than_twelve_characters_are_refused() {
    let host = TestHost::start();
    let refused = host.admin(
        "users.create",
        json!({ "user_id": "alice", "password": "elevenchars" }),
    );
    assert_eq!(refused.unwrap_err(), ErrorCode::InvalidArgument);
    host.admin(
        "users.create",
        json!({ "user_id": "alice", "password": "twelve chars" }),
    )
    .unwrap();
    let refused = host.admin(
        "users.resetPassword",
        json!({ "user_id": "alice", "password": "short" }),
    );
    assert_eq!(refused.unwrap_err(), ErrorCode::InvalidArgument);
}

#[test]
fn the_user_store_holds_a_hash_and_user_listing_never_shows_it() {
    let host = TestHost::start();
    host.create_user("alice");
    let stored = host
        .stores
        .lock()
        .unwrap()
        .users
        .get("alice")
        .cloned()
        .unwrap();
    let text = String::from_utf8(stored).unwrap();
    assert!(!text.contains(GOOD_PASSWORD));
    let listed = host.admin("users.list", json!({})).unwrap();
    assert_eq!(listed[0]["user_id"], "alice");
    assert!(listed[0].get("password_hash").is_none());
}

#[test]
fn disabling_a_user_ends_their_sessions_and_blocks_login() {
    let host = TestHost::start();
    host.create_user("alice");
    let mut session = host.logged_in("alice");
    let (key, chain) = (session.key.clone(), session.chain.clone());
    host.admin("users.disable", json!({ "user_id": "alice" }))
        .unwrap();
    session.wait_until("the session to close", |c| c.closed);
    let mut again = host.connect(key, chain);
    assert_eq!(
        again.login("alice", GOOD_PASSWORD),
        ErrorCode::AuthenticationFailed
    );
}

#[test]
fn a_certificate_can_be_renewed_for_the_same_key() {
    let host = TestHost::start();
    host.create_user("alice");
    let mut alice = host.logged_in("alice");
    alice.send(&ControlMessage::new(kind::CERT_RENEW_REQUEST));
    let result = alice.wait_control(kind::CERT_RENEW_RESULT);
    assert_eq!(result.get_u16(field::STATUS), Some(0));
    let chain =
        cert::parse_many(host.provider.as_ref(), result.get(field::CHAIN).unwrap()).unwrap();
    assert_eq!(chain[0].fields.sign_public, *alice.key.public_key());
    assert_eq!(chain[0].fields.subject_b, alice.device_id());
    let old = cert::parse_many(host.provider.as_ref(), &alice.chain).unwrap();
    assert_ne!(chain[0].fields.serial, old[0].fields.serial);
}

#[test]
fn session_reports_feed_metrics() {
    let host = TestHost::start();
    host.create_user("alice");
    let mut alice = host.logged_in("alice");
    let mut counters = 5u64.to_be_bytes().to_vec();
    counters.extend_from_slice(&100u64.to_be_bytes());
    alice.send(
        &ControlMessage::new(kind::SESSION_REPORT)
            .with(field::SESSION_ID, &[1; 16])
            .with(field::PATH, &[2])
            .with(field::COUNTERS, &counters),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !host
        .core
        .metrics()
        .contains("qalqon_data_sessions_relayed_total 1")
    {
        assert!(Instant::now() < deadline);
        alice.pump();
        std::thread::sleep(Duration::from_millis(1));
    }
    let _ = to_hex(&[]);
}
