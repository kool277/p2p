//! The server side of Qalqon as a library, embedded by every host through its binding
//! or through the sidecar. See `docs/HOST-SPI.md`.
//!
//! A host owns the socket, the database and the configuration, and it hands every frame
//! to [`ServerCore`]. Nothing calls back into the host: `ServerCore` returns [`Effect`]s,
//! which the host performs. So everything here works the same on an event loop, on a
//! thread pool and over the sidecar.
#![forbid(unsafe_code)]

mod exec;
mod flows;
pub mod policy;
pub mod records;

use crate::exec::Executor;
use crate::policy::Policy;
use crypto_provider::{CryptoProvider, SigningKey, to_hex};
use qalqon_audit::{AuditChain, AuditEvent, operation as audit_op};
use qalqon_core::cert::{self, Certificate};
use qalqon_core::control::ControlMessage;
use qalqon_core::crl::Crl;
use qalqon_core::session::{Limits, Plane, Role, SessionConfig, TransportCaps};
use qalqon_core::wire::reason;
use qalqon_core::{ErrorCode, Event, PeerExpectation, Session, UncheckedPeers};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Waker;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use crypto_ext::argon2id::Cost as PasswordCost;

/// Which Host SPI store an effect addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreKind {
    /// `UserStore`.
    User,
    /// `DeviceStore`.
    Device,
    /// `PolicyStore`.
    Policy,
    /// `AuditSink`.
    Audit,
}

/// The operation a store effect requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoreOperation {
    /// Read one record by key.
    Get,
    /// Create or replace one record.
    Put,
    /// Read records. `key` narrows them: `user:<id>` for one user's devices.
    List,
    /// Append one row. `AuditSink` only.
    Append,
    /// Read the latest row. `AuditSink` only.
    Head,
    /// Read rows in a range, with `from,to` in `key`, both inclusive. `AuditSink` only.
    Range,
}

/// How serious an alarm is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Informational.
    Info,
    /// Needs attention.
    Warning,
    /// A likely breach attempt or integrity failure.
    Critical,
}

/// Something the host must do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Send a frame on a connection. No completion is needed.
    SendFrame {
        /// The connection.
        conn_id: u64,
        /// The frame.
        frame: Vec<u8>,
    },
    /// Close a connection. No completion is needed.
    CloseConnection {
        /// The connection.
        conn_id: u64,
        /// The close code.
        code: u16,
    },
    /// Perform a store operation, then call [`ServerCore::complete_effect`].
    Store {
        /// Pass this to `complete_effect`.
        effect_id: u64,
        /// Which store.
        store: StoreKind,
        /// Which operation.
        operation: StoreOperation,
        /// The key, filter or range.
        key: Option<String>,
        /// The record to write, as JSON.
        record: Option<Vec<u8>>,
    },
    /// Raise an alarm to the security administrator. No completion is needed.
    Alarm {
        /// How serious it is.
        severity: Severity,
        /// A short description, containing no secrets.
        summary: String,
    },
}

/// The issuing CA, when this server issues device certificates itself.
pub struct IssuingCa {
    /// The issuing key.
    pub key: Arc<dyn SigningKey>,
    /// The issuing certificate, which is the second certificate of every chain.
    pub certificate: Vec<u8>,
}

impl std::fmt::Debug for IssuingCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IssuingCa(..)")
    }
}

/// What a host hands to [`ServerCore::new`]. The binding layer opens `identity` and
/// `issuing` from a `keyRef`, so a host never holds the key's bytes.
pub struct ServerOptions {
    /// The crypto provider.
    pub provider: Arc<dyn CryptoProvider>,
    /// The server's identity key.
    pub identity: Arc<dyn SigningKey>,
    /// The server's own chain: its role 3 leaf, then the issuing certificate.
    pub chain: Vec<u8>,
    /// The trusted roots, as concatenated certificates.
    pub ca_bundle: Vec<u8>,
    /// Issues device certificates. Without it, enrolment fails.
    pub issuing: Option<IssuingCa>,
    /// Relay addresses for clients.
    pub relay_addresses: Vec<String>,
    /// The key the server shares with its relays, for grants.
    pub relay_key: Vec<u8>,
    /// The key for hashing secrets presented in failed logins (`docs/COMPLIANCE.md`).
    pub audit_key: Vec<u8>,
    /// The policy document to install on first start.
    pub policy: serde_json::Value,
    /// Argon2id cost for new password hashes.
    pub password_cost: PasswordCost,
    /// Protocol limits for control sessions.
    pub limits: Limits,
    /// The current time, so tests can run on a simulated clock.
    pub now_ms: u64,
}

impl std::fmt::Debug for ServerOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerOptions(..)")
    }
}

/// `health()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthSnapshot {
    /// The core is running.
    pub live: bool,
    /// Self-tests passed, the identity key is open and the stores responded.
    pub ready: bool,
    /// A short reason when not ready.
    pub detail: String,
}

pub(crate) struct Conn {
    pub session: Session,
    pub remote: String,
    pub peer: Option<qalqon_core::PeerInfo>,
    pub session_id: Option<[u8; 16]>,
    pub user: Option<AuthenticatedUser>,
}

#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedUser {
    pub user_id: String,
    pub device_id: String,
    pub role: String,
}

pub(crate) struct Rendezvous {
    pub opener: u64,
    pub target: u64,
    pub id: [u8; 16],
    pub accepted: bool,
    pub expires_at: u64,
}

#[derive(Default)]
pub(crate) struct Counters {
    pub handshake_failures: u64,
    pub sessions_total: u64,
    pub logins_ok: u64,
    pub logins_failed: u64,
    pub direct_sessions: u64,
    pub relayed_sessions: u64,
    pub alarms: u64,
    pub rendezvous_opened: u64,
    pub reported_records: u64,
    pub reported_bytes: u64,
}

pub(crate) struct PendingStore {
    pub result: Option<Result<Option<Vec<u8>>, ErrorCode>>,
    pub waker: Option<Waker>,
}

pub(crate) struct State {
    pub now_ms: u64,
    pub next_conn: u64,
    pub conns: HashMap<u64, Conn>,
    pub next_effect: u64,
    pub effects: VecDeque<Effect>,
    pub pending: HashMap<u64, PendingStore>,
    pub online: HashMap<String, HashMap<String, u64>>,
    pub rendezvous: HashMap<[u8; 16], Rendezvous>,
    pub requests: HashMap<(u64, [u8; 16]), [u8; 16]>,
    pub policy: Policy,
    pub revoked: HashSet<[u8; 16]>,
    pub crl: Option<Vec<u8>>,
    pub crl_next_refresh: u64,
    pub crl_this_update: u64,
    pub audit: AuditChain,
    pub audit_locked: bool,
    pub audit_waiters: VecDeque<Waker>,
    pub ready: bool,
    pub not_ready_reason: String,
    pub shut_down: bool,
    pub counters: Counters,
    pub addr_buckets: HashMap<String, (f64, u64)>,
    pub password_jobs: u32,
}

pub(crate) struct Inner {
    pub provider: Arc<dyn CryptoProvider>,
    pub identity: Arc<dyn SigningKey>,
    pub chain: Vec<u8>,
    pub roots: Vec<Certificate>,
    pub issuing: Option<IssuingCa>,
    pub relay_addresses: Vec<String>,
    pub relay_key: Vec<u8>,
    pub audit_key: Vec<u8>,
    pub initial_policy: serde_json::Value,
    pub password_cost: PasswordCost,
    pub limits: Limits,
    pub executor: Arc<Executor>,
    pub state: Mutex<State>,
}

impl Inner {
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// See the crate documentation.
pub struct ServerCore {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for ServerCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerCore(..)")
    }
}

/// The current system time.
pub fn system_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

impl ServerCore {
    /// Creates the core. Runs the provider's self-tests, then starts reading the stores
    /// through effects, so a host's effect loop must be running for it to become ready.
    pub fn new(options: ServerOptions) -> Result<Self, ErrorCode> {
        options
            .provider
            .self_test()
            .map_err(|_| ErrorCode::SelfTestFailed)?;
        let roots = cert::parse_many(options.provider.as_ref(), &options.ca_bundle)
            .map_err(|_| ErrorCode::InvalidArgument)?;
        if roots.is_empty() || options.chain.is_empty() {
            return Err(ErrorCode::InvalidArgument);
        }
        let fingerprint = {
            let encoded = cert::encode_public_key(options.identity.public_key())
                .map_err(|_| ErrorCode::InvalidArgument)?;
            cert::fingerprint(options.provider.as_ref(), &encoded)
        };
        let policy: Policy = serde_json::from_value(options.policy.clone())
            .map_err(|_| ErrorCode::InvalidArgument)?;
        let audit = AuditChain::new(options.provider.as_ref(), &fingerprint);
        let inner = Arc::new(Inner {
            provider: options.provider,
            identity: options.identity,
            chain: options.chain,
            roots,
            issuing: options.issuing,
            relay_addresses: options.relay_addresses,
            relay_key: options.relay_key,
            audit_key: options.audit_key,
            initial_policy: options.policy,
            password_cost: options.password_cost,
            limits: options.limits,
            executor: Arc::new(Executor::default()),
            state: Mutex::new(State {
                now_ms: options.now_ms,
                next_conn: 1,
                conns: HashMap::new(),
                next_effect: 1,
                effects: VecDeque::new(),
                pending: HashMap::new(),
                online: HashMap::new(),
                rendezvous: HashMap::new(),
                requests: HashMap::new(),
                policy,
                revoked: HashSet::new(),
                crl: None,
                crl_next_refresh: 0,
                crl_this_update: 0,
                audit,
                audit_locked: false,
                audit_waiters: VecDeque::new(),
                ready: false,
                not_ready_reason: "waiting for the stores".into(),
                shut_down: false,
                counters: Counters::default(),
                addr_buckets: HashMap::new(),
                password_jobs: 0,
            }),
        });
        let core = ServerCore { inner };
        core.spawn(flows::startup(core.inner.clone()));
        Ok(core)
    }

    fn spawn(&self, task: impl std::future::Future<Output = ()> + Send + 'static) {
        self.inner.executor.spawn(Box::pin(task));
    }

    fn running(&self) -> Result<MutexGuard<'_, State>, ErrorCode> {
        let state = self.inner.lock();
        if state.shut_down {
            Err(ErrorCode::Closed)
        } else {
            Ok(state)
        }
    }

    /// Registers an accepted WebSocket connection and returns its identifier.
    pub fn accept(&self, remote_address: &str) -> Result<u64, ErrorCode> {
        let mut state = self.running()?;
        let now = state.now_ms;
        if !flows::take_address_token(&mut state, remote_address, now) {
            return Err(ErrorCode::RateLimited);
        }
        let inner = &self.inner;
        let session = Session::new(
            SessionConfig {
                provider: inner.provider.clone(),
                role: Role::Responder,
                plane: Plane::Control,
                transport: TransportCaps::STREAM,
                identity: inner.identity.clone(),
                chain: inner.chain.clone(),
                roots: inner.roots.clone(),
                expectation: PeerExpectation::Client,
                // Revocation is checked as soon as the handshake reports the peer, before
                // any control message is acted on.
                verifier: Box::new(UncheckedPeers),
                versions: SessionConfig::default_versions(),
                suites: inner.provider.suites().to_vec(),
                cached_peer_chain: None,
                rendezvous_id: None,
                limits: inner.limits,
            },
            now,
        )
        .map_err(|_| ErrorCode::Internal)?;
        let conn_id = state.next_conn;
        state.next_conn += 1;
        state.conns.insert(
            conn_id,
            Conn {
                session,
                remote: remote_address.into(),
                peer: None,
                session_id: None,
                user: None,
            },
        );
        Ok(conn_id)
    }

    /// Hands the core a frame from a connection. Returns quickly: results surface as effects.
    pub fn on_frame(&self, conn_id: u64, frame: &[u8]) -> Result<(), ErrorCode> {
        let mut state = self.running()?;
        let now = state.now_ms;
        let conn = state
            .conns
            .get_mut(&conn_id)
            .ok_or(ErrorCode::InvalidArgument)?;
        conn.session.handle_frame(now, frame);
        drop(state);
        self.pump_connection(conn_id);
        self.inner.executor.run_ready();
        Ok(())
    }

    /// Reports that a connection has ended.
    pub fn on_close(&self, conn_id: u64) -> Result<(), ErrorCode> {
        let mut state = self.running()?;
        let now = state.now_ms;
        let conn = state
            .conns
            .get_mut(&conn_id)
            .ok_or(ErrorCode::InvalidArgument)?;
        conn.session.on_transport_closed(now);
        drop(state);
        self.pump_connection(conn_id);
        self.remove_connection(conn_id);
        self.inner.executor.run_ready();
        Ok(())
    }

    /// Drives timers. Call this about once a second.
    pub fn tick(&self, now_ms: u64) -> Result<(), ErrorCode> {
        let mut state = self.running()?;
        state.now_ms = state.now_ms.max(now_ms);
        let now = state.now_ms;
        let ids: Vec<u64> = state.conns.keys().copied().collect();
        for id in &ids {
            if let Some(conn) = state.conns.get_mut(id) {
                conn.session.handle_timeout(now);
            }
        }
        state.rendezvous.retain(|_, r| r.expires_at > now);
        let live: HashSet<[u8; 16]> = state.rendezvous.keys().copied().collect();
        state.requests.retain(|_, id| live.contains(id));
        let refresh_crl = state.ready && now >= state.crl_next_refresh;
        drop(state);
        for id in ids {
            self.pump_connection(id);
        }
        if refresh_crl && self.inner.issuing.is_some() {
            self.spawn(flows::publish_crl(self.inner.clone()));
        }
        self.inner.executor.run_ready();
        Ok(())
    }

    /// Returns the next thing the host must do, waiting up to `timeout` for one. A wait
    /// is needed because password checks finish on worker threads.
    pub fn poll_effect(&self, timeout: Duration) -> Result<Option<Effect>, ErrorCode> {
        let deadline = Instant::now() + timeout;
        loop {
            self.inner.executor.run_ready();
            {
                let mut state = self.inner.lock();
                if let Some(effect) = state.effects.pop_front() {
                    return Ok(Some(effect));
                }
                if state.shut_down {
                    return Err(ErrorCode::Closed);
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let executor = &self.inner.executor;
            let guard = executor
                .activity_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // Bounded, so a wakeup that races this wait costs at most this long.
            let wait = (deadline - now).min(Duration::from_millis(20));
            let _ = executor.activity.wait_timeout(guard, wait);
        }
    }

    /// Reports the result of a store effect: 0 for success, otherwise an error code.
    pub fn complete_effect(
        &self,
        effect_id: u64,
        status: u32,
        record: Option<Vec<u8>>,
    ) -> Result<(), ErrorCode> {
        let waker = {
            let mut state = self.running()?;
            let pending = state
                .pending
                .get_mut(&effect_id)
                .ok_or(ErrorCode::InvalidArgument)?;
            pending.result = Some(if status == 0 {
                Ok(record)
            } else {
                Err(ErrorCode::from_code(status).unwrap_or(ErrorCode::Internal))
            });
            pending.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        self.inner.executor.run_ready();
        Ok(())
    }

    /// Runs an admin operation after the host has authenticated the caller. This
    /// blocks until the stores have answered, so the host's effect loop must be running
    /// on another thread.
    pub fn admin_call(&self, method: &str, params_json: &str) -> Result<String, ErrorCode> {
        self.running().map(drop)?;
        let params: serde_json::Value = serde_json::from_str(if params_json.is_empty() {
            "{}"
        } else {
            params_json
        })
        .map_err(|_| ErrorCode::InvalidArgument)?;
        let slot = Arc::new(Mutex::new(None));
        let writer = slot.clone();
        let inner = self.inner.clone();
        let method = method.to_string();
        self.spawn(async move {
            let result = flows::admin(inner.clone(), &method, params).await;
            *writer.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
            inner.executor.notify();
        });
        self.inner.executor.notify();
        loop {
            if let Some(result) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
                return result;
            }
            let executor = &self.inner.executor;
            let guard = executor
                .activity_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let _ = executor
                .activity
                .wait_timeout(guard, Duration::from_millis(10));
        }
    }

    /// Returns liveness and readiness.
    pub fn health(&self) -> HealthSnapshot {
        let state = self.inner.lock();
        HealthSnapshot {
            live: !state.shut_down,
            ready: state.ready && !state.shut_down,
            detail: if state.ready {
                String::new()
            } else {
                state.not_ready_reason.clone()
            },
        }
    }

    /// Returns counters in Prometheus text format. These names are fixed, so that
    /// dashboards work on every host.
    pub fn metrics(&self) -> String {
        let state = self.inner.lock();
        let c = &state.counters;
        let active = state.conns.len();
        let rows: [(&str, &str, u64); 10] = [
            (
                "qalqon_sessions_active",
                "Control sessions now open.",
                active as u64,
            ),
            (
                "qalqon_sessions_total",
                "Control sessions established.",
                c.sessions_total,
            ),
            (
                "qalqon_handshake_failures_total",
                "Handshakes that failed.",
                c.handshake_failures,
            ),
            ("qalqon_logins_ok_total", "Successful logins.", c.logins_ok),
            (
                "qalqon_logins_failed_total",
                "Failed logins.",
                c.logins_failed,
            ),
            (
                "qalqon_rendezvous_opened_total",
                "Rendezvous requests delivered.",
                c.rendezvous_opened,
            ),
            (
                "qalqon_data_sessions_direct_total",
                "Self-reported direct data sessions.",
                c.direct_sessions,
            ),
            (
                "qalqon_data_sessions_relayed_total",
                "Self-reported relayed data sessions.",
                c.relayed_sessions,
            ),
            ("qalqon_alarms_total", "Alarms raised.", c.alarms),
            (
                "qalqon_audit_entries",
                "Audit chain length.",
                state.audit.seq(),
            ),
        ];
        let mut out = String::new();
        for (name, help, value) in rows {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
            ));
        }
        out
    }

    /// Stops the core. Secrets held by sessions are zeroized as they drop.
    pub fn shutdown(&self) {
        let mut state = self.inner.lock();
        state.shut_down = true;
        state.conns.clear();
        drop(state);
        self.inner.executor.notify();
    }

    /// Moves everything a session produced into effects and acts on its events.
    fn pump_connection(&self, conn_id: u64) {
        let mut events = Vec::new();
        {
            let mut state = self.inner.lock();
            let Some(conn) = state.conns.get_mut(&conn_id) else {
                return;
            };
            while let Some(event) = conn.session.poll_event() {
                events.push(event);
            }
        }
        for event in events {
            self.on_session_event(conn_id, event);
        }
        flows::flush_connection(&self.inner, conn_id);
    }

    fn on_session_event(&self, conn_id: u64, event: Event) {
        match event {
            Event::Established {
                peer, session_id, ..
            } => {
                let subject = format!("{}/{}", peer.subject_a, peer.subject_b);
                let mut state = self.inner.lock();
                // A revoked device cannot get past the handshake.
                if state.revoked.contains(&peer.serial) {
                    let now = state.now_ms;
                    if let Some(conn) = state.conns.get_mut(&conn_id) {
                        conn.session.close(now, reason::REJECTED);
                    }
                    state.counters.handshake_failures += 1;
                    state.effects.push_back(Effect::CloseConnection {
                        conn_id,
                        code: 4403,
                    });
                    drop(state);
                    self.spawn(flows::audit_only(
                        self.inner.clone(),
                        subject,
                        "session".into(),
                        audit_op::SESSION_ESTABLISHED.into(),
                        ErrorCode::PeerRevoked.name().into(),
                        String::new(),
                    ));
                    return;
                }
                state.counters.sessions_total += 1;
                if let Some(conn) = state.conns.get_mut(&conn_id) {
                    conn.peer = Some(peer);
                    conn.session_id = Some(session_id);
                }
                drop(state);
                self.spawn(flows::audit_only(
                    self.inner.clone(),
                    subject,
                    to_hex(&session_id),
                    audit_op::SESSION_ESTABLISHED.into(),
                    "ok".into(),
                    String::new(),
                ));
            }
            Event::HandshakeFailed(failure) => {
                let mut state = self.inner.lock();
                state.counters.handshake_failures += 1;
                let remote = state
                    .conns
                    .get(&conn_id)
                    .map(|c| c.remote.clone())
                    .unwrap_or_default();
                state.effects.push_back(Effect::CloseConnection {
                    conn_id,
                    code: 4400,
                });
                drop(state);
                self.spawn(flows::audit_only(
                    self.inner.clone(),
                    remote,
                    "session".into(),
                    audit_op::SESSION_ESTABLISHED.into(),
                    failure.code.name().into(),
                    failure.detail.into(),
                ));
            }
            Event::Control { body } => match ControlMessage::decode(&body) {
                Ok(message) => self.spawn(flows::control(self.inner.clone(), conn_id, message)),
                Err(_) => {
                    let mut state = self.inner.lock();
                    let now = state.now_ms;
                    if let Some(conn) = state.conns.get_mut(&conn_id) {
                        conn.session.close(now, reason::PROTOCOL_ERROR);
                    }
                }
            },
            Event::Closed {
                clean,
                reason: code,
            } => {
                let mut state = self.inner.lock();
                let subject = state
                    .conns
                    .get(&conn_id)
                    .and_then(|c| c.peer.as_ref())
                    .map_or_else(String::new, |p| format!("{}/{}", p.subject_a, p.subject_b));
                let id = state.conns.get(&conn_id).and_then(|c| c.session_id);
                state.effects.push_back(Effect::CloseConnection {
                    conn_id,
                    code: 1000,
                });
                drop(state);
                if let Some(id) = id {
                    self.spawn(flows::audit_only(
                        self.inner.clone(),
                        subject,
                        to_hex(&id),
                        audit_op::SESSION_TEARDOWN.into(),
                        "ok".into(),
                        format!("clean={clean} reason={code}"),
                    ));
                }
            }
            // Control sessions carry no channels, and rotation needs no host action.
            _ => {}
        }
    }

    fn remove_connection(&self, conn_id: u64) {
        let mut state = self.inner.lock();
        if let Some(conn) = state.conns.remove(&conn_id)
            && let Some(user) = &conn.user
            && let Some(devices) = state.online.get_mut(&user.user_id)
        {
            devices.remove(&user.device_id);
        }
        state
            .rendezvous
            .retain(|_, r| r.opener != conn_id && r.target != conn_id);
        state.requests.retain(|(conn, _), _| *conn != conn_id);
    }

    /// The server's chain, which a test or a tool can show.
    pub fn chain(&self) -> &[u8] {
        &self.inner.chain
    }

    /// Verifies the audit log's current head against what the core holds. Exposed for
    /// `audit.verify`, and for tests.
    pub fn audit_position(&self) -> (u64, String) {
        let state = self.inner.lock();
        (state.audit.seq(), to_hex(state.audit.head()))
    }
}

pub(crate) fn audit_event(
    now_ms: u64,
    subject: String,
    object: String,
    operation: String,
    result: String,
    detail: String,
) -> AuditEvent {
    AuditEvent {
        at: now_ms,
        subject,
        object,
        operation,
        result,
        detail,
    }
}

pub(crate) fn serials_from_crl(crl: &Crl) -> HashSet<[u8; 16]> {
    crl.revoked.iter().copied().collect()
}
