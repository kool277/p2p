//! The client side of Qalqon, as a sans-I/O state machine.
//!
//! [`ClientCore`] holds the control session, the login, rendezvous, path selection and
//! every peer session. It never touches a socket or a thread: it issues
//! [`TransportCommand`]s and is told what happened, which is exactly the
//! `ExternalTransport` contract in `docs/CLIENT-ADAPTER.md`. A native SDK answers those
//! commands with sockets on its own threads, and a browser answers them from JavaScript.
//!
//! Long operations return an operation number, and their result arrives through
//! [`ClientCore::take_completion`].
#![forbid(unsafe_code)]

mod trust;

pub use trust::{SavedState, Trust};

use crypto_provider::suite::is_test_only;
use crypto_provider::{CryptoProvider, SigningKey, Zeroizing, to_hex};
use qalqon_api as api;
use qalqon_api::{ErrorKind, TransportCommand};
use qalqon_audit::{AuditChain, AuditEntry, AuditEvent, operation as audit_op, to_jsonl};
use qalqon_core::cert::{self, Certificate};
use qalqon_core::control::{
    ControlMessage, RelayGrant, encode_channel_options, field, kind, parse_channel_options, parse_grants,
};
use qalqon_core::crl::Crl;
use qalqon_core::pins::safety_number;
use qalqon_core::relay;
use qalqon_core::session::{Limits, Plane, Role, SessionConfig, TransportCaps};
use qalqon_core::wire::reason;
use qalqon_core::{ChannelOptions, ErrorCode, Event, PeerExpectation, PeerInfo, PinStatus, Session};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use trust::{DataPlaneVerifier, UncheckedControlVerifier};

/// How long a direct path gets before falling back to the relay. The responder waits
/// longer than the initiator, so a late direct connection still finds it listening.
const DIRECT_TIMEOUT_INITIATOR_MS: u64 = 3_000;
const DIRECT_TIMEOUT_RESPONDER_MS: u64 = 4_000;
const DEFAULT_CHANNEL_TIMEOUT_MS: u64 = 30_000;
const LOGIN_TIMEOUT_MS: u64 = 30_000;
/// A relay sends this once both sides have joined.
const RELAY_PAIRED: &[u8] = &[1];

/// What a client session needs to start.
pub struct ClientOptions {
    /// The crypto provider.
    pub provider: Arc<dyn CryptoProvider>,
    /// `wss://host/qalqon`. `ws://` is only accepted for a loopback host.
    pub server_url: String,
    /// The trusted roots, as concatenated certificates.
    pub ca_bundle: Vec<u8>,
    /// This device's long-term key.
    pub identity: Arc<dyn SigningKey>,
    /// This device's chain. `None` means not enrolled, so a pre-enrolment certificate is used.
    pub chain: Option<Vec<u8>>,
    /// How to reach peers.
    pub relay_policy: api::RelayPolicy,
    /// What to do when a peer's identity changes.
    pub identity_change_policy: api::IdentityChangePolicy,
    /// How long past a CRL's next update new peer sessions are still allowed.
    pub revocation_grace_ms: u64,
    /// Pins, known chains and the audit chain from an earlier run.
    pub saved: SavedState,
    /// Protocol limits.
    pub limits: Limits,
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions").field("server_url", &self.server_url).finish_non_exhaustive()
    }
}

/// The successful result of an operation.
#[derive(Debug, PartialEq, Eq)]
pub enum OpValue {
    /// Nothing to return.
    None,
    /// Enrolment finished. The chain should be stored with the key.
    Enrolled {
        /// The public result.
        result: api::EnrollmentResult,
        /// The new chain.
        chain: Vec<u8>,
    },
    /// A channel is ready, with this identifier.
    Channel(u64),
}

/// An operation's outcome.
pub type OpResult = Result<OpValue, ErrorKind>;

fn kind_of(code: ErrorCode) -> ErrorKind {
    ErrorKind::from_code(code.code()).unwrap_or(ErrorKind::Internal)
}

/// Parses `serverUrl`, and refuses anything that would turn off platform transport
/// security (build prompt §1.1).
fn parse_server_host(url: &str) -> Result<String, ErrorKind> {
    let (scheme, rest) = url.split_once("://").ok_or(ErrorKind::InvalidArgument)?;
    let authority = rest.split('/').next().unwrap_or("");
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("").to_string()
    } else {
        authority.split(':').next().unwrap_or("").to_string()
    };
    if host.is_empty() {
        return Err(ErrorKind::InvalidArgument);
    }
    let loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");
    match scheme {
        "wss" | "tcp+tls" => Ok(host),
        "ws" | "tcp" if loopback => Ok(host),
        _ => Err(ErrorKind::InvalidArgument),
    }
}

enum ControlStage {
    Idle,
    Connecting,
    Handshaking,
    FetchingCrl,
    Enrolling,
    LoggingIn,
    Ready,
    Closed,
}

enum Goal {
    Login { op: u64, user_id: String, secret: Zeroizing<Vec<u8>>, mfa_code: Option<String> },
    Enroll { op: u64, token: String, device_name: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinkPurpose {
    Control,
    Direct(u64),
    Relay { peer: u64, joined: bool, paired: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerStage {
    Rendezvous,
    AwaitingAccept,
    Connecting,
    Handshaking,
    Established,
}

enum Waiting {
    /// `openChannel`: open this channel once the session is up.
    Open { op: u64, handle: u64, deadline: u64 },
    /// `acceptChannel`: complete when the initiator's channel request arrives.
    Accept { op: u64, handle: u64, deadline: u64 },
}

struct Peer {
    id: u64,
    user_id: String,
    device_id: Option<String>,
    request_id: [u8; 16],
    rendezvous_id: Option<[u8; 16]>,
    role: Role,
    stage: PeerStage,
    grants: Vec<RelayGrant>,
    link: Option<u64>,
    path: Option<api::PathKind>,
    direct_deadline: Option<u64>,
    buffered_signals: Vec<Vec<u8>>,
    session: Option<Session>,
    waiting: Vec<Waiting>,
    options: api::ChannelOptions,
    hint_chain: Vec<u8>,
    peer_info: Option<PeerInfo>,
    session_id: Option<[u8; 16]>,
    rotate_ops: Vec<u64>,
}

struct ChannelEntry {
    peer: u64,
    wire_id: Option<u16>,
    inbox: VecDeque<Vec<u8>>,
    open: bool,
    options: api::ChannelOptions,
    close_op: Option<u64>,
}

/// See the crate documentation.
pub struct ClientCore {
    provider: Arc<dyn CryptoProvider>,
    server_url: String,
    server_host: String,
    identity: Arc<dyn SigningKey>,
    my_fingerprint: Vec<u8>,
    chain: Vec<u8>,
    enrolled: bool,
    roots: Vec<Certificate>,
    relay_policy: api::RelayPolicy,
    limits: Limits,
    trust: Arc<Mutex<Trust>>,

    stage: ControlStage,
    control_link: Option<u64>,
    control: Option<Session>,
    server_issuing: Option<crypto_provider::PublicKey>,
    server_serial: Option<[u8; 16]>,
    goal: Option<Goal>,
    goal_deadline: Option<u64>,
    crl_refresh_at: Option<u64>,
    close_op: Option<u64>,

    next_link: u64,
    links: HashMap<u64, LinkPurpose>,
    relay_caps: HashMap<u64, TransportCaps>,
    commands: VecDeque<TransportCommand>,

    next_peer: u64,
    peers: BTreeMap<u64, Peer>,
    next_channel: u64,
    channels: BTreeMap<u64, ChannelEntry>,
    /// `channelRequested` from a live session: request text to (peer, wire id, handle).
    session_requests: HashMap<String, (u64, u16, api::ChannelOptions)>,

    next_op: u64,
    completions: HashMap<u64, OpResult>,
    events: VecDeque<api::Event>,

    audit: AuditChain,
    audit_entries: Vec<AuditEntry>,
    audit_unsaved: Vec<AuditEntry>,
    dirty: bool,
}

impl std::fmt::Debug for ClientCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCore").field("server_url", &self.server_url).finish_non_exhaustive()
    }
}

impl ClientCore {
    /// Creates the core and runs the provider's self-tests.
    pub fn new(options: ClientOptions, now_ms: u64) -> Result<Self, ErrorKind> {
        let p = options.provider.as_ref();
        p.self_test().map_err(|_| ErrorKind::SelfTestFailed)?;
        let server_host = parse_server_host(&options.server_url)?;
        let roots = cert::parse_many(p, &options.ca_bundle).map_err(|_| ErrorKind::InvalidArgument)?;
        if roots.is_empty() {
            return Err(ErrorKind::InvalidArgument);
        }
        let encoded = cert::encode_public_key(options.identity.public_key()).map_err(|_| ErrorKind::Internal)?;
        let my_fingerprint = cert::fingerprint(p, &encoded);

        let (enrolled, chain) = match options.chain {
            Some(chain) => (true, chain),
            None => {
                let day = 24 * 60 * 60 * 1000;
                let chain = cert::pre_enrolment(p, options.identity.as_ref(), now_ms.saturating_sub(day), now_ms + day)
                    .map_err(|_| ErrorKind::Internal)?;
                (false, chain)
            }
        };

        let audit_entries = options.saved.audit_entries.clone();
        let audit = match audit_entries.last() {
            Some(last) => AuditChain::resume(
                crypto_provider::from_hex(&last.entry_hash).ok_or(ErrorKind::Internal)?,
                last.seq,
            ),
            None => AuditChain::new(p, &my_fingerprint),
        };
        let trust = Trust::from_saved(&options.saved, options.identity_change_policy, options.revocation_grace_ms);

        Ok(ClientCore {
            provider: options.provider,
            server_url: options.server_url,
            server_host,
            identity: options.identity,
            my_fingerprint,
            chain,
            enrolled,
            roots,
            relay_policy: options.relay_policy,
            limits: options.limits,
            trust: Arc::new(Mutex::new(trust)),
            stage: ControlStage::Idle,
            control_link: None,
            control: None,
            server_issuing: None,
            server_serial: None,
            goal: None,
            goal_deadline: None,
            crl_refresh_at: None,
            close_op: None,
            next_link: 1,
            links: HashMap::new(),
            relay_caps: HashMap::new(),
            commands: VecDeque::new(),
            next_peer: 1,
            peers: BTreeMap::new(),
            next_channel: 1,
            channels: BTreeMap::new(),
            session_requests: HashMap::new(),
            next_op: 1,
            completions: HashMap::new(),
            events: VecDeque::new(),
            audit,
            audit_entries,
            audit_unsaved: Vec::new(),
            dirty: false,
        })
    }

    fn new_op(&mut self) -> u64 {
        let op = self.next_op;
        self.next_op += 1;
        op
    }

    fn complete(&mut self, op: u64, result: OpResult) {
        self.completions.insert(op, result);
    }

    /// Takes an operation's result, if it has finished.
    pub fn take_completion(&mut self, op: u64) -> Option<OpResult> {
        self.completions.remove(&op)
    }

    /// The next command for the transport.
    pub fn poll_command(&mut self) -> Option<TransportCommand> {
        self.commands.pop_front()
    }

    /// The next event for the application.
    pub fn poll_event(&mut self) -> Option<api::Event> {
        self.events.pop_front()
    }

    /// True while the control session is logged in.
    pub fn is_ready(&self) -> bool {
        matches!(self.stage, ControlStage::Ready)
    }

    /// True once the session has ended.
    pub fn is_closed(&self) -> bool {
        matches!(self.stage, ControlStage::Closed)
    }

    /// Returns what should be saved, if anything has changed since the last call.
    pub fn take_state_to_save(&mut self) -> Option<SavedState> {
        if !self.dirty && self.audit_unsaved.is_empty() {
            return None;
        }
        self.dirty = false;
        self.audit_unsaved.clear();
        let trust = self.trust.lock().unwrap_or_else(|e| e.into_inner());
        Some(trust.to_saved(self.audit_entries.clone()))
    }

    fn audit_event(&mut self, now_ms: u64, subject: &str, object: &str, operation: &str, result: &str, detail: &str) {
        let entry = self.audit.append(
            self.provider.as_ref(),
            AuditEvent {
                at: now_ms,
                subject: subject.into(),
                object: object.into(),
                operation: operation.into(),
                result: result.into(),
                detail: detail.into(),
            },
        );
        self.audit_unsaved.push(entry.clone());
        self.audit_entries.push(entry);
    }

    fn set_state(&mut self, state: api::SessionState) {
        self.events.push_back(api::Event::StateChanged { state });
    }

    // ------------------------------------------------------------- public operations

    /// Starts `enrollDevice`: connects with a pre-enrolment certificate and asks for a
    /// real one.
    pub fn start_enroll(&mut self, now_ms: u64, request: api::EnrollmentRequest) -> u64 {
        let op = self.new_op();
        if !matches!(self.stage, ControlStage::Idle) {
            self.complete(op, Err(ErrorKind::InvalidState));
            return op;
        }
        self.goal = Some(Goal::Enroll { op, token: request.enrollment_token, device_name: request.device_name });
        self.open_control(now_ms);
        op
    }

    /// Starts `connect`.
    pub fn start_connect(&mut self, now_ms: u64, credentials: api::Credentials) -> u64 {
        let op = self.new_op();
        if !matches!(self.stage, ControlStage::Idle) {
            self.complete(op, Err(ErrorKind::InvalidState));
            return op;
        }
        if !self.enrolled {
            self.complete(op, Err(ErrorKind::NotEnrolled));
            return op;
        }
        self.goal = Some(Goal::Login {
            op,
            user_id: credentials.user_id,
            secret: Zeroizing::new(credentials.secret),
            mfa_code: credentials.mfa_code,
        });
        self.open_control(now_ms);
        op
    }

    fn open_control(&mut self, now_ms: u64) {
        let link = self.next_link;
        self.next_link += 1;
        self.links.insert(link, LinkPurpose::Control);
        self.control_link = Some(link);
        self.stage = ControlStage::Connecting;
        self.goal_deadline = Some(now_ms + LOGIN_TIMEOUT_MS);
        self.commands.push_back(TransportCommand::OpenLink {
            link_id: link,
            kind: api::LinkKind::Server,
            url: Some(self.server_url.clone()),
            initiator: true,
        });
        self.set_state(api::SessionState::Connecting);
    }

    fn fail_goal(&mut self, code: ErrorKind) {
        if let Some(goal) = self.goal.take() {
            let op = match goal {
                Goal::Login { op, .. } | Goal::Enroll { op, .. } => op,
            };
            self.complete(op, Err(code));
        }
        self.goal_deadline = None;
    }

    /// Starts `openChannel`.
    pub fn open_channel(&mut self, now_ms: u64, peer: api::PeerRef, options: api::ChannelOptions) -> u64 {
        let op = self.new_op();
        if !self.is_ready() {
            self.complete(op, Err(ErrorKind::Closed));
            return op;
        }
        if options.label.len() > 255 {
            self.complete(op, Err(ErrorKind::InvalidArgument));
            return op;
        }
        let deadline = now_ms + options.timeout_ms.map_or(DEFAULT_CHANNEL_TIMEOUT_MS, u64::from);
        let handle = self.new_channel(0, options.clone());

        // A second channel to a connected peer multiplexes over its session.
        let existing = self
            .peers
            .values()
            .find(|p| {
                p.stage == PeerStage::Established
                    && p.user_id == peer.user_id
                    && peer.device_id.as_ref().is_none_or(|d| p.device_id.as_ref() == Some(d))
            })
            .map(|p| p.id);
        if let Some(peer_id) = existing {
            if let Some(entry) = self.channels.get_mut(&handle) {
                entry.peer = peer_id;
            }
            self.open_on_session(now_ms, peer_id, op, handle, deadline);
            self.drive(now_ms);
            return op;
        }

        let mut request_id = [0u8; 16];
        if self.provider.random(&mut request_id).is_err() {
            self.complete(op, Err(ErrorKind::Internal));
            return op;
        }
        let peer_id = self.next_peer;
        self.next_peer += 1;
        if let Some(entry) = self.channels.get_mut(&handle) {
            entry.peer = peer_id;
        }
        let Ok(option_bytes) = encode_channel_options(options.ordered, options.reliable, &options.label) else {
            self.complete(op, Err(ErrorKind::InvalidArgument));
            return op;
        };
        let mut message = ControlMessage::new(kind::RENDEZVOUS_OPEN)
            .with(field::REQUEST_ID, &request_id)
            .with_str(field::USER_ID, &peer.user_id)
            .with(field::CHANNEL_OPTIONS, &option_bytes);
        if let Some(device) = &peer.device_id {
            message = message.with_str(field::DEVICE_ID, device);
        }
        self.peers.insert(
            peer_id,
            Peer {
                id: peer_id,
                user_id: peer.user_id,
                device_id: peer.device_id,
                request_id,
                rendezvous_id: None,
                role: Role::Initiator,
                stage: PeerStage::Rendezvous,
                grants: Vec::new(),
                link: None,
                path: None,
                direct_deadline: None,
                buffered_signals: Vec::new(),
                session: None,
                waiting: vec![Waiting::Open { op, handle, deadline }],
                options,
                hint_chain: Vec::new(),
                peer_info: None,
                session_id: None,
                rotate_ops: Vec::new(),
            },
        );
        self.send_control(now_ms, &message);
        self.drive(now_ms);
        op
    }

    fn new_channel(&mut self, peer: u64, options: api::ChannelOptions) -> u64 {
        let handle = self.next_channel;
        self.next_channel += 1;
        self.channels.insert(
            handle,
            ChannelEntry { peer, wire_id: None, inbox: VecDeque::new(), open: false, options, close_op: None },
        );
        handle
    }

    fn open_on_session(&mut self, now_ms: u64, peer_id: u64, op: u64, handle: u64, deadline: u64) {
        let Some(options) = self.channels.get(&handle).map(|c| c.options.clone()) else { return };
        let Some(session) = self.peers.get_mut(&peer_id).and_then(|p| p.session.as_mut()) else {
            self.complete(op, Err(ErrorKind::Closed));
            return;
        };
        let wire_options =
            ChannelOptions { ordered: options.ordered, reliable: options.reliable, label: options.label.clone() };
        match session.open_channel(now_ms, wire_options) {
            Ok(wire_id) => {
                if let Some(entry) = self.channels.get_mut(&handle) {
                    entry.wire_id = Some(wire_id);
                }
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.waiting.push(Waiting::Open { op, handle, deadline });
                }
            }
            Err(code) => {
                self.channels.remove(&handle);
                self.complete(op, Err(kind_of(code)));
            }
        }
    }

    /// Starts `acceptChannel`.
    pub fn accept_channel(&mut self, now_ms: u64, request_id: &str) -> u64 {
        let op = self.new_op();
        // A channel requested inside a live session.
        if let Some((peer_id, wire_id, options)) = self.session_requests.remove(request_id) {
            let handle = self.new_channel(peer_id, options);
            let accepted = self
                .peers
                .get_mut(&peer_id)
                .and_then(|p| p.session.as_mut())
                .map_or(Err(ErrorCode::Closed), |s| s.accept_channel(now_ms, wire_id));
            match accepted {
                Ok(()) => {
                    if let Some(entry) = self.channels.get_mut(&handle) {
                        entry.wire_id = Some(wire_id);
                        entry.open = true;
                    }
                    self.complete(op, Ok(OpValue::Channel(handle)));
                    self.events.push_back(api::Event::ChannelOpened { channel_id: handle });
                }
                Err(code) => {
                    self.channels.remove(&handle);
                    self.complete(op, Err(kind_of(code)));
                }
            }
            self.drive(now_ms);
            return op;
        }
        // A rendezvous from another client.
        let found = self
            .peers
            .values()
            .find(|p| p.stage == PeerStage::AwaitingAccept && to_hex(&p.request_id) == request_id)
            .map(|p| p.id);
        let Some(peer_id) = found else {
            self.complete(op, Err(ErrorKind::InvalidArgument));
            return op;
        };
        let (request, options, deadline) = {
            let peer = &self.peers[&peer_id];
            (peer.request_id, peer.options.clone(), now_ms + DEFAULT_CHANNEL_TIMEOUT_MS)
        };
        let handle = self.new_channel(peer_id, options);
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.waiting.push(Waiting::Accept { op, handle, deadline });
            peer.stage = PeerStage::Connecting;
        }
        self.send_control(now_ms, &ControlMessage::new(kind::RENDEZVOUS_ACCEPT).with(field::REQUEST_ID, &request));
        self.start_paths(now_ms, peer_id);
        self.drive(now_ms);
        op
    }

    /// `rejectChannel`.
    pub fn reject_channel(&mut self, now_ms: u64, request_id: &str) -> Result<(), ErrorKind> {
        if let Some((peer_id, wire_id, _)) = self.session_requests.remove(request_id) {
            let session = self.peers.get_mut(&peer_id).and_then(|p| p.session.as_mut()).ok_or(ErrorKind::Closed)?;
            session.reject_channel(now_ms, wire_id, reason::REJECTED).map_err(kind_of)?;
            self.drive(now_ms);
            return Ok(());
        }
        let found = self
            .peers
            .values()
            .find(|p| p.stage == PeerStage::AwaitingAccept && to_hex(&p.request_id) == request_id)
            .map(|p| (p.id, p.request_id));
        let (peer_id, request) = found.ok_or(ErrorKind::InvalidArgument)?;
        self.peers.remove(&peer_id);
        self.send_control(now_ms, &ControlMessage::new(kind::RENDEZVOUS_REJECT).with(field::REQUEST_ID, &request));
        self.drive(now_ms);
        Ok(())
    }

    /// `channel.send`.
    pub fn send(&mut self, now_ms: u64, channel_id: u64, payload: &[u8]) -> Result<(), ErrorKind> {
        let entry = self.channels.get(&channel_id).ok_or(ErrorKind::InvalidArgument)?;
        if !entry.open {
            return Err(ErrorKind::Closed);
        }
        let wire_id = entry.wire_id.ok_or(ErrorKind::InvalidState)?;
        let peer_id = entry.peer;
        let session = self.peers.get_mut(&peer_id).and_then(|p| p.session.as_mut()).ok_or(ErrorKind::Closed)?;
        session.send(now_ms, wire_id, payload).map_err(kind_of)?;
        self.drive(now_ms);
        Ok(())
    }

    /// `channel.receive`, without waiting. `Ok(None)` means nothing is ready yet.
    pub fn receive(&mut self, channel_id: u64) -> Result<Option<Vec<u8>>, ErrorKind> {
        let entry = self.channels.get_mut(&channel_id).ok_or(ErrorKind::InvalidArgument)?;
        match entry.inbox.pop_front() {
            Some(message) => Ok(Some(message)),
            None if !entry.open => Err(ErrorKind::Closed),
            None => Ok(None),
        }
    }

    /// `channel.info`.
    pub fn channel_info(&self, channel_id: u64) -> Result<api::ChannelInfo, ErrorKind> {
        let entry = self.channels.get(&channel_id).ok_or(ErrorKind::InvalidArgument)?;
        let peer = self.peers.get(&entry.peer).ok_or(ErrorKind::Closed)?;
        Ok(api::ChannelInfo {
            channel_id,
            peer: self.identity_of(peer)?,
            path: peer.path.unwrap_or(api::PathKind::Direct),
            key_epoch: peer.session.as_ref().and_then(Session::send_epoch).unwrap_or(0),
        })
    }

    fn identity_of(&self, peer: &Peer) -> Result<api::PeerIdentity, ErrorKind> {
        let trust = self.trust.lock().unwrap_or_else(|e| e.into_inner());
        // Prefer what a handshake authenticated. A rendezvous's chain is only a hint for
        // showing who is calling, before any handshake has run.
        let (device, fingerprint) = match peer.peer_info.as_ref() {
            Some(info) => (info.subject_b.clone(), info.fingerprint.clone()),
            None => trust.known_device(&peer.user_id, peer.device_id.as_deref()).unwrap_or_else(|| {
                (peer.device_id.clone().unwrap_or_default(), self.hint_fingerprint(peer))
            }),
        };
        let safety = if fingerprint.is_empty() {
            String::new()
        } else {
            safety_number(self.provider.as_ref(), &self.my_fingerprint, &fingerprint)
                .map_err(|_| ErrorKind::Internal)?
        };
        let status = trust.status_of(&peer.user_id, &device, &fingerprint);
        Ok(api::PeerIdentity {
            user_id: peer.user_id.clone(),
            device_id: device,
            fingerprint: to_hex(&fingerprint),
            safety_number: safety,
            status,
        })
    }

    /// The fingerprint from a rendezvous's chain. This is only for showing who is
    /// calling (section 12), and nothing here trusts it.
    fn hint_fingerprint(&self, peer: &Peer) -> Vec<u8> {
        cert::parse_many(self.provider.as_ref(), &peer.hint_chain)
            .ok()
            .and_then(|c| c.into_iter().next())
            .map(|leaf| cert::fingerprint(self.provider.as_ref(), &leaf.sign_public_encoded))
            .unwrap_or_default()
    }

    /// `channel.close`.
    pub fn close_channel(&mut self, now_ms: u64, channel_id: u64) -> u64 {
        let op = self.new_op();
        let Some(entry) = self.channels.get_mut(&channel_id) else {
            self.complete(op, Err(ErrorKind::InvalidArgument));
            return op;
        };
        let (peer_id, wire_id, open) = (entry.peer, entry.wire_id, entry.open);
        if !open {
            self.complete(op, Ok(OpValue::None));
            return op;
        }
        entry.close_op = Some(op);
        let Some(wire_id) = wire_id else {
            self.complete(op, Ok(OpValue::None));
            return op;
        };
        let closed = self
            .peers
            .get_mut(&peer_id)
            .and_then(|p| p.session.as_mut())
            .map_or(Err(ErrorCode::Closed), |s| s.close_channel(now_ms, wire_id, reason::NORMAL));
        if closed.is_err() {
            if let Some(entry) = self.channels.get_mut(&channel_id) {
                entry.open = false;
                entry.close_op = None;
            }
            self.complete(op, Ok(OpValue::None));
        }
        self.drive(now_ms);
        op
    }

    /// `verifyPeer`. Given a safety number, compares it in constant time and records the
    /// peer as verified if it matches.
    pub fn verify_peer(
        &mut self,
        now_ms: u64,
        peer: &api::PeerRef,
        safety: Option<&str>,
    ) -> Result<api::PeerIdentity, ErrorKind> {
        let found = self
            .peers
            .values()
            .find(|p| {
                p.user_id == peer.user_id
                    && peer.device_id.as_ref().is_none_or(|d| {
                        p.peer_info.as_ref().map(|i| &i.subject_b) == Some(d) || p.device_id.as_ref() == Some(d)
                    })
            })
            .map(|p| self.identity_of(p))
            .transpose()?;
        let mut identity = match found {
            Some(identity) => identity,
            None => {
                let trust = self.trust.lock().unwrap_or_else(|e| e.into_inner());
                let (device, fingerprint) =
                    trust.known_device(&peer.user_id, peer.device_id.as_deref()).ok_or(ErrorKind::PeerUnavailable)?;
                let number = safety_number(self.provider.as_ref(), &self.my_fingerprint, &fingerprint)
                    .map_err(|_| ErrorKind::Internal)?;
                let status = trust.status_of(&peer.user_id, &device, &fingerprint);
                api::PeerIdentity {
                    user_id: peer.user_id.clone(),
                    device_id: device,
                    fingerprint: to_hex(&fingerprint),
                    safety_number: number,
                    status,
                }
            }
        };
        if let Some(presented) = safety {
            if identity.safety_number.is_empty()
                || !crypto_provider::ct_eq(presented.as_bytes(), identity.safety_number.as_bytes())
            {
                return Err(ErrorKind::InvalidArgument);
            }
            let fingerprint = crypto_provider::from_hex(&identity.fingerprint).ok_or(ErrorKind::Internal)?;
            let mut trust = self.trust.lock().unwrap_or_else(|e| e.into_inner());
            trust.pins.record_verified(&identity.user_id, &identity.device_id, &fingerprint);
            drop(trust);
            identity.status = api::VerificationStatus::Verified;
            self.dirty = true;
            let (user, device) = (identity.user_id.clone(), identity.device_id.clone());
            self.audit_event(now_ms, "local user", &format!("{user}/{device}"), audit_op::PIN_CHANGED, "ok", "verified out of band");
        }
        Ok(identity)
    }

    /// Starts `rotateKeys`.
    pub fn rotate_keys(&mut self, now_ms: u64, peer: Option<&api::PeerRef>) -> u64 {
        let op = self.new_op();
        let targets: Vec<u64> = self
            .peers
            .values()
            .filter(|p| p.stage == PeerStage::Established)
            .filter(|p| {
                peer.is_none_or(|r| {
                    p.user_id == r.user_id && r.device_id.as_ref().is_none_or(|d| p.device_id.as_ref() == Some(d))
                })
            })
            .map(|p| p.id)
            .collect();
        if targets.is_empty() {
            let result = if peer.is_some() { Err(ErrorKind::InvalidState) } else { Ok(OpValue::None) };
            self.complete(op, result);
            return op;
        }
        // The operation completes when the last peer has moved.
        for peer_id in &targets {
            if let Some(entry) = self.peers.get_mut(peer_id) {
                if entry.session.as_mut().is_some_and(|s| s.rotate_keys(now_ms).is_ok()) {
                    entry.rotate_ops.push(op);
                }
            }
        }
        self.drive(now_ms);
        op
    }

    /// `exportAudit`.
    pub fn export_audit(&self, request: &api::AuditExportRequest) -> Result<api::AuditExport, ErrorKind> {
        let selected: Vec<AuditEntry> = self
            .audit_entries
            .iter()
            .filter(|e| request.from_ms.is_none_or(|f| e.event.at >= f))
            .filter(|e| request.to_ms.is_none_or(|t| e.event.at <= t))
            .cloned()
            .collect();
        let events = to_jsonl(&selected).map_err(|_| ErrorKind::Internal)?;
        let checkpoint = self.audit.checkpoint(self.identity.as_ref()).map_err(|_| ErrorKind::AuditUnavailable)?;
        Ok(api::AuditExport {
            events: events.into_bytes(),
            chain_head: self.audit.head().to_vec(),
            checkpoint_signature: crypto_provider::from_hex(&checkpoint.signature).ok_or(ErrorKind::Internal)?,
        })
    }

    /// Starts `session.close`: closes every peer session and the control session with an
    /// authenticated close, then logs out.
    pub fn close(&mut self, now_ms: u64) -> u64 {
        let op = self.new_op();
        if matches!(self.stage, ControlStage::Closed | ControlStage::Idle) {
            self.stage = ControlStage::Closed;
            self.complete(op, Ok(OpValue::None));
            return op;
        }
        self.close_op = Some(op);
        let ids: Vec<u64> = self.peers.keys().copied().collect();
        for id in ids {
            if let Some(session) = self.peers.get_mut(&id).and_then(|p| p.session.as_mut()) {
                session.close(now_ms, reason::NORMAL);
            }
        }
        if let Some(control) = self.control.as_mut() {
            control.close(now_ms, reason::NORMAL);
        }
        self.audit_event(now_ms, "local user", "session", audit_op::LOGOUT, "ok", "");
        self.drive(now_ms);
        op
    }

    // ------------------------------------------------------------- transport reports

    /// `linkOpened`.
    pub fn link_opened(&mut self, now_ms: u64, link_id: u64, caps: api::TransportCaps) {
        let caps = TransportCaps { ordered: caps.ordered, reliable: caps.reliable, max_frame_len: caps.max_frame_len as usize };
        match self.links.get(&link_id).copied() {
            Some(LinkPurpose::Control) => self.control_link_opened(now_ms, caps),
            Some(LinkPurpose::Direct(peer_id)) => {
                if let Some(peer) = self.peers.get_mut(&peer_id) {
                    peer.direct_deadline = None;
                    peer.path = Some(api::PathKind::Direct);
                }
                self.start_peer_session(now_ms, peer_id, caps);
            }
            Some(LinkPurpose::Relay { peer, .. }) => {
                let Some(entry) = self.peers.get(&peer) else { return };
                let (Some(id), Some(grant)) = (entry.rendezvous_id, entry.grants.first()) else { return };
                let Ok(join) = relay::encode_join(&id, &grant.token) else { return };
                self.commands.push_back(TransportCommand::SendFrame { link_id, frame: join });
                self.links.insert(link_id, LinkPurpose::Relay { peer, joined: true, paired: false });
                // The caps are remembered in the entry for when the relay says it is paired.
                self.relay_caps.insert(link_id, caps);
            }
            None => {}
        }
        self.drive(now_ms);
    }

    /// `linkClosed`.
    pub fn link_closed(&mut self, now_ms: u64, link_id: u64) {
        let Some(purpose) = self.links.remove(&link_id) else { return };
        match purpose {
            LinkPurpose::Control => {
                if let Some(control) = self.control.as_mut() {
                    control.on_transport_closed(now_ms);
                } else {
                    self.control_ended(now_ms, ErrorKind::TransportFailed);
                }
            }
            LinkPurpose::Direct(peer_id) | LinkPurpose::Relay { peer: peer_id, .. } => {
                let is_direct = matches!(purpose, LinkPurpose::Direct(_));
                let session_running = self.peers.get(&peer_id).is_some_and(|p| p.session.is_some());
                if session_running {
                    if let Some(session) = self.peers.get_mut(&peer_id).and_then(|p| p.session.as_mut()) {
                        session.on_transport_closed(now_ms);
                    }
                } else if is_direct {
                    self.direct_failed(now_ms, peer_id);
                } else {
                    self.fail_peer(now_ms, peer_id, ErrorKind::TransportFailed);
                }
            }
        }
        self.drive(now_ms);
    }

    /// `frameReceived`.
    pub fn frame_received(&mut self, now_ms: u64, link_id: u64, frame: &[u8]) {
        match self.links.get(&link_id).copied() {
            Some(LinkPurpose::Control) => {
                if let Some(control) = self.control.as_mut() {
                    control.handle_frame(now_ms, frame);
                }
            }
            Some(LinkPurpose::Direct(peer_id)) => {
                if let Some(session) = self.peers.get_mut(&peer_id).and_then(|p| p.session.as_mut()) {
                    session.handle_frame(now_ms, frame);
                }
            }
            Some(LinkPurpose::Relay { peer, joined, paired: false }) => {
                if frame == RELAY_PAIRED {
                    self.links.insert(link_id, LinkPurpose::Relay { peer, joined, paired: true });
                    let caps = self.relay_caps.remove(&link_id).unwrap_or(TransportCaps::STREAM);
                    self.start_peer_session(now_ms, peer, caps);
                }
            }
            Some(LinkPurpose::Relay { peer, .. }) => {
                if let Some(session) = self.peers.get_mut(&peer).and_then(|p| p.session.as_mut()) {
                    session.handle_frame(now_ms, frame);
                }
            }
            None => {}
        }
        self.drive(now_ms);
    }

    /// `signalReceived`: connectivity data from the platform goes to the peer through the
    /// server, as an opaque blob.
    pub fn signal_received(&mut self, now_ms: u64, link_id: u64, blob: &[u8]) {
        let Some(LinkPurpose::Direct(peer_id)) = self.links.get(&link_id).copied() else { return };
        let Some(id) = self.peers.get(&peer_id).and_then(|p| p.rendezvous_id) else { return };
        self.send_control(
            now_ms,
            &ControlMessage::new(kind::PEER_SIGNAL).with(field::RENDEZVOUS_ID, &id).with(field::BLOB, blob),
        );
        self.drive(now_ms);
    }

    // ------------------------------------------------------------- control plane

    fn control_link_opened(&mut self, now_ms: u64, caps: TransportCaps) {
        let verifier = Box::new(UncheckedControlVerifier);
        let session = Session::new(
            SessionConfig {
                provider: self.provider.clone(),
                role: Role::Initiator,
                plane: Plane::Control,
                transport: caps,
                identity: self.identity.clone(),
                chain: self.chain.clone(),
                roots: self.roots.clone(),
                expectation: PeerExpectation::Server { host: self.server_host.clone() },
                verifier,
                versions: SessionConfig::default_versions(),
                suites: self.provider.suites().to_vec(),
                cached_peer_chain: None,
                rendezvous_id: None,
                limits: self.limits,
            },
            now_ms,
        );
        match session {
            Ok(session) => {
                self.control = Some(session);
                self.stage = ControlStage::Handshaking;
            }
            Err(f) => self.control_ended(now_ms, kind_of(f.code)),
        }
    }

    fn send_control(&mut self, now_ms: u64, message: &ControlMessage) {
        let Ok(body) = message.encode() else { return };
        if let Some(control) = self.control.as_mut() {
            let _ = control.send_control(now_ms, &body);
        }
    }

    fn on_control_established(&mut self, now_ms: u64, peer: &PeerInfo) {
        self.audit_event(now_ms, "local device", &peer.subject_a, audit_op::SESSION_ESTABLISHED, "ok", "control plane");
        let certs = cert::parse_many(self.provider.as_ref(), &peer.chain).unwrap_or_default();
        self.server_issuing = certs.get(1).map(|c| c.fields.sign_public.clone());
        self.server_serial = Some(peer.serial);
        // Section 11.5: fetch the CRL at once, and close if the server's certificate is listed.
        self.stage = ControlStage::FetchingCrl;
        let issuer = certs
            .get(1)
            .map(|c| cert::key_id(self.provider.as_ref(), &c.sign_public_encoded))
            .unwrap_or([0; 16]);
        self.send_control(now_ms, &ControlMessage::new(kind::CRL_REQUEST).with(field::ISSUER_KEY_ID, &issuer));
    }

    fn on_crl(&mut self, now_ms: u64, raw: &[u8]) {
        let Some(issuing) = self.server_issuing.clone() else { return };
        let Ok(crl) = Crl::verify(self.provider.as_ref(), &issuing, raw) else {
            self.audit_event(now_ms, "server", "crl", audit_op::ALARM, "invalid", "the CRL's signature does not verify");
            return self.after_crl(now_ms, Err(ErrorKind::HandshakeFailed));
        };
        let revoked_server = self.server_serial.is_some_and(|s| crl.is_revoked(&s));
        let (refresh, live_revoked) = {
            let mut trust = self.trust.lock().unwrap_or_else(|e| e.into_inner());
            // An older CRL is refused, so a server cannot roll a revocation back.
            let _ = trust.crl.update(crl.clone());
            let current = trust.crl.current().cloned().unwrap_or(crl);
            let live: Vec<u64> = self
                .peers
                .values()
                .filter(|p| p.peer_info.as_ref().is_some_and(|i| current.is_revoked(&i.serial)))
                .map(|p| p.id)
                .collect();
            (current.next_update, live)
        };
        // Refresh well before it is due.
        self.crl_refresh_at = Some(refresh.saturating_sub(60 * 60 * 1000).max(now_ms + 60_000));
        self.dirty = true;
        for peer_id in live_revoked {
            if let Some(session) = self.peers.get_mut(&peer_id).and_then(|p| p.session.as_mut()) {
                session.close(now_ms, reason::REJECTED);
            }
            self.audit_event(now_ms, "server", "peer", audit_op::REVOCATION, "peerRevoked", "a live session's peer was revoked");
        }
        if revoked_server {
            return self.after_crl(now_ms, Err(ErrorKind::PeerRevoked));
        }
        self.after_crl(now_ms, Ok(()));
    }

    fn after_crl(&mut self, now_ms: u64, outcome: Result<(), ErrorKind>) {
        if !matches!(self.stage, ControlStage::FetchingCrl) {
            return;
        }
        if let Err(code) = outcome {
            if let Some(control) = self.control.as_mut() {
                control.close(now_ms, reason::REJECTED);
            }
            self.fail_goal(code);
            return;
        }
        let message = match self.goal.as_ref() {
            Some(Goal::Login { user_id, secret, mfa_code, .. }) => {
                self.stage = ControlStage::LoggingIn;
                let mut m = ControlMessage::new(kind::LOGIN_REQUEST)
                    .with_str(field::USER_ID, user_id)
                    .with(field::SECRET, secret);
                if let Some(code) = mfa_code {
                    m = m.with_str(field::MFA_CODE, code);
                }
                m
            }
            Some(Goal::Enroll { token, device_name, .. }) => {
                self.stage = ControlStage::Enrolling;
                ControlMessage::new(kind::ENROLL_REQUEST)
                    .with_str(field::TOKEN, token)
                    .with_str(field::DEVICE_NAME, device_name)
            }
            None => return,
        };
        self.send_control(now_ms, &message);
    }

    fn on_control_message(&mut self, now_ms: u64, message: ControlMessage) {
        match message.kind {
            kind::CRL_RESPONSE => {
                if let Some(raw) = message.get(field::CRL) {
                    let raw = raw.to_vec();
                    self.on_crl(now_ms, &raw);
                }
            }
            kind::LOGIN_RESULT => self.on_login_result(now_ms, &message),
            kind::ENROLL_RESULT => self.on_enroll_result(now_ms, &message),
            kind::RENDEZVOUS_INCOMING => self.on_incoming(now_ms, &message),
            kind::RENDEZVOUS_READY => self.on_ready(now_ms, &message),
            kind::RENDEZVOUS_REJECT => self.on_rejected(now_ms, &message),
            kind::PEER_SIGNAL => self.on_signal(&message),
            kind::CERT_RENEW_RESULT => self.on_renew_result(&message),
            _ => {}
        }
    }

    fn on_login_result(&mut self, now_ms: u64, message: &ControlMessage) {
        let status = message.get_u16(field::STATUS).unwrap_or(ErrorKind::Internal.code() as u16);
        let code = ErrorKind::from_code(u32::from(status)).unwrap_or(ErrorKind::Internal);
        let user = match self.goal.as_ref() {
            Some(Goal::Login { user_id, .. }) => user_id.clone(),
            _ => return,
        };
        if code == ErrorKind::Ok {
            let op = match self.goal.take() {
                Some(Goal::Login { op, .. }) => op,
                _ => return,
            };
            self.goal_deadline = None;
            self.stage = ControlStage::Ready;
            self.audit_event(now_ms, &user, "session", audit_op::LOGIN, "ok", "");
            self.set_state(api::SessionState::Connected);
            self.complete(op, Ok(OpValue::None));
        } else {
            self.audit_event(now_ms, &user, "session", audit_op::LOGIN, code.name(), "");
            self.fail_goal(code);
            if let Some(control) = self.control.as_mut() {
                control.close(now_ms, reason::REJECTED);
            }
        }
    }

    fn on_enroll_result(&mut self, now_ms: u64, message: &ControlMessage) {
        let status = message.get_u16(field::STATUS).unwrap_or(ErrorKind::Internal.code() as u16);
        let code = ErrorKind::from_code(u32::from(status)).unwrap_or(ErrorKind::Internal);
        let op = match self.goal.as_ref() {
            Some(Goal::Enroll { op, .. }) => *op,
            _ => return,
        };
        self.goal = None;
        self.goal_deadline = None;
        let outcome = if code == ErrorKind::Ok {
            self.install_enrolled_chain(message)
        } else {
            Err(code)
        };
        self.audit_event(
            now_ms,
            "local device",
            "enrolment",
            audit_op::ENROLLMENT,
            outcome.as_ref().map_or_else(|e| e.name(), |_| "ok"),
            "",
        );
        if let Some(control) = self.control.as_mut() {
            control.close(now_ms, reason::NORMAL);
        }
        self.complete(op, outcome);
    }

    fn install_enrolled_chain(&mut self, message: &ControlMessage) -> OpResult {
        let chain = message.get(field::CHAIN).ok_or(ErrorKind::Internal)?.to_vec();
        let certs = cert::parse_many(self.provider.as_ref(), &chain).map_err(|_| ErrorKind::Internal)?;
        let leaf = certs.first().ok_or(ErrorKind::Internal)?;
        // A server could hand back a certificate for someone else's key.
        if leaf.fields.sign_public != *self.identity.public_key() {
            return Err(ErrorKind::EnrollmentRejected);
        }
        let result = api::EnrollmentResult {
            device_id: leaf.fields.subject_b.clone(),
            fingerprint: to_hex(&self.my_fingerprint),
            certificate_expires_at_ms: leaf.fields.not_after,
        };
        self.chain = chain.clone();
        self.enrolled = true;
        Ok(OpValue::Enrolled { result, chain })
    }

    fn on_renew_result(&mut self, message: &ControlMessage) {
        if message.get_u16(field::STATUS) == Some(0)
            && let Some(chain) = message.get(field::CHAIN)
        {
            self.chain = chain.to_vec();
            self.dirty = true;
        }
    }

    fn on_incoming(&mut self, now_ms: u64, message: &ControlMessage) {
        let (Some(request_id), Some(rendezvous_id), Some(user), Some(device), Some(options_raw)) = (
            message.get_id(field::REQUEST_ID),
            message.get_id(field::RENDEZVOUS_ID),
            message.get_str(field::USER_ID),
            message.get_str(field::DEVICE_ID),
            message.get(field::CHANNEL_OPTIONS),
        ) else {
            return;
        };
        let Ok((ordered, reliable, label)) = parse_channel_options(options_raw) else { return };
        let grants = message.get(field::RELAY_GRANTS).and_then(|g| parse_grants(g).ok()).unwrap_or_default();
        let options = api::ChannelOptions { label, ordered, reliable, timeout_ms: None };
        let peer_id = self.next_peer;
        self.next_peer += 1;
        let peer = Peer {
            id: peer_id,
            user_id: user.into(),
            device_id: Some(device.into()),
            request_id,
            rendezvous_id: Some(rendezvous_id),
            role: Role::Responder,
            stage: PeerStage::AwaitingAccept,
            grants,
            link: None,
            path: None,
            direct_deadline: None,
            buffered_signals: Vec::new(),
            session: None,
            waiting: Vec::new(),
            options: options.clone(),
            hint_chain: message.get(field::CHAIN).unwrap_or_default().to_vec(),
            peer_info: None,
            session_id: None,
            rotate_ops: Vec::new(),
        };
        let identity = self.identity_of(&peer);
        self.peers.insert(peer_id, peer);
        match identity {
            Ok(identity) => self.events.push_back(api::Event::ChannelRequested {
                request_id: to_hex(&request_id),
                peer: identity,
                options,
            }),
            Err(_) => {
                self.peers.remove(&peer_id);
            }
        }
        let _ = now_ms;
    }

    fn on_ready(&mut self, now_ms: u64, message: &ControlMessage) {
        let (Some(request_id), Some(rendezvous_id)) =
            (message.get_id(field::REQUEST_ID), message.get_id(field::RENDEZVOUS_ID))
        else {
            return;
        };
        let found = self
            .peers
            .values_mut()
            .find(|p| p.stage == PeerStage::Rendezvous && p.request_id == request_id);
        let Some(peer) = found else { return };
        peer.rendezvous_id = Some(rendezvous_id);
        peer.grants = message.get(field::RELAY_GRANTS).and_then(|g| parse_grants(g).ok()).unwrap_or_default();
        peer.hint_chain = message.get(field::CHAIN).unwrap_or_default().to_vec();
        peer.stage = PeerStage::Connecting;
        let peer_id = peer.id;
        self.start_paths(now_ms, peer_id);
    }

    fn on_rejected(&mut self, now_ms: u64, message: &ControlMessage) {
        let Some(request_id) = message.get_id(field::REQUEST_ID) else { return };
        let found = self.peers.values().find(|p| p.request_id == request_id).map(|p| p.id);
        if let Some(peer_id) = found {
            self.fail_peer(now_ms, peer_id, ErrorKind::PeerUnavailable);
        }
    }

    fn on_signal(&mut self, message: &ControlMessage) {
        let (Some(rendezvous_id), Some(blob)) = (message.get_id(field::RENDEZVOUS_ID), message.get(field::BLOB)) else {
            return;
        };
        let found = self.peers.values_mut().find(|p| p.rendezvous_id == Some(rendezvous_id));
        let Some(peer) = found else { return };
        match peer.link {
            Some(link) if peer.path == Some(api::PathKind::Direct) => {
                self.commands.push_back(TransportCommand::SendSignal { link_id: link, blob: blob.to_vec() });
            }
            _ => peer.buffered_signals.push(blob.to_vec()),
        }
    }

    fn control_ended(&mut self, now_ms: u64, code: ErrorKind) {
        if let Some(link) = self.control_link.take() {
            if self.links.remove(&link).is_some() {
                self.commands.push_back(TransportCommand::CloseLink { link_id: link });
            }
        }
        self.control = None;
        self.fail_goal(code);
        let was_running = !matches!(self.stage, ControlStage::Closed);
        self.stage = ControlStage::Closed;
        // Direct sessions could outlive the server, but a closed Session owns its peers.
        let ids: Vec<u64> = self.peers.keys().copied().collect();
        for id in ids {
            let running = self.peers.get_mut(&id).and_then(|p| p.session.as_mut());
            match running {
                Some(session) if !session.is_closed() => session.close(now_ms, reason::NORMAL),
                _ => self.fail_peer(now_ms, id, ErrorKind::Closed),
            }
        }
        if was_running {
            self.set_state(api::SessionState::Closed);
        }
        if let Some(op) = self.close_op.take() {
            self.complete(op, Ok(OpValue::None));
        }
    }

    // ------------------------------------------------------------- data plane

    fn start_paths(&mut self, now_ms: u64, peer_id: u64) {
        if self.relay_policy == api::RelayPolicy::RelayOnly {
            self.open_relay(now_ms, peer_id);
            return;
        }
        let Some(peer) = self.peers.get_mut(&peer_id) else { return };
        let link = self.next_link;
        self.next_link += 1;
        self.links.insert(link, LinkPurpose::Direct(peer_id));
        peer.link = Some(link);
        peer.path = Some(api::PathKind::Direct);
        let initiator = peer.role == Role::Initiator;
        let timeout = if initiator { DIRECT_TIMEOUT_INITIATOR_MS } else { DIRECT_TIMEOUT_RESPONDER_MS };
        peer.direct_deadline = Some(now_ms + timeout);
        self.commands.push_back(TransportCommand::OpenLink {
            link_id: link,
            kind: api::LinkKind::Peer,
            url: None,
            initiator,
        });
        for blob in std::mem::take(&mut peer.buffered_signals) {
            self.commands.push_back(TransportCommand::SendSignal { link_id: link, blob });
        }
    }

    fn open_relay(&mut self, now_ms: u64, peer_id: u64) {
        let Some(peer) = self.peers.get_mut(&peer_id) else { return };
        let Some(address) = peer.grants.first().map(|g| g.address.clone()) else {
            return self.fail_peer(now_ms, peer_id, ErrorKind::PeerUnreachable);
        };
        let link = self.next_link;
        self.next_link += 1;
        self.links.insert(link, LinkPurpose::Relay { peer: peer_id, joined: false, paired: false });
        peer.link = Some(link);
        peer.path = Some(api::PathKind::Relayed);
        peer.direct_deadline = None;
        self.commands.push_back(TransportCommand::OpenLink {
            link_id: link,
            kind: api::LinkKind::Relay,
            url: Some(address),
            initiator: peer.role == Role::Initiator,
        });
    }

    fn direct_failed(&mut self, now_ms: u64, peer_id: u64) {
        match self.relay_policy {
            api::RelayPolicy::DirectOnly => self.fail_peer(now_ms, peer_id, ErrorKind::PeerUnreachable),
            _ => {
                let Some(peer) = self.peers.get_mut(&peer_id) else { return };
                peer.direct_deadline = None;
                if let Some(link) = peer.link.take() {
                    if self.links.remove(&link).is_some() {
                        self.commands.push_back(TransportCommand::CloseLink { link_id: link });
                    }
                }
                self.open_relay(now_ms, peer_id);
            }
        }
    }

    fn start_peer_session(&mut self, now_ms: u64, peer_id: u64, caps: TransportCaps) {
        let Some(peer) = self.peers.get_mut(&peer_id) else { return };
        let cached = self.trust.lock().unwrap_or_else(|e| e.into_inner()).cached_chain(&peer.user_id, peer.device_id.as_deref());
        let config = SessionConfig {
            provider: self.provider.clone(),
            role: peer.role,
            plane: Plane::Data,
            transport: caps,
            identity: self.identity.clone(),
            chain: self.chain.clone(),
            roots: self.roots.clone(),
            expectation: PeerExpectation::Peer { user_id: peer.user_id.clone(), device_id: peer.device_id.clone() },
            verifier: Box::new(DataPlaneVerifier::new(self.trust.clone())),
            versions: SessionConfig::default_versions(),
            suites: self.provider.suites().to_vec(),
            cached_peer_chain: if peer.role == Role::Initiator { cached } else { None },
            rendezvous_id: peer.rendezvous_id,
            limits: self.limits,
        };
        match Session::new(config, now_ms) {
            Ok(session) => {
                peer.session = Some(session);
                peer.stage = PeerStage::Handshaking;
            }
            Err(f) => self.fail_peer(now_ms, peer_id, kind_of(f.code)),
        }
    }

    /// Ends a peer before its session is usable, and fails whatever was waiting on it.
    fn fail_peer(&mut self, now_ms: u64, peer_id: u64, code: ErrorKind) {
        let Some(peer) = self.peers.remove(&peer_id) else { return };
        if let Some(link) = peer.link {
            if self.links.remove(&link).is_some() {
                self.commands.push_back(TransportCommand::CloseLink { link_id: link });
            }
        }
        for waiting in peer.waiting {
            let (op, handle) = match waiting {
                Waiting::Open { op, handle, .. } | Waiting::Accept { op, handle, .. } => (op, handle),
            };
            self.channels.remove(&handle);
            self.complete(op, Err(code));
        }
        for op in peer.rotate_ops {
            self.complete(op, Err(code));
        }
        let _ = now_ms;
    }

    fn on_peer_event(&mut self, now_ms: u64, peer_id: u64, event: Event) {
        match event {
            Event::Established { peer: info, session_id, .. } => self.on_peer_established(now_ms, peer_id, info, session_id),
            Event::HandshakeFailed(failure) => {
                let code = kind_of(failure.code);
                let (user, device) = self
                    .peers
                    .get(&peer_id)
                    .map(|p| (p.user_id.clone(), p.device_id.clone().unwrap_or_default()))
                    .unwrap_or_default();
                // The detail stays local, and the application only sees the code.
                self.audit_event(now_ms, &user, &device, audit_op::SESSION_ESTABLISHED, code.name(), failure.detail);
                if code == ErrorKind::PeerIdentityChanged {
                    let identity = self.peers.get(&peer_id).map(|p| self.identity_of(p));
                    if let Some(Ok(identity)) = identity {
                        self.audit_event(now_ms, &user, &device, audit_op::PIN_CHANGED, code.name(), &identity.fingerprint);
                        self.events.push_back(api::Event::PeerIdentityChanged { peer: identity });
                    }
                    self.dirty = true;
                }
                self.fail_peer(now_ms, peer_id, code);
            }
            Event::PeerConfirmed => {}
            Event::ChannelRequested { channel_id, options } => self.on_channel_requested(now_ms, peer_id, channel_id, options),
            Event::ChannelOpened { channel_id } => self.on_channel_opened(peer_id, channel_id),
            Event::ChannelRejected { channel_id, reason: code } => self.on_channel_rejected(peer_id, channel_id, code),
            Event::ChannelClosed { channel_id, clean, .. } => self.on_channel_closed(peer_id, channel_id, clean),
            Event::Message { channel_id, payload } => {
                let handle = self
                    .channels
                    .iter()
                    .find(|(_, c)| c.peer == peer_id && c.wire_id == Some(channel_id))
                    .map(|(h, _)| *h);
                if let Some(handle) = handle
                    && let Some(entry) = self.channels.get_mut(&handle)
                {
                    entry.inbox.push_back(payload);
                    self.events.push_back(api::Event::MessageAvailable { channel_id: handle });
                }
            }
            Event::KeysRotated { send, epoch } => {
                let peer = self.peer_ref(peer_id);
                let object = peer.user_id.clone();
                self.audit_event(now_ms, "local device", &object, audit_op::KEY_ROTATED, "ok", if send { "send" } else { "receive" });
                self.events.push_back(api::Event::KeysRotated { peer, epoch });
            }
            Event::RotationComplete => {
                let ops = self.peers.get_mut(&peer_id).map(|p| std::mem::take(&mut p.rotate_ops)).unwrap_or_default();
                for op in ops {
                    self.complete(op, Ok(OpValue::None));
                }
            }
            Event::RotationTimedOut => {
                let ops = self.peers.get_mut(&peer_id).map(|p| std::mem::take(&mut p.rotate_ops)).unwrap_or_default();
                for op in ops {
                    self.complete(op, Err(ErrorKind::Timeout));
                }
            }
            Event::Closed { clean, reason: code } => self.on_peer_closed(now_ms, peer_id, clean, code),
            Event::Control { .. } => {}
        }
    }

    fn peer_ref(&self, peer_id: u64) -> api::PeerRef {
        match self.peers.get(&peer_id) {
            Some(p) => api::PeerRef { user_id: p.user_id.clone(), device_id: p.device_id.clone() },
            None => api::PeerRef { user_id: String::new(), device_id: None },
        }
    }

    fn on_peer_established(&mut self, now_ms: u64, peer_id: u64, info: PeerInfo, session_id: [u8; 16]) {
        let Some(peer) = self.peers.get_mut(&peer_id) else { return };
        peer.stage = PeerStage::Established;
        peer.device_id = Some(info.subject_b.clone());
        peer.session_id = Some(session_id);
        let path = peer.path.unwrap_or(api::PathKind::Direct);
        let (user, device) = (peer.user_id.clone(), info.subject_b.clone());
        let waiting: Vec<(u64, u64, u64)> = peer
            .waiting
            .iter()
            .filter_map(|w| match w {
                Waiting::Open { op, handle, deadline } => Some((*op, *handle, *deadline)),
                Waiting::Accept { .. } => None,
            })
            .collect();
        peer.waiting.retain(|w| matches!(w, Waiting::Accept { .. }));
        let status = info.status;
        {
            let mut trust = self.trust.lock().unwrap_or_else(|e| e.into_inner());
            trust.remember_chain(&user, &device, &info.chain);
        }
        if let Some(peer) = self.peers.get_mut(&peer_id) {
            peer.peer_info = Some(info);
        }
        self.dirty = true;
        self.audit_event(now_ms, &user, &device, audit_op::SESSION_ESTABLISHED, "ok", &to_hex(&session_id));
        if status == PinStatus::Changed {
            // The local policy is warn, so the session continues, but it must be seen.
            let identity = self.peers.get(&peer_id).map(|p| self.identity_of(p));
            if let Some(Ok(identity)) = identity {
                self.events.push_back(api::Event::PeerIdentityChanged { peer: identity });
            }
        }
        let peer_ref = self.peer_ref(peer_id);
        self.events.push_back(api::Event::PathChanged { peer: peer_ref, path });
        for (op, handle, deadline) in waiting {
            self.open_on_session(now_ms, peer_id, op, handle, deadline);
        }
    }

    fn on_channel_requested(&mut self, now_ms: u64, peer_id: u64, wire_id: u16, options: ChannelOptions) {
        let accept = self.peers.get_mut(&peer_id).and_then(|peer| {
            let index = peer.waiting.iter().position(|w| matches!(w, Waiting::Accept { .. }))?;
            Some(peer.waiting.remove(index))
        });
        if let Some(Waiting::Accept { op, handle, .. }) = accept {
            // The user already accepted this rendezvous.
            let accepted = self
                .peers
                .get_mut(&peer_id)
                .and_then(|p| p.session.as_mut())
                .map_or(Err(ErrorCode::Closed), |s| s.accept_channel(now_ms, wire_id));
            match accepted {
                Ok(()) => {
                    if let Some(entry) = self.channels.get_mut(&handle) {
                        entry.wire_id = Some(wire_id);
                        entry.open = true;
                    }
                    self.events.push_back(api::Event::ChannelOpened { channel_id: handle });
                    self.complete(op, Ok(OpValue::Channel(handle)));
                }
                Err(code) => {
                    self.channels.remove(&handle);
                    self.complete(op, Err(kind_of(code)));
                }
            }
            return;
        }
        // A further channel in a live session: the application decides.
        let request = format!("ch-{peer_id}-{wire_id}");
        let options = api::ChannelOptions {
            label: options.label,
            ordered: options.ordered,
            reliable: options.reliable,
            timeout_ms: None,
        };
        self.session_requests.insert(request.clone(), (peer_id, wire_id, options.clone()));
        let Some(peer) = self.peers.get(&peer_id) else { return };
        if let Ok(identity) = self.identity_of(peer) {
            self.events.push_back(api::Event::ChannelRequested { request_id: request, peer: identity, options });
        }
    }

    fn channel_by_wire(&self, peer_id: u64, wire_id: u16) -> Option<u64> {
        self.channels.iter().find(|(_, c)| c.peer == peer_id && c.wire_id == Some(wire_id)).map(|(h, _)| *h)
    }

    fn take_open_waiter(&mut self, peer_id: u64, handle: u64) -> Option<u64> {
        let peer = self.peers.get_mut(&peer_id)?;
        let index = peer.waiting.iter().position(|w| matches!(w, Waiting::Open { handle: h, .. } if *h == handle))?;
        match peer.waiting.remove(index) {
            Waiting::Open { op, .. } | Waiting::Accept { op, .. } => Some(op),
        }
    }

    fn on_channel_opened(&mut self, peer_id: u64, wire_id: u16) {
        let Some(handle) = self.channel_by_wire(peer_id, wire_id) else { return };
        if let Some(entry) = self.channels.get_mut(&handle) {
            entry.open = true;
        }
        self.events.push_back(api::Event::ChannelOpened { channel_id: handle });
        if let Some(op) = self.take_open_waiter(peer_id, handle) {
            self.complete(op, Ok(OpValue::Channel(handle)));
        }
    }

    fn on_channel_rejected(&mut self, peer_id: u64, wire_id: u16, code: u16) {
        let Some(handle) = self.channel_by_wire(peer_id, wire_id) else { return };
        self.channels.remove(&handle);
        if let Some(op) = self.take_open_waiter(peer_id, handle) {
            let kind = match code {
                reason::TRANSPORT_UNSUPPORTED => ErrorKind::TransportUnsupported,
                reason::TIMEOUT => ErrorKind::Timeout,
                // The peer only ever sees that it did not happen.
                _ => ErrorKind::PeerUnavailable,
            };
            self.complete(op, Err(kind));
        }
    }

    fn on_channel_closed(&mut self, peer_id: u64, wire_id: u16, clean: bool) {
        let Some(handle) = self.channel_by_wire(peer_id, wire_id) else { return };
        let Some(entry) = self.channels.get_mut(&handle) else { return };
        entry.open = false;
        let op = entry.close_op.take();
        self.events.push_back(api::Event::ChannelClosed { channel_id: handle, clean });
        if let Some(op) = op {
            self.complete(op, Ok(OpValue::None));
        }
    }

    fn on_peer_closed(&mut self, now_ms: u64, peer_id: u64, clean: bool, code: u16) {
        let handles: Vec<u64> = self.channels.iter().filter(|(_, c)| c.peer == peer_id && c.open).map(|(h, _)| *h).collect();
        for handle in handles {
            if let Some(entry) = self.channels.get_mut(&handle) {
                entry.open = false;
                let op = entry.close_op.take();
                self.events.push_back(api::Event::ChannelClosed { channel_id: handle, clean });
                if let Some(op) = op {
                    self.complete(op, Ok(OpValue::None));
                }
            }
        }
        let Some(peer) = self.peers.get(&peer_id) else { return };
        let (user, session_id, path, stats) = (
            peer.user_id.clone(),
            peer.session_id,
            peer.path,
            peer.session.as_ref().map(Session::stats).unwrap_or_default(),
        );
        self.audit_event(now_ms, &user, "session", audit_op::SESSION_TEARDOWN, "ok", &format!("clean={clean} reason={code}"));
        // Section 12: self-reported, so it only feeds metrics.
        if let (Some(session_id), Some(path)) = (session_id, path) {
            let mut counters = stats.records_sent.saturating_add(stats.records_received).to_be_bytes().to_vec();
            counters.extend_from_slice(&stats.bytes_sent.saturating_add(stats.bytes_received).to_be_bytes());
            let value = if path == api::PathKind::Direct { 1u8 } else { 2 };
            self.send_control(
                now_ms,
                &ControlMessage::new(kind::SESSION_REPORT)
                    .with(field::SESSION_ID, &session_id)
                    .with(field::PATH, &[value])
                    .with(field::COUNTERS, &counters),
            );
        }
        self.fail_peer(now_ms, peer_id, ErrorKind::Closed);
    }

    // ------------------------------------------------------------- driving

    /// Moves everything sessions have produced into commands and events.
    pub fn drive(&mut self, now_ms: u64) {
        // Events can produce frames and more events, so repeat until nothing moves.
        for _ in 0..64 {
            let mut moved = false;

            if let Some(control) = self.control.as_mut() {
                let link = self.control_link;
                while let Some(frame) = control.poll_transmit() {
                    if let Some(link_id) = link {
                        self.commands.push_back(TransportCommand::SendFrame { link_id, frame });
                    }
                    moved = true;
                }
            }
            let mut control_events = Vec::new();
            if let Some(control) = self.control.as_mut() {
                while let Some(event) = control.poll_event() {
                    control_events.push(event);
                }
            }
            for event in control_events {
                moved = true;
                match event {
                    Event::Established { peer, .. } => self.on_control_established(now_ms, &peer),
                    Event::HandshakeFailed(failure) => {
                        self.audit_event(now_ms, "server", &self.server_host.clone(), audit_op::SESSION_ESTABLISHED, failure.code.name(), failure.detail);
                        self.control_ended(now_ms, kind_of(failure.code));
                    }
                    Event::Control { body } => {
                        if let Ok(message) = ControlMessage::decode(&body) {
                            self.on_control_message(now_ms, message);
                        }
                    }
                    Event::Closed { .. } => self.control_ended(now_ms, ErrorKind::Closed),
                    _ => {}
                }
            }

            let ids: Vec<u64> = self.peers.keys().copied().collect();
            for id in ids {
                let Some(peer) = self.peers.get_mut(&id) else { continue };
                let link = peer.link;
                let Some(session) = peer.session.as_mut() else { continue };
                let mut frames = Vec::new();
                while let Some(frame) = session.poll_transmit() {
                    frames.push(frame);
                }
                let mut events = Vec::new();
                while let Some(event) = session.poll_event() {
                    events.push(event);
                }
                moved |= !frames.is_empty() || !events.is_empty();
                if let Some(link_id) = link {
                    for frame in frames {
                        self.commands.push_back(TransportCommand::SendFrame { link_id, frame });
                    }
                }
                for event in events {
                    self.on_peer_event(now_ms, id, event);
                }
            }
            if !moved {
                break;
            }
        }
    }

    /// The next time [`ClientCore::handle_timeout`] has work.
    pub fn next_timeout(&self) -> Option<u64> {
        let mut next: Option<u64> = None;
        let mut consider = |t: u64| next = Some(next.map_or(t, |n: u64| n.min(t)));
        if let Some(t) = self.control.as_ref().and_then(Session::next_timeout) {
            consider(t);
        }
        if let Some(t) = self.goal_deadline {
            consider(t);
        }
        if let Some(t) = self.crl_refresh_at {
            consider(t);
        }
        for peer in self.peers.values() {
            if let Some(t) = peer.session.as_ref().and_then(Session::next_timeout) {
                consider(t);
            }
            if let Some(t) = peer.direct_deadline {
                consider(t);
            }
            for waiting in &peer.waiting {
                let (Waiting::Open { deadline, .. } | Waiting::Accept { deadline, .. }) = waiting;
                consider(*deadline);
            }
        }
        next
    }

    /// Drives every timer.
    pub fn handle_timeout(&mut self, now_ms: u64) {
        if let Some(control) = self.control.as_mut() {
            control.handle_timeout(now_ms);
        }
        if self.goal_deadline.is_some_and(|t| now_ms >= t) {
            self.goal_deadline = None;
            self.fail_goal(ErrorKind::Timeout);
            if let Some(control) = self.control.as_mut() {
                control.close(now_ms, reason::TIMEOUT);
            } else {
                self.control_ended(now_ms, ErrorKind::Timeout);
            }
        }
        if self.crl_refresh_at.is_some_and(|t| now_ms >= t) {
            self.crl_refresh_at = Some(now_ms + 60 * 60 * 1000);
            if self.is_ready() {
                self.send_control(now_ms, &ControlMessage::new(kind::CRL_REQUEST).with(field::ISSUER_KEY_ID, &[0; 16]));
            }
        }
        let ids: Vec<u64> = self.peers.keys().copied().collect();
        for id in ids {
            let Some(peer) = self.peers.get_mut(&id) else { continue };
            if let Some(session) = peer.session.as_mut() {
                session.handle_timeout(now_ms);
            }
            if peer.direct_deadline.is_some_and(|t| now_ms >= t) {
                self.direct_failed(now_ms, id);
            }
            // Only an operation that has not started its session waits here. Once a
            // session runs, its own timers end it.
            let expired: Vec<(u64, u64)> = self
                .peers
                .get(&id)
                .map(|p| {
                    p.waiting
                        .iter()
                        .filter_map(|w| match w {
                            Waiting::Open { op, handle, deadline } | Waiting::Accept { op, handle, deadline }
                                if now_ms >= *deadline =>
                            {
                                Some((*op, *handle))
                            }
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();
            for (op, handle) in expired {
                if let Some(peer) = self.peers.get_mut(&id) {
                    peer.waiting.retain(|w| {
                        !matches!(w, Waiting::Open { op: o, .. } | Waiting::Accept { op: o, .. } if *o == op)
                    });
                }
                self.channels.remove(&handle);
                self.complete(op, Err(ErrorKind::Timeout));
            }
        }
        self.drive(now_ms);
    }

    /// True if this build uses a test-only suite, so an application can warn.
    pub fn is_test_build(&self) -> bool {
        self.provider.suites().iter().any(|s| is_test_only(*s))
    }

    /// The certificate chain this device is using.
    pub fn chain(&self) -> &[u8] {
        &self.chain
    }
}
