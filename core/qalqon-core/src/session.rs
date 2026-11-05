//! A Qalqon session: the sans-I/O state machine over one transport. It joins the
//! handshake, the record layer and channels, and applies the retransmission and
//! failure rules in `docs/PROTOCOL.md`.
//!
//! A caller feeds it with [`Session::handle_frame`] and [`Session::handle_timeout`],
//! and drains [`Session::poll_transmit`] and [`Session::poll_event`]. Time is always
//! passed in, in milliseconds.

use crate::cert::{Certificate, ValidatedChain};
use crate::error::{ErrorCode, HandshakeFailure};
use crate::frag::{Reassembler, fragment};
use crate::handshake::{self, Completed, InitOutcome, Initiator, Responder};
use crate::record::RecordLayer;
use crate::wire::{
    HEADER_LEN, MAX_BODY, Reader, VERSION_0_1, Writer, inner, msg, parse_frame, reason,
};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use crypto_provider::{CryptoProvider, SigningKey, Zeroizing, ct_eq};

/// Which side of the handshake this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Sends `XX_INIT`.
    Initiator,
    /// Answers `XX_INIT`.
    Responder,
}

/// Which plane a session runs on (`session_role`, section 5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    /// Client to server.
    Control,
    /// Client to client.
    Data,
}

impl Plane {
    pub(crate) fn wire_value(self) -> u8 {
        match self {
            Plane::Control => 1,
            Plane::Data => 2,
        }
    }
}

/// What a transport adapter declares (section 5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportCaps {
    /// Frames arrive in order.
    pub ordered: bool,
    /// Frames are not lost.
    pub reliable: bool,
    /// The largest frame the transport can carry, in bytes.
    pub max_frame_len: usize,
}

impl TransportCaps {
    /// TCP, a QUIC stream or a WebSocket: strict.
    pub const STREAM: TransportCaps = TransportCaps {
        ordered: true,
        reliable: true,
        max_frame_len: HEADER_LEN + MAX_BODY,
    };

    /// A UDP socket: lossy, with a conservative datagram size.
    pub const DATAGRAM: TransportCaps = TransportCaps {
        ordered: false,
        reliable: false,
        max_frame_len: 1400,
    };

    /// Both ordered and reliable. Everything else counts as lossy.
    pub fn is_strict(&self) -> bool {
        self.ordered && self.reliable
    }
}

/// Who the peer should be (section 11.3, steps 3 and 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerExpectation {
    /// On the control plane, I expects a server with this host name.
    Server {
        /// The host in `serverUrl`.
        host: String,
    },
    /// On the control plane, R accepts device and pre-enrolment certificates.
    Client,
    /// On the data plane, the user and any device named at rendezvous.
    Peer {
        /// The expected user.
        user_id: String,
        /// The expected device, if one was named.
        device_id: Option<String>,
    },
}

/// Why a peer was refused by local policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRejection {
    /// The certificate is on the CRL.
    Revoked,
    /// The cached CRL is missing or too old.
    RevocationStale,
    /// The key differs from the pin, or a pinned user presented a new device.
    IdentityChanged,
    /// Refused for another local reason.
    Other(&'static str),
}

/// How far a peer's identity has been checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinStatus {
    /// Pins do not apply here, as on the control plane.
    NotPinned,
    /// Pinned on first use, and not compared out of band.
    Pinned,
    /// The user compared the safety number.
    Verified,
    /// The identity changed, and local policy chose to warn and continue.
    Changed,
}

/// Local trust decisions the engine asks about during a handshake (section 7.3).
pub trait PeerVerifier: Send {
    /// Step 2: revocation. Must not change any pin.
    fn check_revocation(
        &mut self,
        chain: &ValidatedChain,
        now_ms: u64,
    ) -> Result<(), PeerRejection>;
    /// Step 4: called only after the signature and MAC verify, so committing a
    /// first-contact pin here is safe.
    fn check_pin(
        &mut self,
        chain: &ValidatedChain,
        now_ms: u64,
    ) -> Result<PinStatus, PeerRejection>;
}

/// A verifier that accepts every peer whose chain validates. For the control plane
/// before the first CRL arrives (section 11.5), and for tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct UncheckedPeers;

impl PeerVerifier for UncheckedPeers {
    fn check_revocation(&mut self, _: &ValidatedChain, _: u64) -> Result<(), PeerRejection> {
        Ok(())
    }
    fn check_pin(&mut self, _: &ValidatedChain, _: u64) -> Result<PinStatus, PeerRejection> {
        Ok(PinStatus::NotPinned)
    }
}

/// Protocol limits. The rekey limits can only be lowered, which tests use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Rotate before this many records in an epoch.
    pub rekey_records: u64,
    /// Rotate before this many plaintext bytes in an epoch.
    pub rekey_bytes: u64,
    /// Rotate after this long in an epoch, including while idle.
    pub rekey_ms: u64,
    /// The overall limit on the handshake and on repeated control records.
    pub give_up_ms: u64,
    /// The first retransmission delay, which then doubles.
    pub retransmit_ms: u64,
    /// How long a lossy receiver keeps old keys.
    pub old_key_retention_ms: u64,
    /// The largest application message.
    pub max_message: usize,
    /// All partial messages in one session, together.
    pub max_reassembly: usize,
    /// How long a partial message waits on a lossy transport.
    pub partial_timeout_ms: u64,
    /// How often to `PING`. `None` turns keepalive off.
    pub keepalive_ms: Option<u64>,
    /// How long to wait for the peer's `CLOSE` on a strict transport.
    pub close_timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            rekey_records: 1 << 32,
            rekey_bytes: 1 << 30,
            rekey_ms: 3_600_000,
            give_up_ms: 30_000,
            retransmit_ms: 500,
            old_key_retention_ms: 30_000,
            max_message: 16 * 1024 * 1024,
            max_reassembly: 64 * 1024 * 1024,
            partial_timeout_ms: 30_000,
            keepalive_ms: None,
            close_timeout_ms: 5_000,
        }
    }
}

impl Limits {
    fn clamped(self) -> Self {
        let d = Limits::default();
        Limits {
            rekey_records: self.rekey_records.clamp(4, d.rekey_records),
            rekey_bytes: self.rekey_bytes.clamp(1, d.rekey_bytes),
            rekey_ms: self.rekey_ms.min(d.rekey_ms),
            old_key_retention_ms: self.old_key_retention_ms.min(d.old_key_retention_ms),
            max_message: self.max_message.min(d.max_message),
            max_reassembly: self.max_reassembly.min(d.max_reassembly),
            ..self
        }
    }
}

/// Everything needed to start a session.
pub struct SessionConfig {
    /// The crypto provider.
    pub provider: Arc<dyn CryptoProvider>,
    /// Initiator or responder.
    pub role: Role,
    /// Control or data plane.
    pub plane: Plane,
    /// What the transport can do.
    pub transport: TransportCaps,
    /// This endpoint's long-term key.
    pub identity: Arc<dyn SigningKey>,
    /// This endpoint's encoded certificate chain.
    pub chain: Vec<u8>,
    /// The trusted roots.
    pub roots: Vec<Certificate>,
    /// Who the peer should be.
    pub expectation: PeerExpectation,
    /// Local trust decisions.
    pub verifier: Box<dyn PeerVerifier>,
    /// Versions to offer or accept, most preferred first.
    pub versions: Vec<u8>,
    /// Suites to offer or accept, most preferred first.
    pub suites: Vec<u16>,
    /// A chain kept from an earlier completed handshake with this peer (section 8).
    pub cached_peer_chain: Option<Vec<u8>>,
    /// The rendezvous this data-plane session belongs to.
    pub rendezvous_id: Option<[u8; 16]>,
    /// Protocol limits.
    pub limits: Limits,
}

impl core::fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionConfig")
            .field("role", &self.role)
            .field("plane", &self.plane)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

impl SessionConfig {
    /// The protocol versions this build speaks.
    pub fn default_versions() -> Vec<u8> {
        vec![VERSION_0_1]
    }
}

/// What the handshake learned about the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// The certificate's role.
    pub role: u8,
    /// `user_id`, or the host name.
    pub subject_a: String,
    /// `device_id`, or the server instance.
    pub subject_b: String,
    /// The certificate's serial, for revocation checks of live sessions.
    pub serial: [u8; 16],
    /// When the certificate expires.
    pub not_after: u64,
    /// The peer's fingerprint.
    pub fingerprint: Vec<u8>,
    /// The peer's full chain, for section 8 on later handshakes.
    pub chain: Vec<u8>,
    /// How far this identity has been checked.
    pub status: PinStatus,
}

/// Requirements for a new channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelOptions {
    /// Messages must arrive in order.
    pub ordered: bool,
    /// Messages must not be lost.
    pub reliable: bool,
    /// An application-chosen name, at most 255 bytes.
    pub label: String,
}

/// Something the session reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The handshake verified the peer. I may send from now on. R has verified
    /// `XX_FINISH`.
    Established {
        /// The peer.
        peer: PeerInfo,
        /// Safe to log, and identical on both sides.
        session_id: [u8; 16],
        /// The selected suite.
        suite: u16,
        /// The selected version.
        version: u8,
    },
    /// I opened a record from R, so R holds the same transcript (section 15, item 4).
    PeerConfirmed,
    /// The handshake failed. `detail` is for the local audit log.
    HandshakeFailed(HandshakeFailure),
    /// The peer asked for a channel. Answer with `accept_channel` or `reject_channel`.
    ChannelRequested {
        /// The channel.
        channel_id: u16,
        /// What the peer asked for.
        options: ChannelOptions,
    },
    /// A channel this side opened was accepted.
    ChannelOpened {
        /// The channel.
        channel_id: u16,
    },
    /// A channel this side opened was refused, or timed out.
    ChannelRejected {
        /// The channel.
        channel_id: u16,
        /// A `reason` code.
        reason: u16,
    },
    /// An open channel ended.
    ChannelClosed {
        /// The channel.
        channel_id: u16,
        /// False if nothing authenticated the end, so data may have been cut off.
        clean: bool,
        /// A `reason` code.
        reason: u16,
    },
    /// A whole application message arrived.
    Message {
        /// The channel.
        channel_id: u16,
        /// The plaintext.
        payload: Vec<u8>,
    },
    /// A `CONTROL` record arrived.
    Control {
        /// The record body.
        body: Vec<u8>,
    },
    /// A direction moved to a new epoch.
    KeysRotated {
        /// True for this side's sending direction.
        send: bool,
        /// The new epoch.
        epoch: u16,
    },
    /// The peer rotated in answer to [`Session::rotate_keys`].
    RotationComplete,
    /// The peer did not rotate in time.
    RotationTimedOut,
    /// The session has ended.
    Closed {
        /// False if the transport ended without a valid `CLOSE`, so data may have
        /// been cut off. An application can treat that as truncation.
        clean: bool,
        /// A `reason` code.
        reason: u16,
    },
}

#[derive(Clone, Copy, Debug)]
struct Retry {
    next_at: u64,
    interval: u64,
    give_up_at: u64,
}

impl Retry {
    fn new(now_ms: u64, limits: &Limits) -> Self {
        Retry {
            next_at: now_ms.saturating_add(limits.retransmit_ms),
            interval: limits.retransmit_ms,
            give_up_at: now_ms.saturating_add(limits.give_up_ms),
        }
    }

    fn bump(&mut self, now_ms: u64) {
        self.interval = self.interval.saturating_mul(2);
        self.next_at = now_ms.saturating_add(self.interval);
    }
}

#[derive(Debug)]
struct Partial {
    fragments: BTreeMap<u16, Vec<u8>>,
    last_index: Option<u16>,
    bytes: usize,
    started_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChannelState {
    /// This side sent `CHANNEL_OPEN`.
    Opening,
    /// The peer sent `CHANNEL_OPEN`, and the application has not answered.
    Pending,
    Open,
    /// This side sent `CHANNEL_CLOSE`.
    Closing,
    /// Ended by the peer's close, or by this side after its close was answered.
    Closed {
        by_us: bool,
    },
    Rejected {
        reason: u16,
    },
}

#[derive(Debug)]
struct Channel {
    options: ChannelOptions,
    state: ChannelState,
    next_message_id: u32,
    last_delivered: Option<u32>,
    partials: BTreeMap<u32, Partial>,
    retry: Option<Retry>,
    close_reason: u16,
}

impl Channel {
    fn new(options: ChannelOptions, state: ChannelState) -> Self {
        Channel {
            options,
            state,
            next_message_id: 0,
            last_delivered: None,
            partials: BTreeMap::new(),
            retry: None,
            close_reason: reason::NORMAL,
        }
    }
}

enum State {
    Initiating(Box<Initiator>),
    WaitingForInit,
    WaitingForFinish(Box<Responder>),
    Established,
    /// Sent `CLOSE` on a strict transport, and waiting for the reply.
    Closing {
        give_up_at: u64,
        reason: u16,
    },
    /// Repeating `CLOSE` on a lossy transport.
    ClosingLossy {
        remaining: u8,
        next_at: u64,
        reason: u16,
    },
    Closed,
}

#[derive(Debug)]
struct RotateRequest {
    peer_epoch: u16,
    retry: Retry,
}

/// Counters for `SESSION_REPORT` and for tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Records sent.
    pub records_sent: u64,
    /// Records opened.
    pub records_received: u64,
    /// Application bytes sent.
    pub bytes_sent: u64,
    /// Application bytes received.
    pub bytes_received: u64,
    /// Frames dropped on a lossy transport.
    pub frames_dropped: u64,
}

/// One session. See the module documentation.
pub struct Session {
    cfg: SessionConfig,
    state: State,
    record: Option<RecordLayer>,
    peer: Option<PeerInfo>,
    session_id: Option<[u8; 16]>,
    channels: BTreeMap<u16, Channel>,
    next_channel_id: u32,
    partial_bytes: usize,
    tx: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    reassembler: Reassembler,
    stats: Stats,

    hs_deadline: u64,
    flight_retry: Option<Retry>,
    last_failure: Option<HandshakeFailure>,
    handshake_complete: bool,
    rx_bytes: u64,
    tx_bytes: u64,

    peer_confirmed: bool,
    finish_frame: Option<Vec<u8>>,
    finish_hash: Option<Vec<u8>>,
    last_confirm_ms: Option<u64>,

    rotate_request: Option<RotateRequest>,
    deferred_update: bool,
    last_update_served_ms: Option<u64>,

    last_rx_ms: u64,
    last_ping_ms: u64,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("role", &self.cfg.role)
            .field("established", &self.is_established())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Starts a session. An initiator's first frame is ready at once.
    pub fn new(mut cfg: SessionConfig, now_ms: u64) -> Result<Self, HandshakeFailure> {
        cfg.limits = cfg.limits.clamped();
        let params = cfg.provider.params();
        if params.hash_len < 32 || params.iv_len < 12 {
            return Err(HandshakeFailure {
                code: ErrorCode::Unsupported,
                detail: "the provider's parameters are below the protocol's minimums",
            });
        }
        let give_up = cfg.limits.give_up_ms;
        let mut session = Session {
            state: State::WaitingForInit,
            record: None,
            peer: None,
            session_id: None,
            channels: BTreeMap::new(),
            next_channel_id: if cfg.role == Role::Initiator { 1 } else { 2 },
            partial_bytes: 0,
            tx: VecDeque::new(),
            events: VecDeque::new(),
            reassembler: Reassembler::new(),
            stats: Stats::default(),
            hs_deadline: now_ms.saturating_add(give_up),
            flight_retry: None,
            last_failure: None,
            handshake_complete: false,
            rx_bytes: 0,
            tx_bytes: 0,
            peer_confirmed: false,
            finish_frame: None,
            finish_hash: None,
            last_confirm_ms: None,
            rotate_request: None,
            deferred_update: false,
            last_update_served_ms: None,
            last_rx_ms: now_ms,
            last_ping_ms: now_ms,
            cfg,
        };
        if session.cfg.role == Role::Initiator {
            let initiator = handshake::start(&session.cfg)?;
            let frame = initiator.frame().to_vec();
            session.state = State::Initiating(Box::new(initiator));
            session.queue_handshake_message(&frame)?;
            if !session.is_strict() {
                session.flight_retry = Some(Retry::new(now_ms, &session.cfg.limits));
            }
        }
        Ok(session)
    }

    fn is_strict(&self) -> bool {
        self.cfg.transport.is_strict()
    }

    fn provider(&self) -> Arc<dyn CryptoProvider> {
        self.cfg.provider.clone()
    }

    /// True once the handshake has verified the peer and until the session ends.
    pub fn is_established(&self) -> bool {
        matches!(self.state, State::Established)
    }

    /// True once the session has ended.
    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed)
    }

    /// What the handshake learned about the peer.
    pub fn peer(&self) -> Option<&PeerInfo> {
        self.peer.as_ref()
    }

    /// `session_id`, once established.
    pub fn session_id(&self) -> Option<[u8; 16]> {
        self.session_id
    }

    /// The current send epoch.
    pub fn send_epoch(&self) -> Option<u16> {
        self.record.as_ref().map(RecordLayer::send_epoch)
    }

    /// The current receive epoch.
    pub fn recv_epoch(&self) -> Option<u16> {
        self.record.as_ref().map(RecordLayer::recv_epoch)
    }

    /// Counters for reports and tests.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// The next frame to send. On a lossy transport R stays under the
    /// anti-amplification limit until the handshake completes.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        let len = self.tx.front()?.len() as u64;
        let limited =
            !self.is_strict() && self.cfg.role == Role::Responder && !self.handshake_complete;
        if limited && self.tx_bytes + len > 3 * self.rx_bytes {
            return None;
        }
        self.tx_bytes += len;
        self.tx.pop_front()
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    fn queue_handshake_message(&mut self, frame: &[u8]) -> Result<(), HandshakeFailure> {
        let frames = fragment(frame, self.cfg.transport.max_frame_len)
            .map_err(|_| HandshakeFailure::generic("cannot fragment a handshake message"))?;
        self.tx.extend(frames);
        Ok(())
    }

    fn finish_closed(&mut self) {
        self.state = State::Closed;
        self.record = None;
        self.flight_retry = None;
        self.rotate_request = None;
        self.finish_frame = None;
    }

    fn handshake_failed(&mut self, failure: HandshakeFailure) {
        self.events.push_back(Event::HandshakeFailed(failure));
        self.finish_closed();
    }

    /// A failed handshake message. A strict session ends. A lossy session ignores
    /// the message, because it may be spoofed, and remembers the reason for when the
    /// timer expires. A pin failure comes after the signature and MAC verified, so it
    /// cannot be spoofed and ends a lossy session too.
    fn on_handshake_error(&mut self, failure: HandshakeFailure) {
        if self.is_strict() || failure.code == ErrorCode::PeerIdentityChanged {
            self.handshake_failed(failure);
        } else {
            self.stats.frames_dropped += 1;
            self.last_failure = Some(failure);
        }
    }

    fn invalid_frame(&mut self, now_ms: u64, detail: &'static str) {
        if !self.handshake_complete && !self.record_ready() {
            self.on_handshake_error(HandshakeFailure::generic(detail));
            return;
        }
        if self.is_strict() {
            self.abort(now_ms, reason::PROTOCOL_ERROR);
        } else {
            self.stats.frames_dropped += 1;
        }
    }

    fn record_ready(&self) -> bool {
        self.record.is_some()
    }

    /// Ends a session with a generic error, telling the peer only that it failed.
    fn abort(&mut self, _now_ms: u64, code: u16) {
        if let Some(record) = self.record.as_mut()
            && record.can_send()
        {
            let mut plain = vec![inner::CLOSE];
            plain.extend_from_slice(&code.to_be_bytes());
            if let Ok(frame) = record.seal(0, &plain) {
                self.tx.push_back(frame);
            }
        }
        self.events.push_back(Event::Closed {
            clean: false,
            reason: code,
        });
        self.finish_closed();
    }

    /// Hands the session one frame.
    pub fn handle_frame(&mut self, now_ms: u64, frame: &[u8]) {
        if self.is_closed() {
            return;
        }
        self.rx_bytes += frame.len() as u64;
        let (header, body) = match parse_frame(frame) {
            Ok(parts) => parts,
            Err(_) => return self.invalid_frame(now_ms, "malformed frame"),
        };
        match header.msg_type {
            msg::RECORD => self.on_record(now_ms, &header, frame),
            msg::HS_FRAGMENT => match self.reassembler.push(&header, body) {
                Ok(Some(whole)) => self.on_handshake_message(now_ms, &whole),
                Ok(None) => {}
                Err(_) => self.invalid_frame(now_ms, "invalid handshake fragment"),
            },
            _ => self.on_handshake_message(now_ms, frame),
        }
    }

    fn on_handshake_message(&mut self, now_ms: u64, frame: &[u8]) {
        let Ok((header, body)) = parse_frame(frame) else {
            return self.invalid_frame(now_ms, "malformed handshake message");
        };
        if header.channel_id != 0 || header.seq != 0 {
            return self.invalid_frame(now_ms, "handshake header fields are not zero");
        }
        match (&mut self.state, header.msg_type) {
            (State::WaitingForInit, msg::XX_INIT) => match handshake::on_init(&self.cfg, frame) {
                Ok(InitOutcome::Drop) => {
                    self.on_handshake_error(HandshakeFailure::generic("unknown rendezvous id"))
                }
                Ok(InitOutcome::Reject { frame, failure }) => {
                    self.tx.push_back(frame);
                    self.handshake_failed(failure);
                }
                Ok(InitOutcome::Accept(responder)) => {
                    let resp = responder.resp_frame().to_vec();
                    self.state = State::WaitingForFinish(responder);
                    if let Err(f) = self.queue_handshake_message(&resp) {
                        self.handshake_failed(f);
                    }
                }
                Err(f) => self.on_handshake_error(f),
            },
            (State::WaitingForFinish(responder), msg::XX_INIT) => {
                // A duplicate gets the stored XX_RESP, without signing again.
                if !self.cfg.transport.is_strict() && responder.init_frame() == frame {
                    let resp = responder.resp_frame().to_vec();
                    if let Err(f) = self.queue_handshake_message(&resp) {
                        self.handshake_failed(f);
                    }
                } else {
                    self.invalid_frame(now_ms, "an unexpected XX_INIT");
                }
            }
            (State::WaitingForFinish(responder), msg::XX_FINISH) => {
                match responder.on_finish(&mut self.cfg, frame, now_ms) {
                    Ok(done) => {
                        let hash = self.cfg.provider.hash(frame);
                        self.finish_hash = Some(hash);
                        self.install(now_ms, done);
                    }
                    Err(f) => self.on_handshake_error(f),
                }
            }
            (State::Initiating(initiator), msg::XX_RESP) => {
                match initiator.on_resp(&mut self.cfg, frame, now_ms) {
                    Ok(done) => self.install(now_ms, done),
                    Err(f) => self.on_handshake_error(f),
                }
            }
            (State::Initiating(initiator), msg::HS_REJECT) => {
                // Section 13: ignored unless it echoes our random. Only an on-path
                // attacker can forge one, and the only reaction is to fail the attempt.
                let mut r = Reader::new(body);
                let (Ok(code), Ok(echo)) = (r.u16(), r.array::<32>()) else {
                    return self.invalid_frame(now_ms, "malformed HS_REJECT");
                };
                if !ct_eq(&echo, initiator.random()) {
                    return self.invalid_frame(now_ms, "HS_REJECT does not echo our random");
                }
                let failure = match code {
                    crate::wire::reject::UNSUPPORTED_VERSION => HandshakeFailure {
                        code: ErrorCode::VersionMismatch,
                        detail: "rejected: version",
                    },
                    crate::wire::reject::UNSUPPORTED_SUITE => HandshakeFailure {
                        code: ErrorCode::SuiteMismatch,
                        detail: "rejected: suite",
                    },
                    _ => HandshakeFailure::generic("rejected: busy"),
                };
                self.handshake_failed(failure);
            }
            (
                State::Established | State::Closing { .. } | State::ClosingLossy { .. },
                msg::XX_FINISH,
            ) if self.cfg.role == Role::Responder => {
                self.on_duplicate_finish(now_ms, frame);
            }
            // A late duplicate of something already processed.
            (State::Established, msg::XX_RESP | msg::XX_INIT)
                if !self.cfg.transport.is_strict() =>
            {
                self.stats.frames_dropped += 1;
            }
            _ => self.invalid_frame(now_ms, "an unexpected handshake message"),
        }
    }

    /// Section 5.5: R answers a duplicate `XX_FINISH` with a new `KEY_CONFIRM`, at
    /// most once per second.
    fn on_duplicate_finish(&mut self, now_ms: u64, frame: &[u8]) {
        let hash = self.cfg.provider.hash(frame);
        if self.is_strict() || self.finish_hash.as_deref() != Some(hash.as_slice()) {
            return self.invalid_frame(now_ms, "an unexpected XX_FINISH");
        }
        if self
            .last_confirm_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < 1000)
        {
            return;
        }
        self.last_confirm_ms = Some(now_ms);
        let _ = self.send_inner(now_ms, 0, inner::KEY_CONFIRM, &[]);
    }

    fn install(&mut self, now_ms: u64, done: Completed) {
        let is_initiator = self.cfg.role == Role::Initiator;
        let record = RecordLayer::new(
            self.cfg.provider.clone(),
            done.version,
            done.suite,
            self.is_strict(),
            is_initiator,
            done.secrets.i_ap,
            done.secrets.r_ap,
            self.cfg.limits,
            now_ms,
        );
        let record = match record {
            Ok(record) => record,
            Err(_) => {
                return self.handshake_failed(HandshakeFailure::generic("key schedule failed"));
            }
        };
        self.record = Some(record);
        self.session_id = Some(done.secrets.session_id);
        self.peer = Some(done.peer.clone());
        self.state = State::Established;
        self.last_rx_ms = now_ms;
        self.last_ping_ms = now_ms;
        self.last_failure = None;
        self.flight_retry = None;
        self.events.push_back(Event::Established {
            peer: done.peer,
            session_id: done.secrets.session_id,
            suite: done.suite,
            version: done.version,
        });

        if is_initiator {
            if let Some(finish) = done.finish_frame {
                if let Err(f) = self.queue_handshake_message(&finish) {
                    return self.handshake_failed(f);
                }
                if !self.is_strict() {
                    let mut retry = Retry::new(now_ms, &self.cfg.limits);
                    retry.give_up_at = self.hs_deadline;
                    self.flight_retry = Some(retry);
                    self.finish_frame = Some(finish);
                }
            }
        } else {
            // R has verified XX_FINISH, so the handshake is complete for it.
            self.handshake_complete = true;
            self.last_confirm_ms = Some(now_ms);
            if self.send_inner(now_ms, 0, inner::KEY_CONFIRM, &[]).is_err() {
                self.abort(now_ms, reason::INTERNAL_ERROR);
            }
        }
    }

    fn on_record(&mut self, now_ms: u64, header: &crate::wire::Header, frame: &[u8]) {
        let accepts = matches!(
            self.state,
            State::Established | State::Closing { .. } | State::ClosingLossy { .. }
        );
        let Some(record) = self.record.as_mut().filter(|_| accepts) else {
            // R must not accept records before XX_FINISH has verified.
            return self.invalid_frame(now_ms, "a record before the handshake completed");
        };
        let opened = match record.open(header, frame, now_ms) {
            Ok(opened) => opened,
            Err(_) => return self.invalid_frame(now_ms, "a record was refused"),
        };
        let epoch_now = record.recv_epoch();
        let exceeded = record.peer_exceeded_limits();

        self.last_rx_ms = now_ms;
        self.stats.records_received += 1;

        // Any valid record tells I that R holds the same transcript.
        if self.cfg.role == Role::Initiator && !self.peer_confirmed {
            self.peer_confirmed = true;
            self.handshake_complete = true;
            self.flight_retry = None;
            self.finish_frame = None;
            self.events.push_back(Event::PeerConfirmed);
        }
        if opened.epoch_advanced {
            self.events.push_back(Event::KeysRotated {
                send: false,
                epoch: epoch_now,
            });
            self.check_rotation_done(epoch_now);
        }
        if exceeded {
            return self.abort(now_ms, reason::PROTOCOL_ERROR);
        }
        self.dispatch_inner(now_ms, header.channel_id, opened.epoch, &opened.plaintext);
    }

    fn check_rotation_done(&mut self, epoch_now: u16) {
        if self
            .rotate_request
            .as_ref()
            .is_some_and(|r| epoch_now > r.peer_epoch)
        {
            self.rotate_request = None;
            self.events.push_back(Event::RotationComplete);
        }
    }

    fn dispatch_inner(&mut self, now_ms: u64, channel_id: u16, epoch: u16, plaintext: &[u8]) {
        let Some((&inner_type, body)) = plaintext.split_first() else {
            return self.invalid_frame(now_ms, "an empty record");
        };
        let channel_rule_ok = match inner_type {
            inner::DATA
            | inner::CHANNEL_OPEN
            | inner::CHANNEL_ACCEPT
            | inner::CHANNEL_REJECT
            | inner::CHANNEL_CLOSE => channel_id != 0,
            _ => channel_id == 0,
        };
        if !channel_rule_ok {
            return self.invalid_frame(now_ms, "channel_id does not fit the record type");
        }
        match inner_type {
            inner::DATA => self.on_data(now_ms, channel_id, body),
            inner::KEY_UPDATE => self.on_key_update(now_ms, epoch, body),
            inner::KEY_CONFIRM => {
                if self.cfg.role != Role::Initiator || !body.is_empty() {
                    self.invalid_frame(now_ms, "an unexpected KEY_CONFIRM");
                }
            }
            inner::CHANNEL_OPEN => self.on_channel_open(now_ms, channel_id, body),
            inner::CHANNEL_ACCEPT => self.on_channel_accept(now_ms, channel_id, body),
            inner::CHANNEL_REJECT => self.on_channel_reject(now_ms, channel_id, body),
            inner::CHANNEL_CLOSE => self.on_channel_close(now_ms, channel_id, body),
            inner::PING => {
                if body.len() != 8 {
                    return self.invalid_frame(now_ms, "a malformed PING");
                }
                let _ = self.send_inner(now_ms, 0, inner::PONG, body);
            }
            inner::PONG => {
                if body.len() != 8 {
                    self.invalid_frame(now_ms, "a malformed PONG");
                }
            }
            inner::CLOSE => self.on_close(now_ms, body),
            inner::CONTROL => {
                if self.cfg.plane != Plane::Control {
                    return self.invalid_frame(now_ms, "CONTROL on the data plane");
                }
                self.events.push_back(Event::Control {
                    body: body.to_vec(),
                });
            }
            _ => self.invalid_frame(now_ms, "an unknown record type"),
        }
    }

    // ---------------------------------------------------------------- sending

    fn send_inner(
        &mut self,
        now_ms: u64,
        channel_id: u16,
        inner_type: u8,
        body: &[u8],
    ) -> Result<(), ErrorCode> {
        let must_rotate = {
            let record = self.record.as_ref().ok_or(ErrorCode::InvalidState)?;
            if !record.can_send() {
                return Err(ErrorCode::Closed);
            }
            record.must_rotate(now_ms, body.len() + 1)
        };
        if must_rotate {
            self.rotate_send_now(now_ms, false)?;
        }
        let record = self.record.as_mut().ok_or(ErrorCode::InvalidState)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(body.len() + 1));
        plaintext.push(inner_type);
        plaintext.extend_from_slice(body);
        let frame = record
            .seal(channel_id, &plaintext)
            .map_err(|_| ErrorCode::InvalidState)?;
        self.tx.push_back(frame);
        self.stats.records_sent += 1;
        Ok(())
    }

    /// Section 9.5: `KEY_UPDATE` is the last record under the old keys, and the old
    /// secret and keys are zeroized at once.
    fn rotate_send_now(&mut self, now_ms: u64, update_requested: bool) -> Result<(), ErrorCode> {
        let record = self.record.as_mut().ok_or(ErrorCode::InvalidState)?;
        let frame = record
            .seal(0, &[inner::KEY_UPDATE, u8::from(update_requested)])
            .map_err(|_| ErrorCode::InvalidState)?;
        let epoch = record
            .rotate_send(now_ms)
            .map_err(|_| ErrorCode::InvalidState)?;
        self.tx.push_back(frame);
        self.stats.records_sent += 1;
        self.events
            .push_back(Event::KeysRotated { send: true, epoch });
        Ok(())
    }

    fn max_record_plaintext(&self) -> usize {
        let frame = self.cfg.transport.max_frame_len.min(HEADER_LEN + MAX_BODY);
        frame.saturating_sub(HEADER_LEN + self.cfg.provider.params().tag_len)
    }

    /// Opens a channel. The result arrives as [`Event::ChannelOpened`] or
    /// [`Event::ChannelRejected`].
    pub fn open_channel(&mut self, now_ms: u64, options: ChannelOptions) -> Result<u16, ErrorCode> {
        if !self.is_established() {
            return Err(ErrorCode::InvalidState);
        }
        if options.label.len() > 255 {
            return Err(ErrorCode::InvalidArgument);
        }
        if options.reliable && !self.is_strict() {
            return Err(ErrorCode::TransportUnsupported);
        }
        let id = u16::try_from(self.next_channel_id).map_err(|_| ErrorCode::InvalidState)?;
        let body = crate::control::encode_channel_options(
            options.ordered,
            options.reliable,
            &options.label,
        )
        .map_err(|_| ErrorCode::InvalidArgument)?;
        self.send_inner(now_ms, id, inner::CHANNEL_OPEN, &body)?;
        self.next_channel_id += 2;
        let mut channel = Channel::new(options, ChannelState::Opening);
        channel.retry = Some(Retry::new(now_ms, &self.cfg.limits));
        self.channels.insert(id, channel);
        Ok(id)
    }

    /// Accepts a channel from [`Event::ChannelRequested`].
    pub fn accept_channel(&mut self, now_ms: u64, channel_id: u16) -> Result<(), ErrorCode> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or(ErrorCode::InvalidArgument)?;
        if channel.state != ChannelState::Pending {
            return Err(ErrorCode::InvalidState);
        }
        channel.state = ChannelState::Open;
        self.send_inner(now_ms, channel_id, inner::CHANNEL_ACCEPT, &[])
    }

    /// Declines a channel from [`Event::ChannelRequested`].
    pub fn reject_channel(
        &mut self,
        now_ms: u64,
        channel_id: u16,
        code: u16,
    ) -> Result<(), ErrorCode> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or(ErrorCode::InvalidArgument)?;
        if channel.state != ChannelState::Pending {
            return Err(ErrorCode::InvalidState);
        }
        channel.state = ChannelState::Rejected { reason: code };
        self.send_inner(
            now_ms,
            channel_id,
            inner::CHANNEL_REJECT,
            &code.to_be_bytes(),
        )
    }

    /// Sends one application message, fragmenting it if needed.
    pub fn send(&mut self, now_ms: u64, channel_id: u16, payload: &[u8]) -> Result<(), ErrorCode> {
        if !self.is_established() {
            return Err(ErrorCode::Closed);
        }
        if payload.len() > self.cfg.limits.max_message {
            return Err(ErrorCode::MessageTooLarge);
        }
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or(ErrorCode::InvalidArgument)?;
        if channel.state != ChannelState::Open {
            return Err(ErrorCode::Closed);
        }
        let message_id = channel.next_message_id;
        channel.next_message_id = message_id.checked_add(1).ok_or(ErrorCode::InvalidState)?;

        const DATA_HEADER: usize = 7;
        let max_chunk = self
            .max_record_plaintext()
            .checked_sub(1 + DATA_HEADER)
            .filter(|n| *n > 0)
            .ok_or(ErrorCode::Unsupported)?;
        let count = payload.len().div_ceil(max_chunk).max(1);
        if count > usize::from(u16::MAX) + 1 {
            return Err(ErrorCode::MessageTooLarge);
        }
        let mut chunks = payload.chunks(max_chunk);
        for index in 0..count {
            let chunk = chunks.next().unwrap_or(&[]);
            let mut w = Writer::new();
            w.u32(message_id);
            w.u16(index as u16);
            w.u8(u8::from(index + 1 == count));
            w.bytes(chunk);
            self.send_inner(now_ms, channel_id, inner::DATA, &w.buf)?;
        }
        self.stats.bytes_sent += payload.len() as u64;
        Ok(())
    }

    /// Closes one channel. Other channels stay open.
    pub fn close_channel(
        &mut self,
        now_ms: u64,
        channel_id: u16,
        code: u16,
    ) -> Result<(), ErrorCode> {
        let limits = self.cfg.limits;
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or(ErrorCode::InvalidArgument)?;
        if !matches!(channel.state, ChannelState::Open | ChannelState::Pending) {
            return Err(ErrorCode::InvalidState);
        }
        channel.state = ChannelState::Closing;
        channel.close_reason = code;
        channel.retry = Some(Retry::new(now_ms, &limits));
        self.send_inner(
            now_ms,
            channel_id,
            inner::CHANNEL_CLOSE,
            &code.to_be_bytes(),
        )
    }

    /// Sends a `CONTROL` record. It must fit in one record.
    pub fn send_control(&mut self, now_ms: u64, body: &[u8]) -> Result<(), ErrorCode> {
        if self.cfg.plane != Plane::Control {
            return Err(ErrorCode::InvalidState);
        }
        if !self.is_established() {
            return Err(ErrorCode::InvalidState);
        }
        if body.len() + 1 > self.max_record_plaintext() {
            return Err(ErrorCode::MessageTooLarge);
        }
        self.send_inner(now_ms, 0, inner::CONTROL, body)
    }

    /// Asks the peer to rotate too, and rotates this side. The result arrives as
    /// [`Event::RotationComplete`] or [`Event::RotationTimedOut`].
    pub fn rotate_keys(&mut self, now_ms: u64) -> Result<(), ErrorCode> {
        if !self.is_established() {
            return Err(ErrorCode::InvalidState);
        }
        if self.rotate_request.is_some() {
            return Ok(());
        }
        let peer_epoch = self.recv_epoch().ok_or(ErrorCode::InvalidState)?;
        self.rotate_send_now(now_ms, true)?;
        self.rotate_request = Some(RotateRequest {
            peer_epoch,
            retry: Retry::new(now_ms, &self.cfg.limits),
        });
        Ok(())
    }

    /// Rotates only this side's sending keys, as the limits in section 9.5 do. It
    /// needs no cooperation from the peer.
    pub fn rotate_send(&mut self, now_ms: u64) -> Result<(), ErrorCode> {
        if !self.is_established() {
            return Err(ErrorCode::InvalidState);
        }
        self.rotate_send_now(now_ms, false)
    }

    /// Sends `PING`.
    pub fn ping(&mut self, now_ms: u64) -> Result<(), ErrorCode> {
        let mut random = [0u8; 8];
        self.provider()
            .random(&mut random)
            .map_err(|_| ErrorCode::Internal)?;
        self.send_inner(now_ms, 0, inner::PING, &random)
    }

    /// Finishes the session with an authenticated `CLOSE` (section 9.7).
    pub fn close(&mut self, now_ms: u64, code: u16) {
        match self.state {
            State::Established => {
                let sent = self
                    .send_inner(now_ms, 0, inner::CLOSE, &code.to_be_bytes())
                    .is_ok();
                if !sent {
                    self.events.push_back(Event::Closed {
                        clean: false,
                        reason: code,
                    });
                    return self.finish_closed();
                }
                if self.is_strict() {
                    if let Some(record) = self.record.as_mut() {
                        record.drop_send_keys();
                    }
                    self.state = State::Closing {
                        give_up_at: now_ms.saturating_add(self.cfg.limits.close_timeout_ms),
                        reason: code,
                    };
                } else {
                    self.state = State::ClosingLossy {
                        remaining: 2,
                        next_at: now_ms + 200,
                        reason: code,
                    };
                }
            }
            State::Closing { .. } | State::ClosingLossy { .. } | State::Closed => {}
            _ => {
                self.events.push_back(Event::Closed {
                    clean: false,
                    reason: code,
                });
                self.finish_closed();
            }
        }
    }

    /// Tells the session that the transport has ended.
    pub fn on_transport_closed(&mut self, _now_ms: u64) {
        match self.state {
            State::Closed => {}
            State::Initiating(_) | State::WaitingForInit | State::WaitingForFinish(_) => {
                self.handshake_failed(HandshakeFailure {
                    code: ErrorCode::TransportFailed,
                    detail: "the transport ended during the handshake",
                });
            }
            // Nothing authenticated the end, so an application can detect truncation.
            _ => {
                self.events.push_back(Event::Closed {
                    clean: false,
                    reason: reason::NORMAL,
                });
                self.finish_closed();
            }
        }
    }

    // ---------------------------------------------------------------- receiving

    fn on_key_update(&mut self, now_ms: u64, epoch: u16, body: &[u8]) {
        let [requested] = body else {
            return self.invalid_frame(now_ms, "a malformed KEY_UPDATE");
        };
        if *requested > 1 {
            return self.invalid_frame(now_ms, "a malformed KEY_UPDATE");
        }
        // Only a KEY_UPDATE from the current epoch moves the receiver. A reordered
        // one from an earlier epoch has already been overtaken.
        let current = self.recv_epoch() == Some(epoch);
        if current {
            let Some(record) = self.record.as_mut() else {
                return;
            };
            if record.advance_recv(now_ms).is_err() {
                return self.abort(now_ms, reason::PROTOCOL_ERROR);
            }
            let epoch_now = record.recv_epoch();
            self.events.push_back(Event::KeysRotated {
                send: false,
                epoch: epoch_now,
            });
            self.check_rotation_done(epoch_now);
        }
        if *requested == 1 {
            self.serve_update_request(now_ms);
        }
    }

    /// A peer serves at most one request per second, and defers the rest so that
    /// repeated requests combine into one rotation (section 9.5).
    fn serve_update_request(&mut self, now_ms: u64) {
        let allowed = self
            .last_update_served_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= 1000);
        if allowed {
            self.last_update_served_ms = Some(now_ms);
            self.deferred_update = false;
            if self.is_established() && self.rotate_send_now(now_ms, false).is_err() {
                self.abort(now_ms, reason::INTERNAL_ERROR);
            }
        } else {
            self.deferred_update = true;
        }
    }

    fn on_close(&mut self, now_ms: u64, body: &[u8]) {
        let [high, low] = body else {
            return self.invalid_frame(now_ms, "a malformed CLOSE");
        };
        let code = u16::from_be_bytes([*high, *low]);
        match self.state {
            State::Established => {
                if self.is_strict() {
                    let _ = self.send_inner(now_ms, 0, inner::CLOSE, &code.to_be_bytes());
                }
                self.close_all_channels(true);
                self.events.push_back(Event::Closed {
                    clean: true,
                    reason: code,
                });
                self.finish_closed();
            }
            State::Closing { reason, .. } => {
                self.close_all_channels(true);
                self.events.push_back(Event::Closed {
                    clean: true,
                    reason,
                });
                self.finish_closed();
            }
            _ => {}
        }
    }

    fn close_all_channels(&mut self, clean: bool) {
        for (id, channel) in &mut self.channels {
            if matches!(
                channel.state,
                ChannelState::Open | ChannelState::Closing | ChannelState::Pending
            ) {
                channel.state = ChannelState::Closed { by_us: false };
                channel.retry = None;
                channel.partials.clear();
                self.events.push_back(Event::ChannelClosed {
                    channel_id: *id,
                    clean,
                    reason: reason::NORMAL,
                });
            }
        }
        self.partial_bytes = 0;
    }

    fn peer_allocates(&self, channel_id: u16) -> bool {
        // I allocates odd IDs and R allocates even ones.
        let odd = channel_id % 2 == 1;
        match self.cfg.role {
            Role::Initiator => !odd,
            Role::Responder => odd,
        }
    }

    fn on_channel_open(&mut self, now_ms: u64, channel_id: u16, body: &[u8]) {
        if !self.peer_allocates(channel_id) {
            return self.invalid_frame(now_ms, "CHANNEL_OPEN with this side's channel id");
        }
        let Ok((ordered, reliable, label)) = crate::control::parse_channel_options(body) else {
            return self.invalid_frame(now_ms, "a malformed CHANNEL_OPEN");
        };
        // Duplicates get the same reply (section 9.8).
        if let Some(channel) = self.channels.get(&channel_id) {
            match channel.state {
                ChannelState::Open | ChannelState::Closing => {
                    let _ = self.send_inner(now_ms, channel_id, inner::CHANNEL_ACCEPT, &[]);
                }
                ChannelState::Rejected { reason } => {
                    let _ = self.send_inner(
                        now_ms,
                        channel_id,
                        inner::CHANNEL_REJECT,
                        &reason.to_be_bytes(),
                    );
                }
                _ => {}
            }
            return;
        }
        let options = ChannelOptions {
            ordered,
            reliable,
            label,
        };
        if options.reliable && !self.is_strict() {
            // Section 10: the core does not retransmit application data.
            let code = reason::TRANSPORT_UNSUPPORTED;
            self.channels.insert(
                channel_id,
                Channel::new(options, ChannelState::Rejected { reason: code }),
            );
            let _ = self.send_inner(
                now_ms,
                channel_id,
                inner::CHANNEL_REJECT,
                &code.to_be_bytes(),
            );
            return;
        }
        self.channels.insert(
            channel_id,
            Channel::new(options.clone(), ChannelState::Pending),
        );
        self.events.push_back(Event::ChannelRequested {
            channel_id,
            options,
        });
    }

    fn on_channel_accept(&mut self, now_ms: u64, channel_id: u16, body: &[u8]) {
        if !body.is_empty() {
            return self.invalid_frame(now_ms, "a malformed CHANNEL_ACCEPT");
        }
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return self.invalid_frame(now_ms, "CHANNEL_ACCEPT for an unknown channel");
        };
        if channel.state == ChannelState::Opening {
            channel.state = ChannelState::Open;
            channel.retry = None;
            self.events.push_back(Event::ChannelOpened { channel_id });
        }
    }

    fn on_channel_reject(&mut self, now_ms: u64, channel_id: u16, body: &[u8]) {
        let [high, low] = body else {
            return self.invalid_frame(now_ms, "a malformed CHANNEL_REJECT");
        };
        let code = u16::from_be_bytes([*high, *low]);
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return self.invalid_frame(now_ms, "CHANNEL_REJECT for an unknown channel");
        };
        if channel.state == ChannelState::Opening {
            channel.state = ChannelState::Rejected { reason: code };
            channel.retry = None;
            self.events.push_back(Event::ChannelRejected {
                channel_id,
                reason: code,
            });
        }
    }

    fn on_channel_close(&mut self, now_ms: u64, channel_id: u16, body: &[u8]) {
        let [high, low] = body else {
            return self.invalid_frame(now_ms, "a malformed CHANNEL_CLOSE");
        };
        let code = u16::from_be_bytes([*high, *low]);
        let strict = self.is_strict();
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return self.invalid_frame(now_ms, "CHANNEL_CLOSE for an unknown channel");
        };
        match channel.state {
            ChannelState::Open | ChannelState::Pending | ChannelState::Opening => {
                channel.state = ChannelState::Closed { by_us: false };
                channel.retry = None;
                let freed: usize = channel.partials.values().map(|p| p.bytes).sum();
                channel.partials.clear();
                self.partial_bytes = self.partial_bytes.saturating_sub(freed);
                self.events.push_back(Event::ChannelClosed {
                    channel_id,
                    clean: true,
                    reason: code,
                });
                let _ = self.send_inner(
                    now_ms,
                    channel_id,
                    inner::CHANNEL_CLOSE,
                    &code.to_be_bytes(),
                );
            }
            ChannelState::Closing => {
                let our_reason = channel.close_reason;
                channel.state = ChannelState::Closed { by_us: true };
                channel.retry = None;
                let freed: usize = channel.partials.values().map(|p| p.bytes).sum();
                channel.partials.clear();
                self.partial_bytes = self.partial_bytes.saturating_sub(freed);
                self.events.push_back(Event::ChannelClosed {
                    channel_id,
                    clean: true,
                    reason: our_reason,
                });
            }
            // Only the side that answered a close repeats its answer. The side that
            // started the close stays quiet, so the two cannot echo forever.
            ChannelState::Closed { by_us: false } if !strict => {
                let _ = self.send_inner(
                    now_ms,
                    channel_id,
                    inner::CHANNEL_CLOSE,
                    &code.to_be_bytes(),
                );
            }
            _ => {}
        }
    }

    fn on_data(&mut self, now_ms: u64, channel_id: u16, body: &[u8]) {
        let mut r = Reader::new(body);
        let (Ok(message_id), Ok(index), Ok(flags)) = (r.u32(), r.u16(), r.u8()) else {
            return self.invalid_frame(now_ms, "a malformed DATA record");
        };
        let payload = r.rest();
        if flags > 1 {
            return self.invalid_frame(now_ms, "a malformed DATA record");
        }
        let last = flags == 1;
        let strict = self.is_strict();
        let limits = self.cfg.limits;
        let Some(channel) = self.channels.get_mut(&channel_id) else {
            return self.invalid_frame(now_ms, "DATA for an unknown channel");
        };
        match channel.state {
            ChannelState::Open | ChannelState::Closing => {}
            _ => return self.invalid_frame(now_ms, "DATA for a channel that is not open"),
        }
        self.stats.bytes_received += payload.len() as u64;

        let drop_late = !strict && channel.options.ordered;
        if drop_late && channel.last_delivered.is_some_and(|l| message_id <= l) {
            return;
        }

        // The common case needs no buffering.
        if index == 0 && last {
            if payload.len() > limits.max_message {
                return self.channel_too_large(now_ms, channel_id);
            }
            channel.last_delivered = Some(
                channel
                    .last_delivered
                    .map_or(message_id, |l| l.max(message_id)),
            );
            self.events.push_back(Event::Message {
                channel_id,
                payload: payload.to_vec(),
            });
            return;
        }

        let partial = channel
            .partials
            .entry(message_id)
            .or_insert_with(|| Partial {
                fragments: BTreeMap::new(),
                last_index: None,
                bytes: 0,
                started_at: now_ms,
            });
        if partial.fragments.contains_key(&index) {
            return;
        }
        if partial.bytes + payload.len() > limits.max_message
            || self.partial_bytes + payload.len() > limits.max_reassembly
        {
            return self.channel_too_large(now_ms, channel_id);
        }
        partial.fragments.insert(index, payload.to_vec());
        partial.bytes += payload.len();
        self.partial_bytes += payload.len();
        if last {
            partial.last_index = Some(index);
        }
        let complete = partial
            .last_index
            .is_some_and(|l| partial.fragments.len() == usize::from(l) + 1);
        if !complete {
            return;
        }

        let done = channel.partials.remove(&message_id);
        let Some(done) = done else { return };
        self.partial_bytes -= done.bytes;
        let mut whole = Vec::with_capacity(done.bytes);
        for fragment in done.fragments.values() {
            whole.extend_from_slice(fragment);
        }
        if drop_late {
            // Anything older can no longer be delivered in order.
            let stale: Vec<u32> = channel
                .partials
                .range(..message_id)
                .map(|(id, _)| *id)
                .collect();
            for id in stale {
                if let Some(p) = channel.partials.remove(&id) {
                    self.partial_bytes -= p.bytes;
                }
            }
        }
        channel.last_delivered = Some(
            channel
                .last_delivered
                .map_or(message_id, |l| l.max(message_id)),
        );
        self.events.push_back(Event::Message {
            channel_id,
            payload: whole,
        });
    }

    fn channel_too_large(&mut self, now_ms: u64, channel_id: u16) {
        let code = reason::MESSAGE_TOO_LARGE;
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            let freed: usize = channel.partials.values().map(|p| p.bytes).sum();
            channel.partials.clear();
            self.partial_bytes = self.partial_bytes.saturating_sub(freed);
            channel.state = ChannelState::Closed { by_us: true };
            channel.retry = None;
        }
        self.events.push_back(Event::ChannelClosed {
            channel_id,
            clean: false,
            reason: code,
        });
        let _ = self.send_inner(
            now_ms,
            channel_id,
            inner::CHANNEL_CLOSE,
            &code.to_be_bytes(),
        );
    }

    // ---------------------------------------------------------------- timers

    /// The next time [`Session::handle_timeout`] has work to do. Every timer returned
    /// here is cleared or moved by handling it, so a caller never spins on a past time.
    pub fn next_timeout(&self) -> Option<u64> {
        let mut next: Option<u64> = None;
        let mut consider = |t: u64| next = Some(next.map_or(t, |n: u64| n.min(t)));
        match self.state {
            State::Closed => return None,
            State::Initiating(_) | State::WaitingForInit | State::WaitingForFinish(_) => {
                consider(self.hs_deadline);
                if let Some(retry) = &self.flight_retry {
                    consider(retry.next_at);
                }
            }
            State::Closing { give_up_at, .. } => consider(give_up_at),
            State::ClosingLossy { next_at, .. } => consider(next_at),
            State::Established => {
                let strict = self.is_strict();
                if self.cfg.role == Role::Initiator && !self.peer_confirmed {
                    consider(self.hs_deadline);
                    if let Some(retry) = &self.flight_retry {
                        consider(retry.next_at);
                    }
                }
                if let Some(request) = &self.rotate_request {
                    consider(request.retry.give_up_at);
                    if !strict {
                        consider(request.retry.next_at);
                    }
                }
                if self.deferred_update
                    && let Some(last) = self.last_update_served_ms
                {
                    consider(last.saturating_add(1000));
                }
                if let Some(record) = &self.record {
                    consider(record.rotate_deadline());
                }
                for channel in self.channels.values() {
                    if let Some(retry) = &channel.retry {
                        consider(retry.give_up_at);
                        if !strict {
                            consider(retry.next_at);
                        }
                    }
                    if !strict {
                        for partial in channel.partials.values() {
                            consider(
                                partial
                                    .started_at
                                    .saturating_add(self.cfg.limits.partial_timeout_ms),
                            );
                        }
                    }
                }
                if let Some(interval) = self.cfg.limits.keepalive_ms {
                    consider(self.last_ping_ms.saturating_add(interval));
                }
            }
        }
        if let Some(expiry) = self
            .record
            .as_ref()
            .and_then(RecordLayer::next_retained_expiry)
        {
            consider(expiry);
        }
        next
    }

    /// Drives every timer. Calling it early or often is harmless.
    pub fn handle_timeout(&mut self, now_ms: u64) {
        match self.state {
            State::Closed => return,
            State::Initiating(_) | State::WaitingForInit | State::WaitingForFinish(_) => {
                if now_ms >= self.hs_deadline {
                    let failure = self.last_failure.unwrap_or(HandshakeFailure {
                        code: ErrorCode::Timeout,
                        detail: "the handshake timed out",
                    });
                    return self.handshake_failed(failure);
                }
            }
            State::Closing { give_up_at, reason } => {
                if now_ms >= give_up_at {
                    self.events.push_back(Event::Closed {
                        clean: false,
                        reason,
                    });
                    return self.finish_closed();
                }
            }
            State::ClosingLossy {
                remaining,
                next_at,
                reason,
            } => {
                if now_ms >= next_at {
                    let _ = self.send_inner(now_ms, 0, inner::CLOSE, &reason.to_be_bytes());
                    if remaining <= 1 {
                        self.events.push_back(Event::Closed {
                            clean: true,
                            reason,
                        });
                        return self.finish_closed();
                    }
                    self.state = State::ClosingLossy {
                        remaining: remaining - 1,
                        next_at: now_ms + 200,
                        reason,
                    };
                }
            }
            State::Established => {}
        }

        self.retransmit_flight(now_ms);
        if self.is_closed() {
            return;
        }

        // I gives up if R never confirms.
        if self.is_established()
            && self.cfg.role == Role::Initiator
            && !self.peer_confirmed
            && now_ms >= self.hs_deadline
        {
            self.events
                .push_back(Event::HandshakeFailed(HandshakeFailure {
                    code: ErrorCode::Timeout,
                    detail: "the responder never confirmed the handshake",
                }));
            return self.finish_closed();
        }

        if let Some(record) = self.record.as_mut() {
            record.expire_retained(now_ms);
        }
        if !self.is_established() {
            return;
        }

        self.drive_rotation(now_ms);
        if self.is_closed() {
            return;
        }
        self.drive_channels(now_ms);
        self.drive_keepalive(now_ms);
    }

    fn retransmit_flight(&mut self, now_ms: u64) {
        let Some(retry) = self.flight_retry.as_mut() else {
            return;
        };
        if now_ms < retry.next_at {
            return;
        }
        retry.bump(now_ms);
        if now_ms >= retry.give_up_at {
            return;
        }
        let frame = match &self.state {
            State::Initiating(initiator) => Some(initiator.frame().to_vec()),
            State::Established => self.finish_frame.clone(),
            _ => None,
        };
        if let Some(frame) = frame
            && let Err(f) = self.queue_handshake_message(&frame)
        {
            self.handshake_failed(f);
        }
    }

    fn drive_rotation(&mut self, now_ms: u64) {
        // Time-based rotation, including while idle.
        let due = self
            .record
            .as_ref()
            .is_some_and(|r| r.must_rotate(now_ms, 0));
        if due && self.rotate_send_now(now_ms, false).is_err() {
            return self.abort(now_ms, reason::INTERNAL_ERROR);
        }
        // Requests deferred by the once-per-second limit.
        if self.deferred_update {
            self.serve_update_request(now_ms);
        }
        // Section 9.8: repeat until the peer's epoch advances. Strict transports never
        // lose it, so they only wait for the time limit.
        let Some(request) = self.rotate_request.as_mut() else {
            return;
        };
        if now_ms >= request.retry.give_up_at {
            self.rotate_request = None;
            self.events.push_back(Event::RotationTimedOut);
            return;
        }
        if !self.cfg.transport.is_strict() && now_ms >= request.retry.next_at {
            request.retry.bump(now_ms);
            if self.rotate_send_now(now_ms, true).is_err() {
                self.abort(now_ms, reason::INTERNAL_ERROR);
            }
        }
    }

    fn drive_channels(&mut self, now_ms: u64) {
        let strict = self.is_strict();
        let partial_timeout = self.cfg.limits.partial_timeout_ms;
        let mut resend: Vec<(u16, u8, Vec<u8>)> = Vec::new();
        for (id, channel) in &mut self.channels {
            if !strict {
                let expired: Vec<u32> = channel
                    .partials
                    .iter()
                    .filter(|(_, p)| now_ms.saturating_sub(p.started_at) >= partial_timeout)
                    .map(|(id, _)| *id)
                    .collect();
                for message_id in expired {
                    if let Some(p) = channel.partials.remove(&message_id) {
                        self.partial_bytes = self.partial_bytes.saturating_sub(p.bytes);
                    }
                }
            }
            let Some(retry) = channel.retry.as_mut() else {
                continue;
            };
            if now_ms >= retry.give_up_at {
                channel.retry = None;
                match channel.state {
                    ChannelState::Opening => {
                        channel.state = ChannelState::Rejected {
                            reason: reason::TIMEOUT,
                        };
                        self.events.push_back(Event::ChannelRejected {
                            channel_id: *id,
                            reason: reason::TIMEOUT,
                        });
                    }
                    ChannelState::Closing => {
                        channel.state = ChannelState::Closed { by_us: true };
                        self.events.push_back(Event::ChannelClosed {
                            channel_id: *id,
                            clean: false,
                            reason: reason::TIMEOUT,
                        });
                    }
                    _ => {}
                }
                continue;
            }
            if strict || now_ms < retry.next_at {
                continue;
            }
            retry.bump(now_ms);
            match channel.state {
                ChannelState::Opening => {
                    if let Ok(body) = crate::control::encode_channel_options(
                        channel.options.ordered,
                        channel.options.reliable,
                        &channel.options.label,
                    ) {
                        resend.push((*id, inner::CHANNEL_OPEN, body));
                    }
                }
                ChannelState::Closing => {
                    resend.push((
                        *id,
                        inner::CHANNEL_CLOSE,
                        channel.close_reason.to_be_bytes().to_vec(),
                    ));
                }
                _ => {}
            }
        }
        for (id, inner_type, body) in resend {
            let _ = self.send_inner(now_ms, id, inner_type, &body);
        }
    }

    fn drive_keepalive(&mut self, now_ms: u64) {
        let Some(interval) = self.cfg.limits.keepalive_ms else {
            return;
        };
        if now_ms.saturating_sub(self.last_rx_ms) >= interval.saturating_mul(3) {
            self.events.push_back(Event::Closed {
                clean: false,
                reason: reason::TIMEOUT,
            });
            return self.finish_closed();
        }
        if now_ms.saturating_sub(self.last_ping_ms) >= interval {
            self.last_ping_ms = now_ms;
            let _ = self.ping(now_ms);
        }
    }
}
