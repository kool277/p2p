//! A small PKI and a simulated network, for tests.
#![allow(dead_code)]

use provider_testonly::TestOnlyProvider;
use qalqon_core::cert::{self, CertFields, Certificate, role};
use qalqon_core::crypto::{CryptoProvider, SigningKey};
use qalqon_core::session::{Limits, PinStatus, Plane, Role, SessionConfig, TransportCaps};
use qalqon_core::{Event, PeerExpectation, PeerRejection, PeerVerifier, Session, UncheckedPeers};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

pub const NOW: u64 = 1_800_000_000_000;
pub const DAY: u64 = 86_400_000;

pub struct Pki {
    pub provider: Arc<dyn CryptoProvider>,
    pub root_key: Box<dyn SigningKey>,
    pub root: Vec<u8>,
    pub issuing_key: Box<dyn SigningKey>,
    pub issuing: Vec<u8>,
}

fn encoded(key: &dyn SigningKey) -> Vec<u8> {
    cert::encode_public_key(key.public_key()).unwrap()
}

impl Pki {
    pub fn new() -> Self {
        Self::with_provider(Arc::new(TestOnlyProvider::new()))
    }

    pub fn with_provider(provider: Arc<dyn CryptoProvider>) -> Self {
        let p = provider.as_ref();
        let root_key = p.generate_signing_key().unwrap();
        let root = cert::issue(
            p,
            root_key.as_ref(),
            &CertFields {
                serial: cert::random_serial(p).unwrap(),
                role: role::ROOT,
                subject_a: "test root".into(),
                subject_b: String::new(),
                not_before: NOW - DAY,
                not_after: NOW + 3650 * DAY,
                sign_public: root_key.public_key().clone(),
                issuer_key_id: cert::key_id(p, &encoded(root_key.as_ref())),
            },
        )
        .unwrap();
        let issuing_key = p.generate_signing_key().unwrap();
        let issuing = cert::issue(
            p,
            root_key.as_ref(),
            &CertFields {
                serial: cert::random_serial(p).unwrap(),
                role: role::ISSUING,
                subject_a: "test issuing".into(),
                subject_b: String::new(),
                not_before: NOW - DAY,
                not_after: NOW + 365 * DAY,
                sign_public: issuing_key.public_key().clone(),
                issuer_key_id: cert::key_id(p, &encoded(root_key.as_ref())),
            },
        )
        .unwrap();
        Pki {
            provider,
            root_key,
            root,
            issuing_key,
            issuing,
        }
    }

    pub fn roots(&self) -> Vec<Certificate> {
        cert::parse_many(self.provider.as_ref(), &self.root).unwrap()
    }

    pub fn leaf(&self, role_value: u8, a: &str, b: &str, key: &dyn SigningKey) -> Vec<u8> {
        self.leaf_times(role_value, a, b, key, NOW - DAY, NOW + 30 * DAY)
    }

    pub fn leaf_times(
        &self,
        role_value: u8,
        a: &str,
        b: &str,
        key: &dyn SigningKey,
        not_before: u64,
        not_after: u64,
    ) -> Vec<u8> {
        let p = self.provider.as_ref();
        let mut chain = cert::issue(
            p,
            self.issuing_key.as_ref(),
            &CertFields {
                serial: cert::random_serial(p).unwrap(),
                role: role_value,
                subject_a: a.into(),
                subject_b: b.into(),
                not_before,
                not_after,
                sign_public: key.public_key().clone(),
                issuer_key_id: cert::key_id(p, &encoded(self.issuing_key.as_ref())),
            },
        )
        .unwrap();
        chain.extend_from_slice(&self.issuing);
        chain
    }
}

pub struct Endpoint {
    pub identity: Arc<dyn SigningKey>,
    pub chain: Vec<u8>,
}

impl Pki {
    pub fn device(&self, user: &str, device: &str) -> Endpoint {
        let key = self.provider.generate_signing_key().unwrap();
        let chain = self.leaf(role::DEVICE, user, device, key.as_ref());
        Endpoint {
            identity: Arc::from(key),
            chain,
        }
    }

    pub fn server(&self, host: &str) -> Endpoint {
        let key = self.provider.generate_signing_key().unwrap();
        let chain = self.leaf(role::SERVER, host, "instance-1", key.as_ref());
        Endpoint {
            identity: Arc::from(key),
            chain,
        }
    }

    pub fn config(
        &self,
        role: Role,
        plane: Plane,
        transport: TransportCaps,
        me: &Endpoint,
        expectation: PeerExpectation,
    ) -> SessionConfig {
        SessionConfig {
            provider: self.provider.clone(),
            role,
            plane,
            transport,
            identity: me.identity.clone(),
            chain: me.chain.clone(),
            roots: self.roots(),
            expectation,
            verifier: Box::new(UncheckedPeers),
            versions: SessionConfig::default_versions(),
            suites: self.provider.suites().to_vec(),
            cached_peer_chain: None,
            rendezvous_id: if plane == Plane::Data {
                Some([9; 16])
            } else {
                None
            },
            limits: Limits::default(),
        }
    }

    /// Data-plane configs for alice (I) and bob (R).
    pub fn data_pair(&self, transport: TransportCaps) -> (SessionConfig, SessionConfig) {
        let alice = self.device("alice", "a1");
        let bob = self.device("bob", "b1");
        (
            self.config(
                Role::Initiator,
                Plane::Data,
                transport,
                &alice,
                PeerExpectation::Peer {
                    user_id: "bob".into(),
                    device_id: Some("b1".into()),
                },
            ),
            self.config(
                Role::Responder,
                Plane::Data,
                transport,
                &bob,
                PeerExpectation::Peer {
                    user_id: "alice".into(),
                    device_id: Some("a1".into()),
                },
            ),
        )
    }
}

/// Decides what happens to each frame on the simulated network.
pub type Fate = Box<dyn FnMut(&[u8]) -> FrameFate>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameFate {
    Deliver,
    Drop,
    Duplicate,
    /// Hold this frame until after the next one.
    Delay,
}

/// Two sessions joined by a controllable network, with a simulated clock.
pub struct Link {
    pub a: Session,
    pub b: Session,
    pub now: u64,
    pub a_events: Vec<Event>,
    pub b_events: Vec<Event>,
    pub to_a: VecDeque<Vec<u8>>,
    pub to_b: VecDeque<Vec<u8>>,
    pub fate: Fate,
    held_a: Vec<Vec<u8>>,
    held_b: Vec<Vec<u8>>,
    pub frames_a_to_b: Vec<Vec<u8>>,
    pub frames_b_to_a: Vec<Vec<u8>>,
}

impl Link {
    pub fn new(a: SessionConfig, b: SessionConfig) -> Self {
        Link {
            a: Session::new(a, NOW).unwrap(),
            b: Session::new(b, NOW).unwrap(),
            now: NOW,
            a_events: Vec::new(),
            b_events: Vec::new(),
            to_a: VecDeque::new(),
            to_b: VecDeque::new(),
            fate: Box::new(|_| FrameFate::Deliver),
            held_a: Vec::new(),
            held_b: Vec::new(),
            frames_a_to_b: Vec::new(),
            frames_b_to_a: Vec::new(),
        }
    }

    fn route(
        frame: Vec<u8>,
        fate: &mut Fate,
        queue: &mut VecDeque<Vec<u8>>,
        held: &mut Vec<Vec<u8>>,
    ) {
        match fate(&frame) {
            FrameFate::Deliver => {
                queue.push_back(frame);
                queue.extend(held.drain(..));
            }
            FrameFate::Drop => {}
            FrameFate::Duplicate => {
                queue.push_back(frame.clone());
                queue.push_back(frame);
                queue.extend(held.drain(..));
            }
            FrameFate::Delay => held.push(frame),
        }
    }

    /// Runs until nothing more moves without the clock advancing.
    pub fn pump(&mut self) {
        loop {
            let mut moved = false;
            while let Some(frame) = self.a.poll_transmit() {
                self.frames_a_to_b.push(frame.clone());
                Self::route(frame, &mut self.fate, &mut self.to_b, &mut self.held_b);
                moved = true;
            }
            while let Some(frame) = self.b.poll_transmit() {
                self.frames_b_to_a.push(frame.clone());
                Self::route(frame, &mut self.fate, &mut self.to_a, &mut self.held_a);
                moved = true;
            }
            while let Some(frame) = self.to_b.pop_front() {
                self.b.handle_frame(self.now, &frame);
                moved = true;
            }
            while let Some(frame) = self.to_a.pop_front() {
                self.a.handle_frame(self.now, &frame);
                moved = true;
            }
            while let Some(event) = self.a.poll_event() {
                self.a_events.push(event);
                moved = true;
            }
            while let Some(event) = self.b.poll_event() {
                self.b_events.push(event);
                moved = true;
            }
            if !moved {
                return;
            }
        }
    }

    /// Advances the clock by `ms`, driving timers as they come due.
    pub fn advance(&mut self, ms: u64) {
        let end = self.now + ms;
        loop {
            self.pump();
            let next = [self.a.next_timeout(), self.b.next_timeout()]
                .into_iter()
                .flatten()
                .min();
            let Some(due) = next.filter(|t| *t <= end) else {
                break;
            };
            self.now = self.now.max(due);
            self.a.handle_timeout(self.now);
            self.b.handle_timeout(self.now);
            self.pump();
            // A timer still due after being handled would spin a host's event loop.
            for session in [&self.a, &self.b] {
                if let Some(t) = session.next_timeout() {
                    assert!(t > self.now, "a timer stayed due: {t} at {}", self.now);
                }
            }
        }
        self.now = end;
        self.a.handle_timeout(self.now);
        self.b.handle_timeout(self.now);
        self.pump();
    }

    pub fn messages_at_a(&self) -> Vec<(u16, Vec<u8>)> {
        collect_messages(&self.a_events)
    }

    pub fn messages_at_b(&self) -> Vec<(u16, Vec<u8>)> {
        collect_messages(&self.b_events)
    }
}

fn collect_messages(events: &[Event]) -> Vec<(u16, Vec<u8>)> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Message {
                channel_id,
                payload,
            } => Some((*channel_id, payload.clone())),
            _ => None,
        })
        .collect()
}

/// Opens a channel from a to b, accepting it on b's side, and returns its id.
pub fn open_channel(link: &mut Link, ordered: bool, reliable: bool) -> u16 {
    let id = link
        .a
        .open_channel(
            link.now,
            qalqon_core::ChannelOptions {
                ordered,
                reliable,
                label: "test".into(),
            },
        )
        .unwrap();
    link.pump();
    assert!(
        link.b_events
            .iter()
            .any(|e| matches!(e, Event::ChannelRequested { channel_id, .. } if *channel_id == id)),
        "channel request did not arrive: {:?}",
        link.b_events
    );
    link.b.accept_channel(link.now, id).unwrap();
    link.pump();
    assert!(
        link.a_events
            .iter()
            .any(|e| matches!(e, Event::ChannelOpened { channel_id } if *channel_id == id)),
        "channel did not open: {:?}",
        link.a_events
    );
    id
}

pub fn established(link: &Link) -> bool {
    let is = |events: &[Event]| {
        events
            .iter()
            .any(|e| matches!(e, Event::Established { .. }))
    };
    is(&link.a_events) && is(&link.b_events)
}

/// A shared pin table behind the verifier trait, as the SDK will use it.
#[derive(Clone, Default)]
pub struct PinVerifier {
    pub table: Arc<Mutex<qalqon_core::pins::PinTable>>,
    pub warn: bool,
}

impl PeerVerifier for PinVerifier {
    fn check_revocation(
        &mut self,
        _: &qalqon_core::cert::ValidatedChain,
        _: u64,
    ) -> Result<(), PeerRejection> {
        Ok(())
    }

    fn check_pin(
        &mut self,
        chain: &qalqon_core::cert::ValidatedChain,
        _: u64,
    ) -> Result<PinStatus, PeerRejection> {
        use qalqon_core::pins::PinDecision;
        let fields = &chain.leaf.fields;
        let mut table = self.table.lock().unwrap();
        match table.decide(&fields.subject_a, &fields.subject_b, &chain.fingerprint) {
            PinDecision::FirstContact => {
                table.commit(&fields.subject_a, &fields.subject_b, &chain.fingerprint);
                Ok(PinStatus::Pinned)
            }
            PinDecision::Match { verified: true } => Ok(PinStatus::Verified),
            PinDecision::Match { verified: false } => Ok(PinStatus::Pinned),
            PinDecision::Changed if self.warn => Ok(PinStatus::Changed),
            PinDecision::Changed => Err(PeerRejection::IdentityChanged),
        }
    }
}
