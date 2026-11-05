//! A responder and an initiator fed attacker-controlled frames at every stage.
#![no_main]

use libfuzzer_sys::fuzz_target;
use provider_testonly::TestOnlyProvider;
use qalqon_core::cert::{self, CertFields, role};
use qalqon_core::crypto::{CryptoProvider, SigningKey};
use qalqon_core::session::{Limits, Plane, Role, SessionConfig, TransportCaps};
use qalqon_core::{PeerExpectation, Session, UncheckedPeers};
use std::sync::{Arc, OnceLock};

const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 86_400_000;

struct Fixture {
    provider: Arc<dyn CryptoProvider>,
    root: Vec<u8>,
    key: Arc<dyn SigningKey>,
    chain: Vec<u8>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let provider: Arc<dyn CryptoProvider> = Arc::new(TestOnlyProvider::seeded(b"fuzz"));
        let p = provider.as_ref();
        let root_key = p.generate_signing_key().unwrap();
        let encoded = cert::encode_public_key(root_key.public_key()).unwrap();
        let id = cert::key_id(p, &encoded);
        let fields = |role_value: u8, a: &str, b: &str, key: &dyn SigningKey, issuer| CertFields {
            serial: [role_value; 16],
            role: role_value,
            subject_a: a.into(),
            subject_b: b.into(),
            not_before: NOW - DAY,
            not_after: NOW + DAY,
            sign_public: key.public_key().clone(),
            issuer_key_id: issuer,
        };
        let root = cert::issue(p, root_key.as_ref(), &fields(role::ROOT, "root", "", root_key.as_ref(), id)).unwrap();
        let issuing_key = p.generate_signing_key().unwrap();
        let issuing = cert::issue(p, root_key.as_ref(), &fields(role::ISSUING, "issuing", "", issuing_key.as_ref(), id)).unwrap();
        let issuing_id = cert::key_id(p, &cert::encode_public_key(issuing_key.public_key()).unwrap());
        let key = p.generate_signing_key().unwrap();
        let mut chain = cert::issue(p, issuing_key.as_ref(), &fields(role::DEVICE, "a", "b", key.as_ref(), issuing_id)).unwrap();
        chain.extend_from_slice(&issuing);
        Fixture { provider, root, key: Arc::from(key), chain }
    })
}

fn session(role: Role, transport: TransportCaps) -> Session {
    let f = fixture();
    Session::new(
        SessionConfig {
            provider: f.provider.clone(),
            role,
            plane: Plane::Data,
            transport,
            identity: f.key.clone(),
            chain: f.chain.clone(),
            roots: cert::parse_many(f.provider.as_ref(), &f.root).unwrap(),
            expectation: PeerExpectation::Peer { user_id: "a".into(), device_id: None },
            verifier: Box::new(UncheckedPeers),
            versions: SessionConfig::default_versions(),
            suites: f.provider.suites().to_vec(),
            cached_peer_chain: None,
            rendezvous_id: Some([0; 16]),
            limits: Limits::default(),
        },
        NOW,
    )
    .unwrap()
}

fuzz_target!(|data: &[u8]| {
    // The first byte picks the stage and the transport, and the rest splits into frames.
    let Some((&selector, rest)) = data.split_first() else { return };
    let transport = if selector & 1 == 0 { TransportCaps::STREAM } else { TransportCaps::DATAGRAM };
    let mut i = session(Role::Initiator, transport);
    let mut r = session(Role::Responder, transport);
    if selector & 2 != 0 {
        for _ in 0..4 {
            while let Some(f) = i.poll_transmit() {
                r.handle_frame(NOW, &f);
            }
            while let Some(f) = r.poll_transmit() {
                i.handle_frame(NOW, &f);
            }
        }
    }
    let mut now = NOW;
    for chunk in rest.chunks(256) {
        now += 100;
        i.handle_frame(now, chunk);
        r.handle_frame(now, chunk);
        i.handle_timeout(now);
        r.handle_timeout(now);
        while i.poll_transmit().is_some() {}
        while r.poll_transmit().is_some() {}
        while i.poll_event().is_some() {}
        while r.poll_event().is_some() {}
    }
});
