//! The shared conformance vectors from `docs/PROTOCOL.md`, section 16.
//!
//! These files are produced with the test-only provider and live in
//! `tests/conformance/testonly`, apart from any official vectors (ADR-0002, part 2).
//! Every value in them comes from the code, so they catch changes and disagreements
//! between runtimes, not misreadings of the specification. That is the job of
//! `core/qalqon-core/tests/spec_conformance.rs`.
//!
//! A binding proves itself by passing a vector file to [`run_file`] through its own
//! FFI, WebAssembly or sidecar path, inside its own runtime.
#![forbid(unsafe_code)]

use crypto_provider::suite::{SUITE_TESTONLY_X25519, SUITE_TESTONLY_X25519_ML_KEM_768};
use crypto_provider::{CryptoProvider, from_hex, secret, to_hex};
use provider_testonly::TestOnlyProvider;
use qalqon_audit::{AuditChain, AuditEvent};
use qalqon_core::cert::{self, CertFields, role};
use qalqon_core::record::RecordLayer;
use qalqon_core::schedule::{derive_secret, expand_label, record_nonce, traffic_keys};
use qalqon_core::session::{Limits, Plane, Role, SessionConfig, TransportCaps};
use qalqon_core::wire::{self, VERSION_0_1};
use qalqon_core::{Event, PeerExpectation, Session, UncheckedPeers};
use serde_json::{Value, json};
use std::sync::Arc;

const NOW: u64 = 1_800_000_000_000;
const DAY: u64 = 86_400_000;

fn hex(value: &Value) -> Vec<u8> {
    value.as_str().and_then(from_hex).unwrap_or_default()
}

/// One file's outcome.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// How many vectors passed.
    pub passed: u32,
    /// A description of each failure.
    pub failed: Vec<String>,
}

impl Report {
    fn check(&mut self, name: &str, ok: bool) {
        if ok {
            self.passed += 1;
        } else {
            self.failed.push(name.to_string());
        }
    }
}

/// Every vector file, by name.
pub fn generate() -> Vec<(&'static str, Value)> {
    vec![
        ("kdf.json", generate_kdf()),
        ("handshake.json", generate_handshakes()),
        ("records.json", generate_records()),
        ("negative.json", generate_negative()),
        ("safety.json", generate_safety()),
        ("audit.json", generate_audit()),
    ]
}

/// Checks one vector file.
pub fn run_file(text: &str) -> Report {
    let mut report = Report::default();
    let Ok(file) = serde_json::from_str::<Value>(text) else {
        report.failed.push("the file is not JSON".into());
        return report;
    };
    let Some(vectors) = file["vectors"].as_array() else {
        report.failed.push("the file has no vectors".into());
        return report;
    };
    for vector in vectors {
        let name = vector["name"].as_str().unwrap_or("unnamed").to_string();
        let ok = match file["kind"].as_str() {
            Some("kdf") => check_kdf(vector),
            Some("handshake") => check_handshake(vector),
            Some("records") => check_records(vector),
            Some("negative") => check_negative(vector),
            Some("safety") => check_safety(vector),
            Some("audit") => check_audit(vector),
            _ => false,
        };
        report.check(&name, ok);
    }
    report
}

// ------------------------------------------------------------------------- KDF

fn generate_kdf() -> Value {
    let p = TestOnlyProvider::seeded(b"kdf");
    let mut vectors = Vec::new();
    for (i, (label, context, length)) in [
        ("key", vec![], 32usize),
        ("iv", vec![], 12),
        ("session id", vec![0xAB; 32], 16),
        ("safety", vec![], 60),
    ]
    .into_iter()
    .enumerate()
    {
        let mut secret_bytes = [0u8; 32];
        p.random(&mut secret_bytes).ok();
        let output = expand_label(&p, &secret_bytes, label, &context, length)
            .map(|s| s.to_vec())
            .unwrap_or_default();
        vectors.push(json!({
            "name": format!("expand_label {i}: {label}"),
            "op": "expand_label",
            "secret": to_hex(&secret_bytes),
            "label": label,
            "context": to_hex(&context),
            "length": length,
            "output": to_hex(&output),
        }));
    }
    let mut secret_bytes = [0u8; 32];
    p.random(&mut secret_bytes).ok();
    let transcript = b"a transcript".to_vec();
    let derived = derive_secret(&p, &secret_bytes, "i hs", &transcript)
        .map(|s| s.to_vec())
        .unwrap_or_default();
    vectors.push(json!({
        "name": "derive_secret",
        "op": "derive_secret",
        "secret": to_hex(&secret_bytes),
        "label": "i hs",
        "transcript": to_hex(&transcript),
        "output": to_hex(&derived),
    }));
    vectors.push(json!({
        "name": "record_nonce",
        "op": "record_nonce",
        "iv": "101112131415161718191a1b",
        "direction": 1,
        "seq": "0001000000000005",
        "output": to_hex(&record_nonce(&from_hex("101112131415161718191a1b").unwrap_or_default(), 1, 0x0001_0000_0000_0005)),
    }));
    json!({ "kind": "kdf", "provider": "testonly", "vectors": vectors })
}

fn check_kdf(v: &Value) -> bool {
    let p = TestOnlyProvider::new();
    let output = hex(&v["output"]);
    match v["op"].as_str() {
        Some("expand_label") => expand_label(
            &p,
            &hex(&v["secret"]),
            v["label"].as_str().unwrap_or(""),
            &hex(&v["context"]),
            v["length"].as_u64().unwrap_or(0) as usize,
        )
        .is_ok_and(|s| s.as_slice() == output),
        Some("derive_secret") => derive_secret(
            &p,
            &hex(&v["secret"]),
            v["label"].as_str().unwrap_or(""),
            &hex(&v["transcript"]),
        )
        .is_ok_and(|s| s.as_slice() == output),
        Some("record_nonce") => {
            let seq = u64::from_str_radix(v["seq"].as_str().unwrap_or("0"), 16).unwrap_or(0);
            record_nonce(
                &hex(&v["iv"]),
                v["direction"].as_u64().unwrap_or(0) as u8,
                seq,
            ) == output
        }
        _ => false,
    }
}

// ------------------------------------------------------------------- handshakes

/// A deterministic hierarchy and two endpoints, all drawn from one seeded provider.
struct Fixture {
    provider: Arc<dyn CryptoProvider>,
    root: Vec<u8>,
    alice_key: Arc<dyn crypto_provider::SigningKey>,
    alice_chain: Vec<u8>,
    bob_key: Arc<dyn crypto_provider::SigningKey>,
    bob_chain: Vec<u8>,
}

fn fixture(seed: &str) -> Fixture {
    let provider: Arc<dyn CryptoProvider> = Arc::new(TestOnlyProvider::seeded(seed.as_bytes()));
    let p = provider.as_ref();
    let root_key = p.generate_signing_key().expect("seeded key");
    let issuing_key = p.generate_signing_key().expect("seeded key");
    let encoded = |k: &dyn crypto_provider::SigningKey| {
        cert::encode_public_key(k.public_key()).expect("encodes")
    };
    let root_id = cert::key_id(p, &encoded(root_key.as_ref()));
    let issuing_id = cert::key_id(p, &encoded(issuing_key.as_ref()));
    let certificate = |signer: &dyn crypto_provider::SigningKey, fields: CertFields| {
        cert::issue(p, signer, &fields).expect("issues")
    };
    let root = certificate(
        root_key.as_ref(),
        CertFields {
            serial: [1; 16],
            role: role::ROOT,
            subject_a: "root".into(),
            subject_b: String::new(),
            not_before: NOW - DAY,
            not_after: NOW + 3650 * DAY,
            sign_public: root_key.public_key().clone(),
            issuer_key_id: root_id,
        },
    );
    let issuing = certificate(
        root_key.as_ref(),
        CertFields {
            serial: [2; 16],
            role: role::ISSUING,
            subject_a: "issuing".into(),
            subject_b: String::new(),
            not_before: NOW - DAY,
            not_after: NOW + 365 * DAY,
            sign_public: issuing_key.public_key().clone(),
            issuer_key_id: root_id,
        },
    );
    let device = |user: &str, device: &str, serial: u8| {
        let key = p.generate_signing_key().expect("seeded key");
        let mut chain = certificate(
            issuing_key.as_ref(),
            CertFields {
                serial: [serial; 16],
                role: role::DEVICE,
                subject_a: user.into(),
                subject_b: device.into(),
                not_before: NOW - DAY,
                not_after: NOW + 30 * DAY,
                sign_public: key.public_key().clone(),
                issuer_key_id: issuing_id,
            },
        );
        chain.extend_from_slice(&issuing);
        (Arc::<dyn crypto_provider::SigningKey>::from(key), chain)
    };
    let (alice_key, alice_chain) = device("alice", "a1", 3);
    let (bob_key, bob_chain) = device("bob", "b1", 4);
    Fixture {
        provider,
        root,
        alice_key,
        alice_chain,
        bob_key,
        bob_chain,
    }
}

fn session_config(
    f: &Fixture,
    initiator: bool,
    transport: TransportCaps,
    suite: u16,
    cached: Option<Vec<u8>>,
) -> SessionConfig {
    let roots = cert::parse_many(f.provider.as_ref(), &f.root).expect("the fixture's root parses");
    SessionConfig {
        provider: f.provider.clone(),
        role: if initiator {
            Role::Initiator
        } else {
            Role::Responder
        },
        plane: Plane::Data,
        transport,
        identity: if initiator {
            f.alice_key.clone()
        } else {
            f.bob_key.clone()
        },
        chain: if initiator {
            f.alice_chain.clone()
        } else {
            f.bob_chain.clone()
        },
        roots,
        expectation: PeerExpectation::Peer {
            user_id: if initiator {
                "bob".into()
            } else {
                "alice".into()
            },
            device_id: None,
        },
        verifier: Box::new(UncheckedPeers),
        versions: SessionConfig::default_versions(),
        suites: vec![suite],
        cached_peer_chain: cached,
        rendezvous_id: Some([0x5A; 16]),
        limits: Limits::default(),
    }
}

/// `(frames in order with their sender, session id)`.
type HandshakeRun = (Vec<(String, Vec<u8>)>, Option<[u8; 16]>);

/// Runs one handshake to completion.
fn run_handshake(seed: &str, strict: bool, suite: u16, known: bool) -> HandshakeRun {
    let f = fixture(seed);
    let transport = if strict {
        TransportCaps::STREAM
    } else {
        TransportCaps::DATAGRAM
    };
    let cached = known.then(|| f.bob_chain.clone());
    let mut i =
        Session::new(session_config(&f, true, transport, suite, cached), NOW).expect("session");
    let mut r =
        Session::new(session_config(&f, false, transport, suite, None), NOW).expect("session");
    let mut frames = Vec::new();
    for _ in 0..8 {
        let mut moved = false;
        while let Some(frame) = i.poll_transmit() {
            r.handle_frame(NOW, &frame);
            frames.push(("i".to_string(), frame));
            moved = true;
        }
        while let Some(frame) = r.poll_transmit() {
            i.handle_frame(NOW, &frame);
            frames.push(("r".to_string(), frame));
            moved = true;
        }
        if !moved {
            break;
        }
    }
    let session_id = match (i.session_id(), r.session_id()) {
        (Some(a), Some(b)) if a == b => Some(a),
        _ => None,
    };
    (frames, session_id)
}

fn handshake_cases() -> Vec<(&'static str, &'static str, bool, u16, bool)> {
    vec![
        ("strict, X25519", "hs-1", true, SUITE_TESTONLY_X25519, false),
        (
            "lossy with padding, X25519",
            "hs-2",
            false,
            SUITE_TESTONLY_X25519,
            false,
        ),
        (
            "strict, X25519 + ML-KEM-768",
            "hs-3",
            true,
            SUITE_TESTONLY_X25519_ML_KEM_768,
            false,
        ),
        (
            "lossy with fragments, X25519 + ML-KEM-768",
            "hs-4",
            false,
            SUITE_TESTONLY_X25519_ML_KEM_768,
            false,
        ),
        (
            "strict, known_responder omits the chain",
            "hs-5",
            true,
            SUITE_TESTONLY_X25519,
            true,
        ),
    ]
}

fn generate_handshakes() -> Value {
    let vectors: Vec<Value> = handshake_cases()
        .into_iter()
        .map(|(name, seed, strict, suite, known)| {
            let (frames, session_id) = run_handshake(seed, strict, suite, known);
            json!({
                "name": name,
                "seed": seed,
                "strict": strict,
                "suite": suite,
                "known_responder": known,
                "frames": frames.iter().map(|(from, f)| json!({ "from": from, "bytes": to_hex(f) })).collect::<Vec<_>>(),
                "session_id": session_id.map(|id| to_hex(&id)),
            })
        })
        .collect();
    json!({ "kind": "handshake", "provider": "testonly", "vectors": vectors })
}

fn check_handshake(v: &Value) -> bool {
    let (frames, session_id) = run_handshake(
        v["seed"].as_str().unwrap_or(""),
        v["strict"].as_bool().unwrap_or(false),
        v["suite"].as_u64().unwrap_or(0) as u16,
        v["known_responder"].as_bool().unwrap_or(false),
    );
    let Some(expected) = v["frames"].as_array() else {
        return false;
    };
    frames.len() == expected.len()
        && frames.iter().zip(expected).all(|((from, bytes), e)| {
            e["from"].as_str() == Some(from.as_str()) && hex(&e["bytes"]) == *bytes
        })
        && session_id.map(|id| to_hex(&id)).as_deref() == v["session_id"].as_str()
}

// ---------------------------------------------------------------------- records

fn record_layer(
    p: Arc<dyn CryptoProvider>,
    strict: bool,
    initiator: bool,
    i_ap: &[u8],
    r_ap: &[u8],
) -> Option<RecordLayer> {
    RecordLayer::new(
        p,
        VERSION_0_1,
        SUITE_TESTONLY_X25519,
        strict,
        initiator,
        secret(i_ap),
        secret(r_ap),
        Limits::default(),
        NOW,
    )
    .ok()
}

fn generate_records() -> Value {
    let provider: Arc<dyn CryptoProvider> = Arc::new(TestOnlyProvider::seeded(b"records"));
    let (mut i_ap, mut r_ap) = ([0u8; 32], [0u8; 32]);
    provider.random(&mut i_ap).ok();
    provider.random(&mut r_ap).ok();
    let mut vectors = Vec::new();
    for strict in [true, false] {
        let Some(mut sender) = record_layer(provider.clone(), strict, true, &i_ap, &r_ap) else {
            continue;
        };
        let keys = traffic_keys(provider.as_ref(), &i_ap);
        let mut frames = Vec::new();
        for (channel, plain) in [
            (0u16, vec![0x08u8; 9]),
            (1, vec![0x01, 0, 0, 0, 0, 0, 0, 1, b'h', b'i']),
            (1, vec![0x01; 40]),
        ] {
            if let Ok(frame) = sender.seal(channel, &plain) {
                frames.push(json!({ "channel": channel, "plaintext": to_hex(&plain), "frame": to_hex(&frame) }));
            }
        }
        // The epoch advances, and the counter does not restart.
        if sender.rotate_send(NOW).is_ok()
            && let Ok(frame) = sender.seal(1, &[0x01, 9])
        {
            frames.push(
                json!({ "channel": 1, "plaintext": "0109", "frame": to_hex(&frame), "epoch": 1 }),
            );
        }
        vectors.push(json!({
            "name": if strict { "seal and open, strict" } else { "seal and open, lossy" },
            "strict": strict,
            "i_ap": to_hex(&i_ap),
            "r_ap": to_hex(&r_ap),
            "keys_derive": keys.is_ok(),
            "frames": frames,
        }));
    }
    json!({ "kind": "records", "provider": "testonly", "vectors": vectors })
}

fn check_records(v: &Value) -> bool {
    let provider: Arc<dyn CryptoProvider> = Arc::new(TestOnlyProvider::new());
    let strict = v["strict"].as_bool().unwrap_or(true);
    let (i_ap, r_ap) = (hex(&v["i_ap"]), hex(&v["r_ap"]));
    let (Some(mut sender), Some(mut receiver)) = (
        record_layer(provider.clone(), strict, true, &i_ap, &r_ap),
        record_layer(provider.clone(), strict, false, &i_ap, &r_ap),
    ) else {
        return false;
    };
    let Some(frames) = v["frames"].as_array() else {
        return false;
    };
    for frame in frames {
        let (plain, bytes) = (hex(&frame["plaintext"]), hex(&frame["frame"]));
        if frame["epoch"].as_u64() == Some(1) {
            if sender.rotate_send(NOW).is_err() {
                return false;
            }
            // A strict receiver moves when it opens KEY_UPDATE. This vector moves it directly.
            if strict && receiver.advance_recv(NOW).is_err() {
                return false;
            }
        }
        // Sealing reproduces the bytes, which pins the nonce, tag and header layout.
        if sender
            .seal(frame["channel"].as_u64().unwrap_or(0) as u16, &plain)
            .ok()
            .as_deref()
            != Some(bytes.as_slice())
        {
            return false;
        }
        let Ok((header, _)) = wire::parse_frame(&bytes) else {
            return false;
        };
        match receiver.open(&header, &bytes, NOW) {
            Ok(opened) if opened.plaintext.as_slice() == plain => {}
            _ => return false,
        }
        // The same record again is always refused.
        if receiver.open(&header, &bytes, NOW).is_ok() {
            return false;
        }
    }
    true
}

// --------------------------------------------------------------------- negative

/// Every frame here must leave a fresh responder unestablished and silent or closed.
fn generate_negative() -> Value {
    let (frames, _) = run_handshake("neg", true, SUITE_TESTONLY_X25519, false);
    let init = frames[0].1.clone();
    let resp = frames[1].1.clone();
    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
    let mut with = |name: &str, change: &dyn Fn(&mut Vec<u8>)| {
        let mut frame = init.clone();
        change(&mut frame);
        cases.push((name.to_string(), frame));
    };
    with("wrong magic", &|f| f[0] ^= 0xFF);
    with("unknown message type", &|f| f[5] = 0x7E);
    with("trailing byte after length", &|f| f.push(0));
    with("truncated body", &|f| {
        f.pop();
    });
    with("nonzero seq in a handshake message", &|f| f[15] = 1);
    with("nonzero channel in a handshake message", &|f| f[7] = 1);
    with("a suite selected in XX_INIT", &|f| f[4] = 1);
    with("a header version not in the offer", &|f| f[2] = 0x7F);
    cases.push(("XX_RESP sent to a responder".to_string(), resp));
    cases.push(("empty frame".to_string(), Vec::new()));
    cases.push(("one byte".to_string(), vec![0x51]));
    let vectors: Vec<Value> = cases
        .into_iter()
        .map(|(name, frame)| json!({ "name": name, "frame": to_hex(&frame) }))
        .collect();
    json!({ "kind": "negative", "provider": "testonly", "vectors": vectors })
}

fn check_negative(v: &Value) -> bool {
    let f = fixture("neg");
    let Ok(mut r) = Session::new(
        session_config(
            &f,
            false,
            TransportCaps::STREAM,
            SUITE_TESTONLY_X25519,
            None,
        ),
        NOW,
    ) else {
        return false;
    };
    r.handle_frame(NOW, &hex(&v["frame"]));
    let mut failed = false;
    while let Some(event) = r.poll_event() {
        match event {
            Event::Established { .. } => return false,
            Event::HandshakeFailed(_) => failed = true,
            _ => {}
        }
    }
    failed && r.is_closed() && r.poll_transmit().is_none()
}

// ----------------------------------------------------------------- safety, audit

fn generate_safety() -> Value {
    let p = TestOnlyProvider::seeded(b"safety");
    let mut vectors = Vec::new();
    for n in 0..3 {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        p.random(&mut a).ok();
        p.random(&mut b).ok();
        let number = qalqon_core::pins::safety_number(&p, &a, &b).unwrap_or_default();
        vectors.push(json!({ "name": format!("safety number {n}"), "a": to_hex(&a), "b": to_hex(&b), "number": number }));
    }
    json!({ "kind": "safety", "provider": "testonly", "vectors": vectors })
}

fn check_safety(v: &Value) -> bool {
    let p = TestOnlyProvider::new();
    let (a, b) = (hex(&v["a"]), hex(&v["b"]));
    let expected = v["number"].as_str().unwrap_or("x");
    qalqon_core::pins::safety_number(&p, &a, &b).is_ok_and(|n| n == expected)
        && qalqon_core::pins::safety_number(&p, &b, &a).is_ok_and(|n| n == expected)
}

fn audit_events() -> Vec<AuditEvent> {
    (0..4u64)
        .map(|n| AuditEvent {
            at: NOW + n,
            subject: format!("subject-{n}"),
            object: format!("object-{n}"),
            operation: "access".into(),
            result: if n % 2 == 0 {
                "ok".into()
            } else {
                "accessDenied".into()
            },
            detail: "ünïcode détail".into(),
        })
        .collect()
}

fn generate_audit() -> Value {
    let p = TestOnlyProvider::new();
    let mut chain = AuditChain::new(&p, b"vector fingerprint");
    let hashes: Vec<String> = audit_events()
        .into_iter()
        .map(|e| chain.append(&p, e).entry_hash)
        .collect();
    json!({
        "kind": "audit",
        "provider": "testonly",
        "vectors": [ { "name": "hash chain", "fingerprint": to_hex(b"vector fingerprint"), "entry_hashes": hashes } ],
    })
}

fn check_audit(v: &Value) -> bool {
    let p = TestOnlyProvider::new();
    let mut chain = AuditChain::new(&p, &hex(&v["fingerprint"]));
    let Some(expected) = v["entry_hashes"].as_array() else {
        return false;
    };
    let events = audit_events();
    events.len() == expected.len()
        && events
            .into_iter()
            .zip(expected)
            .all(|(e, h)| h.as_str() == Some(chain.append(&p, e).entry_hash.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_generated_file_passes_and_generation_is_deterministic() {
        let first = generate();
        let second = generate();
        for ((name, a), (_, b)) in first.iter().zip(&second) {
            assert_eq!(a, b, "{name} is not deterministic");
            let report = run_file(&serde_json::to_string(a).unwrap());
            assert!(report.failed.is_empty(), "{name}: {:?}", report.failed);
            assert!(report.passed > 0, "{name} has no vectors");
        }
    }

    #[test]
    fn a_changed_vector_fails() {
        let (_, value) = generate().remove(1);
        let mut value = value;
        let frame = value["vectors"][0]["frames"][1]["bytes"]
            .as_str()
            .unwrap()
            .to_string();
        let flipped = format!(
            "{}{}",
            if frame.starts_with('0') { "1" } else { "0" },
            &frame[1..]
        );
        value["vectors"][0]["frames"][1]["bytes"] = json!(flipped);
        assert!(!run_file(&value.to_string()).failed.is_empty());
    }
}
