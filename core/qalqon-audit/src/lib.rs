//! The audit chain: `docs/PROTOCOL.md`, section 14, with the event list from build
//! prompt §1.6.
//!
//! ```text
//! entry_0 = H(ctx("audit genesis") || fingerprint)
//! entry_n = H(ctx("audit") || entry_(n-1) || canonical(event_n))
//! ```
//!
//! An endpoint periodically signs a checkpoint over `n` and `entry_n`, so a chain cut
//! short after the last checkpoint is detected by comparing it with the checkpoint.
#![forbid(unsafe_code)]

use crypto_provider::{CryptoError, CryptoProvider, PublicKey, SigningKey, from_hex, to_hex};
use qalqon_core::schedule::ctx;
use serde::{Deserialize, Serialize};
use std::fmt;

/// The operations §1.6 requires to be logged.
pub mod operation {
    #![allow(missing_docs)]
    pub const LOGIN: &str = "login";
    pub const LOGOUT: &str = "logout";
    pub const SESSION_ESTABLISHED: &str = "session.established";
    pub const SESSION_TEARDOWN: &str = "session.teardown";
    pub const KEY_ROTATED: &str = "key.rotated";
    pub const KEY_GENERATED: &str = "key.generated";
    pub const KEY_USED: &str = "key.used";
    pub const ACCESS: &str = "access";
    pub const SERVER_START: &str = "server.start";
    pub const SERVER_STOP: &str = "server.stop";
    pub const PRIVILEGE_CHANGE: &str = "privilege.change";
    pub const ENROLLMENT: &str = "device.enroll";
    pub const REVOCATION: &str = "device.revoke";
    pub const RENDEZVOUS: &str = "rendezvous";
    pub const PIN_CHANGED: &str = "pin.changed";
    pub const ALARM: &str = "alarm";
}

/// One audited event: subject, object, operation and result, as §1.6 lists them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When it happened, in milliseconds since the Unix epoch.
    pub at: u64,
    /// Who acted.
    pub subject: String,
    /// What was acted on.
    pub object: String,
    /// What was attempted. See [`operation`].
    pub operation: String,
    /// `ok`, or the IDL name of the error.
    pub result: String,
    /// Further detail. Never contains a secret.
    pub detail: String,
}

/// An event in its place in the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// `n`, starting at 1.
    pub seq: u64,
    /// The event.
    #[serde(flatten)]
    pub event: AuditEvent,
    /// `entry_n`, in hex.
    pub entry_hash: String,
}

/// A signed statement of the chain's position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// `n`.
    pub seq: u64,
    /// `entry_n`, in hex.
    pub entry_hash: String,
    /// `Sign(identity, ctx("audit checkpoint") || u64(n) || entry_n)`, in hex.
    pub signature: String,
}

/// Something wrong with a chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditError {
    /// An entry's position, event or hash does not follow from what comes before it.
    Broken {
        /// The first entry that does not verify.
        seq: u64,
    },
    /// A checkpoint's signature does not verify, or it does not match the chain.
    Checkpoint,
    /// An encoded value is malformed.
    Malformed,
    /// A provider operation failed.
    Crypto(CryptoError),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditError::Broken { seq } => write!(f, "the audit chain breaks at entry {seq}"),
            AuditError::Checkpoint => f.write_str("the audit checkpoint does not verify"),
            AuditError::Malformed => f.write_str("the audit export is malformed"),
            AuditError::Crypto(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AuditError {}

fn put_field(out: &mut Vec<u8>, field: &str) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field.as_bytes());
}

/// `canonical(event_n)`: one encoding for each event, with every field length-prefixed
/// and the position included, so that entries cannot be reordered or spliced.
pub fn canonical(seq: u64, event: &AuditEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&event.at.to_be_bytes());
    put_field(&mut out, &event.subject);
    put_field(&mut out, &event.object);
    put_field(&mut out, &event.operation);
    put_field(&mut out, &event.result);
    put_field(&mut out, &event.detail);
    out
}

fn genesis(p: &dyn CryptoProvider, fingerprint: &[u8]) -> Vec<u8> {
    let mut input = ctx("audit genesis");
    input.extend_from_slice(fingerprint);
    p.hash(&input)
}

fn next_hash(p: &dyn CryptoProvider, previous: &[u8], seq: u64, event: &AuditEvent) -> Vec<u8> {
    let mut input = ctx("audit");
    input.extend_from_slice(previous);
    input.extend_from_slice(&canonical(seq, event));
    p.hash(&input)
}

fn checkpoint_input(seq: u64, head: &[u8]) -> Vec<u8> {
    let mut input = ctx("audit checkpoint");
    input.extend_from_slice(&seq.to_be_bytes());
    input.extend_from_slice(head);
    input
}

/// The writing end of a chain. Keeps only its head, so it is cheap to hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditChain {
    head: Vec<u8>,
    seq: u64,
}

impl AuditChain {
    /// Starts a chain for the endpoint with this fingerprint.
    pub fn new(p: &dyn CryptoProvider, fingerprint: &[u8]) -> Self {
        AuditChain {
            head: genesis(p, fingerprint),
            seq: 0,
        }
    }

    /// Continues a chain from a stored position.
    pub fn resume(head: Vec<u8>, seq: u64) -> Self {
        AuditChain { head, seq }
    }

    /// The latest entry's hash.
    pub fn head(&self) -> &[u8] {
        &self.head
    }

    /// The latest entry's position, or 0 for an empty chain.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Computes the next entry without moving the chain. A caller that has to store
    /// the entry durably first calls [`AuditChain::commit`] after the store succeeds,
    /// so a failed append leaves the chain where it was.
    pub fn prepare(&self, p: &dyn CryptoProvider, event: AuditEvent) -> AuditEntry {
        let seq = self.seq + 1;
        let hash = next_hash(p, &self.head, seq, &event);
        AuditEntry {
            seq,
            event,
            entry_hash: to_hex(&hash),
        }
    }

    /// Moves the chain past an entry from [`AuditChain::prepare`].
    pub fn commit(&mut self, entry: &AuditEntry) -> Result<(), AuditError> {
        if entry.seq != self.seq + 1 {
            return Err(AuditError::Broken { seq: entry.seq });
        }
        self.head = from_hex(&entry.entry_hash).ok_or(AuditError::Malformed)?;
        self.seq = entry.seq;
        Ok(())
    }

    /// Appends an event, for a chain whose store cannot fail.
    pub fn append(&mut self, p: &dyn CryptoProvider, event: AuditEvent) -> AuditEntry {
        let entry = self.prepare(p, event);
        self.seq = entry.seq;
        self.head = from_hex(&entry.entry_hash).unwrap_or_default();
        entry
    }

    /// Signs a checkpoint at the current position.
    pub fn checkpoint(&self, identity: &dyn SigningKey) -> Result<Checkpoint, AuditError> {
        let signature = identity
            .sign(&checkpoint_input(self.seq, &self.head))
            .map_err(AuditError::Crypto)?;
        Ok(Checkpoint {
            seq: self.seq,
            entry_hash: to_hex(&self.head),
            signature: to_hex(&signature),
        })
    }
}

/// Verifies a whole chain from its genesis, returning the head.
pub fn verify_chain(
    p: &dyn CryptoProvider,
    fingerprint: &[u8],
    entries: &[AuditEntry],
) -> Result<Vec<u8>, AuditError> {
    let mut head = genesis(p, fingerprint);
    for (index, entry) in entries.iter().enumerate() {
        let seq = index as u64 + 1;
        if entry.seq != seq {
            return Err(AuditError::Broken { seq });
        }
        let hash = next_hash(p, &head, seq, &entry.event);
        if to_hex(&hash) != entry.entry_hash {
            return Err(AuditError::Broken { seq });
        }
        head = hash;
    }
    Ok(head)
}

/// Verifies a checkpoint's signature and, given the chain's entries, that the chain
/// still contains the checkpointed position. A chain cut short fails here.
pub fn verify_checkpoint(
    p: &dyn CryptoProvider,
    identity: &PublicKey,
    checkpoint: &Checkpoint,
    entries: &[AuditEntry],
) -> Result<(), AuditError> {
    let head = from_hex(&checkpoint.entry_hash).ok_or(AuditError::Malformed)?;
    let signature = from_hex(&checkpoint.signature).ok_or(AuditError::Malformed)?;
    p.verify(
        identity,
        &checkpoint_input(checkpoint.seq, &head),
        &signature,
    )
    .map_err(|_| AuditError::Checkpoint)?;
    if checkpoint.seq == 0 {
        return Ok(());
    }
    let index = usize::try_from(checkpoint.seq - 1).map_err(|_| AuditError::Checkpoint)?;
    match entries.get(index) {
        Some(entry) if entry.entry_hash == checkpoint.entry_hash => Ok(()),
        _ => Err(AuditError::Checkpoint),
    }
}

/// Encodes entries as JSON Lines, the format of an audit export.
pub fn to_jsonl(entries: &[AuditEntry]) -> Result<String, AuditError> {
    let mut out = String::new();
    for entry in entries {
        out.push_str(&serde_json::to_string(entry).map_err(|_| AuditError::Malformed)?);
        out.push('\n');
    }
    Ok(out)
}

/// Decodes JSON Lines.
pub fn from_jsonl(text: &str) -> Result<Vec<AuditEntry>, AuditError> {
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).map_err(|_| AuditError::Malformed))
        .collect()
}

/// The keyed hash of a failed login's presented secret, under a log-specific key.
/// Auditors can correlate repeated attempts, but the log is not a guessable list of
/// near-misses of real passwords. See the open interpretation in `docs/COMPLIANCE.md`.
pub fn secret_digest(p: &dyn CryptoProvider, log_key: &[u8], secret: &[u8]) -> String {
    let mut input = ctx("audit secret");
    input.extend_from_slice(secret);
    to_hex(&p.mac(log_key, &input))
}

#[cfg(test)]
mod tests {
    use super::*;
    use provider_testonly::TestOnlyProvider;

    fn event(n: u64) -> AuditEvent {
        AuditEvent {
            at: 1000 + n,
            subject: "alice".into(),
            object: format!("object-{n}"),
            operation: operation::ACCESS.into(),
            result: "ok".into(),
            detail: String::new(),
        }
    }

    fn chain_of(p: &dyn CryptoProvider, n: u64) -> (AuditChain, Vec<AuditEntry>) {
        let mut chain = AuditChain::new(p, b"fingerprint");
        let entries = (1..=n).map(|i| chain.append(p, event(i))).collect();
        (chain, entries)
    }

    #[test]
    fn a_chain_verifies_and_every_kind_of_tampering_breaks_it() {
        let p = TestOnlyProvider::new();
        let (chain, entries) = chain_of(&p, 5);
        assert_eq!(
            verify_chain(&p, b"fingerprint", &entries).unwrap(),
            chain.head()
        );

        let mut changed = entries.clone();
        changed[2].event.result = "denied".into();
        assert_eq!(
            verify_chain(&p, b"fingerprint", &changed),
            Err(AuditError::Broken { seq: 3 })
        );

        let mut removed = entries.clone();
        removed.remove(1);
        assert_eq!(
            verify_chain(&p, b"fingerprint", &removed),
            Err(AuditError::Broken { seq: 2 })
        );

        let mut swapped = entries.clone();
        swapped.swap(0, 1);
        assert_eq!(
            verify_chain(&p, b"fingerprint", &swapped),
            Err(AuditError::Broken { seq: 1 })
        );

        assert!(verify_chain(&p, b"someone else", &entries).is_err());
    }

    #[test]
    fn fields_cannot_shift_between_each_other() {
        let mut a = event(1);
        let mut b = event(1);
        a.subject = "ab".into();
        a.object = "c".into();
        b.subject = "a".into();
        b.object = "bc".into();
        assert_ne!(canonical(1, &a), canonical(1, &b));
    }

    #[test]
    fn a_checkpoint_detects_a_chain_cut_short() {
        let p = TestOnlyProvider::new();
        let identity = p.generate_signing_key().unwrap();
        let (chain, entries) = chain_of(&p, 5);
        let checkpoint = chain.checkpoint(identity.as_ref()).unwrap();
        verify_checkpoint(&p, identity.public_key(), &checkpoint, &entries).unwrap();

        // Truncation still verifies as a chain, which is why the checkpoint matters.
        assert!(verify_chain(&p, b"fingerprint", &entries[..3]).is_ok());
        assert_eq!(
            verify_checkpoint(&p, identity.public_key(), &checkpoint, &entries[..3]),
            Err(AuditError::Checkpoint)
        );

        let mut forged = checkpoint.clone();
        forged.seq = 4;
        assert_eq!(
            verify_checkpoint(&p, identity.public_key(), &forged, &entries),
            Err(AuditError::Checkpoint)
        );
    }

    #[test]
    fn prepare_leaves_the_chain_alone_until_commit() {
        let p = TestOnlyProvider::new();
        let mut chain = AuditChain::new(&p, b"fp");
        let before = chain.clone();
        let entry = chain.prepare(&p, event(1));
        assert_eq!(
            chain, before,
            "a failed store must leave the chain where it was"
        );
        chain.commit(&entry).unwrap();
        assert_eq!(chain.seq(), 1);
        assert!(
            chain.commit(&entry).is_err(),
            "an entry cannot be committed twice"
        );
    }

    #[test]
    fn exports_round_trip() {
        let p = TestOnlyProvider::new();
        let (_, entries) = chain_of(&p, 3);
        let text = to_jsonl(&entries).unwrap();
        assert_eq!(text.lines().count(), 3);
        assert_eq!(from_jsonl(&text).unwrap(), entries);
        assert!(from_jsonl("not json").is_err());
    }

    #[test]
    fn the_secret_digest_is_keyed_and_correlates() {
        let p = TestOnlyProvider::new();
        assert_eq!(
            secret_digest(&p, b"key", b"hunter2"),
            secret_digest(&p, b"key", b"hunter2")
        );
        assert_ne!(
            secret_digest(&p, b"key", b"hunter2"),
            secret_digest(&p, b"other", b"hunter2")
        );
        assert!(!secret_digest(&p, b"key", b"hunter2").contains("hunter2"));
    }
}
