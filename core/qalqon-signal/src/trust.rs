//! A client's local trust state: pins, known chains and the CRL. Nothing here ever goes
//! to the server, which has no access to the pin store (section 11.4).

use crypto_provider::{from_hex, to_hex};
use qalqon_api as api;
use qalqon_audit::AuditEntry;
use qalqon_core::cert::ValidatedChain;
use qalqon_core::crl::{CrlCache, CrlError};
use qalqon_core::pins::{PinDecision, PinTable};
use qalqon_core::{PeerRejection, PeerVerifier, PinStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// One saved pin.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPin {
    /// The user.
    pub user_id: String,
    /// The device.
    pub device_id: String,
    /// The pinned fingerprint, in hex.
    pub fingerprint: String,
    /// True if it was verified out of band.
    pub verified: bool,
}

/// What a client keeps between runs. An SDK writes this to `dataDir`, and a browser
/// writes it to IndexedDB. Key material is never in here.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedState {
    /// Pins.
    #[serde(default)]
    pub pins: Vec<SavedPin>,
    /// Chains from completed handshakes, for section 8: `(user, device, chain hex)`.
    #[serde(default)]
    pub chains: Vec<(String, String, String)>,
    /// The audit chain.
    #[serde(default)]
    pub audit_entries: Vec<AuditEntry>,
}

/// See the module documentation.
#[derive(Debug)]
pub struct Trust {
    /// `user_id -> { device_id -> fingerprint }`.
    pub pins: PinTable,
    /// The cached CRL.
    pub crl: CrlCache,
    chains: BTreeMap<(String, String), Vec<u8>>,
    /// What each device presented in its latest authenticated handshake.
    seen: BTreeMap<(String, String), Vec<u8>>,
    /// The device of each user that most recently passed signature and MAC checks.
    last_presented: BTreeMap<String, String>,
    policy: api::IdentityChangePolicy,
    grace_ms: u64,
}

impl Trust {
    /// Restores saved state.
    pub fn from_saved(
        saved: &SavedState,
        policy: api::IdentityChangePolicy,
        grace_ms: u64,
    ) -> Self {
        let mut pins = PinTable::new();
        for pin in &saved.pins {
            if let Some(fingerprint) = from_hex(&pin.fingerprint) {
                if pin.verified {
                    pins.record_verified(&pin.user_id, &pin.device_id, &fingerprint);
                } else {
                    pins.commit(&pin.user_id, &pin.device_id, &fingerprint);
                }
            }
        }
        let chains = saved
            .chains
            .iter()
            .filter_map(|(u, d, c)| Some(((u.clone(), d.clone()), from_hex(c)?)))
            .collect();
        Trust {
            pins,
            crl: CrlCache::new(),
            chains,
            seen: BTreeMap::new(),
            last_presented: BTreeMap::new(),
            policy,
            grace_ms,
        }
    }

    /// What should be saved.
    pub fn to_saved(&self, audit_entries: Vec<AuditEntry>) -> SavedState {
        SavedState {
            pins: self
                .pins
                .iter()
                .map(|(u, d, p)| SavedPin {
                    user_id: u.into(),
                    device_id: d.into(),
                    fingerprint: to_hex(&p.fingerprint),
                    verified: p.verified,
                })
                .collect(),
            chains: self
                .chains
                .iter()
                .map(|((u, d), c)| (u.clone(), d.clone(), to_hex(c)))
                .collect(),
            audit_entries,
        }
    }

    /// Keeps a chain from a completed handshake. Section 8 forbids using one that came
    /// from a server during rendezvous, so this is only called after `Established`.
    pub fn remember_chain(&mut self, user: &str, device: &str, chain: &[u8]) {
        self.chains
            .insert((user.into(), device.into()), chain.to_vec());
    }

    /// A chain to offer with `known_responder`. With no device named, only a user with
    /// exactly one known device has an unambiguous chain.
    pub fn cached_chain(&self, user: &str, device: Option<&str>) -> Option<Vec<u8>> {
        match device {
            Some(device) => self
                .chains
                .get(&(user.to_string(), device.to_string()))
                .cloned(),
            None => {
                let mut matching = self.chains.iter().filter(|((u, _), _)| u == user);
                let first = matching.next()?;
                if matching.next().is_some() {
                    None
                } else {
                    Some(first.1.clone())
                }
            }
        }
    }

    /// A device of this user that an authenticated handshake has shown, or a pinned one.
    /// With no device named, the most recent one wins.
    pub fn known_device(&self, user: &str, device: Option<&str>) -> Option<(String, Vec<u8>)> {
        let device = device
            .map(str::to_string)
            .or_else(|| self.last_presented.get(user).cloned());
        if let Some(device) = &device
            && let Some(fingerprint) = self.seen.get(&(user.to_string(), device.clone()))
        {
            return Some((device.clone(), fingerprint.clone()));
        }
        self.pins
            .iter()
            .find(|(u, d, _)| *u == user && device.as_deref().is_none_or(|x| x == *d))
            .map(|(_, d, p)| (d.to_string(), p.fingerprint.clone()))
    }

    /// The public status of an identity.
    pub fn status_of(
        &self,
        user: &str,
        device: &str,
        fingerprint: &[u8],
    ) -> api::VerificationStatus {
        match self.pins.decide(user, device, fingerprint) {
            PinDecision::FirstContact => api::VerificationStatus::Unverified,
            PinDecision::Match { verified: true } => api::VerificationStatus::Verified,
            PinDecision::Match { verified: false } => api::VerificationStatus::Pinned,
            PinDecision::Changed => api::VerificationStatus::Changed,
        }
    }
}

/// The checks on the data plane, sections 7.3 and 11.
pub(crate) struct DataPlaneVerifier {
    trust: Arc<Mutex<Trust>>,
}

impl DataPlaneVerifier {
    pub(crate) fn new(trust: Arc<Mutex<Trust>>) -> Self {
        DataPlaneVerifier { trust }
    }
}

impl PeerVerifier for DataPlaneVerifier {
    fn check_revocation(
        &mut self,
        chain: &ValidatedChain,
        now_ms: u64,
    ) -> Result<(), PeerRejection> {
        let trust = self.trust.lock().unwrap_or_else(|e| e.into_inner());
        trust
            .crl
            .check_data_plane(&chain.leaf.fields.serial, now_ms, trust.grace_ms)
            .map_err(|e| match e {
                CrlError::Revoked => PeerRejection::Revoked,
                _ => PeerRejection::RevocationStale,
            })
    }

    fn check_pin(
        &mut self,
        chain: &ValidatedChain,
        _now_ms: u64,
    ) -> Result<PinStatus, PeerRejection> {
        let fields = &chain.leaf.fields;
        let mut trust = self.trust.lock().unwrap_or_else(|e| e.into_inner());
        let key = (fields.subject_a.clone(), fields.subject_b.clone());
        trust.seen.insert(key, chain.fingerprint.clone());
        trust
            .last_presented
            .insert(fields.subject_a.clone(), fields.subject_b.clone());
        match trust
            .pins
            .decide(&fields.subject_a, &fields.subject_b, &chain.fingerprint)
        {
            PinDecision::FirstContact => {
                trust
                    .pins
                    .commit(&fields.subject_a, &fields.subject_b, &chain.fingerprint);
                Ok(PinStatus::Pinned)
            }
            PinDecision::Match { verified: true } => Ok(PinStatus::Verified),
            PinDecision::Match { verified: false } => Ok(PinStatus::Pinned),
            PinDecision::Changed => match trust.policy {
                api::IdentityChangePolicy::Warn => Ok(PinStatus::Changed),
                api::IdentityChangePolicy::Block => Err(PeerRejection::IdentityChanged),
            },
        }
    }
}

/// Servers are not pinned: the CA and host name identify them, and the end-to-end
/// guarantees never rely on trusting a server. Revocation is checked right after the
/// first CRL arrives (section 11.5).
pub(crate) struct UncheckedControlVerifier;

impl PeerVerifier for UncheckedControlVerifier {
    fn check_revocation(&mut self, _: &ValidatedChain, _: u64) -> Result<(), PeerRejection> {
        Ok(())
    }
    fn check_pin(&mut self, _: &ValidatedChain, _: u64) -> Result<PinStatus, PeerRejection> {
        Ok(PinStatus::NotPinned)
    }
}
