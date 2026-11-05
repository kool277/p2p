//! Per-user pins and safety numbers: `docs/PROTOCOL.md`, section 11.4.

use crate::schedule::{expand_label, salt0};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use crypto_provider::{CryptoError, CryptoProvider};

/// One device's pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The pinned fingerprint.
    pub fingerprint: Vec<u8>,
    /// True if the user compared safety numbers out of band.
    pub verified: bool,
}

/// What a client's pins say about a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinDecision {
    /// First contact with this user. Pinning is safe only after signature and MAC.
    FirstContact,
    /// The device matches its pin.
    Match {
        /// True if the pin was verified out of band.
        verified: bool,
    },
    /// The key changed, or this is a new device of a user who is already pinned.
    /// Either way the server may be substituting someone, so this fails by default.
    Changed,
}

/// `user_id -> { device_id -> fingerprint }`. Local to the device, and the server
/// has no access to it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PinTable {
    users: BTreeMap<String, BTreeMap<String, Pin>>,
}

impl PinTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decides what a presented device means, without changing anything.
    pub fn decide(&self, user_id: &str, device_id: &str, fingerprint: &[u8]) -> PinDecision {
        let Some(devices) = self.users.get(user_id) else {
            return PinDecision::FirstContact;
        };
        match devices.get(device_id) {
            Some(pin) if crypto_provider::ct_eq(&pin.fingerprint, fingerprint) => {
                PinDecision::Match {
                    verified: pin.verified,
                }
            }
            _ => PinDecision::Changed,
        }
    }

    /// Commits a first-contact pin. Call this only after the signature and MAC have
    /// verified (section 7.3).
    pub fn commit(&mut self, user_id: &str, device_id: &str, fingerprint: &[u8]) {
        self.users.entry(user_id.into()).or_default().insert(
            device_id.into(),
            Pin {
                fingerprint: fingerprint.to_vec(),
                verified: false,
            },
        );
    }

    /// Records that the user compared safety numbers, which also lets a new device
    /// join the user's pins or replaces a changed key.
    pub fn record_verified(&mut self, user_id: &str, device_id: &str, fingerprint: &[u8]) {
        self.users.entry(user_id.into()).or_default().insert(
            device_id.into(),
            Pin {
                fingerprint: fingerprint.to_vec(),
                verified: true,
            },
        );
    }

    /// The pin for one device.
    pub fn get(&self, user_id: &str, device_id: &str) -> Option<&Pin> {
        self.users.get(user_id)?.get(device_id)
    }

    /// Every pin, for persistence.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str, &Pin)> {
        self.users.iter().flat_map(|(u, d)| {
            d.iter()
                .map(move |(id, pin)| (u.as_str(), id.as_str(), pin))
        })
    }
}

/// Computes the safety number for two fingerprints: 60 digits in 12 groups of 5.
/// Both sides compute the same number.
pub fn safety_number(p: &dyn CryptoProvider, a: &[u8], b: &[u8]) -> Result<String, CryptoError> {
    let (low, high) = if a <= b { (a, b) } else { (b, a) };
    let mut input = Vec::with_capacity(low.len() + high.len());
    input.extend_from_slice(low);
    input.extend_from_slice(high);
    let prk = p.hkdf_extract(&salt0(p), &input);
    let okm = expand_label(p, &prk, "safety", &[], 60)?;
    let mut out = String::with_capacity(60);
    for group in okm.chunks_exact(5) {
        let mut value = 0u64;
        for byte in group {
            value = (value << 8) | u64::from(*byte);
        }
        let value = value % 100_000;
        let mut divisor = 10_000;
        while divisor > 0 {
            out.push(char::from(b'0' + ((value / divisor) % 10) as u8));
            divisor /= 10;
        }
    }
    Ok(out)
}
