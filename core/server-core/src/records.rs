//! The records a host stores, as JSON. `server-core` owns their fields, and a host
//! keeps them as opaque documents (`docs/HOST-SPI.md`).

use serde::{Deserialize, Serialize};

/// A pending one-time enrolment token. Only its hash is stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentToken {
    /// `H(ctx("enrollment token") || token)`, in hex.
    pub hash: String,
    /// When it stops working.
    pub expires_at: u64,
}

/// `UserStore`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    /// The user's identifier.
    pub user_id: String,
    /// A name for display.
    pub display_name: String,
    /// Argon2id output, opaque to the host.
    pub password_hash: String,
    /// Opaque MFA state, or null when MFA is off.
    pub mfa_state: Option<String>,
    /// `user` or `admin`.
    pub role: String,
    /// `active` or `disabled`.
    pub status: String,
    /// Consecutive failed logins.
    pub failed_attempts: u32,
    /// Login is refused until this time.
    pub locked_until: u64,
    /// Pending enrolment tokens.
    #[serde(default)]
    pub enrollment_tokens: Vec<EnrollmentToken>,
    /// Creation time.
    pub created_at: u64,
    /// Last change.
    pub updated_at: u64,
}

/// `DeviceStore`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// The identifier the server assigned.
    pub device_id: String,
    /// The owner.
    pub user_id: String,
    /// A name for display.
    pub device_name: String,
    /// The identity key's fingerprint, in hex.
    pub fingerprint: String,
    /// The current chain, in hex.
    pub cert_chain: String,
    /// The leaf certificate's serial, in hex, for revocation.
    pub serial: String,
    /// `active` or `revoked`.
    pub status: String,
    /// When it enrolled.
    pub enrolled_at: u64,
    /// When it was revoked.
    pub revoked_at: Option<u64>,
    /// Last successful login.
    pub last_seen_at: Option<u64>,
}

/// `PolicyStore`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRecord {
    /// The document's name.
    pub name: String,
    /// Increases on each change.
    pub version: u64,
    /// The document itself.
    pub document: serde_json::Value,
    /// Last change.
    pub updated_at: u64,
}
