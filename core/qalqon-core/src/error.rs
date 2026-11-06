//! The error taxonomy. Values match the `errors` table in `core/idl/qalqon.api.yaml`.

/// A public error code. These numbers are the same in every language.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
#[allow(missing_docs)]
pub enum ErrorCode {
    Ok = 0,
    InvalidArgument = 1,
    InvalidState = 2,
    Timeout = 3,
    Closed = 4,
    Unsupported = 5,
    Internal = 6,
    TransportFailed = 100,
    TransportUnsupported = 101,
    PeerUnavailable = 102,
    PeerUnreachable = 103,
    MessageTooLarge = 104,
    HandshakeFailed = 200,
    VersionMismatch = 201,
    SuiteMismatch = 202,
    PeerIdentityChanged = 203,
    PeerRevoked = 204,
    RevocationDataStale = 205,
    AuthenticationFailed = 300,
    MfaRequired = 301,
    RateLimited = 302,
    AccessDenied = 303,
    NotEnrolled = 304,
    EnrollmentRejected = 305,
    KeyStoreUnavailable = 400,
    SelfTestFailed = 401,
    IntegrityCheckFailed = 402,
    AuditUnavailable = 500,
}

/// Every code, for iteration and for the IDL agreement test.
pub const ALL_CODES: [ErrorCode; 28] = [
    ErrorCode::Ok,
    ErrorCode::InvalidArgument,
    ErrorCode::InvalidState,
    ErrorCode::Timeout,
    ErrorCode::Closed,
    ErrorCode::Unsupported,
    ErrorCode::Internal,
    ErrorCode::TransportFailed,
    ErrorCode::TransportUnsupported,
    ErrorCode::PeerUnavailable,
    ErrorCode::PeerUnreachable,
    ErrorCode::MessageTooLarge,
    ErrorCode::HandshakeFailed,
    ErrorCode::VersionMismatch,
    ErrorCode::SuiteMismatch,
    ErrorCode::PeerIdentityChanged,
    ErrorCode::PeerRevoked,
    ErrorCode::RevocationDataStale,
    ErrorCode::AuthenticationFailed,
    ErrorCode::MfaRequired,
    ErrorCode::RateLimited,
    ErrorCode::AccessDenied,
    ErrorCode::NotEnrolled,
    ErrorCode::EnrollmentRejected,
    ErrorCode::KeyStoreUnavailable,
    ErrorCode::SelfTestFailed,
    ErrorCode::IntegrityCheckFailed,
    ErrorCode::AuditUnavailable,
];

impl ErrorCode {
    /// The numeric code.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Finds the code with this number.
    pub fn from_code(code: u32) -> Option<Self> {
        ALL_CODES.iter().copied().find(|c| c.code() == code)
    }

    /// The IDL's name for this code.
    pub const fn name(self) -> &'static str {
        match self {
            ErrorCode::Ok => "ok",
            ErrorCode::InvalidArgument => "invalidArgument",
            ErrorCode::InvalidState => "invalidState",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Closed => "closed",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::Internal => "internal",
            ErrorCode::TransportFailed => "transportFailed",
            ErrorCode::TransportUnsupported => "transportUnsupported",
            ErrorCode::PeerUnavailable => "peerUnavailable",
            ErrorCode::PeerUnreachable => "peerUnreachable",
            ErrorCode::MessageTooLarge => "messageTooLarge",
            ErrorCode::HandshakeFailed => "handshakeFailed",
            ErrorCode::VersionMismatch => "versionMismatch",
            ErrorCode::SuiteMismatch => "suiteMismatch",
            ErrorCode::PeerIdentityChanged => "peerIdentityChanged",
            ErrorCode::PeerRevoked => "peerRevoked",
            ErrorCode::RevocationDataStale => "revocationDataStale",
            ErrorCode::AuthenticationFailed => "authenticationFailed",
            ErrorCode::MfaRequired => "mfaRequired",
            ErrorCode::RateLimited => "rateLimited",
            ErrorCode::AccessDenied => "accessDenied",
            ErrorCode::NotEnrolled => "notEnrolled",
            ErrorCode::EnrollmentRejected => "enrollmentRejected",
            ErrorCode::KeyStoreUnavailable => "keyStoreUnavailable",
            ErrorCode::SelfTestFailed => "selfTestFailed",
            ErrorCode::IntegrityCheckFailed => "integrityCheckFailed",
            ErrorCode::AuditUnavailable => "auditUnavailable",
        }
    }
}

/// Why a handshake failed. `code` may be shown to the application. `detail` is for
/// the local audit log only and never goes on the wire (section 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeFailure {
    /// The public code.
    pub code: ErrorCode,
    /// The local reason.
    pub detail: &'static str,
}

impl HandshakeFailure {
    pub(crate) const fn generic(detail: &'static str) -> Self {
        HandshakeFailure {
            code: ErrorCode::HandshakeFailed,
            detail,
        }
    }
}
