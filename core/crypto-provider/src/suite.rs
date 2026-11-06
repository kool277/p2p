//! The cipher-suite registry from `docs/PROTOCOL.md`, section 4.

/// The national key-agreement component from ADR-0001.
pub const KEX_NAT: u16 = 0x0001;
/// X25519 (RFC 7748).
pub const KEX_X25519: u16 = 0x0002;
/// ML-KEM-768 (FIPS 203).
pub const KEX_ML_KEM_768: u16 = 0x0003;

/// Reserved: "not selected yet". Valid only in `XX_INIT`, its fragments and `HS_REJECT`.
pub const SUITE_NONE: u16 = 0x0000;
/// `nat` + X25519, with library record protection, 1106 and 1092. Provisional.
pub const SUITE_NAT_X25519: u16 = 0x0101;
/// `nat` + X25519 + ML-KEM-768. Provisional.
pub const SUITE_NAT_X25519_ML_KEM_768: u16 = 0x0102;
/// Test only: X25519, AES-256-CTR + HMAC-SHA-256, SHA-256, Ed25519.
/// The range `0xFF00..=0xFFFF` is never offered by a release build.
pub const SUITE_TESTONLY_X25519: u16 = 0xFF01;
/// Test only: X25519 + ML-KEM-768, otherwise as [`SUITE_TESTONLY_X25519`].
pub const SUITE_TESTONLY_X25519_ML_KEM_768: u16 = 0xFF02;

/// The key-agreement components of a suite, in ascending `kex_id` order.
pub fn suite_kex(suite_id: u16) -> Option<&'static [u16]> {
    match suite_id {
        SUITE_NAT_X25519 => Some(&[KEX_NAT, KEX_X25519]),
        SUITE_NAT_X25519_ML_KEM_768 => Some(&[KEX_NAT, KEX_X25519, KEX_ML_KEM_768]),
        SUITE_TESTONLY_X25519 => Some(&[KEX_X25519]),
        SUITE_TESTONLY_X25519_ML_KEM_768 => Some(&[KEX_X25519, KEX_ML_KEM_768]),
        _ => None,
    }
}

/// True for the test-only range, which a release build must refuse.
pub fn is_test_only(suite_id: u16) -> bool {
    suite_id >= 0xFF00
}
