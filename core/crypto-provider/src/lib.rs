//! The boundary between the Qalqon engine and a cryptographic library.
//!
//! `core/provider-<lib>` implements [`CryptoProvider`] over the certified library
//! and holds the only FFI to it. The engine calls nothing else for cryptography.
//! HMAC, HKDF and the encrypt-then-MAC composition are written here once, over
//! the provider's hash and cipher, using the published constructions named in
//! `docs/PROTOCOL.md` (RFC 2104, RFC 5869). A library that has its own may
//! override the default methods.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod etm;
mod kdf;
pub mod suite;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

pub use subtle;
pub use zeroize::{Zeroize, Zeroizing};

/// Secret bytes that are erased when dropped.
pub type Secret = Zeroizing<Vec<u8>>;

/// Creates a [`Secret`] holding a copy of `bytes`.
pub fn secret(bytes: &[u8]) -> Secret {
    Zeroizing::new(bytes.to_vec())
}

/// A failure inside a provider. Deliberately carries no detail about secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// A tag, signature or shared-secret check failed.
    Verification,
    /// A key, nonce or length is not valid for this provider.
    InvalidInput,
    /// The random source failed.
    Random,
    /// This provider does not offer the requested operation or component.
    Unsupported,
    /// A known-answer self-test failed.
    SelfTest,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CryptoError::Verification => "verification failed",
            CryptoError::InvalidInput => "invalid cryptographic input",
            CryptoError::Random => "random source failed",
            CryptoError::Unsupported => "operation not supported by this provider",
            CryptoError::SelfTest => "known-answer self-test failed",
        })
    }
}

/// The symbolic constants from `docs/PROTOCOL.md`, section 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// `HashLen`: hash output in bytes. The protocol requires at least 32.
    pub hash_len: usize,
    /// `HashBlockLen`: the hash's internal block in bytes, for HMAC.
    pub hash_block_len: usize,
    /// `KeyLen`: record protection key in bytes.
    pub key_len: usize,
    /// `IvLen`: nonce in bytes. The protocol requires at least 12.
    pub iv_len: usize,
    /// `TagLen`: authentication tag in bytes.
    pub tag_len: usize,
    /// MAC key in bytes for section 9.2, or 0 when the provider has a true AEAD.
    pub mac_key_len: usize,
    /// The signature algorithm written into certificates.
    pub signature_algorithm: u16,
}

/// A record protection key: an encryption key and, for encrypt-then-MAC, a MAC key.
#[derive(Clone)]
pub struct AeadKey {
    /// The cipher key, `KeyLen` bytes.
    pub enc: Secret,
    /// The MAC key, empty for a true AEAD.
    pub mac: Secret,
}

impl fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AeadKey(..)")
    }
}

/// A public signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// The signature algorithm.
    pub algorithm: u16,
    /// The encoded key.
    pub key: Vec<u8>,
}

/// A long-term signing key behind a handle. It may live in an HSM or a platform
/// key store, so nothing here assumes the secret can be read.
pub trait SigningKey: Send + Sync {
    /// The public half.
    fn public_key(&self) -> &PublicKey;
    /// Signs `message`.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    /// Exports the secret so a key store can wrap it. `None` for a key that
    /// cannot leave its hardware.
    fn export_secret(&self) -> Option<Secret>;
}

/// Key-agreement output for the responder: its share and the shared secret.
pub type KexResponse = (Vec<u8>, Secret);

/// Every cryptographic operation the engine uses (build prompt §2).
pub trait CryptoProvider: Send + Sync {
    /// The sizes this provider uses.
    fn params(&self) -> Params;

    /// The suites this provider supports, most preferred first.
    fn suites(&self) -> &[u16];

    /// The O'z DSt 1106 hash.
    fn hash(&self, data: &[u8]) -> Vec<u8>;

    /// HMAC over [`CryptoProvider::hash`] (RFC 2104).
    fn mac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        kdf::hmac(&|d| self.hash(d), self.params().hash_block_len, key, data)
    }

    /// HKDF-Extract (RFC 5869).
    fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Secret {
        Zeroizing::new(if salt.is_empty() {
            self.mac(&vec![0u8; self.params().hash_len], ikm)
        } else {
            self.mac(salt, ikm)
        })
    }

    /// HKDF-Expand (RFC 5869).
    fn hkdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Secret, CryptoError> {
        kdf::hkdf_expand(
            &|k, d| self.mac(k, d),
            self.params().hash_len,
            prk,
            info,
            len,
        )
    }

    /// Seals `plaintext`, returning the ciphertext followed by the tag.
    fn aead_seal(
        &self,
        key: &AeadKey,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Opens `sealed`. The tag is checked in constant time before any decryption.
    fn aead_open(
        &self,
        key: &AeadKey,
        nonce: &[u8],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Secret, CryptoError>;

    /// Verifies a signature over `message`.
    fn verify(
        &self,
        public: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;

    /// Generates a new long-term signing key.
    fn generate_signing_key(&self) -> Result<Box<dyn SigningKey>, CryptoError>;

    /// Recreates a signing key from a secret produced by [`SigningKey::export_secret`].
    fn import_signing_key(&self, secret: &[u8]) -> Result<Box<dyn SigningKey>, CryptoError>;

    /// Creates an ephemeral key-agreement key: the secret and the share to send.
    fn kex_keygen(&self, kex_id: u16) -> Result<(Secret, Vec<u8>), CryptoError>;

    /// The responder's side: creates a share from the initiator's and returns
    /// the shared secret. For a KEM this encapsulates to `peer_share`.
    fn kex_respond(&self, kex_id: u16, peer_share: &[u8]) -> Result<KexResponse, CryptoError> {
        let (own, share) = self.kex_keygen(kex_id)?;
        let shared = self.kex_agree(kex_id, &own, peer_share)?;
        Ok((share, shared))
    }

    /// The initiator's side: derives the shared secret from the responder's share.
    /// For a KEM this decapsulates.
    fn kex_agree(&self, kex_id: u16, own: &[u8], peer_share: &[u8]) -> Result<Secret, CryptoError>;

    /// Fills `out` from the library's CSPRNG.
    fn random(&self, out: &mut [u8]) -> Result<(), CryptoError>;

    /// Wraps key material under a key-encryption key. The default seals it with a
    /// random nonce and prefixes the nonce.
    fn key_wrap(&self, kek: &AeadKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = vec![0u8; self.params().iv_len];
        self.random(&mut nonce)?;
        let mut out = nonce.clone();
        out.extend_from_slice(&self.aead_seal(kek, &nonce, b"qalqon0 key wrap", plaintext)?);
        Ok(out)
    }

    /// Reverses [`CryptoProvider::key_wrap`].
    fn key_unwrap(&self, kek: &AeadKey, wrapped: &[u8]) -> Result<Secret, CryptoError> {
        let iv_len = self.params().iv_len;
        if wrapped.len() < iv_len {
            return Err(CryptoError::InvalidInput);
        }
        let (nonce, sealed) = wrapped.split_at(iv_len);
        self.aead_open(kek, nonce, b"qalqon0 key wrap", sealed)
    }

    /// Runs the known-answer self-tests. Called once at module load.
    fn self_test(&self) -> Result<(), CryptoError>;

    /// A short name for logs, so a test-only build can never be mistaken for a
    /// certified one.
    fn name(&self) -> &'static str;
}

/// Constant-time equality. Slices of different lengths compare unequal.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Encodes bytes as lowercase hex, for fingerprints and logs of public values.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

/// Decodes lowercase or uppercase hex.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let raw = text.as_bytes();
    if raw.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        out.push(digit(pair[0])? << 4 | digit(pair[1])?);
    }
    Some(out)
}

/// A failure in a [`KeyStore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyStoreError {
    /// The store cannot be reached or read.
    Unavailable(String),
    /// A stored key failed to unwrap, which suggests tampering or the wrong store.
    Corrupt,
    /// A cryptographic step failed.
    Crypto(CryptoError),
}

impl From<CryptoError> for KeyStoreError {
    fn from(e: CryptoError) -> Self {
        KeyStoreError::Crypto(e)
    }
}

/// Holds long-term keys on one platform (ADR-0002, part 6). Implementations live
/// in `core/keystore-<platform>/`. Nothing above this trait ever sees key bytes.
pub trait KeyStore: Send + Sync {
    /// Opens the signing key named `label`, creating it if `create` is true.
    /// Returns `Ok(None)` if the key does not exist and `create` is false.
    fn signing_key(
        &self,
        provider: &dyn CryptoProvider,
        label: &str,
        create: bool,
    ) -> Result<Option<Box<dyn SigningKey>>, KeyStoreError>;

    /// Opens the symmetric secret named `label`, creating `len` random bytes if needed.
    fn secret(
        &self,
        provider: &dyn CryptoProvider,
        label: &str,
        len: usize,
    ) -> Result<Secret, KeyStoreError>;
}
