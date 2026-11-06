//! A crypto provider built from public crates, so that engine, state-machine and
//! vector work can proceed before the certified library arrives (ADR-0002, part 2).
//!
//! **This is not the certified library and carries no compliance claim.** It uses
//! SHA-256, AES-256-CTR with HMAC-SHA-256, Ed25519, X25519 and ML-KEM-768 instead of
//! O'z DSt 1105, 1106 and 1092. Three things keep it out of production:
//!
//! - It refuses to compile when debug assertions are off, which is the release profile.
//! - It offers only suites in the `0xFF00..=0xFFFF` range, so it can never negotiate
//!   with a real build.
//! - Every binary that contains it carries [`TESTONLY_MARKER`], which a CI check greps for.
#![forbid(unsafe_code)]

#[cfg(not(debug_assertions))]
compile_error!(
    "provider-testonly must not be compiled in a release profile: it is not the certified \
     library. Build provider-<lib> instead, or build without --release during development."
);

use aes::Aes256;
use crypto_ext::{ml_kem_768, x25519};
use crypto_provider::suite::{
    KEX_ML_KEM_768, KEX_X25519, SUITE_TESTONLY_X25519, SUITE_TESTONLY_X25519_ML_KEM_768,
};
use crypto_provider::{
    AeadKey, CryptoError, CryptoProvider, KexResponse, Params, PublicKey, Secret, SigningKey,
    Zeroizing, etm, secret,
};
use ctr::Ctr32BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ed25519_dalek::{Signature, Signer as _, Verifier as _};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

/// Appears in every binary that links this provider.
pub const TESTONLY_MARKER: &str = "QALQON-TESTONLY-PROVIDER-NOT-FOR-RELEASE";

/// The signature algorithm code for Ed25519 in certificates. In the test-only range.
pub const SIG_ED25519_TESTONLY: u16 = 0xFF01;

const PARAMS: Params = Params {
    hash_len: 32,
    hash_block_len: 64,
    key_len: 32,
    iv_len: 12,
    tag_len: 32,
    mac_key_len: 32,
    signature_algorithm: SIG_ED25519_TESTONLY,
};

const SUITES: [u16; 2] = [SUITE_TESTONLY_X25519, SUITE_TESTONLY_X25519_ML_KEM_768];

enum Rng {
    Os,
    /// Deterministic output for test vectors: SHA-256 of the seed and a counter.
    Seeded {
        seed: Vec<u8>,
        counter: Mutex<u64>,
    },
}

/// See the crate documentation. Never use this outside tests and development.
pub struct TestOnlyProvider {
    rng: Rng,
    suites: Vec<u16>,
}

impl std::fmt::Debug for TestOnlyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestOnlyProvider")
    }
}

impl Default for TestOnlyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TestOnlyProvider {
    /// A provider that draws randomness from the operating system.
    pub fn new() -> Self {
        std::hint::black_box(TESTONLY_MARKER);
        TestOnlyProvider {
            rng: Rng::Os,
            suites: SUITES.to_vec(),
        }
    }

    /// A provider with reproducible randomness, for the vectors in `tests/conformance`.
    pub fn seeded(seed: &[u8]) -> Self {
        TestOnlyProvider {
            rng: Rng::Seeded {
                seed: seed.to_vec(),
                counter: Mutex::new(0),
            },
            suites: SUITES.to_vec(),
        }
    }

    /// Restricts the suites this provider offers, most preferred first. Tests use
    /// this to exercise negotiation.
    pub fn with_suites(mut self, suites: &[u16]) -> Self {
        self.suites = suites.to_vec();
        self
    }
}

struct Ed25519Key {
    key: ed25519_dalek::SigningKey,
    public: PublicKey,
}

impl SigningKey for Ed25519Key {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.key.sign(message).to_bytes().to_vec())
    }
    fn export_secret(&self) -> Option<Secret> {
        Some(secret(&self.key.to_bytes()))
    }
}

fn ed25519_from_seed(seed: &[u8; 32]) -> Box<dyn SigningKey> {
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    let public = PublicKey {
        algorithm: SIG_ED25519_TESTONLY,
        key: key.verifying_key().to_bytes().to_vec(),
    };
    Box::new(Ed25519Key { key, public })
}

/// AES-256-CTR with each counter block `nonce || u32(block_index)`, section 9.2.
fn keystream(key: &[u8], nonce: &[u8], buffer: &mut [u8]) -> Result<(), CryptoError> {
    if key.len() != PARAMS.key_len || nonce.len() != PARAMS.iv_len {
        return Err(CryptoError::InvalidInput);
    }
    let mut iv = [0u8; 16];
    iv[..12].copy_from_slice(nonce);
    let key: &[u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidInput)?;
    let mut cipher = Ctr32BE::<Aes256>::new(key.into(), (&iv).into());
    cipher.apply_keystream(buffer);
    Ok(())
}

impl CryptoProvider for TestOnlyProvider {
    fn params(&self) -> Params {
        PARAMS
    }

    fn suites(&self) -> &[u16] {
        &self.suites
    }

    fn hash(&self, data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).as_slice().to_vec()
    }

    fn aead_seal(
        &self,
        key: &AeadKey,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        etm::seal(self, &keystream, key, nonce, aad, plaintext)
    }

    fn aead_open(
        &self,
        key: &AeadKey,
        nonce: &[u8],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Secret, CryptoError> {
        etm::open(self, &keystream, key, nonce, aad, sealed)
    }

    fn verify(
        &self,
        public: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if public.algorithm != SIG_ED25519_TESTONLY {
            return Err(CryptoError::Unsupported);
        }
        let key: &[u8; 32] = public
            .key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Verification)?;
        let key =
            ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| CryptoError::Verification)?;
        let signature = Signature::from_slice(signature).map_err(|_| CryptoError::Verification)?;
        key.verify(message, &signature)
            .map_err(|_| CryptoError::Verification)
    }

    fn generate_signing_key(&self) -> Result<Box<dyn SigningKey>, CryptoError> {
        let mut seed = Zeroizing::new([0u8; 32]);
        self.random(seed.as_mut())?;
        Ok(ed25519_from_seed(&seed))
    }

    fn import_signing_key(&self, secret: &[u8]) -> Result<Box<dyn SigningKey>, CryptoError> {
        let seed: &[u8; 32] = secret.try_into().map_err(|_| CryptoError::InvalidInput)?;
        Ok(ed25519_from_seed(seed))
    }

    fn kex_keygen(&self, kex_id: u16) -> Result<(Secret, Vec<u8>), CryptoError> {
        match kex_id {
            KEX_X25519 => {
                let mut r = Zeroizing::new([0u8; 32]);
                self.random(r.as_mut())?;
                Ok(x25519::keygen(*r))
            }
            KEX_ML_KEM_768 => {
                let mut r = Zeroizing::new([0u8; 64]);
                self.random(r.as_mut())?;
                Ok(ml_kem_768::keygen(&r))
            }
            _ => Err(CryptoError::Unsupported),
        }
    }

    fn kex_respond(&self, kex_id: u16, peer_share: &[u8]) -> Result<KexResponse, CryptoError> {
        match kex_id {
            KEX_X25519 => {
                let (own, share) = self.kex_keygen(kex_id)?;
                Ok((share, x25519::agree(&own, peer_share)?))
            }
            KEX_ML_KEM_768 => {
                let mut r = Zeroizing::new([0u8; 32]);
                self.random(r.as_mut())?;
                ml_kem_768::encapsulate(peer_share, &r)
            }
            _ => Err(CryptoError::Unsupported),
        }
    }

    fn kex_agree(&self, kex_id: u16, own: &[u8], peer_share: &[u8]) -> Result<Secret, CryptoError> {
        match kex_id {
            KEX_X25519 => x25519::agree(own, peer_share),
            KEX_ML_KEM_768 => ml_kem_768::decapsulate(own, peer_share),
            _ => Err(CryptoError::Unsupported),
        }
    }

    fn random(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        match &self.rng {
            Rng::Os => getrandom::fill(out).map_err(|_| CryptoError::Random),
            Rng::Seeded { seed, counter } => {
                let mut counter = counter.lock().map_err(|_| CryptoError::Random)?;
                for chunk in out.chunks_mut(32) {
                    let mut input = seed.clone();
                    input.extend_from_slice(&counter.to_be_bytes());
                    *counter += 1;
                    let block = self.hash(&input);
                    chunk.copy_from_slice(&block[..chunk.len()]);
                }
                Ok(())
            }
        }
    }

    fn self_test(&self) -> Result<(), CryptoError> {
        // FIPS 180-4 example: SHA-256("abc").
        let abc = crypto_provider::from_hex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .ok_or(CryptoError::SelfTest)?;
        if self.hash(b"abc") != abc {
            return Err(CryptoError::SelfTest);
        }
        // Seal and open, and confirm that a flipped ciphertext bit is refused.
        let key = AeadKey {
            enc: secret(&[7u8; 32]),
            mac: secret(&[9u8; 32]),
        };
        let nonce = [3u8; 12];
        let mut sealed = self.aead_seal(&key, &nonce, b"aad", b"plaintext")?;
        if self.aead_open(&key, &nonce, b"aad", &sealed)?.as_slice() != b"plaintext" {
            return Err(CryptoError::SelfTest);
        }
        sealed[0] ^= 1;
        if self.aead_open(&key, &nonce, b"aad", &sealed).is_ok() {
            return Err(CryptoError::SelfTest);
        }
        // Sign and verify, and confirm that a changed message is refused.
        let identity = ed25519_from_seed(&[5u8; 32]);
        let signature = identity.sign(b"self test")?;
        self.verify(identity.public_key(), b"self test", &signature)
            .map_err(|_| CryptoError::SelfTest)?;
        if self
            .verify(identity.public_key(), b"self tesT", &signature)
            .is_ok()
        {
            return Err(CryptoError::SelfTest);
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        TESTONLY_MARKER
    }
}
