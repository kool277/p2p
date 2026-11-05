//! Primitives outside the certified boundary, each behind its own feature
//! (ADR-0001 and `docs/crypto-inventory.md`). Nothing here protects a record.
//! X25519 and ML-KEM-768 only feed the key schedule, and Argon2id only checks
//! passwords inside `server-core`.
//!
//! All randomness is passed in, so the caller's CSPRNG stays in charge and test
//! vectors stay deterministic.
#![forbid(unsafe_code)]

#[cfg(feature = "x25519")]
pub mod x25519 {
    //! X25519 (RFC 7748).
    use crypto_provider::{CryptoError, Secret, Zeroizing};
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Share length in bytes.
    pub const SHARE_LEN: usize = 32;

    /// Derives the secret and public share from 32 random bytes.
    pub fn keygen(random: [u8; 32]) -> (Secret, Vec<u8>) {
        let secret = StaticSecret::from(random);
        let public = PublicKey::from(&secret);
        (
            Zeroizing::new(secret.to_bytes().to_vec()),
            public.to_bytes().to_vec(),
        )
    }

    /// Computes the shared secret, rejecting a non-contributory (all-zero)
    /// result as RFC 7748, section 6.1 requires.
    pub fn agree(own: &[u8], peer_share: &[u8]) -> Result<Secret, CryptoError> {
        let own: [u8; 32] = own.try_into().map_err(|_| CryptoError::InvalidInput)?;
        let peer: [u8; 32] = peer_share
            .try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        let shared = StaticSecret::from(own).diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(CryptoError::Verification);
        }
        Ok(Zeroizing::new(shared.to_bytes().to_vec()))
    }
}

#[cfg(feature = "ml-kem")]
pub mod ml_kem_768 {
    //! ML-KEM-768 (FIPS 203).
    use crypto_provider::{CryptoError, Secret, Zeroizing};
    use ml_kem::{
        DecapsulationKey, EncapsulationKey, Key, MlKem768, Seed,
        kem::{Decapsulate, KeyExport},
    };

    /// The initiator's share: an encapsulation key.
    pub const EK_LEN: usize = 1184;
    /// The responder's share: a ciphertext.
    pub const CT_LEN: usize = 1088;

    /// Derives the decapsulation seed and encapsulation key from 64 random bytes.
    pub fn keygen(random: &[u8; 64]) -> (Secret, Vec<u8>) {
        let seed: Seed = (*random).into();
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed);
        let ek = dk.encapsulation_key().to_bytes();
        (Zeroizing::new(random.to_vec()), ek.as_slice().to_vec())
    }

    /// Encapsulates to `ek`. Invalid keys are rejected, which applies the
    /// encapsulation key check in FIPS 203.
    pub fn encapsulate(ek: &[u8], random: &[u8; 32]) -> Result<(Vec<u8>, Secret), CryptoError> {
        if ek.len() != EK_LEN {
            return Err(CryptoError::InvalidInput);
        }
        let key = Key::<EncapsulationKey<MlKem768>>::try_from(ek)
            .map_err(|_| CryptoError::InvalidInput)?;
        let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| CryptoError::InvalidInput)?;
        let (ct, shared) = ek.encapsulate_deterministic(&(*random).into());
        Ok((
            ct.as_slice().to_vec(),
            Zeroizing::new(shared.as_slice().to_vec()),
        ))
    }

    /// Decapsulates `ciphertext` using the seed from [`keygen`].
    pub fn decapsulate(seed: &[u8], ciphertext: &[u8]) -> Result<Secret, CryptoError> {
        if ciphertext.len() != CT_LEN {
            return Err(CryptoError::InvalidInput);
        }
        let seed: [u8; 64] = seed.try_into().map_err(|_| CryptoError::InvalidInput)?;
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed.into());
        let ct = ciphertext
            .try_into()
            .map_err(|_| CryptoError::InvalidInput)?;
        let shared = dk.decapsulate(&ct);
        Ok(Zeroizing::new(shared.as_slice().to_vec()))
    }
}

#[cfg(feature = "argon2id")]
pub mod argon2id {
    //! Argon2id password hashing (RFC 9106), used only by `server-core`.
    use argon2::{Algorithm, Argon2, Params, Version};
    use crypto_provider::{CryptoError, ct_eq};

    /// Cost parameters. These travel with each stored hash, so they can be raised later.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Cost {
        /// Memory in KiB.
        pub m_kib: u32,
        /// Passes.
        pub t: u32,
        /// Lanes.
        pub p: u32,
    }

    impl Default for Cost {
        /// RFC 9106's second recommended option.
        fn default() -> Self {
            Cost {
                m_kib: 64 * 1024,
                t: 3,
                p: 1,
            }
        }
    }

    fn derive(password: &[u8], salt: &[u8], cost: Cost) -> Result<[u8; 32], CryptoError> {
        let params = Params::new(cost.m_kib, cost.t, cost.p, Some(32))
            .map_err(|_| CryptoError::InvalidInput)?;
        let mut out = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password, salt, &mut out)
            .map_err(|_| CryptoError::InvalidInput)?;
        Ok(out)
    }

    /// Hashes `password` with a random 16-byte `salt`, returning
    /// `m_kib$t$p$salt-hex$hash-hex`, which the host stores as an opaque value.
    pub fn hash(password: &[u8], salt: &[u8; 16], cost: Cost) -> Result<String, CryptoError> {
        let out = derive(password, salt, cost)?;
        Ok(format!(
            "{}${}${}${}${}",
            cost.m_kib,
            cost.t,
            cost.p,
            crypto_provider::to_hex(salt),
            crypto_provider::to_hex(&out)
        ))
    }

    /// Checks `password` against a value from [`hash`], in constant time.
    pub fn verify(password: &[u8], stored: &str) -> Result<bool, CryptoError> {
        let mut parts = stored.split('$');
        let mut number = || {
            parts
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .ok_or(CryptoError::InvalidInput)
        };
        let cost = Cost {
            m_kib: number()?,
            t: number()?,
            p: number()?,
        };
        let mut parts = stored.splitn(5, '$').skip(3);
        let salt = parts
            .next()
            .and_then(crypto_provider::from_hex)
            .ok_or(CryptoError::InvalidInput)?;
        let expected = parts
            .next()
            .and_then(crypto_provider::from_hex)
            .ok_or(CryptoError::InvalidInput)?;
        let out = derive(password, &salt, cost)?;
        Ok(ct_eq(&out, &expected))
    }
}
