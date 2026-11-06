//! The key schedule: `docs/PROTOCOL.md`, section 6. It follows RFC 8446, section 7.1.

use crate::wire::Writer;
use alloc::vec;
use alloc::vec::Vec;
use crypto_provider::{AeadKey, CryptoError, CryptoProvider, Secret};

const LABEL_PREFIX: &[u8] = b"qalqon0 ";

/// `ctx(name)` = `"qalqon0 " || name || 0x00`. It separates every signature and
/// chained hash by purpose.
pub fn ctx(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(LABEL_PREFIX.len() + name.len() + 1);
    out.extend_from_slice(LABEL_PREFIX);
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out
}

/// `HKDF-Expand-Label`.
pub fn expand_label(
    p: &dyn CryptoProvider,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Secret, CryptoError> {
    let length_u16 = u16::try_from(length).map_err(|_| CryptoError::InvalidInput)?;
    let mut prefixed = Vec::with_capacity(LABEL_PREFIX.len() + label.len());
    prefixed.extend_from_slice(LABEL_PREFIX);
    prefixed.extend_from_slice(label.as_bytes());
    let mut info = Writer::new();
    info.u16(length_u16);
    info.vec8(&prefixed)
        .map_err(|_| CryptoError::InvalidInput)?;
    info.vec8(context).map_err(|_| CryptoError::InvalidInput)?;
    p.hkdf_expand(secret, &info.buf, length)
}

/// `Derive-Secret`.
pub fn derive_secret(
    p: &dyn CryptoProvider,
    secret: &[u8],
    label: &str,
    transcript: &[u8],
) -> Result<Secret, CryptoError> {
    let hash = p.hash(transcript);
    expand_label(p, secret, label, &hash, p.params().hash_len)
}

/// `salt0` = `H(ctx("salt"))`.
pub fn salt0(p: &dyn CryptoProvider) -> Vec<u8> {
    p.hash(&ctx("salt"))
}

/// The keys derived from one traffic secret.
#[derive(Debug)]
pub struct TrafficKeys {
    /// `key` and `mac`.
    pub aead: AeadKey,
    /// `iv`.
    pub iv: Secret,
}

/// Derives `key`, `iv` and (without a library AEAD) `mac` from a traffic secret.
pub fn traffic_keys(p: &dyn CryptoProvider, secret: &[u8]) -> Result<TrafficKeys, CryptoError> {
    let params = p.params();
    let enc = expand_label(p, secret, "key", &[], params.key_len)?;
    let iv = expand_label(p, secret, "iv", &[], params.iv_len)?;
    let mac = if params.mac_key_len > 0 {
        expand_label(p, secret, "mac", &[], params.mac_key_len)?
    } else {
        Secret::new(Vec::new())
    };
    Ok(TrafficKeys {
        aead: AeadKey { enc, mac },
        iv,
    })
}

/// `fin`, for handshake secrets only.
pub fn finished_key(p: &dyn CryptoProvider, secret: &[u8]) -> Result<Secret, CryptoError> {
    expand_label(p, secret, "finished", &[], p.params().hash_len)
}

/// `S_next` = `HKDF-Expand-Label(S, "traffic upd", "", HashLen)`.
pub fn next_traffic_secret(p: &dyn CryptoProvider, secret: &[u8]) -> Result<Secret, CryptoError> {
    expand_label(p, secret, "traffic upd", &[], p.params().hash_len)
}

/// `nonce` = `iv XOR pad(direction || seq)`, section 9.1.
pub fn record_nonce(iv: &[u8], direction: u8, seq: u64) -> Vec<u8> {
    let mut nonce = vec![0u8; iv.len()];
    let offset = iv.len() - 9;
    nonce[offset] = direction;
    nonce[offset + 1..].copy_from_slice(&seq.to_be_bytes());
    for (n, i) in nonce.iter_mut().zip(iv) {
        *n ^= i;
    }
    nonce
}

/// `ms`, and the secrets derived from it once the transcript `T8` is known.
#[derive(Debug)]
pub struct ApplicationSecrets {
    /// `i_ap_0`.
    pub i_ap: Secret,
    /// `r_ap_0`.
    pub r_ap: Secret,
    /// `session_id`, safe to log.
    pub session_id: [u8; 16],
}

/// Derives the application secrets from `hs` and `T8`, section 7.2.
pub fn application_secrets(
    p: &dyn CryptoProvider,
    hs: &[u8],
    t8: &[u8],
) -> Result<ApplicationSecrets, CryptoError> {
    let hash_len = p.params().hash_len;
    let derived = derive_secret(p, hs, "derived", &[])?;
    let ms = p.hkdf_extract(&derived, &vec![0u8; hash_len]);
    let i_ap = derive_secret(p, &ms, "i ap", t8)?;
    let r_ap = derive_secret(p, &ms, "r ap", t8)?;
    let hash = p.hash(t8);
    let id = expand_label(p, &ms, "session id", &hash, 16)?;
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&id);
    Ok(ApplicationSecrets {
        i_ap,
        r_ap,
        session_id,
    })
}
