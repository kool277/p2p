//! Encrypt-then-MAC from `docs/PROTOCOL.md`, section 9.2, for a library without
//! an AEAD mode. It composes a counter or gamma keystream with HMAC, using
//! independent keys:
//!
//! ```text
//! ciphertext = keystream(key, nonce) XOR plaintext
//! tag = HMAC(mac, u64(len(nonce)) || nonce || u64(len(aad)) || aad || ciphertext)
//! ```
//!
//! The nonce is authenticated too. A true AEAD binds its nonce, and without this a
//! changed nonce would pass the tag and decrypt to garbage, which matters wherever
//! the nonce travels with the ciphertext, as in key wrapping.
//!
//! The tag is verified in constant time before anything is decrypted.

use crate::{AeadKey, CryptoError, CryptoProvider, Secret, ct_eq};
use alloc::vec::Vec;

/// Applies a keystream to `buffer` in place. For CTR, each counter block is
/// `nonce || u32(block_index)`, with `block_index` starting at 0.
pub type Keystream<'a> = &'a dyn Fn(&[u8], &[u8], &mut [u8]) -> Result<(), CryptoError>;

fn tag<P: CryptoProvider + ?Sized>(
    p: &P,
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(16 + nonce.len() + aad.len() + ciphertext.len());
    input.extend_from_slice(&(nonce.len() as u64).to_be_bytes());
    input.extend_from_slice(nonce);
    input.extend_from_slice(&(aad.len() as u64).to_be_bytes());
    input.extend_from_slice(aad);
    input.extend_from_slice(ciphertext);
    p.mac(&key.mac, &input)
}

/// Seals `plaintext`, returning the ciphertext followed by the tag.
pub fn seal<P: CryptoProvider + ?Sized>(
    p: &P,
    keystream: Keystream<'_>,
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut out = Vec::with_capacity(plaintext.len() + p.params().tag_len);
    out.extend_from_slice(plaintext);
    keystream(&key.enc, nonce, &mut out)?;
    let t = tag(p, key, nonce, aad, &out);
    out.extend_from_slice(&t);
    Ok(out)
}

/// Opens `sealed`, verifying the tag before decrypting.
pub fn open<P: CryptoProvider + ?Sized>(
    p: &P,
    keystream: Keystream<'_>,
    key: &AeadKey,
    nonce: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Secret, CryptoError> {
    let tag_len = p.params().tag_len;
    if sealed.len() < tag_len {
        return Err(CryptoError::Verification);
    }
    let (ciphertext, received) = sealed.split_at(sealed.len() - tag_len);
    if !ct_eq(&tag(p, key, nonce, aad, ciphertext), received) {
        return Err(CryptoError::Verification);
    }
    let mut plaintext = Secret::new(ciphertext.to_vec());
    keystream(&key.enc, nonce, &mut plaintext)?;
    Ok(plaintext)
}
