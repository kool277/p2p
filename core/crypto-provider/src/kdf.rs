//! HMAC (RFC 2104) and HKDF-Expand (RFC 5869) over any hash.
//!
//! Tested against the RFC 4231 and RFC 5869 vectors in `core/provider-testonly`.

use crate::{CryptoError, Secret, Zeroizing};
use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn hmac(
    hash: &dyn Fn(&[u8]) -> Vec<u8>,
    block_len: usize,
    key: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut block = Zeroizing::new(vec![0u8; block_len]);
    if key.len() > block_len {
        let digest = Zeroizing::new(hash(key));
        block[..digest.len()].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Zeroizing::new(Vec::with_capacity(block_len + data.len()));
    inner.extend(block.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(data);
    let inner_hash = Zeroizing::new(hash(&inner));

    let mut outer = Zeroizing::new(Vec::with_capacity(block_len + inner_hash.len()));
    outer.extend(block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    hash(&outer)
}

type MacFn<'a> = &'a dyn Fn(&[u8], &[u8]) -> Vec<u8>;

pub(crate) fn hkdf_expand(
    mac: MacFn<'_>,
    hash_len: usize,
    prk: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Secret, CryptoError> {
    if len > 255 * hash_len {
        return Err(CryptoError::InvalidInput);
    }
    let mut okm = Zeroizing::new(Vec::with_capacity(len + hash_len));
    let mut previous: Secret = Zeroizing::new(Vec::new());
    let mut counter = 1u8;
    while okm.len() < len {
        let mut input = Zeroizing::new(Vec::with_capacity(previous.len() + info.len() + 1));
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);
        previous = Zeroizing::new(mac(prk, &input));
        okm.extend_from_slice(&previous);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(len);
    Ok(okm)
}
