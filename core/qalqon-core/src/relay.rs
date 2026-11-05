//! Relay grants. A grant lets a client join a relay session for one rendezvous, and
//! a relay checks it with a key it shares with the server. The relay holds no
//! session keys and only forwards ciphertext (build prompt §1.1).
//!
//! This uses the provider's HMAC, because rule 0.4 keeps every key operation in `core/`.

use crate::wire::{Reader, WireError, Writer};
use alloc::vec::Vec;
use crypto_provider::{CryptoProvider, ct_eq};

fn input(rendezvous_id: &[u8; 16], expires_at: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(b"qalqon0 relay grant\0");
    w.bytes(rendezvous_id);
    w.u64(expires_at);
    w.buf
}

/// Issues the token for a grant: `u64 expires_at || HMAC(key, input)`.
pub fn issue_token(
    p: &dyn CryptoProvider,
    key: &[u8],
    rendezvous_id: &[u8; 16],
    expires_at: u64,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64(expires_at);
    w.bytes(&p.mac(key, &input(rendezvous_id, expires_at)));
    w.buf
}

/// Checks a token in constant time. A relay calls this before pairing two clients.
pub fn check_token(
    p: &dyn CryptoProvider,
    key: &[u8],
    rendezvous_id: &[u8; 16],
    token: &[u8],
    now_ms: u64,
) -> bool {
    let mut r = Reader::new(token);
    let Ok(expires_at) = r.u64() else {
        return false;
    };
    if now_ms > expires_at {
        return false;
    }
    ct_eq(&p.mac(key, &input(rendezvous_id, expires_at)), r.rest())
}

/// The first message a client sends to a relay: which rendezvous, and its grant.
pub fn encode_join(rendezvous_id: &[u8; 16], token: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new();
    w.bytes(rendezvous_id);
    w.vec8(token)?;
    Ok(w.buf)
}

/// Parses a relay join message.
pub fn parse_join(raw: &[u8]) -> Result<([u8; 16], &[u8]), WireError> {
    let mut r = Reader::new(raw);
    let id = r.array::<16>()?;
    let token = r.vec8()?;
    r.finish()?;
    Ok((id, token))
}
