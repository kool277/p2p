//! Certificate revocation lists: `docs/PROTOCOL.md`, section 11.5.

use crate::schedule::ctx;
use crate::wire::{Reader, WireError, Writer};
use alloc::vec::Vec;
use crypto_provider::{CryptoProvider, PublicKey, SigningKey};

/// `next_update` may be at most this far after `this_update`.
pub const MAX_VALIDITY_MS: u64 = 24 * 60 * 60 * 1000;

/// How long past `next_update` new data-plane sessions stay allowed, by default.
pub const DEFAULT_GRACE_MS: u64 = 72 * 60 * 60 * 1000;

/// A verified CRL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Crl {
    /// The issuing CA's key id.
    pub issuer_key_id: [u8; 16],
    /// When this CRL was issued.
    pub this_update: u64,
    /// When the next CRL is due.
    pub next_update: u64,
    /// The revoked serial numbers.
    pub revoked: Vec<[u8; 16]>,
}

fn signing_input(p: &dyn CryptoProvider, body: &[u8]) -> Vec<u8> {
    let mut input = ctx("crl");
    input.extend_from_slice(&p.hash(body));
    input
}

impl Crl {
    /// Encodes and signs this CRL.
    pub fn sign(
        &self,
        p: &dyn CryptoProvider,
        issuer: &dyn SigningKey,
    ) -> Result<Vec<u8>, CrlError> {
        let mut serials = Writer::new();
        for serial in &self.revoked {
            serials.bytes(serial);
        }
        let mut body = Writer::new();
        body.bytes(&self.issuer_key_id);
        body.u64(self.this_update);
        body.u64(self.next_update);
        body.vec16(&serials.buf)?;
        let signature = issuer
            .sign(&signing_input(p, &body.buf))
            .map_err(|_| CrlError::Signature)?;
        let mut out = Writer::new();
        out.vec16(&body.buf)?;
        out.vec16(&signature)?;
        Ok(out.buf)
    }

    /// Parses a CRL and verifies its signature against the issuing CA's key.
    pub fn verify(p: &dyn CryptoProvider, issuer: &PublicKey, raw: &[u8]) -> Result<Crl, CrlError> {
        let mut outer = Reader::new(raw);
        let body = outer.vec16()?;
        let signature = outer.vec16()?;
        outer.finish()?;
        p.verify(issuer, &signing_input(p, body), signature)
            .map_err(|_| CrlError::Signature)?;

        let mut r = Reader::new(body);
        let issuer_key_id = r.array::<16>()?;
        let this_update = r.u64()?;
        let next_update = r.u64()?;
        let serials = r.vec16()?;
        r.finish()?;
        if serials.len() % 16 != 0
            || next_update < this_update
            || next_update - this_update > MAX_VALIDITY_MS
        {
            return Err(CrlError::Malformed);
        }
        let mut revoked = Vec::with_capacity(serials.len() / 16);
        for chunk in serials.chunks_exact(16) {
            let mut serial = [0u8; 16];
            serial.copy_from_slice(chunk);
            revoked.push(serial);
        }
        Ok(Crl {
            issuer_key_id,
            this_update,
            next_update,
            revoked,
        })
    }

    /// True if `serial` is revoked.
    pub fn is_revoked(&self, serial: &[u8; 16]) -> bool {
        self.revoked.iter().any(|s| s == serial)
    }

    /// True if new data-plane sessions must fail with `revocationDataStale`.
    pub fn is_stale(&self, now_ms: u64, grace_ms: u64) -> bool {
        now_ms > self.next_update.saturating_add(grace_ms)
    }
}

/// A client's cached CRL.
#[derive(Clone, Debug, Default)]
pub struct CrlCache {
    current: Option<Crl>,
}

impl CrlCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The cached CRL.
    pub fn current(&self) -> Option<&Crl> {
        self.current.as_ref()
    }

    /// Installs a verified CRL. One older than the cached CRL is rejected, so a
    /// server cannot roll a revocation back.
    pub fn update(&mut self, crl: Crl) -> Result<(), CrlError> {
        if let Some(current) = &self.current
            && crl.issuer_key_id == current.issuer_key_id
            && crl.this_update < current.this_update
        {
            return Err(CrlError::Rollback);
        }
        self.current = Some(crl);
        Ok(())
    }

    /// Checks a data-plane peer. A missing CRL counts as stale, because a server can
    /// withhold a CRL but cannot forge one.
    pub fn check_data_plane(
        &self,
        serial: &[u8; 16],
        now_ms: u64,
        grace_ms: u64,
    ) -> Result<(), CrlError> {
        let crl = self.current.as_ref().ok_or(CrlError::Stale)?;
        if crl.is_revoked(serial) {
            return Err(CrlError::Revoked);
        }
        if crl.is_stale(now_ms, grace_ms) {
            return Err(CrlError::Stale);
        }
        Ok(())
    }
}

/// A CRL failed to parse or apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrlError {
    /// Not a well-formed CRL.
    Malformed,
    /// The signature did not verify.
    Signature,
    /// Older than the cached CRL.
    Rollback,
    /// The serial is revoked.
    Revoked,
    /// The cached CRL is missing or too old.
    Stale,
}

impl From<WireError> for CrlError {
    fn from(_: WireError) -> Self {
        CrlError::Malformed
    }
}
