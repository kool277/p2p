//! The record layer: `docs/PROTOCOL.md`, section 9.

use crate::schedule::{next_traffic_secret, record_nonce, traffic_keys};
use crate::session::Limits;
use crate::wire::{HEADER_LEN, Header, msg};
use alloc::sync::Arc;
use alloc::vec::Vec;
use crypto_provider::{AeadKey, CryptoError, CryptoProvider, Secret, Zeroizing};

const COUNTER_BITS: u32 = 48;
const COUNTER_MASK: u64 = (1 << COUNTER_BITS) - 1;
const WINDOW_BITS: u64 = 1024;
const WINDOW_WORDS: usize = (WINDOW_BITS / 64) as usize;
/// Lossy receivers accept up to this many epochs ahead (section 9.4).
pub const MAX_EPOCHS_AHEAD: u16 = 16;

/// A record was refused. Nothing here reaches the peer, and the reasons stay local.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The header's version or suite is wrong.
    Header,
    /// No key for this epoch.
    Epoch,
    /// A replay, or too old for the window, or (on a strict transport) out of order.
    Sequence,
    /// The tag did not verify.
    Open,
    /// The sequence or epoch space is used up, so a new handshake is needed.
    Exhausted,
    /// A provider operation failed.
    Crypto(CryptoError),
}

impl From<CryptoError> for RecordError {
    fn from(e: CryptoError) -> Self {
        RecordError::Crypto(e)
    }
}

/// The 1,024-entry replay window (section 9.4). `counter` runs for the whole session,
/// so one window serves every epoch.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    /// One past the highest counter seen.
    top: u64,
    bits: [u64; WINDOW_WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow {
            top: 0,
            bits: [0; WINDOW_WORDS],
        }
    }
}

impl ReplayWindow {
    fn index(counter: u64) -> (usize, u64) {
        let slot = counter % WINDOW_BITS;
        ((slot / 64) as usize, 1u64 << (slot % 64))
    }

    /// True if `counter` is new and inside the window.
    pub fn check(&self, counter: u64) -> bool {
        if counter >= self.top {
            return true;
        }
        if self.top - counter > WINDOW_BITS {
            return false;
        }
        let (word, mask) = Self::index(counter);
        self.bits[word] & mask == 0
    }

    /// Records `counter`. Call this only after the record has opened.
    pub fn update(&mut self, counter: u64) {
        if counter >= self.top {
            let advance = counter + 1 - self.top;
            if advance >= WINDOW_BITS {
                self.bits = [0; WINDOW_WORDS];
            } else {
                for c in self.top..=counter {
                    let (word, mask) = Self::index(c);
                    self.bits[word] &= !mask;
                }
            }
            self.top = counter + 1;
        }
        let (word, mask) = Self::index(counter);
        self.bits[word] |= mask;
    }
}

struct Keys {
    secret: Secret,
    aead: AeadKey,
    iv: Secret,
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Keys(..)")
    }
}

impl Keys {
    fn derive(p: &dyn CryptoProvider, secret: Secret) -> Result<Self, CryptoError> {
        let t = traffic_keys(p, &secret)?;
        Ok(Keys {
            secret,
            aead: t.aead,
            iv: t.iv,
        })
    }

    fn next(&self, p: &dyn CryptoProvider) -> Result<Self, CryptoError> {
        Self::derive(p, next_traffic_secret(p, &self.secret)?)
    }
}

#[derive(Debug)]
struct Retained {
    epoch: u16,
    aead: AeadKey,
    iv: Secret,
    expires_at: u64,
}

/// One session's traffic protection.
pub struct RecordLayer {
    provider: Arc<dyn CryptoProvider>,
    version: u8,
    suite: u16,
    strict: bool,
    send_direction: u8,
    recv_direction: u8,
    limits: Limits,

    send: Option<Keys>,
    send_epoch: u16,
    send_counter: u64,
    send_records: u64,
    send_bytes: u64,
    send_epoch_started: u64,

    recv: Keys,
    recv_epoch: u16,
    next_counter: u64,
    window: ReplayWindow,
    retained: Vec<Retained>,
    recv_records: u64,
    recv_bytes: u64,
}

impl core::fmt::Debug for RecordLayer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecordLayer")
            .field("send_epoch", &self.send_epoch)
            .field("recv_epoch", &self.recv_epoch)
            .finish_non_exhaustive()
    }
}

/// What opening a record found.
#[derive(Debug)]
pub struct Opened {
    /// The inner plaintext: `inner_type`, then the body.
    pub plaintext: Secret,
    /// The record's epoch.
    pub epoch: u16,
    /// True if this record moved the receive epoch forward.
    pub epoch_advanced: bool,
}

impl RecordLayer {
    /// Creates the record layer from `i_ap_0` and `r_ap_0`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: Arc<dyn CryptoProvider>,
        version: u8,
        suite: u16,
        strict: bool,
        is_initiator: bool,
        i_ap: Secret,
        r_ap: Secret,
        limits: Limits,
        now_ms: u64,
    ) -> Result<Self, CryptoError> {
        let i_keys = Keys::derive(provider.as_ref(), i_ap)?;
        let r_keys = Keys::derive(provider.as_ref(), r_ap)?;
        let (send, recv) = if is_initiator {
            (i_keys, r_keys)
        } else {
            (r_keys, i_keys)
        };
        Ok(RecordLayer {
            provider,
            version,
            suite,
            strict,
            send_direction: u8::from(!is_initiator),
            recv_direction: u8::from(is_initiator),
            limits,
            send: Some(send),
            send_epoch: 0,
            send_counter: 0,
            send_records: 0,
            send_bytes: 0,
            send_epoch_started: now_ms,
            recv,
            recv_epoch: 0,
            next_counter: 0,
            window: ReplayWindow::default(),
            retained: Vec::new(),
            recv_records: 0,
            recv_bytes: 0,
        })
    }

    /// The current send epoch.
    pub fn send_epoch(&self) -> u16 {
        self.send_epoch
    }

    /// The current receive epoch.
    pub fn recv_epoch(&self) -> u16 {
        self.recv_epoch
    }

    /// True while send keys exist.
    pub fn can_send(&self) -> bool {
        self.send.is_some()
    }

    /// Zeroizes the send keys, after sending `CLOSE`.
    pub fn drop_send_keys(&mut self) {
        self.send = None;
    }

    /// True if the send direction must rotate before sending `upcoming` more
    /// plaintext bytes. One record of headroom is kept for `KEY_UPDATE` itself.
    pub fn must_rotate(&self, now_ms: u64, upcoming: usize) -> bool {
        if now_ms.saturating_sub(self.send_epoch_started) >= self.limits.rekey_ms {
            return true;
        }
        // A fresh epoch has nothing to gain from rotating again.
        self.send_records > 0
            && (self.send_records + 2 > self.limits.rekey_records
                || self.send_bytes.saturating_add(upcoming as u64 + 2) > self.limits.rekey_bytes)
    }

    /// When the send direction must rotate if nothing else happens.
    pub fn rotate_deadline(&self) -> u64 {
        self.send_epoch_started.saturating_add(self.limits.rekey_ms)
    }

    /// True if the peer has gone past twice a limit in this epoch (section 9.5).
    pub fn peer_exceeded_limits(&self) -> bool {
        self.recv_records > self.limits.rekey_records.saturating_mul(2)
            || self.recv_bytes > self.limits.rekey_bytes.saturating_mul(2)
    }

    /// Seals one record.
    pub fn seal(&mut self, channel_id: u16, plaintext: &[u8]) -> Result<Vec<u8>, RecordError> {
        let p = self.provider.clone();
        let keys = self.send.as_ref().ok_or(RecordError::Exhausted)?;
        if self.send_counter > COUNTER_MASK {
            return Err(RecordError::Exhausted);
        }
        let seq = (u64::from(self.send_epoch) << COUNTER_BITS) | self.send_counter;
        let length = plaintext.len() + p.params().tag_len;
        let header = Header {
            version: self.version,
            suite_id: self.suite,
            msg_type: msg::RECORD,
            channel_id,
            seq,
            length: u16::try_from(length).map_err(|_| RecordError::Exhausted)?,
        };
        let encoded = header.encode();
        let nonce = record_nonce(&keys.iv, self.send_direction, seq);
        let sealed = p.aead_seal(&keys.aead, &nonce, &encoded, plaintext)?;
        let mut frame = Vec::with_capacity(HEADER_LEN + sealed.len());
        frame.extend_from_slice(&encoded);
        frame.extend_from_slice(&sealed);
        self.send_counter += 1;
        self.send_records += 1;
        self.send_bytes += plaintext.len() as u64;
        Ok(frame)
    }

    /// Moves the send direction to the next epoch and zeroizes the old keys at once.
    /// The caller has already sent `KEY_UPDATE` as the last record under them.
    pub fn rotate_send(&mut self, now_ms: u64) -> Result<u16, RecordError> {
        if self.send_epoch == u16::MAX {
            return Err(RecordError::Exhausted);
        }
        let keys = self.send.as_ref().ok_or(RecordError::Exhausted)?;
        self.send = Some(keys.next(self.provider.as_ref())?);
        self.send_epoch += 1;
        self.send_records = 0;
        self.send_bytes = 0;
        self.send_epoch_started = now_ms;
        Ok(self.send_epoch)
    }

    /// Moves the receive direction forward after opening `KEY_UPDATE` in the current
    /// epoch. A strict receiver keeps no old keys.
    pub fn advance_recv(&mut self, now_ms: u64) -> Result<(), RecordError> {
        if self.recv_epoch == u16::MAX {
            return Err(RecordError::Exhausted);
        }
        let next = self.recv.next(self.provider.as_ref())?;
        self.commit_epochs(alloc::vec![next], now_ms);
        Ok(())
    }

    fn commit_epochs(&mut self, forward: Vec<Keys>, now_ms: u64) {
        let expires_at = now_ms.saturating_add(self.limits.old_key_retention_ms);
        for keys in forward {
            let old = core::mem::replace(&mut self.recv, keys);
            if !self.strict {
                self.retained.push(Retained {
                    epoch: self.recv_epoch,
                    aead: old.aead,
                    iv: old.iv,
                    expires_at,
                });
            }
            self.recv_epoch += 1;
        }
        self.recv_records = 0;
        self.recv_bytes = 0;
    }

    /// Erases retained keys whose time is up.
    pub fn expire_retained(&mut self, now_ms: u64) {
        self.retained.retain(|r| r.expires_at > now_ms);
    }

    /// When the next retained key expires.
    pub fn next_retained_expiry(&self) -> Option<u64> {
        self.retained.iter().map(|r| r.expires_at).min()
    }

    /// Opens one record, following the steps in section 9.4. State changes only
    /// after the record has opened.
    pub fn open(
        &mut self,
        header: &Header,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Opened, RecordError> {
        if header.version != self.version
            || header.suite_id != self.suite
            || header.msg_type != msg::RECORD
        {
            return Err(RecordError::Header);
        }
        self.expire_retained(now_ms);
        let epoch = (header.seq >> COUNTER_BITS) as u16;
        let counter = header.seq & COUNTER_MASK;

        if self.strict {
            if epoch != self.recv_epoch {
                return Err(RecordError::Epoch);
            }
            if counter != self.next_counter {
                return Err(RecordError::Sequence);
            }
        } else if !self.window.check(counter) {
            return Err(RecordError::Sequence);
        }

        let p = self.provider.clone();
        let nonce_for = |iv: &[u8]| record_nonce(iv, self.recv_direction, header.seq);
        let aad = &frame[..HEADER_LEN];
        let sealed = &frame[HEADER_LEN..];
        let mut forward: Vec<Keys> = Vec::new();
        let plaintext: Zeroizing<Vec<u8>> = if epoch == self.recv_epoch {
            p.aead_open(&self.recv.aead, &nonce_for(&self.recv.iv), aad, sealed)
                .map_err(|_| RecordError::Open)?
        } else if epoch < self.recv_epoch {
            let old = self
                .retained
                .iter()
                .find(|r| r.epoch == epoch)
                .ok_or(RecordError::Epoch)?;
            p.aead_open(&old.aead, &nonce_for(&old.iv), aad, sealed)
                .map_err(|_| RecordError::Open)?
        } else {
            let ahead = epoch - self.recv_epoch;
            if ahead > MAX_EPOCHS_AHEAD {
                return Err(RecordError::Epoch);
            }
            forward.push(self.recv.next(p.as_ref())?);
            for _ in 1..ahead {
                let next = forward[forward.len() - 1].next(p.as_ref())?;
                forward.push(next);
            }
            let keys = &forward[forward.len() - 1];
            p.aead_open(&keys.aead, &nonce_for(&keys.iv), aad, sealed)
                .map_err(|_| RecordError::Open)?
        };

        let epoch_advanced = !forward.is_empty();
        if self.strict {
            self.next_counter += 1;
        } else {
            self.window.update(counter);
        }
        if epoch_advanced {
            self.commit_epochs(forward, now_ms);
        }
        self.recv_records += 1;
        self.recv_bytes += plaintext.len() as u64;
        Ok(Opened {
            plaintext,
            epoch,
            epoch_advanced,
        })
    }
}
