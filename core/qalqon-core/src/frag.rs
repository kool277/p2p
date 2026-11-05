//! Handshake fragmentation: `docs/PROTOCOL.md`, section 5.5.

use crate::wire::{HEADER_LEN, Header, Reader, WireError, Writer, msg};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// A receiver buffers at most this much per handshake.
pub const MAX_BUFFERED: usize = 32 * 1024;

const FRAGMENT_OVERHEAD: usize = HEADER_LEN + 5;

/// Splits a handshake message into frames of at most `max_frame` bytes. A message
/// that fits is returned unchanged.
pub fn fragment(frame: &[u8], max_frame: usize) -> Result<Vec<Vec<u8>>, WireError> {
    if frame.len() <= max_frame {
        return Ok(vec![frame.to_vec()]);
    }
    if max_frame <= FRAGMENT_OVERHEAD {
        return Err(WireError);
    }
    let header = Header::parse(frame)?;
    let body = &frame[HEADER_LEN..];
    let total_len = u16::try_from(body.len()).map_err(|_| WireError)?;
    let chunk_len = max_frame - FRAGMENT_OVERHEAD;
    let mut out = Vec::new();
    for (i, chunk) in body.chunks(chunk_len).enumerate() {
        let offset = u16::try_from(i * chunk_len).map_err(|_| WireError)?;
        let mut w = Writer::new();
        let length = u16::try_from(chunk.len() + 5).map_err(|_| WireError)?;
        w.bytes(
            &Header::handshake(header.version, header.suite_id, msg::HS_FRAGMENT, length).encode(),
        );
        w.u8(header.msg_type);
        w.u16(total_len);
        w.u16(offset);
        w.bytes(chunk);
        out.push(w.buf);
    }
    Ok(out)
}

#[derive(Debug)]
struct Partial {
    version: u8,
    suite_id: u16,
    total_len: u16,
    data: Vec<u8>,
    filled: Vec<bool>,
    missing: usize,
}

/// Reassembles fragmented handshake messages. Each completed message is the header
/// with `msg_type = inner_msg_type` and `length = total_len`, then the body, and
/// transcripts always use that form.
#[derive(Debug, Default)]
pub struct Reassembler {
    partials: BTreeMap<u8, Partial>,
}

impl Reassembler {
    /// A reassembler with nothing buffered.
    pub fn new() -> Self {
        Self::default()
    }

    fn buffered(&self) -> usize {
        self.partials.values().map(|p| p.data.len()).sum()
    }

    /// Adds one `HS_FRAGMENT`. Returns the whole message when the last byte arrives.
    pub fn push(&mut self, header: &Header, body: &[u8]) -> Result<Option<Vec<u8>>, WireError> {
        let mut r = Reader::new(body);
        let inner = r.u8()?;
        let total_len = r.u16()?;
        let offset = usize::from(r.u16()?);
        let fragment = r.rest();
        if !matches!(inner, msg::XX_INIT | msg::XX_RESP | msg::XX_FINISH) {
            return Err(WireError);
        }
        if offset + fragment.len() > usize::from(total_len) || fragment.is_empty() {
            return Err(WireError);
        }
        if !self.partials.contains_key(&inner) {
            if self.buffered() + usize::from(total_len) > MAX_BUFFERED {
                return Err(WireError);
            }
            self.partials.insert(
                inner,
                Partial {
                    version: header.version,
                    suite_id: header.suite_id,
                    total_len,
                    data: vec![0; usize::from(total_len)],
                    filled: vec![false; usize::from(total_len)],
                    missing: usize::from(total_len),
                },
            );
        }
        let partial = self.partials.get_mut(&inner).ok_or(WireError)?;
        if partial.total_len != total_len
            || partial.version != header.version
            || partial.suite_id != header.suite_id
        {
            return Err(WireError);
        }
        for (i, byte) in fragment.iter().enumerate() {
            let at = offset + i;
            if partial.filled[at] {
                if partial.data[at] != *byte {
                    return Err(WireError);
                }
            } else {
                partial.data[at] = *byte;
                partial.filled[at] = true;
                partial.missing -= 1;
            }
        }
        if partial.missing > 0 {
            return Ok(None);
        }
        let done = self.partials.remove(&inner).ok_or(WireError)?;
        let mut out = Vec::with_capacity(HEADER_LEN + done.data.len());
        out.extend_from_slice(
            &Header::handshake(done.version, done.suite_id, inner, total_len).encode(),
        );
        out.extend_from_slice(&done.data);
        Ok(Some(out))
    }
}
