//! Byte-level encoding: `docs/PROTOCOL.md`, section 5.

use alloc::vec::Vec;

/// The frame magic, "QL".
pub const MAGIC: [u8; 2] = [0x51, 0x4C];
/// The header is always this long.
pub const HEADER_LEN: usize = 18;
/// `hdr16`: the header without `length`.
pub const HDR16_LEN: usize = 16;
/// Protocol version 0.1: high nibble major, low nibble minor.
pub const VERSION_0_1: u8 = 0x01;
/// The largest value of `length`.
pub const MAX_BODY: usize = u16::MAX as usize;
/// The largest frame.
pub const MAX_FRAME: usize = HEADER_LEN + MAX_BODY;

/// Message types, section 5.2.
pub mod msg {
    #![allow(missing_docs)]
    pub const XX_INIT: u8 = 0x01;
    pub const XX_RESP: u8 = 0x02;
    pub const XX_FINISH: u8 = 0x03;
    pub const HS_REJECT: u8 = 0x04;
    pub const HS_FRAGMENT: u8 = 0x05;
    pub const RECORD: u8 = 0x10;
}

/// Extension types, section 5.4.
pub mod ext {
    #![allow(missing_docs)]
    pub const PADDING: u16 = 0x0003;
    pub const KNOWN_RESPONDER: u16 = 0x0004;
    pub const SESSION_ROLE: u16 = 0x8001;
    pub const RENDEZVOUS_ID: u16 = 0x8002;
}

/// Inner plaintext types, section 9.6.
pub mod inner {
    #![allow(missing_docs)]
    pub const DATA: u8 = 0x01;
    pub const KEY_UPDATE: u8 = 0x02;
    pub const KEY_CONFIRM: u8 = 0x03;
    pub const CHANNEL_OPEN: u8 = 0x04;
    pub const CHANNEL_ACCEPT: u8 = 0x05;
    pub const CHANNEL_REJECT: u8 = 0x06;
    pub const CHANNEL_CLOSE: u8 = 0x07;
    pub const PING: u8 = 0x08;
    pub const PONG: u8 = 0x09;
    pub const CLOSE: u8 = 0x0A;
    pub const CONTROL: u8 = 0x20;
}

/// `reason` codes, section 9.6.
pub mod reason {
    #![allow(missing_docs)]
    pub const NORMAL: u16 = 0;
    pub const PROTOCOL_ERROR: u16 = 1;
    pub const TRANSPORT_UNSUPPORTED: u16 = 2;
    pub const MESSAGE_TOO_LARGE: u16 = 3;
    pub const REJECTED: u16 = 4;
    pub const TIMEOUT: u16 = 5;
    pub const INTERNAL_ERROR: u16 = 6;
}

/// Handshake rejection codes, section 13.
pub mod reject {
    #![allow(missing_docs)]
    pub const UNSUPPORTED_VERSION: u16 = 1;
    pub const UNSUPPORTED_SUITE: u16 = 2;
    pub const BUSY: u16 = 3;
}

/// A frame or field is malformed. Deliberately carries no detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireError;

/// The fixed frame header, section 5.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// `version`.
    pub version: u8,
    /// `suite_id`.
    pub suite_id: u16,
    /// `msg_type`.
    pub msg_type: u8,
    /// `channel_id`.
    pub channel_id: u16,
    /// `seq`.
    pub seq: u64,
    /// `length`: bytes following the header.
    pub length: u16,
}

impl Header {
    /// A handshake header, whose `channel_id` and `seq` are 0.
    pub fn handshake(version: u8, suite_id: u16, msg_type: u8, length: u16) -> Self {
        Header {
            version,
            suite_id,
            msg_type,
            channel_id: 0,
            seq: 0,
            length,
        }
    }

    /// Encodes all 18 bytes.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..2].copy_from_slice(&MAGIC);
        out[2] = self.version;
        out[3..5].copy_from_slice(&self.suite_id.to_be_bytes());
        out[5] = self.msg_type;
        out[6..8].copy_from_slice(&self.channel_id.to_be_bytes());
        out[8..16].copy_from_slice(&self.seq.to_be_bytes());
        out[16..18].copy_from_slice(&self.length.to_be_bytes());
        out
    }

    /// `hdr16`: the first 16 bytes, used in transcripts.
    pub fn hdr16(&self) -> [u8; HDR16_LEN] {
        let full = self.encode();
        let mut out = [0u8; HDR16_LEN];
        out.copy_from_slice(&full[..HDR16_LEN]);
        out
    }

    /// Parses a header, checking `magic` and `msg_type`.
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < HEADER_LEN || bytes[0..2] != MAGIC {
            return Err(WireError);
        }
        let msg_type = bytes[5];
        if !matches!(
            msg_type,
            msg::XX_INIT
                | msg::XX_RESP
                | msg::XX_FINISH
                | msg::HS_REJECT
                | msg::HS_FRAGMENT
                | msg::RECORD
        ) {
            return Err(WireError);
        }
        Ok(Header {
            version: bytes[2],
            suite_id: u16::from_be_bytes([bytes[3], bytes[4]]),
            msg_type,
            channel_id: u16::from_be_bytes([bytes[6], bytes[7]]),
            seq: u64::from_be_bytes(bytes[8..16].try_into().map_err(|_| WireError)?),
            length: u16::from_be_bytes([bytes[16], bytes[17]]),
        })
    }
}

/// Parses a whole frame. Trailing bytes after `length`, or too few, are invalid.
pub fn parse_frame(frame: &[u8]) -> Result<(Header, &[u8]), WireError> {
    let header = Header::parse(frame)?;
    let body = &frame[HEADER_LEN..];
    if body.len() != usize::from(header.length) {
        return Err(WireError);
    }
    Ok((header, body))
}

/// Splits a byte stream into frames, for TCP and QUIC streams (section 5.3).
#[derive(Clone, Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    /// A decoder with nothing buffered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes read from the stream.
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Returns the next complete frame, if there is one. An error means the stream
    /// is corrupt and the connection should be closed.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, WireError> {
        if self.buffer.len() >= 2 && self.buffer[0..2] != MAGIC {
            return Err(WireError);
        }
        if self.buffer.len() < HEADER_LEN {
            return Ok(None);
        }
        let header = Header::parse(&self.buffer)?;
        let total = HEADER_LEN + usize::from(header.length);
        if self.buffer.len() < total {
            return Ok(None);
        }
        let rest = self.buffer.split_off(total);
        Ok(Some(core::mem::replace(&mut self.buffer, rest)))
    }
}

/// Reads big-endian fields from a buffer.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Starts at the beginning of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// True if everything has been read.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Reads `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if n > self.remaining() {
            return Err(WireError);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Reads a `u8`.
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    /// Reads a `u16`.
    pub fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Reads a `u32`.
    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a `u64`.
    pub fn u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// Reads a `vec8`.
    pub fn vec8(&mut self) -> Result<&'a [u8], WireError> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    /// Reads a `vec16`.
    pub fn vec16(&mut self) -> Result<&'a [u8], WireError> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }

    /// Reads a fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Reads everything left.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }

    /// Fails unless everything has been read.
    pub fn finish(&self) -> Result<(), WireError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(WireError)
        }
    }
}

/// Writes big-endian fields into a buffer.
#[derive(Clone, Debug, Default)]
pub struct Writer {
    /// The bytes written so far.
    pub buf: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Writes raw bytes.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Writes a `u8`.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Writes a `u16`.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    /// Writes a `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    /// Writes a `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    /// Writes a `vec8`, failing if `b` is too long.
    pub fn vec8(&mut self, b: &[u8]) -> Result<&mut Self, WireError> {
        let n = u8::try_from(b.len()).map_err(|_| WireError)?;
        self.u8(n);
        Ok(self.bytes(b))
    }

    /// Writes a `vec16`, failing if `b` is too long.
    pub fn vec16(&mut self, b: &[u8]) -> Result<&mut Self, WireError> {
        let n = u16::try_from(b.len()).map_err(|_| WireError)?;
        self.u16(n);
        Ok(self.bytes(b))
    }
}

/// One parsed extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extension<'a> {
    /// `type`. Bit 15 marks it critical.
    pub ty: u16,
    /// The value.
    pub value: &'a [u8],
}

impl Extension<'_> {
    /// True if an unknown extension of this type must fail the handshake.
    pub fn is_critical(&self) -> bool {
        self.ty & 0x8000 != 0
    }
}

/// Parses an extension list, requiring ascending `type` with no duplicates, so each
/// set has exactly one encoding.
pub fn parse_extensions(raw: &[u8]) -> Result<Vec<Extension<'_>>, WireError> {
    let mut reader = Reader::new(raw);
    let mut out: Vec<Extension<'_>> = Vec::new();
    while !reader.is_empty() {
        let ty = reader.u16()?;
        let value = reader.vec16()?;
        if let Some(last) = out.last()
            && last.ty >= ty
        {
            return Err(WireError);
        }
        out.push(Extension { ty, value });
    }
    Ok(out)
}

/// Encodes an extension list, sorting by `type`. Duplicates are an error.
pub fn encode_extensions(mut list: Vec<(u16, Vec<u8>)>) -> Result<Vec<u8>, WireError> {
    list.sort_by_key(|(ty, _)| *ty);
    let mut w = Writer::new();
    let mut last = None;
    for (ty, value) in &list {
        if last == Some(*ty) {
            return Err(WireError);
        }
        last = Some(*ty);
        w.u16(*ty);
        w.vec16(value)?;
    }
    Ok(w.buf)
}

/// Finds an extension by type.
pub fn find_extension<'a>(list: &[Extension<'a>], ty: u16) -> Option<&'a [u8]> {
    list.iter().find(|e| e.ty == ty).map(|e| e.value)
}
