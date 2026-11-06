//! Control plane messages: `docs/PROTOCOL.md`, section 12. The body of a `CONTROL`
//! record is `u16 control_type`, then fields encoded as extensions.

use crate::wire::{Reader, WireError, Writer, encode_extensions, parse_extensions};
use alloc::string::String;
use alloc::vec::Vec;

/// `control_type` values.
pub mod kind {
    #![allow(missing_docs)]
    pub const ENROLL_REQUEST: u16 = 0x0001;
    pub const ENROLL_RESULT: u16 = 0x0002;
    pub const LOGIN_REQUEST: u16 = 0x0003;
    pub const LOGIN_RESULT: u16 = 0x0004;
    pub const RENDEZVOUS_OPEN: u16 = 0x0005;
    pub const RENDEZVOUS_INCOMING: u16 = 0x0006;
    pub const RENDEZVOUS_ACCEPT: u16 = 0x0007;
    pub const RENDEZVOUS_REJECT: u16 = 0x0008;
    pub const RENDEZVOUS_READY: u16 = 0x0009;
    pub const PEER_SIGNAL: u16 = 0x000A;
    pub const CRL_REQUEST: u16 = 0x000B;
    pub const CRL_RESPONSE: u16 = 0x000C;
    pub const CERT_RENEW_REQUEST: u16 = 0x000D;
    pub const CERT_RENEW_RESULT: u16 = 0x000E;
    pub const SESSION_REPORT: u16 = 0x000F;
}

/// Field `type` values.
pub mod field {
    #![allow(missing_docs)]
    pub const REQUEST_ID: u16 = 0x8101;
    pub const RENDEZVOUS_ID: u16 = 0x8102;
    pub const STATUS: u16 = 0x8103;
    pub const TOKEN: u16 = 0x8104;
    pub const DEVICE_NAME: u16 = 0x8105;
    pub const USER_ID: u16 = 0x8106;
    pub const DEVICE_ID: u16 = 0x0107;
    pub const SECRET: u16 = 0x8108;
    pub const MFA_CODE: u16 = 0x0109;
    pub const RETRY_AFTER_MS: u16 = 0x010A;
    pub const CHAIN: u16 = 0x810B;
    pub const CHANNEL_OPTIONS: u16 = 0x810C;
    pub const RELAY_GRANTS: u16 = 0x810D;
    pub const BLOB: u16 = 0x810E;
    pub const ISSUER_KEY_ID: u16 = 0x810F;
    pub const CRL: u16 = 0x8110;
    pub const SESSION_ID: u16 = 0x8111;
    pub const PATH: u16 = 0x8112;
    pub const COUNTERS: u16 = 0x8113;
    pub(super) const ALL: [u16; 19] = [
        REQUEST_ID,
        RENDEZVOUS_ID,
        STATUS,
        TOKEN,
        DEVICE_NAME,
        USER_ID,
        DEVICE_ID,
        SECRET,
        MFA_CODE,
        RETRY_AFTER_MS,
        CHAIN,
        CHANNEL_OPTIONS,
        RELAY_GRANTS,
        BLOB,
        ISSUER_KEY_ID,
        CRL,
        SESSION_ID,
        PATH,
        COUNTERS,
    ];
}

/// One decoded control message. Fields are held raw, and the typed getters check them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlMessage {
    /// `control_type`.
    pub kind: u16,
    fields: Vec<(u16, Vec<u8>)>,
}

impl ControlMessage {
    /// A message with no fields yet.
    pub fn new(kind: u16) -> Self {
        ControlMessage {
            kind,
            fields: Vec::new(),
        }
    }

    /// Adds a raw field.
    pub fn with(mut self, ty: u16, value: &[u8]) -> Self {
        self.fields.push((ty, value.to_vec()));
        self
    }

    /// Adds a text field.
    pub fn with_str(self, ty: u16, value: &str) -> Self {
        self.with(ty, value.as_bytes())
    }

    /// Adds a `u16` field.
    pub fn with_u16(self, ty: u16, value: u16) -> Self {
        self.with(ty, &value.to_be_bytes())
    }

    /// Adds a `u32` field.
    pub fn with_u32(self, ty: u16, value: u32) -> Self {
        self.with(ty, &value.to_be_bytes())
    }

    /// Encodes the record body.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut w = Writer::new();
        w.u16(self.kind);
        w.bytes(&encode_extensions(self.fields.clone())?);
        Ok(w.buf)
    }

    /// Decodes a record body. An unknown critical field is refused.
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let kind = r.u16()?;
        let mut fields = Vec::new();
        for e in parse_extensions(r.rest())? {
            if e.is_critical() && !field::ALL.contains(&e.ty) {
                return Err(WireError);
            }
            fields.push((e.ty, e.value.to_vec()));
        }
        Ok(ControlMessage { kind, fields })
    }

    /// A raw field.
    pub fn get(&self, ty: u16) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(t, _)| *t == ty)
            .map(|(_, v)| v.as_slice())
    }

    /// A UTF-8 field.
    pub fn get_str(&self, ty: u16) -> Option<&str> {
        core::str::from_utf8(self.get(ty)?).ok()
    }

    /// A 16-byte identifier field.
    pub fn get_id(&self, ty: u16) -> Option<[u8; 16]> {
        self.get(ty)?.try_into().ok()
    }

    /// A `u16` field.
    pub fn get_u16(&self, ty: u16) -> Option<u16> {
        let b: [u8; 2] = self.get(ty)?.try_into().ok()?;
        Some(u16::from_be_bytes(b))
    }

    /// A `u32` field.
    pub fn get_u32(&self, ty: u16) -> Option<u32> {
        let b: [u8; 4] = self.get(ty)?.try_into().ok()?;
        Some(u32::from_be_bytes(b))
    }
}

/// `channel_options` on the wire: `u8 ordered; u8 reliable; vec8 label`.
pub fn encode_channel_options(
    ordered: bool,
    reliable: bool,
    label: &str,
) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new();
    w.u8(u8::from(ordered));
    w.u8(u8::from(reliable));
    w.vec8(label.as_bytes())?;
    Ok(w.buf)
}

/// Parses `channel_options`.
pub fn parse_channel_options(raw: &[u8]) -> Result<(bool, bool, String), WireError> {
    let mut r = Reader::new(raw);
    let ordered = bool_byte(r.u8()?)?;
    let reliable = bool_byte(r.u8()?)?;
    let label = core::str::from_utf8(r.vec8()?)
        .map_err(|_| WireError)?
        .into();
    r.finish()?;
    Ok((ordered, reliable, label))
}

fn bool_byte(b: u8) -> Result<bool, WireError> {
    match b {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WireError),
    }
}

/// One relay grant: `vec8 address; vec8 token; u64 expires_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayGrant {
    /// Where the relay listens.
    pub address: String,
    /// The short-lived token.
    pub token: Vec<u8>,
    /// When the token stops working, in milliseconds since the Unix epoch.
    pub expires_at: u64,
}

/// Encodes a list of grants.
pub fn encode_grants(grants: &[RelayGrant]) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new();
    for g in grants {
        w.vec8(g.address.as_bytes())?;
        w.vec8(&g.token)?;
        w.u64(g.expires_at);
    }
    Ok(w.buf)
}

/// Parses a list of grants.
pub fn parse_grants(raw: &[u8]) -> Result<Vec<RelayGrant>, WireError> {
    let mut r = Reader::new(raw);
    let mut out = Vec::new();
    while !r.is_empty() {
        let address = core::str::from_utf8(r.vec8()?)
            .map_err(|_| WireError)?
            .into();
        let token = r.vec8()?.to_vec();
        let expires_at = r.u64()?;
        out.push(RelayGrant {
            address,
            token,
            expires_at,
        });
    }
    Ok(out)
}
