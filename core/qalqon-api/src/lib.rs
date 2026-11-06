//! The public API's types, shared by the SDK, the C ABI, the sidecar and WebAssembly.
//! Everything in `generated.rs` comes from `core/idl/qalqon.api.yaml`. Do not edit it.
#![forbid(unsafe_code)]
#![allow(missing_docs)]

#[rustfmt::skip]
mod generated;
pub use generated::*;

/// A failure from the public API: the IDL's numeric code and its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApiError(pub ErrorKind);

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.0.name(), self.0.code())
    }
}

impl std::error::Error for ApiError {}

impl From<ErrorKind> for ApiError {
    fn from(kind: ErrorKind) -> Self {
        ApiError(kind)
    }
}

/// `bytes` fields travel as standard base64 in JSON (ADR-0004).
pub mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Encodes bytes.
    pub fn encode(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }

    /// Decodes bytes.
    pub fn decode(text: &str) -> Option<Vec<u8>> {
        STANDARD.decode(text).ok()
    }

    /// For `#[serde(with = "b64")]`.
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&encode(bytes))
    }

    /// For `#[serde(with = "b64")]`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        decode(&text).ok_or_else(|| serde::de::Error::custom("not valid base64"))
    }
}

/// `bytes?` fields.
pub mod b64_opt {
    use super::b64;
    use serde::{Deserialize, Deserializer, Serializer};

    /// For `#[serde(with = "b64_opt")]`.
    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&b64::encode(b)),
            None => s.serialize_none(),
        }
    }

    /// For `#[serde(with = "b64_opt")]`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let text = Option::<String>::deserialize(d)?;
        text.map(|t| b64::decode(&t).ok_or_else(|| serde::de::Error::custom("not valid base64")))
            .transpose()
    }
}
