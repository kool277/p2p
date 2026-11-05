//! Certificates: `docs/PROTOCOL.md`, section 11. This is the proposed TLV format,
//! which is easy to parse safely without an OS or in WebAssembly. Whether to keep
//! it or use X.509 depends on the library, and is an open decision.

use crate::schedule::ctx;
use crate::session::{PeerExpectation, Plane};
use crate::wire::{Reader, WireError, Writer, encode_extensions, find_extension, parse_extensions};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use crypto_provider::{CryptoError, CryptoProvider, PublicKey, SigningKey};

/// The format this code writes and accepts.
pub const FORMAT_VERSION: u8 = 1;

/// Certificate roles, section 11.2.
pub mod role {
    #![allow(missing_docs)]
    pub const ROOT: u8 = 1;
    pub const ISSUING: u8 = 2;
    pub const SERVER: u8 = 3;
    pub const DEVICE: u8 = 4;
    pub const PRE_ENROLMENT: u8 = 5;
}

mod field {
    pub const FORMAT_VERSION: u16 = 0x8001;
    pub const SERIAL: u16 = 0x8002;
    pub const ROLE: u16 = 0x8003;
    pub const SUBJECT: u16 = 0x8004;
    pub const NOT_BEFORE: u16 = 0x8005;
    pub const NOT_AFTER: u16 = 0x8006;
    pub const SIGN_PUBLIC: u16 = 0x8007;
    pub const ISSUER_KEY_ID: u16 = 0x8008;
    pub const ALL: [u16; 8] = [
        FORMAT_VERSION,
        SERIAL,
        ROLE,
        SUBJECT,
        NOT_BEFORE,
        NOT_AFTER,
        SIGN_PUBLIC,
        ISSUER_KEY_ID,
    ];
}

/// The fields of a certificate, before signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertFields {
    /// A unique serial, 16 random bytes.
    pub serial: [u8; 16],
    /// See [`role`].
    pub role: u8,
    /// Role 3: host name. Role 4: `user_id`. Roles 1 and 2: name. Role 5: empty.
    pub subject_a: String,
    /// Role 3: server instance. Role 4: `device_id`. Otherwise empty.
    pub subject_b: String,
    /// Valid from, in milliseconds since the Unix epoch.
    pub not_before: u64,
    /// Valid until, in milliseconds since the Unix epoch.
    pub not_after: u64,
    /// The subject's public signing key.
    pub sign_public: PublicKey,
    /// The issuer's key id. For a self-signed certificate, the subject's own.
    pub issuer_key_id: [u8; 16],
}

/// A parsed certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// The parsed fields.
    pub fields: CertFields,
    /// The encoded `sign_public` value, which fingerprints and key ids hash.
    pub sign_public_encoded: Vec<u8>,
    tbs: Vec<u8>,
    signature: Vec<u8>,
    raw: Vec<u8>,
}

/// Encodes a `sign_public` value: `u16 algorithm, vec16 key`.
pub fn encode_public_key(key: &PublicKey) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new();
    w.u16(key.algorithm);
    w.vec16(&key.key)?;
    Ok(w.buf)
}

/// `issuer_key_id`: the first 16 bytes of the hash of an encoded `sign_public`.
pub fn key_id(p: &dyn CryptoProvider, sign_public_encoded: &[u8]) -> [u8; 16] {
    let hash = p.hash(sign_public_encoded);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash[..16]);
    out
}

/// `fingerprint` = `H(ctx("fingerprint") || sign_public)`, section 11.4.
pub fn fingerprint(p: &dyn CryptoProvider, sign_public_encoded: &[u8]) -> Vec<u8> {
    let mut input = ctx("fingerprint");
    input.extend_from_slice(sign_public_encoded);
    p.hash(&input)
}

fn signing_input(p: &dyn CryptoProvider, tbs: &[u8]) -> Vec<u8> {
    let mut input = ctx("certificate");
    input.extend_from_slice(&p.hash(tbs));
    input
}

/// Encodes and signs a certificate.
pub fn issue(
    p: &dyn CryptoProvider,
    issuer: &dyn SigningKey,
    fields: &CertFields,
) -> Result<Vec<u8>, CertError> {
    let mut subject = Writer::new();
    subject.vec8(fields.subject_a.as_bytes())?;
    subject.vec8(fields.subject_b.as_bytes())?;
    let tbs = encode_extensions(vec![
        (field::FORMAT_VERSION, vec![FORMAT_VERSION]),
        (field::SERIAL, fields.serial.to_vec()),
        (field::ROLE, vec![fields.role]),
        (field::SUBJECT, subject.buf),
        (field::NOT_BEFORE, fields.not_before.to_be_bytes().to_vec()),
        (field::NOT_AFTER, fields.not_after.to_be_bytes().to_vec()),
        (field::SIGN_PUBLIC, encode_public_key(&fields.sign_public)?),
        (field::ISSUER_KEY_ID, fields.issuer_key_id.to_vec()),
    ])?;
    let signature = issuer.sign(&signing_input(p, &tbs))?;
    let mut w = Writer::new();
    w.vec16(&tbs)?;
    w.vec16(&signature)?;
    Ok(w.buf)
}

/// A random serial.
pub fn random_serial(p: &dyn CryptoProvider) -> Result<[u8; 16], CertError> {
    let mut serial = [0u8; 16];
    p.random(&mut serial)?;
    Ok(serial)
}

/// A pre-enrolment certificate: role 5, self-signed, with empty subject (section 11.6).
pub fn pre_enrolment(
    p: &dyn CryptoProvider,
    key: &dyn SigningKey,
    not_before: u64,
    not_after: u64,
) -> Result<Vec<u8>, CertError> {
    let encoded = encode_public_key(key.public_key())?;
    issue(
        p,
        key,
        &CertFields {
            serial: random_serial(p)?,
            role: role::PRE_ENROLMENT,
            subject_a: String::new(),
            subject_b: String::new(),
            not_before,
            not_after,
            sign_public: key.public_key().clone(),
            issuer_key_id: key_id(p, &encoded),
        },
    )
}

fn parse_one(p: &dyn CryptoProvider, reader: &mut Reader<'_>) -> Result<Certificate, CertError> {
    let start = reader.remaining();
    let snapshot = reader.clone();
    let tbs = reader.vec16()?;
    let signature = reader.vec16()?;
    let raw_len = start - reader.remaining();
    let raw = snapshot.clone().take(raw_len)?.to_vec();

    let extensions = parse_extensions(tbs)?;
    for e in &extensions {
        if e.is_critical() && !field::ALL.contains(&e.ty) {
            return Err(CertError::Malformed);
        }
    }
    let need = |ty| find_extension(&extensions, ty).ok_or(CertError::Malformed);

    if need(field::FORMAT_VERSION)? != [FORMAT_VERSION] {
        return Err(CertError::Malformed);
    }
    let serial: [u8; 16] = need(field::SERIAL)?
        .try_into()
        .map_err(|_| CertError::Malformed)?;
    let role_value = need(field::ROLE)?;
    let [role_value] = role_value else {
        return Err(CertError::Malformed);
    };
    let mut subject = Reader::new(need(field::SUBJECT)?);
    let subject_a = utf8(subject.vec8()?)?;
    let subject_b = utf8(subject.vec8()?)?;
    subject.finish()?;
    let not_before = be_u64(need(field::NOT_BEFORE)?)?;
    let not_after = be_u64(need(field::NOT_AFTER)?)?;
    let encoded = need(field::SIGN_PUBLIC)?;
    let mut public = Reader::new(encoded);
    let algorithm = public.u16()?;
    let key = public.vec16()?.to_vec();
    public.finish()?;
    let issuer_key_id: [u8; 16] = need(field::ISSUER_KEY_ID)?
        .try_into()
        .map_err(|_| CertError::Malformed)?;

    let subject_ok = match *role_value {
        role::ROOT | role::ISSUING => !subject_a.is_empty() && subject_b.is_empty(),
        role::SERVER | role::DEVICE => !subject_a.is_empty() && !subject_b.is_empty(),
        role::PRE_ENROLMENT => subject_a.is_empty() && subject_b.is_empty(),
        _ => false,
    };
    if !subject_ok || not_after < not_before {
        return Err(CertError::Malformed);
    }
    if key.is_empty() || p.params().signature_algorithm != algorithm {
        return Err(CertError::Malformed);
    }

    Ok(Certificate {
        fields: CertFields {
            serial,
            role: *role_value,
            subject_a,
            subject_b,
            not_before,
            not_after,
            sign_public: PublicKey { algorithm, key },
            issuer_key_id,
        },
        sign_public_encoded: encoded.to_vec(),
        tbs: tbs.to_vec(),
        signature: signature.to_vec(),
        raw,
    })
}

fn utf8(bytes: &[u8]) -> Result<String, CertError> {
    core::str::from_utf8(bytes)
        .map(ToString::to_string)
        .map_err(|_| CertError::Malformed)
}

fn be_u64(bytes: &[u8]) -> Result<u64, CertError> {
    let a: [u8; 8] = bytes.try_into().map_err(|_| CertError::Malformed)?;
    Ok(u64::from_be_bytes(a))
}

/// Parses a sequence of certificates, such as a chain or a CA bundle.
pub fn parse_many(p: &dyn CryptoProvider, bytes: &[u8]) -> Result<Vec<Certificate>, CertError> {
    let mut reader = Reader::new(bytes);
    let mut out = Vec::new();
    while !reader.is_empty() {
        out.push(parse_one(p, &mut reader)?);
    }
    Ok(out)
}

impl Certificate {
    /// The encoded certificate.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Checks this certificate's signature against the issuer's key.
    pub fn verify_signature(
        &self,
        p: &dyn CryptoProvider,
        issuer: &PublicKey,
    ) -> Result<(), CertError> {
        p.verify(issuer, &signing_input(p, &self.tbs), &self.signature)
            .map_err(|_| CertError::Signature)
    }

    /// True if `now` is inside the validity period.
    pub fn is_current(&self, now_ms: u64) -> bool {
        self.fields.not_before <= now_ms && now_ms <= self.fields.not_after
    }
}

/// A certificate failed to parse or validate. Detail stays local (section 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertError {
    /// Not a well-formed certificate or chain.
    Malformed,
    /// A signature did not verify, or no trusted root was found.
    Signature,
    /// A certificate is outside its validity period.
    Expired,
    /// The chain's shape or a certificate's role is not allowed here.
    Role,
    /// The subject does not match what was expected.
    Subject,
    /// A cryptographic operation failed.
    Crypto(CryptoError),
}

impl From<WireError> for CertError {
    fn from(_: WireError) -> Self {
        CertError::Malformed
    }
}

impl From<CryptoError> for CertError {
    fn from(e: CryptoError) -> Self {
        CertError::Crypto(e)
    }
}

/// The result of validating a peer's chain, before any pin is consulted.
#[derive(Clone, Debug)]
pub struct ValidatedChain {
    /// The peer's own certificate.
    pub leaf: Certificate,
    /// The issuing CA's certificate, absent for a pre-enrolment chain.
    pub issuing: Option<Certificate>,
    /// The leaf's fingerprint.
    pub fingerprint: Vec<u8>,
}

/// Validates a chain as in section 11.3, steps 1 to 4. Revocation and pins are
/// separate, because pins are only checked after the signature and MAC.
pub fn validate_chain(
    p: &dyn CryptoProvider,
    roots: &[Certificate],
    raw_chain: &[u8],
    now_ms: u64,
    plane: Plane,
    expectation: &PeerExpectation,
) -> Result<ValidatedChain, CertError> {
    let certs = parse_many(p, raw_chain)?;

    // Step 1: shape and signatures. Any other shape is refused, so a device
    // certificate can never act as a CA.
    let (leaf, issuing) = match certs.as_slice() {
        [leaf] if leaf.fields.role == role::PRE_ENROLMENT => {
            if leaf.fields.issuer_key_id != key_id(p, &leaf.sign_public_encoded) {
                return Err(CertError::Signature);
            }
            leaf.verify_signature(p, &leaf.fields.sign_public)?;
            (leaf.clone(), None)
        }
        [leaf, issuing] => {
            if !matches!(leaf.fields.role, role::SERVER | role::DEVICE)
                || issuing.fields.role != role::ISSUING
            {
                return Err(CertError::Role);
            }
            if leaf.fields.issuer_key_id != key_id(p, &issuing.sign_public_encoded) {
                return Err(CertError::Signature);
            }
            leaf.verify_signature(p, &issuing.fields.sign_public)?;
            let root = roots
                .iter()
                .find(|r| {
                    r.fields.role == role::ROOT
                        && key_id(p, &r.sign_public_encoded) == issuing.fields.issuer_key_id
                })
                .ok_or(CertError::Signature)?;
            issuing.verify_signature(p, &root.fields.sign_public)?;
            // Step 2 for the root, which is not on the wire.
            if !root.is_current(now_ms) {
                return Err(CertError::Expired);
            }
            (leaf.clone(), Some(issuing.clone()))
        }
        _ => return Err(CertError::Role),
    };

    // Step 2: times.
    if !leaf.is_current(now_ms) || issuing.as_ref().is_some_and(|c| !c.is_current(now_ms)) {
        return Err(CertError::Expired);
    }

    // Step 3: role, and step 4: subject.
    match (plane, expectation) {
        (Plane::Control, PeerExpectation::Server { host }) => {
            if leaf.fields.role != role::SERVER {
                return Err(CertError::Role);
            }
            if !leaf.fields.subject_a.eq_ignore_ascii_case(host) {
                return Err(CertError::Subject);
            }
        }
        (Plane::Control, PeerExpectation::Client) => {
            if !matches!(leaf.fields.role, role::DEVICE | role::PRE_ENROLMENT) {
                return Err(CertError::Role);
            }
        }
        (Plane::Data, PeerExpectation::Peer { user_id, device_id }) => {
            if leaf.fields.role != role::DEVICE {
                return Err(CertError::Role);
            }
            if leaf.fields.subject_a != *user_id {
                return Err(CertError::Subject);
            }
            if device_id
                .as_ref()
                .is_some_and(|d| *d != leaf.fields.subject_b)
            {
                return Err(CertError::Subject);
            }
        }
        _ => return Err(CertError::Role),
    }

    let fingerprint = fingerprint(p, &leaf.sign_public_encoded);
    Ok(ValidatedChain {
        leaf,
        issuing,
        fingerprint,
    })
}
