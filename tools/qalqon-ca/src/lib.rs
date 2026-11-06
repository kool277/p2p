//! The certificate hierarchy from `docs/PROTOCOL.md`, section 11.1, for development and
//! tests. A real deployment runs the root offline, which `docs/OPERATIONS.md` covers.
#![forbid(unsafe_code)]

use crypto_provider::{CryptoProvider, SigningKey};
use qalqon_core::cert::{self, CertError, CertFields, role};
use std::sync::Arc;

/// One day, in milliseconds.
pub const DAY_MS: u64 = 86_400_000;

fn encoded(key: &dyn SigningKey) -> Result<Vec<u8>, CertError> {
    Ok(cert::encode_public_key(key.public_key())?)
}

/// A root and an issuing CA, both held in memory.
pub struct DevCa {
    provider: Arc<dyn CryptoProvider>,
    /// The root key. Offline in a real deployment.
    pub root_key: Box<dyn SigningKey>,
    /// The issuing CA's key.
    pub issuing_key: Box<dyn SigningKey>,
    /// The encoded root certificate, which is the CA bundle.
    pub root_cert: Vec<u8>,
    /// The encoded issuing certificate.
    pub issuing_cert: Vec<u8>,
}

impl std::fmt::Debug for DevCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DevCa(..)")
    }
}

impl DevCa {
    /// Creates a root with 10 years of validity and an issuing CA with 1 year.
    pub fn new(provider: Arc<dyn CryptoProvider>, now_ms: u64) -> Result<Self, CertError> {
        let root_key = provider.generate_signing_key()?;
        let issuing_key = provider.generate_signing_key()?;
        Self::from_keys(provider, root_key, issuing_key, now_ms)
    }

    /// Issues the root and issuing certificates for existing keys.
    pub fn from_keys(
        provider: Arc<dyn CryptoProvider>,
        root_key: Box<dyn SigningKey>,
        issuing_key: Box<dyn SigningKey>,
        now_ms: u64,
    ) -> Result<Self, CertError> {
        let p = provider.as_ref();
        let not_before = now_ms - DAY_MS;
        let root_id = cert::key_id(p, &encoded(root_key.as_ref())?);
        let root_cert = cert::issue(
            p,
            root_key.as_ref(),
            &CertFields {
                serial: cert::random_serial(p)?,
                role: role::ROOT,
                subject_a: "Qalqon development root".into(),
                subject_b: String::new(),
                not_before,
                not_after: now_ms + 3650 * DAY_MS,
                sign_public: root_key.public_key().clone(),
                issuer_key_id: root_id,
            },
        )?;
        let issuing_cert = cert::issue(
            p,
            root_key.as_ref(),
            &CertFields {
                serial: cert::random_serial(p)?,
                role: role::ISSUING,
                subject_a: "Qalqon development issuing CA".into(),
                subject_b: String::new(),
                not_before,
                not_after: now_ms + 365 * DAY_MS,
                sign_public: issuing_key.public_key().clone(),
                issuer_key_id: root_id,
            },
        )?;
        Ok(DevCa {
            provider,
            root_key,
            issuing_key,
            root_cert,
            issuing_cert,
        })
    }

    /// Loads an existing hierarchy, keeping its certificates as they were issued.
    pub fn load(
        provider: Arc<dyn CryptoProvider>,
        root_key: Box<dyn SigningKey>,
        issuing_key: Box<dyn SigningKey>,
        root_cert: Vec<u8>,
        issuing_cert: Vec<u8>,
    ) -> Self {
        DevCa {
            provider,
            root_key,
            issuing_key,
            root_cert,
            issuing_cert,
        }
    }

    /// Issues a chain for a server: the leaf with the host name, then the issuing CA.
    pub fn issue_server(
        &self,
        host: &str,
        instance: &str,
        key: &dyn SigningKey,
        now_ms: u64,
    ) -> Result<Vec<u8>, CertError> {
        self.issue_leaf(role::SERVER, host, instance, key, now_ms)
    }

    /// Issues a chain for a device.
    pub fn issue_device(
        &self,
        user_id: &str,
        device_id: &str,
        key: &dyn SigningKey,
        now_ms: u64,
    ) -> Result<Vec<u8>, CertError> {
        self.issue_leaf(role::DEVICE, user_id, device_id, key, now_ms)
    }

    fn issue_leaf(
        &self,
        role_value: u8,
        a: &str,
        b: &str,
        key: &dyn SigningKey,
        now_ms: u64,
    ) -> Result<Vec<u8>, CertError> {
        let p = self.provider.as_ref();
        let mut chain = cert::issue(
            p,
            self.issuing_key.as_ref(),
            &CertFields {
                serial: cert::random_serial(p)?,
                role: role_value,
                subject_a: a.into(),
                subject_b: b.into(),
                not_before: now_ms - DAY_MS,
                not_after: now_ms + 30 * DAY_MS,
                sign_public: key.public_key().clone(),
                issuer_key_id: cert::key_id(p, &encoded(self.issuing_key.as_ref())?),
            },
        )?;
        chain.extend_from_slice(&self.issuing_cert);
        Ok(chain)
    }
}
