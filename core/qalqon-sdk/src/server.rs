//! The server core behind its IDL types: what every host binding calls.

use crate::{open_key_store, provider};
use crypto_provider::{CryptoProvider, KeyStore, SigningKey};
use qalqon_api as api;
use qalqon_api::{ApiError, ErrorKind};
use qalqon_core::session::Limits;
use server_core::policy::Policy;
use server_core::{Effect, IssuingCa, PasswordCost, ServerOptions};
use std::sync::Arc;
use std::time::Duration;

fn map_code(code: qalqon_core::ErrorCode) -> ApiError {
    ErrorKind::from_code(code.code())
        .unwrap_or(ErrorKind::Internal)
        .into()
}

fn open_signing(p: &dyn CryptoProvider, reference: &str) -> Result<Arc<dyn SigningKey>, ErrorKind> {
    let (location, label) = reference
        .split_once('#')
        .ok_or(ErrorKind::InvalidArgument)?;
    let store = open_key_store(location)?;
    store
        .signing_key(p, label, true)
        .map_err(|_| ErrorKind::KeyStoreUnavailable)?
        .map(Arc::from)
        .ok_or(ErrorKind::KeyStoreUnavailable)
}

fn open_secret(
    p: &dyn CryptoProvider,
    reference: &str,
) -> Result<crypto_provider::Secret, ErrorKind> {
    let (location, label) = reference
        .split_once('#')
        .ok_or(ErrorKind::InvalidArgument)?;
    open_key_store(location)?
        .secret(p, label, 32)
        .map_err(|_| ErrorKind::KeyStoreUnavailable)
}

/// `createServerCore`. The core opens every key from its reference, so the host never
/// holds a key's bytes.
pub fn create_server_core(config: api::ServerConfig) -> Result<ServerCore, ApiError> {
    let provider = provider();
    let p = provider.as_ref();
    let identity = open_signing(p, &config.identity_key_ref)?;
    let issuing = match (&config.issuing_key_ref, &config.issuing_certificate) {
        (Some(reference), Some(certificate)) => Some(IssuingCa {
            key: open_signing(p, reference)?,
            certificate: certificate.clone(),
        }),
        (None, None) => None,
        _ => return Err(ErrorKind::InvalidArgument.into()),
    };
    let policy = match &config.policy {
        Some(bytes) => serde_json::from_slice(bytes).map_err(|_| ErrorKind::InvalidArgument)?,
        None => Policy::default_document(),
    };
    let relay_key = open_secret(p, &config.relay_key_ref)?;
    let audit_key = open_secret(p, &config.audit_key_ref)?;
    let core = server_core::ServerCore::new(ServerOptions {
        identity,
        chain: config.chain,
        ca_bundle: config.ca_bundle,
        issuing,
        relay_addresses: config.relay_addresses,
        relay_key: relay_key.to_vec(),
        audit_key: audit_key.to_vec(),
        policy,
        password_cost: PasswordCost::default(),
        limits: Limits::default(),
        now_ms: crate::now_ms(),
        provider,
    })
    .map_err(map_code)?;
    Ok(ServerCore {
        core: Arc::new(core),
    })
}

/// The server side of the protocol, embedded by every host. See `docs/HOST-SPI.md`.
#[derive(Clone, Debug)]
pub struct ServerCore {
    core: Arc<server_core::ServerCore>,
}

fn store_kind(kind: server_core::StoreKind) -> api::StoreKind {
    match kind {
        server_core::StoreKind::User => api::StoreKind::User,
        server_core::StoreKind::Device => api::StoreKind::Device,
        server_core::StoreKind::Policy => api::StoreKind::Policy,
        server_core::StoreKind::Audit => api::StoreKind::Audit,
    }
}

fn store_operation(operation: server_core::StoreOperation) -> api::StoreOperation {
    match operation {
        server_core::StoreOperation::Get => api::StoreOperation::Get,
        server_core::StoreOperation::Put => api::StoreOperation::Put,
        server_core::StoreOperation::List => api::StoreOperation::List,
        server_core::StoreOperation::Append => api::StoreOperation::Append,
        server_core::StoreOperation::Head => api::StoreOperation::Head,
        server_core::StoreOperation::Range => api::StoreOperation::Range,
    }
}

fn severity(value: server_core::Severity) -> api::Severity {
    match value {
        server_core::Severity::Info => api::Severity::Info,
        server_core::Severity::Warning => api::Severity::Warning,
        server_core::Severity::Critical => api::Severity::Critical,
    }
}

impl ServerCore {
    /// `serverCore.accept`.
    pub fn accept(&self, meta: api::ConnectionMeta) -> Result<u64, ApiError> {
        self.core.accept(&meta.remote_address).map_err(map_code)
    }

    /// `serverCore.onFrame`.
    pub fn on_frame(&self, conn_id: u64, frame: &[u8]) -> Result<(), ApiError> {
        self.core.on_frame(conn_id, frame).map_err(map_code)
    }

    /// `serverCore.onClose`.
    pub fn on_close(&self, conn_id: u64) -> Result<(), ApiError> {
        self.core.on_close(conn_id).map_err(map_code)
    }

    /// `serverCore.tick`.
    pub fn tick(&self, now_ms: u64) -> Result<(), ApiError> {
        self.core.tick(now_ms).map_err(map_code)
    }

    /// `serverCore.pollEffect`.
    pub fn poll_effect(&self, timeout_ms: u32) -> Result<Option<api::Effect>, ApiError> {
        let effect = self
            .core
            .poll_effect(Duration::from_millis(u64::from(timeout_ms)))
            .map_err(map_code)?;
        Ok(effect.map(|effect| match effect {
            Effect::SendFrame { conn_id, frame } => api::Effect::SendFrame { conn_id, frame },
            Effect::CloseConnection { conn_id, code } => {
                api::Effect::CloseConnection { conn_id, code }
            }
            Effect::Store {
                effect_id,
                store,
                operation,
                key,
                record,
            } => api::Effect::Store {
                effect_id,
                store: store_kind(store),
                operation: store_operation(operation),
                key,
                record,
            },
            Effect::Alarm {
                severity: s,
                summary,
            } => api::Effect::Alarm {
                severity: severity(s),
                summary,
            },
        }))
    }

    /// `serverCore.completeEffect`.
    pub fn complete_effect(
        &self,
        effect_id: u64,
        status: u32,
        record: Option<Vec<u8>>,
    ) -> Result<(), ApiError> {
        self.core
            .complete_effect(effect_id, status, record)
            .map_err(map_code)
    }

    /// `serverCore.adminCall`.
    pub fn admin_call(&self, method: &str, params_json: &str) -> Result<String, ApiError> {
        self.core.admin_call(method, params_json).map_err(map_code)
    }

    /// `serverCore.health`.
    pub fn health(&self) -> Result<api::HealthSnapshot, ApiError> {
        let health = self.core.health();
        Ok(api::HealthSnapshot {
            live: health.live,
            ready: health.ready,
            detail: health.detail,
        })
    }

    /// `serverCore.metrics`.
    pub fn metrics(&self) -> Result<api::MetricsSnapshot, ApiError> {
        Ok(api::MetricsSnapshot {
            text: self.core.metrics(),
        })
    }

    /// `serverCore.shutdown`.
    pub fn shutdown(&self) -> Result<(), ApiError> {
        self.core.shutdown();
        Ok(())
    }
}
