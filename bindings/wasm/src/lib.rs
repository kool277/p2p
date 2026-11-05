//! The core for browsers. Structured values cross as JSON text, as everywhere else, and
//! `bytes` cross as `Uint8Array`. JavaScript answers transport commands and stores opaque
//! blobs, but it never holds a key and has no protocol logic. See
//! `packages/js/web/src/worker.js`.
#![forbid(unsafe_code)]
#![allow(missing_debug_implementations)]

use crypto_provider::{CryptoProvider, SigningKey};
use provider_testonly::TestOnlyProvider;
use qalqon_api as api;
use qalqon_core::session::Limits;
use qalqon_signal::{ClientCore, ClientOptions, OpResult, OpValue, SavedState};
use serde_json::json;
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use web_sys::CryptoKey;

fn now() -> u64 {
    js_sys::Date::now() as u64
}

fn provider() -> Arc<dyn CryptoProvider> {
    Arc::new(TestOnlyProvider::new())
}

fn bad_input(what: &str) -> JsValue {
    JsValue::from_str(&format!("invalidArgument: {what}"))
}

fn parse<T: serde::de::DeserializeOwned>(text: &str, what: &str) -> Result<T, JsValue> {
    serde_json::from_str(text).map_err(|_| bad_input(what))
}

fn api_error(kind: api::ErrorKind) -> JsValue {
    JsValue::from_str(kind.name())
}

/// A long-term key, loaded into WebAssembly memory. JavaScript holds only this handle.
#[wasm_bindgen]
pub struct Identity {
    key: Arc<dyn SigningKey>,
}

#[wasm_bindgen]
impl Identity {
    /// Creates a new identity, and returns it with its wrapped form for storage.
    #[wasm_bindgen(js_name = create)]
    pub async fn create(wrapping_key: CryptoKey) -> Result<CreatedIdentity, JsValue> {
        let (key, wrapped) =
            keystore_webcrypto::create_identity(provider().as_ref(), &wrapping_key).await?;
        Ok(CreatedIdentity {
            identity: Some(Identity {
                key: Arc::from(key),
            }),
            wrapped,
        })
    }

    /// Opens a stored identity.
    #[wasm_bindgen(js_name = open)]
    pub async fn open(wrapping_key: CryptoKey, wrapped: Vec<u8>) -> Result<Identity, JsValue> {
        let key =
            keystore_webcrypto::open_identity(provider().as_ref(), &wrapping_key, &wrapped).await?;
        Ok(Identity {
            key: Arc::from(key),
        })
    }
}

/// [`Identity::create`]'s result.
#[wasm_bindgen]
pub struct CreatedIdentity {
    identity: Option<Identity>,
    wrapped: Vec<u8>,
}

#[wasm_bindgen]
impl CreatedIdentity {
    /// The bytes to store. They are useless without the wrapping key.
    #[wasm_bindgen(getter)]
    pub fn wrapped(&self) -> Vec<u8> {
        self.wrapped.clone()
    }

    /// Takes the identity.
    #[wasm_bindgen(js_name = takeIdentity)]
    pub fn take_identity(&mut self) -> Option<Identity> {
        self.identity.take()
    }
}

/// Creates a new non-extractable wrapping key, for JavaScript to keep in IndexedDB.
#[wasm_bindgen(js_name = newWrappingKey)]
pub async fn new_wrapping_key() -> Result<CryptoKey, JsValue> {
    keystore_webcrypto::new_wrapping_key().await
}

/// `conformanceRun`.
#[wasm_bindgen(js_name = conformanceRun)]
pub fn conformance_run(vectors: &str) -> String {
    let report = qalqon_conformance::run_file(vectors);
    json!({ "passed": report.passed, "failed": report.failed, "provider": provider().name() })
        .to_string()
}

/// The name of the crypto provider in this build. A test-only build says so.
#[wasm_bindgen(js_name = providerName)]
pub fn provider_name() -> String {
    provider().name().to_string()
}

/// `ClientCore`, for JavaScript to drive.
#[wasm_bindgen]
pub struct Client {
    core: ClientCore,
}

fn completion_json(result: OpResult) -> String {
    match result {
        Ok(OpValue::None) => json!({ "ok": null }).to_string(),
        Ok(OpValue::Channel(handle)) => json!({ "ok": { "channelId": handle } }).to_string(),
        Ok(OpValue::Enrolled { result, chain }) => {
            json!({ "ok": { "enrolled": result, "chain": api::b64::encode(&chain) } }).to_string()
        }
        Err(kind) => json!({ "error": { "code": kind.code(), "name": kind.name() } }).to_string(),
    }
}

#[wasm_bindgen]
impl Client {
    /// Creates a client. `config` is a `SessionConfig` as JSON, `chain` is this device's
    /// certificate chain if it has one, and `saved` is what `takeStateToSave` last gave.
    #[wasm_bindgen(constructor)]
    pub fn new(
        config: &str,
        identity: &Identity,
        chain: Option<Vec<u8>>,
        saved: Option<String>,
    ) -> Result<Client, JsValue> {
        let config: api::SessionConfig = parse(config, "SessionConfig")?;
        let saved: SavedState = match saved {
            Some(text) => parse(&text, "the saved state")?,
            None => SavedState::default(),
        };
        let core = ClientCore::new(
            ClientOptions {
                provider: provider(),
                server_url: config.server_url,
                ca_bundle: config.ca_bundle,
                identity: identity.key.clone(),
                chain,
                relay_policy: config
                    .relay_policy
                    .unwrap_or(api::RelayPolicy::PreferDirect),
                identity_change_policy: config
                    .identity_change_policy
                    .unwrap_or(api::IdentityChangePolicy::Block),
                revocation_grace_ms: config.revocation_grace_ms.unwrap_or(72 * 60 * 60 * 1000),
                saved,
                limits: Limits::default(),
            },
            now(),
        )
        .map_err(api_error)?;
        Ok(Client { core })
    }

    /// `enrollDevice`. Returns an operation number.
    #[wasm_bindgen(js_name = startEnroll)]
    pub fn start_enroll(&mut self, request: &str) -> Result<f64, JsValue> {
        let request: api::EnrollmentRequest = parse(request, "EnrollmentRequest")?;
        Ok(self.core.start_enroll(now(), request) as f64)
    }

    /// `connect`. Returns an operation number.
    #[wasm_bindgen(js_name = startConnect)]
    pub fn start_connect(&mut self, credentials: &str) -> Result<f64, JsValue> {
        let credentials: api::Credentials = parse(credentials, "Credentials")?;
        Ok(self.core.start_connect(now(), credentials) as f64)
    }

    /// An operation's result as JSON, once it has finished.
    #[wasm_bindgen(js_name = takeCompletion)]
    pub fn take_completion(&mut self, op: f64) -> Option<String> {
        self.core.take_completion(op as u64).map(completion_json)
    }

    /// The next transport command, as JSON. Frames in it are base64.
    #[wasm_bindgen(js_name = pollCommand)]
    pub fn poll_command(&mut self) -> Option<String> {
        self.core
            .poll_command()
            .and_then(|c| serde_json::to_string(&c).ok())
    }

    /// The next event, as JSON.
    #[wasm_bindgen(js_name = pollEvent)]
    pub fn poll_event(&mut self) -> Option<String> {
        self.core
            .poll_event()
            .and_then(|e| serde_json::to_string(&e).ok())
    }

    /// `linkOpened`.
    #[wasm_bindgen(js_name = linkOpened)]
    pub fn link_opened(&mut self, link: f64, caps: &str) -> Result<(), JsValue> {
        let caps: api::TransportCaps = parse(caps, "TransportCaps")?;
        self.core.link_opened(now(), link as u64, caps);
        Ok(())
    }

    /// `linkClosed`.
    #[wasm_bindgen(js_name = linkClosed)]
    pub fn link_closed(&mut self, link: f64) {
        self.core.link_closed(now(), link as u64);
    }

    /// `frameReceived`.
    #[wasm_bindgen(js_name = frameReceived)]
    pub fn frame_received(&mut self, link: f64, frame: &[u8]) {
        self.core.frame_received(now(), link as u64, frame);
    }

    /// `signalReceived`.
    #[wasm_bindgen(js_name = signalReceived)]
    pub fn signal_received(&mut self, link: f64, blob: &[u8]) {
        self.core.signal_received(now(), link as u64, blob);
    }

    /// Drives every timer. Returns the next time it has work, or null.
    #[wasm_bindgen(js_name = handleTimeout)]
    pub fn handle_timeout(&mut self) -> Option<f64> {
        let at = now();
        self.core.handle_timeout(at);
        self.core.next_timeout().map(|t| t as f64)
    }

    /// `openChannel`. Returns an operation number.
    #[wasm_bindgen(js_name = openChannel)]
    pub fn open_channel(&mut self, peer: &str, options: &str) -> Result<f64, JsValue> {
        let peer: api::PeerRef = parse(peer, "PeerRef")?;
        let options: api::ChannelOptions = parse(options, "ChannelOptions")?;
        Ok(self.core.open_channel(now(), peer, options) as f64)
    }

    /// `acceptChannel`. Returns an operation number.
    #[wasm_bindgen(js_name = acceptChannel)]
    pub fn accept_channel(&mut self, request_id: &str) -> f64 {
        self.core.accept_channel(now(), request_id) as f64
    }

    /// `rejectChannel`.
    #[wasm_bindgen(js_name = rejectChannel)]
    pub fn reject_channel(&mut self, request_id: &str) -> Result<(), JsValue> {
        self.core
            .reject_channel(now(), request_id)
            .map_err(api_error)
    }

    /// `channel.send`.
    pub fn send(&mut self, channel: f64, payload: &[u8]) -> Result<(), JsValue> {
        self.core
            .send(now(), channel as u64, payload)
            .map_err(api_error)
    }

    /// `channel.receive`, without waiting.
    pub fn receive(&mut self, channel: f64) -> Result<Option<Vec<u8>>, JsValue> {
        self.core.receive(channel as u64).map_err(api_error)
    }

    /// `channel.info`, as JSON.
    #[wasm_bindgen(js_name = channelInfo)]
    pub fn channel_info(&self, channel: f64) -> Result<String, JsValue> {
        let info = self.core.channel_info(channel as u64).map_err(api_error)?;
        serde_json::to_string(&info).map_err(|_| api_error(api::ErrorKind::Internal))
    }

    /// `channel.close`. Returns an operation number.
    #[wasm_bindgen(js_name = closeChannel)]
    pub fn close_channel(&mut self, channel: f64) -> f64 {
        self.core.close_channel(now(), channel as u64) as f64
    }

    /// `verifyPeer`, as JSON.
    #[wasm_bindgen(js_name = verifyPeer)]
    pub fn verify_peer(
        &mut self,
        peer: &str,
        safety_number: Option<String>,
    ) -> Result<String, JsValue> {
        let peer: api::PeerRef = parse(peer, "PeerRef")?;
        let identity = self
            .core
            .verify_peer(now(), &peer, safety_number.as_deref())
            .map_err(api_error)?;
        serde_json::to_string(&identity).map_err(|_| api_error(api::ErrorKind::Internal))
    }

    /// `rotateKeys`. Returns an operation number.
    #[wasm_bindgen(js_name = rotateKeys)]
    pub fn rotate_keys(&mut self, peer: Option<String>) -> Result<f64, JsValue> {
        let peer: Option<api::PeerRef> = peer.map(|p| parse(&p, "PeerRef")).transpose()?;
        Ok(self.core.rotate_keys(now(), peer.as_ref()) as f64)
    }

    /// `exportAudit`, as JSON.
    #[wasm_bindgen(js_name = exportAudit)]
    pub fn export_audit(&self, request: &str) -> Result<String, JsValue> {
        let request: api::AuditExportRequest = parse(request, "AuditExportRequest")?;
        let export = self.core.export_audit(&request).map_err(api_error)?;
        serde_json::to_string(&export).map_err(|_| api_error(api::ErrorKind::Internal))
    }

    /// `session.close`. Returns an operation number.
    pub fn close(&mut self) -> f64 {
        self.core.close(now()) as f64
    }

    /// What to store, if anything has changed. Holds no key material.
    #[wasm_bindgen(js_name = takeStateToSave)]
    pub fn take_state_to_save(&mut self) -> Option<String> {
        self.core
            .take_state_to_save()
            .and_then(|s| serde_json::to_string(&s).ok())
    }

    /// Moves everything sessions have produced into commands and events.
    pub fn drive(&mut self) {
        self.core.drive(now());
    }
}
