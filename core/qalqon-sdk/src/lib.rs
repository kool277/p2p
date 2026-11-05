//! The native SDK. Every name and error code here comes from `docs/SDK-API.md`, in Rust's
//! casing. `async` calls in the IDL are blocking calls here, and the C ABI and the
//! sidecar are built on them.
//!
//! [`qalqon_signal::ClientCore`] does the work. This crate only answers its transport
//! commands with real sockets on background threads, persists its state, and waits.
#![forbid(unsafe_code)]

mod links;
mod server;

pub use qalqon_api as api;
pub use qalqon_api::{ApiError, ErrorKind};
pub use server::{ServerCore, create_server_core};

use crypto_provider::{CryptoProvider, KeyStore, SigningKey, from_hex, to_hex};
use keystore_file::FileKeyStore;
use qalqon_api::TransportCommand;
use qalqon_core::session::Limits;
use qalqon_signal::{ClientCore, ClientOptions, OpResult, OpValue, SavedState};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long a blocking call waits by default before reporting `timeout`.
const DEFAULT_OP_TIMEOUT: Duration = Duration::from_secs(60);
const IDENTITY_LABEL: &str = "device-identity";
const DEFAULT_REVOCATION_GRACE_MS: u64 = 72 * 60 * 60 * 1000;

pub(crate) fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// The provider this build uses.
pub fn provider() -> Arc<dyn CryptoProvider> {
    #[cfg(feature = "testonly")]
    {
        Arc::new(provider_testonly::TestOnlyProvider::new())
    }
    #[cfg(not(feature = "testonly"))]
    {
        compile_error!("no crypto provider is selected: provider-<lib> is not in this repository yet")
    }
}

/// Constant-time comparison, for a host's own secrets such as an admin token.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    crypto_provider::ct_eq(a, b)
}

/// The name of the provider this build uses, so a test build can never be mistaken for
/// a certified one.
pub fn provider_name() -> &'static str {
    provider().name()
}

/// Opens a key store named in a reference like `file:/path/to/keys#label`, or in a
/// `keyStore` URI like `file:/path/to/keys`.
pub(crate) fn open_key_store(uri: &str) -> Result<FileKeyStore, ErrorKind> {
    let path = uri.strip_prefix("file:").ok_or(ErrorKind::InvalidArgument)?;
    FileKeyStore::open(path).map_err(|_| ErrorKind::KeyStoreUnavailable)
}

fn resolve_key_store(config: &api::SessionConfig) -> Result<FileKeyStore, ErrorKind> {
    match config.key_store.kind {
        api::KeyStoreKind::External => {
            open_key_store(config.key_store.uri.as_deref().ok_or(ErrorKind::InvalidArgument)?)
        }
        // The platform stores in ADR-0002, part 6, are not built yet, so the default on
        // this platform is the file store in the data directory. docs/COMPLIANCE.md
        // records this as a gap.
        api::KeyStoreKind::OsDefault => {
            let dir = config.data_dir.as_deref().ok_or(ErrorKind::InvalidArgument)?;
            FileKeyStore::open(Path::new(dir).join("keys")).map_err(|_| ErrorKind::KeyStoreUnavailable)
        }
    }
}

fn data_file(config_dir: &Option<PathBuf>, name: &str) -> Option<PathBuf> {
    config_dir.as_ref().map(|d| d.join(name))
}

fn read_chain(dir: &Option<PathBuf>) -> Option<Vec<u8>> {
    let text = std::fs::read_to_string(data_file(dir, "device.chain")?).ok()?;
    from_hex(text.trim())
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)
}

fn read_saved(dir: &Option<PathBuf>) -> SavedState {
    data_file(dir, "state.json")
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Shared between the application's threads, the runtime thread and the link threads.
pub(crate) struct Shared {
    pub(crate) core: Mutex<ClientCore>,
    pub(crate) activity: Condvar,
    pub(crate) links: links::LinkTable,
    data_dir: Option<PathBuf>,
    external: Mutex<Option<Arc<ExternalInner>>>,
    stopped: std::sync::atomic::AtomicBool,
}

impl Shared {
    pub(crate) fn lock(&self) -> MutexGuard<'_, ClientCore> {
        self.core.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn poke(&self) {
        self.activity.notify_all();
    }

    fn wait_op(&self, op: u64, timeout: Duration) -> OpResult {
        let deadline = Instant::now() + timeout;
        let mut core = self.lock();
        loop {
            if let Some(result) = core.take_completion(op) {
                return result;
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(ErrorKind::Timeout);
            }
            let (guard, _) = self
                .activity
                .wait_timeout(core, (deadline - now).min(Duration::from_millis(100)))
                .unwrap_or_else(|e| e.into_inner());
            core = guard;
        }
    }

    fn persist(&self, core: &mut ClientCore) {
        let Some(saved) = core.take_state_to_save() else { return };
        if let (Some(path), Ok(bytes)) = (data_file(&self.data_dir, "state.json"), serde_json::to_vec(&saved)) {
            // A local store that cannot be written is reported by exportAudit later,
            // and must not take down a live session.
            let _ = write_private(&path, &bytes);
        }
    }
}

/// The runtime: performs transport commands and drives timers until the core is closed.
fn run_runtime(shared: Arc<Shared>) {
    loop {
        let (commands, wait, closed) = {
            let mut core = shared.lock();
            let now = now_ms();
            core.handle_timeout(now);
            let mut commands = Vec::new();
            let external = shared.external.lock().unwrap_or_else(|e| e.into_inner()).is_some();
            if !external {
                while let Some(command) = core.poll_command() {
                    commands.push(command);
                }
            }
            shared.persist(&mut core);
            let wait = core.next_timeout().map_or(1000, |t| t.saturating_sub(now)).clamp(1, 1000);
            (commands, wait, core.is_closed())
        };
        for command in commands {
            links::perform(&shared, command);
        }
        shared.poke();
        if closed && !shared.links.any_open() {
            let mut core = shared.lock();
            shared.persist(&mut core);
            return;
        }
        if shared.stopped.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let guard = shared.lock();
        // A command queued since the last drain must not wait for the next timeout.
        if !external_mode(&shared) && guard.has_pending_commands() {
            continue;
        }
        let (mut guard, _) = shared
            .activity
            .wait_timeout(guard, Duration::from_millis(wait.min(20)))
            .unwrap_or_else(|e| e.into_inner());
        guard.drive(now_ms());
    }
}

fn external_mode(shared: &Shared) -> bool {
    shared.external.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

struct Prepared {
    shared: Arc<Shared>,
    data_dir: Option<PathBuf>,
}

fn prepare(config: &api::SessionConfig, require_chain: bool) -> Result<Prepared, ErrorKind> {
    let provider = provider();
    let store = resolve_key_store(config)?;
    let data_dir = config.data_dir.as_ref().map(PathBuf::from);
    if let Some(dir) = &data_dir {
        std::fs::create_dir_all(dir).map_err(|_| ErrorKind::KeyStoreUnavailable)?;
    }
    let chain = read_chain(&data_dir);
    if require_chain && chain.is_none() {
        return Err(ErrorKind::NotEnrolled);
    }
    let identity: Arc<dyn SigningKey> = store
        .signing_key(provider.as_ref(), IDENTITY_LABEL, true)
        .map_err(|_| ErrorKind::KeyStoreUnavailable)?
        .map(Arc::from)
        .ok_or(ErrorKind::KeyStoreUnavailable)?;
    let core = ClientCore::new(
        ClientOptions {
            provider,
            server_url: config.server_url.clone(),
            ca_bundle: config.ca_bundle.clone(),
            identity,
            chain,
            relay_policy: config.relay_policy.unwrap_or(api::RelayPolicy::PreferDirect),
            identity_change_policy: config.identity_change_policy.unwrap_or(api::IdentityChangePolicy::Block),
            revocation_grace_ms: config.revocation_grace_ms.unwrap_or(DEFAULT_REVOCATION_GRACE_MS),
            saved: read_saved(&data_dir),
            limits: Limits::default(),
        },
        now_ms(),
    )?;
    let external = match &config.external_transport {
        Some(id) => Some(external_registry().lock().unwrap_or_else(|e| e.into_inner()).get(id).cloned().ok_or(ErrorKind::InvalidArgument)?),
        None => None,
    };
    let shared = Arc::new(Shared {
        core: Mutex::new(core),
        activity: Condvar::new(),
        links: links::LinkTable::default(),
        data_dir: data_dir.clone(),
        external: Mutex::new(external.clone()),
        stopped: std::sync::atomic::AtomicBool::new(false),
    });
    if let Some(external) = external {
        *external.shared.lock().unwrap_or_else(|e| e.into_inner()) = Some(shared.clone());
    }
    let runtime = shared.clone();
    std::thread::Builder::new()
        .name("qalqon-runtime".into())
        .spawn(move || run_runtime(runtime))
        .map_err(|_| ErrorKind::Internal)?;
    Ok(Prepared { shared, data_dir })
}

/// `enrollDevice`.
pub fn enroll_device(config: api::SessionConfig, request: api::EnrollmentRequest) -> Result<api::EnrollmentResult, ApiError> {
    let prepared = prepare(&config, false)?;
    let shared = &prepared.shared;
    let op = shared.lock().start_enroll(now_ms(), request);
    shared.poke();
    let outcome = shared.wait_op(op, DEFAULT_OP_TIMEOUT);
    let close = shared.lock().close(now_ms());
    shared.poke();
    let _ = shared.wait_op(close, Duration::from_secs(5));
    match outcome? {
        OpValue::Enrolled { result, chain } => {
            if let Some(path) = data_file(&prepared.data_dir, "device.chain") {
                write_private(&path, to_hex(&chain).as_bytes()).map_err(|_| ErrorKind::KeyStoreUnavailable)?;
            }
            Ok(result)
        }
        _ => Err(ErrorKind::Internal.into()),
    }
}

/// `connect`.
pub fn connect(config: api::SessionConfig, credentials: api::Credentials) -> Result<Session, ApiError> {
    let prepared = prepare(&config, true)?;
    let shared = prepared.shared;
    let op = shared.lock().start_connect(now_ms(), credentials);
    shared.poke();
    match shared.wait_op(op, DEFAULT_OP_TIMEOUT) {
        Ok(_) => Ok(Session { shared }),
        Err(code) => {
            shared.stopped.store(true, std::sync::atomic::Ordering::SeqCst);
            shared.poke();
            Err(code.into())
        }
    }
}

/// `conformanceRun`.
pub fn conformance_run(vectors: &str) -> Result<String, ApiError> {
    let report = qalqon_conformance::run_file(vectors);
    Ok(serde_json::json!({
        "passed": report.passed,
        "failed": report.failed,
        "provider": provider_name(),
    })
    .to_string())
}

/// A logged-in connection to a host.
#[derive(Clone)]
pub struct Session {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Session(..)")
    }
}

impl Session {
    fn channel_from(&self, op: u64, timeout: Duration) -> Result<Channel, ApiError> {
        self.shared.poke();
        match self.shared.wait_op(op, timeout)? {
            OpValue::Channel(id) => Ok(Channel { id, shared: self.shared.clone() }),
            _ => Err(ErrorKind::Internal.into()),
        }
    }

    /// `session.openChannel`.
    pub fn open_channel(&self, peer: api::PeerRef, options: api::ChannelOptions) -> Result<Channel, ApiError> {
        let timeout = Duration::from_millis(u64::from(options.timeout_ms.unwrap_or(30_000)) + 1000);
        let op = self.shared.lock().open_channel(now_ms(), peer, options);
        self.channel_from(op, timeout)
    }

    /// `session.acceptChannel`.
    pub fn accept_channel(&self, request_id: &str) -> Result<Channel, ApiError> {
        let op = self.shared.lock().accept_channel(now_ms(), request_id);
        self.channel_from(op, DEFAULT_OP_TIMEOUT)
    }

    /// `session.rejectChannel`.
    pub fn reject_channel(&self, request_id: &str) -> Result<(), ApiError> {
        self.shared.lock().reject_channel(now_ms(), request_id)?;
        self.shared.poke();
        Ok(())
    }

    /// `session.verifyPeer`.
    pub fn verify_peer(&self, peer: api::PeerRef, safety_number: Option<String>) -> Result<api::PeerIdentity, ApiError> {
        let result = self.shared.lock().verify_peer(now_ms(), &peer, safety_number.as_deref())?;
        self.shared.poke();
        Ok(result)
    }

    /// `session.rotateKeys`.
    pub fn rotate_keys(&self, peer: Option<api::PeerRef>) -> Result<(), ApiError> {
        let op = self.shared.lock().rotate_keys(now_ms(), peer.as_ref());
        self.shared.poke();
        self.shared.wait_op(op, DEFAULT_OP_TIMEOUT)?;
        Ok(())
    }

    /// `session.exportAudit`.
    pub fn export_audit(&self, request: api::AuditExportRequest) -> Result<api::AuditExport, ApiError> {
        Ok(self.shared.lock().export_audit(&request)?)
    }

    /// `session.nextEvent`.
    pub fn next_event(&self, timeout_ms: u32) -> Result<Option<api::Event>, ApiError> {
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        let mut core = self.shared.lock();
        loop {
            if let Some(event) = core.poll_event() {
                return Ok(Some(event));
            }
            if core.is_closed() {
                return Err(ErrorKind::Closed.into());
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let (guard, _) = self
                .shared
                .activity
                .wait_timeout(core, (deadline - now).min(Duration::from_millis(100)))
                .unwrap_or_else(|e| e.into_inner());
            core = guard;
        }
    }

    /// `session.close`.
    pub fn close(&self) -> Result<(), ApiError> {
        let op = self.shared.lock().close(now_ms());
        self.shared.poke();
        self.shared.wait_op(op, Duration::from_secs(10))?;
        Ok(())
    }

    /// The audit chain's position, for tests that compare it with an export.
    pub fn is_closed(&self) -> bool {
        self.shared.lock().is_closed()
    }
}

/// An encrypted channel to one peer.
#[derive(Clone)]
pub struct Channel {
    id: u64,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Channel({})", self.id)
    }
}

impl Channel {
    /// The channel's identifier within its session.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// `channel.send`.
    pub fn send(&self, payload: &[u8]) -> Result<(), ApiError> {
        self.shared.lock().send(now_ms(), self.id, payload)?;
        self.shared.poke();
        Ok(())
    }

    /// `channel.receive`.
    pub fn receive(&self, timeout_ms: u32) -> Result<Option<Vec<u8>>, ApiError> {
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        let mut core = self.shared.lock();
        loop {
            if let Some(message) = core.receive(self.id)? {
                return Ok(Some(message));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let (guard, _) = self
                .shared
                .activity
                .wait_timeout(core, (deadline - now).min(Duration::from_millis(50)))
                .unwrap_or_else(|e| e.into_inner());
            core = guard;
        }
    }

    /// `channel.info`.
    pub fn info(&self) -> Result<api::ChannelInfo, ApiError> {
        Ok(self.shared.lock().channel_info(self.id)?)
    }

    /// `channel.close`.
    pub fn close(&self) -> Result<(), ApiError> {
        let op = self.shared.lock().close_channel(now_ms(), self.id);
        self.shared.poke();
        self.shared.wait_op(op, Duration::from_secs(35))?;
        Ok(())
    }
}

// ------------------------------------------------------------------ external transport

struct ExternalInner {
    id: String,
    shared: Mutex<Option<Arc<Shared>>>,
}

fn external_registry() -> &'static Mutex<HashMap<String, Arc<ExternalInner>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<ExternalInner>>>> = OnceLock::new();
    REGISTRY.get_or_init(Mutex::default)
}

/// `createExternalTransport`.
pub fn create_external_transport() -> Result<ExternalTransport, ApiError> {
    let mut random = [0u8; 16];
    provider().random(&mut random).map_err(|_| ErrorKind::Internal)?;
    let inner = Arc::new(ExternalInner { id: to_hex(&random), shared: Mutex::new(None) });
    external_registry().lock().unwrap_or_else(|e| e.into_inner()).insert(inner.id.clone(), inner.clone());
    Ok(ExternalTransport { inner })
}

/// Lets an adapter own the sockets. See `docs/CLIENT-ADAPTER.md`.
#[derive(Clone)]
pub struct ExternalTransport {
    inner: Arc<ExternalInner>,
}

impl std::fmt::Debug for ExternalTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExternalTransport({})", self.inner.id)
    }
}

impl ExternalTransport {
    fn shared(&self) -> Option<Arc<Shared>> {
        self.inner.shared.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn with_core<T>(&self, f: impl FnOnce(&mut ClientCore) -> T) -> Result<T, ApiError> {
        let shared = self.shared().ok_or(ErrorKind::Closed)?;
        let result = f(&mut shared.lock());
        shared.poke();
        Ok(result)
    }

    /// `externalTransport.handleId`.
    pub fn handle_id(&self) -> Result<String, ApiError> {
        Ok(self.inner.id.clone())
    }

    /// `externalTransport.pollCommand`.
    pub fn poll_command(&self, timeout_ms: u32) -> Result<Option<TransportCommand>, ApiError> {
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
        loop {
            if let Some(shared) = self.shared() {
                let core = shared.lock();
                let mut core = core;
                if let Some(command) = core.poll_command() {
                    return Ok(Some(command));
                }
                let now = Instant::now();
                if now >= deadline {
                    return Ok(None);
                }
                let wait = (deadline - now).min(Duration::from_millis(50));
                let _ = shared.activity.wait_timeout(core, wait).unwrap_or_else(|e| e.into_inner());
            } else {
                let now = Instant::now();
                if now >= deadline {
                    return Ok(None);
                }
                std::thread::sleep((deadline - now).min(Duration::from_millis(10)));
            }
        }
    }

    /// `externalTransport.linkOpened`.
    pub fn link_opened(&self, link_id: u64, caps: api::TransportCaps) -> Result<(), ApiError> {
        self.with_core(|core| core.link_opened(now_ms(), link_id, caps))
    }

    /// `externalTransport.linkClosed`.
    pub fn link_closed(&self, link_id: u64) -> Result<(), ApiError> {
        self.with_core(|core| core.link_closed(now_ms(), link_id))
    }

    /// `externalTransport.frameReceived`.
    pub fn frame_received(&self, link_id: u64, frame: &[u8]) -> Result<(), ApiError> {
        self.with_core(|core| core.frame_received(now_ms(), link_id, frame))
    }

    /// `externalTransport.signalReceived`.
    pub fn signal_received(&self, link_id: u64, blob: &[u8]) -> Result<(), ApiError> {
        self.with_core(|core| core.signal_received(now_ms(), link_id, blob))
    }
}
