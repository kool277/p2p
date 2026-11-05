//! The development CA.
//!
//! ```text
//! qalqon-ca init <dir>                    a root and an issuing CA
//! qalqon-ca server <dir> <host>           a server key and chain, and the relay and audit keys
//! qalqon-ca device <dir> <user> <device>  a device key and chain, for tests that skip enrolment
//! ```
//!
//! Keys go into `<dir>/keys`, wrapped by `keystore-file`, and hosts open them by reference.
//! Certificates are hex files. This runs on the test-only provider, so its output protects
//! nothing real, and a real deployment keeps its root offline.

use crypto_provider::{CryptoProvider, KeyStore, SigningKey, from_hex, to_hex};
use keystore_file::FileKeyStore;
use provider_testonly::TestOnlyProvider;
use qalqon_ca::DevCa;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn key(
    store: &FileKeyStore,
    p: &dyn CryptoProvider,
    label: &str,
) -> Result<Box<dyn SigningKey>, String> {
    store
        .signing_key(p, label, true)
        .map_err(|e| format!("{label}: {e:?}"))?
        .ok_or_else(|| format!("{label}: no such key"))
}

fn write_hex(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, to_hex(bytes)).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_hex(path: &Path) -> Result<Vec<u8>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    from_hex(text.trim()).ok_or_else(|| format!("{} is not hex", path.display()))
}

fn store(dir: &Path) -> Result<FileKeyStore, String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    FileKeyStore::open(dir.join("keys")).map_err(|e| format!("{e:?}"))
}

fn load_ca(provider: Arc<dyn CryptoProvider>, dir: &Path) -> Result<DevCa, String> {
    let keys = store(dir)?;
    let root_key = key(&keys, provider.as_ref(), "root")?;
    let issuing_key = key(&keys, provider.as_ref(), "issuing")?;
    Ok(DevCa::load(
        provider,
        root_key,
        issuing_key,
        read_hex(&dir.join("root.cert"))?,
        read_hex(&dir.join("issuing.cert"))?,
    ))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let provider: Arc<dyn CryptoProvider> = Arc::new(TestOnlyProvider::new());
    let usage = "usage: qalqon-ca init <dir> | server <dir> <host> | device <dir> <user> <device>";
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["init", dir] => {
            let dir = Path::new(dir);
            let keys = store(dir)?;
            let root_key = key(&keys, provider.as_ref(), "root")?;
            let issuing_key = key(&keys, provider.as_ref(), "issuing")?;
            let ca = DevCa::from_keys(provider, root_key, issuing_key, now_ms())
                .map_err(|e| format!("{e:?}"))?;
            write_hex(&dir.join("root.cert"), &ca.root_cert)?;
            write_hex(&dir.join("issuing.cert"), &ca.issuing_cert)
        }
        ["server", dir, host] => {
            let dir = Path::new(dir);
            let ca = load_ca(provider.clone(), dir)?;
            let keys = store(dir)?;
            let server = key(&keys, provider.as_ref(), &format!("server-{host}"))?;
            keys.secret(provider.as_ref(), "relay", 32)
                .map_err(|e| format!("{e:?}"))?;
            keys.secret(provider.as_ref(), "audit-log", 32)
                .map_err(|e| format!("{e:?}"))?;
            let chain = ca
                .issue_server(host, "instance-1", server.as_ref(), now_ms())
                .map_err(|e| format!("{e:?}"))?;
            write_hex(&dir.join(format!("server-{host}.chain")), &chain)
        }
        ["device", dir, user, device] => {
            let dir = Path::new(dir);
            let ca = load_ca(provider.clone(), dir)?;
            let device_key = provider.generate_signing_key().map_err(|e| e.to_string())?;
            let chain = ca
                .issue_device(user, device, device_key.as_ref(), now_ms())
                .map_err(|e| format!("{e:?}"))?;
            let secret = device_key
                .export_secret()
                .ok_or("this key cannot be exported")?;
            let path = dir.join(format!("device-{user}-{device}.key"));
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                file.write_all(to_hex(&secret).as_bytes())
                    .map_err(|e| e.to_string())?;
            }
            write_hex(&dir.join(format!("device-{user}-{device}.chain")), &chain)
        }
        _ => Err(usage.into()),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
