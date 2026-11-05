//! `qalqon-ca init <dir>`: writes a development hierarchy to a directory.
//! `qalqon-ca server <dir> <host>`: adds a server key and chain.
//! `qalqon-ca device <dir> <user> <device>`: adds a device key and chain.
//!
//! Files are hex. Key files are created with mode `0600`. This is a development tool
//! running on the test-only provider, so its output protects nothing real.

use crypto_provider::{CryptoProvider, SigningKey, from_hex, to_hex};
use provider_testonly::TestOnlyProvider;
use qalqon_ca::DevCa;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn write_key(path: &Path, key: &dyn SigningKey) -> Result<(), String> {
    let secret = key.export_secret().ok_or("this key cannot be exported")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(to_hex(&secret).as_bytes())
        .map_err(|e| e.to_string())
}

fn read_key(p: &dyn CryptoProvider, path: &Path) -> Result<Box<dyn SigningKey>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bytes = from_hex(text.trim()).ok_or("malformed key file")?;
    p.import_signing_key(&bytes).map_err(|e| e.to_string())
}

fn write_hex(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, to_hex(bytes)).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_hex(path: &Path) -> Result<Vec<u8>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    from_hex(text.trim()).ok_or_else(|| format!("{} is not hex", path.display()))
}

fn load_ca(provider: Arc<dyn CryptoProvider>, dir: &Path) -> Result<DevCa, String> {
    let root_key = read_key(provider.as_ref(), &dir.join("root.key"))?;
    let issuing_key = read_key(provider.as_ref(), &dir.join("issuing.key"))?;
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
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            let ca = DevCa::new(provider, now_ms()).map_err(|e| format!("{e:?}"))?;
            write_key(&dir.join("root.key"), ca.root_key.as_ref())?;
            write_key(&dir.join("issuing.key"), ca.issuing_key.as_ref())?;
            write_hex(&dir.join("root.cert"), &ca.root_cert)?;
            write_hex(&dir.join("issuing.cert"), &ca.issuing_cert)
        }
        ["server", dir, host] => {
            let dir = Path::new(dir);
            let ca = load_ca(provider.clone(), dir)?;
            let key = provider.generate_signing_key().map_err(|e| e.to_string())?;
            let chain = ca
                .issue_server(host, "instance-1", key.as_ref(), now_ms())
                .map_err(|e| format!("{e:?}"))?;
            write_key(&dir.join(format!("server-{host}.key")), key.as_ref())?;
            write_hex(&dir.join(format!("server-{host}.chain")), &chain)
        }
        ["device", dir, user, device] => {
            let dir = Path::new(dir);
            let ca = load_ca(provider.clone(), dir)?;
            let key = provider.generate_signing_key().map_err(|e| e.to_string())?;
            let chain = ca
                .issue_device(user, device, key.as_ref(), now_ms())
                .map_err(|e| format!("{e:?}"))?;
            write_key(
                &dir.join(format!("device-{user}-{device}.key")),
                key.as_ref(),
            )?;
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
