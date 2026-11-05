//! A key store for mounted secrets, as containers use (`targets.yaml`). Keys are wrapped
//! under a key-encryption key kept in a `0600` file, with the provider's `key_wrap`.
//!
//! This protects keys against reading the wrapped files alone. It does not protect
//! against anyone who can read the directory's KEK file, so the platform stores in
//! ADR-0002, part 6, are stronger wherever they exist. They are a recorded gap.
//!
//! The one `unsafe`-free compromise is on non-Unix platforms, where a file's mode cannot
//! be set here: this crate refuses to run there rather than leave keys readable.
#![forbid(unsafe_code)]

use crypto_provider::{
    AeadKey, CryptoProvider, KeyStore, KeyStoreError, Secret, SigningKey, Zeroizing, secret,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// See the crate documentation.
#[derive(Clone, Debug)]
pub struct FileKeyStore {
    dir: PathBuf,
}

fn unavailable(what: &str, e: std::io::Error) -> KeyStoreError {
    KeyStoreError::Unavailable(format!("{what}: {e}"))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), KeyStoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| unavailable("creating a key file", e))?;
    file.write_all(bytes)
        .map_err(|e| unavailable("writing a key file", e))?;
    file.sync_all()
        .map_err(|e| unavailable("syncing a key file", e))
}

fn read_private(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
    match fs::metadata(path) {
        Ok(meta) => {
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(KeyStoreError::Unavailable(format!(
                    "{} is readable by other users",
                    path.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(unavailable("reading a key file", e)),
    }
    fs::read(path)
        .map(|b| Some(Zeroizing::new(b)))
        .map_err(|e| unavailable("reading a key file", e))
}

fn valid_label(label: &str) -> Result<(), KeyStoreError> {
    let ok = !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !label.starts_with('.');
    if ok {
        Ok(())
    } else {
        Err(KeyStoreError::Unavailable(format!(
            "invalid key label: {label}"
        )))
    }
}

impl FileKeyStore {
    /// Opens a key store in `dir`, creating the directory with mode `0700` if needed.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, KeyStoreError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| unavailable("creating the key directory", e))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| unavailable("securing the key directory", e))?;
        Ok(FileKeyStore { dir })
    }

    fn kek(&self, provider: &dyn CryptoProvider) -> Result<AeadKey, KeyStoreError> {
        let params = provider.params();
        let path = self.dir.join("kek");
        let len = params.key_len + params.mac_key_len;
        let bytes = match read_private(&path)? {
            Some(b) => b,
            None => {
                let mut fresh = Zeroizing::new(vec![0u8; len]);
                provider.random(&mut fresh)?;
                write_private(&path, &fresh)?;
                fresh
            }
        };
        if bytes.len() != len {
            return Err(KeyStoreError::Corrupt);
        }
        Ok(AeadKey {
            enc: secret(&bytes[..params.key_len]),
            mac: secret(&bytes[params.key_len..]),
        })
    }

    fn load_or_store(
        &self,
        provider: &dyn CryptoProvider,
        file: &str,
        create: &dyn Fn() -> Result<Secret, KeyStoreError>,
    ) -> Result<Secret, KeyStoreError> {
        let kek = self.kek(provider)?;
        let path = self.dir.join(file);
        if let Some(wrapped) = read_private(&path)? {
            return provider
                .key_unwrap(&kek, &wrapped)
                .map_err(|_| KeyStoreError::Corrupt);
        }
        let fresh = create()?;
        let wrapped = provider.key_wrap(&kek, &fresh)?;
        write_private(&path, &wrapped)?;
        Ok(fresh)
    }
}

impl KeyStore for FileKeyStore {
    fn signing_key(
        &self,
        provider: &dyn CryptoProvider,
        label: &str,
        create: bool,
    ) -> Result<Option<Box<dyn SigningKey>>, KeyStoreError> {
        valid_label(label)?;
        let file = format!("{label}.signing");
        if !create && !self.dir.join(&file).exists() {
            return Ok(None);
        }
        let stored = self.load_or_store(provider, &file, &|| {
            provider
                .generate_signing_key()?
                .export_secret()
                .ok_or_else(|| KeyStoreError::Unavailable("this key cannot be wrapped".into()))
        })?;
        Ok(Some(provider.import_signing_key(&stored)?))
    }

    fn secret(
        &self,
        provider: &dyn CryptoProvider,
        label: &str,
        len: usize,
    ) -> Result<Secret, KeyStoreError> {
        valid_label(label)?;
        self.load_or_store(provider, &format!("{label}.secret"), &|| {
            let mut fresh = Zeroizing::new(vec![0u8; len]);
            provider.random(&mut fresh)?;
            Ok(fresh)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provider_testonly::TestOnlyProvider;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_dir() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "qalqon-keystore-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_key_survives_reopening_and_is_wrapped_on_disk() {
        let p = TestOnlyProvider::new();
        let dir = temp_dir();
        let store = FileKeyStore::open(&dir).unwrap();
        assert!(store.signing_key(&p, "identity", false).unwrap().is_none());
        let key = store.signing_key(&p, "identity", true).unwrap().unwrap();
        let public = key.public_key().clone();
        let exported = key.export_secret().unwrap();

        let again = FileKeyStore::open(&dir)
            .unwrap()
            .signing_key(&p, "identity", false)
            .unwrap()
            .unwrap();
        assert_eq!(again.public_key(), &public);

        let on_disk = fs::read(dir.join("identity.signing")).unwrap();
        assert!(
            !on_disk
                .windows(exported.len())
                .any(|w| w == exported.as_slice()),
            "the key is on disk in the clear"
        );
        let mode = fs::metadata(dir.join("identity.signing"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_readable_key_file_is_refused() {
        let p = TestOnlyProvider::new();
        let dir = temp_dir();
        let store = FileKeyStore::open(&dir).unwrap();
        store.signing_key(&p, "identity", true).unwrap();
        fs::set_permissions(
            dir.join("identity.signing"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            store.signing_key(&p, "identity", false),
            Err(KeyStoreError::Unavailable(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_tampered_key_file_is_refused() {
        let p = TestOnlyProvider::new();
        let dir = temp_dir();
        let store = FileKeyStore::open(&dir).unwrap();
        store.signing_key(&p, "identity", true).unwrap();
        let path = dir.join("identity.signing");
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            store.signing_key(&p, "identity", false),
            Err(KeyStoreError::Corrupt)
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn labels_cannot_escape_the_directory() {
        let p = TestOnlyProvider::new();
        let store = FileKeyStore::open(temp_dir()).unwrap();
        for bad in ["../evil", "a/b", ".hidden", ""] {
            assert!(store.signing_key(&p, bad, true).is_err(), "{bad}");
        }
    }

    #[test]
    fn secrets_are_stable_and_distinct() {
        let p = TestOnlyProvider::new();
        let store = FileKeyStore::open(temp_dir()).unwrap();
        let one = store.secret(&p, "audit-log", 32).unwrap();
        assert_eq!(one.len(), 32);
        assert_eq!(
            store.secret(&p, "audit-log", 32).unwrap().as_slice(),
            one.as_slice()
        );
        assert_ne!(
            store.secret(&p, "relay", 32).unwrap().as_slice(),
            one.as_slice()
        );
    }
}
