//! Rule 0.4: protocol and crypto logic may exist only under `core/`. This fails any
//! binding, package, client, server or template that implements a handshake step, derives
//! a key or touches a key byte. It looks for the names such code cannot avoid. It is a
//! tripwire and not a proof, and review still matters.

use std::path::{Path, PathBuf};

const SCANNED: &[&str] = &["bindings", "packages", "clients", "servers", "templates"];

/// Generated from the IDL, so these may mention key references and identity handles.
const SKIPPED_DIRS: &[&str] = &["node_modules", "dist", "target", "wasm", ".git", "browser"];

const TEXT_EXTENSIONS: &[&str] = &[
    "rs", "c", "h", "cpp", "hpp", "js", "jsx", "mjs", "ts", "tsx", "php", "py", "rb", "ex", "sh",
    "go", "java", "kt", "cs", "swift", "dart", "qml", "yaml",
];

/// (what it looks for, why it is not allowed here)
const FORBIDDEN: &[(&str, &str)] = &[
    ("XX_INIT", "a handshake message"),
    ("XX_RESP", "a handshake message"),
    ("XX_FINISH", "a handshake message"),
    ("expand_label", "key derivation"),
    ("derive_secret", "key derivation"),
    ("hkdf", "key derivation"),
    ("hmac", "a MAC"),
    ("aead_", "record protection"),
    ("kex_", "key agreement"),
    ("export_secret", "raw key access"),
    ("import_signing_key", "raw key access"),
    ("generate_signing_key", "raw key access"),
    ("qalqon_core::schedule", "the key schedule"),
    ("qalqon_core::record", "the record layer"),
    ("qalqon_core::session", "the protocol engine"),
    ("crypto.subtle", "cryptography outside the core"),
    ("subtle.encrypt", "cryptography outside the core"),
    ("subtle.decrypt", "cryptography outside the core"),
    ("createCipher", "cryptography outside the core"),
    ("createHmac", "cryptography outside the core"),
    ("createHash", "cryptography outside the core"),
    ("openssl_", "cryptography outside the core"),
    ("hashlib", "cryptography outside the core"),
    ("Sha256", "a hash outside the core"),
    ("sha256", "a hash outside the core"),
    ("x25519", "key agreement"),
    ("ed25519", "signatures"),
    ("ml_kem", "key agreement"),
];

/// A driver may hash a path to pick a port. That is not protocol logic.
const ALLOWED: &[(&str, &str)] = &[("tests/", "")];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !SKIPPED_DIRS.contains(&name.as_str()) {
                walk(&path, out);
            }
        } else if path
            .extension()
            .is_some_and(|e| TEXT_EXTENSIONS.contains(&e.to_string_lossy().as_ref()))
        {
            out.push(path);
        }
    }
}

/// Finds violations under `root`, as `(path, line, what, why)`.
pub fn scan(root: &Path) -> Vec<(String, usize, &'static str, &'static str)> {
    let mut files = Vec::new();
    for folder in SCANNED {
        walk(&root.join(folder), &mut files);
    }
    let mut violations = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .to_string();
        if ALLOWED
            .iter()
            .any(|(prefix, _)| relative.starts_with(prefix))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            for (needle, why) in FORBIDDEN {
                if line.contains(needle) {
                    violations.push((relative.clone(), index + 1, *needle, *why));
                }
            }
        }
    }
    violations
}

pub fn run(root: &Path) -> Result<(), String> {
    let violations = scan(root);
    if violations.is_empty() {
        println!("rule 0.4: no protocol or crypto logic found outside core/");
        return Ok(());
    }
    for (path, line, what, why) in &violations {
        eprintln!("{path}:{line}: `{what}` ({why}) does not belong outside core/");
    }
    Err(format!("{} violations of rule 0.4", violations.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qalqon-lint-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("servers/bad")).unwrap();
        dir
    }

    #[test]
    fn a_host_that_derives_a_key_is_caught() {
        let root = temp_root("bad");
        std::fs::write(
            root.join("servers/bad/app.py"),
            "import hashlib\nkey = hkdf(secret)\n",
        )
        .unwrap();
        let found = scan(&root);
        assert!(
            found
                .iter()
                .any(|(p, l, w, _)| p == "servers/bad/app.py" && *l == 1 && *w == "hashlib")
        );
        assert!(found.iter().any(|(_, l, w, _)| *l == 2 && *w == "hkdf"));
        assert!(run(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_thin_host_is_clean() {
        let root = temp_root("good");
        std::fs::write(
            root.join("servers/bad/app.py"),
            "core.on_frame(conn, frame)\n",
        )
        .unwrap();
        assert!(scan(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dependencies_and_build_output_are_not_scanned() {
        let root = temp_root("deps");
        std::fs::create_dir_all(root.join("clients/x/node_modules/lib")).unwrap();
        std::fs::write(
            root.join("clients/x/node_modules/lib/a.js"),
            "crypto.subtle.encrypt()\n",
        )
        .unwrap();
        assert!(scan(&root).is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
