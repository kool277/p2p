//! `idlgen` writes every generated file from `core/idl/qalqon.api.yaml`, and
//! `idlgen --check` fails if any file on disk differs from what it would write.
//! Run it from the repository root, or let `cargo run -p idlgen` find the root.

mod docs;
mod idl;
mod rust_api;
mod schema;

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().expect("the repository root exists")
}

fn main() {
    let check = std::env::args().any(|a| a == "--check");
    let root = root();
    let source = std::fs::read_to_string(root.join("core/idl/qalqon.api.yaml")).expect("read the IDL");
    let idl = match idl::Idl::parse(&source) {
        Ok(idl) => idl,
        Err(problems) => {
            eprintln!("the IDL has problems:\n{problems}");
            std::process::exit(1);
        }
    };

    let mut outputs: Vec<(&str, String)> = vec![
        ("core/qalqon-api/src/generated.rs", rust_api::generate(&idl)),
        ("docs/SDK-API.md", docs::generate(&idl)),
        ("core/idl/generated/qalqon.udl", schema::udl(&idl)),
        ("core/idl/generated/qalqon.wit", schema::wit(&idl)),
        ("core/idl/generated/qalqon.jsonrpc.json", schema::jsonrpc(&idl)),
        ("core/idl/generated/qalqon.d.ts", schema::typescript(&idl)),
    ];
    outputs.sort_by_key(|(path, _)| *path);

    let mut stale = false;
    for (path, content) in &outputs {
        let full = root.join(path);
        if check {
            if std::fs::read_to_string(&full).ok().as_deref() != Some(content.as_str()) {
                eprintln!("{path} is stale. Run `cargo run -p idlgen`.");
                stale = true;
            }
        } else {
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).expect("create the directory");
            }
            std::fs::write(&full, content).expect("write the file");
            println!("wrote {path}");
        }
    }
    if stale {
        std::process::exit(1);
    }
}
