//! `idlgen` writes every generated file from `core/idl/qalqon.api.yaml`, and
//! `idlgen --check` fails if any file on disk differs from what it would write.
//! Run it from the repository root, or let `cargo run -p idlgen` find the root.

mod c_abi;
mod docs;
mod idl;
mod rust_api;
mod schema;
mod sidecar;

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root exists")
}

fn main() {
    let check = std::env::args().any(|a| a == "--check");
    let root = root();
    let source =
        std::fs::read_to_string(root.join("core/idl/qalqon.api.yaml")).expect("read the IDL");
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
        (
            "core/idl/generated/qalqon.jsonrpc.json",
            schema::jsonrpc(&idl),
        ),
        ("core/idl/generated/qalqon.d.ts", schema::typescript(&idl)),
    ];
    outputs.push(("core/ffi/src/generated.rs", c_abi::generate(&idl)));
    outputs.push(("core/sidecar/src/generated.rs", sidecar::dispatch(&idl)));
    outputs.push((
        "bindings/sidecar-clients/php/QalqonClient.php",
        sidecar::php(&idl),
    ));
    outputs.push((
        "bindings/sidecar-clients/ruby/qalqon_client.rb",
        sidecar::ruby(&idl),
    ));
    outputs.push((
        "bindings/sidecar-clients/elixir/qalqon_client.ex",
        sidecar::elixir(&idl),
    ));
    outputs.push((
        "bindings/sidecar-clients/shell/qalqon.sh",
        sidecar::shell(&idl),
    ));
    outputs.sort_by_key(|(path, _)| *path);

    // cbindgen reads the ABI source, so in --check mode it reads what would be written.
    let abi_dir = std::env::temp_dir().join(format!("qalqon-idlgen-{}", std::process::id()));
    std::fs::create_dir_all(&abi_dir).expect("create a temporary directory");
    std::fs::copy(root.join("core/ffi/src/lib.rs"), abi_dir.join("lib.rs"))
        .expect("read the ABI source");
    let generated = outputs
        .iter()
        .find(|(p, _)| *p == "core/ffi/src/generated.rs")
        .expect("generated above");
    std::fs::write(abi_dir.join("generated.rs"), &generated.1).expect("write a temporary file");
    let header = c_abi::header(&abi_dir);
    let _ = std::fs::remove_dir_all(&abi_dir);
    outputs.push(("bindings/c/include/qalqon.h", header));

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
