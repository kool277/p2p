//! The `qalqon` command. Run it with `cargo qalqon <command>` from anywhere in the repository.
//!
//! ```text
//! qalqon list                                       every client, server and primary pair
//! qalqon doctor [--client <x>] [--server <y>]       checks toolchains, and says how to get them
//! qalqon manifests [--check]                        writes combinations.yaml from the manifests
//! qalqon lint                                       rule 0.4: no protocol logic outside core/
//! qalqon build --client <x> --server <y>            builds only what this pair needs
//! qalqon dev --client <x> --server <y>              runs the host and the relay locally
//! qalqon test --pair <x>:<y> | --triple <a>,<b>:<y> | --conformance <binding> | --primary
//! qalqon package --client <x> --server <y>          artifacts into dist/<x>+<y>/
//! qalqon new binding --lang <x> --path ffi|wasm|sidecar
//! qalqon new client --lang <x> --framework <y>
//! qalqon new server --lang <x> --framework <y>
//! qalqon new target --triple <t> --os <name>
//! ```

mod lint;
mod manifests;
mod scaffold;

use manifests::{Manifest, Repo};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn run_shell(root: &Path, command: &str) -> Result<(), String> {
    let status = Command::new("bash")
        .arg("-c")
        .arg(command)
        .current_dir(root)
        .status()
        .map_err(|e| format!("cannot run bash: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("this failed: {command}"))
    }
}

fn require_pair(args: &[String]) -> Result<(String, String), String> {
    match (flag(args, "--client"), flag(args, "--server")) {
        (Some(c), Some(s)) => Ok((c, s)),
        _ => Err("this needs --client <name> and --server <name>".into()),
    }
}

/// Hashes a folder's sources, so an unchanged folder is not rebuilt.
fn hash_folder(hasher: &mut Sha256, folder: &Path, root: &Path) {
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(folder) {
        Ok(read) => read.flatten().map(|e| e.path()).collect(),
        Err(_) => return,
    };
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if matches!(
            name.as_str(),
            "target" | "node_modules" | "dist" | ".qalqon" | "wasm"
        ) {
            continue;
        }
        if path.is_dir() {
            hash_folder(hasher, &path, root);
        } else if let Ok(bytes) = std::fs::read(&path) {
            hasher.update(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .as_bytes(),
            );
            hasher.update([0]);
            hasher.update(&bytes);
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A folder's content-addressed key: its sources, everything it depends on, the lockfile
/// and the Rust toolchain (ADR-0003, part 5).
fn cache_key(repo: &Repo, manifest: &Manifest) -> String {
    let mut hasher = Sha256::new();
    let mut folders: Vec<&Manifest> = repo.closure(std::slice::from_ref(&manifest.path));
    folders.sort_by(|a, b| a.path.cmp(&b.path));
    for folder in folders {
        hash_folder(&mut hasher, &repo.root.join(&folder.path), &repo.root);
    }
    for file in ["Cargo.lock", "rust-toolchain.toml"] {
        if let Ok(bytes) = std::fs::read(repo.root.join(file)) {
            hasher.update(&bytes);
        }
    }
    to_hex(&hasher.finalize())
}

/// Builds only the folders on the pair's path, reusing what is cached.
fn build(repo: &Repo, starts: &[String]) -> Result<(), String> {
    let closure = repo.closure(starts);
    let cache = repo.root.join(".qalqon/cache");
    std::fs::create_dir_all(&cache).map_err(|e| e.to_string())?;
    let mut built = 0;
    let mut reused = 0;
    for manifest in closure {
        if manifest.build.is_empty() {
            continue;
        }
        let key = cache_key(repo, manifest);
        let stamp = cache.join(format!("{}-{key}", manifest.name));
        if stamp.exists() {
            reused += 1;
            println!("  cached  {}", manifest.path);
            continue;
        }
        println!("  build   {}", manifest.path);
        for command in &manifest.build {
            run_shell(&repo.root, command)?;
        }
        std::fs::write(&stamp, "").map_err(|e| e.to_string())?;
        built += 1;
    }
    println!("built {built}, reused {reused}");
    Ok(())
}

/// The folders a pair needs: both sides, plus the services every pair needs.
fn pair_folders(repo: &Repo, client: &str, server: &str) -> Result<Vec<String>, String> {
    let client = repo.find(client, "client")?;
    let server = repo.find(server, "server")?;
    let mut starts = vec![
        client.path.clone(),
        server.path.clone(),
        "infra/relay".to_string(),
        "tools/qalqon-ca".to_string(),
    ];
    // The other end of every interop run.
    if let Ok(peer) = repo.find("cli-rust", "client") {
        starts.push(peer.path.clone());
    }
    Ok(starts)
}

fn interop(
    repo: &Repo,
    client: &str,
    peer: &str,
    server: &str,
    records: Option<String>,
) -> Result<(), String> {
    let starts = pair_folders(repo, client, server)?;
    let mut starts = starts;
    starts.push(repo.find(peer, "client")?.path.clone());
    build(repo, &starts)?;
    let records = records.map_or(String::new(), |r| format!(" --records {r}"));
    run_shell(
        &repo.root,
        &format!(
            "python3 tests/interop/interop.py --client {client} --peer {peer} --server {server}{records}"
        ),
    )
}

fn test(repo: &Repo, args: &[String]) -> Result<(), String> {
    let records = flag(args, "--records");
    if let Some(pair) = flag(args, "--pair") {
        let (client, server) = pair
            .split_once(':')
            .ok_or("--pair looks like client:server")?;
        return interop(repo, client, "cli-rust", server, records);
    }
    if let Some(triple) = flag(args, "--triple") {
        let (clients, server) = triple
            .split_once(':')
            .ok_or("--triple looks like a,b:server")?;
        let (a, b) = clients
            .split_once(',')
            .ok_or("--triple looks like a,b:server")?;
        return interop(repo, a, b, server, records);
    }
    if let Some(binding) = flag(args, "--conformance") {
        let manifest = repo.find(&binding, "binding")?;
        let command = manifest
            .conformance
            .as_ref()
            .ok_or_else(|| format!("{binding} has no conformance command"))?;
        build(repo, std::slice::from_ref(&manifest.path))?;
        println!("conformance: {binding}");
        return run_shell(&repo.root, command);
    }
    if args.iter().any(|a| a == "--primary") {
        for server in repo.of_kind("server") {
            for client in &server.primary_pairs {
                interop(repo, client, "cli-rust", &server.name, records.clone())?;
            }
            for triple in &server.primary_triples {
                if let [a, b] = triple.as_slice() {
                    interop(repo, a, b, &server.name, records.clone())?;
                }
            }
        }
        return Ok(());
    }
    Err("test needs --pair, --triple, --conformance or --primary".into())
}

fn list(repo: &Repo) {
    let names = |kind: &str| {
        repo.of_kind(kind)
            .iter()
            .map(|m| m.name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!("clients:  {}", names("client"));
    println!("servers:  {}", names("server"));
    println!("bindings: {}", names("binding"));
    println!("packages: {}", names("package"));
    let unowned: Vec<&str> = repo
        .all()
        .filter(|m| m.owners.is_empty())
        .map(|m| m.path.as_str())
        .collect();
    if !unowned.is_empty() {
        println!(
            "unowned, so treat these as experimental: {}",
            unowned.join(", ")
        );
    }
    println!("primary pairs:");
    for server in repo.of_kind("server") {
        for client in &server.primary_pairs {
            println!("  {client} + {}", server.name);
        }
        for triple in &server.primary_triples {
            println!("  {} + {}", triple.join(" and "), server.name);
        }
    }
}

const TOOLS: &[(&str, &str, &str)] = &[
    ("cargo", "--version", "curl https://sh.rustup.rs | sh"),
    (
        "node",
        "--version",
        "install Node 22 LTS from nodejs.org, or use infra/devcontainer",
    ),
    ("npm", "--version", "it comes with Node"),
    ("gcc", "--version", "sudo apt install build-essential"),
    ("php", "--version", "sudo apt install php-cli"),
    (
        "wasm-bindgen",
        "--version",
        "cargo install wasm-bindgen-cli --version 0.2.130 --locked",
    ),
];

fn doctor(repo: &Repo, args: &[String]) -> Result<(), String> {
    let needed: BTreeSet<String> = match (flag(args, "--client"), flag(args, "--server")) {
        (Some(c), Some(s)) => {
            let starts = pair_folders(repo, &c, &s)?;
            repo.closure(&starts)
                .iter()
                .flat_map(|m| m.toolchain.keys().cloned())
                .collect()
        }
        _ => repo
            .all()
            .flat_map(|m| m.toolchain.keys().cloned())
            .collect(),
    };
    let mut missing = false;
    for tool in &needed {
        let version_flag = TOOLS
            .iter()
            .find(|(t, _, _)| t == tool)
            .map_or("--version", |(_, f, _)| *f);
        let output = Command::new(tool).arg(version_flag).output();
        match output {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                println!("  ok       {tool}: {}", text.lines().next().unwrap_or(""));
            }
            _ => {
                missing = true;
                let hint = TOOLS
                    .iter()
                    .find(|(t, _, _)| t == tool)
                    .map_or("see infra/devcontainer", |(_, _, h)| *h);
                println!("  missing  {tool}: {hint}");
            }
        }
    }
    println!(
        "provider: test-only. `provider-<lib>` waits for the certified library, so release builds are refused."
    );
    if missing {
        Err("some toolchains are missing".into())
    } else {
        Ok(())
    }
}

fn dev(repo: &Repo, args: &[String]) -> Result<(), String> {
    let (client, server) = require_pair(args)?;
    let starts = pair_folders(repo, &client, &server)?;
    build(repo, &starts)?;
    run_shell(
        &repo.root,
        &format!("tests/interop/dev.sh {server} {client}"),
    )
}

fn package(repo: &Repo, args: &[String]) -> Result<(), String> {
    let (client, server) = require_pair(args)?;
    let starts = pair_folders(repo, &client, &server)?;
    build(repo, &starts)?;
    let dist = repo.root.join("dist").join(format!("{client}+{server}"));
    std::fs::create_dir_all(&dist).map_err(|e| e.to_string())?;
    let notice = "These are development artifacts built with the test-only crypto provider. \
                  They are unsigned, have no SBOM, and must not protect anything real. \
                  Signed release packaging arrives with the certified library in Phase 6.\n";
    std::fs::write(dist.join("NOT-FOR-RELEASE.txt"), notice).map_err(|e| e.to_string())?;
    run_shell(
        &repo.root,
        &format!(
            "cp target/debug/qalqon-relay target/debug/qalqon-ca {dist}/ 2>/dev/null; \
             [ -f target/debug/qalqon-axum ] && cp target/debug/qalqon-axum {dist}/; \
             [ -f target/cli-c/qalqon-cli-c ] && [ {client} = cli-c ] && cp target/cli-c/qalqon-cli-c {dist}/; \
             [ {client} = web-react ] && cp -r clients/web-react/dist {dist}/web-react; true",
            dist = dist.display()
        ),
    )?;
    println!(
        "artifacts in {} (development only, see NOT-FOR-RELEASE.txt)",
        dist.display()
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = manifests::find_root()?;
    let command = args.first().map(String::as_str).unwrap_or("help");
    if command == "new" {
        return scaffold::run(&root, &args[1..]);
    }
    let repo = Repo::load(&root)?;
    match command {
        "list" => {
            list(&repo);
            Ok(())
        }
        "doctor" => doctor(&repo, &args),
        "manifests" => manifests::write_combinations(&repo, args.iter().any(|a| a == "--check")),
        "lint" => lint::run(&root),
        "build" => {
            let (client, server) = require_pair(&args)?;
            build(&repo, &pair_folders(&repo, &client, &server)?)
        }
        "test" => test(&repo, &args),
        "dev" => dev(&repo, &args),
        "package" => package(&repo, &args),
        _ => {
            Err("usage: qalqon <list|doctor|manifests|lint|build|dev|test|package|new> ...".into())
        }
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("qalqon: {e}");
        std::process::exit(1);
    }
}
