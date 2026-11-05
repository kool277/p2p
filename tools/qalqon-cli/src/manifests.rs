//! Reads every `qalqon.yaml`, resolves dependency closures, and writes `combinations.yaml`.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub framework: Option<String>,
    #[serde(default)]
    pub delivery: Option<String>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub toolchain: BTreeMap<String, String>,
    #[serde(default)]
    pub primary_pairs: Vec<String>,
    #[serde(default)]
    pub primary_triples: Vec<Vec<String>>,
    #[serde(default)]
    pub build: Vec<String>,
    #[serde(default)]
    pub conformance: Option<String>,
    #[serde(default)]
    pub owners: Vec<String>,
    #[serde(skip)]
    pub path: String,
}

#[derive(Debug)]
pub struct Repo {
    pub root: PathBuf,
    manifests: BTreeMap<String, Manifest>,
}

/// The repository root, found by walking up from the current directory.
pub fn find_root() -> Result<PathBuf, String> {
    let mut dir = std::env::current_dir().map_err(|e| e.to_string())?;
    loop {
        if dir.join("targets.yaml").exists() && dir.join("Cargo.toml").exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err("this is not inside the Qalqon repository".into());
        }
    }
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if !matches!(
                name.as_str(),
                "target" | "node_modules" | "dist" | ".qalqon" | ".git" | "templates"
            ) {
                collect(&path, out);
            }
        } else if name == "qalqon.yaml" {
            out.push(path);
        }
    }
}

impl Repo {
    pub fn load(root: &Path) -> Result<Repo, String> {
        let mut files = Vec::new();
        collect(root, &mut files);
        let mut manifests = BTreeMap::new();
        for file in files {
            let text =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let mut manifest: Manifest =
                serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
            let folder = file.parent().unwrap_or(root);
            manifest.path = folder
                .strip_prefix(root)
                .unwrap_or(folder)
                .to_string_lossy()
                .to_string();
            if !matches!(
                manifest.kind.as_str(),
                "core" | "binding" | "package" | "client" | "server" | "infra" | "tool"
            ) {
                return Err(format!(
                    "{}: unknown kind {}",
                    file.display(),
                    manifest.kind
                ));
            }
            manifests.insert(manifest.path.clone(), manifest);
        }
        let repo = Repo {
            root: root.to_path_buf(),
            manifests,
        };
        repo.validate()?;
        Ok(repo)
    }

    fn validate(&self) -> Result<(), String> {
        for manifest in self.manifests.values() {
            for dependency in &manifest.depends_on {
                if !self.manifests.contains_key(dependency) {
                    return Err(format!(
                        "{} depends on {dependency}, which has no manifest",
                        manifest.path
                    ));
                }
            }
            for client in manifest
                .primary_pairs
                .iter()
                .chain(manifest.primary_triples.iter().flatten())
            {
                if self.find(client, "client").is_err() {
                    return Err(format!(
                        "{} lists {client}, which is not a client",
                        manifest.path
                    ));
                }
            }
        }
        // Dependencies point down to core/, and nothing points the other way.
        for manifest in self.manifests.values() {
            for dependency in &manifest.depends_on {
                let target = &self.manifests[dependency];
                let rank = |kind: &str| match kind {
                    "core" => 0,
                    "binding" => 1,
                    "package" => 2,
                    "infra" | "tool" => 3,
                    "client" | "server" => 4,
                    _ => 5,
                };
                if rank(&target.kind) > rank(&manifest.kind) {
                    return Err(format!(
                        "{} ({}) must not depend on {dependency} ({})",
                        manifest.path, manifest.kind, target.kind
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn all(&self) -> impl Iterator<Item = &Manifest> {
        self.manifests.values()
    }

    pub fn of_kind(&self, kind: &str) -> Vec<&Manifest> {
        self.manifests.values().filter(|m| m.kind == kind).collect()
    }

    pub fn find(&self, name: &str, kind: &str) -> Result<&Manifest, String> {
        self.manifests
            .values()
            .find(|m| m.name == name && m.kind == kind)
            .ok_or_else(|| format!("there is no {kind} named {name}. `qalqon list` shows them all"))
    }

    /// Every folder the starting folders need, dependencies first.
    pub fn closure(&self, starts: &[String]) -> Vec<&Manifest> {
        fn visit<'a>(
            repo: &'a Repo,
            path: &str,
            seen: &mut BTreeSet<String>,
            out: &mut Vec<&'a Manifest>,
        ) {
            if !seen.insert(path.to_string()) {
                return;
            }
            let Some(manifest) = repo.manifests.get(path) else {
                return;
            };
            for dependency in &manifest.depends_on {
                visit(repo, dependency, seen, out);
            }
            out.push(manifest);
        }
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for start in starts {
            visit(self, start, &mut seen, &mut out);
        }
        out
    }
}

#[derive(Serialize)]
struct FolderEntry {
    name: String,
    path: String,
    language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    framework: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery: Option<String>,
    targets: Vec<String>,
}

#[derive(Serialize)]
struct Combinations {
    schema: u32,
    clients: Vec<FolderEntry>,
    servers: Vec<FolderEntry>,
    primary_pairs: Vec<[String; 2]>,
    primary_triples: Vec<[String; 3]>,
}

const HEADER: &str = "# GENERATED by `qalqon manifests` from every folder's qalqon.yaml. Do not edit by hand.\n# CI runs `qalqon manifests --check`, which fails if this file is stale.\n\n";

pub fn write_combinations(repo: &Repo, check: bool) -> Result<(), String> {
    let entry = |m: &&Manifest| FolderEntry {
        name: m.name.clone(),
        path: m.path.clone(),
        language: m.language.clone(),
        framework: m.framework.clone(),
        delivery: m.delivery.clone(),
        targets: m.targets.clone(),
    };
    let mut primary_pairs = Vec::new();
    let mut primary_triples = Vec::new();
    for server in repo.of_kind("server") {
        for client in &server.primary_pairs {
            primary_pairs.push([client.clone(), server.name.clone()]);
        }
        for triple in &server.primary_triples {
            if let [a, b] = triple.as_slice() {
                primary_triples.push([a.clone(), b.clone(), server.name.clone()]);
            }
        }
    }
    let document = Combinations {
        schema: 1,
        clients: repo.of_kind("client").iter().map(entry).collect(),
        servers: repo.of_kind("server").iter().map(entry).collect(),
        primary_pairs,
        primary_triples,
    };
    let text = format!(
        "{HEADER}{}",
        serde_yaml::to_string(&document).map_err(|e| e.to_string())?
    );
    let path = repo.root.join("combinations.yaml");
    if check {
        if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            return Err(
                "combinations.yaml is stale or was edited by hand. Run `qalqon manifests`.".into(),
            );
        }
        println!("combinations.yaml matches the manifests");
    } else {
        std::fs::write(&path, text).map_err(|e| e.to_string())?;
        println!("wrote combinations.yaml");
    }
    Ok(())
}
