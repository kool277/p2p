//! `qalqon new`: copies a template from `templates/`, with `{{lang}}`, `{{framework}}` and
//! `{{name}}` filled in. A scaffolded folder must pass conformance or interop before merge.

use std::path::{Path, PathBuf};

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn safe_name(value: &str, what: &str) -> Result<String, String> {
    let ok = !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !value.starts_with('.');
    if ok {
        Ok(value.to_string())
    } else {
        Err(format!("{what} may only hold letters, digits, -, _ and ."))
    }
}

fn fill(text: &str, values: &[(&str, &str)]) -> String {
    let mut out = text.to_string();
    for (key, value) in values {
        out = out.replace(&format!("{{{{{key}}}}}"), value);
    }
    out
}

fn copy_filled(
    from: &Path,
    to: &Path,
    values: &[(&str, &str)],
    created: &mut Vec<PathBuf>,
) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| e.to_string())?;
    for entry in std::fs::read_dir(from)
        .map_err(|e| format!("{}: {e}", from.display()))?
        .flatten()
    {
        let source = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let target = to.join(fill(&name, values));
        if source.is_dir() {
            copy_filled(&source, &target, values, created)?;
        } else {
            let text = std::fs::read_to_string(&source)
                .map_err(|e| format!("{}: {e}", source.display()))?;
            std::fs::write(&target, fill(&text, values)).map_err(|e| e.to_string())?;
            created.push(target);
        }
    }
    Ok(())
}

fn scaffold(
    root: &Path,
    template: PathBuf,
    destination: PathBuf,
    values: &[(&str, &str)],
) -> Result<(), String> {
    if destination.exists() {
        return Err(format!("{} already exists", destination.display()));
    }
    let mut created = Vec::new();
    copy_filled(&template, &destination, values, &mut created)?;
    for file in created {
        println!(
            "  created {}",
            file.strip_prefix(root).unwrap_or(&file).display()
        );
    }
    Ok(())
}

pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let templates = root.join("templates");
    match args.first().map(String::as_str) {
        Some("binding") => {
            let lang = safe_name(&flag(args, "--lang").ok_or("this needs --lang")?, "--lang")?;
            let path = flag(args, "--path").ok_or("this needs --path ffi|wasm|sidecar")?;
            if !matches!(path.as_str(), "ffi" | "wasm" | "sidecar") {
                return Err("--path must be ffi, wasm or sidecar".into());
            }
            let base = templates.join(format!("binding-{path}"));
            // A language with its own template gets a working binding. Any other gets the
            // generic one, whose conformance fails until the idiomatic part is written.
            let specific = base.join(&lang);
            let template = if specific.is_dir() {
                specific
            } else {
                base.join("generic")
            };
            let name = format!("{lang}-{path}");
            let destination = root.join("bindings").join(&name);
            scaffold(
                root,
                template,
                destination,
                &[("lang", &lang), ("name", &name), ("path", &path)],
            )?;
            println!("next: qalqon test --conformance {name}");
            Ok(())
        }
        Some("client") => {
            let lang = safe_name(&flag(args, "--lang").ok_or("this needs --lang")?, "--lang")?;
            let framework = safe_name(
                &flag(args, "--framework").ok_or("this needs --framework")?,
                "--framework",
            )?;
            let name = format!("{lang}-{framework}");
            let values = [
                ("lang", lang.as_str()),
                ("framework", framework.as_str()),
                ("name", name.as_str()),
            ];
            scaffold(
                root,
                templates.join("client"),
                root.join("clients").join(&name),
                &values,
            )?;
            println!("next: write the demo screens, then qalqon test --pair {name}:rust-axum");
            Ok(())
        }
        Some("server") => {
            let lang = safe_name(&flag(args, "--lang").ok_or("this needs --lang")?, "--lang")?;
            let framework = safe_name(
                &flag(args, "--framework").ok_or("this needs --framework")?,
                "--framework",
            )?;
            let name = format!("{lang}-{framework}");
            let values = [
                ("lang", lang.as_str()),
                ("framework", framework.as_str()),
                ("name", name.as_str()),
            ];
            scaffold(
                root,
                templates.join("server"),
                root.join("servers").join(&name),
                &values,
            )?;
            println!("next: implement docs/HOST-SPI.md, then qalqon test --pair cli-rust:{name}");
            Ok(())
        }
        Some("target") => {
            let triple = safe_name(
                &flag(args, "--triple").ok_or("this needs --triple")?,
                "--triple",
            )?;
            let os = safe_name(&flag(args, "--os").ok_or("this needs --os")?, "--os")?;
            let id = format!("{os}-{triple}");
            let path = root.join("targets.yaml");
            let mut text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            if text.contains(&format!("triple: {triple}")) {
                return Err(format!("{triple} is already in targets.yaml"));
            }
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&format!(
                "  - {{ id: {id}, os: {os}, min_os: \"unknown\", triple: {triple}, tier: community, key_storage: [application-defined] }}\n"
            ));
            std::fs::write(&path, text).map_err(|e| e.to_string())?;
            let template = std::fs::read_to_string(templates.join("target/recipe.md"))
                .map_err(|e| e.to_string())?;
            let recipe = root.join("tools/packaging").join(format!("{id}.md"));
            std::fs::create_dir_all(recipe.parent().unwrap_or(root)).map_err(|e| e.to_string())?;
            std::fs::write(
                &recipe,
                fill(&template, &[("triple", &triple), ("os", &os), ("id", &id)]),
            )
            .map_err(|e| e.to_string())?;
            println!("  added {id} to targets.yaml");
            println!(
                "  created {}",
                recipe.strip_prefix(root).unwrap_or(&recipe).display()
            );
            println!("next: rustup target add {triple}, then add a CI runner");
            Ok(())
        }
        _ => Err("usage: qalqon new <binding|client|server|target> ...".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_cannot_leave_their_folder() {
        for bad in ["../evil", "a/b", ".hidden", ""] {
            assert!(safe_name(bad, "x").is_err(), "{bad}");
        }
        assert!(safe_name("python", "x").is_ok());
    }

    #[test]
    fn placeholders_are_filled() {
        assert_eq!(
            fill("{{lang}}-{{path}}", &[("lang", "go"), ("path", "ffi")]),
            "go-ffi"
        );
    }
}
