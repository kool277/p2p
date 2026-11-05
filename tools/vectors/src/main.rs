//! `vectors write <dir>` writes the vector files, and `vectors check <dir>` fails if the
//! committed files differ from what the code generates or if any vector does not pass.

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, dir) = match args.as_slice() {
        [mode, dir] => (mode.as_str(), Path::new(dir)),
        _ => {
            eprintln!("usage: vectors <write|check> <dir>");
            std::process::exit(2);
        }
    };
    let files = qalqon_conformance::generate();
    let mut failed = false;
    for (name, value) in &files {
        let text = serde_json::to_string_pretty(value).expect("vectors serialise") + "\n";
        let path = dir.join(name);
        match mode {
            "write" => {
                std::fs::create_dir_all(dir).expect("create the directory");
                std::fs::write(&path, text).expect("write the file");
            }
            "check" => {
                let committed = std::fs::read_to_string(&path).unwrap_or_default();
                if committed != text {
                    eprintln!("{} is stale: run `vectors write {}`", path.display(), dir.display());
                    failed = true;
                }
                let report = qalqon_conformance::run_file(&committed);
                println!("{name}: {} passed, {} failed", report.passed, report.failed.len());
                for failure in &report.failed {
                    eprintln!("  {failure}");
                    failed = true;
                }
            }
            _ => {
                eprintln!("unknown mode {mode}");
                std::process::exit(2);
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}
