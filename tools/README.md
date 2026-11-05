# tools

| Folder | What it does |
| --- | --- |
| `qalqon-cli` | The `qalqon` command. See `docs/BUILD.md` |
| `idlgen` | Generates every language surface from the IDL |
| `vectors` | Writes and checks `tests/conformance` |
| `qalqon-ca` | A development CA |
| `peer-demo` | Two Rust peers over real sockets, for `tests/phase1-gate.sh` |
| `fuzz` | Fuzz targets, run with `cargo +nightly fuzz run --fuzz-dir tools/fuzz <target>` |
| `packaging` | Per-OS packaging recipes, one per target |
