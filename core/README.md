# core

The only place protocol and crypto logic exist. Everything else in this repository is a thin layer over these crates. `docs/ARCHITECTURE.md` shows how they fit.

```sh
cargo test -p qalqon-core
cargo test -p server-core
cargo test -p qalqon-signal
```

The certified boundary will be `provider-<lib>`, which does not exist yet because the library has not been supplied. Every build uses `provider-testonly`, which refuses to compile in a release profile.
