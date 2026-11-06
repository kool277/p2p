# servers/rust-axum

The reference host: every other host must match its observable behaviour in the interop suite. It implements `docs/HOST-SPI.md` with axum and SQLite, and it holds no protocol logic and no key material.

```sh
cargo qalqon dev --client cli-rust --server rust-axum
```

`docs/OPERATIONS.md` lists its settings. It serves plain WebSocket, so run it behind TLS anywhere but loopback. `Dockerfile` builds a development image with the test-only provider, and that image must never reach production.
