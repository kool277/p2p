# bindings/wasm

The core for browsers, built with `wasm-bindgen`. It runs in a Web Worker, and `packages/js/web` is what an application imports.

```sh
cargo build -p qalqon-wasm --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir packages/js/web/wasm target/wasm32-unknown-unknown/debug/qalqon_wasm.wasm
cargo qalqon test --conformance wasm
```

JavaScript answers transport commands and stores opaque blobs, and it never holds a key: `core/keystore-webcrypto` wraps the identity from Rust, under a non-extractable `CryptoKey`.
