#!/usr/bin/env bash
# Builds the WebAssembly core, its glue and the React demo.
set -euo pipefail
cd "$(dirname "$0")/../../.."
cargo build -q -p qalqon-wasm --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir packages/js/web/wasm target/wasm32-unknown-unknown/debug/qalqon_wasm.wasm
(cd clients/web-react && npm install --no-audit --no-fund --silent && npx vite build --logLevel warn)
