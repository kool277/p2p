# clients/web-react

The demo app in React, with the screens from `docs/CLIENT-ADAPTER.md` and automation IDs of the form `qalqon-<screen>-<control>`.

```sh
tests/interop/web/build.sh
cargo qalqon test --pair web-react:rust-axum
```

`tests/interop/web/driver.mjs` drives it in headless Chromium, through the same CLI contract as every other client.
