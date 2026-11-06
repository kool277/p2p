# bindings/sidecar-clients

Clients for the `qalqond` sidecar, generated from the IDL. See `docs/SIDECAR.md`.

| Language | Status |
| --- | --- |
| `php/` | Conformance and a full interop run pass |
| `shell/` | Conformance passes. Needs bash 4.1 and `jq` |
| `ruby/`, `elixir/` | Generated, and **never run** |

```sh
cargo qalqon test --conformance sidecar-clients
bash bindings/sidecar-clients/shell/conformance.sh tests/conformance/testonly/*.json
```
