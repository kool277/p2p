# {{name}}

A demo client in {{lang}} with {{framework}}. To finish it:

1. Set `delivery` and `depends_on` in `qalqon.yaml` to the binding this uses.
2. Write the demo screens in `docs/CLIENT-ADAPTER.md`, with automation IDs.
3. Implement the CLI contract in that document, so interop runs can drive it, and add it to `CLIENTS` in `tests/interop/interop.py`.
4. Run `qalqon test --pair {{name}}:rust-axum`.
