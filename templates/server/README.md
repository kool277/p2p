# {{name}}

A host in {{lang}} with {{framework}}. A host owns the socket, the database and the configuration, and hands every frame to the server core. To finish it:

1. Set `delivery` and `depends_on` in `qalqon.yaml` to the binding this uses.
2. Implement the upgrade and the effect loop in `docs/HOST-SPI.md`.
3. Apply `core/server-core/migrations/` with your own tool, and implement the four stores.
4. Add it to `SERVERS` in `tests/interop/interop.py`.
5. Run `qalqon test --pair cli-rust:{{name}}`.
