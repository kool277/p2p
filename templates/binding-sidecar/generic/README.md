# {{name}}

A {{lang}} binding through the {{path}} delivery path.

1. Write the idiomatic wrapper over the surface in `docs/SDK-API.md`.
2. Make `conformance.sh` run every vector file through `conformanceRun`, in this runtime.
3. Run `qalqon test --conformance {{name}}`.

`docs/EXTENDING.md` walks through this. A binding must contain no protocol logic.
