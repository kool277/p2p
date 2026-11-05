# Security

**Do not rely on this to protect anything real.** It runs on a test-only crypto provider, and no human cryptographer has reviewed the protocol or the code. See `PLAN.md`.

## Reporting a problem

Please do not open a public issue for a vulnerability. Use [GitHub's private vulnerability reporting](https://github.com/kool277/p2p/security/advisories/new) for this repository.

## What keeps a test build out of production

- `provider-testonly` has a `compile_error!` when debug assertions are off, so a release profile cannot include it.
- It offers only suites from `0xFF00` up, which a real build never offers, so the two cannot negotiate.
- Every binary and page that includes it reports `QALQON-TESTONLY-PROVIDER-NOT-FOR-RELEASE`. So does the demo app's screen, `qalqon_provider_name()` and the sidecar's `hello`.
- `.github/workflows/release.yaml` refuses to run until a certified provider exists.

## How the code is checked

See `docs/TESTING.md`.
