# Qalqon Polyglot Monorepo — Any Client × Any Server: Graphical Design and Build Prompt

Nov 5, 2026 · @kool

One repository, one wire protocol, one Rust core: every client technology and every server technology - any language, any framework, any operating system - gets its own inner folder, and a single command builds only the pair you choose. A React web client with a Spring server and a C client with a Node.js server are two build profiles of the same project, not two projects — and because every profile embeds the same core and speaks the same protocol, any client talks to any server. This document explains the design in drawings first and ends with the prompt that makes a coding agent build it; it extends the earlier doc, which holds the standard's requirements and the protocol internals.

## The big picture

&#91;embedded content: the big picture · 1 core, 11 client platforms, 6 server frameworks\]

The accent box is the only place cryptography and protocol logic exist. Everything on the left is a thin SDK adapter plus a demo app; everything on the right is a thin host that embeds `server-core`. Add a framework on either side and the core does not change.

## Combinations: React + Spring, C + Node, and the rule for any pair

Choosing a pair selects folders; nothing is rewritten. The client side is always *SDK for the client's language + framework adapter + demo app*, the server side is always *server-core (Rust) + binding for the server's language + a thin framework host*, and the infrastructure services are built once for every pair.

| You choose | Client folders that build | Server folders that build | Always built |
| --- | --- | --- | --- |
| React web client + Spring server | `bindings/wasm` → `packages/js/web` → `packages/js/react` → `clients/web-react` | `bindings/java` (JAR with the native library for the server OS) → `packages/java/spring-boot-starter` → `servers/java-spring` | `core/`, `core/server-core`, `infra/relay`, `infra/coturn`, `tests/conformance`, `tests/interop` |
| C client + Node.js server | `bindings/c` (libqalqon, `qalqon.h`, CMake package) → `clients/cli-c` | `bindings/node` (N-API prebuilt) → `packages/node/express` → `servers/node-express` | same |
| Flutter app + Go server | `bindings/c` → `bindings/dart` → `packages/dart/flutter` → `clients/flutter` | `bindings/go` (cgo) → `packages/go/nethttp` → `servers/go-nethttp` | same |
| Qt desktop + .NET server | `bindings/c` → `packages/qt` → `clients/desktop-qt` | `bindings/dotnet` (NuGet with native runtimes) → `packages/dotnet/aspnet` → `servers/dotnet-aspnet` | same |
| Android app + Python server | `bindings/kotlin` (AAR) → `clients/android` | `bindings/python` (wheel) → `packages/python/fastapi` → `servers/python-fastapi` | same |
| iOS app + Rust server | `bindings/swift` (XCFramework) → `clients/ios` | `servers/rust-axum` (native, the reference host) | same |

The commands, all from the repository root:

```text
qalqon build   --client web-react --server java-spring     # compile only this pair
qalqon dev     --client cli-c     --server node-express     # run both with hot reload and a local relay
qalqon test    --pair  web-react:java-spring               # conformance vectors + interop for the pair
qalqon test    --triple web-react,cli-c:java-spring        # two different clients talking P2P through one server
qalqon package --client android   --server python-fastapi  # signed artifacts into dist/android+python-fastapi/
qalqon list                                                # every client, server and the pairs declared primary
```

Why any pair works:

- Both sides embed the same Rust core, so the handshake, record format and key schedule are byte-identical whatever language wraps them.
- `docs/PROTOCOL.md` is the contract and `tests/conformance` holds its vectors; every binding must pass them before a host or client built on it can be released.
- The server framework only hosts: it accepts the WebSocket, persists users, devices and audit rows, and loads configuration. Rendezvous logic, policy evaluation and the audit chain live in `server-core` and are identical in Spring, Node, Go, Python, .NET and Rust.
- The data plane is peer-to-peer, so a React client and a C client can exchange encrypted frames directly after any server brokered the connection.
- Each inner folder carries a `qalqon.yaml` manifest (kind, dependencies, toolchain, minimum versions); the root `combinations.yaml` is generated from them, which is what the `qalqon` CLI resolves.

## From one core to every runtime

&#91;embedded content: compilation targets · 1 source, 4 targets, 10 package families\]

Four compile targets cover every runtime: WebAssembly for browsers, the C ABI for every language that can load a shared library (C, C++, Qt, Java through FFM or JNI, Go through cgo, .NET through P/Invoke, Dart through `dart:ffi`), napi-rs and PyO3 where a runtime-native bridge gives a better developer experience than raw FFI, and UniFFI for the Kotlin and Swift mobile SDKs. The right column is what a developer installs; none of it contains protocol code.

## Any language, any framework, any OS: how the model stays open

The lists in this document are examples, not limits. Three things keep the model open: one language-neutral interface definition from which every binding is generated; four delivery paths that between them cover every language that exists (native Rust, the C ABI through foreign-function interfaces, WebAssembly, or a local sidecar process for anything that can open a socket); and a target file in which an operating system is one more line. A new language, framework or operating system is a scaffolding command plus a conformance run - never a change to `core/`.

&#91;embedded content: delivery-path decision · 3 questions, 4 paths, 1 API\]

Three questions place any language on one of four paths, and all four end in the same SDK API, the same conformance vectors and the same wire protocol. The sidecar is the floor: if a language can open a local socket, it can use Qalqon.

Language dimension - how any language gets the same SDK:

| Delivery path | Who takes it | Generated from the IDL by | Languages it covers |
| --- | --- | --- | --- |
| Native Rust crate | Rust apps and hosts | cargo | Rust (axum, Actix, Rocket, Tauri, Bevy) |
| C ABI through FFI | any language with a foreign-function interface | cbindgen header, then a per-language generator: UniFFI (Kotlin, Swift, Python, Ruby; third-party Go, C#, Dart, Kotlin Multiplatform), jextract (Java FFM), ffigen (Dart), cgo (Go), ClangSharp (.NET), ctypes/cffi (Python), koffi (Node) | C, C++, Zig, Nim, Go, Java, Kotlin, Scala, C#, F#, Swift, Objective-C, Python, Ruby, PHP (FFI extension), Dart, Lua (LuaJIT), Haskell, OCaml, Julia, R, Perl, Delphi/Pascal, Crystal |
| WebAssembly module | browsers; JavaScript runtimes; any language that embeds a WASM runtime | wasm-bindgen for JavaScript and TypeScript; a WASI build for runtime embedders (wasmtime, wasmer, wazero) | React, Vue, Angular, Svelte, Solid, Next.js, Nuxt, Astro, Blazor; Node, Deno, Bun; Go via wazero, Python via wasmtime-py, .NET via Wasmtime |
| Sidecar process `qalqond` | languages without a usable FFI, locked-down runtimes, teams that will not link native code, and any server that prefers a container beside it | the daemon itself (Rust, embeds the core) plus a small client library per language generated from the IDL (JSON-RPC over a local socket) | PHP on shared hosting, Elixir and Erlang, COBOL, Visual Basic, shell scripts, Perl, legacy Java 8, anything that can open a socket |

The interface definition lives in `core/idl/` as the single source of truth: a UniFFI `.udl`, the cbindgen C header, a WIT file for WASM embedders and a JSON-RPC schema for the sidecar are all generated from it, CI checks that they agree, and `docs/SDK-API.md` is rendered from the same file - so every language reads the same method names and error codes.

Framework dimension - adapters over two small contracts:

- A client adapter implements the Client Adapter Contract: create a session from configuration, surface events in the framework's own idiom (hooks, composables, signals, observables, coroutines, async/await or plain callbacks), expose `channel.send` and `channel.receive`, and show `verifyPeer`. Nothing else is framework-specific.
- A server host implements the Host SPI from the server-side section: accept the upgrade, the four stores, configuration, health and metrics, admin. Nothing else is framework-specific.
- `qalqon new client --lang python --framework pyside6` or `qalqon new server --lang php --framework laravel` scaffolds the folder from the `templates/` registry: manifest, build file, README, test harness and the wiring to the right delivery path. The scaffolded folder must pass the interop suite before it is merged; `templates/index.yaml` is community-extensible.

| Role | Framework families covered by the two contracts |
| --- | --- |
| Server hosts | JVM: Spring Boot, Quarkus, Micronaut, Ktor, Vert.x, Play · Node: Express, Fastify, NestJS, Koa, Hono · Deno and Bun: Fresh, Elysia · Python: FastAPI, Django, Flask, Tornado · Go: net/http, Gin, Echo, Fiber, Chi · .NET: ASP.NET Core, Minimal APIs · Rust: axum, Actix, Rocket · PHP: Laravel, Symfony · Ruby: Rails, Sinatra · Elixir: Phoenix · Swift: Vapor · C++: Drogon, Crow · Haskell: Servant |
| Web clients | React, Vue, Angular, Svelte, Solid, Next.js, Nuxt, SvelteKit, Astro, Blazor WebAssembly, plain TypeScript |
| Desktop clients | Electron, Tauri, Qt and QML, GTK, wxWidgets, WPF, WinUI 3, Avalonia, .NET MAUI, WinForms, JavaFX, Compose Multiplatform, Flutter desktop, PySide6 and PyQt, Tkinter, Dear ImGui, plain C or C++ |
| Mobile clients | SwiftUI and UIKit, Jetpack Compose and Views, Kotlin Multiplatform, Flutter, React Native, Ionic and Capacitor, .NET MAUI |
| Engines and other hosts | Unity (C#), Unreal (C++), Godot (GDExtension over the C ABI), game servers, IoT gateways, CLI tools in any language |

Operating-system and CPU dimension - `targets.yaml`:

| Operating system | CPUs | Delivered as | Key storage |
| --- | --- | --- | --- |
| Windows 10 and 11 | x64, arm64 | `qalqon.dll` + import library (MSVC and MinGW), NuGet, npm prebuild, Python wheel, MSIX or winget for apps | DPAPI, CNG |
| Linux: Ubuntu, Debian, Fedora, RHEL (glibc 2.17+) | x64, arm64, armv7 | `libqalqon.so`, `.deb` and `.rpm`, Flatpak, Snap or AppImage for apps; musl static build for Alpine and containers | Secret Service, TPM optional |
| macOS 13+ | arm64, x64 (universal binary) | `libqalqon.dylib`, XCFramework, `.pkg`, Homebrew tap | Keychain, Secure Enclave |
| iOS and iPadOS 15+ | arm64, simulator | XCFramework through SwiftPM or CocoaPods | Secure Enclave |
| Android 9+ (API 28) | arm64-v8a, armeabi-v7a, x86\_64 | AAR with a `.so` per ABI | Keystore, StrongBox |
| Web | wasm32 | `.wasm` plus glue, all evergreen browsers | WebCrypto-wrapped IndexedDB |
| Containers | linux x64, arm64 | distroless and Alpine images for hosts; the `qalqond` sidecar image | mounted secrets or HSM |
| FreeBSD, OpenBSD | x64, arm64 | built from source; community tier | OS keyring |
| WASI runtimes | wasm32-wasip1 | module for wasmtime, wasmer, wazero embedding | host-provided |
| Embedded Linux (Yocto, Buildroot) and `no_std` targets | aarch64, armv7, riscv64 | static library; the core builds without an OS when given an allocator | application-defined |
| HarmonyOS and other platforms | per platform | through the C ABI (NAPI or ArkTS FFI); community tier | platform keystore |

Adding an operating system is three edits: its Rust target triple in `targets.yaml`, a packaging recipe in `tools/packaging/`, and a CI runner; every binding then inherits the target.

The sidecar, in one paragraph: `qalqond` is a static Rust binary that embeds the core and listens on a Unix domain socket (Linux, macOS), a named pipe (Windows) or loopback TCP with a per-launch token; it speaks length-prefixed JSON-RPC that mirrors `SDK-API.md`, checks the peer's credentials (`SO_PEERCRED` or the pipe's SID) and runs as the same user, so the plaintext never leaves the machine and keys never leave the daemon. A client library for a new language is about two hundred lines, generated from the IDL. The same binary runs as a container beside any server.

The procedure for anything new:

1. `qalqon new binding|client|server|target ...` scaffolds the folder: manifest, build file, README, test harness, delivery-path wiring.
2. Fill in the idiomatic part only - the wrapper, the adapter, or the packaging recipe; the generated parts are already there.
3. `qalqon test --conformance <binding>` and `qalqon test --pair <client>:<server>` must pass.
4. List the pair under `primary_pairs` if it should run on every pull request; otherwise the nightly matrix discovers it from the manifest.
5. Nothing to add to the docs by hand: the folder's README is pulled into the site.

## Repository layout: one inner folder per platform

Six roles, and every folder belongs to exactly one of them: the core (protocol and crypto logic, Rust only), bindings (one per language runtime), packages (one per framework, thin adapters), clients (one per client platform), servers (one per server framework), infrastructure (framework-independent services). The rule that keeps the monorepo honest: protocol or crypto logic may exist only under `core/`; a lint in CI fails any binding, package, client or server that implements a handshake step or touches a key byte.

&#91;embedded content: folder roles · 6 roles, dependencies pointing down to core/\]

Read it top-down: a client or server folder depends on a package, a package on a binding, a binding on the core; nothing points the other way, and the four folders at the bottom (infrastructure, tools, tests, docs) serve every level without being depended on by any.

```text
qalqon/                              one repo, one VERSION, one PROTOCOL_VERSION
  VERSION  PROTOCOL_VERSION  combinations.yaml  targets.yaml  justfile  README.md  CODEOWNERS
  core/                              Rust workspace - the only place protocol and crypto logic live
    crypto-provider/                 CryptoProvider trait, key handles, cipher-suite registry
    provider-<lib>/                  FFI binding to your library = the certified boundary
    crypto-ext/                      feature-gated primitives outside the boundary (key agreement if the library has none)
    qalqon-core/                     handshake, record layer, key schedule (sans-I/O, builds without an OS)
    qalqon-transport-*/              webrtc, quic, ws, tcp, udp, relay adapters
    qalqon-signal/                   rendezvous client logic
    qalqon-audit/                    audit event schema, O'z DSt 1106 hash chain
    server-core/                     server-side protocol, session registry, policy engine, audit - embedded by every host
    idl/                             the one API definition; generators for .udl, C header, WIT, JSON-RPC schema, SDK-API.md
    ffi/                             the C ABI surface (cbindgen) every native binding is built on
    sidecar/                         qalqond: the daemon that serves the API over a local socket to any language
  bindings/                          one folder per language runtime; same API, same conformance vectors
    c/                               libqalqon.{a,so,dylib,dll}, qalqon.h, qalqon.hpp (RAII), CMake package config
    wasm/                            wasm32 build + JS glue (wasm-bindgen), designed to run in a Web Worker
    wasi/                            wasm32-wasip1 build for runtime embedders (wasmtime, wasmer, wazero)
    node/                            N-API addon (napi-rs), prebuilt for linux, macOS, Windows x64/arm64
    java/                            JVM binding: Panama FFM (Java 22+) with a JNI fallback (Java 17-21), JAR with native libs
    kotlin/                          Android AAR via UniFFI (shares generated types with java/ where possible)
    swift/                           XCFramework + Swift package via UniFFI
    python/                          PyO3 extension, wheels built by maturin
    go/                              cgo package over the C ABI, static libs vendored per OS/arch
    dotnet/                          P/Invoke wrapper, NuGet with runtimes/<rid>/native
    dart/                            dart:ffi binding for Flutter
    sidecar-clients/                 generated JSON-RPC clients: php/, ruby/, elixir/, shell/, <any>/
  packages/                          framework adapters: idiomatic, thin, no protocol logic
    js/web  js/react  js/vue  js/angular  js/svelte  js/electron
    node/express  node/fastify  node/nest
    java/spring-boot-starter  java/servlet  java/quarkus
    python/fastapi  python/django
    go/nethttp  go/gin
    dotnet/aspnet  dotnet/maui
    dart/flutter
    php/laravel  ruby/rails  elixir/phoenix          (over the sidecar)
    qt/  gtk/                        QML plugin and C++ helpers; GTK helpers in C
  clients/                           reference apps, one inner folder per client platform
    web-react/  web-vue/  web-angular/  web-svelte/
    desktop-electron/  desktop-tauri/  desktop-qt/  desktop-gtk/  desktop-wpf/  cli-c/  cli-rust/
    android/  ios/  flutter/  dotnet-maui/  python-cli/  go-cli/  php-cli/
  servers/                           reference hosts, one per server framework; each embeds server-core
    rust-axum/  node-express/  node-fastify/  java-spring/  java-quarkus/  python-fastapi/  go-nethttp/  dotnet-aspnet/
    php-laravel/  ruby-rails/  elixir-phoenix/     (over the sidecar)
  templates/                         what `qalqon new` copies: binding-ffi, binding-wasm, binding-sidecar, client, server, target; index.yaml
  infra/                             framework-independent services and deployment
    relay/  coturn/  iroh-relay/  sidecar-image/  compose/  helm/  devcontainer/
  tools/                             qalqon CLI (build, dev, test, package, list, doctor, new), packaging recipes per OS,
                                     CA and key ceremony, vector generator, NAT simulator, selftest, fuzz
  tests/
    conformance/                     shared JSON vectors every binding and the sidecar must pass
    interop/                         client x server (and client, client, server) matrix runner: docker hosts + headless clients
  formal/                            Tamarin or ProVerif model of the handshake
  docs/                              mdBook site: PROTOCOL, ARCHITECTURE, SDK-API, HOST-SPI, CLIENT-ADAPTER, SIDECAR, EXTENDING, COMPLIANCE, THREAT-MODEL, ADRs
  .github/workflows/                 matrix CI over targets.yaml, nightly full matrix, release pipeline
```

Every inner folder is self-describing: a `README.md` with a ten-minute quickstart, the build file of its own ecosystem (`Cargo.toml`, `package.json`, `build.gradle.kts`, `CMakeLists.txt`, `pyproject.toml`, `go.mod`, `*.csproj`, `Package.swift`, `pubspec.yaml`), its tests, and a `qalqon.yaml` manifest:

```yaml
name: java-spring
kind: server                # core | binding | package | client | server | infra | tool
depends_on: [core/server-core, bindings/java, packages/java/spring-boot-starter, infra/relay]
toolchain: { java: ">=17", gradle: ">=8.5" }
primary_pairs: [web-react, cli-c]      # clients this host is tested against on every pull request
owners: ["@team-backend"]
```

## Building a chosen pair

&#91;embedded content: build flow · 7 steps, 1 decision, 1 loop\]

The command names a client and a server; the CLI reads the generated `combinations.yaml`, computes the dependency closure, checks the toolchains those folders need (and only those), builds the core once into a content-addressed cache, then builds, tests and packages the folders on the path. Switching to another pair reuses the cached core, so the second pair costs minutes, not the full matrix.

## A session end to end

&#91;embedded content: session sequence · 11 steps across React, Spring and C\]

The same eleven steps happen for any pair: only the lane names change. Steps 1-7 travel inside client-to-server Qalqon channels (the Spring host hands every frame to `server-core`, which runs the policy check and writes the audit row); steps 8-10 happen on the direct path between the two clients, where the React SDK and the C library run the identical handshake and record code compiled from the same core.

## Server-side integration per framework

Every host is thin by design: it owns the socket, the database and the configuration, and hands every frame to `server-core`. A host is finished when it implements the Host SPI below and passes the same interop suite as the Rust reference host.

| Framework | Folders | How it loads the core | What the host adds | Endpoints |
| --- | --- | --- | --- | --- |
| Spring Boot (Java, Kotlin) | `servers/java-spring`, `packages/java/spring-boot-starter`, `bindings/java` | JAR bundles `libqalqon` per OS/arch; loaded through the Foreign Function & Memory API ([final in Java 22](https://openjdk.org/jeps/454)), JNI fallback for Java 17-21 | auto-configuration, `WebSocketHandler` for `/qalqon`, Spring Security filter mapping the Qalqon identity to an `Authentication`, JPA/JDBC adapters for users, devices and audit, Actuator metrics | `wss://host/qalqon` (control plane), `https://host/admin` |
| Node.js (Express, Fastify, NestJS) | `servers/node-express`, `servers/node-fastify`, `packages/node/*`, `bindings/node` | N-API addon built with [napi-rs](https://napi.rs/), prebuilt `.node` binaries resolved at install; runs on the event loop, blocking crypto on the libuv pool | middleware, `ws` upgrade handler, Prisma or Knex adapters, pino logging with secret redaction | same |
| Go (net/http, Gin) | `servers/go-nethttp`, `packages/go/*`, `bindings/go` | cgo over the C ABI, static libraries vendored per OS/arch so `go build` needs no Rust toolchain | handler, WebSocket upgrade, `database/sql` adapters, pprof and Prometheus | same |
| Python (FastAPI, Django) | `servers/python-fastapi`, `packages/python/*`, `bindings/python` | PyO3 extension shipped as wheels (maturin), GIL released during crypto | ASGI middleware, `websockets` handler, SQLAlchemy adapters | same |
| .NET (ASP.NET Core) | `servers/dotnet-aspnet`, `packages/dotnet/aspnet`, `bindings/dotnet` | NuGet with `runtimes/<rid>/native`, P/Invoke with `SafeHandle` wrappers | middleware, WebSocket handler, EF Core adapters, authentication handler | same |
| Rust (axum) | `servers/rust-axum` | native crate dependency | the reference host: every other host must match its observable behaviour in the interop suite | same |

Host SPI (the whole contract a new host must satisfy):

- `accept(upgrade)`: accept the WebSocket upgrade and pump frames between the socket and `server-core`.
- `UserStore`, `DeviceStore`, `PolicyStore`, `AuditSink`: persistence hooks; the reference schema ships as SQL migrations each host applies with its own tool.
- `Config`: load the server identity key, CA bundle, relay addresses and policy from the host's configuration system.
- `Health` and `Metrics`: liveness, readiness, direct-versus-relayed counters, handshake failures, alarm feed.
- `Admin`: expose the admin API `server-core` defines (users, devices, revocation, audit export) under the host's own authentication.

Everything else - handshake, session registry, rendezvous matching, policy evaluation, audit chaining, rate limits - is inside `server-core` and therefore identical in every host.

## Client-side integration per framework

A client folder is a demo app over an SDK, never a second implementation: the SDK (binding plus framework adapter) exposes `connect`, `openChannel`, `send`, `receive`, `verifyPeer`, `rotateKeys` and `exportAudit`, and the app renders them. Adding a new client framework means writing an adapter, not touching `core/`.

| Framework | Folders | Core delivery | Adapter shape | Platform notes |
| --- | --- | --- | --- | --- |
| React, Vue, Angular (browser) | `clients/web-*`, `packages/js/{react,vue,angular}`, `packages/js/web`, `bindings/wasm` | WASM running in a Web Worker | hooks, composables or services: `useQalqonSession`, `useChannel` | WebRTC DataChannel for P2P; strict CSP; keys wrapped by a non-extractable WebCrypto key |
| Electron | `clients/desktop-electron`, `packages/js/electron` | N-API addon in the main process, WASM in the renderer if needed | IPC bridge exposing the session to the renderer | keys in the OS keychain through the main process |
| Tauri 2 | `clients/desktop-tauri` | Rust core linked directly as a plugin | commands and events | smallest binary, no binding layer; desktop and mobile |
| Qt 6 (C++/QML) | `clients/desktop-qt`, `packages/qt`, `bindings/c` | `libqalqon` + `qalqon.hpp` | QML plugin exposing `Session` and `Channel` objects | `find_package(qalqon)` from the CMake package config |
| C or C++ (CLI, embedded, any native app) | `clients/cli-c`, `bindings/c` | static library + header | none - the C API is the adapter | the template for any C/C++ integration; smallest footprint |
| Android (Kotlin) | `clients/android`, `bindings/kotlin` | AAR via UniFFI | Compose demo, coroutine-friendly API | Keystore wrapping; libwebrtc for P2P |
| iOS and macOS (Swift) | `clients/ios`, `bindings/swift` | XCFramework, Swift package | SwiftUI demo, async/await API | Secure Enclave wrapping; WebRTC.framework |
| Flutter (Dart) | `clients/flutter`, `packages/dart/flutter`, `bindings/dart` | `dart:ffi` over the C ABI; WASM path on web | plugin with streams | one codebase for mobile, desktop and web |
| .NET MAUI | `clients/dotnet-maui`, `bindings/dotnet` | NuGet with native runtimes | service with `IAsyncEnumerable` | Windows, macOS, Android, iOS from one project |
| Python, Go, Rust CLIs | `clients/python-cli`, `clients/go-cli`, `clients/cli-rust` | wheel, cgo package, crate | none | operations tooling, scripting, load tests |

The public API is specified once in `docs/SDK-API.md` as a language-neutral interface, and each binding's generated surface is diffed against it in CI, so a React developer and a C developer read the same method names and the same error codes.

## Packaging and CI: one version, many registries

One `VERSION` file stamps every package in a release, so `@qalqon/react 1.4.0` is guaranteed to interoperate with `uz.qalqon:qalqon-spring-boot-starter:1.4.0`; the wire protocol has its own `PROTOCOL_VERSION`, negotiated in the handshake, so packages of the same major version interoperate even when their minor versions differ.

| Artifact | Registry | Built by | Consumed by |
| --- | --- | --- | --- |
| `qalqon-core`, `server-core` crates | crates.io or a private registry | cargo | Rust hosts, Tauri clients |
| `libqalqon` + `qalqon.h` + CMake config | GitHub Releases; optional Conan and vcpkg ports | cargo + cbindgen + cmake | C, C++, Qt, Go (cgo), Dart (ffi) |
| `@qalqon/web`, `@qalqon/react`, `@qalqon/vue`, `@qalqon/angular`, `@qalqon/electron` | npm | wasm-pack + tsup | browsers, Electron renderer |
| `@qalqon/node` + per-platform prebuilds | npm | napi-rs CLI | Node hosts (Express, Fastify, NestJS) |
| `uz.qalqon:qalqon-java`, `qalqon-spring-boot-starter` | Maven Central or a private Nexus | Gradle | Spring and any JVM server |
| `uz.qalqon:qalqon-android` (AAR) | Maven | Gradle + cargo-ndk | Android apps |
| `QalqonKit.xcframework` + Swift package | SwiftPM binary target on a git tag; CocoaPods optional | xcodebuild + cargo | iOS and macOS apps |
| `qalqon` wheels | PyPI | maturin | Python hosts and CLIs |
| `github.com/<org>/qalqon-go` | Go module on a git tag, static libs vendored | cgo | Go hosts and CLIs |
| `Qalqon` NuGet with `runtimes/` | NuGet | dotnet pack | ASP.NET hosts, MAUI clients |
| `qalqon_flutter` | pub.dev | flutter | Flutter apps |
| host images, relay, coturn, iroh-relay | OCI registry (GHCR or private) | docker buildx | deployments via compose or helm |

Release pipeline, in order:

1. Tag `vX.Y.Z`; CI reads `VERSION` and refuses a tag that does not match.
2. Core build matrix: Linux glibc and musl, macOS, Windows, each x64 and arm64; Android arm64-v8a, armeabi-v7a, x86\_64; iOS device and simulator; wasm32. Artifacts go to the build cache keyed by commit.
3. Every binding builds against the cached core artifacts, never from a fresh core build, so all bindings in a release share one set of binaries.
4. Conformance vectors run inside each binding's own runtime (JVM, Node, Python, .NET, Go, Swift, Kotlin, browser).
5. Interop suite runs the primary pairs on every pull request and the full matrix nightly and on release.
6. SBOM (CycloneDX) per artifact, signatures (cosign for images, Sigstore or GPG for packages), reproducible-build check on two runners.
7. Publish to registries in dependency order (core crates, then native libraries, then bindings, then framework packages, then images), then deploy the docs site.

Toolchains are pinned in `infra/devcontainer` (Rust, Node, JDK, Python, Go, .NET, Android SDK and NDK, Xcode on macOS runners, Flutter), so `qalqon build` behaves the same on a laptop and in CI; a Nix flake is the alternative for teams that already use it.

## Interoperability test matrix

Every pull request proves the pairs marked PR; the nightly run proves every cell. Because the data plane is peer-to-peer, an interop test is really a triple - two clients and one server - so each cell below runs the client against the Rust CLI client through that server, and the triples declared in `combinations.yaml` add mixed-client cases (for example React + C through Spring).

| Client \\ Server | rust-axum | node-express | java-spring | python-fastapi | go-nethttp | dotnet-aspnet |
| --- | --- | --- | --- | --- | --- | --- |
| web-react | PR | PR | PR | nightly | nightly | nightly |
| web-vue | nightly | nightly | nightly | nightly | nightly | nightly |
| web-angular | nightly | nightly | nightly | nightly | nightly | nightly |
| desktop-electron | nightly | PR | nightly | nightly | nightly | nightly |
| desktop-tauri | PR | nightly | nightly | nightly | nightly | nightly |
| desktop-qt | nightly | nightly | nightly | nightly | nightly | PR |
| cli-c | PR | PR | PR | nightly | nightly | nightly |
| android | PR | nightly | nightly | PR | nightly | nightly |
| ios | PR | nightly | nightly | nightly | nightly | nightly |
| flutter | nightly | nightly | nightly | nightly | PR | nightly |
| dotnet-maui | nightly | nightly | nightly | nightly | nightly | PR |

What one cell runs: start the host from its OCI image with a fresh database; start the blind relay and coturn; enrol two devices with the test CA; log both clients in; rendezvous; establish the P2P channel directly, then again with hole punching disabled so the relay path is exercised; exchange 1,000 records including a rekey; verify audit chains on both clients and the host; tear down. Headless drivers: Playwright for browsers, Maestro for Android and iOS, the CLI binaries elsewhere; the NAT simulator in `tools/natsim` provides the network conditions.

The PR set is editable: move a cell to PR by listing the pair under `primary_pairs` in the host's `qalqon.yaml`.

## Fill-in block: your library and the combinations you need first

Paste this block at the top of the prompt. The library facts decide the crypto design; the combination facts decide which folders the agent builds first and which registries it targets.

```markdown
### LIBRARY FACTS
- LIBRARY_NAME / VERSION: ___
- LANGUAGE and BUILD SYSTEM: (C / C++ / Rust / Java / C# / Go / Python; CMake / Cargo / Gradle / ...)
- LOCATION: (path inside the repo, git URL, or package name)
- STANDARDS IMPLEMENTED (tick, give sizes):
  - [ ] O'z DSt 1105:2009 block cipher - block ___ bits; key ___ bits; modes: ECB / CBC / CFB / OFB / CTR / gamma / other ___; MAC mode: yes / no
  - [ ] O'z DSt 1106:2009 hash - output ___ bits; streaming API: yes / no
  - [ ] O'z DSt 1092:2009 digital signature - parameter sets ___; key generation: yes / no; X.509 support: yes / no
  - [ ] Key agreement (DH / ECDH / KEM): ___ or NONE   - [ ] KDF: ___ or NONE   - [ ] HMAC/MAC: ___ or NONE   - [ ] Key wrapping: ___ or NONE
  - [ ] CSPRNG: source ___; seeding ___
- API SHAPE: one-shot / streaming; buffer ownership; thread-safety; error reporting; constant-time: known / unknown
- TEST VECTORS: official control examples available: yes / no (where ___)
- CERTIFICATION STATUS: certified / in progress / none; body ___; certified boundary frozen: yes / no
- RULES: all payload crypto through this library: yes / no; agent may add a key-agreement primitive outside it: yes / no / ask first; platform TLS/DTLS as an outer layer: yes / no
- TARGET_CLASS (O'z DSt 2814:2014): 1Г (default) / 1В / other ___

### COMBINATION FACTS
- PRIMARY PAIRS (built and tested on every pull request, in priority order):
  1. client ___ + server ___      e.g. web-react + java-spring
  2. client ___ + server ___      e.g. cli-c + node-express
  3. client ___ + server ___
- FIRST-WAVE CLIENT FOLDERS: (web-react, web-vue, web-angular, web-svelte, desktop-electron, desktop-tauri, desktop-qt, desktop-gtk, desktop-wpf, cli-c, android, ios, flutter, dotnet-maui, python-cli, go-cli, php-cli)
- FIRST-WAVE SERVER FOLDERS: (rust-axum, node-express, node-fastify, java-spring, java-quarkus, python-fastapi, go-nethttp, dotnet-aspnet, php-laravel, ruby-rails, elixir-phoenix)
- ANY OTHER LANGUAGE / FRAMEWORK I ALREADY KNOW I NEED (the agent scaffolds these with qalqon new): ___
- OPERATING SYSTEMS AND CPUs (clients): Windows ___ (x64 / arm64), Ubuntu or other Linux ___ (x64 / arm64), macOS ___, iOS ___, Android ___, web browsers ___, other ___
- OPERATING SYSTEMS AND CPUs (servers): linux x64 / linux arm64 / windows x64 / macos arm64 / containers only
- MINIMUM VERSIONS: Java ___ (17 or 22+)   Node ___ (22 LTS)   Python ___ (3.10+)   .NET ___ (8)   Go ___ (1.22+)   PHP ___ (8.2)   Ruby ___ (3.2)   Android API ___ (28)   iOS ___ (15)
- REGISTRIES: public (npm, Maven Central, PyPI, NuGet, crates.io, pub.dev, Packagist, RubyGems, Hex) / private (Nexus, Artifactory, GHCR) / git tags only
- CI: GitHub Actions / self-hosted runners (which OS) / other ___
- BUILD ORCHESTRATOR PREFERENCE: just + native tools (default) / Bazel / Nx
- SIDECAR ALLOWED on servers: yes / no (needed for languages without FFI, e.g. PHP shared hosting, Elixir)
- EXISTING SYSTEMS TO INTEGRATE: (e.g. an existing Spring app, an existing React app, an identity provider, a database)
- CODENAME: Qalqon (or ___)
```

## The build prompt (copy the whole block)

Paste the fill-in block first, then this prompt. It is self-contained; the companion doc holds the longer protocol and compliance detail, and the agent is told to ask for it if a decision needs more than this prompt gives.

```markdown
# TASK - Build "Qalqon": one polyglot monorepo that gives ANY client technology and ANY server technology - any language, any framework, any operating system - an end-to-end encrypted, P2P-first secure channel on LIBRARY_NAME

You are a senior cryptographic-protocol engineer and a build-systems engineer. Build ONE repository in which the secure channel exists once (a Rust core) and is delivered to every client and server ecosystem through its own inner folder, so that any combination - a React web client with a Spring server, a C client with a Node.js server, a Flutter app with a Go server, a PHP site with a Qt desktop app - is a build profile of the same project. The set of languages, frameworks and operating systems is OPEN: the lists in this prompt are the first wave, and adding a new one must be a scaffolding command plus a conformance run, never a change to the core. All payload cryptography is performed by LIBRARY_NAME (see LIBRARY FACTS). The design must satisfy the cryptographic-subsystem requirements of O'z DSt 2814:2014 for TARGET_CLASS and give host systems the hooks for the standard's access-control, registration and integrity subsystems.

## 0. Working rules
1. Phase 0, before any code: read the library and write docs/crypto-inventory.md; write docs/adr/0001-key-agreement.md, docs/adr/0002-core-and-ffi-strategy.md, docs/adr/0003-build-orchestrator.md, docs/adr/0004-sidecar-ipc.md and a v0 docs/PROTOCOL.md. STOP and ask for approval before implementing.
2. Stop and ask before any choice that is hard to reverse: wire format, C ABI shape, IDL format, sidecar IPC format, certificate format, database schema, orchestrator, anything that weakens a MUST.
3. Never invent cryptographic primitives or modes; compose only published constructions (HMAC RFC 2104, HKDF RFC 5869, encrypt-then-MAC, Noise-style handshakes, a TLS 1.3-style key schedule) from the library's primitives. If the library lacks something, say so in an ADR; never substitute silently.
4. Protocol and crypto logic may exist ONLY under core/. Write a CI lint that fails any binding, package, client, server or template containing a handshake step, key derivation or raw key access. Hosts and adapters are thin by construction.
5. Keep PLAN.md, CHANGELOG.md, combinations.yaml, targets.yaml and docs/COMPLIANCE.md current in every commit; commit after every green step with conventional-commit messages.
6. After each phase report: what was built, which combinations now build and pass, deviations, open risks, questions. Never claim a combination works without an interop run.

## 1. Non-negotiable requirements
### 1.1 Security of the channel
- MUST authenticate both endpoints with long-term identity keys (O'z DSt 1092 signatures) bound to the full handshake transcript (hash O'z DSt 1106).
- MUST provide forward secrecy: fresh ephemeral key agreement per session (resolve the primitive in ADR-0001: library DH/KEM if present; otherwise Diffie-Hellman in the 1092 group inside crypto-ext; recommended hybrid with X25519 and optionally ML-KEM-768 feeding one HKDF-1106 input); traffic keys rekeyed by time, bytes and record count.
- MUST protect every record with AEAD semantics built from the library's cipher and hash: the library's AEAD mode if it has one, otherwise CTR (or the standard's gamma mode) plus HMAC-1106 in encrypt-then-MAC with independent per-direction keys. ECB is forbidden. Nonce = 64-bit sequence plus direction bit, never reused.
- MUST resist downgrade (negotiation inside the transcript hash, key-confirmation MAC), MUST be side-channel conscious (constant-time comparisons, zeroization, no secrets in logs, uniform failures) and MUST be transport-agnostic (sans-I/O core over byte frames: WebRTC DataChannel, QUIC, TCP, WebSocket, UDP, relay).
- MUST be P2P-first: client-to-client payload goes directly; the relay is used only when NAT traversal fails and forwards ciphertext it cannot decrypt. The server MUST NOT be able to read, modify or inject payloads undetected: end-to-end keys never leave endpoints; identity verification resists a malicious server (CA-issued device certificates, out-of-band fingerprint verification, trust-on-first-use pinning, revocation).
- MUST NOT implement cryptography in any language but the core's: every runtime calls the same compiled core, through FFI, WebAssembly or the sidecar. MUST NOT disable platform transport security; layer on top of it.

### 1.2 One core, many runtimes
- The core is one Rust workspace compiled to: a C ABI (cbindgen) for native runtimes, wasm32 for browsers and WASM embedders, a WASI build, the runtime-specific bridges in section 4, and the qalqond sidecar binary. Every delivery exposes the SAME public API, specified once in core/idl/ (see 1.7); CI diffs each binding's generated surface against it.
- Every binding MUST pass the shared conformance vectors in tests/conformance inside its own runtime before anything built on it is released.
- Bindings never re-implement; a binding that contains protocol logic is a defect (rule 0.4).

### 1.3 Monorepo structure
- Folder roles and nothing else: core/, bindings/<runtime>/, packages/<ecosystem>/<framework>/, clients/<platform>/, servers/<framework>/, templates/, infra/, tools/, tests/, formal/, docs/. One inner folder per platform or framework, each self-contained: README quickstart, its ecosystem's native build file, tests, and a qalqon.yaml manifest (name, kind, language, framework, delivery path: rust | ffi | wasm | sidecar, targets, depends_on, toolchain minimums, primary_pairs, owners).
- The root combinations.yaml is GENERATED from the manifests by the qalqon CLI; a hand edit fails CI. targets.yaml lists every operating system and CPU the repo builds for.
- One VERSION for all packages; a separate PROTOCOL_VERSION negotiated on the wire; same-major packages interoperate.

### 1.4 Build orchestration
- Provide tools/qalqon-cli (Rust binary, also runnable as cargo qalqon) with: build --client <x> --server <y> [--targets <os,...>]; dev --client <x> --server <y> (hot reload, local relay and coturn); test --pair <x>:<y>, --triple <a>,<b>:<y>, --conformance <binding>; package --client <x> --server <y> (signed artifacts into dist/<x>+<y>/); list; doctor (verifies toolchains, prints exact install commands or offers the devcontainer); new binding|client|server|target (section 1.7).
- Resolution: read combinations.yaml, compute the dependency closure of the chosen folders, build the core once per target into a content-addressed cache, build only the folders on the path, reuse cached artifacts across pairs and targets.
- Default orchestrator: just recipes plus each ecosystem's native tool (cargo, npm or pnpm, Gradle, CMake, maturin, go, dotnet, xcodebuild, flutter, composer, bundler, mix) driven by the CLI; document Bazel as the scale-up path in ADR-0003. If BUILD ORCHESTRATOR PREFERENCE says Bazel or Nx, use it from the start.
- Toolchains pinned in infra/devcontainer; a Nix flake is optional.

### 1.5 Any client x any server
- tests/interop runs a client against a server through a fresh host container, the blind relay and coturn: enrol two devices with the test CA, log in, rendezvous, direct P2P channel, relay-forced channel, 1,000 records with a rekey, audit chains verified, teardown. Headless drivers: Playwright (browsers), Maestro (Android, iOS), CLI binaries elsewhere; network conditions from tools/natsim.
- PRIMARY PAIRS run on every pull request; the full client x server matrix runs nightly and on release, with rows and columns discovered from the manifests. Mixed-client triples declared in combinations.yaml run nightly.

### 1.6 Compliance with O'z DSt 2814:2014 for TARGET_CLASS
- Cryptographic subsystem (Table 1 items 3.2, 3.4; clauses 5.3-13.3): all restricted data leaving the control zone is encrypted by the library; keys reachable only through access control (per-subject handles, RBAC, audited use); at-rest encryption of the local store for 2A/1B/1A; distinct keys per subject or group for 1A.
- Access control (10.1 / 11.1): user authentication (standard floor: 8 alphanumeric characters; enforce 12, Argon2id, rate limits, optional MFA); device identity certificates as terminal identification; named resources; access matrix via RBAC/ABAC; confidentiality labels with flow control for 1V and up.
- Registration and accounting (10.2 / 11.2): tamper-evident audit log (login/logout, session establishment and teardown, key events, access attempts with subject, object, operation and result, server program starts, privilege changes for 1V+), hash-chained with 1106 and periodically signed, exportable; alarm hook for breach attempts (1V+); clearing of freed memory. Record the identifier presented on failed attempts and a hash of the presented secret, never the cleartext secret; note the interpretation in COMPLIANCE.md.
- Integrity (10.4 / 11.4): known-answer self-tests at module load; 1106 hash of the crypto module and binaries against a signed manifest at start-up; signed reproducible releases with SBOM; no development tools in production images; backup and recovery (two copies); an attack-imitation test suite (qalqon-selftest) runnable in CI and on demand; a security-administrator role with alerting.
- Produce docs/COMPLIANCE.md as a clause-by-clause matrix (control, location, evidence, status), with every host inheriting the server-core rows and adding its own for persistence and configuration. The sidecar adds rows for local IPC protection.

### 1.7 Open to any language, any framework, any operating system
- IDL first: core/idl/ is the single source of truth for the public API. From it generate the UniFFI .udl, the cbindgen C header, a WIT file for WASM embedders, the JSON-RPC schema for the sidecar, and docs/SDK-API.md. CI fails if any generated artifact is stale.
- Four delivery paths, chosen per language by three questions: written in Rust -> native crate; has a foreign-function interface -> generated C ABI binding; can run WebAssembly -> WASM module (wasm-bindgen for JavaScript, WASI build for runtime embedders such as wasmtime, wasmer, wazero); otherwise -> the sidecar. Every path ends in the same SDK API and the same conformance vectors.
- The sidecar qalqond: a static Rust binary that embeds the core and serves the SDK API over a Unix domain socket (Linux, macOS), a named pipe (Windows) or loopback TCP with a per-launch token; length-prefixed JSON-RPC mirroring SDK-API.md; peer-credential checks (SO_PEERCRED, pipe SID); runs as the same user; keys never leave the daemon; shipped per target and as a container image to run beside any server. Provide generated sidecar client libraries (about 200 lines each) for at least PHP, Ruby, Elixir and shell (curl-style) in the first wave, and a generator for any other language.
- Two contracts and nothing else per framework: the Client Adapter Contract (create session from config, surface events in the framework's idiom - hooks, composables, signals, observables, coroutines, async/await, callbacks - expose channel send/receive and verifyPeer) and the Host SPI (accept upgrade, UserStore, DeviceStore, PolicyStore, AuditSink, Config, Health and Metrics, Admin).
- Scaffolding: qalqon new binding --lang <x> --path ffi|wasm|sidecar; qalqon new client --lang <x> --framework <y>; qalqon new server --lang <x> --framework <y>; qalqon new target --triple <t> --os <name>. Each creates a complete folder from templates/ (manifest, build file, README, test harness, delivery-path wiring, CI job) so that only the idiomatic part remains to write. templates/index.yaml is the registry; a scaffolded folder must pass conformance (binding) or interop (client, server) before merge.
- targets.yaml: Windows 10/11 (x64, arm64); Linux glibc 2.17+ (x64, arm64, armv7) and musl (x64, arm64); macOS 13+ (arm64, x64, universal); iOS 15+ (arm64, simulator); Android API 28+ (arm64-v8a, armeabi-v7a, x86_64); web (wasm32); WASI (wasm32-wasip1); containers (linux x64, arm64). FreeBSD, embedded Linux and no_std are community tier: the core must build for them, packaging is optional. Adding an OS = a target triple in targets.yaml + a packaging recipe in tools/packaging/ + a CI runner; every binding inherits it.
- Per-OS packaging in tools/packaging/: Windows (MSVC and MinGW import libraries, MSIX or winget), Linux (.deb, .rpm, Flatpak or AppImage), macOS (.pkg, Homebrew tap), iOS (XCFramework), Android (AAR), web (npm), containers (OCI). Key storage per OS: DPAPI/CNG, Secret Service, Keychain and Secure Enclave, Keystore/StrongBox, WebCrypto-wrapped IndexedDB.
- The procedure for anything new is documented in docs/EXTENDING.md and must be executable by a developer who has never seen the repo in under one day of idiomatic work.

## 2. Architecture
- core/crypto-provider: CryptoProvider trait { hash, mac, hkdf_extract, hkdf_expand, aead_seal, aead_open, sign, verify, kex_keygen, kex_agree, random, key_wrap, key_unwrap }; core/provider-<lib> binds the library (the only unsafe FFI to it); core/crypto-ext holds feature-gated primitives outside the certified boundary.
- core/qalqon-core: sans-I/O engine - handshake state machine, record layer, key schedule, replay window, rekeying, fragmentation, multiplexed channels (16-bit id), optional resumption, error taxonomy; builds without an OS when given an allocator.
- core/qalqon-transport-*: adapters declaring ordered/unordered, reliable/unreliable and MTU; core/qalqon-signal: rendezvous client logic; core/qalqon-audit: event schema and 1106 hash chain.
- core/server-core: the server side as a library - session registry, rendezvous matching, policy evaluation, rate limits, audit chaining, admin API model - embedded by every host through its binding or through the sidecar. Hosts implement the Host SPI. Reference SQL migrations ship with server-core; each host applies them with its own tooling.
- core/ffi: the C ABI (opaque handles, explicit lifetimes, error codes, no callbacks that hold the GIL or the JVM); core/idl: the API definition and generators; core/sidecar: the qalqond daemon.
- SDK API (docs/SDK-API.md, generated): connect, openChannel, send, receive, verifyPeer, rotateKeys, exportAudit, plus events; identical names and error codes in every language and over the sidecar.

## 3. Protocol (docs/PROTOCOL.md, RFC style, frozen at Phase 2)
Binary wire format with a fixed header { magic, version, suite_id, msg_type, channel_id u16, seq u64, length u16 } and TLV extensions; Noise-style handshake (XX-style 3-message first contact, IK-style 1-RTT when the peer's identity is known) with 1092 signatures over the 1106 transcript hash and an HKDF-1106 key schedule with per-direction labels; record layer with per-direction keys, sequence nonces, rekey at the first of 2^32 records, 1 GiB or 1 hour, 1024-entry replay window on unordered transports, authenticated close; device certificates from an offline-root / online-issuing CA with short validity and a CRL endpoint; fingerprints as safety numbers; deterministic JSON test vectors in tests/conformance; a Tamarin or ProVerif model in formal/. If a detail is not settled by this prompt, ask for the companion specification rather than guessing.

## 4. First-wave deliverables per folder (the open model adds more through scaffolding)
- bindings/: c (static and shared libraries, qalqon.h, qalqon.hpp RAII wrapper, CMake package config, Conan and vcpkg recipes), wasm (wasm-bindgen, Worker-first API, TypeScript types) and wasi (component for runtime embedders), node (napi-rs addon with prebuilds for linux glibc and musl, macOS, Windows, x64 and arm64), java (FFM for Java 22+, JNI fallback for 17-21, JAR bundling native libraries per OS/arch), kotlin (Android AAR via UniFFI), swift (XCFramework and Swift package via UniFFI), python (PyO3, wheels via maturin, GIL released around crypto), go (cgo over the C ABI with vendored static libs), dotnet (P/Invoke with SafeHandle, NuGet runtimes/), dart (dart:ffi for Flutter), sidecar-clients (php, ruby, elixir, shell; generator for others).
- packages/: js/web, js/react (hooks), js/vue (composables), js/angular (services), js/svelte (stores), js/electron (IPC bridge); node/express, node/fastify, node/nest; java/spring-boot-starter (auto-configuration, WebSocketHandler, Spring Security integration, JPA adapters), java/servlet, java/quarkus; python/fastapi, python/django; go/nethttp, go/gin; dotnet/aspnet, dotnet/maui; dart/flutter; php/laravel (via sidecar); ruby/rails (via sidecar); elixir/phoenix (via sidecar); qt (QML plugin); gtk (C).
- clients/: web-react, web-vue, web-angular, web-svelte, desktop-electron, desktop-tauri, desktop-qt, desktop-gtk, desktop-wpf, cli-c, cli-rust, android, ios, flutter, dotnet-maui, python-cli, go-cli, php-cli (sidecar) - each a minimal text-and-file-transfer app over its SDK, with the same screens so interop runs can drive them uniformly.
- servers/: rust-axum (reference), node-express, node-fastify, java-spring, java-quarkus, python-fastapi, go-nethttp, dotnet-aspnet, php-laravel (sidecar), ruby-rails (sidecar), elixir-phoenix (sidecar) - each a thin host over server-core with an OCI image, SQL migrations applied by its own tool, health and metrics, and an admin CLI entry point.
- templates/: one template per kind (binding-ffi, binding-wasm, binding-sidecar, client, server, target) with the registry index. infra/: relay (blind, ciphertext only), coturn, iroh-relay, sidecar image, compose, helm, devcontainer. tools/: qalqon-cli, packaging, ca, vectors, interop, natsim, selftest, fuzz. tests/: conformance, interop. formal/. docs/.
- Build ONLY the folders the PRIMARY PAIRS need first (Phase 3), then widen; every folder listed in the fill-in block must exist by Phase 6 with at least a passing nightly cell; everything else is reachable through qalqon new.

## 5. Packaging and release
One VERSION; artifacts and registries: crates (crates.io or private), libqalqon + header (GitHub Releases, Conan, vcpkg), npm (@qalqon/web, react, vue, angular, svelte, electron, node with prebuilds), Maven (qalqon-java, spring-boot-starter, quarkus extension, qalqon-android AAR), SwiftPM binary target (XCFramework), PyPI wheels, Go module tag with vendored libs, NuGet with runtimes/, pub.dev, Packagist (PHP sidecar client), RubyGems, Hex (Elixir), OCI images for hosts, the sidecar and infra; per-OS installers from tools/packaging. Pipeline: tag -> core build matrix over targets.yaml into a content-addressed cache -> bindings and the sidecar built from cached core artifacts -> conformance in each runtime -> interop (primary pairs; full matrix on release) -> SBOM and signatures -> publish in dependency order -> docs site.

## 6. Documentation (mandatory, per phase)
Root README with the pair-selection story and the command table; docs/ARCHITECTURE.md (C4 levels 1-3 as Mermaid, including the delivery-path and polyglot diagrams); docs/PROTOCOL.md; docs/SDK-API.md (generated); docs/HOST-SPI.md; docs/CLIENT-ADAPTER.md; docs/SIDECAR.md; docs/EXTENDING.md (adding a language, a framework, an OS, step by step); docs/BUILD.md (orchestrator, manifests, cache, targets); docs/THREAT-MODEL.md; docs/SECURITY.md; docs/COMPLIANCE.md; docs/OPERATIONS.md (deploy per host and per OS, key ceremony, rotation, revocation, backup and restore, audit export); docs/TESTING.md; ADRs; CHANGELOG; a README quickstart in every inner folder; generated API references per language; the whole set published as an mdBook site.

## 7. Phases and gates
0. Inventory, ADRs 0001-0004, PROTOCOL v0, IDL v0, SDK-API v0, HOST-SPI v0, CLIENT-ADAPTER v0 -> gate: my approval.
1. core/: crypto-provider with known-answer tests from the official control examples, timing tests, fuzzers; qalqon-core with vectors; formal model; server-core -> gate: two Rust peers interoperate over TCP and UDP; lemmas proven.
2. core/idl with generators, core/ffi C ABI, bindings/c, bindings/wasm, core/sidecar with the PHP and shell clients, servers/rust-axum, infra/relay and coturn, tools/qalqon-cli (build, test, list, doctor, new), templates/ -> gate: cli-c, web-react and a sidecar-based PHP CLI each talk to rust-axum; qalqon new scaffolds a passing binding.
3. PRIMARY PAIRS: their bindings, packages, clients and hosts -> gate: every primary pair green in tests/interop on every PR; mixed-client triple green.
4. Mobile and targets: bindings/kotlin and swift, clients/android and ios, the full targets.yaml build matrix with per-OS packaging -> gate: android and ios against two different hosts; every target in targets.yaml produces its artifact.
5. Remaining first-wave hosts, clients and sidecar languages from the fill-in block -> gate: every declared folder has a passing nightly cell.
6. Release pipeline to all registries, docs site, hardening, selftest suite, reproducible signed release with SBOM -> gate: a tagged release installs from the registries alone and the full matrix is green.

## 8. Definition of done
- Core and provider: at least 90 percent line coverage, property tests, one hour of fuzzing per target without a crash, Miri clean; unsafe only in core/ffi and core/provider-<lib>, each block justified.
- Every binding and the sidecar pass tests/conformance in their own runtime; every host passes the interop suite against the Rust CLI client and its primary pairs; the nightly matrix has no red cell for a declared folder.
- qalqon build --client <any declared> --server <any declared> succeeds on a clean devcontainer for every target in targets.yaml that the pair supports; qalqon doctor explains every missing toolchain.
- Openness proven: a developer following docs/EXTENDING.md adds a new language through qalqon new in under one day and its binding passes conformance; a new server framework added the same way passes interop; a new OS added through targets.yaml builds every binding.
- Supply chain: cargo-audit, cargo-deny, npm audit, pip-audit, OWASP dependency-check for JVM and .NET clean; pinned toolchains; CycloneDX SBOM per artifact; signed artifacts; reproducible build verified on two runners.
- Performance measured on every platform (handshake latency, per-record overhead, throughput, sidecar round trip); budgets set after Phase 2 and enforced in CI.
- Documentation complete per section 6; COMPLIANCE.md has no row without evidence or an explicit, dated gap.
```

## Roadmap: the order that unlocks the most combinations

The C ABI and the WASM build come before any framework work, because together they unlock C, C++, Qt, Go, Dart and every browser framework at once; the two servers you named (Spring, Node) come next; mobile and the long tail follow. Durations assume one engineer plus the agent.

1. Phase 0 - Inventory and decisions (1 week): crypto inventory, ADR-0001 key agreement, ADR-0002 core and FFI strategy, ADR-0003 build orchestrator, PROTOCOL v0, SDK-API v0, Host SPI v0. Gate: your approval.
2. Phase 1 - Core (4 weeks): crypto provider with known-answer tests, protocol engine, vectors, formal model, server-core. Gate: Rust peers interoperate; lemmas proven.
3. Phase 2 - Universal deliveries (3 weeks): C ABI, `bindings/c`, `bindings/wasm`, `servers/rust-axum`, relay and coturn, `qalqon` CLI with build, test, list, doctor. Gate: `cli-c` and `web-react` both talk to `rust-axum` through the CLI.
4. Phase 3 - Primary pairs (4 weeks): for React + Spring - `bindings/java`, `spring-boot-starter`, `servers/java-spring`, `packages/js/react`, `clients/web-react`; for C + Node - `bindings/node`, `packages/node/express`, `servers/node-express`, `clients/cli-c`. Gate: both pairs and the mixed triple green on every PR.
5. Phase 4 - Mobile (3 weeks): `bindings/kotlin`, `bindings/swift`, `clients/android`, `clients/ios`. Gate: each against two hosts.
6. Phase 5 - Long tail (4 weeks): Python, Go and .NET hosts; Flutter, Qt, Electron, Tauri, Vue, Angular and MAUI clients. Gate: every declared folder has a passing nightly cell.
7. Phase 6 - Release (2 weeks): registries, signing, SBOM, docs site, selftest suite. Gate: a tagged release installs from registries alone; full matrix green.

About 21 weeks end to end; certification of the library runs in parallel with the authorised body and is not on this clock.

## Risks and decisions specific to a polyglot monorepo

The protocol risks (key agreement, certification scope, browser tier, NAT failure) are in the companion doc; these are the ones a many-language repository adds.

| Risk or decision | Impact if ignored | Mitigation or decision |
| --- | --- | --- |
| Toolchain sprawl: Rust, Node, JDK, Python, Go, .NET, Android SDK/NDK, Xcode, Flutter | Nobody can build the whole repo; onboarding takes days | Pinned devcontainer; `qalqon doctor`; `qalqon build` only needs the toolchains of the chosen pair |
| Logic drift into hosts and adapters | Six slightly different servers; a bug fixed in one host survives in five | Rule 0.4 lint (no protocol logic outside `core/`); the Host SPI is the whole contract; interop suite compares every host to the Rust reference |
| Native prebuild matrix explosion (OS x CPU x runtime) | CI minutes and release size balloon | Build the core once per target into a content-addressed cache; bindings reuse it; limit targets to the fill-in block's list; add targets on request |
| Java FFM versus JNI | Java 17 shops cannot load the FFM binding; Java 22+ shops should not pay the JNI cost | Ship both in one JAR, pick at runtime by `Runtime.version()`; FFM is final since Java 22 |
| Node-API ABI and Node versions | Addon fails on an unsupported Node | napi-rs prebuilds target the Node-API level, not a Node version; test on Node 22 and 24 LTS |
| Version skew between packages from different registries | A React 1.5 client against a Spring 1.3 host | One `VERSION`; `PROTOCOL_VERSION` negotiated on the wire; same-major interoperability tested nightly |
| Build orchestrator choice | just-based scripts stop scaling; Bazel adoption is costly | Start with the `qalqon` CLI over native tools (ADR-0003); keep manifests orchestrator-neutral so a Bazel migration is mechanical |
| Ownership of 30+ folders | Unowned folders rot | `CODEOWNERS` per folder, `owners` in every manifest, nightly cell per folder; a folder without an owner is marked experimental in the docs |
| libwebrtc on Android and iOS | Large binaries, update cadence | Pin a libwebrtc release per `VERSION`; document size; Tauri and Qt use webrtc-rs or libdatachannel instead |
| Memory zeroization in managed runtimes (JVM, .NET, Node, Python, Dart) | Key bytes linger in garbage-collected heaps | Keys never cross the FFI boundary as bytes: handles only; secrets stay in Rust-owned memory and are zeroized there |
| Conformance vectors drifting from PROTOCOL.md | Bindings agree with each other but not with the spec | Vectors are generated from the Rust reference by `tools/vectors` on every change and reviewed as part of the spec PR |

## Sources

- Companion doc: *Secure P2P Channel Project - Build Prompt, Architecture & Stack (O'z DSt 2814:2014)* - the standard's requirements, the protocol internals and the compliance matrix this doc builds on.
- O'z DSt 2814:2014 - the scanned official edition you attached; all clause numbers refer to it.
- [JEP 454: Foreign Function & Memory API](https://openjdk.org/jeps/454) - status Closed / Delivered in Java 22; the basis of the JVM binding.
- [NAPI-RS](https://napi.rs/) - pre-compiled Node.js addons in Rust; Node-API ABI stability; current CI on Node 22, 24 and 26.
- [mozilla/uniffi-rs](https://github.com/mozilla/uniffi-rs) - Kotlin and Swift bindings generator, plus third-party WASM, React Native, Kotlin Multiplatform, Go, C# and Dart bindings.
- [Iroh 1.0: Dial Keys, Not IPs](https://pinggy.io/blog/iroh_1_0_dial_keys_not_ips/) - QUIC hole punching and relay fallback for the native fast path.
- Constructions referenced: Noise Protocol Framework, TLS 1.3 key schedule (RFC 8446), HMAC (RFC 2104), HKDF (RFC 5869).
