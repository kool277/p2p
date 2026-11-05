# bindings/c

`libqalqon` and its headers, for C, C++, Qt, and any language that can call a C library.

```sh
cargo build -p qalqon-ffi       # target/debug/libqalqon.{a,so}
cargo qalqon test --conformance c
```

- `include/qalqon.h` is generated from the IDL through cbindgen. Do not edit it.
- `include/qalqon.hpp` is a small RAII wrapper.
- `CMakeLists.txt` is the CMake package. **It has never run,** because CMake is not on the development machine.

## The rules of the ABI

- Handles are opaque, and each type has its own `_free`.
- Every fallible call returns a `qalqon_status_t`, whose values are the IDL's error codes. `qalqon_status_name` gives the name.
- Bytes from the core come in a `qalqon_buffer_t`. Release it with `qalqon_buffer_free`. Text is also NUL-terminated.
- Bytes and strings into the core are borrowed for the duration of the call.
- Structured values are JSON text, in the encoding `docs/SDK-API.md` describes. `qalqon_json_get_string` and `qalqon_json_get_u64` read a field if you have no parser.
- Nothing calls back. Events, frames and host effects are all polled.
- A panic never crosses this boundary. It becomes `QALQON_INTERNAL`.
- Keys never cross this boundary as bytes.

`clients/cli-c` is a complete example, and the template for any C or C++ integration.
