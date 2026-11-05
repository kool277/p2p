"""Python over the C ABI with ctypes. It loads the same core as every other binding, and
holds no protocol logic. See bindings/c/README.md for the ABI's rules."""

import ctypes
import os


class Buffer(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_ubyte)), ("len", ctypes.c_size_t)]


class QalqonError(Exception):
    def __init__(self, code, name):
        super().__init__(name)
        self.code = code
        self.name = name


def load(path=None):
    library = ctypes.CDLL(path or os.environ.get("QALQON_LIBRARY", "target/debug/libqalqon.so"))
    library.qalqon_abi_version.restype = ctypes.c_uint32
    library.qalqon_status_name.restype = ctypes.c_char_p
    library.qalqon_status_name.argtypes = [ctypes.c_uint32]
    library.qalqon_conformance_run.restype = ctypes.c_uint32
    library.qalqon_conformance_run.argtypes = [ctypes.c_char_p, ctypes.POINTER(Buffer)]
    library.qalqon_buffer_free.argtypes = [ctypes.POINTER(Buffer)]
    if library.qalqon_abi_version() != 0:
        raise RuntimeError("this library has a different ABI version")
    return library


def conformance_run(library, vectors):
    out = Buffer()
    status = library.qalqon_conformance_run(vectors.encode(), ctypes.byref(out))
    if status != 0:
        raise QalqonError(status, library.qalqon_status_name(status).decode())
    try:
        return ctypes.string_at(out.data, out.len).decode()
    finally:
        library.qalqon_buffer_free(ctypes.byref(out))
