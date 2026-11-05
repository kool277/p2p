"""A Python client for the qalqond sidecar: framing, hello and call. See docs/adr/0004-sidecar-ipc.md.

Every method in docs/SDK-API.md is `client.call("session.openChannel", {...})`. Write
idiomatic wrappers over this if you want them. There is no cryptography here, and there
must never be any.
"""

import json
import socket
import struct


class QalqonError(Exception):
    def __init__(self, code, name, message):
        super().__init__(message)
        self.code = code
        self.name = name


class QalqonClient:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(path)
        self.next_id = 1
        self.call("qalqond.hello", {"abi": 0, "client": "python/0.1.0"})

    def call(self, method, params=None):
        request_id = self.next_id
        self.next_id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}).encode()
        self.socket.sendall(struct.pack(">I", len(body)) + body)
        reply = json.loads(self._read(struct.unpack(">I", self._read(4))[0]))
        if "error" in reply:
            error = reply["error"]
            raise QalqonError(error["code"], error.get("data", {}).get("name"), error["message"])
        return reply.get("result")

    def _read(self, length):
        out = b""
        while len(out) < length:
            chunk = self.socket.recv(length - len(out))
            if not chunk:
                raise QalqonError(100, "transportFailed", "qalqond went away")
            out += chunk
        return out
