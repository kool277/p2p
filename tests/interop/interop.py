#!/usr/bin/env python3
"""One interop cell, as the build prompt's section 1.5 describes.

Starts a fresh host and the blind relay, enrols two devices with the test CA, logs in,
runs a direct channel, then a relay-forced channel, exchanges records with a rekey,
verifies the audit chain on the host, and tears everything down.

Usage: interop.py --client <name> [--peer <name>] --server <name> [--records N]

A client is a command that speaks the CLI contract in docs/CLIENT-ADAPTER.md, and each
is listed in CLIENTS below. A non-zero exit means the cell failed.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BIN = os.path.join(ROOT, "target", "debug")
PASSWORD = "correct horse battery staple"


def bin_path(name):
    return os.path.join(BIN, name)


CLIENTS = {
    "cli-rust": [bin_path("qalqon-cli-rust")],
    "cli-c": [os.path.join(ROOT, "target", "cli-c", "qalqon-cli-c")],
    "php-cli": ["php", os.path.join(ROOT, "clients", "php-cli", "qalqon.php")],
    "web-react": ["node", os.path.join(ROOT, "tests", "interop", "web", "driver.mjs")],
}

# A browser has no direct path to a native peer yet, so it reaches one through the relay.
RELAY_ONLY_WITH_NATIVE = {"web-react"}

SERVERS = {
    "rust-axum": lambda port, db, pki, token, relay: [
        bin_path("qalqon-axum"), "--listen", f"127.0.0.1:{port}", "--db", db, "--pki", pki,
        "--host", "localhost", "--relay", relay, "--admin-token-file", token,
    ],
}


def needs_sidecar(client):
    return client == "php-cli"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Failure(Exception):
    pass


class Cell:
    def __init__(self, work, server, records):
        self.work = work
        self.server = server
        self.records = records
        self.processes = []
        self.pki = os.path.join(work, "pki")
        self.server_port = free_port()
        self.relay_port = free_port()
        self.server_url = f"ws://127.0.0.1:{self.server_port}/qalqon"
        self.http = f"http://127.0.0.1:{self.server_port}"
        self.relay_url = f"ws://127.0.0.1:{self.relay_port}/"
        self.ca = os.path.join(self.pki, "root.cert")
        self.admin_token = os.urandom(16).hex()

    def start(self):
        ca = bin_path("qalqon-ca")
        subprocess.run([ca, "init", self.pki], check=True)
        subprocess.run([ca, "server", self.pki, "127.0.0.1"], check=True)
        token_file = os.path.join(self.work, "admin.token")
        fd = os.open(token_file, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, self.admin_token.encode())
        os.close(fd)
        keys = os.path.join(self.pki, "keys")
        relay_log = open(os.path.join(self.work, "relay.log"), "w")
        self.processes.append(subprocess.Popen(
            [bin_path("qalqon-relay"), "--listen", f"127.0.0.1:{self.relay_port}", "--relay-key", f"file:{keys}#relay"],
            stdout=relay_log, stderr=relay_log))
        command = SERVERS[self.server](self.server_port, os.path.join(self.work, "host.sqlite"), self.pki, token_file, self.relay_url)
        command[command.index("--host") + 1] = "127.0.0.1"
        host_log = open(os.path.join(self.work, "host.log"), "w")
        self.processes.append(subprocess.Popen(command, stdout=host_log, stderr=host_log))
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(self.http + "/readyz", timeout=1) as r:
                    if r.status == 200:
                        return
            except (urllib.error.URLError, ConnectionError, OSError):
                pass
            time.sleep(0.1)
        raise Failure("the host did not become ready:\n" + open(os.path.join(self.work, "host.log")).read())

    def start_sidecar(self):
        """qalqond for the clients that talk to it. Its socket lives in a 0700 directory."""
        directory = os.path.join(self.work, "sidecar")
        os.makedirs(directory, mode=0o700)
        os.chmod(directory, 0o700)
        path = os.path.join(directory, "qalqond.sock")
        log = open(os.path.join(self.work, "qalqond.log"), "w")
        self.processes.append(subprocess.Popen([bin_path("qalqond"), "serve", "--socket", path], stdout=log, stderr=log))
        deadline = time.time() + 10
        while time.time() < deadline and not os.path.exists(path):
            time.sleep(0.02)
        if not os.path.exists(path):
            raise Failure("qalqond did not start")
        return path

    def stop(self):
        for process in reversed(self.processes):
            process.send_signal(signal.SIGTERM)
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    def admin(self, method, params=None):
        request = urllib.request.Request(
            f"{self.http}/admin/{method}",
            data=json.dumps(params or {}).encode(),
            headers={"Authorization": f"Bearer {self.admin_token}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read())

    def metric(self, name):
        with urllib.request.urlopen(self.http + "/metrics", timeout=5) as r:
            for line in r.read().decode().splitlines():
                if line.startswith(name + " "):
                    return int(line.split()[1])
        raise Failure(f"the metric {name} is missing")

    def common(self, data, relay_only=False):
        args = ["--server", self.server_url, "--ca", self.ca, "--data", data]
        if relay_only:
            args.append("--relay-only")
        return args


def run_json_lines(command, env, timeout, name, work):
    """Runs a client, returning its parsed JSON lines."""
    log = os.path.join(work, f"{name}.log")
    with open(log, "w") as output:
        code = subprocess.run(command, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=timeout).returncode
    return code, parse_lines(log), log


def parse_lines(log):
    lines = []
    with open(log) as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                try:
                    lines.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return lines


def result_of(lines, log):
    for line in reversed(lines):
        if "result" in line:
            if line["result"] != "ok":
                raise Failure(f"the client reported {line} (see {log})")
            return line
    raise Failure(f"the client printed no result. Its output:\n{open(log).read()[-2000:]}")


def scenario(cell, caller, callee, data_a, data_b, relay_only, expected_path, env, name):
    """Callee answers, caller calls. Both must finish and agree."""
    common_b = cell.common(data_b, relay_only)
    answer_log = os.path.join(cell.work, f"{name}-answer.log")
    answer_out = open(answer_log, "w")
    answer = subprocess.Popen(
        CLIENTS[callee] + ["answer"] + common_b + ["--user", "bob", "--wait-ms", "60000"],
        env=env, stdout=answer_out, stderr=subprocess.STDOUT)
    # Wait until the callee has logged in, so the rendezvous finds it online.
    deadline = time.time() + 30
    while time.time() < deadline:
        if any("state" in l for l in parse_lines(answer_log)):
            break
        if answer.poll() is not None:
            raise Failure(f"{callee} ended early:\n{open(answer_log).read()[-2000:]}")
        time.sleep(0.05)
    else:
        raise Failure(f"{callee} did not log in:\n{open(answer_log).read()[-2000:]}")

    command = CLIENTS[caller] + ["call"] + cell.common(data_a, relay_only) + [
        "--user", "alice", "--peer", "bob", "--records", str(cell.records)]
    code, lines, call_log = run_json_lines(command, env, 180, f"{name}-call", cell.work)
    called = result_of(lines, call_log)
    if code != 0:
        raise Failure(f"{caller} exited with {code} (see {call_log})")

    try:
        answer.wait(timeout=30)
    except subprocess.TimeoutExpired:
        answer.kill()
        raise Failure(f"{callee} did not finish after the call ended:\n{open(answer_log).read()[-2000:]}")
    answer_out.close()
    answered = result_of(parse_lines(answer_log), answer_log)

    problems = []
    if called["records"] != cell.records:
        problems.append(f"{called['records']} of {cell.records} came back")
    if answered["records"] != cell.records:
        problems.append(f"the callee echoed {answered['records']}")
    if called["path"] != expected_path or answered["path"] != expected_path:
        problems.append(f"the path was {called['path']} and {answered['path']}, not {expected_path}")
    if called["key_epoch"] < 1:
        problems.append("the keys never rotated")
    if not called["safety_number"] or called["safety_number"] != answered["safety_number"]:
        problems.append("the two sides computed different safety numbers")
    if problems:
        raise Failure(f"{name}: " + "; ".join(problems))
    print(f"  ok {name}: {called['records']} records, path {called['path']}, key epoch {called['key_epoch']}, "
          f"peer {called['peer_status']}, {called['audit_entries']} local audit entries")
    return called, answered


def run_cell(args):
    work = tempfile.mkdtemp(prefix="qalqon-interop-")
    cell = Cell(work, args.server, args.records)
    keep = False
    try:
        cell.start()
        for user in ("alice", "bob"):
            cell.admin("users.create", {"user_id": user, "password": PASSWORD})
        env = dict(os.environ, QALQON_PASSWORD=PASSWORD)
        if needs_sidecar(args.client) or needs_sidecar(args.peer):
            env["QALQOND_SOCKET"] = cell.start_sidecar()

        data_a, data_b = os.path.join(work, "alice"), os.path.join(work, "bob")
        for user, client, data in (("alice", args.client, data_a), ("bob", args.peer, data_b)):
            token = cell.admin("devices.createEnrollmentToken", {"user_id": user})["token"]
            command = CLIENTS[client] + ["enroll"] + cell.common(data) + ["--token", token]
            code, lines, log = run_json_lines(command, env, 60, f"enroll-{user}", work)
            if code != 0 or not any("enrolled" in l for l in lines):
                raise Failure(f"{client} did not enrol: exit {code}\n{open(log).read()[-2000:]}")
        print(f"  ok enrolled {args.client} and {args.peer}")

        # Two browsers get a direct WebRTC path, and a browser with a native peer falls
        # back to the relay by itself. That fallback is part of what this checks.
        pair = {args.client, args.peer}
        expected = "relayed" if pair & RELAY_ONLY_WITH_NATIVE and pair != RELAY_ONLY_WITH_NATIVE else "direct"
        first, _ = scenario(cell, args.client, args.peer, data_a, data_b, False, expected, env, "prefer-direct")
        if first["peer_status"] != "pinned":
            raise Failure(f"expected a pinned peer on first contact, got {first['peer_status']}")
        scenario(cell, args.client, args.peer, data_a, data_b, True, "relayed", env, "relay-forced")

        deadline = time.time() + 5
        while time.time() < deadline and cell.metric("qalqon_data_sessions_relayed_total") < 1:
            time.sleep(0.1)
        direct_seen = cell.metric("qalqon_data_sessions_direct_total")
        relayed_seen = cell.metric("qalqon_data_sessions_relayed_total")
        if relayed_seen < 1 or (expected == "direct" and direct_seen < 1):
            raise Failure(f"the host's metrics show {direct_seen} direct and {relayed_seen} relayed sessions")

        verified = cell.admin("audit.verify")
        if verified.get("ok") is not True:
            raise Failure(f"the host's audit chain does not verify: {verified}")
        print(f"  ok host audit chain verifies over {verified['entries']} entries")

        # The host's log and database must never contain the password or message bodies.
        db_bytes = open(os.path.join(work, "host.sqlite"), "rb").read()
        if PASSWORD.encode() in db_bytes:
            raise Failure("the password is in the host's database")
        if b"record 000000" in db_bytes:
            raise Failure("application data is in the host's database")
        print("  ok the host's database holds neither the password nor any message")
    except Failure:
        keep = True
        raise
    finally:
        cell.stop()
        if keep:
            print(f"  logs kept in {work}", file=sys.stderr)
        else:
            shutil.rmtree(work, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", default="cli-rust", choices=sorted(CLIENTS))
    parser.add_argument("--peer", default="cli-rust", choices=sorted(CLIENTS))
    parser.add_argument("--server", default="rust-axum", choices=sorted(SERVERS))
    parser.add_argument("--records", type=int, default=1000)
    args = parser.parse_args()
    print(f"interop: {args.client} + {args.peer} through {args.server}")
    try:
        run_cell(args)
    except (Failure, subprocess.TimeoutExpired, OSError) as e:
        print(f"FAILED: {e}", file=sys.stderr)
        return 1
    print("passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
