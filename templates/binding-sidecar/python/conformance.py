#!/usr/bin/env python3
"""Runs the shared vectors through this binding, against a qalqond it starts itself."""

import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qalqon_client import QalqonClient  # noqa: E402


def main():
    directory = tempfile.mkdtemp(prefix="qalqon-conformance-")
    os.chmod(directory, 0o700)
    path = os.path.join(directory, "qalqond.sock")
    daemon = subprocess.Popen(["target/debug/qalqond", "serve", "--socket", path], stderr=subprocess.DEVNULL)
    try:
        for _ in range(500):
            if os.path.exists(path):
                break
            time.sleep(0.01)
        client = QalqonClient(path)
        failed = 0
        for file in sys.argv[1:]:
            with open(file) as f:
                report = json.loads(client.call("conformanceRun", {"vectors": f.read()}))
            print(f"{os.path.basename(file)}: {report['passed']} passed, {len(report['failed'])} failed")
            failed += len(report["failed"])
            if report["passed"] == 0:
                failed += 1
        return 1 if failed else 0
    finally:
        daemon.terminate()
        daemon.wait()


if __name__ == "__main__":
    sys.exit(main())
