#!/usr/bin/env python3
"""Runs the shared vectors through the C ABI, inside the Python runtime."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qalqon_ffi import conformance_run, load  # noqa: E402


def main():
    library = load()
    failed = 0
    for file in sys.argv[1:]:
        with open(file) as f:
            report = json.loads(conformance_run(library, f.read()))
        print(f"{os.path.basename(file)}: {report['passed']} passed, {len(report['failed'])} failed")
        failed += len(report["failed"])
        if report["passed"] == 0:
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
