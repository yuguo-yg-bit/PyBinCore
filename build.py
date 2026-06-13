#!/usr/bin/env python3
"""Build entry point for PyBinCore."""

from __future__ import annotations

import os
import subprocess
import sys


def main() -> int:
    root_dir = os.path.dirname(os.path.abspath(__file__))
    if "--test" in sys.argv[1:]:
        from compiler_regression import run_suite

        return run_suite()
    command = [sys.executable, os.path.join(root_dir, "main.py"), *sys.argv[1:]]
    return subprocess.call(command, cwd=root_dir)


if __name__ == "__main__":
    raise SystemExit(main())
