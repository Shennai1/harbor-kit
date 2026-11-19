"""Run the public-source checks and complete developer regression suite."""

import ast
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import unittest

from tools.public_source import ExportError, collect


class CheckError(Exception):
    pass


def source_check(root):
    snapshot = collect(root)
    public = {item["path"] for item in snapshot["files"]}
    # Fail when a new code/test file would be missing from the delivered source.
    actual = {path.relative_to(root).as_posix()
              for name in ("snellctl", "tests", "tools")
              for path in (root / name).rglob("*.py")}
    expected = {path for path in public if path.endswith(".py")}
    if actual != expected:
        raise CheckError("Python files and the public allowlist differ.")
    test_files = sorted(path for path in expected
                        if path.startswith("tests/test_") and path.count("/") == 1)
    if not test_files:
        raise CheckError("No regression test files found.")
    for item in snapshot["tree_elements"]:
        if item["path"].endswith(".py"):
            try:
                ast.parse(item["content"], filename=item["path"], feature_version=(3, 11))
            except SyntaxError:
                raise CheckError("Python 3.11 syntax check failed: " + item["path"]) from None
    return {"snapshot_sha256": snapshot["snapshot_sha256"],
            "public_files": snapshot["file_count"], "python_files": len(expected),
            "test_files": len(test_files)}


def environment_check():
    if os.name != "posix" or sys.version_info < (3, 11):
        raise CheckError("Tests require POSIX and Python 3.11 or later.")
    if not ssl.HAS_TLSv1_3:
        raise CheckError("Python must support TLS 1.3; TLS tests are not skipped.")
    openssl = shutil.which("openssl")
    if openssl is None:
        raise CheckError("OpenSSL CLI is required for disposable test certificates.")
    try:
        subprocess.run([openssl, "version"], check=True, timeout=10,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
    except (OSError, subprocess.SubprocessError):
        raise CheckError("OpenSSL or local loopback listening is unavailable; no tests skipped.") from None


def run_checks(root):
    before = source_check(root)
    environment_check()
    loader = unittest.TestLoader()
    suite = loader.discover(str(root / "tests"), pattern="test_*.py")
    if loader.errors or suite.countTestCases() == 0:
        raise CheckError("Test discovery failed or produced no tests.")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    after = source_check(root)
    unchanged = before == after
    passed = (result.wasSuccessful() and not result.skipped
              and not result.expectedFailures and unchanged)
    return {"format": 1, "operation": "developer-check",
            "result": "passed" if passed else "failed",
            "tests_run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped),
            "expected_failures": len(result.expectedFailures),
            "source_unchanged": unchanged, "source": before,
            "python": sys.version.split()[0], "vps_acceptance": False}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args:
        print("Usage: python3 -E -s -B -m tools.check", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    previous = Path.cwd()
    try:
        os.chdir(root)
        report = run_checks(root)
    except KeyboardInterrupt:
        report = {"format": 1, "operation": "developer-check", "result": "interrupted"}
    except (CheckError, ExportError) as error:
        report = {"format": 1, "operation": "developer-check", "result": "blocked",
                  "reason": str(error)}
    except OSError:
        report = {"format": 1, "operation": "developer-check", "result": "blocked",
                  "reason": "Unable to read source or run the test environment."}
    finally:
        os.chdir(previous)
    print(json.dumps(report, indent=2))
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
