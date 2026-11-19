from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools import check, public_source


class SourceCheckTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "tests").mkdir()
        self.file = self.root / "tests/test_example.py"
        self.file.write_text("value = 1\n", encoding="utf-8")
        patched = patch.object(public_source, "PUBLIC_FILES", ("tests/test_example.py",))
        patched.start()
        self.addCleanup(patched.stop)

    def test_public_source_summary(self):
        result = check.source_check(self.root)
        self.assertEqual(result["test_files"], 1)
        self.assertEqual(result["python_files"], 1)
        self.assertEqual(result["public_files"], 1)
        self.assertNotIn("value", json.dumps(result))

    def test_unlisted_python_file_rejected(self):
        (self.root / "tests/test_forgotten.py").write_text("pass\n")
        with self.assertRaises(check.CheckError):
            check.source_check(self.root)

    def test_private_notes_ignored(self):
        (self.root / "private.txt").write_bytes(b"private\xff")
        self.assertEqual(check.source_check(self.root)["public_files"], 1)

    def test_syntax_newer_than_minimum_rejected(self):
        self.file.write_text("type Alias = int\n")
        with self.assertRaisesRegex(check.CheckError, "syntax"):
            check.source_check(self.root)

    def test_empty_test_scope_rejected(self):
        self.file.unlink()
        with patch.object(public_source, "PUBLIC_FILES", ()):
            with self.assertRaisesRegex(check.CheckError, "No regression"):
                check.source_check(self.root)


class CheckRunnerTests(unittest.TestCase):
    def test_environment_checks_openssl_and_loopback(self):
        with patch.object(check.shutil, "which", return_value="/usr/bin/openssl"), \
             patch.object(check.subprocess, "run") as command, \
             patch.object(check.socket, "socket") as sock:
            check.environment_check()
        command.assert_called_once()
        self.assertEqual(command.call_args.args[0], ["/usr/bin/openssl", "version"])
        sock.return_value.__enter__.return_value.bind.assert_called_once_with(("127.0.0.1", 0))

    def test_missing_openssl_and_tls_are_blockers(self):
        with patch.object(check.shutil, "which", return_value=None):
            with self.assertRaises(check.CheckError):
                check.environment_check()
        with patch.object(check.ssl, "HAS_TLSv1_3", False):
            with self.assertRaises(check.CheckError):
                check.environment_check()

    def test_environment_failure_not_skipped(self):
        for error in (OSError(), subprocess.TimeoutExpired("openssl", 10)):
            with self.subTest(error=type(error).__name__), \
                 patch.object(check.shutil, "which", return_value="openssl"), \
                 patch.object(check.subprocess, "run", side_effect=error):
                with self.assertRaises(check.CheckError):
                    check.environment_check()

    def invoke(self, *, changed=False, skipped=False, success=True, count=1,
               loader_errors=False, expected_failure=False):
        result = Mock(testsRun=1, failures=[], errors=[], skipped=[("test", "why")] if skipped else [],
                      expectedFailures=[("test", "failure")] if expected_failure else [])
        result.wasSuccessful.return_value = success
        loader = Mock(errors=["error"] if loader_errors else [])
        loader.discover.return_value.countTestCases.return_value = count
        with patch.object(check, "source_check", side_effect=[{"snapshot": "a"}, {"snapshot": "b" if changed else "a"}]), \
             patch.object(check, "environment_check"), \
             patch.object(check.unittest, "TestLoader", return_value=loader), \
             patch.object(check.unittest, "TextTestRunner") as runner:
            runner.return_value.run.return_value = result
            return check.run_checks(Path("."))

    def test_success_and_failure_are_not_conflated(self):
        self.assertEqual(self.invoke()["result"], "passed")
        self.assertEqual(self.invoke(success=False)["result"], "failed")

    def test_skips_and_source_change_fail(self):
        self.assertEqual(self.invoke(skipped=True)["result"], "failed")
        self.assertFalse(self.invoke(changed=True)["source_unchanged"])
        self.assertEqual(self.invoke(changed=True)["result"], "failed")

    def test_discovery_errors_and_zero_tests_block(self):
        for arguments in ({"count": 0}, {"loader_errors": True}):
            with self.assertRaises(check.CheckError):
                self.invoke(**arguments)

    def test_expected_failures_do_not_hide_regressions(self):
        self.assertEqual(self.invoke(expected_failure=True)["result"], "failed")

    def test_main_exit_codes_and_directory_restored(self):
        before = Path.cwd()
        for result, code in (("passed", 0), ("failed", 1)):
            with patch.object(check, "run_checks", return_value={"result": result}), redirect_stdout(io.StringIO()):
                self.assertEqual(check.main([]), code)
            self.assertEqual(Path.cwd(), before)
        with patch.object(check, "run_checks", side_effect=KeyboardInterrupt), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(check.main([]), 1)
        self.assertEqual(json.loads(output.getvalue())["result"], "interrupted")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(check.main(["--skip-tls"]), 2)

    def test_blocked_environment_is_reported(self):
        with patch.object(check, "run_checks", side_effect=check.CheckError("loopback unavailable")), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(check.main([]), 1)
        self.assertEqual(json.loads(output.getvalue())["result"], "blocked")


if __name__ == "__main__":
    unittest.main()
