from dataclasses import replace
import os
import sys
import unittest
from unittest.mock import patch

from snellctl.hostcommands import DebianCommands
from snellctl.hostprep import Command, PreparationError


class CommandRunnerTests(unittest.TestCase):
    def test_current_mac_cannot_construct_live_runner(self):
        with patch("snellctl.hostcommands.platform.system", return_value="Darwin"):
            with self.assertRaises(PreparationError):
                DebianCommands()

    def test_nonroot_linux_cannot_construct_live_runner(self):
        with patch("snellctl.hostcommands.platform.system", return_value="Linux"), \
             patch("snellctl.hostcommands.platform.machine", return_value="x86_64"), \
             patch("snellctl.hostcommands.os.geteuid", return_value=1000):
            with self.assertRaises(PreparationError):
                DebianCommands()

    def test_wrong_debian_version_cannot_construct_runner(self):
        with patch("snellctl.hostcommands.platform.system", return_value="Linux"), \
             patch("snellctl.hostcommands.platform.machine", return_value="x86_64"), \
             patch("snellctl.hostcommands.os.geteuid", return_value=0), \
             patch("snellctl.hostcommands.Path.read_text", return_value='ID=debian\nVERSION_ID="12"\n'):
            with self.assertRaises(PreparationError):
                DebianCommands()

    def test_allowed_environment_without_systemd_stops(self):
        with patch("snellctl.hostcommands.platform.system", return_value="Linux"), \
             patch("snellctl.hostcommands.platform.machine", return_value="x86_64"), \
             patch("snellctl.hostcommands.os.geteuid", return_value=0), \
             patch("snellctl.hostcommands.Path.read_text", return_value='ID=debian\nVERSION_ID="13"\n'), \
             patch("snellctl.hostcommands.Path.is_dir", return_value=False):
            with self.assertRaises(PreparationError):
                DebianCommands()

    def runner(self):
        # Test the adapter against a harmless Python child, never Linux tools.
        return object.__new__(DebianCommands)

    def run_python(self, code, timeout=5):
        with patch("snellctl.hostcommands.PROGRAMS", {"openssl": sys.executable}):
            return self.runner()(Command(("openssl", "-c", code), timeout))

    def test_real_child_no_shell_and_no_inherited_token(self):
        with patch.dict(os.environ, {"CF_Token": "TEST-SECRET", "OPENSSL_CONF": "/unwanted"}):
            reply = self.run_python("import os; print(os.environ.get('CF_Token', 'absent')); print(os.environ.get('OPENSSL_CONF', 'absent')); print(os.getcwd())")
        self.assertEqual(reply.code, 0)
        self.assertFalse(reply.uncertain)
        self.assertEqual(reply.output, "absent\nabsent\n/\n")

    def test_real_child_stderr_not_exposed(self):
        reply = self.run_python("import sys; print('PRIVATE', file=sys.stderr); sys.exit(12)")
        self.assertEqual(reply.code, 12)
        self.assertEqual(reply.output, "")
        self.assertNotIn("PRIVATE", repr(reply))

    def test_only_allowed_checks_capture_stderr_internally(self):
        command = Command(("certbot", "renew", "--dry-run"), capture_stderr=True)
        # Replace only the executable and arguments after validation via a tiny child.
        import subprocess
        real_popen = subprocess.Popen
        def child(args, **kwargs):
            return real_popen([sys.executable, "-c", "import sys; print('hook marker', file=sys.stderr)"], **kwargs)
        with patch("snellctl.hostcommands.subprocess.Popen", side_effect=child):
            result = self.runner()(command)
        self.assertEqual(result.output, "hook marker\n")
        self.assertNotIn("hook marker", repr(result))
        with self.assertRaises(PreparationError):
            self.runner()(Command(("openssl", "version"), capture_stderr=True))

    def test_binary_direct_execution_only_allows_version(self):
        from snellctl.deployment import SHADOWTLS_BINARY
        with self.assertRaises(PreparationError):
            self.runner()(Command((SHADOWTLS_BINARY, "server")))

    def test_firewall_backend_is_read_only(self):
        for program in ("iptables", "ip6tables"):
            for args in (("-F",), ("-P", "INPUT", "ACCEPT"), ("-A", "INPUT", "-j", "ACCEPT"), ("-S", "OUTPUT")):
                with self.subTest(program=program, args=args), self.assertRaises(PreparationError):
                    self.runner()(Command((program, *args)))

    def test_real_timeout_returns_uncertain_after_reaping_process(self):
        reply = self.run_python("import time; time.sleep(60)", timeout=0.1)
        self.assertTrue(reply.uncertain)
        self.assertEqual(reply.code, -1)

    def test_output_limit_is_not_reported_as_success(self):
        reply = self.run_python("print('x' * (1024 * 1024 + 1))")
        self.assertTrue(reply.uncertain)
        self.assertEqual(reply.output, "")

    def test_missing_executable_is_uncertain_not_success(self):
        with patch("snellctl.hostcommands.PROGRAMS", {"openssl": "/nonexistent/snellctl-test-program"}):
            result = self.runner()(Command(("openssl",)))
        self.assertTrue(result.uncertain)

    def test_no_arbitrary_program_or_environment(self):
        for command in (Command(("sh", "-c", "exit 0")), Command(()),
                        replace(Command(("openssl",)), env=(("PATH", "/tmp"),)),
                        Command(("openssl",), timeout=0)):
            with self.subTest(command=command), self.assertRaises(PreparationError):
                self.runner()(command)

    def test_command_error_does_not_echo_input(self):
        with self.assertRaises(PreparationError) as raised:
            self.runner()(Command(("PRIVATE-INVALID-PROGRAM",)))
        self.assertNotIn("PRIVATE", str(raised.exception))
