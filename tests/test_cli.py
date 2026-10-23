from contextlib import redirect_stdout, redirect_stderr
import io
import json
import unittest
from unittest.mock import patch

from snellctl.__main__ import main
from snellctl.menu import run_menu


class CliTests(unittest.TestCase):
    def test_plan_json_never_runs_machine_checks_or_generates_keys(self):
        output = io.StringIO()
        with redirect_stdout(output), \
             patch("snellctl.__main__.collect", side_effect=AssertionError("machine check")), \
             patch("snellctl.deployment.secrets.token_hex", side_effect=AssertionError("secret generation")):
            self.assertEqual(main(["plan", "--domain", "node.example.net", "--public-port", "24443", "--json"]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["listeners"]["shadowtls_tcp"], "0.0.0.0:24443")
        self.assertFalse(report["environment_checked"])

    def test_invalid_plan_returns_error_without_raw_input(self):
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            status = main(["plan", "--domain", "INJECTED;COMMAND"])
        self.assertEqual(status, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("INJECTED", error.getvalue())

    def test_menu_refuses_noninteractive_stdin(self):
        for args in ([], ["menu"]):
            with self.subTest(args=args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                 patch("sys.stdin.isatty", return_value=False), \
                 patch("snellctl.__main__.run_menu", side_effect=AssertionError("unexpected menu")):
                self.assertEqual(main(args), 2)

    def test_default_command_opens_menu_in_terminal(self):
        with patch("sys.stdin.isatty", return_value=True), patch("snellctl.__main__.run_menu", return_value=0) as menu:
            self.assertEqual(main([]), 0)
        menu.assert_called_once_with()

    def test_doctor_still_reports_unsupported_platform(self):
        from snellctl.doctor import collect
        report = collect(system="Darwin", machine="arm64")
        output = io.StringIO()
        with patch("snellctl.__main__.collect", return_value=report), redirect_stdout(output):
            self.assertEqual(main(["doctor", "--json"]), 2)
        self.assertFalse(json.loads(output.getvalue())["platform_supported"])


class MenuTests(unittest.TestCase):
    def test_preview_with_custom_ports_and_exit(self):
        answers = ["2", "second", "node.example.net", "24443", "32001", "32443", "0"]
        output = io.StringIO()
        with patch("builtins.input", side_effect=answers), redirect_stdout(output), \
             patch("snellctl.menu.collect", side_effect=AssertionError("machine check")), \
             patch("snellctl.deployment.secrets.token_hex", side_effect=AssertionError("secret generation")):
            self.assertEqual(run_menu(), 0)
        for text in ("second", "0.0.0.0:24443", "127.0.0.1:32001", "127.0.0.1:32443", "未执行"):
            self.assertIn(text, output.getvalue())

    def test_invalid_port_returns_to_menu_without_traceback(self):
        with patch("builtins.input", side_effect=["2", "", "node.example.net", "bad-port", "0"]), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(run_menu(), 0)
        self.assertNotIn("Traceback", output.getvalue())
        self.assertNotIn("bad-port", output.getvalue())

    def test_unknown_choice_and_keyboard_interrupt_are_safe(self):
        with patch("builtins.input", side_effect=["99", KeyboardInterrupt]), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(run_menu(), 130)
        self.assertIn("请选择", output.getvalue())
        self.assertIn("未执行部署", output.getvalue())

    def test_eof_exits_without_changes(self):
        with patch("builtins.input", side_effect=EOFError), redirect_stdout(io.StringIO()):
            self.assertEqual(run_menu(), 130)

    def test_doctor_choice_renders_existing_diagnostics(self):
        from snellctl.doctor import collect
        report = collect(system="Darwin", machine="arm64")
        with patch("builtins.input", side_effect=["1", "0"]), \
             patch("snellctl.menu.collect", return_value=report), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(run_menu(), 0)
        self.assertIn("只读环境检查", output.getvalue())
