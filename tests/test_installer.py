from contextlib import contextmanager, redirect_stdout, redirect_stderr
import getpass
import io
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import warnings

from snellctl.__main__ import main
from snellctl.activation import Activation
from snellctl.artifacts import ArtifactError, CATALOG
from snellctl.deployment import NodeSpec
from snellctl.hostprep import Preparation, PreparationError, STATE, CREDENTIAL
from snellctl.installer import (Installation, Terminal, installation_status, render_status,
                               run_wizard, real_installation)
from snellctl.menu import run_menu
from test_hostprep import DOMAIN, TOKEN
from test_publish import PublicHost, UFW_UNCHANGED


ANSWERS = [DOMAIN, "", "", "", "54321", "y", "y", "y", "y", "y", "y", "y"]


class Console:
    def __init__(self, answers=None):
        self.answers = iter(ANSWERS if answers is None else answers)
        self.messages = []
        self.prompts = []
        self.secret = Mock(return_value=TOKEN)

    def interactive(self):
        return True

    def say(self, message):
        self.messages.append(message)

    def ask(self, prompt):
        self.prompts.append(prompt)
        value = next(self.answers)
        if isinstance(value, BaseException):
            raise value
        return value

    @property
    def text(self):
        return "\n".join(self.messages)


class WizardTests(unittest.TestCase):
    def setUp(self):
        self.engine = Mock()
        self.engine.downloads.return_value = {"snell": b"zip", "shadow-tls": b"binary"}
        self.ui = Console()
        self.closed = False

    @contextmanager
    def factory(self):
        try:
            yield self.engine
        finally:
            self.closed = True

    def run_wizard(self):
        return run_wizard(factory=self.factory, terminal=self.ui)

    def test_full_sequence_and_separate_explicit_consents(self):
        self.assertEqual(self.run_wizard(), 0)
        self.assertTrue(self.closed)
        names = [call[0] for call in self.engine.mock_calls]
        self.assertEqual(names, ["preflight", "downloads", "prep.initialize", "prep.packages",
                                "prep.credential", "prep.certificate", "prep.certificate",
                                "local.activate", "local.test_renewal", "public.enable"])
        calls = self.engine.prep.certificate.call_args_list
        self.assertEqual(calls[0].kwargs, {"production": False, "agree_tos": True})
        self.assertEqual(calls[1].kwargs, {"production": True, "agree_tos": True, "confirm_issue": True})
        self.assertEqual(self.engine.public.enable.call_args.kwargs, dict(
            ssh_port=54321, confirm_public=True, confirm_renewal=True, confirm_ssh_reconnected=True))
        self.assertIn("尚需客户端", self.ui.text)
        self.assertNotIn(TOKEN, self.ui.text)

    def test_custom_ports_are_forwarded_not_historical_vps_defaults(self):
        self.ui = Console([DOMAIN, "24443", "32001", "32443", "52000", *ANSWERS[5:]])
        self.assertEqual(self.run_wizard(), 0)
        spec, ssh = self.engine.preflight.call_args.args
        self.assertEqual((spec.public_port, spec.snell_port, spec.tls_port, ssh), (24443, 32001, 32443, 52000))

    def test_noninteractive_has_no_factory_secret_or_host_calls(self):
        self.ui.interactive = lambda: False
        factory = Mock(side_effect=AssertionError("must not create host adapter"))
        self.assertEqual(run_wizard(factory=factory, terminal=self.ui), 2)
        factory.assert_not_called()
        self.ui.secret.assert_not_called()

    def test_all_three_streams_must_be_terminals(self):
        for index in range(3):
            streams = [Mock(), Mock(), Mock()]
            for i, stream in enumerate(streams):
                stream.isatty.return_value = i != index
            with patch("sys.stdin", streams[0]), patch("sys.stdout", streams[1]), patch("sys.stderr", streams[2]):
                self.assertFalse(Terminal().interactive())

    def test_blank_ssh_port_not_assumed_to_be_22(self):
        self.ui = Console([*ANSWERS[:4], ""])
        self.assertEqual(self.run_wizard(), 1)
        self.engine.preflight.assert_not_called()

    def test_conflicting_ssh_port_stops_before_host_checks(self):
        self.ui = Console([*ANSWERS[:4], "443"])
        self.assertEqual(self.run_wizard(), 1)
        self.engine.preflight.assert_not_called()

    def test_invalid_input_is_not_echoed_by_exception_handler(self):
        self.ui = Console(["DOMAIN-PRIVATE;COMMAND", "", "", ""])
        self.assertEqual(self.run_wizard(), 1)
        self.assertNotIn("DOMAIN-PRIVATE", self.ui.text)
        self.assertIn('"phase": "inputs"', self.ui.text)

    def test_every_confirmation_defaults_to_cancel(self):
        for index in range(5, len(ANSWERS)):
            with self.subTest(index=index):
                self.engine.reset_mock()
                answers = list(ANSWERS)
                answers[index] = ""
                self.ui = Console(answers)
                self.assertEqual(self.run_wizard(), 130)
                self.engine.public.enable.assert_not_called()
                if index <= 6:
                    self.engine.prep.initialize.assert_not_called()
                    self.ui.secret.assert_not_called()
                elif index == 7:
                    self.assertEqual(self.engine.prep.certificate.call_count, 1)
                if index >= 7:
                    self.assertIn("已进入系统写入阶段", self.ui.text)
                    self.assertNotIn("尚未执行本工具的系统配置写入", self.ui.text)

    def test_preflight_failure_cannot_download_or_prompt_for_token(self):
        self.engine.preflight.side_effect = PreparationError("RAW SECRET")
        self.assertEqual(self.run_wizard(), 1)
        self.engine.downloads.assert_not_called()
        self.ui.secret.assert_not_called()
        self.assertNotIn("RAW SECRET", self.ui.text)

    def test_download_failure_is_before_any_host_mutation(self):
        self.engine.downloads.side_effect = ArtifactError("RAW SECRET")
        self.assertEqual(self.run_wizard(), 1)
        self.engine.prep.initialize.assert_not_called()
        self.ui.secret.assert_not_called()
        self.assertIn('"host_changes_attempted": false', self.ui.text)

    def test_each_mutating_failure_has_fixed_diagnostics_and_stops(self):
        for method, phase in (("initialize", "initialize"), ("packages", "packages"),
                              ("credential", "credential"), ("certificate", "dns-test")):
            with self.subTest(method=method):
                self.setUp()
                getattr(self.engine.prep, method).side_effect = RuntimeError(TOKEN + " RAW\x1b[31m")
                self.assertEqual(self.run_wizard(), 1)
                self.assertTrue(self.closed)
                self.engine.public.enable.assert_not_called()
                self.assertNotIn(TOKEN, self.ui.text)
                self.assertNotIn("RAW", self.ui.text)
                self.assertNotIn("Traceback", self.ui.text)
                self.assertIn(f'"phase": "{phase}"', self.ui.text)
                self.assertIn('"host_changes_attempted": true', self.ui.text)

    def test_later_failures_never_claim_service_stopped_or_changes_undone(self):
        for object_name, method, phase in (("local", "activate", "activation"),
                                          ("local", "test_renewal", "renewal-test"),
                                          ("public", "enable", "public")):
            with self.subTest(phase=phase):
                self.setUp()
                getattr(getattr(self.engine, object_name), method).side_effect = RuntimeError(TOKEN)
                self.assertEqual(self.run_wizard(), 1)
                self.assertIn(f'"phase": "{phase}"', self.ui.text)
                self.assertNotIn("已停止全部服务", self.ui.text)
                self.assertNotIn("已回滚", self.ui.text)
                self.assertNotIn(TOKEN, self.ui.text)

    def test_ctrl_c_during_secret_is_cancelled_without_requesting_a_certificate(self):
        self.ui.secret.side_effect = KeyboardInterrupt
        self.assertEqual(self.run_wizard(), 130)
        self.engine.prep.credential.assert_not_called()
        self.engine.prep.certificate.assert_not_called()
        self.assertIn('"phase": "credential"', self.ui.text)

    def test_eof_before_write_does_not_claim_possible_mutations(self):
        self.ui = Console([EOFError()])
        self.assertEqual(self.run_wizard(), 130)
        self.assertIn('"host_changes_attempted": false', self.ui.text)

    def test_platform_error_not_echoed_or_followed_by_inputs(self):
        factory = Mock(side_effect=RuntimeError("PRIVATE environment"))
        self.assertEqual(run_wizard(factory=factory, terminal=self.ui), 1)
        self.assertNotIn("PRIVATE", self.ui.text)
        self.assertIn('"phase": "platform"', self.ui.text)

    def test_getpass_warning_is_error_before_plaintext_fallback(self):
        visible_fallback = Mock()
        def unsafe_getpass(_prompt):
            warnings.warn("could echo", getpass.GetPassWarning)
            visible_fallback()
            return TOKEN
        with patch("snellctl.installer.getpass.getpass", side_effect=unsafe_getpass):
            with self.assertRaises(getpass.GetPassWarning):
                Terminal().secret()
        visible_fallback.assert_not_called()

    def test_secret_format_error_never_contains_input(self):
        for value in ("", " bad token ", "X" * 257, TOKEN + "\n"):
            with patch("snellctl.installer.getpass.getpass", return_value=value):
                with self.assertRaises(PreparationError) as raised:
                    Terminal().secret()
                self.assertNotIn(value or "EMPTY-PLACEHOLDER", str(raised.exception))

    def test_real_terminal_hides_token_and_restores_echo(self):
        import termios
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        original = termios.tcgetattr(slave)
        code = ("from snellctl.installer import Terminal; "
                "value = Terminal().secret(); "
                "print('INPUT_OK' if len(value) == 32 else 'INPUT_BAD', flush=True)")
        transcript = bytearray()
        with subprocess.Popen([sys.executable, "-c", code], stdin=slave, stdout=slave, stderr=slave,
                              cwd=Path(__file__).resolve().parents[1], start_new_session=True) as child:
            try:
                deadline = time.monotonic() + 5
                while "回车确认）：".encode() not in transcript:
                    if time.monotonic() >= deadline:
                        self.fail("hidden-input prompt timed out")
                    if select.select([master], [], [], 0.05)[0]:
                        transcript.extend(os.read(master, 4096))
                token = b"T" * 32
                os.write(master, token + b"\n")
                child.wait(timeout=5)
                while select.select([master], [], [], 0)[0]:
                    transcript.extend(os.read(master, 4096))
                self.assertEqual(child.returncode, 0)
                self.assertIn(b"INPUT_OK", transcript)
                self.assertNotIn(token, transcript)
                self.assertEqual(termios.tcgetattr(slave), original)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_real_factory_refuses_this_mac_without_opening_host_files(self):
        with patch("snellctl.hostcommands.platform.system", return_value="Darwin"), \
             patch("snellctl.installer.Preparation", side_effect=AssertionError("host files")):
            with self.assertRaises(PreparationError), real_installation():
                self.fail("must not yield")


class InstallerIntegrationTests(unittest.TestCase):
    """Real controllers and files; system commands, downloads and TLS are simulated."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.host = PublicHost(self.root)
        self.prep = Preparation(self.root, self.host)
        self.addCleanup(self.prep.files.close)
        self.probe = Mock(return_value=True)
        self.local = Activation(self.prep, self.probe, readiness_timeout=0)
        self.check = Mock(return_value={"limited_checks_passed": True})
        self.downloader = Mock(return_value=b"download fixture")
        self.engine = Installation(self.prep, self.local, preflight_check=self.check, downloader=self.downloader)

    @contextmanager
    def factory(self):
        yield self.engine

    def run_wizard(self, ui):
        with patch("snellctl.installer.verify", return_value=b"BINARY"), \
             patch("snellctl.activation.verify", side_effect=lambda a, data: b"BINARY-" + a.name.encode()):
            return run_wizard(factory=self.factory, terminal=ui)

    def test_complete_workflow_from_empty_state_with_real_file_guards(self):
        old = {p: self.host.path(p).read_bytes() for p in UFW_UNCHANGED}
        ui = Console()
        self.assertEqual(self.run_wizard(ui), 0, ui.text)
        self.assertEqual(old, {p: self.host.path(p).read_bytes() for p in UFW_UNCHANGED})
        self.assertTrue(self.host.path(STATE + "/public-ready.json").exists())
        self.assertEqual(self.host.path(CREDENTIAL).stat().st_mode & 0o777, 0o600)
        self.assertIn("certbot.timer", self.host.enabled)
        self.assertTrue(self.probe.called)
        report = installation_status(root=self.root)
        self.assertEqual(report["phases"]["public"], "completion-recorded")
        self.assertEqual(report["current_service_health"], "not-checked")
        self.assertNotIn(TOKEN, json.dumps(report) + ui.text)
        self.assertNotIn(DOMAIN, json.dumps(report))
        self.assertNotIn(TOKEN, str([c.argv for c in self.host.calls]))

    def test_cancel_after_packages_then_rerun_stops_before_download_or_certificate(self):
        ui = Console()
        ui.secret.side_effect = EOFError
        self.assertEqual(self.run_wizard(ui), 130)
        self.assertEqual(installation_status(root=self.root)["phases"]["packages"], "completion-recorded")
        before = len(self.host.calls)
        self.downloader.reset_mock()
        again = Console()
        self.assertEqual(self.run_wizard(again), 1)
        self.assertIn('"phase": "preflight"', again.text)
        self.downloader.assert_not_called()
        again.secret.assert_not_called()
        self.assertEqual(len(self.host.calls), before)

    def test_early_firewall_failure_precedes_download_packages_and_state(self):
        self.host.rules.append("ufw allow 443/tcp")
        self.assertEqual(self.run_wizard(Console()), 1)
        self.downloader.assert_not_called()
        self.assertFalse(self.host.path(STATE).exists())
        self.assertFalse(any(c.argv[0] == "apt-get" for c in self.host.calls))

    def test_preflight_false_or_missing_cannot_be_treated_as_ready(self):
        for report in ({}, {"limited_checks_passed": False}, {"limited_checks_passed": "true"}):
            self.check.return_value = report
            with self.assertRaises(PreparationError):
                self.engine.preflight(NodeSpec(DOMAIN), 54321)
        self.assertFalse(self.host.path(STATE).exists())

    def test_bad_download_really_checks_pinned_digest(self):
        with self.assertRaises(ArtifactError):
            self.engine.downloads()
        self.downloader.assert_called_once_with(CATALOG[0])
        self.assertFalse(self.host.path(STATE).exists())

    def test_status_absent_creates_no_files(self):
        before = sorted(p.relative_to(self.root) for p in self.root.rglob("*"))
        report = installation_status(root=self.root)
        self.assertEqual(report["state"], "absent")
        self.assertEqual(before, sorted(p.relative_to(self.root) for p in self.root.rglob("*")))
        self.assertIn("不代表", render_status(report))

    def test_status_corrupt_or_locked_not_echoed_or_repaired(self):
        self.prep.initialize()
        self.prep._record("public-ready", {"private": TOKEN})
        report = installation_status(root=self.root)
        self.assertNotIn(TOKEN, json.dumps(report))
        path = self.host.path(STATE + "/public-ready.json")
        path.write_bytes(TOKEN.encode())
        self.assertEqual(installation_status(root=self.root)["state"], "unreadable-or-busy")
        self.assertEqual(path.read_bytes(), TOKEN.encode())
        with self.prep._lock():
            self.assertEqual(installation_status(root=self.root)["state"], "unreadable-or-busy")


class InstallCliTests(unittest.TestCase):
    def test_install_requires_explicit_experimental_flag(self):
        with patch("snellctl.installer.run_wizard") as wizard, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["install"]), 2)
        wizard.assert_not_called()

    def test_opt_in_dispatch_and_return_status(self):
        with patch("snellctl.installer.run_wizard", return_value=130) as wizard:
            self.assertEqual(main(["install", "--experimental"]), 130)
        wizard.assert_called_once_with()

    def test_noninteractive_real_cli_stops_before_platform_or_files(self):
        with patch("sys.stdin.isatty", return_value=False), redirect_stdout(io.StringIO()), \
             patch("snellctl.installer.DebianCommands", side_effect=AssertionError("adapter")):
            self.assertEqual(main(["install", "--experimental"]), 2)

    def test_no_token_argument_or_automatic_yes_interface(self):
        for option in ("--token", "--yes", "--root"):
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                main(["install", "--experimental", option])
            self.assertEqual(raised.exception.code, 2)

    def test_argument_errors_never_echo_accidentally_pasted_credentials(self):
        for args in (["install", "--experimental", "--token", TOKEN],
                     ["install", "--experimental", TOKEN],
                     ["plan", "--domain", DOMAIN, "--public-port", TOKEN]):
            with redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit) as raised:
                main(args)
            self.assertEqual(raised.exception.code, 2)
            self.assertNotIn(TOKEN, output.getvalue())
            self.assertIn("原始输入未显示", output.getvalue())

    def test_status_json_dispatch_does_not_make_real_runner(self):
        report = {"format": 1, "state": "absent", "current_service_health": "not-checked"}
        with patch("snellctl.installer.installation_status", return_value=report), \
             patch("snellctl.installer.DebianCommands", side_effect=AssertionError("adapter")), \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["install-status", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue()), report)

    def test_unknown_status_returns_failure(self):
        with patch("snellctl.installer.installation_status", return_value={"state": "unreadable-or-busy"}), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(main(["install-status"]), 1)

    def test_install_menu_hidden_without_opt_in(self):
        with patch("builtins.input", side_effect=["3", "0"]), redirect_stdout(io.StringIO()) as output, \
             patch("snellctl.installer.run_wizard") as wizard:
            self.assertEqual(run_menu(), 0)
        wizard.assert_not_called()
        self.assertNotIn("3. 实验版", output.getvalue())

    def test_opt_in_menu_never_claims_no_changes_after_install_attempt(self):
        with patch("builtins.input", side_effect=["3", EOFError]), redirect_stdout(io.StringIO()) as output, \
             patch("snellctl.installer.run_wizard", return_value=1) as wizard:
            self.assertEqual(run_menu(experimental=True), 130)
        wizard.assert_called_once_with()
        self.assertNotIn("未执行部署或配置变更", output.getvalue())
        self.assertIn("可能已改变系统", output.getvalue())

    def test_cli_experimental_menu_wiring(self):
        with patch("sys.stdin.isatty", return_value=True), patch("snellctl.__main__.run_menu", return_value=0) as menu:
            self.assertEqual(main(["menu", "--experimental"]), 0)
        menu.assert_called_once_with(experimental=True)
