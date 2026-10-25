from contextlib import contextmanager, redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.activation import Activation
from snellctl.deployment import NodeSpec
from snellctl.hostprep import CREDENTIAL, POLICY, Preparation, Reply, STATE
from snellctl.installer import (Installation, PENDING_PUBLIC_PHASES, render_status,
                               run_resume, run_wizard)
from snellctl.menu import run_menu
from test_hostprep import DOMAIN, TOKEN
from test_installer import ANSWERS, Console
from test_publish import PublicHost, UFW_UNCHANGED


RESUME_ANSWERS = [DOMAIN, "443", "31001", "31443", "54321", "y", "y", "y"]


class ResumeWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.engine = Mock()
        self.engine.prep.status.return_value = {"phases": dict(PENDING_PUBLIC_PHASES)}
        self.ui = Console(RESUME_ANSWERS)

    @contextmanager
    def factory(self):
        yield self.engine

    def run_resume(self):
        return run_resume(factory=self.factory, terminal=self.ui)

    def test_sequence_uses_only_status_live_check_and_gated_publication(self):
        self.assertEqual(self.run_resume(), 0)
        self.assertEqual([c[0] for c in self.engine.mock_calls],
                         ["prep.status", "public.check_pending", "public.enable"])
        self.assertEqual(self.engine.public.enable.call_args.kwargs,
                         dict(ssh_port=54321, confirm_public=True, confirm_renewal=True,
                              confirm_ssh_reconnected=True, require_pending=True))
        self.ui.secret.assert_not_called()
        self.assertNotIn(TOKEN, self.ui.text)

    def test_custom_domain_ports_are_forwarded_without_historical_defaults(self):
        self.ui = Console(["second.example.net", "24443", "32001", "32443", "52000", *RESUME_ANSWERS[5:]])
        self.assertEqual(self.run_resume(), 0)
        call = self.engine.public.check_pending.call_args
        spec = call.args[0]
        self.assertEqual((spec.domain, spec.public_port, spec.snell_port, spec.tls_port, call.kwargs["ssh_port"]),
                         ("second.example.net", 24443, 32001, 32443, 52000))
        self.assertEqual(self.engine.public.enable.call_args.args, (spec,))

    def test_each_port_is_required_and_not_assumed(self):
        for index in range(1, 5):
            with self.subTest(index=index):
                answers = list(RESUME_ANSWERS)
                answers[index] = ""
                self.ui = Console(answers)
                self.assertEqual(self.run_resume(), 1)
        self.engine.public.check_pending.assert_not_called()
        self.engine.public.enable.assert_not_called()

    def test_invalid_domain_and_conflicting_ports_never_reach_live_check(self):
        for index, value in ((0, TOKEN + ";RAW"), (1, "65536"), (2, "443"), (4, "31443")):
            answers = list(RESUME_ANSWERS)
            answers[index] = value
            self.ui = Console(answers)
            self.assertEqual(self.run_resume(), 1)
            self.assertNotIn(TOKEN, self.ui.text)
        self.engine.public.check_pending.assert_not_called()
        self.engine.public.enable.assert_not_called()

    def test_noninteractive_never_constructs_host_adapter(self):
        self.ui.interactive = lambda: False
        factory = Mock(side_effect=AssertionError("host adapter"))
        self.assertEqual(run_resume(factory=factory, terminal=self.ui), 2)
        factory.assert_not_called()

    def test_no_other_stage_is_offered_as_resumable(self):
        for phase in PENDING_PUBLIC_PHASES:
            for value in ("completion-recorded", "not-started", "needs-inspection"):
                if value == PENDING_PUBLIC_PHASES[phase]:
                    continue
                self.engine.prep.status.return_value = {"phases": {**PENDING_PUBLIC_PHASES, phase: value}}
                self.ui = Console([])
                self.assertEqual(self.run_resume(), 1)
        self.engine.public.check_pending.assert_not_called()
        self.engine.public.enable.assert_not_called()

    def test_all_confirmations_default_to_cancel(self):
        for index in range(5, 8):
            answers = list(RESUME_ANSWERS)
            answers[index] = ""
            self.ui = Console(answers)
            self.assertEqual(self.run_resume(), 130)
            self.assertIn('"host_changes_attempted": false', self.ui.text)
        self.engine.public.enable.assert_not_called()

    def test_eof_and_ctrl_c_at_each_prompt_never_publish(self):
        for error in (EOFError, KeyboardInterrupt):
            for index in range(len(RESUME_ANSWERS)):
                answers = list(RESUME_ANSWERS)
                answers[index] = error()
                self.ui = Console(answers)
                self.assertEqual(self.run_resume(), 130)
        self.engine.public.enable.assert_not_called()

    def test_readonly_failure_is_redacted_and_precedes_consent(self):
        self.engine.public.check_pending.side_effect = RuntimeError(TOKEN + " RAW")
        self.ui = Console(RESUME_ANSWERS[:5])
        self.assertEqual(self.run_resume(), 1)
        self.assertIn('"phase": "resume-check"', self.ui.text)
        self.assertIn('"host_changes_attempted": false', self.ui.text)
        self.assertNotIn(TOKEN, self.ui.text)
        self.assertNotIn("RAW", self.ui.text)
        self.engine.public.enable.assert_not_called()

    def test_mutating_failure_never_claims_rollback_or_no_changes(self):
        self.engine.public.enable.side_effect = RuntimeError(TOKEN)
        self.assertEqual(self.run_resume(), 1)
        self.assertIn('"host_changes_attempted": true', self.ui.text)
        self.assertNotIn("尚未执行", self.ui.text)
        self.assertNotIn("已回滚", self.ui.text)
        self.assertNotIn(TOKEN, self.ui.text)

    def test_status_only_suggests_checking_at_the_exact_checkpoint(self):
        report = {"state": "records-found", "phases": dict(PENDING_PUBLIC_PHASES)}
        self.assertIn("resume --experimental", render_status(report))
        report["phases"]["public"] = "needs-inspection"
        self.assertNotIn("resume --experimental", render_status(report))


class ResumeIntegrationTests(unittest.TestCase):
    """Real checkpoint files/controllers; all system commands and TLS are simulated."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.host = PublicHost(self.root)
        self.prep = Preparation(self.root, self.host)
        self.addCleanup(self.prep.files.close)
        self.probe = Mock(return_value=True)
        self.local = Activation(self.prep, self.probe, readiness_timeout=0)
        self.engine = Installation(self.prep, self.local, preflight_check=Mock(return_value={"limited_checks_passed": True}),
                                   downloader=Mock(return_value=b"fixture"))
        with patch("snellctl.installer.verify", return_value=b"fixture"), \
                patch("snellctl.activation.verify", side_effect=lambda a, b: b"fixture-" + a.name.encode()):
            self.assertEqual(run_wizard(factory=self.factory, terminal=Console([*ANSWERS[:10], EOFError()])), 130)
        self.assertEqual(self.prep.status()["phases"], PENDING_PUBLIC_PHASES)
        self.spec = NodeSpec(DOMAIN)
        self.host.calls.clear()
        self.probe.reset_mock()
        self.engine.downloader.reset_mock()

    @contextmanager
    def factory(self):
        yield self.engine

    def resume(self, ui=None):
        self.ui = Console(RESUME_ANSWERS) if ui is None else ui
        return run_resume(factory=self.factory, terminal=self.ui)

    def snapshot(self):
        result = {}
        for path in self.root.rglob("*"):
            info = path.lstat()
            content = str(path.readlink()) if path.is_symlink() else path.read_bytes() if path.is_file() else None
            result[str(path.relative_to(self.root))] = (info.st_mode, info.st_ino, content)
        return result

    def assert_before_intent(self):
        self.assertFalse(self.prep._exists("public-intent"))
        self.assertFalse(self.prep._exists("renewal-enable-intent"))
        self.assertFalse(any(c.argv[:2] == ("ufw", "allow") for c in self.host.calls))

    def test_success_never_reinstalls_reissues_rotates_or_changes_ssh_ipv6(self):
        paths = (CREDENTIAL, self.spec.node_dir + "/snell.conf", *UFW_UNCHANGED)
        before = {p: self.host.path(p).read_bytes() for p in paths}
        old = json.loads(self.host.path(self.spec.node_dir + "/shadowtls.json").read_bytes())
        self.assertEqual(self.resume(), 0, self.ui.text)
        self.assertEqual(before, {p: self.host.path(p).read_bytes() for p in paths})
        old["server"]["listen"] = "0.0.0.0:443"
        self.assertEqual(old, json.loads(self.host.path(self.spec.node_dir + "/shadowtls.json").read_bytes()))
        self.assertEqual(self.prep.status()["phases"]["public"], "completion-recorded")
        self.assertGreaterEqual(self.probe.call_count, 4)
        self.engine.downloader.assert_not_called()
        self.ui.secret.assert_not_called()
        self.assertFalse(any(c.argv[0] in {"apt-get", "certbot"} for c in self.host.calls))
        self.assertIn(("systemctl", "start", "certbot.service"), [c.argv for c in self.host.calls])
        self.assertNotIn(TOKEN, self.ui.text)
        self.assertNotIn(old["server"]["password"], self.ui.text)

    def test_pending_check_is_readonly_and_does_not_contact_ca(self):
        before = self.snapshot()
        self.assertEqual(self.engine.public.check_pending(self.spec, ssh_port=54321), "pending-publication-verified")
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.probe.call_count, 2)
        self.assertFalse(any(c.argv[0] in {"apt-get", "certbot"} or c.argv[:2] == ("systemctl", "start")
                             for c in self.host.calls))

    def test_cancel_after_readonly_checks_changes_no_files(self):
        before = self.snapshot()
        self.assertEqual(self.resume(Console([*RESUME_ANSWERS[:5], ""])), 130)
        self.assertEqual(before, self.snapshot())
        self.assert_before_intent()

    def test_completed_deployment_is_refused_before_any_command_or_input(self):
        self.assertEqual(self.resume(), 0)
        self.host.calls.clear()
        before = self.snapshot()
        self.assertEqual(self.resume(Console([])), 1)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.host.calls, [])

    def test_partial_public_or_renewal_records_are_never_retried(self):
        for name in ("public-intent", "public-files", "public-firewall-added", "renewal-enable-intent", "renewal-enable-ready"):
            self.prep._record(name, {})
            before = self.snapshot()
            self.assertEqual(self.resume(), 1)
            self.assertEqual(before, self.snapshot())
            self.assertEqual(self.host.calls, [])
            self.host.path(STATE + "/" + name + ".json").unlink()

    def test_missing_earlier_records_never_create_new_state(self):
        self.host.path(STATE + "/dns-test-ready.json").unlink()
        before = self.snapshot()
        self.assertEqual(self.resume(Console([])), 1)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.host.calls, [])

    def test_corrupt_record_never_echoed_or_repaired(self):
        self.host.write(STATE + "/activation-ready.json", TOKEN.encode())
        before = self.snapshot()
        self.assertEqual(self.resume(Console([])), 1)
        self.assertEqual(before, self.snapshot())
        self.assertNotIn(TOKEN, self.ui.text)

    def test_wrong_parameters_stop_before_intent_or_writes(self):
        for index, value in ((0, "wrong.example.net"), (1, "24443"), (2, "32001"), (3, "32443"), (4, "22")):
            answers = list(RESUME_ANSWERS)
            answers[index] = value
            before = self.snapshot()
            self.assertEqual(self.resume(Console(answers)), 1)
            self.assertEqual(before, self.snapshot())
            self.assert_before_intent()

    def test_changed_package_version_stops_before_intent(self):
        self.host.versions["nginx"] = "changed-version"
        self.assertEqual(self.resume(), 1)
        self.assert_before_intent()

    def test_tls_failure_does_not_restart_services_or_modify_files(self):
        self.probe.return_value = False
        before = self.snapshot()
        self.assertEqual(self.resume(), 1)
        self.assertEqual(before, self.snapshot())
        self.assert_before_intent()

    def test_stopped_service_is_not_automatically_started(self):
        self.host.active.remove(self.spec.shadowtls_service)
        self.assertEqual(self.resume(), 1)
        self.assertFalse(any(c.argv[:2] == ("systemctl", "start") for c in self.host.calls))
        self.assert_before_intent()

    def test_changed_startup_guard_is_preserved(self):
        self.host.write(POLICY, b"foreign policy\n", 0o755)
        before = self.snapshot()
        self.assertEqual(self.resume(), 1)
        self.assertEqual(before, self.snapshot())
        self.assert_before_intent()

    def test_unknown_firewall_rule_is_not_rewritten(self):
        self.host.rules.append("ufw allow Nginx")
        self.assertEqual(self.resume(), 1)
        self.assertEqual(self.host.rules[-1], "ufw allow Nginx")
        self.assert_before_intent()

    def test_held_lock_is_not_deleted(self):
        before = self.snapshot()
        with self.prep._lock():
            self.assertEqual(self.resume(Console([])), 1)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.host.calls, [])

    def on_last_confirmation(self, callback):
        ui = Console(RESUME_ANSWERS)
        ask = ui.ask
        def changed(prompt):
            if "确认开放？" in prompt:
                callback()
            return ask(prompt)
        ui.ask = changed
        return ui

    def test_config_is_rechecked_after_confirmations(self):
        ui = self.on_last_confirmation(lambda: self.host.write(self.spec.nginx_conf, b"foreign\n", 0o644))
        self.assertEqual(self.resume(ui), 1)
        self.assertEqual(self.host.path(self.spec.nginx_conf).read_bytes(), b"foreign\n")
        self.assert_before_intent()

    def test_intent_appearing_during_confirmation_blocks_publication(self):
        ui = self.on_last_confirmation(lambda: self.prep._record("public-intent", {"external": True}))
        self.assertEqual(self.resume(ui), 1)
        self.assertEqual(self.prep._read_record("public-intent"), {"external": True})
        self.assertFalse(self.prep._exists("renewal-enable-intent"))

    def test_other_session_finishing_during_confirmation_is_not_republished(self):
        def publish():
            self.engine.public.enable(self.spec, ssh_port=54321, confirm_public=True,
                                      confirm_renewal=True, confirm_ssh_reconnected=True)
            self.host.calls.clear()
        self.assertEqual(self.resume(self.on_last_confirmation(publish)), 1)
        self.assertEqual(self.host.calls, [])

    def test_post_write_failure_preserves_state_and_disallows_retry(self):
        self.host.local_override = lambda c: Reply(-1, uncertain=True) if c.argv[:2] == ("ufw", "allow") else None
        self.assertEqual(self.resume(), 1)
        self.assertTrue(self.prep._exists("public-intent"))
        self.assertTrue(self.prep._exists("renewal-enable-ready"))
        self.assertNotIn(self.spec.shadowtls_service, self.host.active)
        self.host.calls.clear()
        self.assertEqual(self.resume(Console([])), 1)
        self.assertEqual(self.host.calls, [])


class ResumeCliTests(unittest.TestCase):
    def test_explicit_experimental_required(self):
        with patch("snellctl.installer.run_resume") as resume, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["resume"]), 2)
        resume.assert_not_called()

    def test_opt_in_dispatch(self):
        with patch("snellctl.installer.run_resume", return_value=130) as resume:
            self.assertEqual(main(["resume", "--experimental"]), 130)
        resume.assert_called_once_with()

    def test_real_noninteractive_cli_stops_before_host_adapter(self):
        with patch("sys.stdin.isatty", return_value=False), redirect_stdout(io.StringIO()), \
                patch("snellctl.installer.DebianCommands", side_effect=AssertionError("adapter")):
            self.assertEqual(main(["resume", "--experimental"]), 2)

    def test_no_yes_force_secret_or_root_override_flags(self):
        for option in ("--yes", "--force", "--token", "--root", "--domain"):
            with redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit) as error:
                main(["resume", "--experimental", option, TOKEN])
            self.assertEqual(error.exception.code, 2)
            self.assertNotIn(TOKEN, output.getvalue())

    def test_menu_hidden_and_not_dispatchable_without_opt_in(self):
        with patch("builtins.input", side_effect=["7", "0"]), redirect_stdout(io.StringIO()) as output, \
                patch("snellctl.installer.run_resume") as resume:
            self.assertEqual(run_menu(), 0)
        resume.assert_not_called()
        self.assertNotIn("7. 中断", output.getvalue())

    def test_menu_dispatch_preserves_possible_changes_warning(self):
        with patch("builtins.input", side_effect=["7", EOFError()]), redirect_stdout(io.StringIO()) as output, \
                patch("snellctl.installer.run_resume", return_value=1) as resume:
            self.assertEqual(run_menu(experimental=True), 130)
        resume.assert_called_once_with()
        self.assertIn("7. 中断", output.getvalue())
        self.assertIn("可能已改变系统", output.getvalue())
        self.assertNotIn("未执行部署或配置变更", output.getvalue())


if __name__ == "__main__":
    unittest.main()
