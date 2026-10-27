from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import shutil
import stat
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.client import read_client, ClientError
from snellctl.hostprep import CREDENTIAL, HostFiles, PreparationError, Reply, STATE
from snellctl.installer import installation_status, render_status
from snellctl.menu import run_menu
from snellctl.retiredcleanup import CleanupPlan, INTENT, SUCCESS, RetiredCleanup, lineage_paths, run_retired_cleanup
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
import test_domainchange
import test_retiredplan


class CleanupHost(test_retiredplan.PlanHost):
    def _dispatch(self, command):
        if command.argv[:2] == ("certbot", "delete"):
            self.calls.append(command)
            domain = command.argv[command.argv.index("--cert-name") + 1]
            for path in lineage_paths(domain):
                target = self.path(path)
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            return Reply(0, "Deleted all files relating to certificate PRIVATE-DOMAIN.")
        return super()._dispatch(command)


class RetiredCleanupTests(unittest.TestCase):
    enrich_renewals = test_retiredplan.RetiredScopeTests.enrich_renewals

    def setUp(self):
        self.fixture = test_domainchange.DomainChangeTests(methodName="test_check_is_read_only_and_repr_is_redacted")
        self.addCleanup(self.fixture.doCleanups)
        with patch("test_domainchange.DomainHost", CleanupHost):
            self.fixture.setUp()
        self.fixture.assert_success(self.fixture.change())
        self.host, self.prep = self.fixture.host, self.fixture.prep
        self.enrich_renewals()
        self.engine = RetiredCleanup(self.fixture.tokens)
        self.host.calls.clear()

    def clean(self, plan=None, **kwargs):
        return self.engine.clean(plan or self.engine.check(DOMAIN), confirm_ownership=True, confirm_delete=True, **kwargs)

    def assert_success(self, report):
        self.assertEqual(report["result"], SUCCESS, report)
        for key in ("certificate_removed_verified", "credential_removed_verified", "renewal_restored_verified",
                    "preserved_scope_verified_before_enable", "report_saved"):
            self.assertTrue(report[key], report)
        self.assertFalse(report["historical_file_ownership_proven"])
        self.assertFalse(report["renewal_paused_verified_after"])
        self.assertFalse(self.prep._exists(INTENT))

    def assert_stopped(self, report, phase=None):
        self.assertEqual(report["result"], "stopped", report)
        self.assertFalse(report["renewal_restored_verified"])
        self.assertTrue(self.prep._exists(INTENT))
        if phase:
            self.assertEqual(report["failure_phase"], phase, report)
        with self.assertRaises(Exception):
            self.engine.check(DOMAIN)

    def test_check_read_only_and_plan_redacted(self):
        before = self.fixture.snapshot()
        plan = self.engine.check(DOMAIN)
        self.assertEqual(before, self.fixture.snapshot())
        for value in (DOMAIN, plan.revision, TOKEN):
            self.assertNotIn(value, repr(plan))
        self.assertFalse(any(c.argv[0] == "certbot" for c in self.host.calls))

    def test_success_exact_scope_preserves_node_accounts_history_and_firewall(self):
        self.host.write("/etc/letsencrypt/accounts/test/account/private_key.json", b"ACCOUNT_SECRET")
        self.host.write("/etc/letsencrypt/live/README", b"shared readme")
        before, client, rules = self.fixture.snapshot(), read_client(root=self.fixture.root), list(self.host.rules)
        self.assert_success(self.clean())
        after = self.fixture.snapshot()
        removed = {p for p in before if p not in after}
        allowed = tuple(p.lstrip("/") for p in lineage_paths(DOMAIN)) + (CREDENTIAL.lstrip("/"),)
        self.assertTrue(removed)
        self.assertTrue(all(any(p == a or p.startswith(a + "/") for a in allowed) for p in removed))
        self.assertTrue(all(before[p] == after[p] for p in before.keys() & after.keys()))
        self.assertEqual(client, read_client(root=self.fixture.root))
        self.assertEqual(rules, self.host.rules)
        self.assertIn("certbot.timer", self.host.enabled)
        self.assertIn("certbot.timer", self.host.active)
        self.fixture.tokens.check()
        calls = [c for c in self.host.calls if c.argv[0] == "certbot"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].argv[:2], ("certbot", "delete"))
        self.assertIn(DOMAIN, calls[0].argv)
        self.assertNotIn(test_domainchange.NEW_DOMAIN, calls[0].argv)
        self.assertTrue(calls[0].capture_stderr)
        self.assertEqual(calls[0].timeout, 120)
        for call in self.host.calls:
            self.assertNotIn(call.argv[:2], {("systemctl", "restart"), ("systemctl", "reload"),
                             ("systemctl", "stop"), ("ufw", "allow"), ("ufw", "delete"), ("apt-get", "purge")})

    def test_old_secret_contents_are_not_read_by_manager(self):
        original = HostFiles.read
        def guarded(files, path, **kwargs):
            self.assertNotEqual(path, CREDENTIAL)
            self.assertFalse("/archive/" + DOMAIN + "/privkey" in path)
            self.assertNotIn("/accounts/", path)
            return original(files, path, **kwargs)
        with patch.object(HostFiles, "read", new=guarded):
            self.assert_success(self.clean())

    def test_private_diagnostic_report_and_no_secret_public_output(self):
        report = self.clean()
        self.assert_success(report)
        for value in (DOMAIN, test_domainchange.NEW_DOMAIN, TOKEN, "PRIVATE-DOMAIN", str(self.fixture.root)):
            self.assertNotIn(value, json.dumps(report))
        dirs = list(self.host.path(STATE).glob("retired-cleanup-*"))
        self.assertEqual(len(dirs), 1)
        self.assertEqual(stat.S_IMODE(dirs[0].stat().st_mode), 0o700)
        for path in dirs[0].iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads((dirs[0] / "report.json").read_bytes()), report)

    def test_both_explicit_confirmations_required(self):
        plan = self.engine.check(DOMAIN)
        for a, b in ((False, True), (True, False), (1, True), (True, "y")):
            before = self.fixture.snapshot()
            with self.assertRaises(PreparationError):
                self.engine.clean(plan, confirm_ownership=a, confirm_delete=b)
            self.assertEqual(before, self.fixture.snapshot())

    def test_invalid_current_or_missing_target_never_writes(self):
        for domain in (test_domainchange.NEW_DOMAIN, "other-1", "not-here.example.org", "../outside"):
            with self.subTest(domain=domain), self.assertRaises(Exception):
                self.engine.check(domain)
        self.assertFalse(self.prep._exists(INTENT))

    def test_changed_target_after_confirmation_never_starts(self):
        plan = self.engine.check(DOMAIN)
        self.host.path(CREDENTIAL).write_bytes(b"different secret")
        before = self.fixture.snapshot()
        with self.assertRaises(Exception):
            self.clean(plan)
        self.assertEqual(before, self.fixture.snapshot())

    def test_changed_current_after_confirmation_never_starts(self):
        plan = self.engine.check(DOMAIN)
        self.host.rules.append("ufw allow 9999/tcp")
        with self.assertRaises(Exception):
            self.clean(plan)
        self.assertFalse(self.prep._exists(INTENT))

    def test_busy_lock_pending_or_bad_metadata_never_starts(self):
        with self.prep._lock(), self.assertRaises(Exception):
            self.engine.check(DOMAIN)
        self.host.path(CREDENTIAL).chmod(0o644)
        with self.assertRaises(Exception):
            self.engine.check(DOMAIN)
        self.assertFalse(self.prep._exists(INTENT))

    def test_preserved_tree_rejects_limits_and_symlinks(self):
        path = "/etc/letsencrypt/accounts/link"
        self.host.path(path).parent.mkdir(parents=True)
        self.host.path(path).symlink_to("/outside")
        with self.assertRaises(Exception):
            self.engine.check(DOMAIN)
        self.host.path(path).unlink()
        self.host.write("/etc/letsencrypt/accounts/" + "x/" * 9 + "file", b"x")
        with self.assertRaises(Exception):
            self.engine.check(DOMAIN)

    def test_pause_race_does_not_stop_active_certbot_or_delete(self):
        def progress(phase):
            if phase == "renewal-pause":
                self.host.local_override = lambda c: Reply(0, "ActiveState=active\nSubState=running\nMainPID=123\nJob=\n") if c.argv[-1] == "ActiveState,SubState,MainPID,Job" else None
        self.engine.progress = progress
        report = self.clean()
        self.assert_stopped(report, "renewal-pause")
        self.assertFalse(report["certbot_delete_attempted"])
        self.assertFalse(any(c.argv[:2] == ("systemctl", "stop") for c in self.host.calls))

    def test_changed_target_before_delete_blocks(self):
        def progress(phase):
            if phase == "before-delete-recheck":
                self.host.path(CREDENTIAL).write_bytes(b"changed")
        self.engine.progress = progress
        report = self.clean()
        self.assert_stopped(report, "before-delete-recheck")
        self.assertFalse(report["certbot_delete_attempted"])

    def test_delete_failed_or_uncertain_keeps_old_credential_and_marker(self):
        for reply in (Reply(1, "PRIVATE"), Reply(-1, uncertain=True)):
            with self.subTest(reply=reply):
                fixture = RetiredCleanupTests(methodName="test_check_read_only_and_plan_redacted")
                fixture.setUp()
                try:
                    fixture.host.local_override = lambda c: reply if c.argv[:2] == ("certbot", "delete") else None
                    report = fixture.clean()
                    fixture.assert_stopped(report, "certificate-delete")
                    self.assertTrue(fixture.host.path(CREDENTIAL).exists())
                    self.assertFalse(report["credential_delete_attempted"])
                    self.assertTrue(report["renewal_paused_verified_after"])
                    self.assertNotIn("PRIVATE", json.dumps(report))
                finally:
                    fixture.doCleanups()

    def test_delete_success_with_leftover_is_failure(self):
        self.host.local_override = lambda c: Reply(0) if c.argv[:2] == ("certbot", "delete") else None
        report = self.clean()
        self.assert_stopped(report, "certificate-delete-postcheck")
        self.assertTrue(self.host.path(CREDENTIAL).exists())

    def test_partial_delete_never_retries_or_manually_removes_cert_files(self):
        def override(command):
            if command.argv[:2] == ("certbot", "delete"):
                self.host.path(lineage_paths(DOMAIN)[2]).unlink()
                return Reply(1, "PRIVATE")
        self.host.local_override = override
        report = self.clean()
        self.assert_stopped(report)
        self.assertTrue(self.host.path(lineage_paths(DOMAIN)[0]).is_dir())
        self.assertTrue(self.host.path(CREDENTIAL).exists())
        with self.assertRaises(Exception):
            self.clean()

    def test_other_resource_change_during_delete_preserves_old_credential(self):
        def progress(phase):
            if phase == "certificate-delete-postcheck":
                self.host.write("/etc/letsencrypt/accounts/new-account/meta.json", b"external")
        self.engine.progress = progress
        report = self.clean()
        self.assert_stopped(report, "certificate-delete-postcheck")
        self.assertTrue(self.host.path(CREDENTIAL).exists())

    def test_old_credential_replacement_after_delete_not_removed(self):
        def progress(phase):
            if phase == "credential-delete":
                self.host.path(CREDENTIAL).unlink()
                self.host.write(CREDENTIAL, b"externally replaced")
        self.engine.progress = progress
        report = self.clean()
        self.assert_stopped(report, "credential-delete")
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), b"externally replaced")

    def test_enable_failure_leaves_pending_even_when_deletion_finished(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "enable", "--now", "certbot.timer") else None
        report = self.clean()
        self.assert_stopped(report, "renewal-enable")
        self.assertTrue(report["credential_removed_verified"])
        self.assertTrue(report["renewal_paused_verified_after"])

    def test_failed_enabled_health_disables_timer_without_repeating_delete(self):
        def progress(phase):
            if phase == "enabled-postcheck":
                self.fixture.probe.return_value = False
        self.engine.progress = progress
        report = self.clean()
        self.assert_stopped(report, "enabled-postcheck")
        self.assertEqual(len([c for c in self.host.calls if c.argv[:2] == ("certbot", "delete")]), 1)
        self.assertTrue(report["renewal_paused_verified_after"])

    def test_interrupt_keeps_intent_and_blocks_other_mutations(self):
        def progress(phase):
            if phase == "before-delete-recheck":
                raise KeyboardInterrupt
        self.engine.progress = progress
        report = self.clean()
        self.assert_stopped(report)
        state = installation_status(root=self.fixture.root)
        self.assertEqual(state["retired_cleanup"], "needs-inspection")
        self.assertIn("旧域名清理", render_status(state))
        with self.assertRaises(ClientError):
            read_client(root=self.fixture.root)
        with self.assertRaises(Exception):
            self.fixture.tokens.check()

    def test_no_restart_required_and_repeat_refused(self):
        self.assert_success(self.clean())
        before = self.fixture.snapshot()
        with self.assertRaises(Exception):
            self.clean()
        self.assertEqual(before, self.fixture.snapshot())

    def test_cleanup_later_retired_domain_preserves_original_retired_domain(self):
        self.fixture.assert_success(self.fixture.change("third.example.net"))
        self.enrich_renewals()
        before = self.host.path(CREDENTIAL).read_bytes()
        self.assert_success(self.clean(self.engine.check(test_domainchange.NEW_DOMAIN)))
        self.assertEqual(before, self.host.path(CREDENTIAL).read_bytes())
        for path in lineage_paths(DOMAIN):
            self.assertTrue(self.host.path(path).exists())

    def test_partial_pause_failure_retains_marker_without_deleting(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "disable", "--now", "certbot.timer") else None
        report = self.clean()
        self.assert_stopped(report, "renewal-pause")
        self.assertFalse(report["certbot_delete_attempted"])
        self.assertFalse(report["renewal_paused_verified_after"])

    def test_delete_output_capture_failure_does_not_delete_credential(self):
        original = HostFiles.write_new
        def write(files, path, *args, **kwargs):
            if path.endswith("/command-output.txt"):
                raise OSError("PRIVATE disk error")
            return original(files, path, *args, **kwargs)
        with patch.object(HostFiles, "write_new", new=write):
            report = self.clean()
        self.assert_stopped(report, "certificate-delete")
        self.assertTrue(self.host.path(CREDENTIAL).exists())
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_credential_unlink_failure_never_restores_deleted_certificates(self):
        original = HostFiles.unlink_owned
        def unlink(files, path, identity):
            if path == CREDENTIAL:
                raise OSError("PRIVATE")
            return original(files, path, identity)
        with patch.object(HostFiles, "unlink_owned", new=unlink):
            report = self.clean()
        self.assert_stopped(report, "credential-delete")
        self.assertTrue(self.host.path(CREDENTIAL).exists())
        self.assertFalse(self.host.path(lineage_paths(DOMAIN)[0]).exists())

    def test_intent_unlink_failure_disables_timer_and_remains_pending(self):
        original = HostFiles.unlink_owned
        def unlink(files, path, identity):
            if path == STATE + "/" + INTENT + ".json":
                raise OSError("PRIVATE")
            return original(files, path, identity)
        with patch.object(HostFiles, "unlink_owned", new=unlink):
            report = self.clean()
        self.assert_stopped(report, "intent-cleanup")
        self.assertTrue(report["renewal_paused_verified_after"])

    def test_report_write_failure_honestly_reports_missing_report(self):
        original = HostFiles.write_new
        def write(files, path, *args, **kwargs):
            if path.endswith("/report.json"):
                raise OSError("PRIVATE")
            return original(files, path, *args, **kwargs)
        with patch.object(HostFiles, "write_new", new=write):
            report = self.clean()
        self.assertEqual(report["result"], SUCCESS)
        self.assertFalse(report["report_saved"])
        self.assertFalse(self.prep._exists(INTENT))

    def test_due_renewal_after_enable_may_change_current_certificate(self):
        def progress(phase):
            if phase == "enabled-postcheck":
                name = test_domainchange.NEW_DOMAIN
                for part in ("cert", "chain", "fullchain", "privkey"):
                    data = b"renewed fixture" * (2 if part == "fullchain" else 1)
                    self.host.write(f"/etc/letsencrypt/archive/{name}/{part}2.pem", data)
                    live = self.host.path(f"/etc/letsencrypt/live/{name}/{part}.pem")
                    live.unlink()
                    live.symlink_to(f"../../archive/{name}/{part}2.pem")
        self.engine.progress = progress
        self.assert_success(self.clean())


class RetiredCleanupInterfaceTests(unittest.TestCase):
    @contextmanager
    def factory(self):
        yield Mock()

    def setUp(self):
        self.engine = Mock()
        self.engine.check.return_value = CleanupPlan(DOMAIN, "redacted", {"archive_generations": 1})
        self.engine.clean.return_value = {"result": SUCCESS}
        self.patcher = patch("snellctl.retiredcleanup.RetiredCleanup", return_value=self.engine)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_two_ascii_confirmations_no_secret_prompt(self):
        ui = Console([DOMAIN, "y", "Y"])
        self.assertEqual(run_retired_cleanup(factory=self.factory, terminal=ui), 0)
        self.engine.clean.assert_called_once_with(self.engine.check.return_value, confirm_ownership=True, confirm_delete=True)
        ui.secret.assert_not_called()

    def test_cancel_either_confirmation(self):
        for answers in ([DOMAIN, "n"], [DOMAIN, "y", ""], [DOMAIN, "yes"], [DOMAIN, "y", "确认"]):
            self.assertEqual(run_retired_cleanup(factory=self.factory, terminal=Console(answers)), 130)
        self.engine.clean.assert_not_called()

    def test_invalid_empty_or_interrupted_input(self):
        for value, code in (("", 130), ("other-1", 1), ("PRIVATE", 1), (KeyboardInterrupt(), 130)):
            ui = Console([value])
            self.assertEqual(run_retired_cleanup(factory=self.factory, terminal=ui), code)
            self.assertNotIn("PRIVATE", ui.text)
        self.engine.check.assert_not_called()
        self.engine.clean.assert_not_called()

    def test_non_tty_and_changed_terminal_do_not_clean(self):
        for states in ([False], [True, False]):
            ui = Console([DOMAIN, "y", "y"])
            ui.interactive = Mock(side_effect=states)
            self.assertIn(run_retired_cleanup(factory=self.factory, terminal=ui), {1, 2})
        self.engine.clean.assert_not_called()

    def test_stopped_report_not_claimed_success(self):
        self.engine.clean.return_value = {"result": "stopped", "failure_phase": "certificate-delete"}
        ui = Console([DOMAIN, "y", "y"])
        self.assertEqual(run_retired_cleanup(factory=self.factory, terminal=ui), 1)
        self.assertIn("可能已部分删除", ui.text)

    def test_cli_and_menu_are_experimental_only(self):
        with patch("snellctl.retiredcleanup.run_retired_cleanup", return_value=0) as run:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["clean-retired-domain"]), 2)
            run.assert_not_called()
            self.assertEqual(main(["clean-retired-domain", "--experimental"]), 0)
            with patch("builtins.input", side_effect=["14", "0"]), redirect_stdout(io.StringIO()):
                self.assertEqual(run_menu(experimental=True), 0)
            self.assertEqual(run.call_count, 2)
            with patch("builtins.input", side_effect=["14", "0"]), redirect_stdout(io.StringIO()):
                self.assertEqual(run_menu(), 0)
            self.assertEqual(run.call_count, 2)

    def test_no_automatic_target_or_confirmation_flags(self):
        for arg in ("--domain", "--yes", "--force", "--root", "--token"):
            with redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit):
                main(["clean-retired-domain", "--experimental", arg, "PRIVATE"])
            self.assertNotIn("PRIVATE", output.getvalue())
