from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
import shutil
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.client import read_client, ClientError
from snellctl.hostprep import CREDENTIAL, HostFiles, PreparationError, Reply, STATE
from snellctl.installer import installation_status, render_status
from snellctl.menu import run_menu
from snellctl.retiredcleanup import (CleanupPlan, INTENT, SUCCESS, RetiredCleanup, lineage_paths,
                                    run_retired_cleanup, run_retired_cleanup_check)
from snellctl.retiredplan import ScopeBlocked
from snellctl.tokenchange import RenewalStateMismatch
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
import test_domainchange
import test_retiredplan


class Clock:
    def __init__(self):
        self.now, self.sleeps = 0, []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class PausedWaitTests(unittest.TestCase):
    timer = "ActiveState=inactive\nSubState=dead\nUnitFileState=disabled\n"
    idle = "ActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\n"
    busy = "ActiveState=activating\nSubState=start\nMainPID=123\nJob=PRIVATE-JOB\n"

    def setUp(self):
        self.clock = Clock()
        self.prep = Mock()
        tokens = SimpleNamespace(prep=self.prep, files=None)
        self.engine = RetiredCleanup(tokens, clock=self.clock, sleep=self.clock.sleep)
        self.report = {}
        self.samples = []
        self.prep._run.side_effect = self.query

    def query(self, argv, timeout):
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 5)
        if argv == ["systemctl", "show", "certbot.timer", "-p", "ActiveState,SubState,UnitFileState"]:
            return self.timer
        self.assertEqual(argv, ["systemctl", "show", "certbot.service", "-p", "ActiveState,SubState,MainPID,Job"])
        return self.samples.pop(0) if self.samples else self.idle

    def wait(self):
        self.engine._wait_paused(self.report)
        return self.report["pause_wait"]

    def test_already_idle_requires_two_observations_separated_by_wait(self):
        result = self.wait()
        self.assertEqual(result, {"result": "idle-observed-twice", "budget_seconds": 90,
                                 "samples": 2, "busy_samples": 0, "elapsed_seconds": 1})
        self.assertEqual(self.clock.sleeps, [1])
        self.assertEqual(self.prep._run.call_count, 4)

    def test_queued_then_starting_then_idle_is_not_a_failure(self):
        self.samples = [self.idle.replace("Job=\n", "Job=PRIVATE-JOB\n"), self.busy]
        result = self.wait()
        self.assertEqual(result["result"], "idle-observed-twice")
        self.assertEqual(result["busy_samples"], 2)
        self.assertEqual(result["samples"], 4)
        self.assertEqual(result["elapsed_seconds"], 3)
        self.assertEqual(result["first_busy"]["observed"]["MainPID"], "0")
        self.assertEqual(result["last_busy"]["observed"]["MainPID"], "123")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_busy_between_idle_samples_resets_confirmation(self):
        self.samples = [self.idle, self.busy, self.idle, self.idle]
        self.assertEqual(self.wait()["samples"], 4)

    def test_wait_for_recognized_process_transitions_only(self):
        for active, sub in (("activating", "start-pre"), ("activating", "start-post"),
                            ("active", "running"), ("deactivating", "stop-post")):
            with self.subTest(state=(active, sub)):
                self.samples = [self.busy.replace("activating", active).replace("SubState=start", "SubState=" + sub)]
                self.assertEqual(self.wait()["busy_samples"], 1)

    def test_permanently_busy_stops_without_stopping_service_or_retrying_mutations(self):
        self.samples = [self.busy] * 100
        with self.assertRaises(ScopeBlocked) as raised:
            self.wait()
        self.assertEqual(raised.exception.code, "renewal-idle-wait-timeout")
        self.assertEqual(self.report["pause_wait"]["result"], "timeout")
        self.assertEqual(self.clock.now, 90)
        self.assertEqual(self.report["pause_wait"]["samples"], 90)
        self.assertTrue(all(c.args[0][:2] == ["systemctl", "show"] for c in self.prep._run.call_args_list))

    def test_timer_reactivated_during_wait_stops_immediately(self):
        count = 0
        def query(argv, timeout):
            nonlocal count
            if argv[2] == "certbot.timer":
                count += 1
                if count == 2:
                    return self.timer.replace("inactive", "active").replace("dead", "waiting").replace("disabled", "enabled")
            return self.query(argv, timeout)
        self.prep._run.side_effect = query
        self.samples = [self.busy]
        with self.assertRaises(RenewalStateMismatch) as raised:
            self.wait()
        self.assertEqual(raised.exception.evidence["unit"], "certbot.timer")
        self.assertEqual(self.prep._run.call_count, 3)

    def test_failed_unknown_or_inconsistent_service_state_not_waited_on(self):
        states = [self.busy.replace("activating", "failed").replace("SubState=start", "SubState=failed"),
                  self.busy.replace("activating", "PRIVATE"), self.busy.replace("MainPID=123", "MainPID=PRIVATE"),
                  self.busy.replace("MainPID=123", "MainPID=99999999999"),
                  self.busy.replace("activating", "active").replace("SubState=start", "SubState=running").replace("123", "0"),
                  self.idle.replace("MainPID=0", "MainPID=123"), self.idle.replace("SubState=dead", "SubState=exited")]
        for value in states:
            with self.subTest(value=value):
                self.samples = [value]
                before = len(self.clock.sleeps)
                with self.assertRaises(RenewalStateMismatch) as raised:
                    self.wait()
                self.assertEqual(len(self.clock.sleeps), before)
                self.assertNotIn("PRIVATE", json.dumps(raised.exception.evidence))

    def test_missing_and_additional_fields_reject_without_wait(self):
        for value in (self.idle.replace("Job=\n", ""), self.idle + "PRIVATE-FIELD=PRIVATE\n"):
            self.samples = [value]
            with self.assertRaises(RenewalStateMismatch):
                self.wait()
            self.assertEqual(self.clock.sleeps, [])

    def test_duplicate_and_nonproperty_lines_fail_closed(self):
        for value in (self.idle + "MainPID=PRIVATE\n", self.idle + "PRIVATE\n"):
            self.samples = [value]
            with self.assertRaises(ScopeBlocked) as raised:
                self.wait()
            self.assertEqual(raised.exception.code, "renewal-state-output-unrecognized")
            self.assertEqual(self.clock.sleeps, [])

    def test_failed_or_interrupted_query_is_not_retried(self):
        for error in (PreparationError("PRIVATE"), KeyboardInterrupt()):
            self.prep._run.reset_mock()
            self.prep._run.side_effect = error
            with self.assertRaises(type(error)):
                self.wait()
            self.assertEqual(self.prep._run.call_count, 1)
            self.assertEqual(self.report["pause_wait"]["result"], "stopped")
            self.assertEqual(self.clock.sleeps, [])

    def test_wait_interruption_does_not_return_idle(self):
        self.samples = [self.busy]
        self.engine.sleep = Mock(side_effect=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.wait()
        self.assertEqual(self.report["pause_wait"]["result"], "stopped")
        self.assertEqual(self.report["pause_wait"]["busy_samples"], 1)

    def test_queries_consume_budget_and_late_idle_is_not_accepted(self):
        def query(argv, timeout):
            result = self.query(argv, timeout)
            self.clock.now += 46
            return result
        self.prep._run.side_effect = query
        with self.assertRaises(ScopeBlocked) as raised:
            self.wait()
        self.assertEqual(raised.exception.code, "renewal-idle-wait-timeout")
        self.assertEqual(self.report["pause_wait"]["result"], "timeout")
        self.assertEqual(self.clock.sleeps, [])

    def test_query_timeout_shrinks_with_remaining_budget(self):
        count = 0
        def query(argv, timeout):
            nonlocal count
            count += 1
            if count == 1:
                self.clock.now += 88
            else:
                self.assertEqual(timeout, 2)
                raise PreparationError("query timed out")
            return self.query(argv, timeout)
        self.prep._run.side_effect = query
        with self.assertRaises(PreparationError):
            self.wait()
        self.assertEqual(self.prep._run.call_count, 2)


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
        self.clock = Clock()
        self.engine = RetiredCleanup(self.fixture.tokens, clock=self.clock, sleep=self.clock.sleep)
        self.host.calls.clear()
        self.enterContext(self.linux_symlink_metadata())

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

    @contextmanager
    def linux_symlink_metadata(self):
        original = HostFiles.info
        def info(files, path):
            item = original(files, path)
            if item is not None and stat.S_ISLNK(item.st_mode):
                values = {name: getattr(item, name) for name in dir(item) if name.startswith("st_")}
                values["st_mode"] = stat.S_IFLNK | 0o777
                return SimpleNamespace(**values)
            return item
        with patch.object(HostFiles, "info", new=info):
            yield

    def test_linux_0777_certificate_links_are_not_writable_regular_files(self):
        with self.linux_symlink_metadata():
            plan = self.engine.check(DOMAIN)
        self.assertEqual(plan.domain, DOMAIN)

    def test_read_only_check_never_enters_cleanup_or_changes_state(self):
        before = self.fixture.snapshot()
        active, enabled, rules = set(self.host.active), set(self.host.enabled), list(self.host.rules)
        with patch.object(self.engine, "clean", side_effect=AssertionError("delete")), \
             patch.object(HostFiles, "write_new", side_effect=AssertionError("write")), \
             patch.object(HostFiles, "unlink_owned", side_effect=AssertionError("unlink")):
            report = self.engine.inspect_only(DOMAIN)
        self.assertEqual(report["result"], "cleanup-check-passed-no-changes", report)
        self.assertEqual(report["linux_style_live_links_checked"], 4)
        for key in ("host_changes_attempted", "cleanup_authorized", "certbot_attempted",
                    "renewal_pause_attempted", "report_saved"):
            self.assertFalse(report[key])
        self.assertEqual(self.fixture.snapshot(), before)
        self.assertEqual((active, enabled, rules), (self.host.active, self.host.enabled, self.host.rules))
        for command in self.host.calls:
            self.assertNotEqual(command.argv[0], "certbot")
            self.assertNotIn(command.argv[:2], {("systemctl", "disable"), ("systemctl", "enable"),
                                             ("systemctl", "stop"), ("systemctl", "reload")})

    def test_normal_file_writable_permissions_still_block(self):
        path = "/etc/letsencrypt/accounts/sample/meta.json"
        self.host.write(path, b"PRIVATE", 0o666)
        report = self.engine.inspect_only(DOMAIN)
        self.assertEqual(report["result"], "blocked-preserve-all", report)
        self.assertEqual(report["failure_phase"], "preserved-resources-check")
        self.assertEqual(report["reason"], "preserved-metadata")
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertNotIn(path, json.dumps(report))

    def test_directory_writable_permissions_still_block(self):
        self.host.write("/etc/letsencrypt/accounts/sample/meta.json", b"fixture")
        self.host.path("/etc/letsencrypt/accounts/sample").chmod(0o777)
        report = self.engine.inspect_only(DOMAIN)
        self.assertEqual(report["failure_phase"], "preserved-resources-check")
        self.assertEqual(report["reason"], "preserved-metadata")

    def test_live_symlink_wrong_owner_still_blocks(self):
        original = HostFiles.info
        path = "/etc/letsencrypt/live/" + test_domainchange.NEW_DOMAIN + "/cert.pem"
        def info(files, name):
            item = original(files, name)
            if name == path:
                item = SimpleNamespace(**vars(item))
                item.st_uid += 1
            return item
        with patch.object(HostFiles, "info", new=info), self.assertRaises(ScopeBlocked) as raised:
            self.engine._preserved_tree((*lineage_paths(DOMAIN), CREDENTIAL))
        self.assertEqual(raised.exception.code, "preserved-owner")

    def test_live_symlink_must_match_its_own_archive_and_file(self):
        path = self.host.path("/etc/letsencrypt/live/" + test_domainchange.NEW_DOMAIN + "/cert.pem")
        for destination in ("/outside/private", "../../archive/" + DOMAIN + "/cert1.pem",
                            "../../archive/" + test_domainchange.NEW_DOMAIN + "/privkey1.pem"):
            with self.subTest(destination=destination):
                path.unlink()
                path.symlink_to(destination)
                with self.assertRaises(ScopeBlocked) as raised:
                    self.engine._preserved_tree((*lineage_paths(DOMAIN), CREDENTIAL))
                self.assertEqual(raised.exception.code, "preserved-symlink-target")

    def test_unknown_live_symlink_and_account_symlink_still_block(self):
        for path in ("/etc/letsencrypt/live/README", "/etc/letsencrypt/accounts/link"):
            with self.subTest(path=path):
                target = self.host.path(path)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to("/outside")
                with self.assertRaises(ScopeBlocked) as raised:
                    self.engine._preserved_tree((*lineage_paths(DOMAIN), CREDENTIAL))
                self.assertEqual(raised.exception.code, "preserved-symlink")
                target.unlink()

    def test_symlink_target_permissions_and_hardlinks_remain_checked(self):
        path = self.host.path("/etc/letsencrypt/archive/" + test_domainchange.NEW_DOMAIN + "/privkey1.pem")
        path.chmod(0o644)
        with self.assertRaises(ScopeBlocked) as raised:
            self.engine._preserved_tree((*lineage_paths(DOMAIN), CREDENTIAL))
        self.assertEqual(raised.exception.code, "preserved-symlink-target-metadata")
        path.chmod(0o600)
        os.link(path, path.parent / "extra-hardlink")
        with self.assertRaises(ScopeBlocked) as raised:
            self.engine._preserved_tree((*lineage_paths(DOMAIN), CREDENTIAL))
        self.assertEqual(raised.exception.code, "preserved-symlink-target-metadata")

    def test_read_only_error_reason_and_lock_phase_are_redacted(self):
        with self.prep._lock():
            report = self.engine.inspect_only(DOMAIN)
        self.assertEqual(report["failure_phase"], "preparation-lock")
        self.assertFalse(report["host_changes_attempted"])
        with patch.object(self.engine, "_preserved_tree", side_effect=RuntimeError("PRIVATE-PATH")):
            report = self.engine.inspect_only(DOMAIN)
        self.assertEqual(report["failure_phase"], "preserved-resources-check")
        self.assertNotIn("PRIVATE-PATH", json.dumps(report))

    def test_read_only_interrupt_never_creates_pending_marker(self):
        self.engine.progress = lambda phase: (_ for _ in ()).throw(KeyboardInterrupt()) if phase == "preserved-resources-check" else None
        report = self.engine.inspect_only(DOMAIN)
        self.assertEqual(report["reason"], "interrupted")
        self.assertFalse(self.prep._exists(INTENT))

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
        self.assert_stopped(report, "renewal-pause-check")
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
        expected = {"attempted": True, "exit_code": 1, "execution_uncertain": False}
        self.assertEqual(report["pause_command"], expected)
        self.assertEqual(report["fallback_pause_command"], expected)
        self.assertEqual(report["fallback_pause_failure"]["failure_phase"], "fallback-pause-command")
        self.assertEqual(report["reason"], "timer-command-failed-or-uncertain")
        self.assertEqual(report["failure_location"]["module"], "retiredplan.py")

    def test_renewal_started_at_pause_finishes_before_single_deletion(self):
        samples = []
        def observe(command):
            if (command.argv[-1] == "ActiveState,SubState,MainPID,Job"
                    and "certbot.timer" not in self.host.active):
                samples.append(command)
                if len(samples) <= 2:
                    return Reply(0, PausedWaitTests.busy)
            if command.argv[:2] == ("certbot", "delete"):
                self.assertGreaterEqual(len(samples), 5)
        self.host.local_override = observe
        report = self.clean()
        self.assert_success(report)
        self.assertEqual(report["pause_wait"]["result"], "idle-observed-twice")
        self.assertEqual(report["pause_wait"]["busy_samples"], 2)
        self.assertEqual(report["pause_wait"]["samples"], 4)
        self.assertEqual(report["pause_wait"]["elapsed_seconds"], 3)
        self.assertEqual(sum(c.argv[:2] == ("certbot", "delete") for c in self.host.calls), 1)
        self.assertEqual(sum(c.argv == ("systemctl", "disable", "--now", "certbot.timer")
                             for c in self.host.calls), 1)
        self.assertFalse(any(c.argv[:2] in {("systemctl", "start"), ("systemctl", "stop"),
                                           ("systemctl", "restart")} for c in self.host.calls))
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_renewal_wait_timeout_preserves_resources_and_blocks_deletion(self):
        def observe(command):
            if (command.argv[-1] == "ActiveState,SubState,MainPID,Job"
                    and "certbot.timer" not in self.host.active):
                return Reply(0, PausedWaitTests.busy)
        self.host.local_override = observe
        report = self.clean()
        self.assert_stopped(report, "renewal-pause-check")
        self.assertEqual(report["reason"], "renewal-idle-wait-timeout")
        self.assertEqual(report["pause_wait"]["result"], "timeout")
        self.assertFalse(report["certbot_delete_attempted"])
        self.assertFalse(report["credential_delete_attempted"])
        self.assertFalse(report["renewal_paused_verified_after"])
        self.assertEqual(report["fallback_pause_failure"]["reason"], "renewal-unit-state-mismatch")
        self.assertTrue(self.host.path(CREDENTIAL).exists())
        self.assertTrue(all(self.host.path(path).exists() for path in lineage_paths(DOMAIN)))
        self.assertFalse(any(c.argv[0] == "certbot" for c in self.host.calls))

    def test_certificate_or_target_change_during_wait_still_blocks_deletion(self):
        for target in ("current-renewal", "old-credential"):
            with self.subTest(target=target):
                fixture = RetiredCleanupTests('test_check_read_only_and_plan_redacted')
                try:
                    fixture.setUp()
                    path = ("/etc/letsencrypt/renewal/" + test_domainchange.NEW_DOMAIN + ".conf"
                            if target == "current-renewal" else CREDENTIAL)
                    def observe(command):
                        if (command.argv[-1] == "ActiveState,SubState,MainPID,Job"
                                and "certbot.timer" not in fixture.host.active and fixture.clock.now == 0):
                            return Reply(0, PausedWaitTests.busy)
                    def sleep(seconds):
                        fixture.clock.sleep(seconds)
                        if fixture.clock.now == 1:
                            old = fixture.host.path(path).read_bytes()
                            fixture.host.path(path).write_bytes(old + b"\n# changed by renewal\n")
                    fixture.host.local_override = observe
                    fixture.engine.sleep = sleep
                    report = fixture.clean()
                    fixture.assert_stopped(report)
                    self.assertEqual(report["pause_wait"]["result"], "idle-observed-twice")
                    self.assertFalse(report["certbot_delete_attempted"])
                    self.assertFalse(report["credential_delete_attempted"])
                    self.assertFalse(any(c.argv[0] == "certbot" for c in fixture.host.calls))
                    self.assertTrue(all(fixture.host.path(p).exists() for p in lineage_paths(DOMAIN)))
                finally:
                    fixture.doCleanups()

    def test_new_busy_state_after_wait_is_rejected_by_unchanged_health_gate(self):
        samples = []
        def observe(command):
            if (command.argv[-1] == "ActiveState,SubState,MainPID,Job"
                    and "certbot.timer" not in self.host.active):
                samples.append(command)
                if len(samples) >= 3:
                    return Reply(0, PausedWaitTests.busy)
        self.host.local_override = observe
        report = self.clean()
        self.assert_stopped(report, "renewal-pause-check")
        self.assertEqual(report["pause_wait"]["result"], "idle-observed-twice")
        self.assertEqual(report["reason"], "renewal-unit-state-mismatch")
        self.assertFalse(report["certbot_delete_attempted"])

    def test_busy_at_precheck_never_pauses_timer_or_enters_wait(self):
        self.host.local_override = lambda c: Reply(0, PausedWaitTests.busy) if (
            c.argv[-1] == "ActiveState,SubState,MainPID,Job") else None
        with self.assertRaises(RenewalStateMismatch):
            self.clean()
        self.assertEqual(self.clock.sleeps, [])
        self.assertFalse(self.prep._exists(INTENT))
        self.assertFalse(any(c.argv[:2] == ("systemctl", "disable") for c in self.host.calls))

    def test_pause_postcheck_failure_preserves_original_and_fallback_diagnostics(self):
        with patch.object(self.engine, "_health", side_effect=PreparationError("PRIVATE cause")):
            report = self.clean()
        self.assert_stopped(report, "renewal-pause-check")
        self.assertEqual(report["pause_command"], {"attempted": True, "exit_code": 0, "execution_uncertain": False})
        self.assertEqual(report["fallback_pause_command"], report["pause_command"])
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertNotIn("/Users/", json.dumps(report))

    def test_idle_failure_evidence_survives_a_later_successful_fallback_check(self):
        seen = []
        def observe(command):
            if (command.argv[-1] == "ActiveState,SubState,MainPID,Job"
                    and "certbot.timer" not in self.host.active):
                seen.append(command.argv)
                if len(seen) == 1:
                    return Reply(0, "ActiveState=inactive\nSubState=dead\nMainPID=0\n")
        self.host.local_override = observe
        report = self.clean()
        self.assert_stopped(report, "renewal-pause-check")
        self.assertEqual(report["reason"], "renewal-unit-state-mismatch")
        self.assertEqual(report["unit_state_check"]["missing_fields"], ["Job"])
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assertNotIn("fallback_pause_failure", report)
        self.assertEqual(len(seen), 2)
        self.assertFalse(report["certbot_delete_attempted"])
        self.assertFalse(report["credential_delete_attempted"])
        self.assertFalse(any(c.argv[0] == "certbot" for c in self.host.calls))
        self.assertFalse(any(c.argv[:2] == ("systemctl", "stop") for c in self.host.calls))
        directory = self.prep._read_record(INTENT)["log_directory"]
        self.assertEqual(json.loads(self.host.path(directory + "/report.json").read_bytes()), report)

    def test_busy_evidence_and_later_bad_fields_keep_separate_safe_evidence(self):
        seen = []
        def observe(command):
            if (command.argv[-1] == "ActiveState,SubState,MainPID,Job"
                    and "certbot.timer" not in self.host.active):
                seen.append(command.argv)
                if len(seen) == 1:
                    return Reply(0, "ActiveState=active\nSubState=running\nMainPID=123\nJob=PRIVATE-JOB\n")
                return Reply(0, "ActiveState=inactive\nSubState=dead\nMainPID=0\nPRIVATE-FIELD=PRIVATE-VALUE\n")
        self.host.local_override = observe
        report = self.clean()
        self.assert_stopped(report, "renewal-pause-check")
        self.assertEqual(report["pause_wait"]["first_busy"]["observed"]["MainPID"], "123")
        self.assertEqual(report["pause_wait"]["busy_samples"], 1)
        self.assertEqual(report["unit_state_check"]["missing_fields"], ["Job"])
        fallback = report["fallback_pause_failure"]
        self.assertEqual(fallback["failure_phase"], "fallback-pause-check")
        self.assertEqual(fallback["unit_state_check"]["missing_fields"], ["Job"])
        self.assertTrue(fallback["unit_state_check"]["unexpected_fields_present"])
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertEqual(len(seen), 3)
        self.assertFalse(report["renewal_paused_verified_after"])
        self.assertFalse(report["certbot_delete_attempted"])
        self.assertFalse(report["credential_delete_attempted"])
        self.assertFalse(any(c.argv[0] == "certbot" for c in self.host.calls))

    def test_command_read_failure_has_no_invented_state_evidence(self):
        def observe(command):
            if (command.argv[-1] == "ActiveState,SubState,MainPID,Job"
                    and "certbot.timer" not in self.host.active):
                return Reply(1, "PRIVATE-OUTPUT")
        self.host.local_override = observe
        report = self.clean()
        self.assert_stopped(report, "renewal-pause-check")
        self.assertNotIn("unit_state_check", report)
        self.assertNotIn("unit_state_check", report["fallback_pause_failure"])
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertFalse(report["certbot_delete_attempted"])

    def test_uncertain_pause_never_reaches_delete(self):
        self.host.local_override = lambda c: Reply(0, "PRIVATE", uncertain=True) if c.argv == ("systemctl", "disable", "--now", "certbot.timer") else None
        report = self.clean()
        self.assert_stopped(report, "renewal-pause")
        self.assertTrue(report["pause_command"]["execution_uncertain"])
        self.assertFalse(report["certbot_delete_attempted"])
        self.assertNotIn("PRIVATE", json.dumps(report))

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

    def test_pre_deletion_failure_message_requires_both_explicit_false_flags(self):
        for certificate, credential in ((False, False), (True, False), (False, True), (0, False), (False, None)):
            with self.subTest(certificate=certificate, credential=credential):
                self.engine.clean.return_value = {"result": "stopped", "certbot_delete_attempted": certificate,
                                                  "credential_delete_attempted": credential}
                ui = Console([DOMAIN, "y", "y"])
                self.assertEqual(run_retired_cleanup(factory=self.factory, terminal=ui), 1)
                if certificate is False and credential is False:
                    self.assertIn("本次未尝试删除旧证书或凭据", ui.text)
                    self.assertNotIn("可能已部分删除", ui.text)
                else:
                    self.assertIn("可能已部分删除", ui.text)
                self.assertIn("续期可能暂停", ui.text)

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

    def test_preconfirmation_cleanup_failure_has_sanitized_phase_report(self):
        self.engine.check.side_effect = ScopeBlocked("preserved-metadata")
        self.engine._check_failure.return_value = {"failure_phase": "preserved-resources-check", "reason": "preserved-metadata"}
        ui = Console([DOMAIN])
        self.assertEqual(run_retired_cleanup(factory=self.factory, terminal=ui), 1)
        self.assertIn('"host_changes_attempted": false', ui.text)
        self.assertIn("preserved-resources-check", ui.text)
        self.engine.clean.assert_not_called()

    def test_read_only_interface_and_cli_cannot_dispatch_delete(self):
        self.engine.inspect_only.return_value = {"result": "cleanup-check-passed-no-changes"}
        ui = Console([DOMAIN, "y"])
        self.assertEqual(run_retired_cleanup_check(factory=self.factory, terminal=ui), 0)
        self.engine.inspect_only.assert_called_once_with(DOMAIN)
        self.engine.clean.assert_not_called()
        ui.secret.assert_not_called()
        with patch("snellctl.retiredcleanup.run_retired_cleanup_check", return_value=0) as check, \
             patch("snellctl.retiredcleanup.run_retired_cleanup") as clean:
            self.assertEqual(main(["clean-retired-domain", "--check-only"]), 0)
            check.assert_called_once_with()
            clean.assert_not_called()
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(["clean-retired-domain", "--check-only", "--experimental"])

    def test_read_only_cancel_and_no_tty_never_check_or_clean(self):
        for answers, status in (([""], 130), ([DOMAIN, ""], 130), ([DOMAIN, "yes"], 130)):
            self.assertEqual(run_retired_cleanup_check(factory=self.factory, terminal=Console(answers)), status)
        ui = Console([DOMAIN, "y"])
        ui.interactive = Mock(return_value=False)
        self.assertEqual(run_retired_cleanup_check(factory=self.factory, terminal=ui), 2)
        self.engine.inspect_only.assert_not_called()
        self.engine.clean.assert_not_called()
