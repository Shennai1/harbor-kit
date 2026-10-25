from contextlib import contextmanager, redirect_stdout, redirect_stderr
import io
import json
import unittest
from unittest.mock import patch

from snellctl.__main__ import main
from snellctl.client import ClientError, read_client
from snellctl.hostprep import CREDENTIAL, STATE, STAGING, PreparationError, Reply
from snellctl.tokendiag import (LOGS, REPORT, STARTED, RECHECK_LOGS, RECHECK_REPORT,
                               RECHECK_STARTED, TokenDiagnostic, run_token_diagnostic)
from snellctl.tokenchange import CANDIDATE, CURRENT, INTENT
from test_installer import Console
import test_tokenchange
from test_tokenchange import NEW_TOKEN, TOKEN, success_output


class TokenDiagnosticTests(unittest.TestCase):
    def setUp(self):
        test_tokenchange.TokenChangeTests.setUp(self)
        self.host.local_override = lambda c: Reply(1) if c.argv[:2] == ("certbot", "renew") else None
        with self.assertRaises(PreparationError):
            self.tokens.change(self.tokens.check(), NEW_TOKEN, confirm_change=True)
        self.host.local_override = None
        self.host.calls.clear()
        self.diag = TokenDiagnostic(self.tokens)

    def run_probe(self):
        return self.diag.run(self.diag.check(), confirm_probe=True)

    def certbot_calls(self):
        return [c for c in self.host.calls if c.argv[:2] == ("certbot", "renew")]

    def assert_no_management_writes(self):
        for command in self.host.calls:
            self.assertNotIn(command.argv[:2], {("ufw", "allow"), ("ufw", "delete"),
                ("systemctl", "enable"), ("systemctl", "disable"), ("systemctl", "stop"),
                ("systemctl", "start"), ("systemctl", "restart"), ("systemctl", "reload")})

    def test_success_is_only_one_probe_not_commit_or_resume(self):
        before = test_tokenchange.TokenChangeTests.snapshot(self)
        report = self.run_probe()
        self.assertEqual(report["result"], "candidate-probe-passed-not-committed")
        self.assertTrue(report["postcheck_passed"])
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assertTrue(report["report_saved"])
        self.assertEqual(self.prep._read_record(REPORT), report)
        after = test_tokenchange.TokenChangeTests.snapshot(self)
        for path, value in before.items():
            self.assertEqual(after[path], value, path)
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertTrue(self.prep._exists(INTENT))
        self.assertTrue(self.host.path(CANDIDATE).exists())
        self.assertFalse(self.prep._exists(CURRENT))
        self.assertNotIn("certbot.timer", self.host.active)
        self.assertNotIn("certbot.timer", self.host.enabled)
        self.assert_no_management_writes()
        self.assertEqual(len(self.certbot_calls()), 1)
        command = self.certbot_calls()[0]
        args = command.argv
        self.assertEqual(args[args.index("--server") + 1], STAGING)
        self.assertEqual(args[args.index("--dns-cloudflare-credentials") + 1], CANDIDATE)
        self.assertEqual(args[args.index("--logs-dir") + 1], LOGS)
        for option in ("--dry-run", "--no-random-sleep-on-renew", "--run-deploy-hooks", "--no-directory-hooks"):
            self.assertIn(option, args)
        self.assertNotIn("--force-renewal", args)
        self.assertEqual(command.timeout, 600)
        self.assertTrue(command.capture_stderr)
        self.assertEqual(self.host.path(LOGS).stat().st_mode & 0o777, 0o700)
        for path in (LOGS + "/command-output.txt", STATE + "/" + REPORT + ".json", STATE + "/" + STARTED + ".json"):
            self.assertEqual(self.host.path(path).stat().st_mode & 0o777, 0o600)

    def test_nonzero_exit_retained_but_secrets_stay_out_of_report(self):
        output = "CloudFlareAPIError: " + NEW_TOKEN + "\nPermissionError: [Errno 13] private.example\n"
        self.host.local_override = lambda c: Reply(7, output) if c.argv[:2] == ("certbot", "renew") else None
        report = self.run_probe()
        self.assertEqual(report["result"], "command-failed")
        self.assertEqual(report["certbot"]["exit_code"], 7)
        self.assertTrue(report["certbot"]["signals"]["cloudflare_api_error"])
        self.assertEqual(report["certbot"]["errno_seen"], [13])
        text = json.dumps(report)
        for secret in (NEW_TOKEN, TOKEN, "private.example", self.spec.domain, self.before_keys.psk):
            self.assertNotIn(secret, text)
        self.assertEqual(self.host.path(LOGS + "/command-output.txt").read_text(), output)
        self.assert_no_management_writes()

    def test_zero_exit_missing_evidence_is_not_success(self):
        self.host.local_override = lambda c: Reply(0, "nothing to do") if c.argv[:2] == ("certbot", "renew") else None
        report = self.run_probe()
        self.assertEqual(report["result"], "evidence-incomplete")
        self.assertFalse(report["certbot"]["evidence"]["fresh_dns_challenge"])

    def test_uncertain_execution_is_not_reported_as_exit_signal(self):
        self.host.local_override = lambda c: Reply(-1, uncertain=True) if c.argv[:2] == ("certbot", "renew") else None
        report = self.run_probe()
        self.assertEqual(report["result"], "execution-uncertain")
        self.assertIsNone(report["certbot"]["exit_code"])
        self.assertTrue(report["certbot"]["execution_uncertain"])

    def test_signal_exit_preserved(self):
        self.host.local_override = lambda c: Reply(-9) if c.argv[:2] == ("certbot", "renew") else None
        self.assertEqual(self.run_probe()["certbot"]["exit_code"], -9)

    def test_interrupt_retains_one_shot_record_and_safe_report(self):
        def interrupt(c):
            if c.argv[:2] == ("certbot", "renew"):
                raise KeyboardInterrupt(NEW_TOKEN)
        self.host.local_override = interrupt
        report = self.run_probe()
        self.assertEqual(report["failure_phase"], "candidate-dry-run")
        self.assertEqual(report["result"], "stopped")
        self.assertNotIn(NEW_TOKEN, json.dumps(report))
        self.assertTrue(self.prep._exists(STARTED))
        self.assert_no_management_writes()

    def test_drift_after_probe_is_not_repaired(self):
        def drift(c):
            if c.argv[:2] == ("certbot", "renew"):
                self.host.path(CREDENTIAL).write_bytes(b"modified-externally")
                return Reply(0, success_output())
        self.host.local_override = drift
        report = self.run_probe()
        self.assertEqual(report["failure_phase"], "postcheck")
        self.assertFalse(report["postcheck_passed"])
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), b"modified-externally")
        self.assertEqual(report["certbot"]["exit_code"], 0)
        self.assert_no_management_writes()

    def test_report_write_failure_does_not_hide_in_memory_outcome(self):
        original = self.prep._record
        def fail(name, value):
            if name == REPORT:
                raise OSError("private-error")
            return original(name, value)
        with patch.object(self.prep, "_record", side_effect=fail):
            report = self.run_probe()
        self.assertFalse(report["report_saved"])
        self.assertEqual(report["result"], "candidate-probe-passed-not-committed")
        self.assertTrue(self.prep._exists(STARTED))

    def test_repeat_is_blocked_without_another_request(self):
        self.run_probe()
        with self.assertRaises(PreparationError):
            self.run_probe()
        self.assertEqual(len(self.certbot_calls()), 1)

    def test_existing_diagnostic_paths_not_overwritten(self):
        for path in (STATE + "/" + REPORT + ".json", STATE + "/" + STARTED + ".json", LOGS):
            self.host.path(path).symlink_to("/unrelated")
            with self.assertRaises(PreparationError):
                self.diag.check()
            self.assertTrue(self.host.path(path).is_symlink())
            self.host.path(path).unlink()
        self.assertEqual(self.certbot_calls(), [])

    def test_old_credential_already_replaced_is_rejected(self):
        self.host.path(CREDENTIAL).write_bytes(self.host.path(CANDIDATE).read_bytes())
        with self.assertRaises(PreparationError):
            self.diag.check()
        self.assertEqual(self.certbot_calls(), [])

    def test_candidate_permission_or_content_drift_rejected(self):
        self.host.path(CANDIDATE).chmod(0o644)
        with self.assertRaises(PreparationError):
            self.diag.check()
        self.host.path(CANDIDATE).chmod(0o600)
        self.host.path(CANDIDATE).write_bytes(self.old)
        with self.assertRaises(PreparationError):
            self.diag.check()
        self.assertEqual(self.certbot_calls(), [])

    def test_active_timer_rejected_without_stopping_it(self):
        self.host.active.add("certbot.timer")
        self.host.enabled.add("certbot.timer")
        with self.assertRaises(PreparationError):
            self.diag.check()
        self.assertIn("certbot.timer", self.host.active)
        self.assert_no_management_writes()
        self.assertEqual(self.certbot_calls(), [])

    def test_other_pending_change_rejected(self):
        for name in ("key-rotation-intent", "port-change-intent"):
            self.prep._record(name, {})
            with self.assertRaises(PreparationError):
                self.diag.check()
            self.host.path(STATE + "/" + name + ".json").unlink()
        self.assertEqual(self.certbot_calls(), [])

    def test_intent_binding_change_rejected(self):
        intent = self.prep._read_record(INTENT)
        intent["binding"] = "a" * 64
        self.host.path(STATE + "/" + INTENT + ".json").write_text(json.dumps(intent))
        with self.assertRaises(PreparationError):
            self.diag.check()
        self.assertEqual(self.certbot_calls(), [])

    def test_missing_explicit_confirmation_has_no_effect(self):
        plan = self.diag.check()
        self.host.calls.clear()
        for value in (False, 1, None):
            with self.assertRaises(PreparationError):
                self.diag.run(plan, confirm_probe=value)
        self.assertEqual(self.host.calls, [])
        self.assertFalse(self.prep._exists(STARTED))

    def test_stale_plan_rejected(self):
        plan = self.diag.check()
        path = self.host.path(CANDIDATE)
        data = path.read_bytes()
        path.rename(path.with_name("old-candidate"))
        self.host.write(CANDIDATE, data)
        with self.assertRaises(PreparationError):
            self.diag.run(plan, confirm_probe=True)
        self.assertEqual(self.certbot_calls(), [])

    def test_pending_guard_still_blocks_ordinary_export_and_management(self):
        self.diag.check()
        with self.assertRaises(ClientError):
            read_client(root=self.root)
        with self.assertRaises(PreparationError):
            self.tokens.check()

    def test_cli_opt_in_and_no_token_argument(self):
        for args in (["diagnose-token"], ["diagnose-token", "--experimental", "--token", NEW_TOKEN]):
            with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                try:
                    result = main(args)
                except SystemExit as exc:
                    result = exc.code
            self.assertEqual(result, 2)
            self.assertNotIn(NEW_TOKEN, out.getvalue() + err.getvalue())
        self.assertEqual(self.certbot_calls(), [])

    def test_ui_cancel_and_noninteractive_never_probe(self):
        @contextmanager
        def factory():
            yield self.tokens
        ui = Console(["n"])
        self.assertEqual(run_token_diagnostic(factory=factory, terminal=ui), 130)
        self.assertEqual(self.certbot_calls(), [])
        self.assertFalse(self.prep._exists(STARTED))
        ui = Console([])
        ui.interactive = lambda: False
        self.assertEqual(run_token_diagnostic(factory=factory, terminal=ui), 2)

    def test_ui_reports_stage_without_exception_or_secret(self):
        @contextmanager
        def factory():
            yield self.tokens
        ui = Console(["y"])
        self.host.local_override = lambda c: Reply(1, NEW_TOKEN) if c.argv[:2] == ("certbot", "renew") else None
        self.assertEqual(run_token_diagnostic(factory=factory, terminal=ui), 1)
        self.assertNotIn(NEW_TOKEN, ui.text)

    def test_changed_formal_lineage_reported_without_rollback(self):
        path = self.host.path("/etc/letsencrypt/renewal/" + self.spec.domain + ".conf")
        before = path.read_bytes()
        def change(c):
            if c.argv[:2] == ("certbot", "renew"):
                path.write_bytes(before + b"\n# external edit\n")
                return Reply(0, success_output())
        self.host.local_override = change
        report = self.run_probe()
        self.assertEqual(report["failure_phase"], "postcheck")
        self.assertFalse(report["postcheck_passed"])
        self.assertEqual(path.read_bytes(), before + b"\n# external edit\n")

    def test_lock_held_during_probe(self):
        def inspect(c):
            if c.argv[:2] == ("certbot", "renew"):
                with self.assertRaises(PreparationError), self.prep._lock():
                    pass
        self.host.local_override = inspect
        self.run_probe()

    def test_unknown_exception_message_not_shown(self):
        @contextmanager
        def factory():
            raise RuntimeError(NEW_TOKEN)
            yield
        ui = Console([])
        self.assertEqual(run_token_diagnostic(factory=factory, terminal=ui), 1)
        self.assertNotIn(NEW_TOKEN, ui.text)
        self.assertIn('"phase": "platform"', ui.text)

    def test_active_certbot_rejected_without_stopping_it(self):
        self.host.local_override = lambda c: Reply(0, "ActiveState=active\nSubState=running\nMainPID=55\nJob=\n") \
            if c.argv[-1] == "ActiveState,SubState,MainPID,Job" else None
        with self.assertRaises(PreparationError):
            self.diag.check()
        self.assertEqual(self.certbot_calls(), [])
        self.assert_no_management_writes()

    def test_symlink_candidate_rejected(self):
        path = self.host.path(CANDIDATE)
        path.unlink()
        path.symlink_to(self.host.path(CREDENTIAL))
        with self.assertRaises(Exception):
            self.diag.check()
        self.assertEqual(self.certbot_calls(), [])

    def test_failed_pause_verification_not_reported_as_still_paused(self):
        def drift(c):
            if c.argv[:2] == ("certbot", "renew"):
                self.host.active.add("certbot.timer")
                self.host.enabled.add("certbot.timer")
                return Reply(0, success_output())
        self.host.local_override = drift
        report = self.run_probe()
        self.assertFalse(report["renewal_paused_verified_after"])
        self.assertFalse(report["postcheck_passed"])
        self.assert_no_management_writes()

    def test_new_current_record_during_probe_is_not_ignored(self):
        def drift(c):
            if c.argv[:2] == ("certbot", "renew"):
                self.prep._record(CURRENT, {})
                return Reply(0, success_output())
        self.host.local_override = drift
        report = self.run_probe()
        self.assertFalse(report["postcheck_passed"])
        self.assertEqual(report["failure_phase"], "postcheck")


class PermissionRecheckTests(unittest.TestCase):
    def setUp(self):
        TokenDiagnosticTests.setUp(self)
        self.failure = ("dns-01 challenge for " + self.spec.domain + "\n"
                        "Encountered CloudFlareAPIError adding TXT record: 10000 Authentication error\n")
        self.host.local_override = lambda c: Reply(1, self.failure) if c.argv[:2] == ("certbot", "renew") else None
        self.previous = self.diag.run(self.diag.check(), confirm_probe=True)
        self.assertTrue(self.previous["postcheck_passed"])
        self.host.local_override = None
        self.host.calls.clear()
        self.diag = TokenDiagnostic(self.tokens, after_permission_fix=True)

    run_probe = TokenDiagnosticTests.run_probe
    certbot_calls = TokenDiagnosticTests.certbot_calls
    assert_no_management_writes = TokenDiagnosticTests.assert_no_management_writes

    def test_one_recheck_preserves_all_prior_files_and_does_not_commit(self):
        before = test_tokenchange.TokenChangeTests.snapshot(self)
        report = self.run_probe()
        self.assertEqual(report["result"], "candidate-probe-passed-not-committed")
        self.assertEqual(report["attempt"], "after-permission-fix")
        self.assertTrue(report["postcheck_passed"])
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assertTrue(report["report_saved"])
        self.assertEqual(self.prep._read_record(RECHECK_REPORT), report)
        self.assertEqual(self.prep._read_record(REPORT), self.previous)
        after = test_tokenchange.TokenChangeTests.snapshot(self)
        for path, value in before.items():
            self.assertEqual(after[path], value, path)
        command, = self.certbot_calls()
        args = command.argv
        self.assertEqual(args[args.index("--logs-dir") + 1], RECHECK_LOGS)
        self.assertEqual(args[args.index("--dns-cloudflare-credentials") + 1], CANDIDATE)
        self.assertIn("--no-random-sleep-on-renew", args)
        self.assertIn("--dry-run", args)
        self.assertEqual(command.timeout, 600)
        self.assertEqual(self.host.path(RECHECK_LOGS).stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.host.path(RECHECK_LOGS + "/command-output.txt").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertTrue(self.host.path(CANDIDATE).exists())
        self.assertTrue(self.prep._exists(INTENT))
        self.assertFalse(self.prep._exists(CURRENT))
        self.assertNotIn("certbot.timer", self.host.enabled)
        self.assert_no_management_writes()

    def test_existing_recheck_paths_stop_without_overwriting(self):
        for path in (STATE + "/" + RECHECK_STARTED + ".json",
                     STATE + "/" + RECHECK_REPORT + ".json", RECHECK_LOGS):
            self.host.path(path).symlink_to("/unrelated")
            with self.assertRaises(Exception):
                self.diag.check()
            self.assertTrue(self.host.path(path).is_symlink())
            self.host.path(path).unlink()
        self.assertEqual(self.certbot_calls(), [])

    def test_no_third_probe_after_success_or_failure(self):
        self.host.local_override = lambda c: Reply(1, self.failure) if c.argv[:2] == ("certbot", "renew") else None
        self.run_probe()
        with self.assertRaises(PreparationError):
            self.run_probe()
        self.assertEqual(len(self.certbot_calls()), 1)

    def test_success_also_blocks_third_probe(self):
        self.run_probe()
        with self.assertRaises(PreparationError):
            self.run_probe()
        self.assertEqual(len(self.certbot_calls()), 1)

    def test_uncertain_recheck_retains_records_and_blocks_retry(self):
        self.host.local_override = lambda c: Reply(-1, uncertain=True) if c.argv[:2] == ("certbot", "renew") else None
        report = self.run_probe()
        self.assertEqual(report["result"], "execution-uncertain")
        self.assertTrue(self.prep._exists(RECHECK_STARTED))
        self.assertEqual(self.prep._read_record(REPORT), self.previous)
        with self.assertRaises(PreparationError):
            self.run_probe()
        self.assertEqual(len(self.certbot_calls()), 1)

    def test_different_error_or_later_phase_is_out_of_scope(self):
        from snellctl.tokendiag import summarize
        path = self.host.path(LOGS + "/command-output.txt")
        report_path = self.host.path(STATE + "/" + REPORT + ".json")
        cases = [self.failure.replace("10000", "10009"), self.failure.replace("Authentication error", "Internal error"),
                 self.failure + "Waiting 60 seconds for DNS changes to propagate\n",
                 self.failure + "Encountered CloudFlareAPIError deleting TXT record: Authentication error\n"]
        for text in cases:
            path.write_text(text)
            report_path.write_text(json.dumps({**self.previous, "certbot": summarize(self.spec, Reply(1, text))}))
            with self.assertRaises(PreparationError):
                self.diag.check()
        self.assertEqual(self.certbot_calls(), [])

    def test_original_entry_still_blocked(self):
        with self.assertRaises(PreparationError):
            TokenDiagnostic(self.tokens).check()
        self.assertEqual(self.certbot_calls(), [])

    def test_missing_prior_report_is_not_bypassed(self):
        self.host.path(STATE + "/" + REPORT + ".json").unlink()
        with self.assertRaises(Exception):
            self.diag.check()
        self.assertFalse(self.prep._exists(RECHECK_STARTED))
        self.assertEqual(self.certbot_calls(), [])

    def test_prior_malformed_or_unverified_outcome_rejected(self):
        cases = [
            {"result": "execution-uncertain"}, {"result": "candidate-probe-passed-not-committed"},
            {"postcheck_passed": False}, {"renewal_paused_verified_after": False},
            {"report_saved": False}, {"certbot_attempted": False}, {"failure_phase": "postcheck"},
            {"certbot": []}, {"certbot": {**self.previous["certbot"], "exit_code": True}},
            {"certbot": {**self.previous["certbot"], "execution_uncertain": True}},
        ]
        path = self.host.path(STATE + "/" + REPORT + ".json")
        original = path.read_bytes()
        for changes in cases:
            with self.subTest(changes=changes):
                path.write_text(json.dumps({**self.previous, **changes}))
                with self.assertRaises(Exception):
                    self.diag.check()
                path.write_bytes(original)
        self.assertEqual(self.certbot_calls(), [])

    def test_old_output_changes_and_symlinks_rejected(self):
        path = self.host.path(LOGS + "/command-output.txt")
        original = path.read_bytes()
        for content in (b"", original.replace(b"10000", b"91090"), original + b"extra"):
            path.write_bytes(content)
            with self.assertRaises(PreparationError):
                self.diag.check()
        path.write_bytes(original)
        path.chmod(0o644)
        with self.assertRaises(Exception):
            self.diag.check()
        path.unlink()
        path.symlink_to(self.host.path(CREDENTIAL))
        with self.assertRaises(Exception):
            self.diag.check()
        self.assertEqual(self.certbot_calls(), [])

    def test_mismatched_previous_binding_rejected(self):
        self.host.path(STATE + "/" + STARTED + ".json").write_text(
            json.dumps({"format": 1, "binding": "a" * 64}))
        with self.assertRaises(PreparationError):
            self.diag.check()
        self.assertEqual(self.certbot_calls(), [])

    def test_previous_report_change_after_confirmation_is_rejected(self):
        plan = self.diag.check()
        value = {**self.previous, "elapsed_seconds": self.previous["elapsed_seconds"] + 1}
        self.host.path(STATE + "/" + REPORT + ".json").write_text(json.dumps(value))
        with self.assertRaises(PreparationError):
            self.diag.run(plan, confirm_probe=True)
        self.assertEqual(self.certbot_calls(), [])

    def test_original_output_drift_during_probe_rejected(self):
        def drift(command):
            if command.argv[:2] == ("certbot", "renew"):
                self.host.path(LOGS + "/command-output.txt").write_text("external edit")
                return Reply(0, success_output())
        self.host.local_override = drift
        report = self.run_probe()
        self.assertFalse(report["postcheck_passed"])
        self.assertEqual(report["failure_phase"], "postcheck")
        self.assert_no_management_writes()

    def test_ui_requires_new_confirmation_and_does_not_read_secret(self):
        @contextmanager
        def factory():
            yield self.tokens
        ui = Console(["n"])
        self.assertEqual(run_token_diagnostic(factory=factory, terminal=ui, after_permission_fix=True), 130)
        self.assertEqual(self.certbot_calls(), [])
        self.assertFalse(self.prep._exists(RECHECK_STARTED))
        ui = Console(["y"])
        ui.secret = lambda: self.fail("must not request another token")
        self.assertEqual(run_token_diagnostic(factory=factory, terminal=ui, after_permission_fix=True), 0)
        self.assertIn("权限", ui.text)
        for secret in (TOKEN, NEW_TOKEN, self.before_keys.psk):
            self.assertNotIn(secret, ui.text)

    def test_cli_dispatch_and_opt_in(self):
        with patch("snellctl.tokendiag.run_token_diagnostic", return_value=0) as run:
            self.assertEqual(main(["diagnose-token", "--experimental", "--after-permission-fix"]), 0)
            run.assert_called_once_with(after_permission_fix=True)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["diagnose-token", "--after-permission-fix"]), 2)

    test_candidate_permission_or_content_drift_rejected = TokenDiagnosticTests.test_candidate_permission_or_content_drift_rejected
    test_old_credential_already_replaced_is_rejected = TokenDiagnosticTests.test_old_credential_already_replaced_is_rejected
    test_active_timer_rejected_without_stopping_it = TokenDiagnosticTests.test_active_timer_rejected_without_stopping_it
    test_active_certbot_rejected_without_stopping_it = TokenDiagnosticTests.test_active_certbot_rejected_without_stopping_it
    test_other_pending_change_rejected = TokenDiagnosticTests.test_other_pending_change_rejected
    test_pending_guard_still_blocks_ordinary_export_and_management = TokenDiagnosticTests.test_pending_guard_still_blocks_ordinary_export_and_management
