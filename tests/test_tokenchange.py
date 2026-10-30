from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.client import ClientError, read_client
from snellctl.hostprep import CREDENTIAL, STATE, STAGING, PreparationError, Reply
from snellctl.installer import installation_status, render_status
from snellctl.menu import run_menu
from snellctl.portchange import PortChange
from snellctl.rotation import KeyRotation
from snellctl.tokenchange import (CANDIDATE, CURRENT, INTENT, UNCHANGED_RECORDS, RenewalStateMismatch,
                                 TokenChange, TokenPlan, run_token_change)
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
from test_portchange import PortHost
import test_publish


NEW_TOKEN = "new_test_token_" + "z" * 30
THIRD_TOKEN = "third_test_token_" + "q" * 30


def success_output():
    return (f"dns-01 challenge for {DOMAIN}\nWaiting 60 seconds for DNS changes to propagate\n"
            "Hook 'deploy-hook' ran with output:\n snellctl: nginx reload command succeeded\n"
            f"  /etc/letsencrypt/live/{DOMAIN}/fullchain.pem (success)\n")


class RenewalStateEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.idle = {"ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "Job": ""}
        self.paused = {"ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled"}
        self.public = Mock()
        self.tokens = TokenChange(self.public)

    def mismatch(self, fields):
        self.public._fields.return_value = fields
        with self.assertRaises(RenewalStateMismatch) as caught:
            self.tokens._idle()
        self.public._fields.assert_called_once_with("certbot.service", "ActiveState,SubState,MainPID,Job")
        return caught.exception

    def test_exact_idle_passes_with_one_unchanged_query(self):
        self.public._fields.return_value = dict(reversed(list(self.idle.items())))
        self.tokens._idle()
        self.public._fields.assert_called_once_with("certbot.service", "ActiveState,SubState,MainPID,Job")

    def test_missing_job_is_not_reported_as_empty_or_busy(self):
        fields = {key: value for key, value in self.idle.items() if key != "Job"}
        evidence = self.mismatch(fields).evidence
        self.assertEqual(evidence["missing_fields"], ["Job"])
        self.assertEqual(evidence["mismatched_fields"], [])
        self.assertNotIn("Job", evidence["observed"])
        self.assertEqual(evidence["source"], "failed-comparison")

    def test_extra_field_still_blocks_without_exposing_its_name_or_value(self):
        evidence = self.mismatch({**self.idle, "SECRET-NAME": "SECRET-VALUE"}).evidence
        self.assertTrue(evidence["unexpected_fields_present"])
        self.assertEqual(evidence["missing_fields"], [])
        self.assertEqual(evidence["mismatched_fields"], [])
        self.assertEqual(evidence["observed"], self.idle)
        self.assertNotIn("SECRET", json.dumps(evidence))

    def test_active_service_observation_is_copied_not_requeried(self):
        fields = {**self.idle, "ActiveState": "active", "SubState": "running", "MainPID": "123"}
        evidence = self.mismatch(fields).evidence
        fields.update(self.idle)
        self.assertEqual(evidence["observed"]["MainPID"], "123")
        self.assertEqual(evidence["expected"], self.idle)
        self.assertEqual(evidence["mismatched_fields"], ["ActiveState", "MainPID", "SubState"])
        self.assertEqual(self.public._fields.call_count, 1)

    def test_nonempty_job_is_redacted_not_assumed_to_be_a_valid_job_id(self):
        evidence = self.mismatch({**self.idle, "Job": "PRIVATE-JOB-PATH"}).evidence
        self.assertEqual(evidence["observed"]["Job"], "[nonempty-redacted]")
        self.assertEqual(evidence["mismatched_fields"], ["Job"])
        self.assertNotIn("PRIVATE", json.dumps(evidence))

    def test_unknown_states_control_characters_and_oversized_pid_are_redacted(self):
        fields = {"ActiveState": "SECRET\x1b[31m", "SubState": "SECRET\nPRIVATE",
                  "MainPID": "9" * 10000, "Job": "SECRET"}
        error = self.mismatch(fields)
        text = json.dumps(error.evidence) + repr(error)
        self.assertNotIn("SECRET", text)
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn("999999", text)
        self.assertLess(len(text), 1500)

    def test_non_string_values_are_not_rendered(self):
        evidence = self.mismatch({key: {"SECRET": "PRIVATE"} for key in self.idle}).evidence
        self.assertTrue(all(value == "[unrecognized-redacted]" for value in evidence["observed"].values()))
        self.assertNotIn("SECRET", json.dumps(evidence))

    def test_empty_output_reports_all_missing_fields(self):
        evidence = self.mismatch({}).evidence
        self.assertEqual(evidence["missing_fields"], sorted(self.idle))
        self.assertEqual(evidence["observed"], {})

    def test_present_but_empty_values_are_distinct_from_missing_or_unknown(self):
        evidence = self.mismatch(dict.fromkeys(self.idle, "")).evidence
        self.assertEqual(evidence["missing_fields"], [])
        self.assertEqual(evidence["observed"], dict.fromkeys(self.idle, ""))
        self.assertEqual(evidence["mismatched_fields"], ["ActiveState", "MainPID", "SubState"])

    def test_known_failed_and_transition_states_do_not_pass(self):
        for active, substate in (("failed", "failed"), ("activating", "start"), ("deactivating", "stop")):
            with self.subTest(active=active):
                self.public.reset_mock()
                evidence = self.mismatch({**self.idle, "ActiveState": active, "SubState": substate}).evidence
                self.assertEqual(evidence["observed"]["ActiveState"], active)
                self.assertEqual(evidence["observed"]["SubState"], substate)

    def test_timer_mismatch_never_queries_service_and_hides_unknown_value(self):
        self.public._fields.return_value = {**self.paused, "UnitFileState": "PRIVATE"}
        with self.assertRaises(RenewalStateMismatch) as caught:
            self.tokens._paused()
        self.public._fields.assert_called_once_with("certbot.timer", "ActiveState,SubState,UnitFileState")
        self.assertEqual(caught.exception.evidence["unit"], "certbot.timer")
        self.assertEqual(caught.exception.evidence["mismatched_fields"], ["UnitFileState"])
        self.assertNotIn("PRIVATE", json.dumps(caught.exception.evidence))

    def test_successful_pause_keeps_original_two_queries(self):
        self.public._fields.side_effect = [self.paused, self.idle]
        self.tokens._paused()
        self.assertEqual(self.public._fields.call_args_list, [
            unittest.mock.call("certbot.timer", "ActiveState,SubState,UnitFileState"),
            unittest.mock.call("certbot.service", "ActiveState,SubState,MainPID,Job"),
        ])

    def test_query_error_is_not_replaced_with_fabricated_state_or_retried(self):
        failure = PreparationError("query failed")
        self.public._fields.side_effect = failure
        with self.assertRaises(PreparationError) as caught:
            self.tokens._idle()
        self.assertIs(caught.exception, failure)
        self.assertFalse(hasattr(failure, "evidence"))
        self.assertEqual(self.public._fields.call_count, 1)


class TokenHost(PortHost):
    def _dispatch(self, command):
        args = command.argv
        result = None
        if args == ("systemctl", "disable", "--now", "certbot.timer"):
            self.active.discard("certbot.timer")
            self.enabled.discard("certbot.timer")
            result = Reply(0)
        elif args[:3] == ("systemctl", "show", "certbot.service") and args[-1] == "ActiveState,SubState,MainPID,Job":
            result = Reply(0, "ActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\n")
        elif args[:3] == ("systemctl", "show", "certbot.timer") and args[-1] == "ActiveState,SubState,UnitFileState":
            active = "certbot.timer" in self.active
            enabled = "enabled" if "certbot.timer" in self.enabled else "disabled"
            result = Reply(0, f"ActiveState={'active' if active else 'inactive'}\n"
                             f"SubState={'waiting' if active else 'dead'}\nUnitFileState={enabled}\n")
        elif args[:3] == ("systemctl", "show", "certbot.timer") and "Triggers" in args[-1] and "certbot.timer" not in self.active:
            result = Reply(0, "ActiveState=inactive\nSubState=dead\nUnitFileState=disabled\n")
        elif args[:2] == ("certbot", "renew") and "--dns-cloudflare-credentials" in args:
            result = Reply(0, success_output())
        if result is not None:
            self.calls.append(command)
            return result
        return super()._dispatch(command)


class TokenChangeTests(unittest.TestCase):
    def setUp(self):
        with patch("test_publish.PublicHost", TokenHost):
            test_publish.PublicationTests.setUp(self)
        test_publish.PublicationTests.enable(self)
        self.tokens = TokenChange(self.engine)
        self.before_keys = read_client(root=self.root).keys
        self.old = self.host.path(CREDENTIAL).read_bytes()
        self.host.calls.clear()
        self.probe.reset_mock()

    def change(self, token=NEW_TOKEN):
        return self.tokens.change(self.tokens.check(), token, confirm_change=True)

    def mutations(self):
        return [c.argv for c in self.host.calls if c.argv[:2] in {
            ("systemctl", "start"), ("systemctl", "stop"), ("systemctl", "enable"),
            ("systemctl", "disable"), ("systemctl", "restart"), ("systemctl", "reload"),
            ("certbot", "renew"), ("ufw", "allow"), ("ufw", "delete"),
        }]

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.lstat().st_mode, p.lstat().st_ino,
                str(p.readlink()) if p.is_symlink() else p.read_bytes() if p.is_file() else None)
                for p in self.root.rglob("*")}

    def assert_pending(self):
        self.assertEqual(installation_status(root=self.root)["token_change"], "needs-inspection")
        self.assertIn("Token 更换：未确认完成", render_status(installation_status(root=self.root)))
        with self.assertRaises(ClientError):
            read_client(root=self.root)
        for check in (self.tokens.check, lambda: KeyRotation(self.engine).check("snell"),
                      lambda: PortChange(self.engine).check(24443),
                      lambda: test_publish.PublicationTests.enable(self)):
            with self.assertRaises(Exception):
                check()
        self.assertTrue({"nginx.service", self.spec.snell_service, self.spec.shadowtls_service} <= self.host.active)
        self.assertIn("ufw.service", self.host.enabled)

    def assert_paused(self):
        self.assert_pending()
        self.assertNotIn("certbot.timer", self.host.active)
        self.assertNotIn("certbot.timer", self.host.enabled)

    def test_success_only_replaces_credential_and_current_metadata(self):
        before = self.snapshot()
        self.assertEqual(self.change(), "token-changed-renewal-tested")
        after = self.snapshot()
        self.assertEqual({p for p in before.keys() | after.keys() if before.get(p) != after.get(p)},
                         {CREDENTIAL.lstrip("/"), (STATE + "/" + CURRENT + ".json").lstrip("/")})
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), f"dns_cloudflare_api_token = {NEW_TOKEN}\n".encode())
        self.assertEqual(self.host.path(CREDENTIAL).stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.host.path(CANDIDATE).exists())
        self.assertFalse(self.prep._exists(INTENT))
        self.assertEqual(read_client(root=self.root).keys, self.before_keys)
        self.assertIn("certbot.timer", self.host.active)
        self.assertIn("certbot.timer", self.host.enabled)
        calls = self.mutations()
        self.assertEqual(calls[0], ("systemctl", "disable", "--now", "certbot.timer"))
        self.assertEqual(calls[-1], ("systemctl", "enable", "--now", "certbot.timer"))
        self.assertEqual(len(calls), 4)
        for command, path in zip((calls[1], calls[2]), (CANDIDATE, CREDENTIAL)):
            self.assertEqual(command[:2], ("certbot", "renew"))
            self.assertEqual(command[command.index("--server") + 1], STAGING)
            self.assertEqual(command[command.index("--cert-name") + 1], DOMAIN)
            self.assertEqual(command[command.index("--dns-cloudflare-credentials") + 1], path)
            self.assertIn("--dry-run", command)
            self.assertIn("--run-deploy-hooks", command)
            self.assertNotIn("--force-renewal", command)
        for command in self.host.calls:
            for secret in (TOKEN, NEW_TOKEN, self.before_keys.psk, self.before_keys.shadowtls_password):
                self.assertNotIn(secret, repr(command))

    def test_candidate_verified_before_existing_credential_changes(self):
        seen = []
        def inspect(command):
            if command.argv[:2] == ("certbot", "renew"):
                seen.append(self.host.path(CREDENTIAL).read_bytes())
                self.assertEqual(self.host.path(CANDIDATE).stat().st_mode & 0o777, 0o600)
        self.host.local_override = inspect
        self.change()
        self.assertEqual(seen, [self.old, f"dns_cloudflare_api_token = {NEW_TOKEN}\n".encode()])

    def test_repeat_change_uses_new_current_record(self):
        self.change()
        self.change(THIRD_TOKEN)
        self.assertIn(THIRD_TOKEN.encode(), self.host.path(CREDENTIAL).read_bytes())
        self.assertEqual(read_client(root=self.root).keys, self.before_keys)

    def test_compatible_with_port_and_key_changes(self):
        self.change()
        ports = PortChange(self.engine)
        ports.change(ports.check(24443), confirm_change=True, confirm_ssh_reconnected=True)
        rotation = KeyRotation(self.engine)
        rotation.rotate(rotation.check("snell"), confirm_change=True, confirm_ssh_reconnected=True)
        self.change(THIRD_TOKEN)
        self.assertEqual(read_client(root=self.root).public_port, 24443)

    def test_missing_confirmation_or_invalid_token_causes_no_commands(self):
        plan = self.tokens.check()
        self.host.calls.clear()
        for value in (False, 1, None):
            with self.assertRaises(PreparationError):
                self.tokens.change(plan, NEW_TOKEN, confirm_change=value)
        for token in ("", "short", NEW_TOKEN + "\n", "x" * 257, None, NEW_TOKEN + "' ;"):
            with self.assertRaises(PreparationError):
                self.tokens.change(plan, token, confirm_change=True)
        self.assertEqual(self.host.calls, [])

    def test_same_token_rejected_without_writes(self):
        before = self.snapshot()
        with self.assertRaises(PreparationError):
            self.change(TOKEN)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.mutations(), [])

    def test_stale_plan_rejected(self):
        plan = self.tokens.check()
        self.change()
        with self.assertRaises(PreparationError):
            self.tokens.change(plan, THIRD_TOKEN, confirm_change=True)
        self.assertFalse(self.prep._exists(INTENT))

    def test_stale_credential_identity_rejected(self):
        plan = self.tokens.check()
        path = self.host.path(CREDENTIAL)
        path.unlink()
        self.host.write(CREDENTIAL, self.old)
        with self.assertRaises(PreparationError):
            self.tokens.change(plan, NEW_TOKEN, confirm_change=True)
        self.assertEqual(self.mutations(), [])

    def test_credential_drift_after_completed_change_rejected(self):
        self.change()
        self.host.write(CREDENTIAL, self.old)
        self.host.calls.clear()
        with self.assertRaises(PreparationError):
            self.tokens.check()
        self.assertEqual(self.mutations(), [])

    def test_candidate_or_partial_file_is_not_overwritten(self):
        for path in (CANDIDATE, CREDENTIAL + ".snellctl-new", STATE + "/" + CURRENT + ".json.snellctl-new"):
            with self.subTest(path=path):
                self.host.path(path).symlink_to("/unrelated")
                with self.assertRaises(PreparationError):
                    self.tokens.check()
                self.assertTrue(self.host.path(path).is_symlink())
                self.host.path(path).unlink()
        self.assertEqual(self.mutations(), [])

    def test_insecure_credential_or_directory_rejected(self):
        for path, mode, correct in ((CREDENTIAL, 0o644, 0o600), ("/etc/snellctl/credentials", 0o755, 0o700)):
            self.host.path(path).chmod(mode)
            with self.assertRaises(PreparationError):
                self.tokens.check()
            self.host.path(path).chmod(correct)
        self.assertEqual(self.mutations(), [])

    def test_active_or_queued_certbot_rejected_without_stopping_it(self):
        for state in ("ActiveState=active\nSubState=running\nMainPID=123\nJob=\n",
                      "ActiveState=inactive\nSubState=dead\nMainPID=0\nJob=123\n"):
            self.host.local_override = lambda c: Reply(0, state) if c.argv[-1] == "ActiveState,SubState,MainPID,Job" else None
            with self.assertRaises(PreparationError):
                self.tokens.check()
        self.assertEqual(self.mutations(), [])

    def test_certbot_racing_timer_pause_is_not_killed(self):
        def race(c):
            if c.argv[-1] == "ActiveState,SubState,MainPID,Job" and "certbot.timer" not in self.host.active:
                return Reply(0, "ActiveState=active\nSubState=running\nMainPID=123\nJob=\n")
        self.host.local_override = race
        with self.assertRaisesRegex(PreparationError, "不确定"):
            self.change()
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertNotIn(("systemctl", "stop", "certbot.service"), self.mutations())
        self.assert_pending()

    def test_failed_candidate_test_preserves_old_credential_and_node(self):
        self.host.local_override = lambda c: Reply(1, NEW_TOKEN) if c.argv[:2] == ("certbot", "renew") else None
        with self.assertRaises(PreparationError) as caught:
            self.change()
        self.assertNotIn(NEW_TOKEN, str(caught.exception))
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertTrue(self.host.path(CANDIDATE).exists())
        self.assert_paused()

    def test_uncertain_or_interrupt_candidate_test_is_not_retried(self):
        def fail(c):
            if c.argv[:2] == ("certbot", "renew"):
                raise KeyboardInterrupt()
        self.host.local_override = fail
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assert_paused()

    def test_timeout_candidate_test_preserves_state(self):
        self.host.local_override = lambda c: Reply(-1, uncertain=True) if c.argv[:2] == ("certbot", "renew") else None
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_paused()

    def test_zero_exit_without_fresh_dns_or_hook_evidence_fails(self):
        outputs = ["", success_output().replace("snellctl: nginx reload command succeeded", "hook failed"),
                   success_output().replace("dns-01 challenge for " + DOMAIN, ""),
                   success_output().replace("Waiting 60 seconds for DNS changes to propagate", ""),
                   success_output().replace(" (success)", " (skipped)"),
                   success_output() + "Certbot was unable to obtain fresh authorizations for every domain\n",
                   success_output() + "Encountered CloudFlareAPIError deleting TXT record: error\n"]
        for output in outputs:
            with self.subTest(output=output):
                self.host.local_override = lambda c: Reply(0, output) if c.argv[:2] == ("certbot", "renew") else None
                with self.assertRaises(PreparationError):
                    self.tokens._dry_run(self.spec, CANDIDATE)

    def test_pending_deprecation_warning_does_not_fail_success(self):
        self.host.local_override = lambda c: Reply(0, "PendingDeprecationWarning\n" + success_output()) \
            if c.argv[:2] == ("certbot", "renew") else None
        self.assertEqual(self.change(), "token-changed-renewal-tested")

    def test_second_test_failure_leaves_new_credential_no_rollback(self):
        def fail(c):
            if c.argv[:2] == ("certbot", "renew") and CREDENTIAL in c.argv:
                return Reply(1)
        self.host.local_override = fail
        with self.assertRaises(PreparationError):
            self.change()
        self.assertIn(NEW_TOKEN.encode(), self.host.path(CREDENTIAL).read_bytes())
        self.assert_paused()

    def test_renewal_config_changed_by_dry_run_stops_before_credential_switch(self):
        def edit(c):
            if c.argv[:2] == ("certbot", "renew"):
                path = self.host.path("/etc/letsencrypt/renewal/" + DOMAIN + ".conf")
                path.write_bytes(path.read_bytes() + b"# external change\n")
        self.host.local_override = edit
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assert_paused()

    def test_candidate_mutation_not_installed_or_deleted(self):
        def edit(c):
            if c.argv[:2] == ("certbot", "renew"):
                self.host.write(CANDIDATE, b"foreign\n")
        self.host.local_override = edit
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertEqual(self.host.path(CANDIDATE).read_bytes(), b"foreign\n")
        self.assert_paused()

    def test_active_credential_changed_during_test_not_overwritten(self):
        def edit(c):
            if c.argv[:2] == ("certbot", "renew"):
                self.host.write(CREDENTIAL, b"foreign\n")
        self.host.local_override = edit
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), b"foreign\n")
        self.assert_paused()

    def test_current_record_write_failure_retains_intent(self):
        original = self.prep._record
        def fail(name, value):
            if name == CURRENT:
                raise OSError("test")
            original(name, value)
        with patch.object(self.prep, "_record", side_effect=fail), self.assertRaises(PreparationError):
            self.change()
        self.assert_paused()

    def test_failed_timer_restore_does_not_report_completion(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "enable", "--now", "certbot.timer") else None
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_paused()

    def test_failed_pause_is_reported_uncertain(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "disable", "--now", "certbot.timer") else None
        with self.assertRaisesRegex(PreparationError, "不确定"):
            self.change()
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assert_pending()

    def test_failed_unlink_fsync_restores_intent(self):
        unlink = self.prep.files.unlink_owned
        def fail(path, identity):
            unlink(path, identity)
            if path.endswith(INTENT + ".json"):
                raise OSError("fsync")
        with patch.object(self.prep.files, "unlink_owned", side_effect=fail), self.assertRaises(PreparationError):
            self.change()
        self.assert_paused()

    def test_foreign_intent_not_deleted(self):
        def edit(c):
            if c.argv == ("systemctl", "enable", "--now", "certbot.timer"):
                self.host.write(STATE + "/" + INTENT + ".json", b'{"foreign": true}\n')
        self.host.local_override = edit
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.prep._read_record(INTENT), {"foreign": True})
        self.assert_paused()

    def test_records_contain_no_tokens_domain_or_key(self):
        self.change()
        data = json.dumps(self.prep._read_record(CURRENT))
        for secret in (TOKEN, NEW_TOKEN, DOMAIN, self.before_keys.psk, self.before_keys.shadowtls_password):
            self.assertNotIn(secret, data)
        self.host.local_override = lambda c: Reply(1) if c.argv[:2] == ("certbot", "renew") else None
        with self.assertRaises(PreparationError):
            self.change(THIRD_TOKEN)
        data = json.dumps(self.prep._read_record(INTENT))
        for secret in (TOKEN, NEW_TOKEN, THIRD_TOKEN, DOMAIN, self.before_keys.psk):
            self.assertNotIn(secret, data)

    def test_unrelated_record_drift_during_candidate_test_blocks_commit(self):
        def edit(c):
            if c.argv[:2] == ("certbot", "renew"):
                self.host.write(STATE + "/public-ready.json", b'{"foreign": true}\n')
        self.host.local_override = edit
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertEqual(self.prep._read_record("public-ready"), {"foreign": True})
        self.assert_paused()

    def test_record_drift_on_timer_restore_blocks_success(self):
        def edit(c):
            if c.argv == ("systemctl", "enable", "--now", "certbot.timer"):
                self.host.write(STATE + "/public-files.json", b'{"foreign": true}\n')
        self.host.local_override = edit
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_paused()

    def test_record_snapshot_covers_all_current_records(self):
        plan = self.tokens.check()
        for name in UNCHANGED_RECORDS:
            with self.subTest(name=name):
                path = self.host.path(STATE + "/" + name + ".json")
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                with self.assertRaises(PreparationError):
                    self.tokens.change(plan, NEW_TOKEN, confirm_change=True)
                path.write_bytes(original)
        self.assertEqual(self.mutations(), [])

    def test_pending_mutations_rejected_without_commands(self):
        for name in ("key-rotation-intent", "port-change-intent", INTENT):
            path = self.host.path(STATE + "/" + name + ".json")
            path.symlink_to("/unrelated")
            with self.assertRaises(PreparationError):
                self.tokens.check()
            path.unlink()
        self.assertEqual(self.host.calls, [])

    def test_lock_is_held_during_both_dns_operations(self):
        from snellctl.hostprep import Preparation
        def check(c):
            if c.argv[:2] == ("certbot", "renew"):
                with Preparation(self.root, self.host) as prep:
                    with self.assertRaisesRegex(PreparationError, "已有准备操作"):
                        with prep._lock():
                            self.fail("lock not held")
        self.host.local_override = check
        self.change()

    def test_timer_pause_zero_exit_without_state_change_is_failure(self):
        self.host.local_override = lambda c: Reply(0) if c.argv == ("systemctl", "disable", "--now", "certbot.timer") else None
        with self.assertRaisesRegex(PreparationError, "不确定"):
            self.change()
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertFalse(self.host.path(CANDIDATE).exists())

    def test_plan_repr_has_no_domain_or_secret_fingerprint(self):
        plan = self.tokens.check()
        self.assertNotIn(DOMAIN, repr(plan))
        self.assertNotIn(plan.revision, repr(plan))

    def test_node_config_drift_during_dns_is_not_repaired(self):
        def edit(c):
            if c.argv[:2] == ("certbot", "renew"):
                self.host.write(self.spec.nginx_conf, b"foreign\n", 0o644)
        self.host.local_override = edit
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertEqual(self.host.path(self.spec.nginx_conf).read_bytes(), b"foreign\n")
        self.assert_paused()


class TokenWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.engine = Mock()
        self.plan = TokenPlan(DOMAIN, "d" * 64)
        self.engine.check.return_value = self.plan
        self.engine.change.return_value = "token-changed-renewal-tested"
        self.ui = Console(["y"])
        self.ui.secret.return_value = NEW_TOKEN

    @contextmanager
    def factory(self):
        yield self.engine

    def run_change(self):
        return run_token_change(factory=self.factory, terminal=self.ui)

    def test_success_has_hidden_input_and_no_secret_output(self):
        self.assertEqual(self.run_change(), 0)
        self.ui.secret.assert_called_once_with()
        self.engine.change.assert_called_once_with(self.plan, NEW_TOKEN, confirm_change=True)
        self.assertNotIn(NEW_TOKEN, self.ui.text)
        self.assertIn("不需要更新 Surge", self.ui.text)

    def test_cancel_before_reading_secret(self):
        for value in ("", "n", "N", "yes", "同意", EOFError(), KeyboardInterrupt()):
            self.ui = Console([value])
            self.assertEqual(self.run_change(), 130)
            self.ui.secret.assert_not_called()
        self.engine.change.assert_not_called()

    def test_noninteractive_does_not_open_host_adapter(self):
        self.ui.interactive = lambda: False
        factory = Mock()
        self.assertEqual(run_token_change(factory=factory, terminal=self.ui), 2)
        factory.assert_not_called()

    def test_tty_lost_before_or_after_secret_does_not_write(self):
        for states in ([True, False], [True, True, False]):
            self.ui = Console(["Y"])
            self.ui.interactive = Mock(side_effect=states)
            self.assertEqual(self.run_change(), 1)
        self.engine.change.assert_not_called()

    def test_secret_prompt_interruption_has_no_mutation(self):
        self.ui.secret.side_effect = KeyboardInterrupt()
        self.assertEqual(self.run_change(), 130)
        self.engine.change.assert_not_called()

    def test_failure_redacted_and_no_claim_of_rollback(self):
        self.engine.change.side_effect = RuntimeError(NEW_TOKEN)
        self.assertEqual(self.run_change(), 1)
        self.assertNotIn(NEW_TOKEN, self.ui.text)
        self.assertIn("自动续期可能已停用", self.ui.text)
        self.assertNotIn("已回滚", self.ui.text)

    def test_unknown_result_is_not_success(self):
        self.engine.change.return_value = "unknown"
        self.assertEqual(self.run_change(), 1)
        self.assertNotIn("Token 已更换", self.ui.text)

    def test_cli_opt_in_and_no_secret_argument(self):
        with patch("snellctl.tokenchange.run_token_change", return_value=130) as run, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["change-token"]), 2)
            run.assert_not_called()
            self.assertEqual(main(["change-token", "--experimental"]), 130)
            run.assert_called_once_with()
        for option in ("--token", "--yes", "--force", "--root"):
            with redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
                main(["change-token", "--experimental", option, NEW_TOKEN])
            self.assertNotIn(NEW_TOKEN, err.getvalue())

    def test_menu_opt_in_required(self):
        for experimental in (False, True):
            with patch("snellctl.tokenchange.run_token_change", return_value=0) as run, \
                    patch("builtins.input", side_effect=["10", "0"]), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(run_menu(experimental=experimental), 0)
                self.assertEqual(run.call_count, int(experimental))
                self.assertEqual("10. 更换 Cloudflare Token" in out.getvalue(), experimental)
