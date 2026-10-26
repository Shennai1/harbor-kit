from contextlib import contextmanager, redirect_stderr
import io
import json
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.client import read_client
from snellctl.hostprep import CREDENTIAL, STATE, STAGING, PreparationError, Reply
from snellctl.tokenchange import CANDIDATE, CURRENT, INTENT
from snellctl.tokendiag import RECHECK_LOGS, RECHECK_REPORT, RECHECK_STARTED, summarize
from snellctl.tokenresume import LOGS, REPORT, STARTED, TokenResume, run_token_resume
import test_tokendiag
import test_tokenchange
from test_installer import Console
from test_tokenchange import NEW_TOKEN, TOKEN, success_output


class TokenResumeTests(unittest.TestCase):
    def setUp(self):
        test_tokendiag.PermissionRecheckTests.setUp(self)
        report = self.diag.run(self.diag.check(), confirm_probe=True)
        self.assertEqual(report["result"], "candidate-probe-passed-not-committed")
        self.host.calls.clear()
        self.resume = TokenResume(self.tokens)

    snapshot = test_tokenchange.TokenChangeTests.snapshot
    mutations = test_tokenchange.TokenChangeTests.mutations
    assert_pending = test_tokenchange.TokenChangeTests.assert_pending
    assert_paused = test_tokenchange.TokenChangeTests.assert_paused
    certbot_calls = test_tokendiag.TokenDiagnosticTests.certbot_calls

    def finish(self):
        return self.resume.finish(self.resume.check(), confirm_finish=True)

    def test_check_is_read_only(self):
        before = self.snapshot()
        plan = self.resume.check()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.mutations(), [])
        self.assertNotIn(self.spec.domain, repr(plan))
        self.assertNotIn(plan.revision, repr(plan))

    def test_success_commits_known_candidate_tests_fixed_path_and_restores_timer(self):
        before = self.snapshot()
        report = self.finish()
        self.assertEqual(report["result"], "token-changed-renewal-tested")
        self.assertTrue(report["fixed_path_test_passed"])
        self.assertTrue(report["renewal_restored_verified"])
        self.assertTrue(report["report_saved"])
        self.assertFalse(report["renewal_paused_verified_after"])
        self.assertEqual(report["fixed_credential_matches"], "after")
        self.assertEqual(self.prep._read_record(REPORT), report)
        self.assertIn(NEW_TOKEN.encode(), self.host.path(CREDENTIAL).read_bytes())
        self.assertEqual(self.prep._read_record(CURRENT), {"format": 1, **self.tokens._credential(CREDENTIAL)})
        self.assertFalse(self.host.path(CANDIDATE).exists())
        self.assertFalse(self.prep._exists(INTENT))
        self.assertIn("certbot.timer", self.host.enabled)
        self.assertIn("certbot.timer", self.host.active)
        self.assertEqual(read_client(root=self.root).keys, self.before_keys)
        self.tokens.check()
        after = self.snapshot()
        allowed = {p.lstrip('/') for p in (CREDENTIAL, CANDIDATE, STATE + '/' + INTENT + '.json',
                   STATE + '/' + CURRENT + '.json', STATE + '/' + STARTED + '.json', STATE + '/' + REPORT + '.json',
                   LOGS, LOGS + '/command-output.txt')}
        changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
        self.assertEqual(changed, allowed)
        self.assertEqual(self.host.path(LOGS).stat().st_mode & 0o777, 0o700)
        for path in (CREDENTIAL, LOGS + '/command-output.txt', STATE + '/' + REPORT + '.json'):
            self.assertEqual(self.host.path(path).stat().st_mode & 0o777, 0o600)
        command, = self.certbot_calls()
        args = command.argv
        self.assertEqual(args[args.index('--dns-cloudflare-credentials') + 1], CREDENTIAL)
        self.assertEqual(args[args.index('--logs-dir') + 1], LOGS)
        self.assertEqual(args[args.index('--server') + 1], STAGING)
        self.assertIn('--dry-run', args)
        self.assertIn('--no-random-sleep-on-renew', args)
        self.assertIn('--run-deploy-hooks', args)
        self.assertEqual(command.timeout, 600)
        self.assertEqual(len(self.mutations()), 2)
        self.assertEqual(self.mutations()[-1], ('systemctl', 'enable', '--now', 'certbot.timer'))
        for secret in (TOKEN, NEW_TOKEN, self.spec.domain, self.before_keys.psk):
            self.assertNotIn(secret, json.dumps(report))
            self.assertNotIn(secret, json.dumps(self.prep._read_record(STARTED)))

    def test_existing_current_metadata_is_updated(self):
        self.prep._record(CURRENT, {'format': 1, **self.tokens._credential(CREDENTIAL)})
        self.assertEqual(self.finish()['result'], 'token-changed-renewal-tested')
        self.assertEqual(self.prep._read_record(CURRENT), {'format': 1, **self.tokens._credential(CREDENTIAL)})

    def test_repeat_success_blocked(self):
        self.finish()
        with self.assertRaises(PreparationError):
            self.finish()
        self.assertEqual(len(self.certbot_calls()), 1)

    def test_no_confirmation_no_effect(self):
        plan = self.resume.check()
        self.host.calls.clear()
        for value in (False, None, 1):
            with self.assertRaises(PreparationError):
                self.resume.finish(plan, confirm_finish=value)
        self.assertEqual(self.host.calls, [])
        self.assertFalse(self.prep._exists(STARTED))

    def test_stale_plan_candidate_replaced_with_identical_bytes(self):
        plan = self.resume.check()
        path = self.host.path(CANDIDATE)
        data = path.read_bytes()
        path.rename(path.with_name('previous-candidate'))
        self.host.write(CANDIDATE, data)
        with self.assertRaises(PreparationError):
            self.resume.finish(plan, confirm_finish=True)
        self.assertEqual(self.mutations(), [])

    def test_stale_plan_recheck_report_drift(self):
        plan = self.resume.check()
        path = self.host.path(STATE + '/' + RECHECK_REPORT + '.json')
        path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaises(PreparationError):
            self.resume.finish(plan, confirm_finish=True)
        self.assertEqual(self.mutations(), [])

    def test_missing_report_or_wrong_binding_rejected(self):
        path = self.host.path(STATE + '/' + RECHECK_REPORT + '.json')
        data = path.read_bytes()
        path.unlink()
        with self.assertRaises(Exception):
            self.resume.check()
        self.host.write(STATE + '/' + RECHECK_REPORT + '.json', data)
        self.host.path(STATE + '/' + RECHECK_STARTED + '.json').write_text(
            json.dumps({'format': 1, 'binding': '0' * 64}))
        with self.assertRaises(PreparationError):
            self.resume.check()
        self.assertEqual(self.mutations(), [])

    def test_failed_or_uncertain_or_unverified_recheck_is_rejected(self):
        path = self.host.path(STATE + '/' + RECHECK_REPORT + '.json')
        original = json.loads(path.read_text())
        cases = [{'postcheck_passed': False}, {'renewal_paused_verified_after': False}, {'report_saved': False},
                 {'result': 'command-failed'}, {'attempt': 'other'}, {'failure_phase': 'postcheck'},
                 {'certbot': []}, {'certbot': {**original['certbot'], 'exit_code': False}},
                 {'certbot': {**original['certbot'], 'execution_uncertain': True}}]
        for changes in cases:
            path.write_text(json.dumps({**original, **changes}))
            with self.assertRaises(PreparationError):
                self.resume.check()
        self.assertEqual(self.mutations(), [])

    def test_recheck_output_mismatch_or_missing_evidence_rejected(self):
        output = self.host.path(RECHECK_LOGS + '/command-output.txt')
        report_path = self.host.path(STATE + '/' + RECHECK_REPORT + '.json')
        original = json.loads(report_path.read_text())
        output.write_text('modified')
        with self.assertRaises(PreparationError):
            self.resume.check()
        for text in ('nothing to do', success_output() + 'CloudFlareAPIError',
                     success_output().replace('snellctl: nginx reload command succeeded', 'not reloaded')):
            output.write_text(text)
            report_path.write_text(json.dumps({**original, 'certbot': summarize(self.spec, Reply(0, text))}))
            with self.assertRaises(PreparationError):
                self.resume.check()
        self.assertEqual(self.mutations(), [])

    def test_insecure_or_symlink_recheck_output_rejected(self):
        path = self.host.path(RECHECK_LOGS + '/command-output.txt')
        path.chmod(0o644)
        with self.assertRaises(Exception):
            self.resume.check()
        path.unlink()
        path.symlink_to(self.host.path(CREDENTIAL))
        with self.assertRaises(Exception):
            self.resume.check()
        self.assertEqual(self.mutations(), [])

    def test_existing_resume_paths_never_overwritten(self):
        for path in (STATE + '/' + STARTED + '.json', STATE + '/' + REPORT + '.json', LOGS):
            self.host.path(path).symlink_to('/foreign')
            with self.assertRaises(Exception):
                self.resume.check()
            self.assertTrue(self.host.path(path).is_symlink())
            self.host.path(path).unlink()
        self.assertEqual(self.mutations(), [])

    def test_already_swapped_credential_is_not_recovered(self):
        self.host.path(CREDENTIAL).write_bytes(self.host.path(CANDIDATE).read_bytes())
        with self.assertRaises(PreparationError):
            self.resume.check()
        self.assertEqual(self.mutations(), [])

    def test_active_timer_or_certbot_is_not_stopped_by_precheck(self):
        self.host.active.add('certbot.timer')
        self.host.enabled.add('certbot.timer')
        with self.assertRaises(PreparationError):
            self.resume.check()
        self.host.active.discard('certbot.timer')
        self.host.enabled.discard('certbot.timer')
        self.host.local_override = lambda c: Reply(0, 'ActiveState=active\nSubState=running\nMainPID=99\nJob=\n') \
            if c.argv[-1] == 'ActiveState,SubState,MainPID,Job' else None
        with self.assertRaises(PreparationError):
            self.resume.check()
        self.assertEqual(self.mutations(), [])

    def test_other_pending_change_or_insecure_candidate_rejected(self):
        for name in ('key-rotation-intent', 'port-change-intent'):
            self.prep._record(name, {})
            with self.assertRaises(PreparationError):
                self.resume.check()
            self.host.path(STATE + '/' + name + '.json').unlink()
        self.host.path(CANDIDATE).chmod(0o644)
        with self.assertRaises(Exception):
            self.resume.check()
        self.assertEqual(self.mutations(), [])

    def test_failed_fixed_path_test_preserves_new_credential_and_pauses(self):
        self.host.local_override = lambda c: Reply(1, NEW_TOKEN) if c.argv[:2] == ('certbot', 'renew') else None
        report = self.finish()
        self.assertEqual(report['result'], 'stopped')
        self.assertEqual(report['certbot']['exit_code'], 1)
        self.assertEqual(report['fixed_credential_matches'], 'after')
        self.assertTrue(report['renewal_paused_verified_after'])
        self.assertIn(NEW_TOKEN.encode(), self.host.path(CREDENTIAL).read_bytes())
        self.assertTrue(self.host.path(CANDIDATE).exists())
        self.assertNotIn(NEW_TOKEN, json.dumps(report))
        self.assert_paused()
        with self.assertRaises(PreparationError):
            self.finish()

    def test_uncertain_result_not_mistaken_for_success(self):
        self.host.local_override = lambda c: Reply(-1, uncertain=True) if c.argv[:2] == ('certbot', 'renew') else None
        report = self.finish()
        self.assertEqual(report['result'], 'stopped')
        self.assertTrue(report['certbot']['execution_uncertain'])
        self.assertIsNone(report['certbot']['exit_code'])
        self.assert_paused()

    def test_interrupt_retains_stage_and_new_credential(self):
        def interrupt(command):
            if command.argv[:2] == ('certbot', 'renew'):
                raise KeyboardInterrupt(NEW_TOKEN)
        self.host.local_override = interrupt
        report = self.finish()
        self.assertEqual(report['failure_phase'], 'fixed-path-dry-run')
        self.assertEqual(report['fixed_credential_matches'], 'after')
        self.assertNotIn(NEW_TOKEN, json.dumps(report))
        self.assert_paused()

    def test_zero_exit_without_full_evidence_not_success(self):
        self.host.local_override = lambda c: Reply(0, 'no renewal') if c.argv[:2] == ('certbot', 'renew') else None
        report = self.finish()
        self.assertFalse(report['fixed_path_test_passed'])
        self.assert_paused()

    def test_failed_replace_keeps_old_credential(self):
        with patch.object(self.prep.files, 'replace_owned', side_effect=OSError('disk')):
            report = self.finish()
        self.assertEqual(report['failure_phase'], 'credential-replace')
        self.assertEqual(report['fixed_credential_matches'], 'before')
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertEqual(self.certbot_calls(), [])
        self.assert_paused()

    def test_lineage_drift_during_dry_run_not_overwritten(self):
        path = self.host.path('/etc/letsencrypt/renewal/' + self.spec.domain + '.conf')
        def edit(command):
            if command.argv[:2] == ('certbot', 'renew'):
                path.write_bytes(path.read_bytes() + b'\n# external\n')
        self.host.local_override = edit
        report = self.finish()
        self.assertEqual(report['failure_phase'], 'paused-postcheck')
        self.assertFalse(report['fixed_path_test_passed'])
        self.assert_paused()

    def test_candidate_drift_not_deleted(self):
        def edit(command):
            if command.argv[:2] == ('certbot', 'renew'):
                self.host.path(CANDIDATE).write_bytes(b'foreign')
        self.host.local_override = edit
        report = self.finish()
        self.assertEqual(report['failure_phase'], 'paused-postcheck')
        self.assertEqual(self.host.path(CANDIDATE).read_bytes(), b'foreign')
        self.assert_paused()

    def test_formal_credential_drift_not_overwritten(self):
        def edit(command):
            if command.argv[:2] == ('certbot', 'renew'):
                self.host.path(CREDENTIAL).write_bytes(b'foreign')
        self.host.local_override = edit
        report = self.finish()
        self.assertEqual(report['result'], 'stopped')
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), b'foreign')
        self.assert_paused()

    def test_current_record_write_failure_keeps_candidate(self):
        original = self.prep._record
        def fail(name, value):
            if name == CURRENT:
                raise OSError('disk')
            return original(name, value)
        with patch.object(self.prep, '_record', side_effect=fail):
            report = self.finish()
        self.assertEqual(report['failure_phase'], 'credential-record')
        self.assertTrue(self.host.path(CANDIDATE).exists())
        self.assert_paused()

    def test_timer_enable_failure_never_clears_intent(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ('systemctl', 'enable', '--now', 'certbot.timer') else None
        report = self.finish()
        self.assertEqual(report['failure_phase'], 'renewal-enable')
        self.assertTrue(report['fixed_path_test_passed'])
        self.assertFalse(report['renewal_restored_verified'])
        self.assert_paused()

    def test_zero_exit_timer_not_active_is_failure(self):
        self.host.local_override = lambda c: Reply(0) if c.argv == ('systemctl', 'enable', '--now', 'certbot.timer') else None
        report = self.finish()
        self.assertEqual(report['failure_phase'], 'enabled-postcheck')
        self.assert_paused()

    def test_intent_cleanup_fsync_failure_restores_marker(self):
        original = self.prep.files.unlink_owned
        def fail(path, identity):
            original(path, identity)
            if path.endswith(INTENT + '.json'):
                raise OSError('fsync')
        with patch.object(self.prep.files, 'unlink_owned', side_effect=fail):
            report = self.finish()
        self.assertEqual(report['failure_phase'], 'intent-cleanup')
        self.assert_paused()

    def test_foreign_intent_preserved(self):
        def edit(command):
            if command.argv == ('systemctl', 'enable', '--now', 'certbot.timer'):
                self.host.path(STATE + '/' + INTENT + '.json').write_text('{"foreign": true}')
        self.host.local_override = edit
        report = self.finish()
        self.assertEqual(report['result'], 'stopped')
        self.assertEqual(self.prep._read_record(INTENT), {'foreign': True})
        self.assert_paused()

    def test_prior_report_drift_blocks_completion(self):
        def edit(command):
            if command.argv == ('systemctl', 'enable', '--now', 'certbot.timer'):
                path = self.host.path(STATE + '/' + RECHECK_REPORT + '.json')
                path.write_bytes(path.read_bytes() + b'\n')
        self.host.local_override = edit
        self.assertEqual(self.finish()['result'], 'stopped')
        self.assert_paused()

    def test_new_other_intent_blocks_completion(self):
        def edit(command):
            if command.argv[:2] == ('certbot', 'renew'):
                self.prep._record('port-change-intent', {})
        self.host.local_override = edit
        self.assertEqual(self.finish()['result'], 'stopped')
        self.assertTrue(self.prep._exists('port-change-intent'))
        self.assert_paused()

    def test_pause_failure_reported_without_killing_certbot(self):
        def fail(command):
            if command.argv == ('systemctl', 'enable', '--now', 'certbot.timer'):
                self.host.active.add('certbot.timer')
                self.host.enabled.add('certbot.timer')
                return Reply(1)
            if command.argv == ('systemctl', 'disable', '--now', 'certbot.timer'):
                return Reply(1)
        self.host.local_override = fail
        report = self.finish()
        self.assertFalse(report['renewal_restored_verified'])
        self.assertFalse(report['renewal_paused_verified_after'])
        self.assertNotIn(('systemctl', 'stop', 'certbot.service'), self.mutations())
        self.assert_pending()

    def test_lock_held_through_fixed_path_test(self):
        def check(command):
            if command.argv[:2] == ('certbot', 'renew'):
                with self.assertRaises(PreparationError), self.prep._lock():
                    pass
        self.host.local_override = check
        self.assertEqual(self.finish()['result'], 'token-changed-renewal-tested')

    def test_report_write_failure_does_not_claim_saved(self):
        original = self.prep._record
        def fail(name, value):
            if name == REPORT:
                raise OSError('disk')
            return original(name, value)
        with patch.object(self.prep, '_record', side_effect=fail):
            report = self.finish()
        self.assertEqual(report['result'], 'token-changed-renewal-tested')
        self.assertFalse(report['report_saved'])
        self.assertTrue(report['renewal_restored_verified'])

    def test_capture_failure_does_not_restore_timer(self):
        original = self.prep.files.write_new
        def fail(path, *args, **kwargs):
            if path == LOGS + '/command-output.txt':
                raise OSError('disk')
            return original(path, *args, **kwargs)
        with patch.object(self.prep.files, 'write_new', side_effect=fail):
            report = self.finish()
        self.assertEqual(report['failure_phase'], 'capture-output')
        self.assertEqual(report['fixed_credential_matches'], 'after')
        self.assert_paused()

    def test_unexpected_candidate_after_enable_not_deleted(self):
        def edit(command):
            if command.argv == ('systemctl', 'enable', '--now', 'certbot.timer'):
                self.host.write(CANDIDATE, b'foreign')
        self.host.local_override = edit
        self.assertEqual(self.finish()['result'], 'stopped')
        self.assertEqual(self.host.path(CANDIDATE).read_bytes(), b'foreign')
        self.assert_paused()

    def test_tty_lost_after_confirmation_does_not_write(self):
        @contextmanager
        def factory():
            yield self.tokens
        ui = Console(['y'])
        ui.interactive = Mock(side_effect=[True, False])
        self.assertEqual(run_token_resume(factory=factory, terminal=ui), 1)
        self.assertEqual(self.mutations(), [])
        self.assertFalse(self.prep._exists(STARTED))

    def test_unknown_platform_exception_is_redacted(self):
        @contextmanager
        def factory():
            raise RuntimeError(NEW_TOKEN)
            yield
        ui = Console([])
        self.assertEqual(run_token_resume(factory=factory, terminal=ui), 1)
        self.assertNotIn(NEW_TOKEN, ui.text)
        self.assertIn('"phase": "platform"', ui.text)

    def test_ui_cancel_noninteractive_and_success(self):
        @contextmanager
        def factory():
            yield self.tokens
        ui = Console(['n'])
        self.assertEqual(run_token_resume(factory=factory, terminal=ui), 130)
        ui.secret.assert_not_called()
        self.assertEqual(self.mutations(), [])
        ui = Console([])
        ui.interactive = lambda: False
        unused = Mock()
        self.assertEqual(run_token_resume(factory=unused, terminal=ui), 2)
        unused.assert_not_called()
        ui = Console(['y'])
        self.assertEqual(run_token_resume(factory=factory, terminal=ui), 0)
        ui.secret.assert_not_called()
        for secret in (TOKEN, NEW_TOKEN, self.before_keys.psk):
            self.assertNotIn(secret, ui.text)
        self.assertIn('自动续期已恢复', ui.text)

    def test_ui_failure_retains_safe_stage_and_hides_output(self):
        @contextmanager
        def factory():
            yield self.tokens
        self.host.local_override = lambda c: Reply(1, NEW_TOKEN) if c.argv[:2] == ('certbot', 'renew') else None
        ui = Console(['y'])
        self.assertEqual(run_token_resume(factory=factory, terminal=ui), 1)
        self.assertNotIn(NEW_TOKEN, ui.text)
        self.assertNotIn('自动续期已恢复', ui.text)

    def test_cli_opt_in_and_no_token_or_yes_flag(self):
        with patch('snellctl.tokenresume.run_token_resume', return_value=0) as run, redirect_stderr(io.StringIO()):
            self.assertEqual(main(['resume-token']), 2)
            run.assert_not_called()
            self.assertEqual(main(['resume-token', '--experimental']), 0)
            run.assert_called_once_with()
        for option in ('--token', '--yes', '--force', '--root'):
            with redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
                main(['resume-token', '--experimental', option, NEW_TOKEN])
            self.assertNotIn(NEW_TOKEN, err.getvalue())
