from contextlib import contextmanager, redirect_stderr
import io
import json
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.client import read_client, ClientError
from snellctl.hostprep import CREDENTIAL, PreparationError, Reply, STATE
from snellctl.installer import installation_status
from snellctl.retiredcleanup import INTENT
from snellctl.retiredrenewal import RetiredRenewal, REPORT, STARTED, SUCCESS, run_retired_renewal
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
from test_domainchange import NEW_DOMAIN
from test_tokenchange import NEW_TOKEN
import test_retiredcleanup


class RetiredRenewalTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_retiredcleanup.RetiredCleanupTests('test_check_read_only_and_plan_redacted')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        with patch.object(self.fixture.engine, '_health', side_effect=PreparationError('fixture stop')):
            result = self.fixture.clean()
        self.assertEqual(result['failure_phase'], 'renewal-pause-check')
        self.assertFalse(result['certbot_delete_attempted'])
        self.tokens = self.fixture.fixture.tokens
        self.host, self.prep = self.fixture.host, self.fixture.prep
        self.engine = RetiredRenewal(self.tokens)
        self.directory = self.prep._read_record(INTENT)['log_directory']
        self.marker = self.host.path(STATE + '/' + INTENT + '.json').read_bytes()
        self.failed_report = self.host.path(self.directory + '/report.json').read_bytes()
        self.host.calls.clear()

    def restore(self):
        return self.engine.restore(self.engine.check(), confirm_restore=True)

    def update_failed(self, **changes):
        value = json.loads(self.failed_report)
        value.update(changes)
        self.host.write(self.directory + '/report.json', json.dumps(value).encode())

    def assert_preserved(self):
        self.assertEqual(self.host.path(STATE + '/' + INTENT + '.json').read_bytes(), self.marker)
        self.assertEqual(self.host.path(self.directory + '/report.json').read_bytes(), self.failed_report)
        self.assertTrue(self.host.path(CREDENTIAL).is_file())
        self.assertTrue(self.host.path('/etc/letsencrypt/live/' + DOMAIN + '/cert.pem').exists())
        self.assertEqual(installation_status(root=self.host.root)['retired_cleanup'], 'needs-inspection')
        with self.assertRaises(ClientError):
            read_client(root=self.host.root)

    def assert_no_deletion_or_pause(self):
        allowed = {('systemctl', 'enable', '--now', 'certbot.timer')}
        for command in self.host.calls:
            self.assertNotEqual(command.argv[0], 'certbot')
            if command.argv[:2] in {('systemctl', 'enable'), ('systemctl', 'disable'),
                                    ('systemctl', 'stop'), ('systemctl', 'restart'), ('systemctl', 'reload')}:
                self.assertIn(command.argv, allowed)
            self.assertNotIn(command.argv[:2], {('ufw', 'allow'), ('ufw', 'delete')})

    def test_read_only_check_and_plan_repr(self):
        before = self.fixture.fixture.snapshot()
        plan = self.engine.check()
        self.assertEqual(self.fixture.fixture.snapshot(), before)
        self.assertNotIn(plan.revision, repr(plan))
        self.assertFalse(any(c.argv[:2] == ('systemctl', 'enable') for c in self.host.calls))

    def test_success_restores_only_timer_preserves_resources_and_pending_marker(self):
        before = self.fixture.fixture.snapshot()
        report = self.restore()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertTrue(report['renewal_restored_verified'])
        self.assertTrue(report['old_resources_unchanged_verified'])
        self.assertTrue(report['cleanup_still_pending'])
        self.assertFalse(report['cleanup_completed'])
        self.assertIn('certbot.timer', self.host.active)
        self.assertIn('certbot.timer', self.host.enabled)
        after = self.fixture.fixture.snapshot()
        self.assertTrue(all(after[path] == data for path, data in before.items()))
        self.assertEqual(set(after) - set(before), {self.directory.lstrip('/') + '/' + name for name in (STARTED, REPORT)})
        self.assert_preserved()
        self.assert_no_deletion_or_pause()
        for value in (DOMAIN, NEW_DOMAIN, TOKEN, NEW_TOKEN):
            self.assertNotIn(value, json.dumps(report))

    def test_refuses_second_attempt(self):
        self.assertEqual(self.restore()['result'], SUCCESS)
        self.host.calls.clear()
        with self.assertRaises(Exception):
            self.restore()
        self.assertEqual(self.host.calls, [])

    def test_new_failed_comparison_evidence_is_preserved_by_restore(self):
        with patch.object(self.tokens.public, '_fields', return_value={
                'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0'}):
            try:
                self.tokens._idle()
            except PreparationError as error:
                details = self.fixture.engine._check_failure(error)
        self.assertEqual(details['unit_state_check']['missing_fields'], ['Job'])
        self.update_failed(**details)
        self.failed_report = self.host.path(self.directory + '/report.json').read_bytes()
        report = self.restore()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assert_preserved()
        self.assert_no_deletion_or_pause()

    def test_failure_report_must_exclude_deletion_and_later_phases(self):
        for changes in ({'certbot_delete_attempted': True}, {'credential_delete_attempted': True},
                        {'certificate_removed_verified': True}, {'certbot_delete_attempted': 0},
                        {'failure_phase': 'certificate-delete'}, {'certbot': {'exit_code': 0}},
                        {'report_saved': False}):
            with self.subTest(changes=changes):
                self.update_failed(**changes)
                with self.assertRaises(Exception):
                    self.engine.check()
        self.assertFalse(any(c.argv[:2] == ('systemctl', 'enable') for c in self.host.calls))

    def test_rejects_missing_old_certificate(self):
        self.host.path('/etc/letsencrypt/live/' + DOMAIN + '/cert.pem').unlink()
        with self.assertRaises(Exception):
            self.engine.check()
        self.assertFalse(self.host.path(self.directory + '/' + STARTED).exists())

    def test_rejects_replaced_old_credential(self):
        self.host.path(CREDENTIAL).unlink()
        self.host.write(CREDENTIAL, b'not-read-by-this-check')
        with self.assertRaises(Exception):
            self.engine.check()

    def test_rejects_other_pending_changes(self):
        self.prep._record('key-rotation-intent', {'format': 1})
        with self.assertRaises(Exception):
            self.engine.check()
        self.assertEqual(self.host.calls, [])

    def test_rejects_active_certbot_and_enabled_timer(self):
        original = self.prep.runner
        def runner(command):
            if command.argv[:3] == ('systemctl', 'show', 'certbot.service') and command.argv[-1] == 'ActiveState,SubState,MainPID,Job':
                return Reply(0, 'ActiveState=active\nSubState=running\nMainPID=1234\nJob=\n')
            return original(command)
        with patch.object(self.prep, 'runner', side_effect=runner), self.assertRaises(Exception):
            self.engine.check()
        self.host.active.add('certbot.timer')
        self.host.enabled.add('certbot.timer')
        with self.assertRaises(Exception):
            self.engine.check()

    def test_rejects_external_log_path_without_reading_it(self):
        intent = self.prep._read_record(INTENT)
        intent['log_directory'] = '/tmp/untrusted'
        self.host.write(STATE + '/' + INTENT + '.json', json.dumps(intent).encode())
        with self.assertRaises(Exception):
            self.engine.check()

    def test_rejects_current_domain_target(self):
        intent = self.prep._read_record(INTENT)
        intent['target_domain'] = NEW_DOMAIN
        self.host.write(STATE + '/' + INTENT + '.json', json.dumps(intent).encode())
        with self.assertRaises(Exception):
            self.engine.check()

    def test_confirmation_rechecks_changed_snapshot(self):
        plan = self.engine.check()
        value = json.loads(self.failed_report)
        value['elapsed_seconds'] = 42
        self.host.write(self.directory + '/report.json', json.dumps(value).encode())
        with self.assertRaises(Exception):
            self.engine.restore(plan, confirm_restore=True)
        self.assertFalse(self.host.path(self.directory + '/' + STARTED).exists())

    def test_requires_explicit_confirmation(self):
        plan = self.engine.check()
        with self.assertRaises(PreparationError):
            self.engine.restore(plan, confirm_restore=False)
        self.assertFalse(self.host.path(self.directory + '/' + STARTED).exists())

    def test_enable_nonzero_or_uncertain_never_retries_or_disables(self):
        plan = self.engine.check()
        original = self.prep.runner
        def runner(command):
            reply = original(command)
            if command.argv == ('systemctl', 'enable', '--now', 'certbot.timer'):
                return Reply(1, 'PRIVATE-ERROR', uncertain=True)
            return reply
        self.prep.runner = runner
        report = self.engine.restore(plan, confirm_restore=True)
        self.assertEqual(report['result'], 'stopped')
        self.assertEqual(report['failure_phase'], 'renewal-enable')
        self.assertEqual(report['enable_command'], {'exit_code': 1, 'execution_uncertain': True})
        self.assertNotIn('PRIVATE-ERROR', json.dumps(report))
        self.assertIn('certbot.timer', self.host.active)
        self.assertEqual(sum(c.argv == ('systemctl', 'enable', '--now', 'certbot.timer') for c in self.host.calls), 1)
        self.assert_preserved()
        self.assert_no_deletion_or_pause()

    def test_postcheck_failure_retains_enabled_timer_and_marker(self):
        original = self.engine.cleanup._health
        def health(before, *, paused):
            if not paused:
                raise PreparationError('PRIVATE')
            return original(before, paused=paused)
        with patch.object(self.engine.cleanup, '_health', side_effect=health):
            report = self.restore()
        self.assertEqual(report['result'], 'stopped')
        self.assertEqual(report['failure_phase'], 'enabled-postcheck')
        self.assertIn('certbot.timer', self.host.active)
        self.assert_preserved()
        self.assert_no_deletion_or_pause()
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_start_record_failure_does_not_enable(self):
        original = self.engine.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/' + STARTED):
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.engine.files, 'write_new', side_effect=write):
            report = self.restore()
        self.assertEqual(report['failure_phase'], 'restore-attempt-record')
        self.assertFalse(report['renewal_enable_attempted'])
        self.assertNotIn('certbot.timer', self.host.active)
        self.assert_preserved()

    def test_report_save_failure_does_not_remove_marker_or_disable(self):
        original = self.engine.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/' + REPORT):
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.engine.files, 'write_new', side_effect=write):
            report = self.restore()
        self.assertEqual(report['result'], SUCCESS)
        self.assertFalse(report['report_saved'])
        self.assert_preserved()
        self.assert_no_deletion_or_pause()

    def test_interruption_during_enable_does_not_delete_or_stop(self):
        original = self.prep.runner
        def runner(command):
            reply = original(command)
            if command.argv == ('systemctl', 'enable', '--now', 'certbot.timer'):
                raise KeyboardInterrupt()
            return reply
        self.prep.runner = runner
        report = self.restore()
        self.assertEqual(report['reason'], 'interrupted')
        self.assertTrue(report['renewal_enable_attempted'])
        self.assert_preserved()
        self.assert_no_deletion_or_pause()

    def test_cli_gate_and_ui_cancel_and_noninteractive(self):
        with redirect_stderr(io.StringIO()), patch('snellctl.retiredrenewal.run_retired_renewal') as run:
            self.assertEqual(main(['restore-retired-renewal']), 2)
            run.assert_not_called()
        with patch('snellctl.retiredrenewal.run_retired_renewal', return_value=0) as run:
            self.assertEqual(main(['restore-retired-renewal', '--experimental']), 0)
            run.assert_called_once_with()
        factory = Mock()
        ui = Console([])
        ui.interactive = Mock(return_value=False)
        self.assertEqual(run_retired_renewal(factory=factory, terminal=ui), 2)
        factory.assert_not_called()
        @contextmanager
        def real_factory():
            yield self.tokens
        ui = Console(['n'])
        before = self.fixture.fixture.snapshot()
        self.assertEqual(run_retired_renewal(factory=real_factory, terminal=ui), 130)
        self.assertEqual(self.fixture.fixture.snapshot(), before)

    def test_ui_precheck_failure_redacts_exception(self):
        factory = Mock(side_effect=PreparationError('PRIVATE-TOKEN'))
        ui = Console([])
        self.assertEqual(run_retired_renewal(factory=factory, terminal=ui), 1)
        self.assertNotIn('PRIVATE-TOKEN', ui.text)

    def test_cli_success_still_reports_pending_cleanup(self):
        @contextmanager
        def factory():
            yield self.tokens
        ui = Console(['y'])
        self.assertEqual(run_retired_renewal(factory=factory, terminal=ui), 0)
        self.assert_preserved()
        self.assert_no_deletion_or_pause()

    def test_legitimate_current_renewal_after_enable_is_not_old_resource_change(self):
        def progress(phase):
            if phase == 'enabled-postcheck':
                for part in ('cert', 'chain', 'fullchain', 'privkey'):
                    data = b'renewed fixture' * (2 if part == 'fullchain' else 1)
                    self.host.write(f'/etc/letsencrypt/archive/{NEW_DOMAIN}/{part}2.pem', data)
                    live = self.host.path(f'/etc/letsencrypt/live/{NEW_DOMAIN}/{part}.pem')
                    live.unlink()
                    live.symlink_to(f'../../archive/{NEW_DOMAIN}/{part}2.pem')
        self.engine.progress = progress
        report = self.restore()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assert_preserved()
        self.assert_no_deletion_or_pause()

    def test_scoped_renewal_target_must_still_match_current_domain(self):
        from snellctl.publish import RENEW_DROPIN
        path = self.host.path(RENEW_DROPIN)
        self.host.write(RENEW_DROPIN, path.read_bytes().replace(NEW_DOMAIN.encode(), DOMAIN.encode()), 0o644)
        with self.assertRaises(Exception):
            self.engine.check()
        self.assertFalse(any(c.argv[:2] == ('systemctl', 'enable') for c in self.host.calls))
