from contextlib import contextmanager, redirect_stderr
import io
import json
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.client import read_client
from snellctl.hostprep import CREDENTIAL, HostFiles, PreparationError, STATE
from snellctl.installer import installation_status
from snellctl.retiredcancel import ARCHIVE, STARTED, REPORT, SUCCESS, RetiredCancel, run_retired_cancel
from snellctl.retiredcleanup import INTENT
from snellctl.retiredrenewal import REPORT as RESTORE_REPORT, STARTED as RESTORE_STARTED
from test_installer import Console
from test_hostprep import DOMAIN, TOKEN
from test_domainchange import NEW_DOMAIN
from test_tokenchange import NEW_TOKEN
import test_retiredrenewal


class RetiredCancelTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_retiredrenewal.RetiredRenewalTests('test_read_only_check_and_plan_repr')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        result = self.fixture.restore()
        self.assertTrue(result['renewal_restored_verified'], result)
        self.host, self.prep, self.tokens = self.fixture.host, self.fixture.prep, self.fixture.tokens
        self.engine = RetiredCancel(self.tokens)
        self.directory = self.fixture.directory
        self.marker_path = STATE + '/' + INTENT + '.json'
        self.marker = self.host.path(self.marker_path).read_bytes()
        self.host.calls.clear()

    def snapshot(self):
        return self.fixture.fixture.fixture.snapshot()

    def cancel(self, plan=None):
        return self.engine.cancel(plan or self.engine.check(), confirm_cancel=True)

    def update_json(self, name, **changes):
        path = self.directory + '/' + name
        content = json.loads(self.host.path(path).read_bytes())
        content.update(changes)
        self.host.write(path, json.dumps(content).encode())

    def assert_no_service_or_resource_mutation(self):
        for command in self.host.calls:
            self.assertNotIn(command.argv[0], {'certbot', 'apt-get'})
            if command.argv[0] == 'systemctl':
                self.assertIn(command.argv[1], {'show', 'cat', 'is-active', 'is-enabled'})
            if command.argv[0] == 'ufw':
                self.assertIn(command.argv[1], {'status', 'show'})
        self.assertIn('certbot.timer', self.host.active)
        self.assertIn('certbot.timer', self.host.enabled)

    def test_check_readonly_and_redacted_plan(self):
        before = self.snapshot()
        plan = self.engine.check()
        self.assertEqual(before, self.snapshot())
        self.assertNotIn(plan.revision, repr(plan))
        self.assert_no_service_or_resource_mutation()

    def test_cancel_archives_exact_marker_preserves_every_other_file(self):
        before = self.snapshot()
        active, enabled, rules = set(self.host.active), set(self.host.enabled), list(self.host.rules)
        report = self.cancel()
        self.assertEqual(report['result'], SUCCESS, report)
        for key in ('history_archived_verified', 'active_intent_removed_verified',
                    'old_resources_preserved_verified', 'renewal_enabled_verified', 'report_saved'):
            self.assertTrue(report[key], report)
        self.assertFalse(report['cleanup_still_pending'])
        self.assertFalse(report['cleanup_completed'])
        self.assertEqual(self.host.path(self.directory + '/' + ARCHIVE).read_bytes(), self.marker)
        after = self.snapshot()
        self.assertEqual(set(before) - set(after), {self.marker_path.lstrip('/')})
        self.assertEqual(set(after) - set(before), {self.directory.lstrip('/') + '/' + n for n in (ARCHIVE, STARTED, REPORT)})
        self.assertTrue(all(after[p] == before[p] for p in before.keys() & after.keys()))
        for name in (ARCHIVE, STARTED, REPORT):
            self.assertEqual(self.host.path(self.directory + '/' + name).stat().st_mode & 0o777, 0o600)
        self.assertEqual((active, enabled, rules), (self.host.active, self.host.enabled, self.host.rules))
        self.assertEqual(installation_status(root=self.host.root)['retired_cleanup'], 'none-pending')
        read_client(root=self.host.root)
        self.tokens.check()
        self.assert_no_service_or_resource_mutation()
        for secret in (DOMAIN, NEW_DOMAIN, TOKEN, NEW_TOKEN, self.directory):
            self.assertNotIn(secret, json.dumps(report))

    def test_original_vps_report_without_new_diagnostics_is_supported(self):
        value = json.loads(self.host.path(self.directory + '/report.json').read_bytes())
        value['failure_phase'] = 'renewal-pause'
        for name in ('pause_command', 'fallback_pause_command', 'reason', 'failure_location'):
            value.pop(name, None)
        self.host.write(self.directory + '/report.json', json.dumps(value).encode())
        self.assertEqual(self.cancel()['result'], SUCCESS)

    def test_deletion_or_later_failure_is_not_cancellable(self):
        for changes in ({'certbot_delete_attempted': True}, {'credential_delete_attempted': True},
                        {'failure_phase': 'certificate-delete'}, {'certbot': {'exit_code': 1}}):
            with self.subTest(changes=changes):
                original = self.host.path(self.directory + '/report.json').read_bytes()
                self.update_json('report.json', **changes)
                with self.assertRaises(Exception):
                    self.engine.check()
                self.host.write(self.directory + '/report.json', original)

    def test_successful_restoration_report_required(self):
        for changes in ({'result': 'stopped'}, {'renewal_restored_verified': False},
                        {'report_saved': False}, {'old_resources_unchanged_verified': False},
                        {'enable_command': {'exit_code': -1, 'execution_uncertain': True}},
                        {'cleanup_completed': True}):
            with self.subTest(changes=changes):
                original = self.host.path(self.directory + '/' + RESTORE_REPORT).read_bytes()
                self.update_json(RESTORE_REPORT, **changes)
                with self.assertRaises(Exception):
                    self.engine.check()
                self.host.write(self.directory + '/' + RESTORE_REPORT, original)

    def test_restore_attempt_record_required(self):
        self.update_json(RESTORE_STARTED, revision='bad')
        with self.assertRaises(Exception):
            self.engine.check()

    def test_restoration_exit_code_false_is_not_integer_zero(self):
        self.update_json(RESTORE_REPORT, enable_command={'exit_code': False, 'execution_uncertain': False})
        with self.assertRaises(Exception):
            self.engine.check()

    def test_scoped_renewal_target_cannot_change_to_old_domain(self):
        from snellctl.publish import RENEW_DROPIN
        path = self.host.path(RENEW_DROPIN)
        self.host.write(RENEW_DROPIN, path.read_bytes().replace(NEW_DOMAIN.encode(), DOMAIN.encode()), 0o644)
        with self.assertRaises(Exception):
            self.engine.check()
        self.assertTrue(self.prep._exists(INTENT))

    def test_current_certificate_renewal_during_cancel_is_allowed(self):
        def progress(phase):
            if phase == 'enabled-health-and-history-check':
                for part in ('cert', 'chain', 'fullchain', 'privkey'):
                    data = b'renewed fixture' * (2 if part == 'fullchain' else 1)
                    self.host.write(f'/etc/letsencrypt/archive/{NEW_DOMAIN}/{part}2.pem', data)
                    live = self.host.path(f'/etc/letsencrypt/live/{NEW_DOMAIN}/{part}.pem')
                    live.unlink()
                    live.symlink_to(f'../../archive/{NEW_DOMAIN}/{part}2.pem')
        self.engine.progress = progress
        self.assertEqual(self.cancel()['result'], SUCCESS)
        self.assert_no_service_or_resource_mutation()

    def test_renewal_must_currently_be_enabled_not_just_historical(self):
        self.host.active.discard('certbot.timer')
        self.host.enabled.discard('certbot.timer')
        with self.assertRaises(Exception):
            self.engine.check()
        self.assertTrue(self.prep._exists(INTENT))

    def test_missing_old_certificate_blocks(self):
        self.host.path('/etc/letsencrypt/live/' + DOMAIN + '/cert.pem').unlink()
        with self.assertRaises(Exception):
            self.engine.check()

    def test_changed_old_credential_blocks(self):
        self.host.write(CREDENTIAL, b'changed-without-reading-original')
        with self.assertRaises(Exception):
            self.engine.check()

    def test_private_record_permissions_and_symlinks_rejected(self):
        path = self.host.path(self.directory + '/' + RESTORE_REPORT)
        path.chmod(0o644)
        with self.assertRaises(Exception):
            self.engine.check()
        path.unlink()
        path.symlink_to('/outside')
        with self.assertRaises(Exception):
            self.engine.check()

    def test_other_pending_change_blocks(self):
        self.prep._record('token-change-intent', {'format': 1})
        with self.assertRaises(Exception):
            self.engine.check()

    def test_confirmation_snapshot_and_explicit_confirmation_required(self):
        plan = self.engine.check()
        with self.assertRaises(PreparationError):
            self.engine.cancel(plan, confirm_cancel=False)
        self.update_json('report.json', elapsed_seconds=999)
        with self.assertRaises(Exception):
            self.cancel(plan)
        self.assertFalse(self.host.path(self.directory + '/' + ARCHIVE).exists())

    def test_existing_attempt_or_archive_blocks_without_overwrite(self):
        for name in (ARCHIVE, STARTED, REPORT):
            with self.subTest(name=name):
                self.host.write(self.directory + '/' + name, b'preserve')
                with self.assertRaises(Exception):
                    self.engine.check()
                self.assertEqual(self.host.path(self.directory + '/' + name).read_bytes(), b'preserve')
                self.host.path(self.directory + '/' + name).unlink()

    def test_archive_write_failure_keeps_marker_and_timer(self):
        original = self.engine.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/' + ARCHIVE):
                raise OSError(28, 'PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.engine.files, 'write_new', side_effect=write):
            report = self.cancel()
        self.assertEqual(report['result'], 'stopped')
        self.assertEqual(report['errno'], 28)
        self.assertTrue(report['cleanup_still_pending'])
        self.assertFalse(report['active_intent_remove_attempted'])
        self.assert_no_service_or_resource_mutation()
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_attempt_write_failure_keeps_marker_and_archive(self):
        original = self.engine.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/' + STARTED):
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.engine.files, 'write_new', side_effect=write):
            report = self.cancel()
        self.assertTrue(report['cleanup_still_pending'])
        self.assertEqual(self.host.path(self.directory + '/' + ARCHIVE).read_bytes(), self.marker)
        self.assertFalse(report['active_intent_remove_attempted'])
        with self.assertRaises(Exception):
            self.cancel()

    def test_health_failure_before_unlink_keeps_marker(self):
        def progress(phase):
            if phase == 'enabled-health-and-history-check':
                self.fixture.fixture.fixture.probe.return_value = False
        self.engine.progress = progress
        report = self.cancel()
        self.assertTrue(report['cleanup_still_pending'])
        self.assertFalse(report['active_intent_remove_attempted'])
        self.assert_no_service_or_resource_mutation()

    def test_tampered_archive_or_old_resource_blocks_last_unlink(self):
        def progress(phase):
            if phase == 'active-marker-remove':
                self.host.write(self.directory + '/' + ARCHIVE, b'external')
        self.engine.progress = progress
        report = self.cancel()
        self.assertTrue(report['cleanup_still_pending'])
        self.assertFalse(report['active_intent_remove_attempted'])

    def test_replaced_marker_is_not_deleted(self):
        def progress(phase):
            if phase == 'active-marker-remove':
                self.host.path(self.marker_path).unlink()
                self.host.write(self.marker_path, b'external')
        self.engine.progress = progress
        report = self.cancel()
        self.assertEqual(self.host.path(self.marker_path).read_bytes(), b'external')
        self.assertTrue(report['cleanup_still_pending'])

    def test_unlink_failure_preserves_marker_no_retry(self):
        with patch.object(self.engine.files, 'unlink_owned', side_effect=OSError('PRIVATE')) as remove:
            report = self.cancel()
        remove.assert_called_once()
        self.assertTrue(report['cleanup_still_pending'])
        self.assertFalse(report['active_intent_removed_verified'])
        self.assert_no_service_or_resource_mutation()

    def test_error_after_unlink_reports_absence_not_fake_pending(self):
        original = self.engine.files.unlink_owned
        def remove(path, identity):
            original(path, identity)
            raise OSError('PRIVATE fsync')
        with patch.object(self.engine.files, 'unlink_owned', side_effect=remove):
            report = self.cancel()
        self.assertEqual(report['result'], 'stopped')
        self.assertFalse(report['cleanup_still_pending'])
        self.assertTrue(report['active_intent_removed_verified'])
        self.assertEqual(self.host.path(self.directory + '/' + ARCHIVE).read_bytes(), self.marker)
        self.assert_no_service_or_resource_mutation()

    def test_final_report_failure_still_leaves_durable_archive_and_authorization(self):
        original = self.engine.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/' + REPORT):
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.engine.files, 'write_new', side_effect=write):
            report = self.cancel()
        self.assertEqual(report['result'], SUCCESS)
        self.assertFalse(report['report_saved'])
        self.assertFalse(report['cleanup_still_pending'])
        self.assertTrue(self.host.path(self.directory + '/' + STARTED).is_file())
        self.assertEqual(self.host.path(self.directory + '/' + ARCHIVE).read_bytes(), self.marker)

    def test_interrupt_keeps_marker_and_enabled_timer(self):
        def progress(phase):
            if phase == 'active-marker-remove':
                raise KeyboardInterrupt()
        self.engine.progress = progress
        report = self.cancel()
        self.assertEqual(report['reason'], 'interrupted')
        self.assertTrue(report['cleanup_still_pending'])
        self.assert_no_service_or_resource_mutation()

    def test_old_secret_contents_never_read(self):
        original = HostFiles.read
        def read(files, path, **kwargs):
            self.assertNotEqual(path, CREDENTIAL)
            self.assertNotIn('/archive/' + DOMAIN + '/privkey', path)
            return original(files, path, **kwargs)
        with patch.object(HostFiles, 'read', new=read):
            self.assertEqual(self.cancel()['result'], SUCCESS)

    def test_cli_gate_noninteractive_cancel_and_success(self):
        with redirect_stderr(io.StringIO()), patch('snellctl.retiredcancel.run_retired_cancel') as run:
            self.assertEqual(main(['cancel-retired-cleanup']), 2)
            run.assert_not_called()
        with patch('snellctl.retiredcancel.run_retired_cancel', return_value=0) as run:
            self.assertEqual(main(['cancel-retired-cleanup', '--experimental']), 0)
            run.assert_called_once_with()
        factory = Mock()
        ui = Console([])
        ui.interactive = Mock(return_value=False)
        self.assertEqual(run_retired_cancel(factory=factory, terminal=ui), 2)
        factory.assert_not_called()
        @contextmanager
        def real_factory():
            yield self.tokens
        before = self.snapshot()
        self.assertEqual(run_retired_cancel(factory=real_factory, terminal=Console(['n'])), 130)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(run_retired_cancel(factory=real_factory, terminal=Console(['y'])), 0)

    def test_precheck_failure_does_not_echo_error(self):
        ui = Console([])
        self.assertEqual(run_retired_cancel(factory=Mock(side_effect=ValueError('PRIVATE')), terminal=ui), 1)
        self.assertNotIn('PRIVATE', ui.text)

    def test_repeat_refused_without_changes(self):
        self.assertEqual(self.cancel()['result'], SUCCESS)
        before = self.snapshot()
        with self.assertRaises(Exception):
            self.cancel()
        self.assertEqual(before, self.snapshot())
