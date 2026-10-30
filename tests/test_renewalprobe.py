from contextlib import contextmanager, redirect_stderr
import io
import json
import signal
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.client import _read_deployment_snapshot
from snellctl.hostprep import Command, PreparationError, Reply, STATE
from snellctl.publish import RENEW_DROPIN
from snellctl.renewalprobe import (SUCCESS, RenewalPauseProbe, ignore_ssh_hangup,
                                  read_only_command, run_renewal_pause_probe)
from snellctl.retiredcancel import RetiredCancel
from snellctl.retiredcleanup import INTENT, RetiredCleanup
from test_domainchange import NEW_DOMAIN
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
from test_retiredcleanup import Clock
from test_tokenchange import NEW_TOKEN
import test_retiredrenewal


PAUSE = ('systemctl', 'disable', '--now', 'certbot.timer')
RESTORE = ('systemctl', 'enable', '--now', 'certbot.timer')
IDLE_QUERY = ('systemctl', 'show', 'certbot.service', '-p', 'ActiveState,SubState,MainPID,Job')
BUSY = 'ActiveState=activating\nSubState=start\nMainPID=123\nJob=PRIVATE-JOB\n'


class RenewalPauseProbeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_retiredrenewal.RetiredRenewalTests('test_read_only_check_and_plan_repr')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.assertTrue(self.fixture.restore()['renewal_restored_verified'])
        self.host, self.prep, self.tokens = self.fixture.host, self.fixture.prep, self.fixture.tokens
        self.engine = RenewalPauseProbe(self.tokens)
        self.clock = Clock()
        self.engine.cleanup.clock, self.engine.cleanup.sleep = self.clock, self.clock.sleep
        self.marker = STATE + '/' + INTENT + '.json'
        self.host.calls.clear()

    def snapshot(self):
        return self.fixture.fixture.fixture.snapshot()

    def probe(self, plan=None):
        with patch.object(RetiredCleanup, 'clean', side_effect=AssertionError('must not delete')), \
             patch.object(self.engine.files, 'unlink_owned', side_effect=AssertionError('must not unlink')):
            return self.engine.probe(plan or self.engine.check(), confirm_probe=True)

    def mutations(self):
        return [c.argv for c in self.host.calls if not read_only_command(c.argv)]

    def assert_restored(self, report):
        self.assertTrue(report['renewal_restored_verified'], report)
        self.assertIn('certbot.timer', self.host.enabled)
        self.assertIn('certbot.timer', self.host.active)
        self.assertTrue(report['cleanup_still_pending'])
        self.assertFalse(report['cleanup_completed'])
        self.assertEqual(self.mutations(), [PAUSE, RESTORE])
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_readonly_check(self):
        before = self.snapshot()
        plan = self.engine.check()
        self.assertNotIn(plan.revision, repr(plan))
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.mutations(), [])

    def test_success_preserves_all_existing_files_and_does_not_clear_marker(self):
        before = self.snapshot()
        report = self.probe()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assert_restored(report)
        self.assertTrue(report['wait_passed'])
        self.assertTrue(report['paused_health_passed'])
        self.assertTrue(report['cleanup_marker_unchanged_verified'])
        self.assertTrue(report['old_resources_unchanged_verified'])
        self.assertEqual(report['pause_wait']['result'], 'idle-observed-twice')
        after = self.snapshot()
        self.assertTrue(all(after[p] == data for p, data in before.items()))
        new = set(after) - set(before)
        self.assertEqual(len(new), 3)
        new_files = {p for p in new if self.host.path('/' + p).is_file()}
        self.assertEqual({p.rsplit('/', 1)[1] for p in new_files}, {'started.json', 'report.json'})
        for path in new_files:
            file = self.host.path('/' + path)
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(file.parent.stat().st_mode & 0o777, 0o700)
        for value in (DOMAIN, NEW_DOMAIN, TOKEN, NEW_TOKEN):
            self.assertNotIn(value, json.dumps(report))
        self.assertTrue(report['report_saved'])
        RetiredCancel(self.tokens).check()

    def test_busy_task_after_pause_is_waited_out_then_restored(self):
        busy = [BUSY, BUSY]
        def override(command):
            if command.argv == IDLE_QUERY and 'certbot.timer' not in self.host.enabled and busy:
                return Reply(0, busy.pop())
        self.host.local_override = override
        report = self.probe()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertEqual(report['pause_wait']['busy_samples'], 2)
        self.assertEqual(report['pause_wait']['elapsed_seconds'], 3)
        self.assert_restored(report)

    def test_timeout_restores_without_stopping_busy_certbot(self):
        self.host.local_override = lambda c: Reply(0, BUSY) if (
            c.argv == IDLE_QUERY and 'certbot.timer' not in self.host.enabled) else None
        report = self.probe()
        self.assertEqual(report['result'], 'probe-stopped-renewal-restored')
        self.assertEqual(report['pause_wait']['result'], 'timeout')
        self.assertFalse(report['wait_passed'])
        self.assert_restored(report)

    def test_unknown_service_state_is_not_waited_through(self):
        self.host.local_override = lambda c: Reply(0, 'ActiveState=failed\nPRIVATE') if (
            c.argv == IDLE_QUERY and 'certbot.timer' not in self.host.enabled) else None
        report = self.probe()
        self.assertEqual(report['pause_wait']['result'], 'stopped')
        self.assert_restored(report)

    def test_wait_keyboard_interrupt_restores(self):
        with patch.object(self.engine.cleanup, '_wait_paused', side_effect=KeyboardInterrupt):
            report = self.probe()
        self.assertEqual(report['result'], 'probe-stopped-renewal-restored')
        self.assert_restored(report)

    def test_failed_or_uncertain_pause_still_attempts_one_restore(self):
        self.host.local_override = lambda c: Reply(-1, 'PRIVATE', uncertain=True) if c.argv == PAUSE else None
        report = self.probe()
        self.assertTrue(report['pause_command']['execution_uncertain'])
        self.assertFalse(report['wait_passed'])
        self.assert_restored(report)

    def test_changed_renewal_config_refuses_automatic_restore(self):
        def progress(phase):
            if phase == 'restore-configuration-check':
                self.host.write(RENEW_DROPIN, b'external', 0o644)
        self.engine.progress = progress
        report = self.probe()
        self.assertFalse(report['renewal_restored_verified'])
        self.assertIn('restoration_failure', report)
        self.assertNotIn('certbot.timer', self.host.enabled)
        self.assertEqual(self.mutations(), [PAUSE])

    def test_changed_credentials_refuse_automatic_restore(self):
        spec, _keys, _record = _read_deployment_snapshot(self.prep)
        credential = self.prep.credential_path(spec)
        def progress(phase):
            if phase == 'restore-configuration-check':
                self.host.write(credential, b'external')
        self.engine.progress = progress
        report = self.probe()
        self.assertFalse(report['renewal_restored_verified'], report)
        self.assertEqual(self.mutations(), [PAUSE])

    def test_changed_marker_reports_unknown_not_false_preservation(self):
        def progress(phase):
            if phase == 'restore-configuration-check':
                self.host.write(self.marker, b'external')
        self.engine.progress = progress
        report = self.probe()
        self.assertFalse(report['cleanup_marker_unchanged_verified'])
        self.assertEqual(report['cleanup_still_pending'], 'not-confirmed')
        self.assertFalse(report['renewal_restored_verified'])
        self.assertEqual(self.mutations(), [PAUSE])

    def test_old_resource_change_fails_probe_but_restores_current_renewal(self):
        def progress(phase):
            if phase == 'paused-health-check':
                self.host.path('/etc/letsencrypt/live/' + DOMAIN + '/cert.pem').unlink()
        self.engine.progress = progress
        report = self.probe()
        self.assertFalse(report['old_resources_unchanged_verified'])
        self.assertEqual(report['result'], 'probe-stopped-renewal-restored')
        self.assert_restored(report)

    def test_restore_failure_not_retried_or_turned_off_again(self):
        self.host.local_override = lambda c: Reply(1, 'PRIVATE') if c.argv == RESTORE else None
        report = self.probe()
        self.assertFalse(report['renewal_restored_verified'])
        self.assertIn('restoration_failure', report)
        self.assertEqual(self.mutations(), [PAUSE, RESTORE])

    def test_restore_with_running_service_does_not_require_idle_or_stop_it(self):
        def progress(phase):
            if phase == 'restore-configuration-check':
                self.host.local_override = lambda c: Reply(0, BUSY) if c.argv == IDLE_QUERY else None
        self.engine.progress = progress
        report = self.probe()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assert_restored(report)

    def test_current_certificate_rotated_during_wait_stops_probe_but_restores(self):
        def progress(phase):
            if phase == 'paused-health-check':
                for part in ('cert', 'chain', 'fullchain', 'privkey'):
                    data = b'renewed fixture' * (2 if part == 'fullchain' else 1)
                    self.host.write(f'/etc/letsencrypt/archive/{NEW_DOMAIN}/{part}2.pem', data)
                    live = self.host.path(f'/etc/letsencrypt/live/{NEW_DOMAIN}/{part}.pem')
                    live.unlink()
                    live.symlink_to(f'../../archive/{NEW_DOMAIN}/{part}2.pem')
        self.engine.progress = progress
        report = self.probe()
        self.assertEqual(report['result'], 'probe-stopped-renewal-restored')
        self.assertFalse(report['paused_health_passed'])
        self.assert_restored(report)

    def test_uncertain_restore_is_not_retried(self):
        self.host.local_override = lambda c: Reply(-1, 'PRIVATE', uncertain=True) if c.argv == RESTORE else None
        report = self.probe()
        self.assertTrue(report['restore_command']['execution_uncertain'])
        self.assertFalse(report['renewal_restored_verified'])
        self.assertEqual(self.mutations(), [PAUSE, RESTORE])

    def test_health_failure_after_restore_is_not_a_probe_pass(self):
        original = self.engine.cleanup._health
        def health(before, *, paused):
            if not paused and self.engine.phase == 'final-state-check':
                raise PreparationError('PRIVATE')
            return original(before, paused=paused)
        with patch.object(self.engine.cleanup, '_health', side_effect=health):
            report = self.probe()
        self.assertEqual(report['current_service_health'], 'not-confirmed')
        self.assertEqual(report['result'], 'probe-stopped-renewal-restored')
        self.assert_restored(report)

    def test_cooperative_lock_refuses_without_pause(self):
        with self.prep._lock(), self.assertRaises(PreparationError):
            self.probe()
        self.assertEqual(self.mutations(), [])

    def test_replaced_report_directory_is_not_written(self):
        def progress(phase):
            if phase == 'final-state-check':
                directory, = self.host.path(STATE).glob('renewal-pause-probe-*')
                moved = directory.with_name('moved-probe-records')
                directory.rename(moved)
                directory.mkdir(mode=0o700)
        self.engine.progress = progress
        report = self.probe()
        self.assert_restored(report)
        self.assertFalse(report['report_saved'])
        directory, = self.host.path(STATE).glob('renewal-pause-probe-*')
        self.assertEqual(list(directory.iterdir()), [])

    def test_busy_precheck_never_pauses(self):
        self.host.local_override = lambda c: Reply(0, BUSY) if c.argv == IDLE_QUERY else None
        with self.assertRaises(Exception):
            self.probe()
        self.assertEqual(self.mutations(), [])

    def test_requires_currently_enabled_renewal(self):
        self.host.enabled.discard('certbot.timer')
        self.host.active.discard('certbot.timer')
        with self.assertRaises(Exception):
            self.engine.check()
        self.assertEqual(self.mutations(), [])

    def test_pending_other_change_blocks(self):
        self.prep._record('token-change-intent', {'format': 1})
        with self.assertRaises(Exception):
            self.engine.check()
        self.assertEqual(self.mutations(), [])

    def test_no_second_probe_and_no_overwrite(self):
        self.assertEqual(self.probe()['result'], SUCCESS)
        before = self.snapshot()
        self.host.calls.clear()
        with self.assertRaises(Exception):
            self.probe()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.mutations(), [])

    def test_explicit_bool_confirmation_and_snapshot_required(self):
        plan = self.engine.check()
        for value in (False, 'y', 1, None):
            with self.assertRaises(PreparationError):
                self.engine.probe(plan, confirm_probe=value)
        path = self.fixture.directory + '/report.json'
        data = json.loads(self.host.path(path).read_bytes())
        data['elapsed_seconds'] = 999
        self.host.write(path, json.dumps(data).encode())
        with self.assertRaises(Exception):
            self.probe(plan)
        self.assertEqual(self.mutations(), [])

    def test_record_write_failure_does_not_pause(self):
        original = self.engine.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/started.json'):
                raise OSError(28, 'PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.engine.files, 'write_new', side_effect=write):
            report = self.probe()
        self.assertFalse(report['pause_attempted'])
        self.assertEqual(self.mutations(), [])
        self.assertTrue(report['report_saved'])

    def test_creation_race_does_not_write_into_existing_directory(self):
        original = self.engine.files.private_directory_new
        def create(path):
            original(path)
            self.host.write(path + '/external.json', b'preserve')
            raise FileExistsError('PRIVATE')
        with patch.object(self.engine.files, 'private_directory_new', side_effect=create):
            report = self.probe()
        self.assertFalse(report['pause_attempted'])
        self.assertFalse(report['report_saved'])
        self.assertEqual(self.mutations(), [])
        directory, = self.host.path(STATE).glob('renewal-pause-probe-*')
        self.assertEqual([p.name for p in directory.iterdir()], ['external.json'])

    def test_report_write_failure_does_not_undo_successful_restoration(self):
        original = self.engine.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/report.json'):
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.engine.files, 'write_new', side_effect=write):
            report = self.probe()
        self.assert_restored(report)
        self.assertFalse(report['report_saved'])

    def test_command_guard_denies_unpermitted_actions_and_restores_runner(self):
        original = self.prep.runner
        denied = [('certbot', 'delete'), ('certbot', 'renew'), ('systemctl', 'stop', 'certbot.service'),
                  ('systemctl', 'start', 'certbot.service'), ('systemctl', 'restart', 'nginx.service'),
                  ('ufw', 'reset'), ('apt-get', 'remove', 'certbot'), PAUSE, RESTORE,
                  ('openssl', 'pkey', '-in', 'private', '-out', 'stolen'),
                  ('systemctl', 'show', 'ssh.service', '-p', 'ActiveState')]
        with self.engine._commands():
            for argv in denied:
                with self.subTest(argv=argv), self.assertRaises(PreparationError):
                    self.prep.runner(Command(argv))
            self.engine.permitted = PAUSE
            self.prep.runner(Command(PAUSE))
            with self.assertRaises(PreparationError):
                self.prep.runner(Command(PAUSE))
        self.assertIs(self.prep.runner, original)


class RenewalPauseProbeCliTests(unittest.TestCase):
    def setUp(self):
        self.engine = Mock()
        self.engine.host_changes_attempted = False
        self.engine.probe.return_value = {'result': SUCCESS}
        self.patcher = patch('snellctl.renewalprobe.RenewalPauseProbe', return_value=self.engine)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    @contextmanager
    def factory(self):
        yield Mock()

    def test_default_cancel_and_yes_only(self):
        for answer in ('', 'n', 'yes', 'y'):
            self.engine.probe.reset_mock()
            code = run_renewal_pause_probe(factory=self.factory, terminal=Console([answer]))
            if answer == 'y':
                self.assertEqual(code, 0)
                self.engine.probe.assert_called_once_with(self.engine.check.return_value, confirm_probe=True)
            else:
                self.assertEqual(code, 130)
                self.engine.probe.assert_not_called()

    def test_requires_tty(self):
        ui = Console([])
        ui.interactive = lambda: False
        self.assertEqual(run_renewal_pause_probe(factory=self.factory, terminal=ui), 2)
        self.engine.check.assert_not_called()

    def test_experimental_gate(self):
        with patch('snellctl.renewalprobe.run_renewal_pause_probe', return_value=0) as run:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(['probe-renewal-pause']), 2)
            run.assert_not_called()
            self.assertEqual(main(['probe-renewal-pause', '--experimental']), 0)
            run.assert_called_once_with()

    def test_no_secret_or_auto_confirmation_arguments(self):
        for args in (['--yes'], ['--token', 'PRIVATE'], ['--domain', 'PRIVATE']):
            output = io.StringIO()
            with redirect_stderr(output), self.assertRaises(SystemExit):
                main(['probe-renewal-pause', '--experimental', *args])
            self.assertNotIn('PRIVATE', output.getvalue())

    def test_lost_output_does_not_run_again(self):
        ui = Console(['y'])
        original = ui.say
        def say(text):
            if text.startswith('{'):
                raise BrokenPipeError('lost terminal')
            original(text)
        ui.say = say
        self.assertEqual(run_renewal_pause_probe(factory=self.factory, terminal=ui), 1)
        self.engine.probe.assert_called_once()

    def test_hangup_handler_restored_on_error(self):
        previous = object()
        with patch('snellctl.renewalprobe.signal.signal', return_value=previous) as handler:
            with self.assertRaises(ValueError), ignore_ssh_hangup():
                raise ValueError('test')
        self.assertEqual(handler.call_args_list[0].args, (signal.SIGHUP, signal.SIG_IGN))
        self.assertEqual(handler.call_args_list[-1].args, (signal.SIGHUP, previous))


if __name__ == '__main__':
    unittest.main()
