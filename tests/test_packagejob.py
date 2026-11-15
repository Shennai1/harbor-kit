from contextlib import redirect_stderr
from dataclasses import replace
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

from snellctl.__main__ import main
from snellctl.hostprep import HostFiles, PreparationError, Reply
from snellctl.packagejob import FIELDS, JobObserver, JobSpec, observation
from snellctl.packagepolicy import RevisionChange


def spec():
    return JobSpec('a' * 32, (RevisionChange('nginx', 'amd64', '1.26.3-3+deb13u9', '1.26.3-3+deb13u10'),
                              RevisionChange('nginx-common', 'all', '1.26.3-3+deb13u9', '1.26.3-3+deb13u10')))


def status(job, state='done', **overrides):
    fields = dict(Id=job.unit, LoadState='loaded', ActiveState='active', SubState='exited',
                  UnitFileState='static', FragmentPath=job.unit_path, DropInPaths='', NeedDaemonReload='no',
                  MainPID='0', ControlPID='0', Job='', Result='success', ExecMainCode='1', ExecMainStatus='0',
                  ExecMainStartTimestampMonotonic='100', ExecMainExitTimestampMonotonic='200',
                  InvocationID='b' * 32, Type='oneshot', RemainAfterExit='yes', Restart='no',
                  NRestarts='0', TimeoutStartUSec='infinity')
    if state == 'running':
        fields.update(ActiveState='activating', SubState='start', MainPID='456', Job='789',
                      ExecMainExitTimestampMonotonic='0', ExecMainCode='0')
    elif state == 'idle':
        fields.update(ActiveState='inactive', SubState='dead', InvocationID='', ExecMainCode='0',
                      ExecMainStartTimestampMonotonic='0', ExecMainExitTimestampMonotonic='0')
    elif state == 'queued':
        return status(job, 'idle', Job='789', **overrides)
    elif state == 'failed':
        fields.update(ActiveState='failed', SubState='failed', Result='exit-code', ExecMainStatus='100')
    fields.update(overrides)
    return Reply(0, ''.join(k + '=' + v + '\n' for k, v in fields.items()))


class JobSpecificationTests(unittest.TestCase):
    def test_template_only_returns_bytes_without_shell_or_boot_enablement(self):
        job = spec()
        text = job.unit_bytes().decode()
        for token in ('Type=oneshot', 'RemainAfterExit=yes', 'Restart=no', 'TimeoutStartSec=infinity',
                      'RuntimeMaxSec=infinity', 'RefuseManualStop=yes', 'UMask=0077',
                      'ExecStart=/usr/bin/python3 -I -S -B '):
            self.assertIn(token, text)
        for token in ('[Install]', 'WantedBy=', 'ExecStop=', '/bin/sh', '--force', '--allow-',
                      'CF_Token', 'package-review/', 'KillMode=none'):
            self.assertNotIn(token, text)
        self.assertEqual(text.count('ExecStart='), 1)
        launcher = job.launcher_bytes().decode()
        for token in ('nginx=1.26.3-3+deb13u10', 'nginx-common=1.26.3-3+deb13u10',
                      '--no-download', '--only-upgrade', 'os.execve', 'os.O_EXCL', 'os.fsync'):
            self.assertIn(token, launcher)
        self.assertNotIn('ENVIRONMENT = dict(os.environ)', launcher)

    def test_job_names_and_version_values_cannot_inject_unit_directives(self):
        for identifier in ('', '../other', 'A' * 32, 'a' * 31, 'a' * 32 + '\n', 'a' * 32 + '%i'):
            with self.subTest(identifier=identifier), self.assertRaises(PreparationError):
                replace(spec(), job_id=identifier)
        with self.assertRaises(PreparationError):
            RevisionChange('nginx', 'amd64', '1.0-1', '1.0-2\nExecStart=/bin/sh')

    def test_empty_unsorted_duplicate_and_mutable_change_sets_refused(self):
        for changes in ((), list(spec().changes), spec().changes[::-1], spec().changes * 2):
            with self.subTest(changes=changes), self.assertRaises(PreparationError):
                JobSpec('a' * 32, changes)

    def test_upgrader_not_exposed_in_cli(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            main(['package-update', '--experimental'])
        self.assertEqual(result.exception.code, 2)


class JobObservationTests(unittest.TestCase):
    def test_success_is_command_exit_not_completed_upgrade(self):
        self.assertEqual(observation(spec(), status(spec())).state, 'command-exited-success')

    def test_idle_zero_exit_status_is_not_success(self):
        self.assertEqual(observation(spec(), status(spec(), 'idle')).state, 'not-started')

    def test_queued_or_active_process_always_remains_pending(self):
        for reply in (status(spec(), 'queued'), status(spec(), 'running'), status(spec(), MainPID='123'),
                      status(spec(), ControlPID='123'), status(spec(), Job='456')):
            self.assertEqual(observation(spec(), reply).state, 'running-or-queued')

    def test_failure_requires_real_execution_evidence(self):
        self.assertEqual(observation(spec(), status(spec(), 'failed')).state, 'command-exited-failure')
        self.assertEqual(observation(spec(), status(spec(), 'failed', ExecMainCode='0',
                                                  ExecMainStartTimestampMonotonic='0')).state, 'inconclusive')

    def test_signal_termination_is_not_success(self):
        self.assertEqual(observation(spec(), status(spec(), 'failed', Result='signal',
                                                  ExecMainCode='2', ExecMainStatus='9')).state,
                         'command-exited-failure')

    def test_zero_exit_alone_or_stopped_unit_does_not_prove_command_succeeded(self):
        for overrides in (dict(InvocationID=''), dict(ExecMainStartTimestampMonotonic='0'),
                          dict(ExecMainExitTimestampMonotonic='0'), dict(ExecMainCode='0'),
                          dict(ExecMainStatus='1'), dict(ActiveState='inactive', SubState='dead'),
                          dict(Result='resources'), dict(ExecMainExitTimestampMonotonic='99')):
            with self.subTest(overrides=overrides):
                self.assertEqual(observation(spec(), status(spec(), **overrides)).state, 'inconclusive')

    def test_missing_duplicate_extra_and_nonproperty_output_fail_closed(self):
        original = status(spec()).output
        for data in (original.replace('Job=\n', ''), original + 'Job=\n', original + 'Secret=PRIVATE\n',
                     original + 'warning\n', original + '\n', original.replace('Job=\n', 'Job=\x1bPRIVATE\n'),
                     original * 1000):
            with self.subTest(data=data[:30]), self.assertRaises(PreparationError) as caught:
                observation(spec(), Reply(0, data))
            self.assertNotIn('PRIVATE', str(caught.exception))

    def test_unexpected_unit_configuration_failed_query_or_uncertainty_is_refused(self):
        for overrides in (dict(Id='ssh.service'), dict(LoadState='not-found'), dict(DropInPaths='/private'),
                          dict(FragmentPath='/private'), dict(NeedDaemonReload='yes'), dict(Restart='always'),
                          dict(NRestarts='1'), dict(TimeoutStartUSec='1min'), dict(Type='simple'),
                          dict(RemainAfterExit='no'), dict(UnitFileState='enabled')):
            with self.subTest(overrides=overrides), self.assertRaises(PreparationError):
                observation(spec(), status(spec(), **overrides))
        for reply in (Reply(1, status(spec()).output), Reply(0, status(spec()).output, uncertain=True), None):
            with self.assertRaises(PreparationError):
                observation(spec(), reply)

    def test_numeric_and_invocation_fields_strict(self):
        for value in ('-1', '1x', '1.0', '00', '9' * 21):
            with self.subTest(value=value), self.assertRaises(PreparationError):
                observation(spec(), status(spec(), MainPID=value))
        with self.assertRaises(PreparationError):
            observation(spec(), status(spec(), InvocationID='PRIVATE'))


class JobWaitTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.files = HostFiles(self.root)
        self.addCleanup(self.files.close)
        self.job = spec()
        self.unit = self.root / self.job.unit_path.lstrip('/')
        self.unit.parent.mkdir(parents=True)
        self.unit.write_bytes(self.job.unit_bytes())
        self.unit.chmod(0o644)
        self.runner = Mock(return_value=status(self.job))
        self.observer = JobObserver(self.job, self.files, self.runner)
        self.now = 0.0

    def sleep(self, seconds):
        self.now += seconds

    def wait(self, **kwargs):
        return self.observer.wait(clock=lambda: self.now, sleep=self.sleep, **kwargs)

    def assert_queries_only(self):
        for call in self.runner.call_args_list:
            command = call.args[0]
            self.assertEqual(command.argv, ('systemctl', 'show', '--all', self.job.unit, '-p', ','.join(FIELDS)))
            self.assertFalse(command.capture_stderr)

    def test_queued_running_and_completed_job_without_mutation(self):
        self.runner.side_effect = [status(self.job, 'queued'), status(self.job, 'running'), status(self.job)]
        report = self.wait()
        self.assertEqual(report['result'], 'command-exited-success')
        self.assertEqual(report['samples'], 3)
        self.assertFalse(report['upgrade_completed'])
        self.assertTrue(report['postchecks_required'])
        self.assertFalse(report['task_stop_attempted'])
        self.assertEqual(self.unit.read_bytes(), self.job.unit_bytes())
        self.assert_queries_only()

    def test_deadline_exhaustion_does_not_stop_or_retry_job(self):
        self.runner.return_value = status(self.job, 'running')
        report = self.wait(budget=3)
        self.assertEqual(report['result'], 'wait-budget-exhausted-task-not-stopped')
        self.assertEqual(report['samples'], 3)
        self.assertFalse(report['automatic_retry'])
        self.assert_queries_only()

    def test_deadline_does_not_use_full_query_timeout_past_budget(self):
        self.runner.return_value = status(self.job, 'running')
        self.wait(budget=3, interval=2)
        self.assertEqual([c.args[0].timeout for c in self.runner.call_args_list], [3, 1])

    def test_uncertain_or_failed_query_does_not_imply_task_failed(self):
        for reply in (Reply(-1, uncertain=True), Reply(1, 'PRIVATE')):
            self.runner.return_value = reply
            report = self.wait()
            self.assertEqual(report['result'], 'observation-failed')
            self.assertEqual(report['last_state'], 'not-observed')
            self.assertNotIn('PRIVATE', json.dumps(report))
        self.assert_queries_only()

    def test_interruption_does_not_dispatch_cleanup(self):
        self.runner.side_effect = KeyboardInterrupt
        report = self.wait()
        self.assertEqual(report['result'], 'observation-interrupted-task-not-stopped')
        self.assert_queries_only()

    def test_invocation_change_and_execution_restart_fail_closed(self):
        for change in (dict(InvocationID='c' * 32), dict(ExecMainStartTimestampMonotonic='101')):
            self.observer = JobObserver(self.job, self.files, self.runner)
            self.runner.side_effect = [status(self.job, 'running'), status(self.job, **change)]
            report = self.wait()
            self.assertEqual(report['result'], 'observation-failed')
            self.assertFalse(report['upgrade_completed'])

    def test_supplied_anchor_must_match_existing_invocation(self):
        self.observer = JobObserver(self.job, self.files, self.runner, invocation='c' * 32, started=100)
        self.assertEqual(self.wait()['result'], 'observation-failed')
        self.observer = JobObserver(self.job, self.files, self.runner, invocation='b' * 32, started=100)
        self.assertEqual(self.wait()['result'], 'command-exited-success')

    def test_invalid_anchor_or_budget_is_rejected_without_query(self):
        for arguments in (dict(invocation='b' * 32), dict(started=100), dict(invocation='PRIVATE', started=100)):
            with self.assertRaises(PreparationError):
                JobObserver(self.job, self.files, self.runner, **arguments)
        for arguments in (dict(budget=0), dict(budget=901), dict(budget=True), dict(interval=0),
                          dict(interval=float('nan')), dict(interval=True)):
            with self.assertRaises(PreparationError):
                self.wait(**arguments)
        self.runner.assert_not_called()

    def test_missing_changed_or_writable_unit_is_not_observed(self):
        self.unit.write_bytes(self.job.unit_bytes() + b'Restart=always\n')
        self.assertEqual(self.wait()['result'], 'observation-failed')
        self.unit.write_bytes(self.job.unit_bytes())
        self.unit.chmod(0o666)
        self.assertEqual(self.wait()['result'], 'observation-failed')
        self.unit.unlink()
        self.assertEqual(self.wait()['result'], 'observation-failed')
        self.runner.assert_not_called()

    def test_symlinked_unit_is_not_followed(self):
        target = self.root / 'unit'
        self.unit.rename(target)
        self.unit.symlink_to(target)
        self.assertEqual(self.wait()['result'], 'observation-failed')
        self.runner.assert_not_called()

    def test_unit_replaced_during_query_is_refused_even_if_content_matches(self):
        def reply(command):
            alternate = self.unit.with_suffix('.new')
            alternate.write_bytes(self.job.unit_bytes())
            alternate.chmod(0o644)
            alternate.replace(self.unit)
            return status(self.job)
        self.runner.side_effect = reply
        self.assertEqual(self.wait()['result'], 'observation-failed')

    def test_no_raw_paths_identifiers_or_process_details_in_report(self):
        report = self.wait()
        text = json.dumps(report)
        for private in (self.job.unit, self.job.job_id, self.job.directory, 'b' * 32, 'MainPID', 'InvocationID'):
            self.assertNotIn(private, text)

    def test_real_harmless_child_survives_observer_budget_exhaustion(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True)
        try:
            self.runner.side_effect = lambda command: status(self.job, 'running', MainPID=str(child.pid))
            report = self.wait(budget=1)
            self.assertEqual(report['result'], 'wait-budget-exhausted-task-not-stopped')
            self.assertIsNone(child.poll())
            self.assert_queries_only()
        finally:
            # Only the test owns/stops this harmless child, not the observer.
            child.terminate()
            child.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
