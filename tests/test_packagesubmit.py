from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from snellctl import aptreview, packagedownload as download
from snellctl.hostcommands import DebianCommands
from snellctl.hostprep import Command, PreparationError, Reply, STATE
from snellctl.packageguards import INTENT
from snellctl.packagesubmit import encoded, observe_submission, submit
from test_packagejob import spec, status
from test_packagedownload import simulated, ORIGIN
import test_packageguards


class SubmissionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_packageguards.PackageGuardsTests('test_success_prepares_only_guards_and_preserves_all_existing_files')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.host, self.prep, self.job = self.fixture.host, self.fixture.prep, self.fixture.job
        self.engine, self.files = self.fixture.engine, self.prep.files
        with self.files.directory('/proc/sys/kernel/random', create=True):
            pass
        self.files.write_new('/proc/sys/kernel/random/boot_id', b'11111111-2222-3333-4444-555555555555\n', mode=0o444)
        self.state, self.interceptor, self.start_reply = 'idle', None, Reply(0)
        self.host.local_override = self.reply
        self.work = download.CACHE + '/' + self.job.job_id
        aptreview._prepare(self.files, self.work, download.configuration(self.work))
        self.files.write_new(self.work + '/lists/example_InRelease', b'synthetic verified index', mode=0o644)
        self.files.write_new(self.job.apt_config, download.configuration(self.work, install=True), mode=0o644)
        payload = b'synthetic certbot deb'
        path = self.work + '/cache/archives/certbot.deb'
        self.files.write_new(path, payload, mode=0o644)
        archive = download.Archive(self.job.changes[0], len(payload), hashlib.sha256(payload).hexdigest(), 'certbot.deb')
        self.batch = download.DownloadedPackages(self.job, (archive,),
                ((path, download.fingerprint(self.files, path, limit=download.MAX_DEB)),),
                download.index_snapshot(self.files, self.work), None)

    def reply(self, c):
        if self.interceptor:
            result = self.interceptor(c)
            if result is not None:
                return result
        if c.argv[:3] == ('systemctl', 'show', '--all') and c.argv[3] == self.job.unit:
            return status(self.job, self.state)
        if c.argv == ('systemctl', 'start', '--no-block', self.job.unit):
            for path in ('armed.json', 'submission-attempt.json', 'submission-ready.json'):
                self.assertIsNotNone(self.files.info(self.job.directory + '/' + path))
            self.state = 'running'
            self.files.write_new(self.job.directory + '/execution-claim.json', encoded({
                'format': 1, 'job_id': self.job.job_id, 'invocation': 'b' * 32}))
            return self.start_reply
        if c.argv == ('systemd-analyze', 'verify', self.job.unit_path):
            return Reply(0)
        if type(c) is download.InstallSimulationCommand:
            c.verify_files(self.files)
            return Reply(0, simulated(self.job.changes))
        if type(c) is download.DownloadCommand:
            c.verify_files(self.files)
            self.assertEqual(c.argv[:2], ('apt-cache', 'madison'))
            versions = {**self.host.versions, **{p.name: p.after for p in self.job.changes}}
            return Reply(0, ''.join(f'{n} | {versions[n]} | {ORIGIN}\n' for n in c.argv[2:]))
        return self.fixture.reply(c)

    def run_submit(self, action=None):
        with self.engine.protected(self.job, confirm_outage=True) as lease:
            self.lease = lease
            if action:
                action(lease)
            return submit(lease, self.batch, consent=True, review_confirmed=True)

    def starts(self):
        return [c.argv for c in self.host.calls if c.argv[:2] == ('systemctl', 'start')]

    def pending(self):
        self.assertTrue(self.prep._exists(INTENT))
        self.assertEqual(self.prep.status()['package_update'], 'needs-inspection')
        self.assertNotIn('nginx.service', self.host.active)
        self.assertNotIn('certbot.timer', self.host.active)

    def test_submit_once_records_private_files_and_never_runs_foreground_install(self):
        report = self.run_submit()
        self.assertEqual(report['result'], 'submitted-postchecks-required', report)
        self.assertTrue(report['submission_acknowledged'])
        self.assertFalse(report['upgrade_completed'])
        self.assertEqual(self.starts(), [('systemctl', 'start', '--no-block', self.job.unit)])
        self.assertTrue(all('--simulate' in c.argv for c in self.host.calls if c.argv[0] == 'apt-get'))
        for name in ('submission-intent.json', 'submission-ready.json', 'submission-attempt.json',
                     'armed.json', 'apt.log', 'launch.py', 'submission-result.json', 'execution-claim.json'):
            self.assertEqual(self.files.info(self.job.directory + '/' + name).st_mode & 0o777, 0o600)
        self.assertEqual(self.files.info(self.job.directory + '/home').st_mode & 0o777, 0o700)
        self.pending()

    def test_upgrade_and_separate_review_consent_are_both_required(self):
        def check(lease):
            for args in ({}, {'consent': True}, {'review_confirmed': True},
                         {'consent': 1, 'review_confirmed': True}):
                with self.assertRaises(PreparationError):
                    submit(lease, self.batch, **args)
        self.run_submit(check)

    def test_expired_or_wrong_lease_and_batch_refused_without_submission(self):
        with self.engine.protected(self.job, confirm_outage=True) as lease:
            self.lease = lease
            with self.assertRaises(PreparationError):
                submit(lease, replace(self.batch, job=replace(self.job, job_id='c' * 32)), consent=True, review_confirmed=True)
        with self.assertRaises(PreparationError):
            submit(self.lease, self.batch, consent=True, review_confirmed=True)
        self.assertEqual(self.starts(), [])

    def test_changed_download_before_submit_stops_before_new_records(self):
        def corrupt(_lease):
            self.host.path(self.batch.paths_and_fingerprints[0][0]).write_bytes(b'changed')
        report = self.run_submit(corrupt)
        self.assertEqual(report['result'], 'blocked-before-submission')
        self.assertFalse(report['host_changes_attempted'])
        self.assertIsNone(self.files.info(self.job.directory + '/submission-intent.json'))
        self.assertEqual(self.starts(), [])

    def test_install_config_simulation_must_equal_reviewed_changes(self):
        self.interceptor = lambda c: Reply(0, simulated(())) if type(c) is download.InstallSimulationCommand else None
        report = self.run_submit()
        self.assertFalse(report['submission_attempted'])
        self.assertEqual(self.starts(), [])

    def test_simulation_uncertainty_is_not_a_valid_plan(self):
        self.interceptor = lambda c: Reply(0, simulated(self.job.changes), uncertain=True) if type(c) is download.InstallSimulationCommand else None
        report = self.run_submit()
        self.assertFalse(report['submission_attempted'])

    def test_existing_job_artifacts_not_adopted(self):
        def foreign(_lease):
            self.files.write_new(self.job.directory + '/submission-attempt.json', b'foreign')
        report = self.run_submit(foreign)
        self.assertFalse(report['submission_attempted'])
        self.assertEqual(self.starts(), [])

    def test_unit_verification_failure_preserves_intent_without_start(self):
        self.interceptor = lambda c: Reply(1, 'PRIVATE-DETAIL') if c.argv[:2] == ('systemd-analyze', 'verify') else None
        report = self.run_submit()
        self.assertFalse(report['submission_attempted'])
        self.assertNotIn('PRIVATE-DETAIL', json.dumps(report))
        self.assertIsNotNone(self.files.info(self.job.directory + '/submission-intent.json'))
        self.assertIsNotNone(self.files.info(self.job.unit_path))
        self.pending()

    def test_cache_change_during_unit_load_refused(self):
        def mutate(c):
            if c.argv[:4] == ('systemctl', 'show', '--all', self.job.unit):
                self.host.path(self.batch.paths_and_fingerprints[0][0]).write_bytes(b'changed-after-check')
        self.interceptor = mutate
        report = self.run_submit()
        self.assertFalse(report['submission_attempted'])
        self.assertEqual(self.starts(), [])

    def test_changed_runtime_log_before_enqueue_refused(self):
        def mutate(c):
            if c.argv[:4] == ('systemctl', 'show', '--all', self.job.unit):
                self.host.path(self.job.directory + '/apt.log').write_bytes(b'unexpected execution')
        self.interceptor = mutate
        report = self.run_submit()
        self.assertFalse(report['submission_attempted'])
        self.assertEqual(self.starts(), [])
        self.pending()

    def test_ready_record_failure_does_not_enqueue_or_erase_attempt(self):
        real = self.files.write_new
        def fail(path, *args, **kwargs):
            if path.endswith('/submission-ready.json'):
                raise OSError('PRIVATE')
            return real(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.run_submit()
        self.assertFalse(report['submission_attempted'])
        self.assertEqual(self.starts(), [])
        self.assertIsNotNone(self.files.info(self.job.directory + '/submission-attempt.json'))
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'inspection-required')

    def test_loaded_unit_with_prior_execution_refused(self):
        self.state = 'done'
        report = self.run_submit()
        self.assertFalse(report['submission_attempted'])
        self.assertIsNone(self.files.info(self.job.directory + '/armed.json'))

    def test_loaded_unit_override_refused(self):
        self.interceptor = lambda c: status(self.job, 'idle', DropInPaths='/unexpected') if c.argv[:4] == ('systemctl', 'show', '--all', self.job.unit) else None
        report = self.run_submit()
        self.assertFalse(report['submission_attempted'])

    def test_repeated_call_after_ack_does_not_submit_again_or_overwrite_result(self):
        with self.engine.protected(self.job, confirm_outage=True) as lease:
            first = submit(lease, self.batch, consent=True, review_confirmed=True)
            saved = self.files.read(self.job.directory + '/submission-result.json')
            second = submit(lease, self.batch, consent=True, review_confirmed=True)
            self.assertEqual(first['result'], 'submitted-postchecks-required')
            self.assertFalse(second['submission_attempted'])
            self.assertEqual(self.files.read(self.job.directory + '/submission-result.json'), saved)
        self.assertEqual(len(self.starts()), 1)

    def test_uncertain_enqueue_is_retained_not_retried(self):
        self.start_reply = Reply(-1, uncertain=True)
        report = self.run_submit()
        self.assertTrue(report['submission_attempted'])
        self.assertFalse(report['submission_acknowledged'])
        self.assertEqual(report['result'], 'submission-uncertain-inspect-only')
        self.assertEqual(len(self.starts()), 1)
        self.pending()
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'running-or-queued')

    def test_enqueue_nonzero_is_not_permission_to_retry(self):
        self.start_reply = Reply(1, 'PRIVATE-DETAIL')
        report = self.run_submit()
        self.assertEqual(report['result'], 'submission-uncertain-inspect-only')
        self.assertNotIn('PRIVATE-DETAIL', json.dumps(report))
        self.assertEqual(len(self.starts()), 1)

    def test_interruption_before_enqueue_leaves_consumed_attempt(self):
        real = self.files.write_new
        def interrupted(path, *args, **kwargs):
            result = real(path, *args, **kwargs)
            if path.endswith('/submission-attempt.json'):
                raise KeyboardInterrupt
            return result
        with patch.object(self.files, 'write_new', side_effect=interrupted):
            report = self.run_submit()
        self.assertFalse(report['submission_attempted'])
        self.assertEqual(self.starts(), [])
        self.assertIsNotNone(self.files.info(self.job.directory + '/submission-attempt.json'))
        self.assertIsNone(self.files.info(self.job.directory + '/armed.json'))
        self.pending()

    def test_interruption_during_enqueue_never_stops_backend_or_unmasks(self):
        def interrupted(c):
            if c.argv == ('systemctl', 'start', '--no-block', self.job.unit):
                raise KeyboardInterrupt
        self.interceptor = interrupted
        report = self.run_submit()
        self.assertTrue(report['submission_attempted'])
        self.assertEqual(report['result'], 'interrupted-inspect-only')
        self.assertFalse(any(c.argv[:2] in {('systemctl', 'unmask'), ('systemctl', 'restart')}
                             or c.argv == ('systemctl', 'stop', self.job.unit) for c in self.host.calls))
        self.pending()

    def test_record_write_failure_after_enqueue_preserves_submission_evidence(self):
        real = self.files.write_new
        def fail(path, *args, **kwargs):
            if path.endswith('/submission-result.json'):
                raise OSError('PRIVATE')
            return real(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.run_submit()
        self.assertTrue(report['submission_acknowledged'])
        self.assertFalse(report['report_saved'])
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'running-or-queued')

    def test_read_only_observation_matches_claim_without_rechecking_changed_package_state(self):
        self.run_submit()
        self.state = 'done'
        self.host.versions['certbot'] = self.job.changes[0].after
        before = self.fixture.fixture.snapshot()
        self.host.calls.clear()
        report = observe_submission(self.prep, self.job)
        self.assertEqual(report['result'], 'command-exited-success')
        self.assertTrue(report['execution_claim_matches'])
        self.assertFalse(report['upgrade_completed'])
        self.assertEqual(before, self.fixture.fixture.snapshot())
        self.assertTrue(all(c.argv[:3] == ('systemctl', 'show', '--all') for c in self.host.calls))

    def test_noncanonical_execution_claim_is_not_evidence(self):
        self.run_submit()
        self.state = 'done'
        path = self.host.path(self.job.directory + '/execution-claim.json')
        original = path.read_bytes()
        malformed = (
            original.replace(b'"format": 1', b'"format": true'),
            original.replace(b'"format": 1', b'"format": 1.0'),
            original.replace(b'"format": 1', b'"format": 0, "format": 1'),
            original.replace(b'"invocation":', b'"invocation": "invalid", "invocation":'),
        )
        for raw in malformed:
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                self.host.calls.clear()
                report = observe_submission(self.prep, self.job)
                self.assertEqual(report['result'], 'inspection-required')
                self.assertFalse(report['execution_claim_matches'])
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(self.host.calls, [])
        path.write_bytes(original)
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'command-exited-success')

    def test_report_write_eof_preserves_acknowledged_submission(self):
        real = self.files.write_new
        def fail(path, *args, **kwargs):
            if path.endswith('/submission-result.json'):
                raise EOFError('PRIVATE')
            return real(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.run_submit()
        self.assertEqual(report['result'], 'interrupted-inspect-only')
        self.assertTrue(report['submission_attempted'])
        self.assertTrue(report['submission_acknowledged'])
        self.assertFalse(report['report_saved'])
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'running-or-queued')
        self.assertEqual(sum(c.argv == ('systemctl', 'start', '--no-block', self.job.unit)
                             for c in self.host.calls), 1)

    def test_missing_execution_claim_never_proves_success(self):
        self.run_submit()
        self.host.path(self.job.directory + '/execution-claim.json').unlink()
        self.state = 'done'
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'inspection-required')
        self.state = 'idle'
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'execution-not-proven-do-not-resubmit')

    def test_another_invocation_cannot_replace_original_claim(self):
        self.run_submit()
        self.interceptor = lambda c: status(self.job, 'done', InvocationID='c' * 32) if c.argv[:4] == ('systemctl', 'show', '--all', self.job.unit) else None
        report = observe_submission(self.prep, self.job)
        self.assertEqual(report['result'], 'inspection-required')
        self.assertFalse(report['execution_claim_matches'])

    def test_mutated_launcher_unit_and_authority_refused_by_observation(self):
        self.run_submit()
        for path in (self.job.unit_path, self.job.directory + '/launch.py', self.job.directory + '/armed.json'):
            original = self.host.path(path).read_bytes()
            self.host.path(path).write_bytes(original + b'changed')
            self.assertEqual(observe_submission(self.prep, self.job)['result'], 'inspection-required')
            self.host.path(path).write_bytes(original)

    def test_observation_failure_and_interruption_do_not_mutate(self):
        self.run_submit()
        before = self.fixture.fixture.snapshot()
        self.interceptor = lambda c: Reply(-1, uncertain=True) if c.argv[:4] == ('systemctl', 'show', '--all', self.job.unit) else None
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'inspection-required')
        self.assertEqual(before, self.fixture.fixture.snapshot())
        def interrupted(c):
            raise KeyboardInterrupt
        self.interceptor = interrupted
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'observation-interrupted-task-not-stopped')
        self.assertEqual(before, self.fixture.fixture.snapshot())

    def test_observation_rejects_claim_changed_during_query(self):
        self.run_submit()
        def mutate(c):
            if c.argv[:4] == ('systemctl', 'show', '--all', self.job.unit):
                self.host.path(self.job.directory + '/execution-claim.json').write_bytes(encoded({
                    'format': 1, 'job_id': self.job.job_id, 'invocation': 'e' * 32}))
        self.interceptor = mutate
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'inspection-required')

    def test_reports_do_not_expose_domain_keys_or_execution_identifiers(self):
        report = self.run_submit()
        report2 = observe_submission(self.prep, self.job)
        from test_hostprep import DOMAIN, TOKEN
        text = json.dumps([report, report2])
        for value in (DOMAIN, TOKEN, self.job.job_id, self.job.directory, 'b' * 32, 'INVOCATION_ID'):
            self.assertNotIn(value, text)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        # A private workspace child avoids shared writable /tmp ancestors.
        self.tmp = tempfile.TemporaryDirectory(prefix='.launcher-test-', dir=Path.cwd())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.job = spec()
        self.invocation = 'c' * 32
        for name, kind in (('armed.json', 'armed'), ('submission-attempt.json', 'submission-attempt')):
            (self.root / name).write_bytes(self.job.authority_bytes(kind))
            (self.root / name).chmod(0o600)
        self.source = self.job.launcher_bytes().decode().replace(repr(self.job.directory), repr(str(self.root)), 1)
        # Exercise the actual claim code but replace execve with a harmless effect.
        self.source = self.source.replace('os.execve(ARGV[0], ARGV, ENVIRONMENT)',
            'open(DIRECTORY + "/executed", "wb").write(json.dumps({"argv": ARGV, "env": ENVIRONMENT}).encode())')
        self.script = self.root / 'launch.py'

    def run_child(self, *, invocation=None, source=None):
        self.script.write_text(self.source if source is None else source)
        self.script.chmod(0o600)
        return subprocess.run([sys.executable, '-I', '-S', '-B', str(self.script)],
                              env={'INVOCATION_ID': self.invocation if invocation is None else invocation,
                                   'CF_Token': 'PRIVATE-ENV', 'http_proxy': 'PRIVATE-PROXY'},
                              capture_output=True, timeout=10)

    def test_one_execution_claim_binds_invocation_and_sanitizes_apt_environment(self):
        first = self.run_child()
        self.assertEqual(first.returncode, 0, first.stderr)
        claim = json.loads((self.root / 'execution-claim.json').read_bytes())
        self.assertEqual(claim, {'format': 1, 'job_id': self.job.job_id, 'invocation': self.invocation})
        self.assertEqual((self.root / 'execution-claim.json').stat().st_mode & 0o777, 0o600)
        executed = json.loads((self.root / 'executed').read_bytes())
        self.assertEqual(executed['argv'], ['/usr/bin/apt-get', *self.job.install_argv()[1:]])
        self.assertNotIn('CF_Token', executed['env'])
        self.assertNotIn('http_proxy', executed['env'])
        (self.root / 'executed').unlink()
        again = self.run_child(invocation='d' * 32)
        self.assertEqual(again.returncode, 125)
        self.assertFalse((self.root / 'executed').exists())
        self.assertEqual(json.loads((self.root / 'execution-claim.json').read_bytes()), claim)

    def test_missing_or_malformed_invocation_blocks_before_claim(self):
        for invocation in ('', 'invalid', 'a' * 31, 'a' * 33):
            self.assertEqual(self.run_child(invocation=invocation).returncode, 125)
            self.assertFalse((self.root / 'execution-claim.json').exists())

    def test_missing_or_modified_authority_blocks_before_claim(self):
        path = self.root / 'armed.json'
        path.write_bytes(b'not-authorized')
        self.assertEqual(self.run_child().returncode, 125)
        self.assertFalse((self.root / 'execution-claim.json').exists())

    def test_symlinked_authority_blocks_before_claim(self):
        target = self.root / 'armed.json'
        target.rename(self.root / 'real-armed.json')
        target.symlink_to(self.root / 'real-armed.json')
        self.assertEqual(self.run_child().returncode, 125)
        self.assertFalse((self.root / 'execution-claim.json').exists())

    def test_nonprivate_runtime_directory_blocks_before_claim(self):
        self.root.chmod(0o755)
        self.assertEqual(self.run_child().returncode, 125)
        self.assertFalse((self.root / 'execution-claim.json').exists())

    def test_concurrent_launchers_only_one_claim_wins(self):
        self.script.write_text(self.source)
        self.script.chmod(0o600)
        children = []
        try:
            for invocation in ('c' * 32, 'd' * 32):
                children.append(subprocess.Popen([sys.executable, '-I', '-S', '-B', str(self.script)],
                    env={'INVOCATION_ID': invocation}, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            for child in children:
                child.communicate(timeout=10)
            self.assertEqual(sorted(child.returncode for child in children), [0, 125])
            winner = 0 if children[0].returncode == 0 else 1
            claim = json.loads((self.root / 'execution-claim.json').read_bytes())
            self.assertEqual(claim['invocation'], ('c' * 32, 'd' * 32)[winner])
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate()

    def test_wrong_permissions_and_hardlinked_authority_rejected(self):
        path = self.root / 'armed.json'
        path.chmod(0o644)
        self.assertEqual(self.run_child().returncode, 125)
        path.chmod(0o600)
        os.link(path, self.root / 'link')
        self.assertEqual(self.run_child().returncode, 125)
        self.assertFalse((self.root / 'execution-claim.json').exists())

    def test_existing_or_symlinked_claim_never_overwritten(self):
        target = self.root / 'untouched'
        target.write_bytes(b'original')
        (self.root / 'execution-claim.json').symlink_to(target)
        self.assertEqual(self.run_child().returncode, 125)
        self.assertEqual(target.read_bytes(), b'original')
        self.assertFalse((self.root / 'executed').exists())

    def test_failure_between_claim_and_exec_remains_nonretryable(self):
        source = self.source.replace('os.chdir("/")', 'raise OSError("PRIVATE-ERROR")')
        failed = self.run_child(source=source)
        self.assertEqual(failed.returncode, 125)
        self.assertNotIn(b'PRIVATE-ERROR', failed.stderr)
        self.assertTrue((self.root / 'execution-claim.json').is_file())
        self.assertEqual(self.run_child().returncode, 125)
        self.assertFalse((self.root / 'executed').exists())

    def test_truncated_claim_from_interruption_does_not_rearm(self):
        (self.root / 'execution-claim.json').write_bytes(b'')
        self.assertEqual(self.run_child().returncode, 125)
        self.assertFalse((self.root / 'executed').exists())

    def test_generated_launcher_uses_python311_syntax(self):
        import ast
        ast.parse(self.job.launcher_bytes(), feature_version=(3, 11))


class SimulationAdapterTests(unittest.TestCase):
    def test_actual_install_args_rejected_before_spawn(self):
        job = spec()
        command = download.InstallSimulationCommand(job.install_argv(), capture_stderr=True, job=job)
        with patch('snellctl.hostcommands.subprocess.Popen') as spawn, self.assertRaises(PreparationError):
            object.__new__(DebianCommands)(command)
        spawn.assert_not_called()

    def test_simulation_uses_install_config_not_download_config(self):
        job = spec()
        command = download.InstallSimulationCommand(job.install_argv(simulate=True), capture_stderr=True, job=job)
        real = subprocess.Popen
        def harmless(args, **kwargs):
            self.assertEqual(args, ['/usr/bin/apt-get', *command.argv[1:]])
            self.assertEqual(kwargs['env']['APT_CONFIG'], job.apt_config)
            return real([sys.executable, '-c', 'print("simulation only")'], **kwargs)
        with patch.object(download.InstallSimulationCommand, 'verify_files') as verified, \
             patch('snellctl.hostcommands.subprocess.Popen', side_effect=harmless):
            self.assertEqual(object.__new__(DebianCommands)(command).code, 0)
        verified.assert_called_once()


if __name__ == '__main__':
    unittest.main()
