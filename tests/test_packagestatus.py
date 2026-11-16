from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.hostprep import STATE, Reply
from snellctl.packagejob import FIELDS
from snellctl.packagestatus import collect_status, run_package_status
from snellctl.packagesubmit import encoded, update_intent
from test_hostprep import DOMAIN, TOKEN
from test_packagejob import status
import test_packagesubmit


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_packagesubmit.SubmissionTests('test_submit_once_records_private_files_and_never_runs_foreground_install')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.prep, self.files, self.host, self.job = self.fixture.prep, self.fixture.files, self.fixture.host, self.fixture.job
        self.path = STATE + '/package-update-intent.json'
        self.host.calls.clear()

    def observe(self):
        self.host.calls.clear()
        with patch.object(self.files, 'write_new', side_effect=AssertionError('must not write')), \
                patch.object(self.files, 'unlink_owned', side_effect=AssertionError('must not delete')):
            report = collect_status(self.prep)
        for c in self.host.calls:
            self.assertEqual(c.argv, ('systemctl', 'show', '--all', self.job.unit, '-p', ','.join(FIELDS)))
        self.assertFalse(report['host_changes_attempted'])
        self.assertFalse(report['upgrade_completed'])
        self.assertFalse(report['restoration_authorized'])
        for secret in (DOMAIN, TOKEN, 'PRIVATE-EXCEPTION'):
            self.assertNotIn(secret, json.dumps(report))
        return report

    def prepare(self):
        self.assertTrue(self.fixture.run_submit()['submission_acknowledged'])

    def test_missing_intent_is_not_a_health_or_completion_claim(self):
        report = self.observe()
        self.assertEqual(report['result'], 'no-active-update-record-not-a-health-verdict')
        self.assertEqual(self.host.calls, [])

    def test_running_original_job_is_only_observed(self):
        self.prepare()
        report = self.observe()
        self.assertEqual(report['result'], 'running-or-queued', report)
        self.assertTrue(report['observation']['execution_claim_matches'])

    def test_success_is_not_restoration_or_completed_upgrade(self):
        self.prepare()
        self.fixture.state = 'done'
        report = self.observe()
        self.assertEqual(report['result'], 'command-exited-success', report)
        self.assertTrue(report['observation']['postchecks_required'])

    def test_failed_job_is_not_restarted(self):
        self.prepare()
        self.fixture.state = 'failed'
        self.assertEqual(self.observe()['result'], 'command-exited-failure')

    def test_partial_guard_record_does_not_create_task(self):
        self.files.write_new(self.path, encoded(update_intent(self.job)))
        self.assertEqual(self.observe()['result'], 'inspection-required')
        self.assertEqual(self.host.calls, [])

    def test_malformed_and_duplicate_intent_keys_never_query_a_unit(self):
        for data in (b'{}', b'{"PRIVATE-EXCEPTION":',
                     encoded(update_intent(self.job)).replace(b'{', b'{"format":1,', 1),
                     encoded(update_intent(self.job)).replace(b'"outage_confirmed": true', b'"outage_confirmed": 1'),
                     encoded(update_intent(self.job)).replace(self.job.job_id.encode(), b'../../evil')):
            with self.subTest(data=data):
                self.host.write(self.path, data, 0o600)
                self.assertEqual(self.observe()['result'], 'inspection-required')
                self.assertEqual(self.host.calls, [])

    def test_public_permissions_and_link_intent_are_refused(self):
        self.prepare()
        target = self.host.path(self.path)
        target.chmod(0o644)
        self.assertEqual(self.observe()['result'], 'inspection-required')
        target.chmod(0o600)
        target.rename(str(target) + '.old')
        target.symlink_to(str(target) + '.old')
        self.assertEqual(self.observe()['result'], 'inspection-required')
        self.assertEqual(self.host.calls, [])

    def test_changed_invocation_is_not_the_original_execution(self):
        self.prepare()
        self.fixture.interceptor = lambda c: status(self.job, 'done', InvocationID='f' * 32)
        self.assertEqual(self.observe()['result'], 'inspection-required')

    def test_missing_claim_cannot_prove_success(self):
        self.prepare()
        self.fixture.state = 'done'
        self.host.path(self.job.directory + '/execution-claim.json').unlink()
        self.assertEqual(self.observe()['result'], 'inspection-required')

    def test_uncertain_systemctl_result_never_proves_success(self):
        self.prepare()
        self.fixture.interceptor = lambda c: Reply(0, 'PRIVATE-EXCEPTION', uncertain=True)
        self.assertEqual(self.observe()['result'], 'inspection-required')

    def test_intent_replacement_during_observation_is_detected(self):
        self.prepare()
        def change(c):
            target = self.host.path(self.path)
            content = target.read_bytes()
            target.rename(str(target) + '.old')
            target.write_bytes(content)
            target.chmod(0o600)
            return status(self.job, 'done')
        self.fixture.interceptor = change
        self.assertEqual(self.observe()['result'], 'inspection-required')

    def test_status_never_reads_secrets_or_raw_task_log(self):
        self.prepare()
        original = self.files.read
        def read(path, **kwargs):
            self.assertNotIn('/credentials/', path)
            self.assertNotIn('/letsencrypt/', path)
            self.assertNotIn('/nodes/', path)
            self.assertFalse(path.endswith('apt.log'))
            return original(path, **kwargs)
        with patch.object(self.files, 'read', side_effect=read):
            self.assertEqual(self.observe()['result'], 'running-or-queued')

    def test_json_adapter_is_parseable_without_terminal_or_mutations(self):
        @contextmanager
        def factory():
            yield self.fixture.engine.tokens
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(run_package_status(factory=factory, json_output=True), 0)
        self.assertEqual(json.loads(out.getvalue())['result'], 'no-active-update-record-not-a-health-verdict')
        self.assertEqual(self.host.calls, [])


class EntryTests(unittest.TestCase):
    def test_readonly_entry_routes_without_experimental_optin(self):
        with patch('snellctl.packagestatus.run_package_status', return_value=0) as run:
            self.assertEqual(main(['package-update-status', '--json']), 0)
            run.assert_called_once_with(json_output=True)

    def test_job_selection_and_automatic_resume_are_not_accepted(self):
        for args in (['--job-id', 'PRIVATE-EXCEPTION'], ['--resume'], ['--retry'], ['--experimental']):
            with redirect_stderr(io.StringIO()) as out, self.assertRaises(SystemExit):
                main(['package-update-status', *args])
            self.assertNotIn('PRIVATE-EXCEPTION', out.getvalue())

    def test_factory_error_is_redacted(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(run_package_status(factory=Mock(side_effect=RuntimeError('PRIVATE-EXCEPTION')), json_output=True), 1)
        self.assertEqual(json.loads(out.getvalue())['result'], 'inspection-required')
        self.assertNotIn('PRIVATE-EXCEPTION', out.getvalue())


if __name__ == '__main__':
    unittest.main()
