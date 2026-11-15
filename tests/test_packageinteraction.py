from dataclasses import replace
import json
import unittest

from snellctl.hostprep import PreparationError
from snellctl.packagereview import ReviewMaterial
import test_packageflow
import test_packagereview


class StagedFlowTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_packageflow.FlowTests('test_complete_flow_submits_once_then_restores_without_external_success_claim')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.flow, self.host, self.prep = self.fixture.flow, self.fixture.host, self.fixture.prep
        self.job = self.fixture.job
        self.fixture.auto_complete = True
        self.material = object.__new__(test_packagereview.MaterialTests)
        self.material.batch = self.fixture.batch
        self.material.control_version = self.job.changes[0].after
        self.material.old_script = '#!/bin/sh\nexit 0\n'
        self.material.new_script = '#!/bin/sh\n# new revision\nexit 0\n'
        self.material.extra_payload = []
        self.material.intercept = None
        self.fixture.fixture.effect = self.reply
        self.decisions, self.reviewed = [], []
        self.decline, self.change_on, self.raise_on = None, None, None

    def reply(self, command):
        self.fixture.reply(command)
        return self.material.reply(command)

    def confirm(self, stage):
        self.decisions.append(stage)
        if stage == self.raise_on:
            raise EOFError('PRIVATE')
        if stage == self.change_on:
            self.material.old_script += '# changed while waiting\n'
        return stage != self.decline

    def reviewer(self, material):
        self.assertIs(type(material), ReviewMaterial)
        self.assertEqual(self.fixture.mutations(), [])
        self.reviewed.append(material)
        return True

    def run_flow(self, **kwargs):
        return self.flow.run_staged(self.job, review=self.reviewer, confirm=self.confirm, **kwargs)

    def test_whole_staged_flow_reads_actual_material_before_outage(self):
        report = self.run_flow()
        self.assertEqual(report['result'], 'packages-restored-external-test-required', report)
        self.assertEqual(self.decisions, ['download', 'outage', 'install', 'restore', 'dns-test', 'renewal'])
        self.assertEqual(len(self.reviewed), 1)
        self.assertIn('candidate_control_files', json.loads(self.reviewed[0].document)['packages'][0])
        self.assertFalse(report['upgrade_completed'])
        self.assertNotIn('#!/bin/sh', json.dumps(report))

    def test_declining_download_does_not_create_cache(self):
        self.decline = 'download'
        report = self.run_flow()
        self.assertEqual(report['result'], 'cancelled-before-download')
        self.fixture.download.assert_not_called()
        self.assertEqual(self.reviewed, [])
        self.assertEqual(self.host.calls, [])

    def test_declining_outage_preserves_services(self):
        self.decline = 'outage'
        report = self.run_flow()
        self.assertEqual(report['result'], 'cancelled-before-maintenance-cache-preserved')
        self.assertEqual(self.decisions, ['download', 'outage'])
        self.assertEqual(self.fixture.mutations(), [])

    def test_declining_install_does_not_stop_services_first(self):
        self.decline = 'install'
        report = self.run_flow()
        self.assertEqual(report['result'], 'cancelled-before-maintenance-cache-preserved')
        self.assertEqual(self.fixture.mutations(), [])
        self.assertFalse(self.prep._exists('package-update-intent'))

    def declined_restore(self, stage):
        self.decline = stage
        report = self.run_flow()
        self.assertEqual(report['result'], 'restoration-not-authorized-inspection-required', report)
        self.assertNotIn('postinstall', report)
        self.assertIsNone(self.prep.files.info(self.job.directory + '/postinstall-intent.json'))
        self.assertTrue(self.prep._exists('package-update-intent'))
        self.assertNotIn(('systemctl', 'start', 'nginx.service'), self.fixture.mutations())
        self.assertEqual(self.fixture.resume()['result'], 'packages-restored-external-test-required')

    def test_declining_restoration_preserves_pre_restoration_continuation(self):
        self.declined_restore('restore')

    def test_declining_dns_test_does_not_half_restore(self):
        self.declined_restore('dns-test')

    def test_declining_renewal_does_not_half_restore(self):
        self.declined_restore('renewal')

    def test_terminal_eof_after_install_does_not_resubmit_or_restore(self):
        self.raise_on = 'restore'
        report = self.run_flow()
        self.assertEqual(report['result'], 'interrupted-inspection-required')
        self.assertEqual(self.fixture.mutations().count(('systemctl', 'start', '--no-block', self.job.unit)), 1)
        self.assertNotIn(('systemctl', 'start', 'nginx.service'), self.fixture.mutations())
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_material_drift_during_confirmation_stops_before_outage(self):
        self.change_on = 'install'
        report = self.run_flow()
        self.assertFalse(report['maintenance_attempted'])
        self.assertEqual(self.fixture.mutations(), [])

    def test_material_is_rechecked_inside_maintenance_before_submission(self):
        original = self.fixture.fixture.effect
        def change(command):
            if command.argv == ('systemctl', 'stop', 'nginx.service'):
                self.material.old_script += '# changed after protection\n'
            return original(command)
        self.fixture.fixture.effect = change
        report = self.run_flow()
        self.assertTrue(report['maintenance_attempted'])
        self.assertNotIn('submission', report)
        self.assertNotIn(('systemctl', 'start', '--no-block', self.job.unit), self.fixture.mutations())

    def test_review_cannot_be_replaced_with_an_ordinary_confirmation(self):
        report = self.flow.run_staged(self.job, review=lambda material: 'y', confirm=self.confirm)
        self.assertEqual(report['result'], 'review-not-approved-cache-preserved')
        self.assertEqual(self.decisions, ['download'])
        self.assertEqual(self.fixture.mutations(), [])

    def test_invalid_callbacks_and_budget_fail_before_any_download(self):
        for kwargs in ({'review': None, 'confirm': self.confirm},
                       {'review': self.reviewer, 'confirm': True},
                       {'review': self.reviewer, 'confirm': self.confirm, 'wait_budget': 0}):
            with self.assertRaises(PreparationError):
                self.flow.run_staged(self.job, **kwargs)
        self.fixture.download.assert_not_called()

    def test_truthy_non_boolean_confirmation_never_authorizes(self):
        report = self.flow.run_staged(self.job, review=self.reviewer, confirm=lambda _: 1)
        self.assertEqual(report['result'], 'cancelled-before-download')
        self.fixture.download.assert_not_called()

    def test_batch_for_another_job_is_not_presented_as_this_review(self):
        self.fixture.download.return_value = replace(self.fixture.batch, job=replace(self.job, job_id='f' * 32))
        report = self.run_flow()
        self.assertFalse(report['maintenance_attempted'])
        self.assertEqual(self.reviewed, [])
        self.assertEqual(self.fixture.mutations(), [])


if __name__ == '__main__':
    unittest.main()
