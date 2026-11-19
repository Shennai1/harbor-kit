from dataclasses import replace
import hashlib
import json
import unittest
from unittest.mock import patch

from snellctl import packagebaseline as baseline
from snellctl.client import read_client
from snellctl.hostprep import POLICY, STATE, PreparationError, Reply
from snellctl.packageflow import PackageFlow, OTHER_PENDING, RESTORE_PREFIXES
from snellctl.packagejob import JobObserver
from snellctl.packagedownload import EXTENDED, DownloadCommand, ArchiveCommand, DOWNLOAD, SIMULATE
from snellctl.packageplan import ALL_PACKAGES
from snellctl.packagesubmit import encoded, observe_submission, submit
from test_hostprep import DOMAIN, TOKEN
from test_packagejob import status
from test_packagedownload import control, record, simulated, ORIGIN
import test_packagefinish
import test_maintenance


CONFIRM = dict(confirm_download=True, confirm_outage=True, confirm_install=True,
               confirm_restore=True, confirm_dns_test=True, confirm_renewal=True)
RESTORE = dict(confirm_restore=True, confirm_dns_test=True, confirm_renewal=True)


class FlowTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_packagefinish.FinishTests('test_success_restores_in_order_without_reinstalling_or_changing_node')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.sub = self.fixture.fixture
        self.host, self.prep, self.job = self.fixture.host, self.fixture.prep, self.fixture.job
        self.files, self.batch, self.tokens = self.fixture.files, self.fixture.batch, self.fixture.tokens
        self.flow = PackageFlow(self.tokens)
        self.flow.guards = self.fixture.guards
        self.download = patch.object(self.flow.downloads, 'stage', return_value=self.batch).start()
        self.addCleanup(patch.stopall)
        self.auto_complete = False
        self.fixture.effect = self.reply

    def reply(self, command):
        if (self.auto_complete and self.sub.state == 'running'
                and command.argv[:4] == ('systemctl', 'show', '--all', self.job.unit)):
            self.complete()

    def complete(self):
        self.sub.state = 'done'
        self.host.versions['certbot'] = self.job.changes[0].after

    def prepare(self):
        self.assertTrue(self.sub.run_submit()['submission_acknowledged'])
        self.complete()
        self.host.calls.clear()

    def resume(self):
        # A fresh coordinator must not rely on the original guard lease.
        return PackageFlow(self.tokens).resume(self.job, **RESTORE)

    def mutations(self):
        return [c.argv for c in self.host.calls if c.argv[:2] in {
            ('systemctl', 'start'), ('systemctl', 'stop'), ('systemctl', 'restart'),
            ('systemctl', 'enable'), ('systemctl', 'disable'), ('systemctl', 'daemon-reload'), ('certbot', 'renew')}]

    def assert_blocked_resume(self):
        report = self.resume()
        self.assertEqual(report['result'], 'inspection-required', report)
        self.assertFalse(report['host_changes_attempted'], report)
        self.assertEqual(self.mutations(), [])
        self.assertTrue(self.prep._exists('package-update-intent'))
        return report

    def test_complete_flow_submits_once_then_restores_without_external_success_claim(self):
        self.auto_complete = True
        keys = read_client(root=self.host.root).keys
        calls = []
        report = self.flow.run(self.job, review=lambda batch: calls.append(batch) or True, **CONFIRM)
        self.assertEqual(report['result'], 'packages-restored-external-test-required', report)
        self.assertFalse(report['upgrade_completed'])
        self.assertTrue(report['external_acceptance_required'])
        self.assertEqual(calls, [self.batch])
        self.download.assert_called_once_with(self.job, consent=True)
        self.assertEqual(read_client(root=self.host.root).keys, keys)
        self.assertEqual(self.mutations().count(('systemctl', 'start', '--no-block', self.job.unit)), 1)
        self.assertTrue(all('--simulate' in c.argv for c in self.host.calls if c.argv[0] == 'apt-get'))

    def test_real_staging_and_coordinator_share_a_single_reviewed_batch(self):
        patch.stopall()
        self.job = replace(self.job, job_id='c' * 32)
        self.sub.job = self.job
        payload = b'synthetic new deb'
        def reply(command):
            self.reply(command)
            units = test_maintenance.MaintenanceTests.unit_reply(self, command)
            if units is not None:
                return units
            if type(command) is ArchiveCommand:
                return Reply(0, control(self.job.changes[0]))
            if type(command) is not DownloadCommand:
                return None
            args, work = command.argv, command.workspace
            if args[:2] == ('apt-get', 'update'):
                self.files.write_new(work + '/lists/test_InRelease', b'synthetic index', mode=0o644)
                return Reply(0)
            versions = {**self.host.versions, 'certbot': self.job.changes[0].after}
            if args[:2] == ('apt-cache', 'policy'):
                return Reply(0, ''.join(f'{n}:\n  Installed: {self.host.versions[n]}\n  Candidate: {versions[n]}\n'
                                       for n in args[2:]))
            if args[:2] == ('apt-cache', 'madison'):
                return Reply(0, ''.join(f'{n} | {versions[n]} | {ORIGIN}\n' for n in args[2:]))
            if args[:3] == ('apt-cache', '--no-all-versions', 'show'):
                return Reply(0, record(self.job.changes[0], payload))
            if args[:len(SIMULATE)] == SIMULATE:
                return Reply(0, simulated(self.job.changes))
            if args[:len(DOWNLOAD)] == DOWNLOAD:
                self.files.write_new(work + '/cache/archives/certbot.deb', payload, mode=0o644)
                return Reply(0)
            self.fail('unexpected command')
        self.fixture.effect = reply
        self.auto_complete = True
        reviewed = []
        report = self.flow.run(self.job, review=lambda b: reviewed.append(b) or True, **CONFIRM)
        self.assertEqual(report['result'], 'packages-restored-external-test-required', report)
        self.assertEqual(len(reviewed), 1)
        self.assertEqual(reviewed[0].archives[0].sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(sum(c.argv[:len(DOWNLOAD)] == DOWNLOAD for c in self.host.calls), 1)

    def test_each_consent_and_valid_wait_budget_required_before_download(self):
        for field in CONFIRM:
            for value in (False, 1, 'y', None):
                with self.subTest(field=field, value=value), self.assertRaises(PreparationError):
                    self.flow.run(self.job, review=lambda b: True, **{**CONFIRM, field: value})
        for budget in (0, True, 901, 1.2):
            with self.assertRaises(PreparationError):
                self.flow.run(self.job, review=lambda b: True, wait_budget=budget, **CONFIRM)
        self.download.assert_not_called()
        self.assertEqual(self.mutations(), [])

    def test_review_is_separate_and_fail_closed(self):
        for decision in (False, None, 1, 'y'):
            report = self.flow.run(self.job, review=lambda b: decision, **CONFIRM)
            self.assertEqual(report['result'], 'review-not-approved-cache-preserved')
            self.assertFalse(report['maintenance_attempted'])
        self.assertFalse(self.prep._exists('package-update-intent'))
        self.assertEqual(self.mutations(), [])

    def test_download_failure_does_not_enter_maintenance(self):
        self.download.side_effect = PreparationError('PRIVATE-DOWNLOAD')
        report = self.flow.run(self.job, review=lambda b: True, **CONFIRM)
        self.assertFalse(report['maintenance_attempted'])
        self.assertNotIn('PRIVATE-DOWNLOAD', json.dumps(report))
        self.assertEqual(self.mutations(), [])

    def test_changed_batch_after_review_refuses_maintenance(self):
        def review(batch):
            self.host.path(batch.paths_and_fingerprints[0][0]).write_bytes(b'changed')
            return True
        report = self.flow.run(self.job, review=review, **CONFIRM)
        self.assertFalse(report['maintenance_attempted'])
        self.assertEqual(self.mutations(), [])

    def test_uncertain_enqueue_is_not_observed_then_automatically_restored(self):
        self.sub.start_reply = Reply(0, uncertain=True)
        self.auto_complete = True
        report = self.flow.run(self.job, review=lambda b: True, **CONFIRM)
        self.assertFalse(report['submission']['submission_acknowledged'])
        self.assertNotIn('observation', report)
        self.assertNotIn(('systemctl', 'start', 'nginx.service'), self.mutations())

    def test_observation_timeout_leaves_installation_and_guards_alone(self):
        with patch.object(JobObserver, 'wait', return_value={'result': 'wait-budget-exhausted-task-not-stopped'}):
            report = self.flow.run(self.job, review=lambda b: True, **CONFIRM)
        self.assertNotIn('postinstall', report)
        self.assertEqual(self.sub.state, 'running')
        self.assertNotIn(('systemctl', 'stop', self.job.unit), self.mutations())
        self.assertIsNotNone(self.files.info(POLICY))

    def test_interruption_after_submit_does_not_kill_or_retry_task(self):
        with patch.object(JobObserver, 'wait', side_effect=KeyboardInterrupt):
            report = self.flow.run(self.job, review=lambda b: True, **CONFIRM)
        self.assertEqual(report['result'], 'interrupted-inspection-required')
        self.assertEqual(self.mutations().count(('systemctl', 'start', '--no-block', self.job.unit)), 1)
        self.assertEqual(self.sub.state, 'running')

    def test_failed_installation_does_not_enter_restoration(self):
        with patch.object(JobObserver, 'wait', return_value={'result': 'command-exited-failure'}):
            report = self.flow.run(self.job, review=lambda b: True, **CONFIRM)
        self.assertNotIn('postinstall', report)
        self.assertNotIn(('systemctl', 'start', 'nginx.service'), self.mutations())

    def test_reconnect_restores_without_new_download_install_or_old_lease(self):
        self.prepare()
        self.assertFalse(self.sub.lease.active)
        with patch.object(self.flow.guards, '_before', side_effect=AssertionError('must not adopt a new baseline')):
            report = self.resume()
        self.assertEqual(report['result'], 'packages-restored-external-test-required', report)
        self.assertTrue(report['report_saved'])
        self.assertFalse(report['installation_submission_attempted'])
        self.assertTrue(all(c.argv[0] not in {'apt-get', 'apt-cache', 'dpkg-deb'} for c in self.host.calls))
        self.assertNotIn(('systemctl', 'start', '--no-block', self.job.unit), self.mutations())
        self.assertFalse(self.prep._exists('package-update-intent'))

    def test_reconnect_can_finish_a_proven_success_after_lost_enqueue_ack(self):
        self.sub.start_reply = Reply(0, uncertain=True)
        report = self.sub.run_submit()
        self.assertFalse(report['submission_acknowledged'])
        self.complete()
        self.host.calls.clear()
        self.assertEqual(self.resume()['result'], 'packages-restored-external-test-required')
        self.assertNotIn(('systemctl', 'start', '--no-block', self.job.unit), self.mutations())

    def test_missing_confirmations_do_not_even_read_resume_state(self):
        for field in RESTORE:
            with self.assertRaises(PreparationError):
                self.flow.resume(self.job, **{**RESTORE, field: 1})
        self.assertEqual(self.host.calls, [])

    def test_running_job_is_read_only_even_with_resume_consent(self):
        self.prepare()
        self.sub.state = 'running'
        self.assert_blocked_resume()

    def test_unclaimed_job_cannot_resume(self):
        self.prepare()
        self.host.path(self.job.directory + '/execution-claim.json').unlink()
        self.assert_blocked_resume()

    def test_other_invocation_cannot_resume(self):
        self.prepare()
        self.fixture.effect = lambda c: status(self.job, 'done', InvocationID='c' * 32) if c.argv[:4] == ('systemctl', 'show', '--all', self.job.unit) else None
        self.assert_blocked_resume()

    def test_changed_boot_id_cannot_resume(self):
        self.prepare()
        self.host.path(baseline.BOOT).unlink()
        self.host.write(baseline.BOOT, b'99999999-2222-3333-4444-555555555555\n', 0o444)
        self.assert_blocked_resume()

    def test_missing_boot_id_cannot_resume(self):
        self.prepare()
        self.host.path(baseline.BOOT).unlink()
        self.assert_blocked_resume()

    def test_legacy_submission_stays_observable_but_cannot_resume(self):
        self.prepare()
        path = self.job.directory + '/submission-ready.json'
        value = json.loads(self.files.read(path))
        value['format'] = 1
        del value['restoration_baseline']
        self.host.write(path, encoded(value), 0o600)
        self.host.path(self.job.directory + '/' + baseline.NAME).unlink()
        self.assertEqual(observe_submission(self.prep, self.job)['result'], 'command-exited-success')
        self.assert_blocked_resume()

    def test_missing_modified_or_replaced_baseline_cannot_resume(self):
        self.prepare()
        path = self.job.directory + '/' + baseline.NAME
        saved = self.files.read(path)
        self.host.write(path, saved + b' ', 0o600)
        self.assert_blocked_resume()
        self.host.write(path, saved, 0o600)
        identity = self.files.identity(path)
        # Keep the old inode alive so recreation cannot reuse its identity.
        with self.host.path(path).open('rb') as original:
            self.host.path(path).unlink()
            self.assert_blocked_resume()
            self.host.write(path, saved, 0o600)
            self.assertEqual(original.read(), self.files.read(path))
            self.assertNotEqual(identity, self.files.identity(path))
            self.assert_blocked_resume()

    def test_other_pending_operations_block_continuation(self):
        self.prepare()
        for name in OTHER_PENDING:
            with self.subTest(name=name):
                self.prep._record(name, {'format': 1})
                self.assert_blocked_resume()
                self.host.path(STATE + '/' + name + '.json').unlink()

    def test_any_partial_restoration_or_previous_resume_attempt_blocks(self):
        self.prepare()
        for prefix in RESTORE_PREFIXES:
            with self.subTest(prefix=prefix):
                path = self.job.directory + '/' + prefix + 'attempt.json'
                self.files.write_new(path, b'{}')
                self.assert_blocked_resume()
                self.host.path(path).unlink()

    def test_current_package_versions_must_match_exact_approved_after_state(self):
        self.prepare()
        self.host.versions['certbot'] = self.job.changes[0].before
        self.assert_blocked_resume()

    def test_unrelated_package_change_cannot_be_reconstructed_as_old_state(self):
        self.prepare()
        self.host.versions['nginx'] += '1'
        self.assert_blocked_resume()

    def test_added_or_held_dependency_cannot_be_reconstructed(self):
        self.prepare()
        base = self.sub.fixture.reply
        for transform in (lambda s: s + 'unrelated\tall\tii \t1.0-1\n',
                          lambda s: s.replace('\tii \t', '\thi \t', 1)):
            self.fixture.effect = lambda c: Reply(0, transform(base(c).output)) if c.argv == ALL_PACKAGES else None
            self.assert_blocked_resume()

    def test_changed_credential_is_not_used_for_restoration(self):
        self.prepare()
        path = self.prep.credential_path(self.sub.lease.before[0][1])
        self.host.write(path, b'dns_cloudflare_api_token = ' + b'z' * 40 + b'\n', 0o600)
        self.assert_blocked_resume()

    def test_changed_current_certificate_is_not_adopted(self):
        self.prepare()
        lineage = self.sub.lease.before[0][5]['lineage']
        path = next('/etc/letsencrypt/' + v['target'].removeprefix('../../')
                    for v in lineage.values() if 'target' in v)
        self.host.path(path).write_bytes(b'changed')
        self.assert_blocked_resume()

    def test_changed_package_record_is_not_adopted(self):
        self.prepare()
        self.host.write(STATE + '/packages-ready.json', encoded({'versions': self.host.versions}), 0o600)
        self.assert_blocked_resume()

    def test_guard_snapshot_change_stops_before_restoration(self):
        self.prepare()
        path = self.job.directory + '/guards-ready.json'
        self.host.path(path).write_bytes(self.files.read(path) + b' ')
        self.assert_blocked_resume()

    def test_removed_policy_or_mask_stays_untouched(self):
        self.prepare()
        self.host.path(POLICY).unlink()
        self.assert_blocked_resume()
        self.assertIsNone(self.files.info(POLICY))

    def test_extended_state_content_change_blocks_restore(self):
        self.prepare()
        self.host.write(EXTENDED, b'Package: certbot\nAuto-Installed: 1\n', 0o644)
        self.assert_blocked_resume()

    def test_changed_vendor_for_approved_package_is_checked_against_current_package(self):
        self.prepare()
        self.host.write('/usr/lib/systemd/system/certbot.service', b'changed-by-approved-package\n', 0o644)
        self.fixture.vendor_sums()
        self.assertEqual(self.resume()['result'], 'packages-restored-external-test-required')

    def test_unapproved_vendor_change_is_not_adopted_even_with_matching_md5(self):
        self.prepare()
        self.host.write('/usr/lib/systemd/system/nginx.service', b'changed-without-upgrade\n', 0o644)
        self.fixture.vendor_sums()
        self.assert_blocked_resume()

    def test_resume_lock_conflict_is_read_only(self):
        self.prepare()
        with self.prep._lock():
            self.assert_blocked_resume()

    def test_recovery_lease_cannot_submit_installation(self):
        self.prepare()
        with self.prep._lock():
            lease, _finish = self.flow._resume_check(self.job)
            try:
                with self.assertRaises(PreparationError):
                    submit(lease, self.batch, consent=True, review_confirmed=True)
                with self.assertRaises(PreparationError):
                    lease.verify()
            finally:
                lease.active = False
        self.assertEqual(self.mutations(), [])

    def test_resume_before_marker_failure_does_not_start_services(self):
        self.prepare()
        original = self.files.write_new
        def fail(path, *args, **kwargs):
            if path.endswith('/restoration-resume-intent.json'):
                raise OSError('PRIVATE-WRITE')
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.resume()
        self.assertEqual(self.mutations(), [])
        self.assertNotIn('PRIVATE-WRITE', json.dumps(report))

    def test_interrupt_after_resume_marker_blocks_a_second_continuation(self):
        self.prepare()
        original = self.files.write_new
        def fail(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path.endswith('/restoration-resume-intent.json'):
                raise KeyboardInterrupt
            return result
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.resume()
        self.assertEqual(report['result'], 'interrupted-inspection-required')
        self.assert_blocked_resume()

    def test_node_failure_during_resume_is_retained_and_not_retried(self):
        self.prepare()
        self.fixture.effect = lambda c: Reply(1, 'PRIVATE-NGINX') if c.argv == ('systemctl', 'start', 'nginx.service') else None
        report = self.resume()
        self.assertEqual(report['result'], 'stopped-inspection-required')
        self.assertNotIn('PRIVATE-NGINX', json.dumps(report))
        self.host.calls.clear()
        self.assert_blocked_resume()

    def test_resume_report_failure_does_not_claim_saved_or_undo_success(self):
        self.prepare()
        original = self.files.write_new
        def fail(path, *args, **kwargs):
            if path.endswith('/restoration-resume-result.json'):
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.resume()
        self.assertEqual(report['result'], 'packages-restored-external-test-required')
        self.assertFalse(report['report_saved'])
        self.assertFalse(self.prep._exists('package-update-intent'))

    def test_private_baseline_does_not_copy_domain_credentials_or_keys(self):
        keys = read_client(root=self.host.root).keys
        self.prepare()
        raw = self.files.read(self.job.directory + '/' + baseline.NAME, mode=0o600).decode()
        for secret in (DOMAIN, TOKEN, keys.psk, keys.shadowtls_password, 'BEGIN PRIVATE KEY'):
            self.assertNotIn(secret, raw)
        value = json.loads(raw)
        self.assertNotIn('database', value)
        self.assertEqual(value['before_sha256'], baseline.digest(self.sub.lease.before))
        report = self.resume()
        for secret in (DOMAIN, TOKEN, keys.psk, keys.shadowtls_password, value['before_sha256'], value['boot_id']):
            self.assertNotIn(secret, json.dumps(report))

    def test_duplicate_keys_bad_shape_and_wrong_paths_in_baseline_refused(self):
        self.prepare()
        path = self.job.directory + '/' + baseline.NAME
        value = json.loads(self.files.read(path))
        for replacement in (encoded(value).replace(b'"format": 1', b'"format": 1, "format": 1'),
                            encoded({**value, 'format': True}), encoded({**value, 'job_id': 'z' * 32}),
                            encoded({**value, 'vendor_files': {'/other': value['guards_ready']}}),
                            encoded({**value, 'extended_sha256': '../other'})):
            self.host.write(path, replacement, 0o600)
            with self.assertRaises(PreparationError):
                baseline.read(self.files, self.job)

    def test_baseline_write_failure_prevents_submission(self):
        original = self.files.write_new
        def fail(path, *args, **kwargs):
            if path.endswith('/' + baseline.NAME):
                raise OSError('PRIVATE-BASELINE')
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.flow.run(self.job, review=lambda b: True, **CONFIRM)
        self.assertFalse(report['submission']['submission_attempted'])
        self.assertNotIn(('systemctl', 'start', '--no-block', self.job.unit), self.mutations())

    def test_unavailable_boot_identity_prevents_submission(self):
        self.host.path(baseline.BOOT).unlink()
        report = self.flow.run(self.job, review=lambda b: True, **CONFIRM)
        self.assertFalse(report['submission']['submission_attempted'])
        self.assertNotIn(('systemctl', 'start', '--no-block', self.job.unit), self.mutations())
