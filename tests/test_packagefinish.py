import hashlib
import json
import unittest
from unittest.mock import patch

from snellctl.client import read_client
from snellctl.hostprep import POLICY, STATE, UNITS, PreparationError, Reply
from snellctl.packagedownload import EXTENDED, fingerprint
from snellctl.packagefinish import PackageFinish, VENDORS
from snellctl.packageguards import INTENT
from snellctl.packageplan import ALL_PACKAGES
from snellctl.packagesubmit import submit
from test_hostprep import DOMAIN, TOKEN
from test_packagejob import status
import test_packagesubmit


class FinishTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_packagesubmit.SubmissionTests('test_submit_once_records_private_files_and_never_runs_foreground_install')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.host, self.prep, self.job = self.fixture.host, self.fixture.prep, self.fixture.job
        self.files, self.guards, self.batch = self.prep.files, self.fixture.engine, self.fixture.batch
        self.tokens = self.guards.tokens
        self.vendor_sums()
        self.effect = None
        self.host.local_override = self.reply
        self.finish = None

    def vendor_sums(self):
        for package in set(VENDORS.values()):
            lines = [hashlib.md5(self.files.read(p), usedforsecurity=False).hexdigest() + '  ' + p.lstrip('/')
                     for p, owner in VENDORS.items() if owner == package]
            self.host.write('/var/lib/dpkg/info/' + package + '.md5sums', ('\n'.join(lines) + '\n').encode(), 0o644)

    def reply(self, command):
        if self.effect:
            result = self.effect(command)
            if result is not None:
                return result
        return self.fixture.reply(command)

    def run_finish(self, before=None, *, progress=lambda phase: None):
        with self.guards.protected(self.job, confirm_outage=True) as lease:
            report = submit(lease, self.batch, consent=True, review_confirmed=True)
            self.assertTrue(report['submission_acknowledged'], report)
            self.fixture.state = 'done'
            self.host.versions['certbot'] = self.job.changes[0].after
            self.finish = PackageFinish(lease, self.batch, progress)
            if before:
                before()
            return self.finish.finish(confirm_restore=True, confirm_dns_test=True, confirm_renewal=True)

    def assert_pending(self):
        self.assertTrue(self.prep._exists(INTENT))
        self.assertEqual(self.prep.status()['package_update'], 'needs-inspection')

    def test_success_restores_in_order_without_reinstalling_or_changing_node(self):
        keys = read_client(root=self.host.root).keys
        rules = list(self.host.rules)
        report = self.run_finish(before=lambda: self.finish._check())
        self.assertEqual(report['result'], 'packages-restored-external-test-required', report)
        for key in ('local_tls_verified', 'renewal_test_passed', 'package_record_committed',
                    'renewal_restored_verified', 'guards_removed_verified', 'completion_recorded',
                    'intent_removed_verified', 'report_saved'):
            self.assertTrue(report[key], key)
        self.assertFalse(report['upgrade_completed'])
        self.assertFalse(self.prep._exists(INTENT))
        self.assertEqual(read_client(root=self.host.root).keys, keys)
        self.assertEqual(self.host.rules, rules)
        self.assertEqual(self.prep._read_record('packages-ready'), {'versions': self.host.versions})
        self.assertTrue({'nginx.service', 'certbot.timer'} <= self.host.active)
        for path in (POLICY, *('/etc/systemd/system/' + u for u in UNITS)):
            self.assertIsNone(self.files.info(path))
        calls = [c.argv for c in self.host.calls]
        self.assertEqual(calls.count(('systemctl', 'start', '--no-block', self.job.unit)), 1)
        self.assertTrue(all('--simulate' in c for c in calls if c[0] == 'apt-get'))
        self.assertNotIn(('systemctl', 'stop', 'certbot.service'), calls)
        test = next(i for i, c in enumerate(calls) if c[:2] == ('certbot', 'renew'))
        self.assertLess(calls.index(('systemctl', 'start', 'nginx.service')), test)
        self.assertLess(test, calls.index(('systemctl', 'enable', '--now', 'certbot.timer')))

    def test_all_confirmations_are_required_before_postcheck_writes(self):
        def check():
            for values in ({}, {'confirm_restore': True}, {'confirm_restore': True, 'confirm_dns_test': True},
                           {'confirm_restore': True, 'confirm_dns_test': True, 'confirm_renewal': 1}):
                with self.assertRaises(PreparationError):
                    self.finish.finish(**values)
            self.assertIsNone(self.files.info(self.job.directory + '/postinstall-intent.json'))
        self.run_finish(check)

    def test_running_job_is_not_a_success(self):
        report = self.run_finish(lambda: setattr(self.fixture, 'state', 'running'))
        self.assertFalse(report['host_changes_attempted'])
        self.assertFalse(report['nginx_start_attempted'])
        self.assert_pending()

    def test_missing_execution_claim_cannot_restore(self):
        report = self.run_finish(lambda: self.host.path(self.job.directory + '/execution-claim.json').unlink())
        self.assertFalse(report['host_changes_attempted'])
        self.assert_pending()

    def test_other_invocation_is_rejected(self):
        def mutate():
            self.effect = lambda c: status(self.job, 'done', InvocationID='c' * 32) if c.argv[:4] == ('systemctl', 'show', '--all', self.job.unit) else None
        report = self.run_finish(mutate)
        self.assertFalse(report['host_changes_attempted'])
        self.assert_pending()

    def test_wrong_installed_version_is_not_recorded(self):
        old = self.prep._read_record('packages-ready')
        report = self.run_finish(lambda: self.host.versions.update(certbot=self.job.changes[0].before))
        self.assertFalse(report['nginx_start_attempted'])
        self.assertEqual(self.prep._read_record('packages-ready'), old)
        self.assert_pending()

    def test_unapproved_package_change_is_rejected(self):
        report = self.run_finish(lambda: self.host.versions.update(nginx='1.2.3-1+deb13u99'))
        self.assertFalse(report['host_changes_attempted'])
        self.assert_pending()

    def test_added_dependency_or_removed_package_is_rejected(self):
        def mutate():
            base = self.fixture.fixture.reply
            self.effect = lambda c: Reply(0, base(c).output + 'unexpected\tamd64\tii \t1.0-1\n') if c.argv == ALL_PACKAGES else None
        report = self.run_finish(mutate)
        self.assertFalse(report['nginx_start_attempted'])
        self.assert_pending()

    def test_half_configured_package_is_rejected(self):
        def mutate():
            base = self.fixture.fixture.reply
            self.effect = lambda c: Reply(0, base(c).output.replace('\tii \t', '\tiF \t', 1)) if c.argv == ALL_PACKAGES else None
        report = self.run_finish(mutate)
        self.assertFalse(report['nginx_start_attempted'])
        self.assert_pending()

    def test_partial_or_held_package_is_rejected(self):
        def mutate():
            base = self.fixture.fixture.reply
            self.effect = lambda c: Reply(0, base(c).output.replace('\tii \t', '\thi \t', 1)) if c.argv == ALL_PACKAGES else None
        report = self.run_finish(mutate)
        self.assertFalse(report['nginx_start_attempted'])
        self.assert_pending()

    def test_nonempty_dpkg_audit_blocks_restoration(self):
        def mutate():
            self.effect = lambda c: Reply(0, 'PRIVATE-DPKG-ERROR') if c.argv == ('dpkg', '--audit') else None
        report = self.run_finish(mutate)
        self.assertFalse(report['nginx_start_attempted'])
        self.assertNotIn('PRIVATE-DPKG-ERROR', json.dumps(report))

    def test_new_auto_install_state_is_not_silently_adopted(self):
        report = self.run_finish(lambda: self.host.write(EXTENDED, b'Package: certbot\nAuto-Installed: 1\n', 0o644))
        self.assertFalse(report['host_changes_attempted'])
        self.assert_pending()

    def test_metadata_only_auto_state_replacement_is_accepted(self):
        from dataclasses import replace
        self.host.write(EXTENDED, b'Package: python3-acme\nAuto-Installed: 1\n', 0o644)
        self.batch = replace(self.batch, extended_state=fingerprint(self.files, EXTENDED, limit=16 * 1024**2))
        def mutate():
            content = self.files.read(EXTENDED)
            self.host.path(EXTENDED).unlink()
            self.host.write(EXTENDED, content, 0o644)
        report = self.run_finish(mutate)
        self.assertEqual(report['result'], 'packages-restored-external-test-required', report)

    def test_protected_site_or_credential_change_blocks_before_restoration(self):
        path = self.tokens.prep.credential_path(self.tokens._check()[1])
        report = self.run_finish(lambda: self.host.path(path).write_bytes(b'changed'))
        self.assertFalse(report['nginx_start_attempted'])
        self.assert_pending()

    def test_managed_nginx_configuration_drift_is_rejected(self):
        report = self.run_finish(lambda: self.host.path(self.finish.spec.nginx_conf).write_bytes(b'foreign site'))
        self.assertFalse(report['nginx_start_attempted'])
        self.assert_pending()

    def test_foreign_firewall_change_is_preserved_and_blocks_restore(self):
        report = self.run_finish(lambda: self.host.rules.append("ufw allow 60000/tcp comment 'external'"))
        self.assertFalse(report['nginx_start_attempted'])
        self.assertIn("ufw allow 60000/tcp comment 'external'", self.host.rules)
        self.assert_pending()

    def test_unowned_mask_is_not_removed(self):
        def mutate():
            path = self.host.path('/etc/systemd/system/nginx.service')
            path.unlink()
            path.write_bytes(b'foreign configuration')
        report = self.run_finish(mutate)
        self.assertFalse(report['nginx_start_attempted'])
        self.assertEqual(self.files.read('/etc/systemd/system/nginx.service'), b'foreign configuration')
        self.assert_pending()

    def test_unapproved_vendor_unit_change_is_rejected(self):
        def mutate():
            self.host.write('/usr/lib/systemd/system/nginx.service', b'# changed', 0o644)
            self.vendor_sums()
        report = self.run_finish(mutate)
        self.assertFalse(report['nginx_start_attempted'])

    def test_approved_certbot_vendor_unit_change_requires_local_package_digest(self):
        def mutate():
            self.host.write('/usr/lib/systemd/system/certbot.service', b'# upgraded certbot service', 0o644)
            self.vendor_sums()
        report = self.run_finish(mutate)
        self.assertEqual(report['result'], 'packages-restored-external-test-required', report)

    def test_changed_vendor_without_matching_digest_is_rejected(self):
        report = self.run_finish(lambda: self.host.write('/usr/lib/systemd/system/certbot.service', b'# corrupt', 0o644))
        self.assertFalse(report['nginx_start_attempted'])

    def test_nginx_start_uncertainty_never_retries_or_enables_renewal(self):
        def mutate():
            self.effect = lambda c: Reply(-1, uncertain=True) if c.argv == ('systemctl', 'start', 'nginx.service') else None
        report = self.run_finish(mutate)
        self.assertTrue(report['nginx_start_attempted'])
        self.assertFalse(report['renewal_enable_attempted'])
        self.assertIsNotNone(self.files.info(POLICY))
        self.assert_pending()

    def test_tls_failure_blocks_dns_and_renewal(self):
        def mutate():
            self.tokens.local.probe.return_value = False
        report = self.run_finish(mutate)
        self.assertTrue(report['nginx_start_attempted'])
        self.assertFalse(report['renewal_test_attempted'])
        self.assert_pending()

    def test_dry_run_failure_does_not_commit_versions_or_enable_timer(self):
        old = self.prep._read_record('packages-ready')
        def mutate():
            self.effect = lambda c: Reply(1, 'PRIVATE-TOKEN') if c.argv[:2] == ('certbot', 'renew') else None
        report = self.run_finish(mutate)
        self.assertTrue(report['renewal_test_attempted'])
        self.assertFalse(report['renewal_enable_attempted'])
        self.assertEqual(self.prep._read_record('packages-ready'), old)
        self.assertNotIn('PRIVATE-TOKEN', json.dumps(report))
        self.assert_pending()

    def test_zero_without_fresh_dns_and_reload_evidence_is_not_success(self):
        def mutate():
            self.effect = lambda c: Reply(0, 'All renewals succeeded') if c.argv[:2] == ('certbot', 'renew') else None
        report = self.run_finish(mutate)
        self.assertTrue(report['renewal_test_attempted'])
        self.assertFalse(report['renewal_test_passed'])
        self.assert_pending()

    def rotate_certificate(self):
        for name in ('cert', 'chain', 'fullchain', 'privkey'):
            data = b'renewed fixture' * (2 if name == 'fullchain' else 1)
            self.host.write(f'/etc/letsencrypt/archive/{self.finish.spec.domain}/{name}2.pem', data)
            path = self.host.path(f'{self.finish.spec.cert_dir}/{name}.pem')
            path.unlink()
            path.symlink_to(f'../../archive/{self.finish.spec.domain}/{name}2.pem')

    def test_dry_run_must_not_change_production_certificate(self):
        def mutate():
            def effect(c):
                if c.argv[:2] == ('certbot', 'renew'):
                    self.rotate_certificate()
            self.effect = effect
        report = self.run_finish(mutate)
        self.assertTrue(report['renewal_test_attempted'])
        self.assertFalse(report['renewal_test_passed'])
        self.assertFalse(report['renewal_enable_attempted'])
        self.assert_pending()

    def test_due_renewal_after_timer_enable_can_rotate_valid_certificate(self):
        def progress(phase):
            if phase == 'enabled-postcheck':
                self.rotate_certificate()
        report = self.run_finish(progress=progress)
        self.assertEqual(report['result'], 'packages-restored-external-test-required', report)
        self.assertTrue(report['renewal_restored_verified'])

    def test_vendor_change_after_dry_run_is_not_adopted(self):
        def mutate():
            def effect(c):
                if c.argv[:2] == ('certbot', 'renew'):
                    self.host.write('/usr/lib/systemd/system/certbot.service', b'# unexpected later change', 0o644)
                    self.vendor_sums()
            self.effect = effect
        report = self.run_finish(mutate)
        self.assertTrue(report['renewal_test_attempted'])
        self.assertFalse(report['renewal_test_passed'])
        self.assert_pending()

    def test_renewal_unit_needing_reload_is_not_treated_as_ready(self):
        def mutate():
            self.effect = lambda c: Reply(0, 'NeedDaemonReload=yes\n') if c.argv == (
                'systemctl', 'show', '--all', 'certbot.service', '-p', 'NeedDaemonReload') else None
        report = self.run_finish(mutate)
        self.assertTrue(report['local_tls_verified'])
        self.assertFalse(report['renewal_test_attempted'])
        self.assert_pending()

    def test_migration_write_failure_retains_old_record_and_intent(self):
        original = self.files.replace_owned
        def fail(path, *args, **kwargs):
            if path == STATE + '/packages-ready.json':
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'replace_owned', side_effect=fail):
            report = self.run_finish()
        self.assertTrue(report['renewal_test_passed'])
        self.assertFalse(report['package_record_committed'])
        self.assertFalse(report['renewal_enable_attempted'])
        self.assert_pending()

    def test_timer_enable_uncertainty_leaves_policy_and_pending_record(self):
        def mutate():
            self.effect = lambda c: Reply(-1, uncertain=True) if c.argv == ('systemctl', 'enable', '--now', 'certbot.timer') else None
        report = self.run_finish(mutate)
        self.assertTrue(report['package_record_committed'])
        self.assertTrue(report['renewal_enable_attempted'])
        self.assertFalse(report['renewal_restored_verified'])
        self.assertIsNotNone(self.files.info(POLICY))
        self.assert_pending()

    def test_policy_removal_failure_does_not_clear_pending_marker(self):
        original = self.files.unlink_owned
        def fail(path, *args, **kwargs):
            if path == POLICY:
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'unlink_owned', side_effect=fail):
            report = self.run_finish()
        self.assertTrue(report['renewal_restored_verified'])
        self.assertFalse(report['guards_removed_verified'])
        self.assert_pending()

    def test_completion_write_failure_still_blocks_new_management(self):
        original = self.files.write_new
        def fail(path, *args, **kwargs):
            if path.endswith('/postinstall-complete.json'):
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.run_finish()
        self.assertTrue(report['guards_removed_verified'])
        self.assertFalse(report['completion_recorded'])
        self.assert_pending()

    def test_result_write_failure_does_not_erase_verified_completion(self):
        original = self.files.write_new
        def fail(path, *args, **kwargs):
            if path.endswith('/postinstall-result.json'):
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.run_finish()
        self.assertEqual(report['result'], 'packages-restored-external-test-required', report)
        self.assertFalse(report['report_saved'])
        self.assertTrue(report['completion_recorded'])
        self.assertFalse(self.prep._exists(INTENT))

    def test_intent_remove_failure_keeps_completion_evidence(self):
        original = self.files.unlink_owned
        def fail(path, *args, **kwargs):
            if path == STATE + '/' + INTENT + '.json':
                raise OSError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'unlink_owned', side_effect=fail):
            report = self.run_finish()
        self.assertTrue(report['completion_recorded'])
        self.assertFalse(report['intent_removed_verified'])
        self.assert_pending()

    def test_result_write_eof_preserves_verified_completion(self):
        original = self.files.write_new
        def fail(path, *args, **kwargs):
            if path.endswith('/postinstall-result.json'):
                raise EOFError('PRIVATE')
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.run_finish()
        self.assertEqual(report['result'], 'interrupted-inspection-required')
        self.assertFalse(report['report_saved'])
        self.assertTrue(report['completion_recorded'])
        self.assertTrue(report['intent_removed_verified'])
        self.assertTrue(report['renewal_restored_verified'])
        self.assertFalse(self.prep._exists(INTENT))

    def test_repeated_finish_and_escaped_lease_are_not_recovery(self):
        def mutate():
            first = self.finish.finish(confirm_restore=True, confirm_dns_test=True, confirm_renewal=True)
            self.assertEqual(first['result'], 'packages-restored-external-test-required', first)
        second = self.run_finish(mutate)
        self.assertFalse(second['host_changes_attempted'])
        with self.assertRaises(PreparationError):
            self.finish.finish(confirm_restore=True, confirm_dns_test=True, confirm_renewal=True)

    def test_interrupted_restoration_preserves_remaining_guards(self):
        def progress(phase):
            if phase == 'renewal-unmask':
                raise KeyboardInterrupt
        report = self.run_finish(progress=progress)
        self.assertEqual(report['result'], 'interrupted-inspection-required')
        self.assertTrue(report['local_tls_verified'])
        for unit in ('certbot.service', 'certbot.timer'):
            self.assertIsNotNone(self.files.info('/etc/systemd/system/' + unit))
        self.assert_pending()

    def test_no_upgrade_or_restore_cli_is_added(self):
        from contextlib import redirect_stderr
        import io
        from snellctl.__main__ import main
        for command in ('package-finish', 'package-upgrade', 'package-restore'):
            with self.subTest(command=command), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main([command, '--experimental'])

    def test_reports_and_post_records_do_not_contain_credentials_or_raw_output(self):
        report = self.run_finish()
        text = json.dumps(report)
        for name in ('postinstall-intent', 'postinstall-complete', 'postinstall-result', 'postinstall-renewal-test-result'):
            text += self.files.read(self.job.directory + '/' + name + '.json').decode()
        for private in (DOMAIN, TOKEN, 'dns_cloudflare_api_token', 'PRIVATE-TOKEN'):
            self.assertNotIn(private, text)


if __name__ == '__main__':
    unittest.main()
