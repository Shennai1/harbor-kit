import json
import unittest
from unittest.mock import patch

from snellctl.client import ClientError, read_client
from snellctl.hostprep import POLICY, POLICY_BYTES, STATE, UNITS, PreparationError, Reply
from snellctl.installer import installation_status, render_status
from snellctl.packageguards import INTENT, PackageGuards
from snellctl.packagejob import JobSpec
from snellctl.packageplan import ALL_PACKAGES
from snellctl.packagepolicy import ARCHITECTURES, RevisionChange
from snellctl.publish import RENEW_DROPIN
from snellctl.retiredplan import ScopeBlocked
from test_hostprep import DOMAIN, TOKEN
import test_domainchange


class PackageGuardsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_domainchange.DomainChangeTests('test_check_is_read_only_and_repr_is_redacted')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.host, self.prep, self.tokens = self.fixture.host, self.fixture.prep, self.fixture.tokens
        self.host.write('/usr/lib/systemd/system/nginx.service', b'[Service]\nExecStart=/usr/sbin/nginx\n', 0o644)
        self.now = 0
        self.engine = PackageGuards(self.tokens, clock=lambda: self.now, sleep=self.sleep)
        self.job = JobSpec('b' * 32, (RevisionChange('certbot', 'all', self.host.versions['certbot'],
                                                  '1.2.3-1+deb13u2'),))
        self.host.local_override = self.reply
        self.host.calls.clear()

    def sleep(self, seconds):
        self.now += seconds

    def reply(self, command):
        args = command.argv
        if args == ALL_PACKAGES:
            return Reply(0, ''.join(f'{name}\t{ARCHITECTURES[name]}\tii \t{version}\n'
                                    for name, version in self.host.versions.items()))
        if args[:2] == ('dpkg', '--compare-versions'):
            return Reply(0)
        if args == ('systemctl', 'stop', 'nginx.service'):
            self.host.active.discard('nginx.service')
            return Reply(0)
        if args[:3] == ('ss', '-H', '-lntu'):
            return Reply(0, 'synthetic listener' if 'nginx.service' in self.host.active else '')
        if args[:3] != ('systemctl', 'show', '--all'):
            return None
        unit = args[3]
        mask = self.host.path('/etc/systemd/system/' + unit).is_symlink()
        active = unit in self.host.active
        fields = dict(LoadState='masked' if mask else 'loaded', ActiveState='active' if active else 'inactive',
                      SubState=('waiting' if unit.endswith('.timer') else 'running') if active else 'dead',
                      UnitFileState='masked' if mask else 'static' if unit == 'certbot.service' else
                                    'enabled' if unit in self.host.enabled else 'disabled',
                      NeedDaemonReload='no', Job='', FragmentPath='/usr/lib/systemd/system/' + unit,
                      DropInPaths=RENEW_DROPIN if unit == 'certbot.service' else '',
                      MainPID='100' if active else '0', ControlPID='0')
        return Reply(0, ''.join(f'{k}={fields[k]}\n' for k in args[-1].split(',')))

    def protect(self, callback=lambda lease: None):
        with self.engine.protected(self.job, confirm_outage=True) as lease:
            callback(lease)
        return lease

    def mutations(self):
        return [c.argv for c in self.host.calls if c.argv[:2] in {
            ('systemctl', 'disable'), ('systemctl', 'stop'), ('systemctl', 'daemon-reload'),
            ('systemctl', 'enable'), ('systemctl', 'start'), ('systemctl', 'restart')}]

    def assert_no_intent(self):
        self.assertFalse(self.prep._exists(INTENT))
        self.assertIsNone(self.prep.files.info(POLICY))
        self.assertEqual(self.mutations(), [])

    def assert_pending(self, phase=None):
        self.assertTrue(self.prep._exists(INTENT))
        self.assertEqual(self.prep.status()['package_update'], 'needs-inspection')
        if phase:
            stopped = json.loads(self.host.path(self.job.directory + '/guards-stopped.json').read_bytes())
            self.assertEqual(stopped['phase'], phase)
        self.assertFalse(any(c.argv[0] in {'apt-get', 'apt-cache', 'certbot'} for c in self.host.calls))
        self.assertNotIn(('systemctl', 'stop', 'certbot.service'), self.mutations())
        self.assertNotIn(('systemctl', 'enable', '--now', 'certbot.timer'), self.mutations())

    def test_success_prepares_only_guards_and_preserves_all_existing_files(self):
        before = self.fixture.snapshot()
        versions, rules = dict(self.host.versions), list(self.host.rules)
        self.protect(lambda lease: lease.verify())
        after = self.fixture.snapshot()
        self.assertTrue(all(after[p] == v for p, v in before.items()))
        self.assertEqual(self.host.versions, versions)
        self.assertEqual(self.host.rules, rules)
        self.assertEqual(self.mutations(), [('systemctl', 'disable', '--now', 'certbot.timer'),
                                           ('systemctl', 'daemon-reload'), ('systemctl', 'stop', 'nginx.service')])
        self.assertNotIn('nginx.service', self.host.active)
        self.assertIn('nginx.service', self.host.enabled)
        self.assertNotIn('certbot.timer', self.host.enabled)
        self.assertIn(self.fixture.spec.snell_service, self.host.active)
        self.assertIn(self.fixture.spec.shadowtls_service, self.host.active)
        self.assertEqual(self.prep.files.read(POLICY, mode=0o755), POLICY_BYTES)
        for unit in UNITS:
            self.assertEqual(self.prep.files.readlink('/etc/systemd/system/' + unit), '/dev/null')
        self.assertTrue(self.host.path(self.job.directory + '/guards-ready.json').is_file())
        self.assertFalse(self.host.path(self.job.unit_path).exists())
        self.assertFalse(self.host.path(self.job.directory + '/armed.json').exists())
        self.assert_pending()

    def test_explicit_outage_consent_required_before_queries_or_writes(self):
        for consent in (False, None, 1, 'y'):
            with self.subTest(consent=consent), self.assertRaises(PreparationError):
                with self.engine.protected(self.job, confirm_outage=consent):
                    self.fail('unexpected entry')
        self.assertEqual(self.host.calls, [])
        self.assert_no_intent()

    def test_invalid_job_or_no_change_does_not_enter_maintenance(self):
        for job in (None, (), {}):
            with self.assertRaises(PreparationError):
                with self.engine.protected(job, confirm_outage=True):
                    self.fail('unexpected entry')
        self.assert_no_intent()

    def test_preparation_lock_held_across_coordinator_and_lease_cannot_escape(self):
        def check(lease):
            with self.assertRaises(PreparationError):
                with self.prep._lock():
                    self.fail('second lock')
        lease = self.protect(check)
        with self.assertRaises(PreparationError):
            lease.verify()
        self.assert_pending()

    def test_lock_conflict_before_writes(self):
        with self.prep._lock(), self.assertRaises(PreparationError):
            self.protect()
        self.assert_no_intent()

    def test_wrong_platform_stops_before_intent(self):
        self.host.write('/etc/os-release', b'ID=debian\nVERSION_ID=12\n', 0o644)
        with self.assertRaises(ScopeBlocked):
            self.protect()
        self.assert_no_intent()

    def test_existing_policy_even_identical_is_not_adopted(self):
        self.host.write(POLICY, POLICY_BYTES, 0o755)
        before = self.fixture.snapshot()
        with self.assertRaises(PreparationError):
            self.protect()
        self.assertEqual(before, self.fixture.snapshot())
        self.assertEqual(self.mutations(), [])

    def test_foreign_masks_units_and_overrides_are_not_overwritten(self):
        for path in ('/etc/systemd/system/nginx.service', '/run/systemd/system/certbot.timer',
                     '/usr/lib/systemd/system/nginx.service.d', self.job.directory,
                     self.job.unit_path, '/run/systemd/system/' + self.job.unit):
            with self.subTest(path=path):
                self.host.write(path, b'foreign', 0o644)
                try:
                    before = self.fixture.snapshot()
                    with self.assertRaises((OSError, PreparationError, ClientError)):
                        self.protect()
                    self.assertEqual(before, self.fixture.snapshot())
                    self.assert_no_intent()
                finally:
                    self.host.path(path).unlink()

    def test_dangling_foreign_policy_is_not_followed(self):
        self.host.path(POLICY).symlink_to('/missing/foreign')
        with self.assertRaises(PreparationError):
            self.protect()
        self.assertTrue(self.host.path(POLICY).is_symlink())
        self.assertEqual(self.mutations(), [])

    def test_installed_version_drift_stops_before_guards(self):
        self.host.versions['certbot'] = '1.2.3-1+deb13u2'
        with self.assertRaises(PreparationError):
            self.protect()
        self.assert_no_intent()

    def test_held_partial_or_wrong_architecture_package_blocks(self):
        for edit in (lambda s: s.replace('ii ', 'hi '), lambda s: s.replace('ii ', 'iU '),
                     lambda s: s.replace('certbot\tall', 'certbot\tarm64')):
            with self.subTest(edit=edit):
                def reply(c):
                    value = self.reply(c)
                    return Reply(0, edit(value.output)) if c.argv == ALL_PACKAGES else value
                self.host.local_override = reply
                with self.assertRaises((PreparationError, ScopeBlocked)):
                    self.protect()
                self.assert_no_intent()

    def test_dpkg_audit_or_version_order_failure_blocks(self):
        for target in ('audit', 'compare'):
            def reply(c):
                if target == 'audit' and c.argv == ('dpkg', '--audit'):
                    return Reply(0, 'synthetic partial package')
                if target == 'compare' and c.argv[:2] == ('dpkg', '--compare-versions'):
                    return Reply(1)
                return self.reply(c)
            self.host.local_override = reply
            with self.assertRaises(PreparationError):
                self.protect()
            self.assert_no_intent()

    def test_strict_unit_fields_reject_missing_duplicate_extra_and_control_bytes(self):
        for edit in (lambda s: s.replace('Job=\n', ''), lambda s: s + 'Job=\n',
                     lambda s: s + 'PRIVATE=secret\n', lambda s: s + '\x1b'):
            def reply(c):
                value = self.reply(c)
                return Reply(0, edit(value.output)) if c.argv[:3] == ('systemctl', 'show', '--all') else value
            self.host.local_override = reply
            with self.assertRaises(PreparationError):
                self.protect()
            self.assert_no_intent()

    def test_partial_intent_blocks_other_workflows_and_status_never_suggests_resume(self):
        self.prep._record(INTENT, {'untrusted': TOKEN})
        report = installation_status(root=self.host.root)
        self.assertEqual(report['package_update'], 'needs-inspection')
        rendered = render_status(report)
        self.assertIn('软件包更新', rendered)
        self.assertNotIn('resume --experimental', rendered)
        self.assertNotIn(TOKEN, json.dumps(report) + rendered)
        with self.assertRaises(ClientError):
            read_client(root=self.host.root)
        for action in (self.tokens.check, self.prep.packages, lambda: self.prep.credential(TOKEN),
                       lambda: self.fixture.domains.check('next.example.com')):
            with self.assertRaises(PreparationError):
                action()
        self.assertEqual(self.mutations(), [])

    def test_pending_update_blocks_recovery_paths_before_reading_old_secrets(self):
        from snellctl.retiredrenewal import RetiredRenewal
        from snellctl.retiredcancel import RetiredCancel
        from snellctl.renewalprobe import RenewalPauseProbe
        from snellctl.tokendiag import TokenDiagnostic
        from snellctl.tokenresume import TokenResume
        self.prep._record(INTENT, {})
        for engine in (RetiredRenewal(self.tokens), RetiredCancel(self.tokens), RenewalPauseProbe(self.tokens),
                       TokenDiagnostic(self.tokens), TokenResume(self.tokens)):
            with self.subTest(engine=type(engine).__name__), self.assertRaises(PreparationError) as caught:
                engine.check()
            self.assertIn('软件包更新', str(caught.exception))
        self.assertEqual(self.host.calls, [])

    def test_reinstall_preparation_override_also_honors_update_gate(self):
        from snellctl.reinstall import ReinstallPreparation
        from snellctl.reinstallplan import PENDING
        self.prep._record(INTENT, {})
        preparation = ReinstallPreparation(self.host.root, self.host)
        self.addCleanup(preparation.files.close)
        with self.assertRaises(PreparationError):
            preparation._reinstall_gate()
        self.assertIn(INTENT, PENDING)

    def test_status_does_not_read_pending_update_record_contents(self):
        path = self.host.path(STATE + '/' + INTENT + '.json')
        path.symlink_to('/missing/private')
        report = installation_status(root=self.host.root)
        self.assertEqual(report['package_update'], 'needs-inspection')
        with self.assertRaises(PreparationError):
            self.prep._package_update_gate()

    def test_repeated_entry_never_resubmits_stop_or_overwrites_records(self):
        self.protect()
        before = self.fixture.snapshot()
        self.host.calls.clear()
        with self.assertRaises(PreparationError):
            self.protect()
        self.assertEqual(before, self.fixture.snapshot())
        self.assertEqual(self.mutations(), [])

    def test_journals_are_private_and_contain_no_node_identifiers_or_secrets(self):
        self.protect()
        records = list(self.host.path(self.job.directory).glob('*.json'))
        records.append(self.host.path(STATE + '/' + INTENT + '.json'))
        self.assertEqual(self.host.path(self.job.directory).stat().st_mode & 0o777, 0o700)
        for record in records:
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)
            content = record.read_text()
            for value in (TOKEN, DOMAIN, self.fixture.before_keys.psk, self.fixture.before_keys.shadowtls_password):
                self.assertNotIn(value, content)

    def test_queued_renewal_finishes_naturally_before_nginx_is_stopped(self):
        count = 0
        def reply(c):
            nonlocal count
            if self.engine.phase == 'renewal-wait' and c.argv[:3] == ('systemctl', 'show', 'certbot.service'):
                count += 1
                if count == 1:
                    self.assertIn('nginx.service', self.host.active)
                    return Reply(0, 'ActiveState=activating\nSubState=start\nMainPID=123\nJob=queued\n')
            return self.reply(c)
        self.host.local_override = reply
        self.protect()
        wait = json.loads(self.host.path(self.job.directory + '/pause-observed.json').read_bytes())['pause_wait']
        self.assertEqual(wait['busy_samples'], 1)
        self.assertEqual(wait['result'], 'idle-observed-twice')
        self.assert_pending()

    def test_busy_renewal_timeout_keeps_nginx_and_does_not_mask_or_kill_certbot(self):
        def reply(c):
            if self.engine.phase == 'renewal-wait' and c.argv[:3] == ('systemctl', 'show', 'certbot.service'):
                return Reply(0, 'ActiveState=active\nSubState=running\nMainPID=123\nJob=\n')
            return self.reply(c)
        self.host.local_override = reply
        with self.assertRaises(ScopeBlocked):
            self.protect()
        self.assertIn('nginx.service', self.host.active)
        self.assertFalse(self.host.path('/etc/systemd/system/certbot.service').is_symlink())
        self.assert_pending('renewal-wait')

    def test_sleep_interrupt_does_not_restore_or_clear_guards(self):
        self.engine.waiter.sleep = lambda _: (_ for _ in ()).throw(KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            self.protect()
        self.assert_pending('renewal-wait')

    def test_intent_write_failure_does_not_stop_anything(self):
        original = self.prep.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/' + INTENT + '.json'):
                raise OSError('synthetic write failure')
            return original(path, *args, **kwargs)
        with patch.object(self.prep.files, 'write_new', side_effect=write), self.assertRaises(OSError):
            self.protect()
        self.assert_no_intent()

    def test_policy_write_failure_preserves_intent_without_service_changes(self):
        original = self.prep.files.write_new
        def write(path, *args, **kwargs):
            if path == POLICY:
                raise OSError('synthetic write failure')
            return original(path, *args, **kwargs)
        with patch.object(self.prep.files, 'write_new', side_effect=write), self.assertRaises(OSError):
            self.protect()
        self.assert_pending('policy-create')
        self.assertEqual(self.mutations(), [])

    def test_uncertain_pause_does_not_retry(self):
        def reply(c):
            return Reply(0, 'private output', uncertain=True) if c.argv == (
                'systemctl', 'disable', '--now', 'certbot.timer') else self.reply(c)
        self.host.local_override = reply
        with self.assertRaises(PreparationError):
            self.protect()
        self.assert_pending('renewal-pause')
        self.assertEqual(len(self.mutations()), 1)

    def test_foreign_mask_appearing_after_preflight_is_preserved(self):
        def progress(phase):
            if phase == 'mask-create':
                self.host.write('/etc/systemd/system/certbot.service', b'foreign', 0o644)
        self.engine.progress = progress
        with self.assertRaises(FileExistsError):
            self.protect()
        self.assertEqual(self.host.path('/etc/systemd/system/certbot.service').read_bytes(), b'foreign')
        self.assertTrue(self.host.path(self.job.directory + '/mask-nginx.service.json').exists())
        self.assertIn('nginx.service', self.host.active)
        self.assert_pending('mask-create')

    def test_failed_daemon_reload_does_not_stop_nginx_or_remove_masks(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ('systemctl', 'daemon-reload') else self.reply(c)
        with self.assertRaises(PreparationError):
            self.protect()
        self.assertIn('nginx.service', self.host.active)
        self.assert_pending('mask-create')

    def test_renewal_reappearing_after_wait_is_not_forcibly_stopped(self):
        def reply(c):
            value = self.reply(c)
            if (self.engine.phase == 'mask-create' and c.argv[:4] == ('systemctl', 'show', '--all', 'certbot.service')):
                return Reply(0, value.output.replace('MainPID=0', 'MainPID=456'))
            return value
        self.host.local_override = reply
        with self.assertRaises(PreparationError):
            self.protect()
        self.assertIn('nginx.service', self.host.active)
        self.assert_pending('mask-create')

    def test_nginx_stop_noop_does_not_count_as_guarded(self):
        self.host.local_override = lambda c: Reply(0) if c.argv == ('systemctl', 'stop', 'nginx.service') else self.reply(c)
        with self.assertRaises(PreparationError):
            self.protect()
        self.assert_pending('guards-verify')
        self.assertFalse(self.host.path(self.job.directory + '/guards-ready.json').exists())

    def test_lingering_tls_listener_blocks_guard_readiness(self):
        self.host.local_override = lambda c: Reply(0, 'unexpected listener') if c.argv[:3] == (
            'ss', '-H', '-lntu') else self.reply(c)
        with self.assertRaises(PreparationError):
            self.protect()
        self.assert_pending('guards-verify')

    def test_coordinator_exception_does_not_unmask_restart_or_delete(self):
        def fail(lease):
            raise RuntimeError(TOKEN)
        with self.assertRaises(RuntimeError):
            self.protect(fail)
        self.assert_pending('protected-coordinator')
        self.assertNotIn(TOKEN, self.host.path(self.job.directory + '/guards-stopped.json').read_text())

    def test_policy_mask_and_intent_tampering_are_detected_by_lease(self):
        def check(lease):
            path = self.host.path(POLICY)
            original = path.read_bytes()
            path.write_bytes(b'foreign')
            with self.assertRaises(PreparationError):
                lease.verify()
            path.write_bytes(original)
            marker = self.host.path(STATE + '/' + INTENT + '.json')
            marker.write_text('{}')
            with self.assertRaises(PreparationError):
                lease.verify()
        self.protect(check)

    def test_package_database_change_while_waiting_stops_before_masks(self):
        def reply(c):
            value = self.reply(c)
            if c.argv == ALL_PACKAGES and self.engine.phase == 'renewal-wait':
                return Reply(0, value.output + 'unrelated\tall\tii \t1.0-1\n')
            return value
        self.host.local_override = reply
        with self.assertRaises(PreparationError):
            self.protect()
        self.assertIn('nginx.service', self.host.active)
        self.assert_pending('renewal-wait')

    def test_preserved_package_configuration_or_hook_changes_block_lease(self):
        def check(lease):
            for path in ('/etc/nginx/nginx.conf', RENEW_DROPIN,
                         '/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-main-nginx',
                         '/usr/lib/systemd/system/certbot.service'):
                file = self.host.path(path)
                data = file.read_bytes()
                file.write_bytes(data + b'\n# foreign\n')
                with self.subTest(path=path), self.assertRaises(PreparationError):
                    lease.verify()
                file.write_bytes(data)
        self.protect(check)

    def test_mask_target_owner_and_identity_rechecked(self):
        def check(lease):
            file = self.host.path('/etc/systemd/system/nginx.service')
            file.unlink()
            file.symlink_to('/foreign')
            with self.assertRaises(PreparationError):
                lease.verify()
        self.protect(check)

    def test_extra_dropin_after_preflight_is_not_ignored_under_masks(self):
        def check(lease):
            self.host.write('/run/systemd/system/nginx.service.d/foreign.conf', b'[Service]\n', 0o644)
            with self.assertRaises(PreparationError):
                lease.verify()
        self.protect(check)

    def test_guard_policy_only_denies_managed_services(self):
        import subprocess
        path = self.host.path('/policy-test')
        path.write_bytes(POLICY_BYTES)
        for name in ('nginx', 'nginx.service', 'certbot', 'certbot.service', 'certbot.timer'):
            for prefix in ([], ['--quiet']):
                reply = subprocess.run(['/bin/sh', str(path), *prefix, name, 'start'], capture_output=True)
                self.assertEqual(reply.returncode, 101)
                self.assertEqual(reply.stdout + reply.stderr, b'')
        for name in ('ssh', 'ssh.service', 'ufw', 'unrelated'):
            reply = subprocess.run(['/bin/sh', str(path), name, 'start'], capture_output=True)
            self.assertEqual(reply.returncode, 0)
        self.assertEqual(self.host.calls, [])

    def test_uncertain_nginx_stop_preserves_protection_without_retry(self):
        self.host.local_override = lambda c: Reply(-1, uncertain=True) if c.argv == (
            'systemctl', 'stop', 'nginx.service') else self.reply(c)
        with self.assertRaises(PreparationError):
            self.protect()
        self.assert_pending('nginx-stop')
        self.assertEqual(self.mutations().count(('systemctl', 'stop', 'nginx.service')), 1)

    def test_no_new_cli_or_menu_execution_entry(self):
        from snellctl.__main__ import main
        from contextlib import redirect_stderr
        import io
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['package-upgrade', '--experimental'])


if __name__ == '__main__':
    unittest.main()
