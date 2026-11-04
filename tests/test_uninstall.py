from contextlib import contextmanager, redirect_stderr
import hashlib
import io
import json
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.client import ClientError, read_client
from snellctl.hostprep import Command, HostFiles, PreparationError, Reply, STATE
from snellctl.installer import installation_status, render_status
from snellctl.portchange import PortChange
from snellctl.publish import RENEW_DROPIN
from snellctl.retiredcleanup import lineage_paths
from snellctl.uninstall import COMPLETE, GONE_FIELDS, INTENT, STOP_FIELDS, SUCCESS, Uninstall, UninstallTicket, run_uninstall
from test_domainchange import NEW_DOMAIN, NEW_TOKEN
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
from test_retiredcleanup import Clock
import test_domainchange
import test_retiredcleanup
import test_uninstallplan


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_uninstallplan.UninstallScopeTests('test_complete_node_after_domain_change_and_retired_cleanup')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.host, self.prep, self.tokens = self.fixture.host, self.fixture.prep, self.fixture.tokens
        self.prepare_engine()

    def prepare_engine(self):
        self.spec = self.tokens._check()[1]
        self.vendor = '/usr/lib/systemd/system/nginx.service'
        data = b'[Service]\nExecStart=/usr/sbin/nginx\n[Install]\nWantedBy=multi-user.target\n'
        self.host.write(self.vendor, data, 0o644)
        self.host.write('/var/lib/dpkg/info/nginx-common.md5sums',
                        (hashlib.md5(data).hexdigest() + '  ' + self.vendor[1:] + '\n').encode(), 0o644)
        self.clock = Clock()
        self.engine = Uninstall(self.tokens, clock=self.clock, sleep=self.clock.sleep)
        self.override = None
        self.prep.runner = self.dispatch
        self.host.calls.clear()

    def dispatch(self, command):
        args = command.argv
        if self.override:
            result = self.override(command)
            if result is not None:
                self.host.calls.append(command)
                return result
        if args[:3] == ('systemctl', 'disable', '--now') and args[-1] != 'certbot.timer':
            self.host.calls.append(command)
            self.host.enabled.discard(args[-1])
            self.host.active.discard(args[-1])
            return Reply(0)
        if args[:2] == ('systemctl', 'show') and args[-1] == STOP_FIELDS:
            self.host.calls.append(command)
            active = args[2] in self.host.active
            enabled = args[2] in self.host.enabled
            return Reply(0, f'ActiveState={"active" if active else "inactive"}\nSubState={"running" if active else "dead"}\n'
                           f'MainPID={100 if active else 0}\nControlPID=0\nJob=\n'
                           f'UnitFileState={"enabled" if enabled else "disabled"}\nNeedDaemonReload=no\n')
        if args[:2] == ('systemctl', 'show') and args[-1] == GONE_FIELDS:
            self.host.calls.append(command)
            present = self.host.path('/etc/systemd/system/' + args[2]).exists()
            return Reply(0, f'LoadState={"loaded" if present else "not-found"}\nActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\n')
        if (args == ('systemctl', 'show', 'certbot.service', '-p', 'LoadState,FragmentPath,DropInPaths')
                and not self.host.path(RENEW_DROPIN).exists()):
            self.host.calls.append(command)
            return Reply(0, 'LoadState=loaded\nFragmentPath=/usr/lib/systemd/system/certbot.service\nDropInPaths=\n')
        return self.host(command)

    def check(self):
        return self.engine.check()

    def remove(self, ticket=None, **kwargs):
        args = dict(confirm_ownership=True, confirm_recovery=True, confirm_final_state=True, confirm_delete=True)
        args.update(kwargs)
        return self.engine.remove(ticket or self.check(), **args)

    def assert_success(self, report):
        self.assertEqual(report['result'], SUCCESS, report)
        for key in ('node_stopped_verified', 'entry_rule_removed_verified', 'certificate_removed_verified',
                    'credential_removed_verified', 'renewal_disabled_verified', 'ssh_and_other_rules_verified',
                    'completion_recorded', 'report_saved'):
            self.assertIs(report[key], True, (key, report))
        self.assertFalse(report['reinstall_ready'])
        self.assertFalse(report['automatic_retry'])
        self.assertEqual(self.host.active, set())
        self.assertEqual(self.host.enabled, {'ufw.service'})
        self.assertEqual(len(self.host.rules), 1)
        self.assertIn('SSH', self.host.rules[0])
        self.assertFalse(self.host.path(STATE + '/' + INTENT + '.json').exists())
        self.assertTrue(self.host.path(STATE + '/' + COMPLETE + '.json').exists())

    def assert_pending(self, report):
        self.assertEqual(report['result'], 'stopped', report)
        self.assertTrue(self.host.path(STATE + '/' + INTENT + '.json').exists())
        status = installation_status(root=self.host.root)
        self.assertEqual(status['uninstall'], 'needs-inspection')
        self.assertIn('节点卸载：未确认完成', render_status(status))
        with self.assertRaises(ClientError):
            read_client(root=self.host.root)
        with self.assertRaises(Exception):
            self.check()

    def test_success_removes_only_targets_and_keeps_history_accounts_packages_firewall(self):
        before = self.fixture.snapshot()
        record = self.tokens._check()[2]
        managed = set(record['node']['files']) | {RENEW_DROPIN, self.prep.credential_path(self.spec)}
        report = self.remove()
        self.assert_success(report)
        self.assertEqual(report['files_removed'], len(managed))
        after = self.fixture.snapshot()
        allowed = [p.lstrip('/') for p in managed] + [p.lstrip('/') for p in lineage_paths(NEW_DOMAIN)]
        allowed += ['etc/ufw/user.rules']
        for path, value in before.items():
            if any(path == p or path.startswith(p + '/') for p in allowed):
                continue
            self.assertEqual(after[path], value, path)
        for path in managed | set(lineage_paths(NEW_DOMAIN)):
            self.assertIsNone(self.prep.files.info(path), path)
        calls = [c.argv for c in self.host.calls]
        self.assertEqual(len([a for a in calls if a[:2] == ('certbot', 'delete')]), 1)
        self.assertFalse(any(a[:2] in {('systemctl', 'start'), ('systemctl', 'enable'), ('systemctl', 'reload'),
                                     ('systemctl', 'restart')} or a[0] == 'apt-get' for a in calls))
        self.assertNotIn(('systemctl', 'stop', 'certbot.service'), calls)

    def test_completed_status_is_history_not_current_renewal_or_reinstall_permission(self):
        self.assert_success(self.remove())
        status = installation_status(root=self.host.root)
        self.assertEqual(status['uninstall'], 'completion-recorded')
        self.assertFalse(status['renewal_enabled_by_this_engine'])
        self.assertFalse(status['deploy_ready'])
        self.assertIn('上述安装记录为历史', render_status(status))
        with self.assertRaises(Exception):
            self.check()
        with self.assertRaises(ClientError):
            read_client(root=self.host.root)

    def test_original_domain_and_credential_also_removed(self):
        fixture = test_domainchange.DomainChangeTests('test_check_is_read_only_and_repr_is_redacted')
        self.addCleanup(fixture.doCleanups)
        with patch('test_domainchange.DomainHost', test_retiredcleanup.CleanupHost):
            fixture.setUp()
        test_retiredcleanup.RetiredCleanupTests.enrich_renewals(fixture)
        self.host, self.prep, self.tokens = fixture.host, fixture.prep, fixture.tokens
        self.prepare_engine()
        self.assertEqual(self.spec.domain, DOMAIN)
        credential = self.prep.credential_path(self.spec)
        self.assert_success(self.remove())
        self.assertIsNone(self.prep.files.info(credential))
        for path in lineage_paths(DOMAIN):
            self.assertIsNone(self.prep.files.info(path))

    def test_precheck_is_read_only_and_ticket_repr_is_redacted(self):
        before = self.fixture.snapshot()
        ticket = self.check()
        self.assertEqual(before, self.fixture.snapshot())
        self.assertNotIn(NEW_DOMAIN, repr(ticket))
        self.assertNotIn(ticket.revision, repr(ticket))

    def test_each_confirmation_requires_true_before_any_change(self):
        ticket = self.check()
        before = self.fixture.snapshot()
        self.host.calls.clear()
        for key in ('confirm_ownership', 'confirm_recovery', 'confirm_final_state', 'confirm_delete'):
            for value in (False, None, 1, 'yes'):
                with self.subTest(key=key, value=value), self.assertRaises(PreparationError):
                    self.remove(ticket, **{key: value})
        self.assertEqual(self.host.calls, [])
        self.assertEqual(before, self.fixture.snapshot())

    def test_modified_vendor_unit_blocks_before_timer_or_intent(self):
        self.host.write(self.vendor, b'PRIVATE', 0o644)
        with self.assertRaises(Exception):
            self.check()
        self.assertFalse(self.host.path(STATE + '/' + INTENT + '.json').exists())
        self.assertIn('certbot.timer', self.host.enabled)

    def test_confirmation_revision_drift_blocks_before_write(self):
        ticket = self.check()
        self.host.path(self.vendor).touch()
        with self.assertRaises(Exception):
            self.remove(ticket)
        self.assertFalse(self.host.path(STATE + '/' + INTENT + '.json').exists())

    def test_changed_public_port_is_not_hardcoded(self):
        engine = PortChange(self.tokens.public)
        engine.change(engine.check(24443), confirm_change=True, confirm_ssh_reconnected=True)
        self.host.calls.clear()
        self.assert_success(self.remove())
        deletion = [c.argv for c in self.host.calls if c.argv[:2] == ('ufw', 'delete')]
        self.assertIn('24443', deletion[0])
        self.assertNotIn('443', deletion[0])

    def test_renewal_pause_failure_keeps_nodes_and_all_files(self):
        self.override = lambda c: Reply(1, 'PRIVATE') if c.argv == ('systemctl', 'disable', '--now', 'certbot.timer') else None
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['node_stop_attempted'])
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertEqual(report['files_removed'], 0)
        self.assertTrue(set(self.host.pids) <= self.host.active)

    def test_queued_renewal_waits_but_does_not_kill_certbot(self):
        count = 0
        def override(c):
            nonlocal count
            if c.argv[-1] == 'ActiveState,SubState,MainPID,Job' and 'certbot.timer' not in self.host.enabled:
                count += 1
                if count == 1:
                    return Reply(0, 'ActiveState=activating\nSubState=start\nMainPID=123\nJob=PRIVATE\n')
        self.override = override
        report = self.remove()
        self.assert_success(report)
        self.assertEqual(report['pause_wait']['busy_samples'], 1)
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_busy_renewal_timeout_does_not_stop_nodes_or_delete(self):
        def override(c):
            if c.argv[-1] == 'ActiveState,SubState,MainPID,Job' and 'certbot.timer' not in self.host.enabled:
                return Reply(0, 'ActiveState=active\nSubState=running\nMainPID=123\nJob=\n')
        self.override = override
        report = self.remove()
        self.assert_pending(report)
        self.assertEqual(report['pause_wait']['result'], 'timeout')
        self.assertFalse(report['node_stop_attempted'])
        self.assertFalse(report['certbot_delete_attempted'])

    def test_stop_command_uncertain_does_not_delete_or_retry(self):
        self.override = lambda c: Reply(0, uncertain=True) if c.argv == ('systemctl', 'disable', '--now', self.spec.shadowtls_service) else None
        report = self.remove()
        self.assert_pending(report)
        self.assertEqual(report['failure_phase'], 'node-stop')
        self.assertFalse(report['firewall_delete_attempted'])
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertEqual(sum(c.argv == ('systemctl', 'disable', '--now', self.spec.shadowtls_service) for c in self.host.calls), 1)

    def test_stop_success_without_real_stop_is_not_accepted(self):
        self.override = lambda c: Reply(0) if c.argv == ('systemctl', 'disable', '--now', self.spec.shadowtls_service) else None
        report = self.remove()
        self.assert_pending(report)
        self.assertEqual(report['reason'], 'service-not-disabled-and-stopped')
        self.assertEqual(report['files_removed'], 0)

    def test_duplicate_stop_state_field_is_rejected(self):
        self.override = lambda c: Reply(0, 'MainPID=0\nMainPID=0\n') if c.argv[-1] == STOP_FIELDS else None
        report = self.remove()
        self.assert_pending(report)
        self.assertEqual(report['reason'], 'unit-fields-duplicated')

    def test_remaining_listener_blocks_rule_and_file_removal(self):
        self.override = lambda c: Reply(0, 'tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("shadow-tls",pid=987,fd=7))\n') if c.argv == ('ss', '-H', '-lntup') and not self.host.active else None
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['firewall_delete_attempted'])

    def test_firewall_success_without_expected_delta_keeps_files(self):
        self.override = lambda c: Reply(0) if c.argv[:2] == ('ufw', 'delete') else None
        report = self.remove()
        self.assert_pending(report)
        self.assertEqual(report['reason'], 'firewall-delta-mismatch')
        self.assertEqual(report['files_removed'], 0)

    def test_configuration_and_hooks_removed_before_certbot_delete(self):
        seen = []
        def override(c):
            if c.argv[:2] == ('certbot', 'delete'):
                self.assertFalse(self.host.path(self.spec.nginx_conf).exists())
                self.assertFalse(self.host.path('/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-main-nginx').exists())
                self.assertTrue(self.host.path(RENEW_DROPIN).exists())
                self.assertFalse(self.host.active)
                self.assertNotIn('certbot.timer', self.host.enabled)
                seen.append(c.argv)
        self.override = override
        self.assert_success(self.remove())
        self.assertEqual(len(seen), 1)
        self.assertIn('--no-directory-hooks', seen[0])
        self.assertEqual(seen[0][seen[0].index('--cert-name') + 1], NEW_DOMAIN)

    def test_certbot_false_success_does_not_delete_credential_or_programs(self):
        self.override = lambda c: Reply(0) if c.argv[:2] == ('certbot', 'delete') else None
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['certificate_removed_verified'])
        self.assertFalse(report['credential_removed_verified'])
        self.assertTrue(self.host.path(self.prep.credential_path(self.spec)).exists())

    def test_certbot_error_or_uncertainty_is_not_retried(self):
        self.override = lambda c: Reply(-1, 'PRIVATE-DOMAIN SECRET', uncertain=True) if c.argv[:2] == ('certbot', 'delete') else None
        report = self.remove()
        self.assert_pending(report)
        self.assertNotIn('PRIVATE', json.dumps(report))
        self.assertEqual(sum(c.argv[:2] == ('certbot', 'delete') for c in self.host.calls), 1)

    def test_external_new_site_after_stop_preserved_and_blocks_delete(self):
        def progress(phase):
            if phase == 'certificate-references-remove':
                self.host.write('/etc/nginx/conf.d/foreign.conf', b'PRIVATE', 0o644)
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertTrue(self.host.path('/etc/nginx/conf.d/foreign.conf').exists())

    def test_external_unit_restart_before_certbot_blocks(self):
        def progress(phase):
            if phase == 'certificate-delete':
                self.host.active.add('nginx.service')
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['certbot_delete_attempted'])

    def test_new_global_certbot_config_before_delete_is_preserved_and_blocks(self):
        path = '/etc/letsencrypt/cli.ini'
        self.host.path(path).unlink(missing_ok=True)
        def progress(phase):
            if phase == 'certificate-delete':
                self.host.write(path, b'max-log-backups = 2\n', 0o644)
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertEqual(self.host.path(path).read_bytes(), b'max-log-backups = 2\n')

    def test_changed_global_certbot_config_before_delete_is_preserved_and_blocks(self):
        path = '/etc/letsencrypt/cli.ini'
        self.host.write(path, b'max-log-backups = 2\n', 0o644)
        def progress(phase):
            if phase == 'certificate-delete':
                self.host.write(path, b'pre-hook = PRIVATE\n', 0o644)
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertEqual(self.host.path(path).read_bytes(), b'pre-hook = PRIVATE\n')
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_new_isolated_home_config_before_delete_is_preserved_and_blocks(self):
        path = STATE + '/home/.config/letsencrypt/cli.ini'
        def progress(phase):
            if phase == 'certificate-delete':
                self.host.write(path, b'pre-hook = PRIVATE\n')
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertEqual(self.host.path(path).read_bytes(), b'pre-hook = PRIVATE\n')
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_marker_drift_preserved_and_stops(self):
        def progress(phase):
            if phase == 'entry-rule-remove':
                self.host.write(STATE + '/' + INTENT + '.json', b'{"external": true}\n')
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['firewall_delete_attempted'])

    def test_file_replacement_not_unlinked(self):
        original = HostFiles.unlink_owned
        target = self.spec.nginx_conf
        def unlink(files, path, identity):
            if path == target:
                self.host.path(path).rename(self.host.path(path + '.old'))
                self.host.write(path, b'PRIVATE foreign', 0o644)
            return original(files, path, identity)
        with patch.object(HostFiles, 'unlink_owned', new=unlink):
            report = self.remove()
        self.assert_pending(report)
        self.assertEqual(self.host.path(target).read_bytes(), b'PRIVATE foreign')
        self.assertFalse(report['certbot_delete_attempted'])

    def test_interrupt_retains_intent_and_does_not_enable_services(self):
        def progress(phase):
            if phase == 'certificate-delete':
                raise KeyboardInterrupt()
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertEqual(report['reason'], 'interrupted')
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertFalse(any(c.argv[:2] == ('systemctl', 'enable') for c in self.host.calls))

    def test_report_write_failure_does_not_repeat_mutations(self):
        original = HostFiles.write_new
        def write(files, path, *args, **kwargs):
            if '/uninstall-' in path and path.endswith('/report.json'):
                raise OSError('PRIVATE')
            return original(files, path, *args, **kwargs)
        with patch.object(HostFiles, 'write_new', new=write):
            report = self.remove()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertFalse(report['report_saved'])
        self.assertTrue(report['completion_recorded'])
        self.assertEqual(sum(c.argv[:2] == ('certbot', 'delete') for c in self.host.calls), 1)

    def test_completion_write_failure_retains_blocking_marker(self):
        original = HostFiles.write_new
        def write(files, path, *args, **kwargs):
            if path == STATE + '/' + COMPLETE + '.json':
                raise OSError('PRIVATE')
            return original(files, path, *args, **kwargs)
        with patch.object(HostFiles, 'write_new', new=write):
            report = self.remove()
        self.assert_pending(report)
        self.assertTrue(report['certificate_removed_verified'])
        self.assertFalse(report['completion_recorded'])

    def test_intent_write_failure_prevents_all_service_mutations(self):
        original = HostFiles.write_new
        def write(files, path, *args, **kwargs):
            if path == STATE + '/' + INTENT + '.json':
                raise OSError('PRIVATE')
            return original(files, path, *args, **kwargs)
        with patch.object(HostFiles, 'write_new', new=write):
            report = self.remove()
        self.assertEqual(report['result'], 'stopped')
        self.assertFalse(any(c.argv[:2] == ('systemctl', 'disable') for c in self.host.calls))
        self.assertFalse(report['certbot_delete_attempted'])

    def test_no_secrets_or_paths_in_report(self):
        ticket = self.check()
        report = self.remove(ticket)
        self.assert_success(report)
        text = json.dumps(report)
        keys = self.fixture.fixture.fixture.before_keys
        for value in (DOMAIN, NEW_DOMAIN, TOKEN, NEW_TOKEN, ticket.revision, keys.psk, keys.shadowtls_password, STATE):
            self.assertNotIn(value, text)

    def test_guard_denies_unexpected_commands_and_restores_runner(self):
        original = self.prep.runner
        with self.engine._commands():
            for args in (('ufw', 'reset'), ('systemctl', 'stop', 'ssh.service'), ('certbot', 'renew'), ('apt-get', 'purge', 'nginx')):
                with self.assertRaises(PreparationError):
                    self.prep.runner(Command(args))
        self.assertEqual(self.prep.runner, original)

    def test_acme_account_change_blocks_before_certificate_removal(self):
        def progress(phase):
            if phase == 'certificate-delete':
                self.host.write('/etc/letsencrypt/accounts/foreign-account', b'PRIVATE')
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertEqual(report['reason'], 'preserved-resources-changed')
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertTrue(self.host.path('/etc/letsencrypt/accounts/foreign-account').exists())

    def test_credential_content_drift_after_certificate_delete_is_preserved(self):
        credential = self.prep.credential_path(self.spec)
        def progress(phase):
            if phase == 'managed-files-remove':
                self.host.write(credential, b'PRIVATE new credential')
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertTrue(report['certificate_removed_verified'])
        self.assertFalse(report['credential_removed_verified'])
        self.assertEqual(self.host.path(credential).read_bytes(), b'PRIVATE new credential')

    def test_certbot_partial_deletion_error_does_not_continue_or_retry(self):
        def override(c):
            if c.argv[:2] == ('certbot', 'delete'):
                self.host.path('/etc/letsencrypt/renewal/' + NEW_DOMAIN + '.conf').unlink()
                return Reply(1, 'PRIVATE partial deletion')
        self.override = override
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['certificate_removed_verified'])
        self.assertTrue(self.host.path('/etc/letsencrypt/live/' + NEW_DOMAIN).exists())
        self.assertTrue(self.host.path(self.prep.credential_path(self.spec)).exists())

    def test_renewal_restart_before_delete_stops_without_stopping_certbot(self):
        def progress(phase):
            if phase == 'certificate-delete':
                self.override = lambda c: Reply(0, 'ActiveState=active\nSubState=running\nMainPID=222\nJob=\n') if c.argv[-1] == 'ActiveState,SubState,MainPID,Job' else None
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertEqual(report['reason'], 'renewal-unit-state-mismatch')
        self.assertFalse(any(c.argv[:2] == ('systemctl', 'stop') for c in self.host.calls))

    def test_daemon_reload_failure_retains_partial_removal_record(self):
        self.override = lambda c: Reply(1) if c.argv == ('systemctl', 'daemon-reload') else None
        report = self.remove()
        self.assert_pending(report)
        self.assertTrue(report['certificate_removed_verified'])
        self.assertTrue(report['credential_removed_verified'])
        self.assertFalse(report['completion_recorded'])
        self.assertFalse(report['final_state_verified'])

    def test_removed_unit_still_loaded_cannot_claim_success(self):
        self.override = lambda c: Reply(0, 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\n') if c.argv[-1] == GONE_FIELDS else None
        report = self.remove()
        self.assert_pending(report)
        self.assertEqual(report['reason'], 'removed-service-still-loaded')
        self.assertFalse(report['completion_recorded'])

    def test_wrong_nginx_include_after_reference_removal_blocks_certbot(self):
        def override(c):
            if c.argv == ('nginx', '-T') and not self.host.path(self.spec.nginx_conf).exists():
                return Reply(0, '# configuration file /etc/nginx/nginx.conf:\n# configuration file /etc/nginx/mime.types:\n# configuration file /PRIVATE:\n')
        self.override = override
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_file_unlink_error_stops_without_certbot(self):
        original = HostFiles.unlink_owned
        def unlink(files, path, identity):
            if path == self.spec.nginx_conf:
                raise OSError(5, 'PRIVATE')
            return original(files, path, identity)
        with patch.object(HostFiles, 'unlink_owned', new=unlink):
            report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['certbot_delete_attempted'])
        self.assertEqual(report['errno'], 5)
        self.assertNotIn('PRIVATE', json.dumps(report))

    def test_intent_cleanup_error_does_not_hide_pending_state_behind_completion(self):
        original = HostFiles.unlink_owned
        def unlink(files, path, identity):
            if path == STATE + '/' + INTENT + '.json':
                raise OSError('PRIVATE')
            return original(files, path, identity)
        with patch.object(HostFiles, 'unlink_owned', new=unlink):
            report = self.remove()
        self.assert_pending(report)
        self.assertTrue(report['completion_recorded'])
        self.assertFalse(report['final_state_verified'])

    def test_unrelated_ipv4_rule_change_during_removal_blocks_and_preserves_it(self):
        def progress(phase):
            if phase == 'entry-rule-remove':
                self.host.rules.append('ufw allow 7777/tcp')
                self.host.input4.append('-A ufw-user-input -p tcp --dport 7777 -j ACCEPT')
                self.host.write('/etc/ufw/user.rules', ('\n'.join(self.host.input4) + '\n').encode(), 0o640)
        self.engine.progress = progress
        report = self.remove()
        self.assert_pending(report)
        self.assertFalse(report['firewall_delete_attempted'])
        self.assertIn('ufw allow 7777/tcp', self.host.rules)

    def test_lock_conflict_never_mutates(self):
        ticket = self.check()
        before = self.fixture.snapshot()
        with self.prep._lock(), self.assertRaises(PreparationError):
            self.remove(ticket)
        self.assertEqual(before, self.fixture.snapshot())


class UninstallCLITests(unittest.TestCase):
    def setUp(self):
        self.engine = Mock()
        self.engine.check.return_value = UninstallTicket('node.example.org', 4443, 23456, 'private-revision')
        self.engine.remove.return_value = {'result': SUCCESS}
        self.factory_calls = 0

    @contextmanager
    def factory(self):
        self.factory_calls += 1
        yield object()

    def run_cli(self, ui):
        with patch('snellctl.uninstall.Uninstall', return_value=self.engine):
            return run_uninstall(factory=self.factory, terminal=ui)

    def test_four_separate_confirmations_before_removal(self):
        self.assertEqual(self.run_cli(Console(['y'] * 4)), 0)
        self.engine.remove.assert_called_once_with(self.engine.check.return_value, confirm_ownership=True,
                                                  confirm_recovery=True, confirm_final_state=True, confirm_delete=True)

    def test_each_no_or_default_cancels_without_mutation(self):
        for index in range(4):
            for answer in ('', 'n', 'yes', '确认'):
                self.engine.remove.reset_mock()
                self.assertEqual(self.run_cli(Console(['y'] * index + [answer])), 130)
                self.engine.remove.assert_not_called()

    def test_noninteractive_refused_before_factory(self):
        ui = Console([])
        ui.interactive = lambda: False
        self.assertEqual(self.run_cli(ui), 2)
        self.assertEqual(self.factory_calls, 0)

    def test_precheck_exception_redacted_no_delete(self):
        self.engine.check.side_effect = PreparationError('PRIVATE')
        self.engine.failure.return_value = {'reason': 'blocked'}
        ui = Console([])
        self.assertEqual(self.run_cli(ui), 1)
        self.assertNotIn('PRIVATE', ui.text)
        self.engine.remove.assert_not_called()

    def test_explicit_experimental_required_and_no_auto_yes(self):
        with patch('snellctl.uninstall.run_uninstall', return_value=0) as run:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(['uninstall']), 2)
                run.assert_not_called()
                for option in ('--yes', '--domain', '--root', '--token'):
                    with self.assertRaises(SystemExit):
                        main(['uninstall', '--experimental', option])
            self.assertEqual(main(['uninstall', '--experimental']), 0)
            run.assert_called_once_with()

    def test_eof_and_interrupt_during_confirmation_cancel_without_remove(self):
        for error in (EOFError(), KeyboardInterrupt()):
            with self.subTest(error=type(error)):
                ui = Console([])
                ui.ask = Mock(side_effect=error)
                self.assertEqual(self.run_cli(ui), 130)
                self.engine.remove.assert_not_called()
