from contextlib import contextmanager, redirect_stderr
import io
import json
import os
from pathlib import PurePosixPath
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.activation import BINARIES
from snellctl.hostprep import Command, HostFiles, PreparationError, Reply, STATE
from snellctl.portchange import PortChange
from snellctl.reinstallplan import (PACKAGE_QUERY, PENDING, READ_COMMANDS, SERVICE_EXPECTED,
                                   SSH_FIELDS, SUCCESS, ReinstallPlan, run_reinstall_plan)
from snellctl.uninstall import COMPLETE, GONE_FIELDS
from test_domainchange import NEW_DOMAIN, NEW_TOKEN
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
import test_uninstall
import test_domainchange
import test_retiredcleanup


class ReinstallPlanTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_uninstall.UninstallTests('test_success_removes_only_targets_and_keeps_history_accounts_packages_firewall')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.finish_uninstall()

    def finish_uninstall(self):
        self.fixture.assert_success(self.fixture.remove())
        self.host, self.prep = self.fixture.host, self.fixture.prep
        self.engine = ReinstallPlan(self.fixture.tokens)
        self.original_runner = self.prep.runner
        self.override = None
        self.prep.runner = self.dispatch
        self.host.calls.clear()
        record = self.prep._read_record(COMPLETE)
        self.history = record['directory']

    def dispatch(self, command):
        if self.override:
            result = self.override(command)
            if result is not None:
                self.host.calls.append(command)
                return result
        args = command.argv
        if args[:2] == ('systemctl', 'show'):
            if args[2] in SERVICE_EXPECTED and args[-1] == ','.join(SERVICE_EXPECTED[args[2]]):
                fields = dict(SERVICE_EXPECTED[args[2]])
                if args[2] in self.host.active:
                    fields.update(ActiveState='active', SubState='running')
                if args[2] in self.host.enabled:
                    fields['UnitFileState'] = 'enabled'
                self.host.calls.append(command)
                return Reply(0, ''.join(f'{k}={v}\n' for k, v in fields.items()))
            if args[2] == 'ssh.service' and args[-1] == SSH_FIELDS:
                self.host.calls.append(command)
                return Reply(0, 'LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=123\n')
        return self.original_runner(command)

    def check(self):
        return self.engine.check()

    def snapshot(self):
        return self.fixture.fixture.snapshot()

    def edit_json(self, path, edit):
        data = json.loads(self.host.path(path).read_bytes())
        edit(data)
        self.host.write(path, json.dumps(data).encode())

    def blocked(self, result=None, reason=None):
        result = self.check() if result is None else result
        self.assertEqual(result['result'], 'blocked-preserve-all', result)
        for key in ('host_changes_attempted', 'report_saved', 'reinstall_ready', 'reinstall_authorized', 'reinstall_implemented'):
            self.assertIs(result[key], False, result)
        self.assertTrue(result['all_assets_preserved'])
        if reason:
            self.assertEqual(result['reason'], reason, result)
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_success_after_uninstall_and_domain_cleanup(self):
        report = self.check()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertEqual(report['current_state'], 'uninstalled-local-checks-passed')
        for key in ('reinstall_ready', 'reinstall_implemented', 'reinstall_authorized', 'apt_indexes_refreshed'):
            self.assertFalse(report[key])

    def test_no_file_service_rule_or_history_changes(self):
        before = self.snapshot()
        state = set(self.host.active), set(self.host.enabled), list(self.host.rules)
        with patch.object(HostFiles, 'write_new', side_effect=AssertionError('write')), \
             patch.object(HostFiles, 'replace_owned', side_effect=AssertionError('replace')), \
             patch.object(HostFiles, 'unlink_owned', side_effect=AssertionError('unlink')), \
             patch.object(HostFiles, 'private_directory_new', side_effect=AssertionError('mkdir')):
            report = self.check()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(state, (self.host.active, self.host.enabled, self.host.rules))
        self.assertTrue(self.host.calls)
        self.assertTrue(all(c.argv in READ_COMMANDS and not c.capture_stderr for c in self.host.calls))
        self.assertFalse(any(c.argv[0] in {'nginx', 'openssl', 'certbot', 'apt-get', 'apt-cache'} for c in self.host.calls))

    def test_original_domain_without_domain_change_supported(self):
        fixture = test_domainchange.DomainChangeTests('test_check_is_read_only_and_repr_is_redacted')
        self.addCleanup(fixture.doCleanups)
        with patch('test_domainchange.DomainHost', test_retiredcleanup.CleanupHost):
            fixture.setUp()
        test_retiredcleanup.RetiredCleanupTests.enrich_renewals(fixture)
        self.fixture.host, self.fixture.prep, self.fixture.tokens = fixture.host, fixture.prep, fixture.tokens
        self.fixture.prepare_engine()
        self.finish_uninstall()
        self.assertEqual(self.check()['result'], SUCCESS)

    def test_nondefault_old_port_derived_from_record(self):
        # A separate valid deployment avoids constructing fake completion records.
        self.fixture.doCleanups()
        self.fixture.setUp()
        ports = PortChange(self.fixture.tokens.public)
        ports.change(ports.check(24443), confirm_change=True, confirm_ssh_reconnected=True)
        self.finish_uninstall()
        self.assertEqual(self.check()['result'], SUCCESS)
        self.host.rules.append('ufw allow 24443/tcp')
        self.blocked(reason='old-entry-rule-or-port-reused')

    def test_output_has_no_domain_path_credential_key_or_fingerprint(self):
        report = self.check()
        self.assertEqual(report['result'], SUCCESS, report)
        text = json.dumps(report)
        revision = self.prep._read_record(COMPLETE)['revision']
        for secret in (DOMAIN, NEW_DOMAIN, TOKEN, NEW_TOKEN, str(self.host.root), STATE, revision):
            self.assertNotIn(secret, text)

    def test_account_keys_and_raw_logs_not_read(self):
        self.host.write('/etc/letsencrypt/accounts/acme.invalid/directory/account/private_key.json', b'PRIVATE')
        self.host.write(self.history + '/letsencrypt.log', b'PRIVATE')
        original = self.prep.files.read
        def read(path, **kw):
            self.assertNotIn('/accounts/', path)
            self.assertFalse(path.endswith('.log'))
            self.assertNotIn('/credentials/', path)
            return original(path, **kw)
        with patch.object(self.prep.files, 'read', side_effect=read):
            report = self.check()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertFalse(report['acme_account_contents_read'])

    def test_missing_completion_or_report_blocks(self):
        for path in (STATE + '/' + COMPLETE + '.json', self.history + '/report.json'):
            with self.subTest(path=path):
                data = self.host.path(path).read_bytes()
                self.host.path(path).unlink()
                self.blocked()
                self.host.write(path, data)

    def test_every_active_marker_blocks_without_reading_it(self):
        for name in PENDING:
            path = STATE + '/' + name + '.json'
            with self.subTest(name=name):
                self.host.write(path, b'PRIVATE not JSON')
                self.blocked(reason='unexpected-resource-preserve-all')
                self.host.path(path).unlink()

    def test_incomplete_or_false_completion_report_blocks(self):
        path = self.history + '/report.json'
        data = self.host.path(path).read_bytes()
        for edit in (lambda d: d.update(result='stopped'), lambda d: d.update(final_state_verified=False),
                     lambda d: d.update(reinstall_ready=True), lambda d: d.update(report_saved=1),
                     lambda d: d.update(format=True)):
            with self.subTest(edit=edit):
                self.edit_json(path, edit)
                self.blocked(reason='uninstall-report-not-success')
                self.host.write(path, data)

    def test_history_path_injection_rejected_without_read(self):
        path = STATE + '/' + COMPLETE + '.json'
        data = self.host.path(path).read_bytes()
        for value in ('/etc/shadow', STATE + '/uninstall-../../PRIVATE', STATE + '/uninstall-abcd', None):
            self.edit_json(path, lambda d: d.update(directory=value))
            self.blocked(reason='uninstall-history-path-unrecognized')
            self.host.write(path, data)

    def test_duplicate_json_fields_rejected(self):
        path = STATE + '/' + COMPLETE + '.json'
        data = self.host.path(path).read_bytes()
        self.host.write(path, b'{"format":1,' + data[1:])
        self.blocked()

    def test_symlink_and_hardlink_record_rejected(self):
        path = self.host.path(STATE + '/' + COMPLETE + '.json')
        saved = path.with_name('saved.json')
        path.rename(saved)
        path.symlink_to(saved.name)
        self.blocked()
        path.unlink()
        os.link(saved, path)
        self.blocked()

    def test_insecure_record_or_history_directory_rejected(self):
        for path, original in ((STATE + '/' + COMPLETE + '.json', 0o600), (self.history, 0o700)):
            self.host.path(path).chmod(0o755)
            self.blocked()
            self.host.path(path).chmod(original)

    def test_certificate_history_mismatch(self):
        self.edit_json(self.history + '/certificate-attempt.json', lambda d: d.update(domain='mismatched.example.org'))
        self.blocked(reason='certificate-history-mismatch')

    def test_public_record_missing_binding_or_invalid_ssh(self):
        path = STATE + '/public-ready.json'
        data = self.host.path(path).read_bytes()
        for value in (None, True, 0, 65536, '54300'):
            self.edit_json(path, lambda d: d.update(ssh_port=value))
            self.blocked(reason='public-history-unrecognized')
            self.host.write(path, data)

    def test_remaining_managed_file_is_not_read_or_removed(self):
        path = '/etc/snellctl/nodes/main/snell.conf'
        self.host.write(path, b'PRIVATE')
        before = self.snapshot()
        self.blocked(reason='unexpected-resource-preserve-all')
        self.assertEqual(before, self.snapshot())

    def test_extra_managed_resource_or_certificate_blocks(self):
        paths = ('/etc/snellctl/credentials/extra', '/etc/snellctl/nodes/other',
                 str(PurePosixPath(BINARIES[0]).parent) + '/extra', '/etc/letsencrypt/renewal/extra.conf',
                 '/etc/letsencrypt/archive/extra', '/etc/letsencrypt/live/extra',
                 '/etc/nginx/sites-enabled/other', '/etc/letsencrypt/renewal-hooks/post/extra')
        for path in paths:
            with self.subTest(path=path):
                self.host.write(path, b'PRIVATE')
                before = self.snapshot()
                self.blocked()
                self.assertEqual(before, self.snapshot())
                self.host.path(path).unlink()

    def test_external_override_or_policy_blocks(self):
        paths = ('/usr/sbin/policy-rc.d', '/run/systemd/system/certbot.service',
                 '/etc/systemd/system/nginx.service.d/extra.conf')
        for path in paths:
            self.host.write(path, b'PRIVATE')
            self.blocked()
            self.host.path(path).unlink()

    def test_empty_retained_override_directory_allowed(self):
        self.host.path('/etc/systemd/system/certbot.service.d').mkdir(exist_ok=True)
        self.assertEqual(self.check()['result'], SUCCESS)

    def test_vendor_unit_and_base_nginx_edits_block(self):
        for path in ('/usr/lib/systemd/system/nginx.service', '/usr/lib/systemd/system/certbot.timer', '/etc/nginx/nginx.conf'):
            data = self.host.path(path).read_bytes()
            self.host.write(path, b'PRIVATE', 0o644)
            self.blocked()
            self.host.write(path, data, 0o644)

    def test_package_audit_output_and_missing_installed_package_block(self):
        self.override = lambda c: Reply(0, 'PRIVATE') if c.argv == ('dpkg', '--audit') else None
        self.blocked(reason='package-audit-not-empty')
        self.override = lambda c: Reply(0, '') if c.argv == PACKAGE_QUERY else None
        self.blocked(reason='packages-unrecognized')

    def test_busy_enabled_or_malformed_service_status_blocks(self):
        unit = 'certbot.service'
        query = ('systemctl', 'show', unit, '-p', ','.join(SERVICE_EXPECTED[unit]))
        valid = ''.join(f'{k}={v}\n' for k, v in SERVICE_EXPECTED[unit].items())
        variants = (valid.replace('MainPID=0', 'MainPID=123'), valid.replace('Job=\n', 'Job=PRIVATE\n'),
                    valid.replace('ActiveState=inactive', 'ActiveState=activating'),
                    valid + 'MainPID=0\n', valid + 'PRIVATE\n', valid.replace('Job=\n', ''))
        for value in variants:
            self.override = lambda c: Reply(0, value) if c.argv == query else None
            self.blocked()

    def test_nginx_or_timer_reenabled_blocks(self):
        for unit in ('nginx.service', 'certbot.timer'):
            self.host.enabled.add(unit)
            self.blocked(reason='vendor-service-not-idle-disabled-or-unmodified')
            self.host.enabled.remove(unit)

    def test_node_unit_reappeared_and_failed_command_block(self):
        self.override = lambda c: Reply(0, 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nJob=\n') if c.argv[-1] == GONE_FIELDS else None
        self.blocked(reason='node-unit-not-removed')
        self.override = lambda c: Reply(1, 'PRIVATE', uncertain=True) if c.argv == PACKAGE_QUERY else None
        self.blocked()

    def test_ssh_stopped_or_allow_removed_blocks(self):
        self.override = lambda c: Reply(0, 'LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=enabled\nMainPID=0\n') if c.argv[-1] == SSH_FIELDS else None
        self.blocked(reason='ssh-service-not-running')
        self.override = None
        self.host.rules.clear()
        self.blocked()

    def test_old_port_or_managed_process_listener_blocks(self):
        for port, process in ((443, 'other'), (60000, 'shadow-tls')):
            value = f'tcp LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:* users:(("{process}",pid=99,fd=3))\n'
            self.override = lambda c: Reply(0, value) if c.argv == ('ss', '-H', '-lntup') else None
            self.blocked(reason='old-entry-or-program-listener-present')

    def test_snapshot_drift_blocks(self):
        self.engine.progress = lambda phase: self.host.path(self.history + '/report.json').touch() if phase == 'unchanged-state-check' else None
        self.blocked()

    def test_cooperative_lock_busy_preserves_all(self):
        before = self.snapshot()
        with self.prep._lock():
            self.blocked()
        self.assertEqual(before, self.snapshot())
        self.assertFalse(self.host.calls)

    def test_command_guard_blocks_all_mutations_and_extra_readers(self):
        calls = (('certbot', 'certificates'), ('systemctl', 'start', 'nginx.service'), ('ufw', 'allow', '443/tcp'),
                 ('apt-get', 'update'), ('nginx', '-T'), ('openssl', 'pkey', '-in', '/PRIVATE'))
        for args in calls:
            with self.engine._commands(), self.assertRaises(PreparationError):
                self.prep.runner(Command(args))
        self.assertFalse(self.host.calls)

    def test_fresh_install_gate_not_relaxed(self):
        self.assertEqual(self.check()['result'], SUCCESS)
        with self.assertRaises(PreparationError):
            self.prep.initialize()
        self.assertTrue(self.host.path(STATE + '/' + COMPLETE + '.json').exists())


class ReinstallCLITests(unittest.TestCase):
    def setUp(self):
        self.engine = Mock()
        self.engine.check.return_value = {'result': SUCCESS}
        self.factory_calls = 0

    @contextmanager
    def factory(self):
        self.factory_calls += 1
        yield object()

    def run_cli(self, ui):
        with patch('snellctl.reinstallplan.ReinstallPlan', return_value=self.engine):
            return run_reinstall_plan(factory=self.factory, terminal=ui)

    def test_confirmed_readonly_check(self):
        self.assertEqual(self.run_cli(Console(['Y'])), 0)
        self.engine.check.assert_called_once_with()

    def test_no_default_and_nonstandard_yes_cancel_before_factory(self):
        for answer in ('', 'n', 'yes', '确认'):
            self.assertEqual(self.run_cli(Console([answer])), 130)
        self.assertEqual(self.factory_calls, 0)

    def test_non_tty_refused_before_factory(self):
        ui = Console([])
        ui.interactive = lambda: False
        self.assertEqual(self.run_cli(ui), 2)
        self.assertEqual(self.factory_calls, 0)

    def test_lost_tty_after_confirmation(self):
        ui = Console(['y'])
        ui.interactive = Mock(side_effect=(True, False))
        self.assertEqual(self.run_cli(ui), 2)
        self.assertEqual(self.factory_calls, 0)

    def test_interrupt_eof_and_failure_redacted(self):
        for error, code in ((EOFError(), 130), (KeyboardInterrupt(), 130), (RuntimeError('PRIVATE'), 1)):
            ui = Console([])
            ui.ask = Mock(side_effect=error)
            self.assertEqual(self.run_cli(ui), code)
            self.assertNotIn('PRIVATE', ui.text)
        self.assertEqual(self.factory_calls, 0)

    def test_blocked_report_exit_status(self):
        self.engine.check.return_value = {'result': 'blocked-preserve-all'}
        self.assertEqual(self.run_cli(Console(['y'])), 1)

    def test_dispatch_and_no_parameters_or_execution_flags(self):
        with patch('snellctl.reinstallplan.run_reinstall_plan', return_value=0) as run:
            self.assertEqual(main(['reinstall-plan']), 0)
            run.assert_called_once_with()
            for option in ('--yes', '--experimental', '--apply', '--root', '--domain', '--token'):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    main(['reinstall-plan', option])
