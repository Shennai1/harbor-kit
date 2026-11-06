from contextlib import contextmanager, redirect_stderr
import io
import json
import os
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.activation import BINARIES
from snellctl.hostprep import Command, HostFiles, PreparationError, Reply, STATE
from snellctl.maintenance import Maintenance, PACKAGE_QUERY, READ_COMMANDS, REVIEW, SUCCESS, UNIT_FIELDS, UNITS, run_maintenance
from snellctl.publish import RENEW_DROPIN
from snellctl.tokenchange import TokenChange
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
import test_domainchange
import test_reinstall


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_domainchange.DomainChangeTests('test_check_is_read_only_and_repr_is_redacted')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.host, self.prep, self.tokens = self.fixture.host, self.fixture.prep, self.fixture.tokens
        self.engine = Maintenance(self.tokens)
        self.host.local_override = self.unit_reply
        self.host.calls.clear()

    def unit_reply(self, command):
        args = command.argv
        if args[:2] != ('systemctl', 'show') or args[-1] != UNIT_FIELDS:
            return None
        unit = args[2]
        self.assertIn(unit, UNITS)
        prefix = '/etc/systemd/system/' if unit.startswith('snellctl-') else '/usr/lib/systemd/system/'
        fields = dict(LoadState='loaded', ActiveState='active', SubState='running', UnitFileState='enabled',
                      FragmentPath=prefix + unit, DropInPaths='', NeedDaemonReload='no')
        if unit == 'certbot.service':
            fields.update(ActiveState='inactive', SubState='dead', UnitFileState='static', DropInPaths=RENEW_DROPIN)
        if unit == 'certbot.timer':
            fields['SubState'] = 'waiting'
        return Reply(0, ''.join(key + '=' + fields[key] + '\n' for key in UNIT_FIELDS.split(',')))

    def check(self):
        return self.engine.check()

    def blocked(self, result, reason=None):
        self.assertEqual(result['result'], 'blocked-preserve-all', result)
        self.assertFalse(result['collection_complete'])
        self.assertFalse(result['host_changes_attempted'])
        self.assertFalse(result['update_authorized'])
        self.assertFalse(result['update_ready'])
        self.assertFalse(result['report_saved'])
        self.assertNotIn('programs', result)
        if reason:
            self.assertEqual(result['reason'], reason, result)

    def test_complete_inventory_not_update_or_health_authority(self):
        result = self.check()
        self.assertEqual(result['result'], SUCCESS, result)
        self.assertTrue(result['collection_complete'])
        self.assertEqual(len(result['programs']), 2)
        self.assertEqual(len(result['packages']), 4)
        self.assertEqual(result['findings'], [])
        self.assertFalse(result['update_ready'])
        self.assertFalse(result['upstream_checked'])
        self.assertFalse(result['apt_indexes_refreshed'])
        self.assertEqual(result['current_service_health'], 'not-checked')
        self.assertEqual(result['security_patch_status'], 'not-assessed')
        self.assertEqual(result['package_source']['installed_package_origin'], 'not-proven')

    def test_no_writes_service_changes_or_network_commands(self):
        before = self.fixture.snapshot()
        state = set(self.host.active), set(self.host.enabled), list(self.host.rules)
        with patch.object(HostFiles, 'write_new', side_effect=AssertionError('write')), \
             patch.object(HostFiles, 'replace_owned', side_effect=AssertionError('replace')), \
             patch.object(HostFiles, 'unlink_owned', side_effect=AssertionError('delete')), \
             patch.object(HostFiles, 'private_directory_new', side_effect=AssertionError('mkdir')):
            result = self.check()
        self.assertEqual(result['result'], SUCCESS, result)
        self.assertEqual(before, self.fixture.snapshot())
        self.assertEqual(state, (self.host.active, self.host.enabled, self.host.rules))
        self.assertTrue(all(c.argv in READ_COMMANDS for c in self.host.calls))
        self.assertFalse(any(c.argv[0] in {'apt-get', 'apt-cache', 'certbot', *BINARIES} for c in self.host.calls))
        self.fixture.probe.assert_not_called()

    def test_tokens_certificate_account_and_logs_not_read(self):
        original = HostFiles.read
        def read(files, path, **kwargs):
            self.assertNotIn('/credentials/', path)
            self.assertFalse(path.startswith('/etc/letsencrypt/') and '/renewal-hooks/deploy/' not in path)
            self.assertNotIn('/var/log/', path)
            self.assertNotIn('/generations/', path)
            return original(files, path, **kwargs)
        with patch.object(HostFiles, 'read', new=read):
            self.assertEqual(self.check()['result'], SUCCESS)

    def test_report_redacts_local_identifiers_and_secrets(self):
        result = self.check()
        self.assertEqual(result['result'], SUCCESS, result)
        text = json.dumps(result)
        for value in (DOMAIN, TOKEN, str(self.host.root), STATE, self.fixture.before_keys.psk,
                      self.fixture.before_keys.shadowtls_password, self.tokens.check().revision):
            self.assertNotIn(value, text)

    def test_after_domain_change_does_not_assume_initial_domain_or_token(self):
        self.fixture.assert_success(self.fixture.change())
        self.host.calls.clear()
        self.assertEqual(self.check()['result'], SUCCESS)

    def test_completed_reinstall_preserves_history_and_supports_inventory(self):
        fixture = test_reinstall.ReinstallTests('test_preflight_read_only')
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.deploy()
        before = fixture.fixture.snapshot()
        original = fixture.prep.runner
        def runner(command):
            reply = self.unit_reply(command)
            return original(command) if reply is None else reply
        fixture.prep.runner = runner
        result = Maintenance(TokenChange(fixture.installation.public)).check()
        self.assertEqual(result['result'], SUCCESS, result)
        self.assertEqual(before, fixture.fixture.snapshot())

    def test_packages_different_from_install_record_report_review_without_repair(self):
        self.host.versions['certbot'] = '4.0.0-2+deb13u2'
        result = self.check()
        self.assertEqual(result['result'], REVIEW, result)
        self.assertEqual(result['findings'], ['package-version-drift'])
        item = next(p for p in result['packages'] if p['name'] == 'certbot')
        self.assertFalse(item['matches_record'])
        self.assertNotEqual(item['installed'], item['recorded'])

    def test_held_packages_are_observed_not_silently_upgradable(self):
        def reply(c):
            if c.argv == PACKAGE_QUERY:
                return Reply(0, ''.join(f'{n}\t{"hi " if n == "certbot" else "ii "}\t{v}\n'
                                        for n, v in self.host.versions.items()))
            return self.unit_reply(c)
        self.host.local_override = reply
        result = self.check()
        self.assertEqual(result['result'], REVIEW, result)
        self.assertEqual(result['findings'], ['held-packages-present'])

    def test_package_query_rejects_missing_duplicate_extra_and_malformed_rows(self):
        rows = [f'{n}\tii \t{v}\n' for n, v in self.host.versions.items()]
        cases = [rows[:-1], rows + rows[:1], rows[:-1] + rows[:1],
                 [rows[0].replace('ii ', 'iU '), *rows[1:]],
                 [rows[0].replace('1.2.3-1+deb13u1', 'PRIVATE\nsecret'), *rows[1:]]]
        for case in cases:
            with self.subTest(case=case):
                self.host.local_override = lambda c: Reply(0, ''.join(case)) if c.argv == PACKAGE_QUERY else self.unit_reply(c)
                self.blocked(self.check())

    def test_invalid_package_record_is_not_reported_as_installed_version(self):
        path = self.host.path(STATE + '/packages-ready.json')
        original = path.read_bytes()
        for value in ({'versions': {'nginx': TOKEN}}, {'versions': self.host.versions, 'extra': TOKEN}):
            with self.subTest(value=value):
                path.write_text(json.dumps(value))
                result = self.check()
                self.blocked(result)
                self.assertNotIn(TOKEN, json.dumps(result))
        path.write_bytes(original)

    def test_package_audit_text_never_returned(self):
        self.host.local_override = lambda c: Reply(0, 'PRIVATE ' + TOKEN) if c.argv == ('dpkg', '--audit') else self.unit_reply(c)
        report = self.check()
        self.assertEqual(report['result'], REVIEW, report)
        self.assertIn('dpkg-audit-needs-review', report['findings'])
        self.assertNotIn(TOKEN, json.dumps(report))

    def test_busy_or_altered_unit_reports_only_constant_summary(self):
        for value in ('ActiveState=activating', 'FragmentPath=/PRIVATE/' + TOKEN, 'NeedDaemonReload=yes'):
            with self.subTest(value=value):
                def reply(c):
                    result = self.unit_reply(c)
                    if result and c.argv[2] == 'certbot.service':
                        key = value.split('=')[0]
                        return Reply(0, '\n'.join(value if line.startswith(key + '=') else line
                                                  for line in result.output.splitlines()) + '\n')
                    return result
                self.host.local_override = reply
                result = self.check()
                self.assertEqual(result['result'], REVIEW, result)
                self.assertIn('service-state-needs-review', result['findings'])
                self.assertNotIn(TOKEN, json.dumps(result))

    def test_duplicate_missing_extra_unit_fields_block(self):
        for edit in (lambda t: t + 'LoadState=loaded\n', lambda t: '\n'.join(t.splitlines()[1:]),
                     lambda t: t + 'PRIVATE=' + TOKEN + '\n'):
            with self.subTest(edit=edit):
                def reply(c):
                    result = self.unit_reply(c)
                    return Reply(0, edit(result.output)) if result else None
                self.host.local_override = reply
                self.blocked(self.check(), 'unit-query-unrecognized')

    def test_changed_nginx_runtime_version_blocks_binding(self):
        self.host.local_override = lambda c: Reply(0, 'nginx version: nginx/1.30.0\n') if c.argv == ('nginx', '-v') else self.unit_reply(c)
        self.blocked(self.check(), 'deployment-version-binding-changed')

    def test_source_template_change_is_not_accepted_as_new_origin(self):
        path = self.host.path(STATE + '/debian.sources')
        path.write_bytes(path.read_bytes().replace(b'https://deb.debian.org', b'https://PRIVATE.invalid'))
        self.blocked(self.check(), 'dedicated-source-template-changed')

    def test_debian_keyring_and_release_aliases(self):
        path = self.host.path('/usr/share/keyrings/debian-archive-keyring.gpg')
        path.rename(path.with_suffix('.pgp'))
        path.symlink_to('debian-archive-keyring.pgp')
        release = self.host.path('/etc/os-release')
        self.host.write('/usr/lib/os-release', release.read_bytes(), 0o644)
        release.unlink()
        release.symlink_to('../usr/lib/os-release')
        self.assertEqual(self.check()['result'], SUCCESS)

    def test_unsupported_platform_and_arbitrary_release_alias_block(self):
        path = self.host.path('/etc/os-release')
        path.write_text('ID=debian\nVERSION_ID=12\n')
        self.blocked(self.check(), 'unsupported-platform')
        path.unlink()
        path.symlink_to('/PRIVATE/' + TOKEN)
        self.blocked(self.check(), 'platform-link-target')

    def test_pending_changes_missing_owner_and_lock_conflict_block(self):
        for name in ('reinstall-intent', 'uninstall-intent', 'token-change-intent', 'domain-change-intent',
                     'retired-cleanup-intent', 'key-rotation-intent', 'port-change-intent', 'uninstall-ready'):
            with self.subTest(name=name):
                self.prep._record(name, {'untrusted': TOKEN})
                self.blocked(self.check())
                self.host.path(STATE + '/' + name + '.json').unlink()
        with self.prep._lock():
            self.blocked(self.check())
        self.host.path(STATE + '/owner.json').unlink()
        self.blocked(self.check())

    def test_modified_managed_binary_or_config_blocks_without_execution(self):
        for path in (BINARIES[0], self.fixture.spec.nginx_conf, RENEW_DROPIN):
            with self.subTest(path=path):
                target = self.host.path(path)
                data = target.read_bytes()
                target.write_bytes(data + b'PRIVATE')
                self.blocked(self.check())
                target.write_bytes(data)

    def test_source_symlink_hardlink_fifo_and_permissions_rejected(self):
        target = self.host.path(STATE + '/debian.sources')
        data = target.read_bytes()
        for kind in ('symlink', 'hardlink', 'fifo', 'mode'):
            with self.subTest(kind=kind):
                target.unlink()
                if kind == 'symlink':
                    target.symlink_to('/PRIVATE')
                elif kind == 'hardlink':
                    other = self.host.path(STATE + '/extra-source')
                    self.host.write(STATE + '/extra-source', data)
                    os.link(other, target)
                elif kind == 'fifo':
                    os.mkfifo(target, 0o600)
                else:
                    self.host.write(STATE + '/debian.sources', data, 0o644)
                self.blocked(self.check())

    def test_package_change_between_observations_is_blocked(self):
        def progress(phase):
            if phase == 'unchanged-state-check':
                self.host.versions['certbot'] = '4.9.9-1'
        self.engine.progress = progress
        self.blocked(self.check(), 'packages-changed-during-check')

    def test_file_change_between_observations_is_blocked(self):
        def progress(phase):
            if phase == 'unchanged-state-check':
                self.host.path(STATE + '/debian.sources').touch()
        self.engine.progress = progress
        self.blocked(self.check())

    def test_review_unit_states_also_must_not_change_between_observations(self):
        count = 0
        def reply(c):
            nonlocal count
            result = self.unit_reply(c)
            if result and c.argv[2] == 'certbot.service':
                count += 1
                return Reply(0, result.output.replace('ActiveState=inactive', 'ActiveState=' + ('activating' if count == 1 else 'failed')))
            return result
        self.host.local_override = reply
        self.blocked(self.check(), 'services-changed-during-check')

    def test_command_failure_timeout_and_exception_are_redacted(self):
        for value in (Reply(1, TOKEN), Reply(-1, TOKEN, uncertain=True), RuntimeError(TOKEN)):
            with self.subTest(value=type(value)):
                def reply(c):
                    if c.argv == PACKAGE_QUERY:
                        if isinstance(value, Exception):
                            raise value
                        return value
                    return self.unit_reply(c)
                self.host.local_override = reply
                result = self.check()
                self.blocked(result)
                self.assertNotIn(TOKEN, json.dumps(result))

    def test_guard_rejects_mutation_and_unexpected_capture(self):
        with self.engine._commands():
            for command in (Command(('systemctl', 'restart', 'nginx.service')), Command(('apt-get', 'update')),
                            Command(('certbot', '--version')), Command(('nginx', '-T')),
                            Command(PACKAGE_QUERY, capture_stderr=True)):
                with self.subTest(argv=command.argv), self.assertRaises(PreparationError):
                    self.prep.runner(command)

    @contextmanager
    def factory(self):
        yield self.tokens

    def test_ui_confirm_cancel_noninteractive_and_secret_free_output(self):
        for answer in ('', 'n', 'yes', 'y', 'Y'):
            with self.subTest(answer=answer):
                ui = Console([answer])
                code = run_maintenance(factory=self.factory, terminal=ui)
                self.assertEqual(code, 0 if answer in {'y', 'Y'} else 130)
                self.assertNotIn(TOKEN, ui.text)
        factory = Mock(side_effect=AssertionError('not allowed'))
        ui = Console([])
        ui.interactive = lambda: False
        self.assertEqual(run_maintenance(factory=factory, terminal=ui), 2)
        factory.assert_not_called()

    def test_cli_routes_only_explicit_readonly_entry(self):
        with patch('snellctl.maintenance.run_maintenance', return_value=0) as run:
            self.assertEqual(main(['maintenance-plan']), 0)
            run.assert_called_once_with()
        for args in (['--yes'], ['--version', TOKEN], ['--experimental']):
            stderr = io.StringIO()
            with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
                main(['maintenance-plan', *args])
            self.assertEqual(raised.exception.code, 2)
            self.assertNotIn(TOKEN, stderr.getvalue())

    def test_cancel_and_interrupt_never_construct_real_adapter(self):
        factory = Mock(side_effect=AssertionError(TOKEN))
        for answer in ('n', '', EOFError(), KeyboardInterrupt()):
            with self.subTest(answer=type(answer)):
                self.assertEqual(run_maintenance(factory=factory, terminal=Console([answer])), 130)
        factory.assert_not_called()
        ui = Console(['y'])
        ui.interactive = Mock(side_effect=[True, False])
        self.assertEqual(run_maintenance(factory=factory, terminal=ui), 2)
        factory.assert_not_called()

    def test_factory_failure_is_redacted(self):
        ui = Console(['y'])
        self.assertEqual(run_maintenance(factory=Mock(side_effect=RuntimeError(TOKEN)), terminal=ui), 1)
        self.assertNotIn(TOKEN, ui.text)


if __name__ == '__main__':
    unittest.main()
