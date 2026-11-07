from contextlib import redirect_stderr
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from snellctl import aptreview as apt
from snellctl.__main__ import main
from snellctl.hostcommands import DebianCommands
from snellctl.hostprep import Command, HostFiles, PreparationError, Reply
from snellctl.packageplan import ALL_PACKAGES, PackagePlan, SUCCESS, package_rows, run_package_plan
from snellctl.preflight import DEPENDENCIES
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
import test_maintenance


WORKSPACE = apt.CACHE + '/' + 'a' * 32
ORIGIN = 'https://deb.debian.org/debian trixie/main amd64 Packages'


def simulate(changes):
    rows = [f'{sum(c[1] is not None for c in changes)} upgraded, '
            f'{sum(c[1] is None for c in changes)} newly installed, 0 to remove and 0 not upgraded.']
    for name, old, new in changes:
        rows.append(f'Inst {name}' + (f' [{old}]' if old else '') + f' ({new} Debian:13/stable [amd64])')
    for name, old, new in changes:
        rows.append(f'Conf {name} ({new} Debian:13/stable [amd64])')
    return '\n'.join(rows) + '\n'


class AptFormatTests(unittest.TestCase):
    def test_canonical_versions_support_epochs_and_debian_revisions(self):
        for version in ('1:2.3.4-5+deb13u10', '1.0~rc1-1', '20250419+deb13u1'):
            self.assertTrue(apt.version_ok(version))
        for version in ('latest', '../x', '1;id', '1\n2', '1_2', '-1', '1' * 101):
            self.assertFalse(apt.version_ok(version))

    def test_policy_requires_all_installed_and_unique_candidate_fields(self):
        versions = {n: '1.0-1' for n in DEPENDENCIES}
        output = ''.join(f'{n}:\n  Installed: 1.0-1\n  Candidate: 2.0-1\n  Version table:\n' for n in DEPENDENCIES)
        self.assertEqual(apt.candidates(output, versions), {n: '2.0-1' for n in DEPENDENCIES})
        for changed in (output + output, output.replace('Candidate: 2.0-1', 'Candidate: (none)', 1),
                        output.replace('Installed: 1.0-1', 'Installed: 0.9-1', 1),
                        output.replace('  Candidate: 2.0-1', '', 1), output + 'secret:\n',
                        output.replace('Candidate: 2.0-1', 'Candidate: 2.0-1\n  Candidate: 2.0-1', 1)):
            with self.subTest(changed=changed), self.assertRaises(PreparationError):
                apt.candidates(changed, versions)

    def test_origins_must_be_exact_known_https_debian_architecture_and_suite(self):
        self.assertEqual(apt.repository_versions(f'nginx | 2.0-1 | {ORIGIN}\n', ['nginx']), {'nginx': {'2.0-1'}})
        for output in (f'nginx | 2.0-1 | {ORIGIN.replace("https:", "http:")}',
                       f'nginx | 2.0-1 | {ORIGIN.replace("trixie", "sid")}',
                       f'nginx | 2.0-1 | {ORIGIN.replace("amd64", "arm64")}',
                       'nginx | 2.0-1 | /var/lib/dpkg/status', 'nginx | 2.0-1 | https://private.invalid',
                       f'other | 2.0-1 | {ORIGIN}', f'nginx | latest | {ORIGIN}'):
            with self.subTest(output=output), self.assertRaises(PreparationError):
                apt.repository_versions(output, ['nginx'])

    def test_simulation_requires_complete_matching_actions_and_summary(self):
        text = simulate([('nginx', '1.0-1', '2.0-1'), ('libnew', None, '1.0-1')])
        parsed = apt.simulation(text)
        self.assertEqual(len(parsed), 2)
        self.assertIsNone(parsed[1]['installed'])
        self.assertEqual(apt.simulation(simulate([])), [])
        for bad in (text.replace('1 upgraded', '2 upgraded'), text + 'Remv ssh [1.0-1]\n',
                    text.replace('Conf nginx', 'Conf unknown'), text + text,
                    text.replace(' [amd64]', ' [arm64]'), text.replace('Inst nginx', ' Inst nginx'),
                    text.replace('0 to remove', '1 to remove'), 'Inst nginx [1] (2)\n',
                    text.replace('Conf nginx (2.0-1', 'Conf nginx (3.0-1')):
            with self.subTest(text=bad), self.assertRaises(PreparationError):
                apt.simulation(bad)

    def test_package_database_rejects_duplicates_malformed_and_partial_states(self):
        row = 'nginx\tamd64\tii \t1.0-1\n'
        self.assertEqual(package_rows(row), {('nginx', 'amd64'): ('1.0-1', False)})
        self.assertTrue(package_rows(row.replace('ii ', 'hi '))[('nginx', 'amd64')][1])
        self.assertEqual(package_rows(row.replace('ii ', 'rc ')), {})
        for bad in ('', row + row, row.replace('ii ', 'iU '), row.replace('1.0-1', 'PRIVATE\nTOKEN')):
            with self.subTest(bad=bad), self.assertRaises(Exception):
                package_rows(bad)


class AptIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.files = HostFiles(self.root)
        self.addCleanup(self.files.close)
        apt.prepare(self.files, WORKSPACE)

    def command(self, args=('apt-get', 'update', '--error-on=any')):
        return apt.AptReviewCommand(args, 60, capture_stderr=True, workspace=WORKSPACE)

    def test_fresh_workspace_and_no_system_configuration_inheritance(self):
        command = self.command()
        command.verify_files(self.files)
        text = apt.configuration(WORKSPACE).decode()
        for value in ('APT::Sandbox::User "_apt"', 'Acquire::Check-Valid-Until "true"',
                      'Acquire::https::Verify-Peer "true"', 'Dir::State::status "/var/lib/dpkg/status"',
                      'Dir::Etc::parts "' + WORKSPACE + '/etc/parts"', 'Dir::Etc::main "' + WORKSPACE + '/etc/main"'):
            self.assertIn(value, text)
        with self.assertRaises(PreparationError):
            apt.prepare(self.files, WORKSPACE)
        self.assertEqual(self.files.info(WORKSPACE).st_mode & 0o777, 0o755)
        self.assertEqual(self.files.info(WORKSPACE + '/apt.conf').st_mode & 0o777, 0o644)

    def test_config_sources_and_empty_hook_directories_rechecked(self):
        for path in ('/apt.conf', '/etc/debian.sources', '/etc/main', '/etc/parts/evil.conf'):
            with self.subTest(path=path):
                file = self.root / (WORKSPACE + path).lstrip('/')
                old = file.read_bytes() if file.exists() else None
                file.write_bytes(b'DPkg::Pre-Invoke { "malicious"; };\n')
                file.chmod(0o644)
                with self.assertRaises(PreparationError):
                    self.command().verify_files(self.files)
                if old is None:
                    file.unlink()
                else:
                    file.write_bytes(old)

    def test_symlinked_configuration_rejected(self):
        path = self.root / (WORKSPACE + '/apt.conf').lstrip('/')
        path.unlink()
        path.symlink_to('/etc/apt/apt.conf')
        with self.assertRaises(OSError):
            self.command().verify_files(self.files)

    def test_command_gate_rejects_install_mutations_overrides_and_custom_paths(self):
        allowed = ('apt-get', '--simulate', '--no-remove', '--no-install-recommends', 'install',
                   *(n + '=1.0-1' for n in DEPENDENCIES))
        self.command(allowed).validate()
        self.command(('apt-cache', 'madison', 'nginx-common')).validate()
        for args in (('apt-get', 'install', 'nginx'), tuple(a for a in allowed if a != '--simulate'),
                     (*allowed, '-o', 'APT::Get::Simulate=false'), ('apt-get', 'upgrade'),
                     ('apt-get', 'update'), ('apt-cache', 'madison', '--config-file=private'),
                     ('apt-cache', 'policy', 'nginx'), ('dpkg', '--install', 'pkg.deb')):
            with self.subTest(args=args), self.assertRaises(PreparationError):
                self.command(args).validate()
        for altered in (replace(self.command(), workspace='/tmp/private'),
                        replace(self.command(), workspace=WORKSPACE + '/..'),
                        replace(self.command(), capture_stderr=False), replace(self.command(), timeout=601),
                        replace(self.command(), env=(('APT_CONFIG', '/evil'),))):
            with self.subTest(altered=altered), self.assertRaises(PreparationError):
                altered.validate()

    def test_real_adapter_uses_apt_config_before_process_start_and_sanitized_environment(self):
        real = subprocess.Popen
        def child(args, **kwargs):
            self.assertEqual(args, ['/usr/bin/apt-get', 'update', '--error-on=any'])
            self.assertEqual(kwargs['env']['APT_CONFIG'], WORKSPACE + '/apt.conf')
            self.assertNotIn('CF_Token', kwargs['env'])
            self.assertNotIn('http_proxy', kwargs['env'])
            return real([sys.executable, '-c', "import sys; print('synthetic error', file=sys.stderr)"], **kwargs)
        with patch.object(apt.AptReviewCommand, 'verify_files') as checked, \
             patch.dict(os.environ, {'CF_Token': TOKEN, 'http_proxy': 'PRIVATE', 'APT_CONFIG': '/evil'}), \
             patch('snellctl.hostcommands.subprocess.Popen', side_effect=child):
            result = object.__new__(DebianCommands)(self.command())
        checked.assert_called_once()
        self.assertEqual(result.output, 'synthetic error\n')
        self.assertNotIn('synthetic error', repr(result))


class PackagePlanTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_maintenance.MaintenanceTests('test_complete_inventory_not_update_or_health_authority')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.host, self.prep, self.tokens = self.fixture.host, self.fixture.prep, self.fixture.tokens
        self.selected = dict(self.host.versions)
        self.selected['nginx'] = '1.2.3-1+deb13u2'
        self.changes = [('nginx', self.host.versions['nginx'], self.selected['nginx'])]
        self.extra = []
        self.interceptor = None
        self.host.local_override = self.reply
        self.engine = PackagePlan(self.tokens)

    def reply(self, c):
        if self.interceptor:
            value = self.interceptor(c)
            if value is not None:
                return value
        args = c.argv
        if args == ALL_PACKAGES:
            return Reply(0, ''.join(f'{n}\tamd64\tii \t{v}\n' for n, v in self.host.versions.items()) + ''.join(self.extra))
        if args[:2] == ('dpkg', '--compare-versions'):
            return Reply(0 if args[2] > args[4] else 1)
        if isinstance(c, apt.AptReviewCommand):
            if args == ('apt-get', 'update', '--error-on=any'):
                return Reply(0, 'Fetched signed indexes.\n')
            if args[:2] == ('apt-cache', 'policy'):
                return Reply(0, ''.join(f'{n}:\n  Installed: {self.host.versions[n]}\n  Candidate: {v}\n' for n, v in self.selected.items()))
            if args[:2] == ('apt-cache', 'madison'):
                versions = {**self.selected, **{n: new for n, old, new in self.changes}}
                return Reply(0, ''.join(f'{n} | {versions[n]} | {ORIGIN}\n' for n in args[2:]))
            if '--simulate' in args:
                return Reply(0, simulate(self.changes))
            raise AssertionError('Unexpected APT command')
        return self.fixture.unit_reply(c)

    def check(self):
        return self.engine.check()

    def assert_blocked(self, report, phase=None):
        self.assertEqual(report['result'], 'blocked-no-upgrade', report)
        self.assertFalse(report['update_ready'])
        self.assertFalse(report['update_authorized'])
        self.assertFalse(report['packages_changed_by_this_operation'])
        self.assertNotIn('candidates', report)
        if phase:
            self.assertEqual(report['failure_phase'], phase, report)

    def test_success_only_writes_cache_and_does_not_claim_actual_update(self):
        before = self.fixture.fixture.snapshot()
        state = set(self.host.active), set(self.host.enabled), list(self.host.rules)
        report = self.check()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertTrue(report['host_changes_attempted'])
        self.assertTrue(report['apt_indexes_refreshed'])
        self.assertTrue(report['simulation_completed'])
        self.assertTrue(report['local_state_unchanged_verified'])
        self.assertFalse(report['update_ready'])
        self.assertEqual(report['security_patch_status'], 'not-assessed')
        after = self.fixture.fixture.snapshot()
        for path, contents in before.items():
            self.assertEqual(after[path], contents, path)
        self.assertTrue(all(path.startswith('var/cache/snellctl/package-review/')
                            or path in {'var/cache', 'var/cache/snellctl', 'var/cache/snellctl/package-review'}
                            for path in set(after) - set(before)))
        self.assertEqual(state, (self.host.active, self.host.enabled, self.host.rules))
        self.assertFalse(any(c.argv[0] == 'certbot' or c.argv[0] == 'ufw' or 'restart' in c.argv for c in self.host.calls))
        self.assertFalse(any(c.argv[0] == 'apt-get' and 'install' in c.argv and '--simulate' not in c.argv for c in self.host.calls))

    def test_no_newer_package_is_still_review_not_permission(self):
        self.selected = dict(self.host.versions)
        self.changes = []
        result = self.check()
        self.assertEqual(result['result'], SUCCESS, result)
        self.assertEqual(result['proposed_changes'], [])
        self.assertFalse(result['update_ready'])

    def test_new_and_updated_dependencies_are_listed_and_flagged(self):
        self.extra = ['nginx-common\tamd64\tii \t1.0-1\n']
        self.changes += [('nginx-common', '1.0-1', '2.0-1'), ('libnew', None, '1.0-1')]
        result = self.check()
        self.assertEqual(result['result'], SUCCESS, result)
        self.assertEqual(len(result['proposed_changes']), 3)
        self.assertTrue(result['additional_dependencies_require_review'])
        self.assertEqual(result['proposed_changes'][2]['direction'], 'install')

    def test_direct_drift_blocks_before_writing_or_network(self):
        self.host.versions['nginx'] = '1.2.3-1+deb13u9'
        result = self.check()
        self.assert_blocked(result, 'local-maintenance-check')
        self.assertFalse(result['host_changes_attempted'])
        self.assertIsNone(self.engine.workspace)

    def test_refresh_failure_or_uncertainty_does_not_query_stale_candidates(self):
        for reply in (Reply(100, TOKEN), Reply(-1, uncertain=True), Reply(0, 'W: partial indexes\n'),
                      Reply(0, 'N: Download is performed unsandboxed as root\n')):
            with self.subTest(reply=reply):
                self.host.calls.clear()
                self.interceptor = lambda c: reply if c.argv == ('apt-get', 'update', '--error-on=any') else None
                result = self.check()
                self.assert_blocked(result, 'signed-index-refresh')
                self.assertFalse(result['apt_indexes_refreshed'])
                self.assertNotIn(TOKEN, json.dumps(result))
                self.assertFalse(any(c.argv[:2] == ('apt-cache', 'policy') for c in self.host.calls))

    def test_candidate_must_be_available_from_official_indexes(self):
        self.interceptor = lambda c: Reply(0, '') if c.argv[:2] == ('apt-cache', 'madison') else None
        self.assert_blocked(self.check(), 'candidate-selection')

    def test_direct_and_dependency_downgrades_are_refused(self):
        self.selected['nginx'] = '1.2.3-1+deb13u0'
        self.assert_blocked(self.check(), 'candidate-selection')
        self.selected['nginx'] = '1.2.3-1+deb13u2'
        self.extra = ['libold\tamd64\tii \t2.0-1\n']
        self.changes += [('libold', '2.0-1', '1.0-1')]
        self.assert_blocked(self.check(), 'dependency-origin-and-hold-check')

    def test_versions_use_dpkg_order_not_lexical_or_three_part_order(self):
        old, new = '1:1.2.3-1+deb13u9', '1:1.2.3-1+deb13u10'
        with patch.object(self.prep, 'runner', return_value=Reply(0)) as run:
            self.assertEqual(self.engine._direction(old, new), 'upgrade')
            run.assert_called_once_with(Command(('dpkg', '--compare-versions', new, 'gt', old)))
        for reply in (Reply(2, TOKEN), Reply(0, TOKEN), Reply(-1, uncertain=True)):
            with patch.object(self.prep, 'runner', return_value=reply), self.assertRaises(Exception):
                self.engine._direction(old, new)

    def test_architecture_independent_package_change_is_supported(self):
        self.extra = ['python3-example\tall\tii \t1.0-1\n']
        self.changes += [('python3-example', '1.0-1', '2.0-1')]
        self.interceptor = lambda c: Reply(0, simulate(self.changes).replace('2.0-1 Debian:13/stable [amd64]',
                                                                          '2.0-1 Debian:13/stable [all]')) if '--simulate' in c.argv else None
        self.assertEqual(self.check()['result'], SUCCESS)

    def test_foreign_architecture_switch_is_not_silently_accepted(self):
        self.extra = ['libnew\tarm64\tii \t1.0-1\n']
        self.changes += [('libnew', None, '2.0-1')]
        self.assert_blocked(self.check(), 'dependency-origin-and-hold-check')

    def test_pending_management_operation_blocks_before_cache_creation(self):
        self.prep._record('token-change-intent', {'format': 1})
        report = self.check()
        self.assert_blocked(report, 'local-maintenance-check')
        self.assertFalse(report['host_changes_attempted'])

    def test_lock_conflict_blocks_without_refresh(self):
        with self.prep._lock():
            report = self.check()
        self.assert_blocked(report, 'local-maintenance-check')
        self.assertFalse(report['host_changes_attempted'])

    def test_partial_cache_creation_is_not_reported_as_no_changes(self):
        with patch('snellctl.packageplan.aptreview.prepare', side_effect=OSError('PRIVATE ' + TOKEN)):
            report = self.check()
        self.assert_blocked(report, 'isolated-cache-preparation')
        self.assertTrue(report['host_changes_attempted'])
        self.assertEqual(report['cache_state'], 'creation-attempted-may-be-partial')
        self.assertNotIn(TOKEN, json.dumps(report))

    def test_each_review_uses_new_workspace_not_previous_cached_indexes(self):
        first = self.check()
        path = self.engine.workspace
        second = self.check()
        self.assertEqual((first['result'], second['result']), (SUCCESS, SUCCESS))
        self.assertNotEqual(self.engine.workspace, path)

    def test_service_state_drift_after_simulation_blocks(self):
        original = self.fixture.unit_reply
        def intercept(c):
            if '--simulate' in c.argv:
                self.fixture.unit_reply = lambda cmd: Reply(0, original(cmd).output.replace('NeedDaemonReload=no', 'NeedDaemonReload=yes')) if original(cmd) else None
            return None
        self.interceptor = intercept
        self.assert_blocked(self.check(), 'unchanged-state-check')

    def test_held_dependencies_refused_without_unhold(self):
        self.extra = ['nginx-common\tamd64\thi \t1.0-1\n']
        self.changes += [('nginx-common', '1.0-1', '2.0-1')]
        self.assert_blocked(self.check(), 'dependency-origin-and-hold-check')

    def test_dependency_origin_checked_not_just_direct_targets(self):
        self.extra = ['nginx-common\tamd64\tii \t1.0-1\n']
        self.changes += [('nginx-common', '1.0-1', '2.0-1')]
        self.interceptor = lambda c: Reply(0, f'nginx-common | 2.0-1 | https://private.invalid\n') if c.argv == ('apt-cache', 'madison', 'nginx', 'nginx-common') else None
        self.assert_blocked(self.check(), 'dependency-origin-and-hold-check')

    def test_incomplete_or_failed_simulation_stops(self):
        for reply in (Reply(100, TOKEN), Reply(0, simulate([])), Reply(0, 'Remv nginx [1]\n')):
            with self.subTest(reply=reply):
                self.interceptor = lambda c: reply if '--simulate' in c.argv else None
                self.assert_blocked(self.check())

    def test_state_change_during_review_stops_without_repair(self):
        def intercept(c):
            if '--simulate' in c.argv:
                self.extra = ['newpkg\tamd64\tii \t1.0-1\n']
            return None
        self.interceptor = intercept
        self.assert_blocked(self.check(), 'unchanged-state-check')

    def test_interruption_keeps_cache_no_retry_or_cleanup(self):
        def intercept(c):
            if '--simulate' in c.argv:
                raise KeyboardInterrupt()
        self.interceptor = intercept
        result = self.check()
        self.assert_blocked(result, 'dependency-simulation')
        self.assertTrue(result['cache_retained'])
        self.assertTrue(self.host.path(self.engine.workspace).exists())
        self.assertFalse(result['automatic_retry'])

    def test_report_excludes_private_identifiers_and_tokens(self):
        report = self.check()
        self.assertEqual(report['result'], SUCCESS, report)
        for value in (DOMAIN, TOKEN, str(self.host.root), self.fixture.fixture.before_keys.psk,
                      self.fixture.fixture.before_keys.shadowtls_password, self.engine.workspace):
            self.assertNotIn(value, json.dumps(report))

    def test_no_token_certificate_or_log_reads(self):
        original = HostFiles.read
        def read(files, path, **kwargs):
            self.assertNotIn('/credentials/', path)
            self.assertFalse(path.startswith('/etc/letsencrypt/') and '/renewal-hooks/deploy/' not in path)
            self.assertFalse(path.startswith('/var/log/'))
            return original(files, path, **kwargs)
        with patch.object(HostFiles, 'read', new=read):
            self.assertEqual(self.check()['result'], SUCCESS)

    def test_guard_rejects_untyped_apt_commands_and_bad_compare(self):
        with self.engine._commands():
            for command in (Command(('apt-get', 'update')), Command(('dpkg', '--compare-versions', '1', 'gt', '2', 'x')),
                            Command(('systemctl', 'stop', 'nginx.service'))):
                with self.subTest(command=command), self.assertRaises(Exception):
                    self.prep.runner(command)


class PackagePlanCliTests(unittest.TestCase):
    def test_confirmation_gate_and_no_secrets_or_automatic_yes(self):
        factory = Mock(side_effect=AssertionError(TOKEN))
        for answer in ('n', '', EOFError(), KeyboardInterrupt()):
            self.assertEqual(run_package_plan(factory=factory, terminal=Console([answer])), 130)
        factory.assert_not_called()
        ui = Console([])
        ui.interactive = Mock(return_value=False)
        self.assertEqual(run_package_plan(factory=factory, terminal=ui), 2)
        factory.assert_not_called()
        ui = Console(['y'])
        self.assertEqual(run_package_plan(factory=factory, terminal=ui), 1)
        self.assertNotIn(TOKEN, ui.text)

    def test_cli_requires_experimental_and_has_no_upgrade_arguments(self):
        with patch('snellctl.packageplan.run_package_plan', return_value=0) as run, redirect_stderr(io.StringIO()):
            self.assertEqual(main(['package-update-plan']), 2)
            run.assert_not_called()
            self.assertEqual(main(['package-update-plan', '--experimental']), 0)
            run.assert_called_once_with()
        for option in ('--yes', '--install', '--token', '--target'):
            error = io.StringIO()
            with redirect_stderr(error), self.assertRaises(SystemExit):
                main(['package-update-plan', '--experimental', option, TOKEN])
            self.assertNotIn(TOKEN, error.getvalue())


if __name__ == '__main__':
    unittest.main()
