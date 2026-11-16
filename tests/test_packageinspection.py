from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import Mock, patch

from snellctl import aptreview
from snellctl.__main__ import main
from snellctl.hostprep import Command, PreparationError, Reply, STATE
from snellctl.packagecontents import ContentsCommand
from snellctl.packagedownload import CACHE, DownloadCommand, InstallSimulationCommand
from snellctl.packageinspection import PackageInspection, SUCCESS, NO_CHANGE, run_package_review, selected_changes
from snellctl.packageplan import ALL_PACKAGES
from snellctl.preflight import DEPENDENCIES
from test_installer import Console
from test_hostprep import DOMAIN, TOKEN
from test_packagereview import section
import test_packagedownload as download_tests


PRIVATE = 'LOCAL-ONLY-CONTROL-CONTENT'


class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = download_tests.DownloadTests('test_success_refreshes_before_download_and_never_installs_or_controls_services')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.prep, self.files, self.tokens, self.host = (self.fixture.prep, self.fixture.files,
                                                       self.fixture.tokens, self.fixture.host)
        self.engine = PackageInspection(self.tokens)
        self.job = self.fixture.job
        self.candidate_changes = self.job.changes
        self.fixture.interceptor = self.reply
        self.ui = Console(['y', 'y', 'y'])
        self.closed = False
        self.decisions, self.decline, self.intercept = [], None, None
        self.old_script = '#!/bin/sh\n# ' + PRIVATE + '\nexit 0\n'
        self.bad_scope = None
        ids = patch('snellctl.packageinspection.uuid.uuid4', side_effect=[Mock(hex='a' * 32), Mock(hex='b' * 32)])
        ids.start()
        self.addCleanup(ids.stop)

    @contextmanager
    def factory(self):
        try:
            yield self.tokens
        finally:
            self.closed = True

    def reply(self, command):
        if self.intercept:
            value = self.intercept(command)
            if value is not None:
                return value
        args = command.argv
        if type(command) is aptreview.AptReviewCommand:
            if args[:2] == ('apt-get', 'update'):
                return Reply(0)
            if args[:2] == ('apt-cache', 'policy'):
                return Reply(0, ''.join(f'{n}:\n  Installed: {self.host.versions[n]}\n  Candidate: {v}\n'
                                       for n, v in self.fixture.selected.items()))
            if args[:2] == ('apt-cache', 'madison'):
                versions = {**self.fixture.selected, **{c.name: c.after for c in self.candidate_changes}}
                return Reply(0, ''.join(f'{n} | {versions[n]} | {download_tests.ORIGIN}\n' for n in args[2:]))
            if '--simulate' in args:
                return Reply(0, download_tests.simulated(self.candidate_changes))
        if args[:2] == ('dpkg-query', '--control-list'):
            return Reply(0, 'list\npostinst\n')
        if args[:2] == ('dpkg-query', '--control-show'):
            return Reply(0, self.old_script if args[3] == 'postinst' else '/usr/bin/example\n')
        if type(command) is ContentsCommand:
            change = next(c for c in self.job.changes if args[2].endswith('/' + c.name + '_apt-cache-name.deb'))
            if args[1] == '--ctrl-tarfile':
                entries = [('control', download_tests.control(change).encode(), tarfile.REGTYPE),
                           ('postinst', b'#!/bin/sh\n# candidate\nexit 0\n', tarfile.REGTYPE)]
            else:
                entries = [('usr/bin/example', b'not executed', tarfile.REGTYPE)]
            return Reply(0, section(entries, args[1]))
        return None

    def decision(self, stage, changes):
        self.decisions.append(stage)
        self.assertEqual(changes, [dict(name=c.name, architecture=c.architecture, before=c.before, after=c.after)
                                   for c in self.job.changes])
        return stage != self.decline

    def run_inspection(self):
        return self.engine.inspect(consent=True, decision=self.decision)

    def assert_no_install_or_service_changes(self):
        self.assertIsNone(self.files.info(STATE + '/package-update-intent.json'))
        self.assertIsNone(self.files.info(self.job.directory))
        self.assertIsNone(self.files.info(self.job.unit_path))
        for c in self.fixture.calls:
            if c.argv[0] == 'apt-get':
                self.assertTrue(c.argv[1] == 'update' or '--simulate' in c.argv or '--download-only' in c.argv, c.argv)
            if c.argv[0] == 'systemctl':
                self.assertEqual(c.argv[1], 'show')
            self.assertNotIn(c.argv[0], ('certbot', 'ufw', 'iptables', 'ip6tables'))

    def test_complete_real_pipeline_collects_private_material_not_install_authority(self):
        before = self.fixture.fixture.fixture.snapshot()
        state = set(self.host.active), set(self.host.enabled), list(self.host.rules)
        report = self.run_inspection()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertEqual(self.decisions, ['download', 'save'])
        path = self.engine.material_path
        material = json.loads(self.files.read(path, mode=0o600, limit=8 * 1024**2))
        receipt = json.loads(self.files.read(str(Path(path).parent) + '/complete.json', mode=0o600))
        self.assertEqual(self.files.info(str(Path(path).parent)).st_mode & 0o777, 0o700)
        self.assertIn(PRIVATE, json.dumps(material))
        self.assertEqual(len(material['packages']), 2)
        self.assertFalse(receipt['update_authorized'])
        self.assertFalse(receipt['reusable_for_installation'])
        self.assertFalse(report['security_audit_passed'])
        self.assertNotIn(PRIVATE, json.dumps(report))
        self.assertNotIn(DOMAIN, json.dumps(report))
        self.assertNotIn(TOKEN, json.dumps(report))
        self.assertNotIn('/var/cache', json.dumps(report))
        after = self.fixture.fixture.fixture.snapshot()
        self.assertTrue(all(after[p] == value for p, value in before.items()))
        self.assertTrue(all(p.startswith('var/cache') for p in set(after) - set(before)))
        self.assertEqual(state, (self.host.active, self.host.enabled, self.host.rules))
        self.assert_no_install_or_service_changes()

    def test_no_changes_finishes_without_download_or_material_confirmation(self):
        self.fixture.selected = dict(self.host.versions)
        self.candidate_changes = ()
        report = self.run_inspection()
        self.assertEqual(report['result'], NO_CHANGE, report)
        self.assertEqual(self.decisions, [])
        self.assertFalse(report['download_attempted'])
        self.assertIsNone(self.files.info(download_tests.WORK))
        self.assert_no_install_or_service_changes()

    def test_initial_consent_required_before_queries_or_cache(self):
        with self.assertRaises(PreparationError):
            self.engine.inspect(decision=self.decision)
        self.assertEqual(self.fixture.calls, [])

    def test_declined_download_keeps_only_plan_cache(self):
        self.decline = 'download'
        report = self.run_inspection()
        self.assertEqual(report['result'], 'cancelled-before-download')
        self.assertTrue(report['host_changes_attempted'])
        self.assertFalse(report['download_attempted'])
        self.assertIsNone(self.files.info(download_tests.WORK))
        self.assert_no_install_or_service_changes()

    def test_declined_save_keeps_downloads_but_no_private_export(self):
        self.decline = 'save'
        report = self.run_inspection()
        self.assertEqual(report['result'], 'cancelled-before-material-save', report)
        self.assertTrue(report['download_attempted'])
        self.assertFalse(report['material_write_attempted'])
        self.assertIsNone(self.files.info(download_tests.WORK + '/review'))
        self.assert_no_install_or_service_changes()

    def test_truthy_confirmation_does_not_authorize(self):
        result = self.engine.inspect(consent=True, decision=lambda *args: 'y')
        self.assertEqual(result['result'], 'cancelled-before-download')
        self.assertFalse(result['download_attempted'])

    def test_plan_failure_hides_raw_output_and_never_downloads(self):
        self.intercept = lambda c: Reply(100, PRIVATE) if c.argv[:2] == ('apt-get', 'update') else None
        report = self.run_inspection()
        self.assertEqual(report['result'], 'stopped-no-upgrade')
        self.assertTrue(report['host_changes_attempted'])
        self.assertFalse(report['download_attempted'])
        self.assertNotIn(PRIVATE, json.dumps(report))
        self.assert_no_install_or_service_changes()

    def test_download_uncertainty_retains_cache_without_export(self):
        self.intercept = lambda c: Reply(-1, PRIVATE, uncertain=True) if '--download-only' in c.argv else None
        report = self.run_inspection()
        self.assertTrue(report['download_attempted'])
        self.assertFalse(report['material_saved_verified'])
        self.assertIsNone(self.files.info(download_tests.WORK + '/review'))
        self.assert_no_install_or_service_changes()

    def test_candidates_changing_before_download_do_not_use_old_plan(self):
        def decide(stage, changes):
            self.fixture.selected['nginx'] = '1.2.3-1+deb13u9'
            return True
        report = self.engine.inspect(consent=True, decision=decide)
        self.assertEqual(report['result'], 'stopped-no-upgrade')
        self.assertFalse(any('--download-only' in c.argv for c in self.fixture.calls))

    def test_control_script_drift_while_save_confirmation_is_pending_blocks_export(self):
        def decide(stage, changes):
            if stage == 'save':
                self.old_script += '# changed\n'
            return True
        report = self.engine.inspect(consent=True, decision=decide)
        self.assertFalse(report['material_write_attempted'])
        self.assert_no_install_or_service_changes()

    def test_eof_after_collection_does_not_save_or_install(self):
        def decide(stage, changes):
            if stage == 'save':
                raise EOFError(PRIVATE)
            return True
        report = self.engine.inspect(consent=True, decision=decide)
        self.assertEqual(report['result'], 'interrupted-no-upgrade')
        self.assertNotIn(PRIVATE, json.dumps(report))
        self.assertFalse(report['material_write_attempted'])
        self.assert_no_install_or_service_changes()

    def test_existing_review_directory_is_not_adopted(self):
        def decide(stage, changes):
            if stage == 'save':
                self.files.private_directory_new(download_tests.WORK + '/review')
            return True
        report = self.engine.inspect(consent=True, decision=decide)
        self.assertTrue(report['material_write_attempted'])
        self.assertFalse(report['material_saved_verified'])
        self.assertIsNone(self.files.info(download_tests.WORK + '/review/material.json'))

    def test_symlink_review_directory_is_not_followed(self):
        target = self.fixture.path('/unrelated')
        target.mkdir()
        def decide(stage, changes):
            if stage == 'save':
                self.fixture.path(download_tests.WORK + '/review').symlink_to(target)
            return True
        report = self.engine.inspect(consent=True, decision=decide)
        self.assertFalse(report['material_saved_verified'])
        self.assertEqual(list(target.iterdir()), [])

    def test_partial_material_write_is_not_complete_or_automatically_removed(self):
        write = self.files.write_new
        def partial(path, content, *args, **kwargs):
            if path.endswith('/review/material.json'):
                write(path, content[:20], *args, **kwargs)
                raise OSError(PRIVATE)
            return write(path, content, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=partial):
            report = self.run_inspection()
        self.assertTrue(report['material_write_attempted'])
        self.assertFalse(report['material_saved_verified'])
        self.assertIsNotNone(self.files.info(download_tests.WORK + '/review/material.json'))
        self.assertIsNone(self.files.info(download_tests.WORK + '/review/complete.json'))
        self.assertNotIn(PRIVATE, json.dumps(report))

    def test_receipt_write_failure_is_not_success(self):
        write = self.files.write_new
        def fail(path, content, *args, **kwargs):
            if path.endswith('/review/complete.json'):
                raise OSError(PRIVATE)
            return write(path, content, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=fail):
            report = self.run_inspection()
        self.assertFalse(report['material_saved_verified'])
        self.assertFalse(report['review_receipt_saved'])
        self.assertIsNotNone(self.files.info(download_tests.WORK + '/review/material.json'))

    def test_material_changed_after_write_prevents_receipt(self):
        write = self.files.write_new
        def change(path, content, *args, **kwargs):
            write(path, b'changed' if path.endswith('/review/material.json') else content, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=change):
            report = self.run_inspection()
        self.assertFalse(report['material_saved_verified'])
        self.assertIsNone(self.files.info(download_tests.WORK + '/review/complete.json'))

    def test_guard_rejects_mutation_and_untyped_archive_commands_before_dispatch(self):
        self.engine.job = self.job
        forbidden = [('systemctl', 'start', 'nginx.service'), ('ufw', 'allow', '443/tcp'),
                     ('certbot', 'renew'), ('dpkg', '--configure', '-a'), ('apt-get', 'upgrade'),
                     ('apt-get', 'install', 'nginx'), ('dpkg-deb', '--ctrl-tarfile', '/tmp/file.deb'),
                     ('dpkg-query', '--control-show', 'sshd', 'postinst'),
                     ('dpkg-query', '--control-show', 'nginx', '../../secret')]
        with self.engine._commands():
            for args in forbidden:
                with self.subTest(args=args), self.assertRaises(PreparationError):
                    self.prep.runner(Command(args))
            with self.assertRaises(PreparationError):
                self.prep.runner(InstallSimulationCommand(self.job.install_argv(simulate=True), job=self.job))
        self.assertEqual(self.fixture.calls, [])

    def test_guard_rejects_foreign_workspaces_pins_and_environment(self):
        self.engine.job = self.job
        base = DownloadCommand(('apt-get', 'update', '--error-on=any'), capture_stderr=True,
                               workspace=download_tests.WORK, pins=tuple(c.name + '=' + c.after for c in self.job.changes))
        with self.engine._commands():
            for command in (replace(base, workspace=CACHE + '/' + 'c' * 32), replace(base, pins=('certbot=1.0-2',)),
                            replace(base, env=(('HOME', '/tmp'),)), replace(base, timeout=True)):
                with self.assertRaises(PreparationError):
                    self.prep.runner(command)
        self.assertEqual(self.fixture.calls, [])

    def test_runner_is_restored_after_failure(self):
        original = self.prep.runner
        self.intercept = lambda c: Reply(100) if c.argv[:2] == ('apt-get', 'update') else None
        self.run_inspection()
        self.assertIs(self.prep.runner, original)

    def test_source_refresh_failure_retains_its_actual_phase(self):
        self.intercept = lambda c: Reply(100) if c.argv[:2] == ('apt-get', 'update') else None
        result = self.run_inspection()
        self.assertEqual(result['phase'], 'signed-index-refresh')

    def test_material_world_readable_write_cannot_be_marked_complete(self):
        write = self.files.write_new
        def changed(path, content, *args, **kwargs):
            write(path, content, *args, **kwargs)
            if path.endswith('/review/material.json'):
                self.fixture.path(path).chmod(0o644)
        with patch.object(self.files, 'write_new', side_effect=changed):
            report = self.run_inspection()
        self.assertFalse(report['material_saved_verified'])
        self.assertIsNone(self.files.info(download_tests.WORK + '/review/complete.json'))

    def test_changed_receipt_is_not_a_verified_export(self):
        write = self.files.write_new
        def changed(path, content, *args, **kwargs):
            write(path, b'changed' if path.endswith('/review/complete.json') else content, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=changed):
            report = self.run_inspection()
        self.assertFalse(report['material_saved_verified'])
        self.assertFalse(report['review_receipt_saved'])

    def test_interrupt_during_write_retains_partial_without_completion_claim(self):
        write = self.files.write_new
        def interrupted(path, content, *args, **kwargs):
            if path.endswith('/review/material.json'):
                write(path, content[:20], *args, **kwargs)
                raise KeyboardInterrupt
            return write(path, content, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=interrupted):
            report = self.run_inspection()
        self.assertEqual(report['result'], 'interrupted-no-upgrade')
        self.assertFalse(report['material_saved_verified'])
        self.assert_no_install_or_service_changes()

    def test_new_pending_operation_during_confirmation_prevents_private_write(self):
        def decide(stage, changes):
            if stage == 'save':
                self.prep._record('port-change-intent', {})
            return True
        report = self.engine.inspect(consent=True, decision=decide)
        self.assertFalse(report['material_write_attempted'])

    def test_reading_credentials_and_certificate_material_is_not_part_of_review(self):
        read = self.files.read
        def checked(path, *args, **kwargs):
            self.assertFalse(path.startswith(('/etc/snellctl/credentials/', '/etc/letsencrypt/live/',
                                               '/etc/letsencrypt/archive/')), path)
            return read(path, *args, **kwargs)
        with patch.object(self.files, 'read', side_effect=checked):
            report = self.run_inspection()
        self.assertEqual(report['result'], SUCCESS, report)

    def test_local_script_controls_are_not_echoed_by_terminal(self):
        self.old_script += '# \x1b[2J\r' + PRIVATE + '\n'
        self.assertEqual(run_package_review(factory=self.factory, terminal=self.ui), 0)
        self.assertNotIn('\x1b', self.ui.text)
        self.assertNotIn(PRIVATE, self.ui.text)
        data = self.files.read(download_tests.WORK + '/review/material.json', mode=0o600, limit=8 * 1024**2)
        self.assertIn(b'\\u001b', data)

    def test_interactive_no_change_needs_only_initial_confirmation(self):
        self.fixture.selected = dict(self.host.versions)
        self.candidate_changes = ()
        self.ui = Console(['y'])
        self.assertEqual(run_package_review(factory=self.factory, terminal=self.ui), 0, self.ui.text)
        self.assertEqual(len(self.ui.prompts), 1)
        self.assertNotIn('/review/material.json', self.ui.text)

    def test_interactive_save_cancel_has_no_material_and_returns_cancel_code(self):
        self.ui = Console(['y', 'y', ''])
        self.assertEqual(run_package_review(factory=self.factory, terminal=self.ui), 130, self.ui.text)
        self.assertIsNone(self.files.info(download_tests.WORK + '/review'))
        self.assertNotIn(PRIVATE, self.ui.text)

    def test_late_terminal_loss_never_saves_or_changes_services(self):
        self.ui.interactive = Mock(side_effect=[True, True, True, False])
        self.assertEqual(run_package_review(factory=self.factory, terminal=self.ui), 130, self.ui.text)
        self.assertIsNone(self.files.info(download_tests.WORK + '/review'))
        self.assert_no_install_or_service_changes()

    def test_pending_operation_blocks_before_network(self):
        self.prep._record('package-update-intent', {})
        result = self.run_inspection()
        self.assertFalse(result['host_changes_attempted'])
        self.assertFalse(any(c.argv[0] == 'apt-get' for c in self.fixture.calls))

    def test_actual_interactive_entry_has_separate_y_n_prompts_no_raw_material(self):
        self.assertEqual(run_package_review(factory=self.factory, terminal=self.ui), 0, self.ui.text)
        self.assertEqual(len(self.ui.prompts), 3)
        self.assertTrue(all('[y/n]' in p for p in self.ui.prompts))
        self.assertNotIn(PRIVATE, self.ui.text)
        self.assertIn('/review/material.json', self.ui.text)
        self.ui.secret.assert_not_called()
        self.assertTrue(self.closed)
        self.assert_no_install_or_service_changes()


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = InspectionTests('test_complete_real_pipeline_collects_private_material_not_install_authority')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.prep = self.fixture.prep
        self.report = self.fixture.engine.plan.check()

    def test_fresh_scope_is_revalidated_against_current_database(self):
        self.assertEqual(selected_changes(self.report, self.prep), self.fixture.job.changes)
        self.fixture.host.versions['nginx'] = '1.2.3-1+deb13u5'
        with self.assertRaises(PreparationError):
            selected_changes(self.report, self.prep)

    def test_unsupported_new_dependency_or_upstream_change_rejected(self):
        for change in ({'name': 'libnew', 'architecture': 'amd64', 'installed': None, 'candidate': '1.0-1',
                        'direction': 'install', 'role': 'dependency'},
                       {'name': 'nginx', 'architecture': 'amd64', 'installed': self.fixture.job.changes[0].before,
                        'candidate': '9.0-1', 'direction': 'upgrade', 'role': 'direct'}):
            bad = {**self.report, 'proposed_changes': [change]}
            with self.assertRaises(PreparationError):
                selected_changes(bad, self.prep)

    def test_incomplete_directions_duplicate_candidates_and_forged_flags_rejected(self):
        for key, value in [('result', 'failed'), ('apt_indexes_refreshed', False), ('simulation_completed', 1),
                           ('proposed_changes', []), ('candidates', self.report['candidates'] * 2)]:
            with self.subTest(key=key), self.assertRaises(PreparationError):
                selected_changes({**self.report, key: value}, self.prep)
        bad = json.loads(json.dumps(self.report))
        bad['proposed_changes'][0]['direction'] = 'downgrade'
        with self.assertRaises(PreparationError):
            selected_changes(bad, self.prep)


class EntryTests(unittest.TestCase):
    def test_help_explains_no_installation_without_opening_host(self):
        with patch('snellctl.packageinspection.run_package_review') as run, redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as result:
                main(['package-update-review', '--help'])
        self.assertEqual(result.exception.code, 0)
        run.assert_not_called()
        self.assertIn('--experimental', out.getvalue())
        self.assertIn('不安装、不停止服务', out.getvalue())

    def test_missing_flag_does_not_construct_engine(self):
        with patch('snellctl.packageinspection.run_package_review') as run, redirect_stderr(io.StringIO()):
            self.assertEqual(main(['package-update-review']), 2)
        run.assert_not_called()

    def test_flag_routes_only_to_material_command(self):
        with patch('snellctl.packageinspection.run_package_review', return_value=0) as run:
            self.assertEqual(main(['package-update-review', '--experimental']), 0)
        run.assert_called_once_with()

    def test_unknown_args_do_not_echo_secrets_or_accept_plan_imports(self):
        for args in (['--yes'], ['--execute'], ['--plan', PRIVATE], ['--output', '/tmp/material'], ['--token', PRIVATE]):
            with redirect_stderr(io.StringIO()) as out, self.assertRaises(SystemExit):
                main(['package-update-review', '--experimental', *args])
            self.assertNotIn(PRIVATE, out.getvalue())

    def test_no_generic_upgrade_command_is_exposed(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(['upgrade', '--experimental'])

    def test_noninteractive_refuses_before_factory_or_queries(self):
        ui, factory = Console(), Mock()
        ui.interactive = lambda: False
        self.assertEqual(run_package_review(factory=factory, terminal=ui), 2)
        factory.assert_not_called()
        self.assertEqual(ui.prompts, [])

    def test_default_no_and_non_y_replies_never_open_host(self):
        for answer in ('', 'n', 'yes', '\u662f'):
            factory = Mock()
            self.assertEqual(run_package_review(factory=factory, terminal=Console([answer])), 130)
            factory.assert_not_called()

    def test_lost_tty_after_initial_confirmation_does_not_open_host(self):
        ui, factory = Console(['y']), Mock()
        ui.interactive = Mock(side_effect=[True, False])
        self.assertEqual(run_package_review(factory=factory, terminal=ui), 2)
        factory.assert_not_called()

    def test_factory_failure_is_redacted(self):
        ui = Console(['y'])
        self.assertEqual(run_package_review(factory=Mock(side_effect=RuntimeError(PRIVATE)), terminal=ui), 1)
        self.assertNotIn(PRIVATE, ui.text)


if __name__ == '__main__':
    unittest.main()
