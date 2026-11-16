from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import os
import tarfile
import unittest
from unittest.mock import Mock, patch

from snellctl import aptreview
from snellctl.__main__ import main
from snellctl.hostprep import Reply
from snellctl.packagecontents import ContentsCommand
from snellctl.packagedownload import ArchiveCommand, DownloadCommand, DOWNLOAD
from snellctl.packageupdate import PackageUpdate, run_package_update, SUCCESS, NO_CHANGE
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
from test_packagedownload import ORIGIN, control, record, simulated
from test_packagereview import section
import test_packageflow
import test_maintenance


PRIVATE = 'PRIVATE-LOCAL-SCRIPT'


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_packageflow.FlowTests('test_complete_flow_submits_once_then_restores_without_external_success_claim')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.prep, self.files, self.host, self.tokens = (self.fixture.prep, self.fixture.files,
                                                       self.fixture.host, self.fixture.tokens)
        self.job = replace(self.fixture.job, job_id='c' * 32)
        self.fixture.job = self.fixture.sub.job = self.job
        self.fixture.auto_complete = True
        self.changes = self.job.changes
        self.payload = b'synthetic new deb'
        self.script = '#!/bin/sh\n# ' + PRIVATE + '\nexit 0\n'
        self.effect = None
        self.fixture.fixture.effect = self.reply
        self.ui = Console(['y'] * 8)
        self.engine = PackageUpdate(self.tokens, self.ui)
        self.engine.flow.guards = self.fixture.flow.guards
        self.engine.flow.guards.progress = self.engine.flow._phase
        self.ids = patch('snellctl.packageupdate.uuid.uuid4', side_effect=[Mock(hex='d' * 32), Mock(hex='c' * 32)])
        self.ids.start()
        self.addCleanup(self.ids.stop)
        self.host.calls.clear()

    def reply(self, command):
        if self.effect:
            value = self.effect(command)
            if value is not None:
                return value
        self.fixture.reply(command)
        units = test_maintenance.MaintenanceTests.unit_reply(self, command)
        if units is not None:
            return units
        args = command.argv
        if type(command) is ContentsCommand:
            if args[1] == '--ctrl-tarfile':
                entries = [('control', control(self.job.changes[0]).encode(), tarfile.REGTYPE),
                           ('postinst', b'#!/bin/sh\nexit 0\n', tarfile.REGTYPE)]
            else:
                entries = [('usr/bin/certbot', b'not executed', tarfile.REGTYPE)]
            return Reply(0, section(entries, args[1]))
        if args[:2] == ('dpkg-query', '--control-list'):
            return Reply(0, 'list\npostinst\n')
        if args[:2] == ('dpkg-query', '--control-show'):
            return Reply(0, self.script if args[-1] == 'postinst' else '/usr/bin/certbot\n')
        if type(command) is ArchiveCommand:
            return Reply(0, control(self.job.changes[0]))
        if type(command) not in {DownloadCommand, aptreview.AptReviewCommand}:
            return None
        work = command.workspace
        if args[:2] == ('apt-get', 'update'):
            self.files.write_new(work + '/lists/test_InRelease', b'synthetic index', mode=0o644)
            return Reply(0)
        versions = {**self.host.versions, **{c.name: c.after for c in self.changes}}
        if args[:2] == ('apt-cache', 'policy'):
            return Reply(0, ''.join(f'{n}:\n  Installed: {self.host.versions[n]}\n  Candidate: {versions[n]}\n'
                                   for n in args[2:]))
        if args[:2] == ('apt-cache', 'madison'):
            return Reply(0, ''.join(f'{n} | {versions[n]} | {ORIGIN}\n' for n in args[2:]))
        if args[:3] == ('apt-cache', '--no-all-versions', 'show'):
            return Reply(0, record(self.job.changes[0], self.payload))
        if '--simulate' in args:
            return Reply(0, simulated(self.changes))
        if args[:len(DOWNLOAD)] == DOWNLOAD:
            self.files.write_new(work + '/cache/archives/certbot.deb', self.payload, mode=0o644)
            return Reply(0)
        self.fail('unexpected simulated command')

    def run_update(self):
        return self.engine.run(consent=True)

    def no_maintenance(self, report):
        self.assertFalse(report['maintenance_attempted'], report)
        self.assertFalse(report['installation_submit_attempted'], report)
        self.assertEqual(self.fixture.mutations(), [])
        self.assertFalse(self.prep._exists('package-update-intent'))

    def test_submission_result_interrupt_retains_evidence_without_restoring(self):
        original = self.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/submission-result.json'):
                raise KeyboardInterrupt
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=write):
            report = self.run_update()
        self.assertEqual(report['result'], 'interrupted-inspection-required')
        submission = report['flow']['submission']
        self.assertTrue(submission['submission_attempted'])
        self.assertTrue(submission['submission_acknowledged'])
        self.assertFalse(submission['report_saved'])
        self.assertNotIn('postinstall', report['flow'])
        self.assertEqual(sum(c.argv == ('systemctl', 'start', '--no-block', self.job.unit)
                             for c in self.host.calls), 1)
        self.assertNotIn(('systemctl', 'start', 'nginx.service'), self.fixture.mutations())

    def test_postinstall_result_interrupt_retains_completion_in_update_report(self):
        original = self.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/postinstall-result.json'):
                raise KeyboardInterrupt
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=write):
            report = self.run_update()
        self.assertEqual(report['result'], 'interrupted-inspection-required')
        postinstall = report['flow']['postinstall']
        self.assertTrue(postinstall['completion_recorded'])
        self.assertTrue(postinstall['intent_removed_verified'])
        self.assertFalse(postinstall['report_saved'])
        self.assertFalse(report['upgrade_completed'])
        self.assertEqual(self.fixture.mutations().count(('systemctl', 'start', 'nginx.service')), 1)

    def test_real_plan_download_material_guard_submit_and_restore_share_one_batch(self):
        report = self.run_update()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertTrue(report['material_saved_verified'])
        self.assertTrue(report['operator_review_confirmed'])
        self.assertFalse(report['security_audit_passed'])
        self.assertFalse(report['upgrade_completed'])
        self.assertEqual(len(self.ui.prompts), 8)
        self.assertEqual(sum(c.argv[:len(DOWNLOAD)] == DOWNLOAD for c in self.host.calls), 1)
        self.assertEqual(self.fixture.mutations().count(('systemctl', 'start', '--no-block', self.job.unit)), 1)
        self.assertFalse(self.prep._exists('package-update-intent'))
        self.assertIn(PRIVATE, self.files.read(self.engine.saved.path).decode())
        text = json.dumps(report) + self.ui.text
        for secret in (PRIVATE, TOKEN, DOMAIN, '#!/bin/sh'):
            self.assertNotIn(secret, text)
        self.ui.secret.assert_not_called()

    def test_no_updates_never_downloads_saves_prompts_or_stops_services(self):
        self.changes = ()
        report = self.run_update()
        self.assertEqual(report['result'], NO_CHANGE, report)
        self.no_maintenance(report)
        self.assertIsNone(self.engine.saved)
        self.assertIsNone(self.engine.job)
        self.assertEqual(self.ui.prompts, [])
        self.assertFalse(any('--download-only' in c.argv for c in self.host.calls))

    def decline(self, index):
        self.ui.answers = iter(['y'] * index + ['n'])
        return self.run_update()

    def test_download_declined(self):
        report = self.decline(0)
        self.assertEqual(report['result'], 'cancelled-before-download')
        self.no_maintenance(report)

    def test_material_save_declined(self):
        report = self.decline(1)
        self.assertEqual(report['result'], 'review-not-approved-cache-preserved')
        self.assertFalse(report['material_write_attempted'])
        self.no_maintenance(report)

    def test_independent_review_declined(self):
        report = self.decline(2)
        self.assertTrue(report['material_saved_verified'])
        self.assertFalse(report['operator_review_confirmed'])
        self.no_maintenance(report)

    def test_outage_declined(self):
        self.no_maintenance(self.decline(3))

    def test_install_declined(self):
        self.no_maintenance(self.decline(4))

    def restoration_declined(self, index):
        report = self.decline(index)
        self.assertEqual(report['result'], 'restoration-not-authorized-inspection-required', report)
        self.assertTrue(report['installation_submit_attempted'])
        self.assertNotIn(('systemctl', 'start', 'nginx.service'), self.fixture.mutations())
        self.assertTrue(self.prep._exists('package-update-intent'))

    def test_restore_declined(self):
        self.restoration_declined(5)

    def test_dns_declined_before_restoration(self):
        self.restoration_declined(6)

    def test_renewal_declined_before_restoration(self):
        self.restoration_declined(7)

    def alter_on_install(self, effect):
        original = self.ui.ask
        def ask(question):
            if len(self.ui.prompts) == 4:
                effect()
            return original(question)
        self.ui.ask = ask

    def test_material_changed_after_review_stops_before_maintenance(self):
        self.alter_on_install(lambda: self.host.path(self.engine.saved.path).write_bytes(b'changed'))
        self.no_maintenance(self.run_update())

    def test_saved_material_permission_change_is_not_accepted(self):
        self.alter_on_install(lambda: self.host.path(self.engine.saved.path).chmod(0o644))
        self.no_maintenance(self.run_update())

    def test_receipt_changed_after_review_is_not_accepted(self):
        self.alter_on_install(lambda: self.host.path(self.engine.saved.path.replace('material.json', 'complete.json')).write_bytes(b'{}'))
        self.no_maintenance(self.run_update())

    def test_file_replacement_with_same_bytes_is_not_accepted(self):
        def replace_file():
            path = self.host.path(self.engine.saved.path)
            data = path.read_bytes()
            os.rename(path, str(path) + '.old')
            path.write_bytes(data)
            path.chmod(0o600)
        self.alter_on_install(replace_file)
        self.no_maintenance(self.run_update())

    def test_material_drift_inside_guard_stops_before_submission(self):
        def effect(command):
            if command.argv == ('systemctl', 'stop', 'nginx.service'):
                self.host.path(self.engine.saved.path).write_bytes(b'changed after stop')
        self.effect = effect
        report = self.run_update()
        self.assertTrue(report['maintenance_attempted'], report)
        self.assertFalse(report['installation_submit_attempted'])
        self.assertTrue(self.prep._exists('package-update-intent'))
        self.assertNotIn(('systemctl', 'start', '--no-block', self.job.unit), self.fixture.mutations())

    def test_material_directory_permissions_rechecked_after_review(self):
        self.alter_on_install(lambda: self.host.path(self.engine.saved.path).parent.chmod(0o755))
        self.no_maintenance(self.run_update())

    def test_material_symlink_cannot_be_read_as_approved(self):
        def change():
            target = self.host.path(self.engine.saved.path)
            target.rename(str(target) + '.old')
            target.symlink_to(str(target) + '.old')
        self.alter_on_install(change)
        self.no_maintenance(self.run_update())

    def test_original_control_script_drift_after_review_blocks_maintenance(self):
        self.alter_on_install(lambda: setattr(self, 'script', self.script + '# new change\n'))
        self.no_maintenance(self.run_update())

    def test_eof_after_background_install_never_retries_or_restores(self):
        self.ui.answers = iter(['y'] * 5 + [EOFError(PRIVATE)])
        report = self.run_update()
        self.assertEqual(report['result'], 'interrupted-inspection-required', report)
        self.assertEqual(self.fixture.mutations().count(('systemctl', 'start', '--no-block', self.job.unit)), 1)
        self.assertNotIn(('systemctl', 'start', 'nginx.service'), self.fixture.mutations())
        self.assertNotIn(PRIVATE, json.dumps(report))

    def test_terminal_loss_after_install_confirmation_stops_before_outage(self):
        self.alter_on_install(lambda: setattr(self.ui, 'interactive', lambda: False))
        self.no_maintenance(self.run_update())

    def test_initial_plan_failure_never_reaches_download_or_review(self):
        self.effect = lambda c: Reply(1, PRIVATE) if c.argv[:2] == ('apt-get', 'update') else None
        report = self.run_update()
        self.no_maintenance(report)
        self.assertIsNone(self.engine.job)
        self.assertNotIn(PRIVATE, json.dumps(report))

    def test_cli_adapter_no_change_path(self):
        self.changes = ()
        self.ui.answers = iter(['y'])
        @contextmanager
        def factory():
            yield self.tokens
        self.assertEqual(run_package_update(factory=factory, terminal=self.ui), 0, self.ui.text)
        self.assertIn(NO_CHANGE, self.ui.text)
        self.assertEqual(self.fixture.mutations(), [])


class EntryTests(unittest.TestCase):
    def test_gate_requires_opt_in_before_any_factory(self):
        with patch('snellctl.packageupdate.run_package_update', return_value=0) as run, redirect_stderr(io.StringIO()):
            self.assertEqual(main(['package-update']), 2)
            run.assert_not_called()
            self.assertEqual(main(['package-update', '--experimental']), 0)
            run.assert_called_once_with()

    def test_initial_default_no_and_noninteractive_never_open_host(self):
        factory = Mock()
        for answer in ('', 'n', 'yes', 'YEAH', 'y y'):
            self.assertEqual(run_package_update(factory=factory, terminal=Console([answer])), 130)
        ui = Console([])
        ui.interactive = lambda: False
        self.assertEqual(run_package_update(factory=factory, terminal=ui), 2)
        factory.assert_not_called()

    def test_unknown_flags_and_values_are_rejected_without_echo(self):
        for args in (['--yes'], ['--version', PRIVATE], ['--plan', PRIVATE], ['--job-id', PRIVATE], [PRIVATE]):
            with redirect_stderr(io.StringIO()) as out, self.assertRaises(SystemExit):
                main(['package-update', '--experimental', *args])
            self.assertNotIn(PRIVATE, out.getvalue())

    def test_help_does_not_enter_update(self):
        with patch('snellctl.packageupdate.run_package_update') as run, redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            main(['package-update', '--help'])
        run.assert_not_called()

    def test_factory_errors_are_redacted(self):
        ui = Console(['y'])
        self.assertEqual(run_package_update(factory=Mock(side_effect=RuntimeError(PRIVATE)), terminal=ui), 1)
        self.assertNotIn(PRIVATE, ui.text)
        self.assertIn('package-update-status', ui.text)


if __name__ == '__main__':
    unittest.main()
