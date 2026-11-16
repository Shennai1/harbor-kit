from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import unittest
from unittest.mock import Mock, patch

from snellctl import packagebaseline as baseline
from snellctl.__main__ import main
from snellctl.client import read_client
from snellctl.hostprep import POLICY, STATE, PreparationError, Reply
from snellctl.packageflow import PackageFlow, RESTORE_PREFIXES
from snellctl.packageresume import run_package_resume
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
from test_packagejob import status
import test_packageflow


SUCCESS = 'packages-restored-external-test-required'
PRIVATE = 'PRIVATE-RESUME-ERROR'


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_packageflow.FlowTests('test_reconnect_restores_without_new_download_install_or_old_lease')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.prep, self.files, self.host, self.tokens, self.job = (
            self.fixture.prep, self.fixture.files, self.fixture.host, self.fixture.tokens, self.fixture.job)
        self.keys = read_client(root=self.host.root).keys
        self.fixture.prepare()
        self.marker = self.job.directory + '/restoration-resume-intent.json'
        self.intent = STATE + '/package-update-intent.json'

    def adapter(self, answers=None):
        ui = answers if isinstance(answers, Console) else Console(['y'] * 5 if answers is None else answers)
        @contextmanager
        def factory():
            yield self.tokens
        code = run_package_resume(factory=factory, terminal=ui)
        reports = [json.loads(m) for m in ui.messages if m.startswith('{')]
        return code, ui, reports[-1] if reports else None

    def assert_no_attempt(self, report):
        self.assertFalse(report['host_changes_attempted'], report)
        self.assertFalse(report['installation_submission_attempted'])
        self.assertFalse(report['report_saved'])
        self.assertFalse(report['upgrade_completed'])
        self.assertIsNone(self.files.info(self.marker))
        self.assertEqual(self.fixture.mutations(), [])
        self.assertIsNotNone(self.files.info(POLICY))

    def test_successful_adapter_reuses_original_task_and_preserves_keys(self):
        keys = self.keys
        original_read = self.files.read
        def read(path, **kwargs):
            self.assertFalse(path.endswith('apt.log'))
            return original_read(path, **kwargs)
        with patch.object(self.files, 'read', side_effect=read):
            code, ui, report = self.adapter()
        self.assertEqual(code, 0, report)
        self.assertEqual(report['result'], SUCCESS)
        self.assertTrue(report['report_saved'])
        self.assertTrue(report['external_acceptance_required'])
        self.assertFalse(report['upgrade_completed'])
        self.assertFalse(report['installation_submission_attempted'])
        self.assertEqual(len(ui.prompts), 5)
        self.assertEqual(read_client(root=self.host.root).keys, keys)
        self.assertFalse(self.prep._exists('package-update-intent'))
        self.assertEqual(self.fixture.mutations().count(('systemctl', 'start', 'nginx.service')), 1)
        for c in self.host.calls:
            self.assertNotIn(c.argv[0], {'apt', 'apt-get', 'apt-cache', 'dpkg-deb', 'curl', 'wget'})
            self.assertNotEqual(c.argv, ('systemctl', 'start', '--no-block', self.job.unit))
            if c.argv[0] == 'dpkg':
                self.assertIn(c.argv, {('dpkg', '--audit'), ('dpkg', '--print-architecture')})
        for secret in (DOMAIN, TOKEN, keys.psk, keys.shadowtls_password, self.job.job_id, PRIVATE):
            self.assertNotIn(secret, ui.text)

    def test_each_confirmation_cancels_without_writes_or_guard_removal(self):
        for index in range(1, 5):
            with self.subTest(index=index), patch.object(self.files, 'write_new', side_effect=AssertionError(PRIVATE)), \
                    patch.object(self.files, 'unlink_owned', side_effect=AssertionError(PRIVATE)):
                code, ui, report = self.adapter(['y'] * index + [''])
            self.assertEqual(code, 130, report)
            self.assertEqual(report['result'], 'cancelled-before-restoration-guards-preserved')
            self.assertEqual(report['phase'], 'restoration-confirmation')
            self.assertEqual(len(ui.prompts), index + 1)
            self.assert_no_attempt(report)

    def test_eof_and_interrupt_at_each_prompt_do_not_attempt_restore(self):
        for error in (EOFError(), KeyboardInterrupt()):
            for index in range(1, 5):
                with self.subTest(error=type(error).__name__, index=index):
                    code, ui, report = self.adapter(['y'] * index + [error])
                    self.assertEqual(code, 130, report)
                    self.assertEqual(report['result'], 'interrupted-inspection-required')
                    self.assert_no_attempt(report)

    def test_bad_task_state_blocks_before_restoration_prompts(self):
        for state in ('running', 'failed', 'idle'):
            self.fixture.sub.state = state
            code, ui, report = self.adapter(['y'])
            self.assertEqual(code, 1)
            self.assertEqual(len(ui.prompts), 1)
            self.assert_no_attempt(report)

    def test_wrong_invocation_blocks_before_confirmations(self):
        self.fixture.fixture.effect = lambda c: status(self.job, 'done', InvocationID='c' * 32) if c.argv[:4] == (
            'systemctl', 'show', '--all', self.job.unit) else None
        code, ui, report = self.adapter(['y'])
        self.assertEqual(code, 1)
        self.assertEqual(len(ui.prompts), 1)
        self.assert_no_attempt(report)

    def test_partial_restoration_never_gets_a_new_attempt(self):
        for prefix in RESTORE_PREFIXES:
            path = self.job.directory + '/' + prefix + 'partial.json'
            self.files.write_new(path, b'{}')
            code, ui, report = self.adapter(['y'])
            self.assertEqual(code, 1)
            self.assertEqual(len(ui.prompts), 1)
            self.assert_no_attempt(report)
            self.host.path(path).unlink()

    def test_missing_active_task_never_scans_history_or_invents_job(self):
        self.host.path(self.intent).unlink()
        code, ui, report = self.adapter(['y'])
        self.assertEqual(code, 1)
        self.assertEqual(self.host.calls, [])
        self.assertEqual(len(ui.prompts), 1)
        self.assert_no_attempt(report)

    def test_malformed_active_intent_never_selects_arbitrary_unit(self):
        raw = self.files.read(self.intent)
        for data in (b'{}', raw.replace(b'{', b'{"format": 1,', 1),
                     raw.replace(self.job.job_id.encode(), b'../../private')):
            self.host.write(self.intent, data, 0o600)
            code, ui, report = self.adapter(['y'])
            self.assertEqual(code, 1)
            self.assertEqual(self.host.calls, [])
            self.assert_no_attempt(report)

    def test_reboot_is_not_supported(self):
        self.host.path(baseline.BOOT).unlink()
        self.host.write(baseline.BOOT, b'99999999-2222-3333-4444-555555555555\n', 0o444)
        code, ui, report = self.adapter(['y'])
        self.assertEqual(code, 1)
        self.assertEqual(len(ui.prompts), 1)
        self.assert_no_attempt(report)

    def test_legacy_submission_is_not_upgraded_into_restore_authority(self):
        path = self.job.directory + '/submission-ready.json'
        value = json.loads(self.files.read(path))
        value['format'] = 1
        del value['restoration_baseline']
        self.host.write(path, json.dumps(value).encode(), 0o600)
        code, ui, report = self.adapter(['y'])
        self.assertEqual(code, 1)
        self.assertEqual(len(ui.prompts), 1)
        self.assert_no_attempt(report)

    def test_preparation_lock_is_held_during_all_confirmations(self):
        seen = []
        def decision(stage):
            with self.assertRaises(PreparationError), self.prep._lock():
                self.fail('lock must be held')
            seen.append(stage)
            return stage != 'renewal'
        report = PackageFlow(self.tokens).resume_staged(self.job, confirm=decision)
        self.assertEqual(seen, ['restore', 'dns-test', 'renewal'])
        self.assert_no_attempt(report)

    def test_only_exact_true_authorizes_staged_restoration(self):
        for answer in (1, 'y', None, False):
            report = PackageFlow(self.tokens).resume_staged(self.job, confirm=lambda stage: answer)
            self.assertEqual(report['result'], 'cancelled-before-restoration-guards-preserved')
            self.assert_no_attempt(report)

    def drift_during_prompt(self, change):
        def decision(stage):
            if stage == 'renewal':
                change()
            return True
        report = PackageFlow(self.tokens).resume_staged(self.job, confirm=decision)
        self.assertEqual(report['result'], 'inspection-required', report)
        self.assert_no_attempt(report)

    def test_token_change_during_confirmation_blocks_without_record(self):
        path = self.prep.credential_path(self.fixture.sub.lease.before[0][1])
        self.drift_during_prompt(lambda: self.host.write(path, b'dns_cloudflare_api_token = ' + b'z' * 40 + b'\n', 0o600))

    def test_even_approved_vendor_change_during_confirmation_is_not_readopted(self):
        def change():
            self.host.write('/usr/lib/systemd/system/certbot.service', b'changed-during-confirmation\n', 0o644)
            self.fixture.fixture.vendor_sums()
        self.drift_during_prompt(change)

    def test_identical_intent_replacement_during_prompt_is_detected(self):
        def change():
            path = self.host.path(self.intent)
            data = path.read_bytes()
            path.rename(str(path) + '.old')
            self.host.write(self.intent, data, 0o600)
        self.drift_during_prompt(change)

    def test_new_boot_during_confirmation_is_refused(self):
        def change():
            self.host.path(baseline.BOOT).unlink()
            self.host.write(baseline.BOOT, b'99999999-2222-3333-4444-555555555555\n', 0o444)
        self.drift_during_prompt(change)

    def test_lost_tty_after_final_answer_prevents_writes(self):
        ui = Console(['y'] * 5)
        original = ui.ask
        def ask(prompt):
            answer = original(prompt)
            if len(ui.prompts) == 5:
                ui.interactive = lambda: False
            return answer
        ui.ask = ask
        code, _, report = self.adapter(ui)
        self.assertEqual(code, 1)
        self.assert_no_attempt(report)

    def test_interrupt_after_marker_does_not_offer_another_restore(self):
        original = self.files.write_new
        def write(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == self.marker:
                raise KeyboardInterrupt
            return result
        with patch.object(self.files, 'write_new', side_effect=write):
            code, ui, report = self.adapter()
        self.assertEqual(code, 130)
        self.assertTrue(report['host_changes_attempted'])
        self.assertIsNotNone(self.files.info(self.marker))
        code, ui, report = self.adapter(['y'])
        self.assertEqual(code, 1)
        self.assertEqual(len(ui.prompts), 1)
        self.assertEqual(self.fixture.mutations(), [])

    def test_failed_restore_preserves_attempt_and_redacts_exception(self):
        self.fixture.fixture.effect = lambda c: Reply(1, PRIVATE) if c.argv == ('systemctl', 'start', 'nginx.service') else None
        code, ui, report = self.adapter()
        self.assertEqual(code, 1)
        self.assertTrue(report['host_changes_attempted'])
        self.assertNotIn(PRIVATE, ui.text)
        self.assertTrue(report['report_saved'])
        self.host.calls.clear()
        code, ui, report = self.adapter(['y'])
        self.assertEqual(code, 1)
        self.assertEqual(len(ui.prompts), 1)
        self.assertEqual(self.fixture.mutations(), [])

    def test_finished_task_is_not_repeated_or_claimed_healthy_by_second_call(self):
        self.assertEqual(self.adapter()[0], 0)
        self.host.calls.clear()
        code, ui, report = self.adapter(['y'])
        self.assertEqual(code, 1)
        self.assertEqual(report['result'], 'inspection-required')
        self.assertFalse(report['upgrade_completed'])
        self.assertEqual(self.host.calls, [])

    def test_result_write_interrupt_does_not_lose_host_change_evidence(self):
        original = self.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/restoration-resume-result.json'):
                raise KeyboardInterrupt
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=write):
            code, ui, report = self.adapter()
        self.assertEqual(code, 130)
        self.assertEqual(report['result'], 'interrupted-inspection-required')
        self.assertTrue(report['host_changes_attempted'])
        self.assertFalse(report['report_saved'])
        self.assertEqual(report['postinstall']['result'], SUCCESS)
        self.assertNotIn('本次未开始恢复', ui.text)
        self.assertEqual(self.fixture.mutations().count(('systemctl', 'start', 'nginx.service')), 1)

    def test_staged_api_requires_job_and_callback_before_host_reads(self):
        flow = PackageFlow(self.tokens)
        for job, callback in ((None, lambda stage: True), (self.job, True), (self.job, None)):
            with self.assertRaises(PreparationError):
                flow.resume_staged(job, confirm=callback)
        self.assertEqual(self.host.calls, [])

    def test_malformed_claim_blocks_before_confirmation_without_changes(self):
        path = self.host.path(self.job.directory + '/execution-claim.json')
        raw = path.read_bytes()
        for value in (b'true', b'1.0', b'0, "format": 1'):
            with self.subTest(value=value):
                path.write_bytes(raw.replace(b'"format": 1', b'"format": ' + value))
                code, ui, report = self.adapter(['y'])
                self.assertEqual(code, 1)
                self.assertEqual(len(ui.prompts), 1)
                self.assert_no_attempt(report)

    def interrupted_inner_result(self, error, *, after_write=False):
        original = self.files.write_new
        def write(path, *args, **kwargs):
            if path.endswith('/postinstall-result.json'):
                if after_write:
                    original(path, *args, **kwargs)
                raise error
            return original(path, *args, **kwargs)
        with patch.object(self.files, 'write_new', side_effect=write):
            code, ui, report = self.adapter()
        self.assertEqual(code, 130)
        self.assertEqual(report['result'], 'interrupted-inspection-required')
        self.assertTrue(report['host_changes_attempted'])
        self.assertTrue(report['report_saved'])
        postinstall = report['postinstall']
        self.assertTrue(postinstall['completion_recorded'])
        self.assertTrue(postinstall['intent_removed_verified'])
        self.assertFalse(postinstall['report_saved'])
        self.assertEqual(self.fixture.mutations().count(('systemctl', 'start', 'nginx.service')), 1)
        self.assertNotIn('本次未开始恢复', ui.text)
        self.host.calls.clear()
        code, ui, report = self.adapter(['y'])
        self.assertEqual(code, 1)
        self.assertEqual(self.host.calls, [])

    def test_inner_result_eof_preserves_completion_in_resume_report(self):
        self.interrupted_inner_result(EOFError())

    def test_inner_result_interrupt_after_write_does_not_allow_second_restore(self):
        self.interrupted_inner_result(KeyboardInterrupt(), after_write=True)


class EntryTests(unittest.TestCase):
    def test_explicit_flag_routes_to_restricted_adapter(self):
        with patch('snellctl.packageresume.run_package_resume', return_value=0) as run:
            self.assertEqual(main(['package-update-resume', '--experimental']), 0)
        run.assert_called_once_with()

    def test_missing_flag_never_opens_host(self):
        with patch('snellctl.packageresume.run_package_resume') as run, redirect_stderr(io.StringIO()):
            self.assertEqual(main(['package-update-resume']), 2)
        run.assert_not_called()

    def test_help_is_safe_without_opening_host(self):
        with patch('snellctl.packageresume.run_package_resume') as run, redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as result:
                main(['package-update-resume', '--help'])
        self.assertEqual(result.exception.code, 0)
        run.assert_not_called()
        self.assertIn('--experimental', out.getvalue())

    def test_no_task_selection_automatic_yes_retry_or_secret_argument(self):
        for args in (['--yes'], ['--retry'], ['--job-id', PRIVATE], ['--plan', PRIVATE], ['--token', PRIVATE], ['--json']):
            with redirect_stderr(io.StringIO()) as out, self.assertRaises(SystemExit):
                main(['package-update-resume', '--experimental', *args])
            self.assertNotIn(PRIVATE, out.getvalue())

    def test_noninteractive_refuses_before_factory(self):
        ui, factory = Console(), Mock()
        ui.interactive = lambda: False
        self.assertEqual(run_package_resume(factory=factory, terminal=ui), 2)
        factory.assert_not_called()
        self.assertEqual(ui.prompts, [])

    def test_initial_cancel_or_eof_never_opens_host(self):
        for answer in ('', 'n', 'yes', 'true', EOFError(), KeyboardInterrupt()):
            ui, factory = Console([answer]), Mock()
            self.assertEqual(run_package_resume(factory=factory, terminal=ui), 130)
            factory.assert_not_called()

    def test_lost_tty_before_factory_refuses_reads(self):
        ui, factory = Console(['y']), Mock()
        ui.interactive = Mock(side_effect=[True, False])
        self.assertEqual(run_package_resume(factory=factory, terminal=ui), 1)
        factory.assert_not_called()

    def test_factory_error_does_not_expose_exception(self):
        ui, factory = Console(['y']), Mock(side_effect=PreparationError(PRIVATE))
        self.assertEqual(run_package_resume(factory=factory, terminal=ui), 1)
        self.assertNotIn(PRIVATE, ui.text)
