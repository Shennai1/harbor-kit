from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from dataclasses import replace
import unittest
from unittest.mock import patch

from snellctl.__main__ import main
from snellctl.activation import Activation, DEFAULT_LINK
from snellctl.client import read_client
from snellctl.deployment import NodeSpec
from snellctl.hostprep import Preparation, PreparationError, Reply, STATE, CREDENTIAL
from snellctl.installer import Installation, installation_status, render_status
from snellctl.reinstall import (COMPLETE, GENERATIONS, INTENT, SUCCESS, Reinstallation,
                               ReinstallPreparation, run_reinstall)
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
import test_reinstallplan
import test_uninstall


class ReinstallTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_reinstallplan.ReinstallPlanTests('test_success_after_uninstall_and_domain_cleanup')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.host = self.fixture.host
        self.prep = ReinstallPreparation(self.host.root, self.fixture.dispatch)
        self.addCleanup(self.prep.files.close)
        local = Activation(self.prep, self.fixture.fixture.tokens.local.probe, readiness_timeout=0.01)
        self.installation = Installation(self.prep, local, preflight_check=lambda spec: None)
        self.engine = Reinstallation(self.installation)
        self.spec = NodeSpec(DOMAIN)
        self.ssh = self.prep._read_record('public-ready')['ssh_port']

    def path(self, path):
        return self.host.path(path)

    @contextmanager
    def factory(self):
        yield self.engine

    def test_preflight_read_only(self):
        before = self.fixture.snapshot()
        names, tree = self.engine.preflight(self.spec, self.ssh)
        self.assertIn('uninstall-ready.json', names)
        self.assertIn('public-ready.json', tree)
        self.assertEqual(before, self.fixture.snapshot())
        self.assertFalse(self.engine.changed)

    def test_archive_preserves_identity_content_and_original_lock(self):
        names, tree = self.engine.preflight(self.spec, self.ssh)
        contents = {name: self.path(STATE + '/' + name).read_bytes() for name in names
                    if self.path(STATE + '/' + name).is_file()}
        lock = self.prep.files.identity(STATE + '/lock')
        owner = self.path(STATE + '/owner.json').read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'simulate'):
            with self.engine.prepare(self.spec, self.ssh, confirmed=True):
                self.assertEqual(lock, self.prep.files.identity(STATE + '/lock'))
                self.assertEqual(owner, self.path(STATE + '/owner.json').read_bytes())
                self.assertEqual(self.engine._tree(self.engine.archive + '/records', names), tree)
                for name, data in contents.items():
                    self.assertEqual(self.path(self.engine.archive + '/records/' + name).read_bytes(), data)
                    self.assertFalse(self.path(STATE + '/' + name).exists())
                self.assertFalse(self.path('/opt/snellctl').exists())
                self.assertFalse(self.path('/etc/snellctl/nodes').exists())
                raise RuntimeError('simulate')
        self.assertTrue(self.path(STATE + '/' + INTENT + '.json').is_file())
        report = installation_status(root=self.host.root)
        self.assertEqual(report['reinstall'], 'needs-inspection')
        self.assertEqual(report['phases']['public'], 'not-started')
        self.assertNotIn('resume --experimental', render_status(report))

    def test_same_inode_lock_excludes_other_instances_and_threads(self):
        import threading
        with self.assertRaises(RuntimeError):
            with self.engine.prepare(self.spec, self.ssh, confirmed=True):
                with Preparation(self.host.root, self.fixture.dispatch) as other:
                    with self.assertRaises(PreparationError):
                        with other._lock():
                            self.fail('second lock obtained')
                result = []
                def take_lock():
                    try:
                        with self.prep._lock():
                            result.append('unsafe')
                    except PreparationError:
                        result.append('blocked')
                thread = threading.Thread(target=take_lock)
                thread.start()
                thread.join(5)
                self.assertEqual(result, ['blocked'])
                raise RuntimeError()

    def test_normal_nested_locks_remain_nonreentrant(self):
        with self.prep._lock():
            with self.assertRaises(PreparationError):
                with self.prep._lock():
                    self.fail('nested normal lock obtained')

    def test_failure_after_first_move_keeps_marker_and_remaining_history(self):
        original = self.engine._move_history
        count = 0
        def fail(name, expected):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('PRIVATE failure')
            original(name, expected)
        with patch.object(self.engine, '_move_history', side_effect=fail):
            with self.assertRaises(OSError):
                with self.engine.prepare(self.spec, self.ssh, confirmed=True):
                    self.fail('should not deploy')
        self.assertTrue(self.path(STATE + '/' + INTENT + '.json').exists())
        self.assertTrue(self.path(STATE + '/uninstall-ready.json').exists())
        self.assertEqual(len(list(self.path(self.engine.archive + '/records').iterdir())), 1)
        self.assertEqual(installation_status(root=self.host.root)['reinstall'], 'needs-inspection')
        with self.assertRaises(PreparationError):
            self.prep.packages()
        with Preparation(self.host.root, self.fixture.dispatch) as other:
            with self.assertRaises(PreparationError):
                other._no_pending_change()

    def test_confirmation_required_before_mutation(self):
        before = self.fixture.snapshot()
        with self.assertRaises(PreparationError):
            with self.engine.prepare(self.spec, self.ssh):
                self.fail('missing consent')
        self.assertEqual(before, self.fixture.snapshot())

    def test_unknown_history_blocks_without_mutation(self):
        self.host.write(STATE + '/foreign-record.json', b'PRIVATE')
        before = self.fixture.snapshot()
        with self.assertRaises(PreparationError):
            with self.engine.prepare(self.spec, self.ssh, confirmed=True):
                self.fail('unknown history')
        self.assertEqual(before, self.fixture.snapshot())

    def test_history_symlink_hardlink_or_public_permissions_block(self):
        target = self.path(STATE + '/token-resume-report.json')
        for kind in ('symlink', 'hardlink', 'public', 'fifo'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    target.symlink_to('owner.json')
                elif kind == 'hardlink':
                    os.link(self.path(STATE + '/owner.json'), target)
                elif kind == 'fifo':
                    os.mkfifo(target, 0o600)
                else:
                    self.host.write(str(target.relative_to(self.host.root)), b'PRIVATE')
                    target.chmod(0o644)
                try:
                    with self.assertRaises(PreparationError):
                        self.engine.preflight(self.spec, self.ssh)
                    self.assertFalse(self.engine.changed)
                finally:
                    target.unlink()

    def test_new_ssh_or_conflicting_ports_rejected(self):
        for ssh in (self.ssh + 1, self.spec.public_port):
            with self.assertRaises(PreparationError):
                self.engine.preflight(self.spec, ssh)
        self.assertFalse(self.engine.changed)

    def test_shared_or_nonempty_resources_rejected(self):
        self.host.write('/opt/snellctl/foreign', b'PRIVATE')
        with self.assertRaises(PreparationError):
            with self.engine.prepare(self.spec, self.ssh, confirmed=True):
                self.fail('shared resource')
        self.assertFalse(self.engine.changed)

    def test_intent_changed_inside_lease_stops_all_further_steps(self):
        with self.assertRaises(PreparationError):
            with self.engine.prepare(self.spec, self.ssh, confirmed=True):
                self.host.write(STATE + '/' + INTENT + '.json', b'{}')
                self.prep.packages()
        self.assertFalse(any(c.argv[0] == 'apt-get' for c in self.host.calls))

    def test_installer_cli_cancellation_before_writes(self):
        console = Console([DOMAIN, '', '', '', str(self.ssh), 'n'])
        before = self.fixture.snapshot()
        self.assertEqual(run_reinstall(factory=self.factory, terminal=console), 130)
        self.assertEqual(before, self.fixture.snapshot())

    def test_noninteractive_does_not_create_factory(self):
        console = Console([])
        console.interactive = lambda: False
        with patch.object(self, 'factory', side_effect=AssertionError('factory')) as factory:
            self.assertEqual(run_reinstall(factory=factory, terminal=console), 2)

    def deploy(self):
        with self.engine.prepare(self.spec, self.ssh, confirmed=True):
            self.prep.packages()
            self.engine.prepare_default_site()
            self.prep.credential(TOKEN)
            self.prep.certificate(self.spec.domain, production=False, agree_tos=True)
            self.prep.certificate(self.spec.domain, production=True, agree_tos=True, confirm_issue=True)
            with patch('snellctl.activation.verify', side_effect=lambda a, data: b'BINARY-' + a.name.encode()):
                self.engine.local.activate(self.spec, {'snell': b'test archive', 'shadow-tls': b'test executable'})
            self.engine.local.test_renewal(self.spec, confirm_test=True)
            self.engine.public.enable(self.spec, ssh_port=self.ssh, confirm_public=True,
                                      confirm_renewal=True, confirm_ssh_reconnected=True)
            self.engine.finish()

    def ui(self):
        return Console([self.spec.domain, str(self.spec.public_port), str(self.spec.snell_port),
                        str(self.spec.tls_port), str(self.ssh), *(['y'] * 9)])

    @contextmanager
    def downloads(self):
        with patch.object(self.installation, 'downloads', return_value={'snell': b'test', 'shadow-tls': b'test'}), \
             patch('snellctl.activation.verify', side_effect=lambda a, data: b'BINARY-' + a.name.encode()):
            yield

    def test_full_interactive_wizard_and_no_secret_output(self):
        console = self.ui()
        with self.downloads():
            self.assertEqual(run_reinstall(factory=self.factory, terminal=console), 0, console.text)
        self.assertIn(SUCCESS, console.text)
        self.assertNotIn(TOKEN, console.text)
        client = read_client(root=self.host.root)
        self.assertNotIn(client.keys.psk, console.text)
        self.assertNotIn(client.keys.shadowtls_password, console.text)
        self.assertEqual(sum('[y/n]' in prompt for prompt in console.prompts), 9)
        self.assertFalse(self.path('/usr/local/bin/snellctl').exists())

    def test_cancel_before_certificate_keeps_renewal_blocked_and_new_intent(self):
        console = Console([DOMAIN, '', '', '', str(self.ssh), *(['y'] * 4), 'n'])
        with self.downloads():
            self.assertEqual(run_reinstall(factory=self.factory, terminal=console), 130, console.text)
        self.assertTrue(self.prep._exists(INTENT))
        self.assertTrue(self.prep._exists('dns-test-ready'))
        self.assertFalse(self.prep._exists('certificate-intent'))
        self.assertNotIn('certbot.timer', self.host.enabled)
        self.assertEqual(len(self.host.rules), 1)
        self.assertNotIn('resume --experimental', render_status(installation_status(root=self.host.root)))

    def test_apt_failure_never_attempts_credential_or_certificate(self):
        def fail(command):
            if command.argv[0] == 'apt-get':
                return Reply(1, 'PRIVATE apt failure')
        self.fixture.override = fail
        console = self.ui()
        with self.downloads():
            self.assertEqual(run_reinstall(factory=self.factory, terminal=console), 1, console.text)
        self.assertTrue(self.prep._exists(INTENT))
        console.secret.assert_not_called()
        self.assertFalse(any(c.argv[0] == 'certbot' for c in self.host.calls))
        self.assertNotIn('PRIVATE', console.text)

    def test_uncertain_production_failure_is_not_retried(self):
        def fail(command):
            if command.argv[:2] == ('certbot', 'certonly') and '--dry-run' not in command.argv:
                return Reply(-1, 'PRIVATE certificate failure', uncertain=True)
        self.fixture.override = fail
        console = self.ui()
        with self.downloads():
            self.assertEqual(run_reinstall(factory=self.factory, terminal=console), 1, console.text)
        self.assertTrue(self.prep._exists(INTENT))
        self.assertTrue(self.prep._exists('certificate-intent'))
        self.assertFalse(self.prep._exists('activation-intent'))
        self.assertEqual(sum(c.argv[:2] == ('certbot', 'certonly') and '--dry-run' not in c.argv for c in self.host.calls), 1)
        self.assertNotIn('PRIVATE', console.text)

    def test_default_link_recreated_only_under_verified_masks(self):
        with self.assertRaises(RuntimeError):
            with self.engine.prepare(self.spec, self.ssh, confirmed=True):
                self.prep.packages()
                self.path(DEFAULT_LINK).unlink()
                self.engine.prepare_default_site()
                self.assertEqual(os.readlink(self.path(DEFAULT_LINK)), '/etc/nginx/sites-available/default')
                self.path('/etc/systemd/system/nginx.service').unlink()
                self.path(DEFAULT_LINK).unlink()
                with self.assertRaises(PreparationError):
                    self.engine.prepare_default_site()
                self.assertFalse(self.path(DEFAULT_LINK).is_symlink())
                raise RuntimeError()

    def test_finish_requires_live_public_services(self):
        original = self.engine.finish
        def stop_before_finish():
            self.host.active.discard('nginx.service')
            original()
        with patch.object(self.engine, 'finish', side_effect=stop_before_finish):
            with self.assertRaises(PreparationError):
                self.deploy()
        self.assertTrue(self.prep._exists(INTENT))
        self.assertFalse(self.prep._exists(COMPLETE))

    def test_second_generation_reinstall_preserves_first_archive(self):
        self.deploy()
        first = self.engine.archive
        first_tree = self.engine._tree(GENERATIONS, [first.rsplit('/', 1)[1]])
        old_keys = read_client(root=self.host.root).keys
        # Certbot's complete renewal file is needed by the existing uninstall checker.
        import test_retiredcleanup
        from snellctl.tokenchange import TokenChange
        tokens = TokenChange(self.engine.public)
        fixture = self.fixture.fixture
        fixture.prep = self.prep
        fixture.tokens = tokens
        test_retiredcleanup.RetiredCleanupTests.enrich_renewals(fixture)
        fixture.prepare_engine()
        fixture.assert_success(fixture.remove())
        self.fixture.original_runner = fixture.dispatch
        self.prep.runner = self.fixture.dispatch
        self.engine = Reinstallation(self.installation)
        self.deploy()
        self.assertNotEqual(first, self.engine.archive)
        self.assertEqual(first_tree, self.engine._tree(GENERATIONS, [first.rsplit('/', 1)[1]]))
        self.assertEqual(len(list(self.path(GENERATIONS).iterdir())), 2)
        new = read_client(root=self.host.root)
        self.assertNotEqual(new.keys.psk, old_keys.psk)
        self.assertNotEqual(new.keys.shadowtls_password, old_keys.shadowtls_password)

    def test_cli_requires_flag_and_hides_unknown_arguments(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as output:
            self.assertEqual(main(['reinstall']), 2)
            with self.assertRaises(SystemExit):
                main(['reinstall', '--experimental', '--token', 'PRIVATE'])
        self.assertNotIn('PRIVATE', output.getvalue())
        with patch('snellctl.reinstall.run_reinstall', return_value=17) as run:
            self.assertEqual(main(['reinstall', '--experimental']), 17)
            run.assert_called_once_with()

    def test_full_reinstall_after_uninstall(self):
        lock = self.prep.files.identity(STATE + '/lock')
        before_rules = list(self.host.rules)
        self.deploy()
        self.assertEqual(self.prep._read_record(COMPLETE)['result'], SUCCESS)
        self.assertFalse(self.prep._exists(INTENT))
        self.assertFalse(self.prep._exists('uninstall-ready'))
        self.assertEqual(lock, self.prep.files.identity(STATE + '/lock'))
        self.assertTrue(self.path(self.engine.archive + '/records/uninstall-ready.json').is_file())
        client = read_client(root=self.host.root)
        self.assertEqual(client.domain, self.spec.domain)
        self.assertNotEqual(client.keys.psk, client.keys.shadowtls_password)
        self.assertEqual(len(client.keys.psk), 64)
        self.assertEqual(len(client.keys.shadowtls_password), 64)
        self.assertTrue(set(before_rules) <= set(self.host.rules))
        self.assertEqual(len(self.host.rules), len(before_rules) + 1)
        self.assertIn('certbot.timer', self.host.enabled)
        self.assertTrue(set(self.host.pids) <= self.host.active)
        self.assertEqual(installation_status(root=self.host.root)['reinstall'], 'completion-recorded')


if __name__ == '__main__':
    unittest.main()
