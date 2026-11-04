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
from snellctl.renewalprobe import read_only_command
from snellctl.uninstallplan import SUCCESS, UninstallPlan, run_uninstall_plan
from test_domainchange import NEW_DOMAIN, NEW_TOKEN
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
import test_retiredcleanup
import test_domainchange


class UninstallScopeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_retiredcleanup.RetiredCleanupTests('test_check_read_only_and_plan_redacted')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.assert_success(self.fixture.clean())
        self.host, self.prep = self.fixture.host, self.fixture.prep
        self.tokens = self.fixture.fixture.tokens
        self.engine = UninstallPlan(self.tokens)
        self.host.calls.clear()

    def snapshot(self):
        return self.fixture.fixture.snapshot()

    def check(self):
        return self.engine.check()

    def blocked(self, report, reason=None):
        self.assertEqual(report['result'], 'blocked-preserve-all', report)
        self.assertFalse(report['host_changes_attempted'])
        self.assertFalse(report['uninstall_authorized'])
        self.assertTrue(report['uninstall_implemented'])
        self.assertTrue(report['all_assets_preserved'])
        self.assertFalse(report['report_saved'])
        if reason:
            self.assertEqual(report['reason'], reason, report)

    def test_complete_node_after_domain_change_and_retired_cleanup(self):
        report = self.check()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertEqual(report['current_service_health'], 'local-checks-passed')
        self.assertFalse(report['uninstall_authorized'])
        self.assertTrue(report['uninstall_implemented'])
        self.assertEqual(report['review_counts']['recorded_ipv4_entry_rules'], 1)
        self.assertEqual(report['review_counts']['archive_generations'], 1)
        self.assertEqual(report['global_reference_check'], 'not-performed')

    def test_original_domain_and_credential_also_supported(self):
        fixture = test_domainchange.DomainChangeTests('test_check_is_read_only_and_repr_is_redacted')
        self.addCleanup(fixture.doCleanups)
        with patch('test_domainchange.DomainHost', test_retiredcleanup.CleanupHost):
            fixture.setUp()
        test_retiredcleanup.RetiredCleanupTests.enrich_renewals(fixture)
        report = UninstallPlan(fixture.tokens).check()
        self.assertEqual(report['result'], SUCCESS, report)

    def test_files_rules_services_and_history_unchanged(self):
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
        self.assertTrue(all(read_only_command(c.argv) for c in self.host.calls))

    def test_report_has_no_domains_paths_keys_tokens_or_fingerprints(self):
        result = self.check()
        self.assertEqual(result['result'], SUCCESS, result)
        text = json.dumps(result)
        keys = self.fixture.fixture.before_keys
        for value in (DOMAIN, NEW_DOMAIN, TOKEN, NEW_TOKEN, str(self.host.root), STATE,
                      keys.psk, keys.shadowtls_password, self.tokens.check().revision):
            self.assertNotIn(value, text)

    def test_changed_public_port_is_derived_not_assumed(self):
        engine = PortChange(self.tokens.public)
        plan = engine.check(24443)
        engine.change(plan, confirm_change=True, confirm_ssh_reconnected=True)
        self.host.calls.clear()
        report = self.check()
        self.assertEqual(report['result'], SUCCESS, report)
        self.assertEqual(report['review_counts']['recorded_ipv4_entry_rules'], 1)
        self.assertNotIn('24443', json.dumps(report))

    def test_other_node_program_version_and_untracked_files_block(self):
        paths = (
            ('/etc/snellctl/nodes/another/config', 'additional-node'),
            ('/etc/snellctl/nodes/main/backup', 'additional-node-file'),
            ('/etc/snellctl/credentials/other.ini', 'additional-credential'),
            ('/etc/snellctl/unknown', 'additional-managed-root-entry'),
            ('/opt/snellctl/unknown', 'additional-program'),
            (str(PurePosixPath(BINARIES[0]).parent.parent) + '/another', 'additional-program-version'),
            (str(PurePosixPath(BINARIES[0]).parent) + '/backup', 'additional-program-file'),
        )
        for path, reason in paths:
            with self.subTest(path=path):
                self.host.write(path, b'PRIVATE')
                before = self.snapshot()
                self.blocked(self.check(), reason)
                self.assertEqual(before, self.snapshot())
                self.host.path(path).unlink()
                if '/another/' in path:
                    self.host.path(path).parent.rmdir()

    def test_other_certificate_or_renewal_is_not_adopted(self):
        for path in ('/etc/letsencrypt/archive/extra', '/etc/letsencrypt/live/extra',
                     '/etc/letsencrypt/renewal/extra.conf'):
            with self.subTest(path=path):
                self.host.write(path, b'PRIVATE')
                self.blocked(self.check())
                self.host.path(path).unlink()

    def test_unrelated_nginx_site_and_hook_block(self):
        for path in ('/etc/nginx/sites-available/unrelated', '/etc/letsencrypt/renewal-hooks/pre/unrelated'):
            with self.subTest(path=path):
                self.host.write(path, b'PRIVATE')
                self.blocked(self.check(), 'extra-nginx-or-renewal-hook-scope')
                self.host.path(path).unlink()

    def test_unrelated_secrets_and_logs_are_never_read(self):
        original = HostFiles.read
        def read(files, path, **kwargs):
            self.assertFalse('/accounts/' in path or '/var/log/' in path or path.endswith('command-output.txt'))
            return original(files, path, **kwargs)
        with patch.object(HostFiles, 'read', new=read):
            self.assertEqual(self.check()['result'], SUCCESS)

    def test_extra_credential_not_read_even_when_secret_or_symlink(self):
        path = '/etc/snellctl/credentials/unrelated.ini'
        original = HostFiles.read
        def read(files, target, **kwargs):
            self.assertNotEqual(target, path)
            return original(files, target, **kwargs)
        self.host.path(path).symlink_to('/root/PRIVATE')
        with patch.object(HostFiles, 'read', new=read):
            self.blocked(self.check(), 'additional-credential')

    def test_unknown_archive_members_and_incomplete_generation_block(self):
        base = '/etc/letsencrypt/archive/' + NEW_DOMAIN
        for name, reason in (('unknown', 'certificate-archive-entries'), ('cert2.pem', 'certificate-incomplete-generation')):
            with self.subTest(name=name):
                self.host.write(base + '/' + name, b'PRIVATE')
                self.blocked(self.check(), reason)
                self.host.path(base + '/' + name).unlink()

    def test_complete_historical_generation_counts_without_reading_old_private_key(self):
        base = '/etc/letsencrypt/archive/' + NEW_DOMAIN
        for part in ('cert', 'chain', 'fullchain', 'privkey'):
            self.host.write(base + '/' + part + '2.pem', b'old fixture')
        original = HostFiles.read
        def read(files, path, **kwargs):
            self.assertNotEqual(path, base + '/privkey2.pem')
            return original(files, path, **kwargs)
        with patch.object(HostFiles, 'read', new=read):
            result = self.check()
        self.assertEqual(result['result'], SUCCESS, result)
        self.assertEqual(result['review_counts']['archive_generations'], 2)

    def test_hardlink_symlink_fifo_and_unsafe_mode_in_old_archive_block(self):
        base = '/etc/letsencrypt/archive/' + NEW_DOMAIN
        for part in ('cert', 'chain', 'fullchain', 'privkey'):
            self.host.write(base + '/' + part + '2.pem', b'fixture')
        target = self.host.path(base + '/privkey2.pem')
        target.chmod(0o644)
        self.blocked(self.check(), 'certificate-archive-metadata')
        target.unlink()
        target.symlink_to('/root/PRIVATE')
        self.blocked(self.check(), 'certificate-archive-metadata')
        target.unlink()
        os.mkfifo(target, 0o600)
        self.blocked(self.check(), 'certificate-archive-metadata')
        target.unlink()
        os.link(self.host.path(base + '/privkey1.pem'), target)
        self.blocked(self.check())

    def test_cross_lineage_renewal_paths_rejected(self):
        path = self.host.path('/etc/letsencrypt/renewal/' + NEW_DOMAIN + '.conf')
        path.write_text(path.read_text().replace('archive/' + NEW_DOMAIN, 'archive/unrelated.example.org'))
        self.blocked(self.check(), 'renewal-paths')

    def test_multi_domain_wildcard_or_missing_san_not_assumed_exclusive(self):
        for san in ('DNS:' + NEW_DOMAIN + ', DNS:another.example.org', 'DNS:*.example.org', ''):
            with self.subTest(san=san):
                self.host.local_override = lambda c: Reply(0, 'X509v3 Subject Alternative Name:\n' + san) if c.argv[-2:] == ('-ext', 'subjectAltName') else None
                self.blocked(self.check(), 'certificate-not-single-domain')

    def test_shared_or_ambiguous_entry_rule_is_not_accepted(self):
        original = self.tokens.public._firewall
        def ambiguous(ssh_port):
            rules, hashes, running = original(ssh_port)
            return [*rules, rules[-1]], hashes, running
        # Isolate the additional scope check from the general deployment digest check.
        def progress(phase):
            if phase == 'entry-rule-check':
                self.patch_scope = patch.object(self.tokens.public, '_firewall', side_effect=ambiguous)
                self.patch_scope.start()
                self.addCleanup(self.patch_scope.stop)
        self.engine.progress = progress
        self.blocked(self.check(), 'entry-rule-not-unique-recorded-ipv4')

    def test_pending_change_lock_conflict_and_missing_owner_block(self):
        with self.prep._lock():
            self.blocked(self.check())
        self.prep._record('retired-cleanup-intent', {'PRIVATE': True})
        self.blocked(self.check())
        self.host.path(STATE + '/retired-cleanup-intent.json').unlink()
        self.host.path(STATE + '/owner.json').unlink()
        self.blocked(self.check())

    def test_changed_managed_config_not_repaired(self):
        path = self.host.path('/etc/snellctl/nodes/main/snell.conf')
        path.write_bytes(b'PRIVATE')
        before = self.snapshot()
        self.blocked(self.check())
        self.assertEqual(before, self.snapshot())

    def test_disabled_renewal_or_busy_service_not_reenabled_or_stopped(self):
        self.host.enabled.discard('certbot.timer')
        self.host.active.discard('certbot.timer')
        self.blocked(self.check())
        self.assertNotIn('certbot.timer', self.host.enabled)
        self.host.enabled.add('certbot.timer')
        self.host.active.add('certbot.timer')
        self.host.local_override = lambda c: Reply(0, 'ActiveState=active\nSubState=running\nMainPID=123\nJob=PRIVATE\n') if c.argv[-1] == 'ActiveState,SubState,MainPID,Job' else None
        report = self.check()
        self.blocked(report, 'renewal-unit-state-mismatch')
        self.assertNotIn('PRIVATE', json.dumps(report))
        self.assertTrue(all(read_only_command(c.argv) for c in self.host.calls))

    def test_running_but_not_boot_enabled_timer_blocks(self):
        self.host.local_override = lambda c: Reply(0, 'ActiveState=active\nSubState=waiting\nUnitFileState=disabled\nTriggers=certbot.service\nNextElapseUSecRealtime=future\n') if c.argv[-1] == 'ActiveState,SubState,UnitFileState,Triggers,NextElapseUSecRealtime' else None
        self.blocked(self.check())

    def test_duplicate_rule_or_ipv6_only_source_and_missing_kernel_entry_block(self):
        from dataclasses import replace
        original = self.tokens.public._firewall
        spec = self.tokens._check()[1]
        record = self.prep._read_record('public-ready')
        rules, hashes, running = original(record['ssh_port'])
        for source in ('::/0', '192.0.2.0/24'):
            changed = [replace(r, source=source) if r.comment == 'snellctl-main' else r for r in rules]
            with patch.object(self.tokens.public, '_firewall', return_value=(changed, hashes, running)), self.assertRaises(Exception):
                self.engine._firewall(spec, record)
        for entries in ([], [*running, *running]):
            with patch.object(self.tokens.public, '_firewall', return_value=(rules, hashes, entries)), self.assertRaises(Exception):
                self.engine._firewall(spec, record)

    def test_query_failures_or_uncertain_results_never_return_success(self):
        for reply in (Reply(1, 'PRIVATE'), Reply(-1, 'PRIVATE', uncertain=True)):
            self.host.local_override = lambda c: reply
            result = self.check()
            self.blocked(result)
            self.assertNotIn('PRIVATE', json.dumps(result))

    def test_failed_local_tls_blocks(self):
        self.fixture.fixture.probe.return_value = False
        self.blocked(self.check())

    def test_directory_change_during_final_health_check_invalidates_result(self):
        def progress(phase):
            if phase == 'unchanged-health-check':
                self.host.write('/etc/snellctl/credentials/late.ini', b'PRIVATE')
        self.engine.progress = progress
        self.blocked(self.check())

    def test_metadata_scan_limit_stops(self):
        with patch('snellctl.domaininventory.LIMIT', 1):
            self.blocked(self.check())

    def test_mutating_command_guard_rejects_before_runner(self):
        for argv in (('systemctl', 'stop', 'nginx.service'), ('certbot', 'delete'), ('ufw', 'reset'),
                     ('apt-get', 'purge', 'nginx'), ('systemctl', 'disable', '--now', 'certbot.timer')):
            original = self.prep.runner
            with self.engine._commands(), self.assertRaises(PreparationError):
                self.prep.runner(Command(argv))
            self.assertIs(self.prep.runner, original)
        self.assertEqual(self.host.calls, [])

    def test_exceptions_and_interruptions_do_not_expose_raw_output(self):
        original = self.prep.runner
        for error in (RuntimeError('PRIVATE'), KeyboardInterrupt(), OSError('PRIVATE')):
            with patch.object(self.tokens, '_check', side_effect=error):
                report = self.check()
            self.blocked(report)
            self.assertIs(self.prep.runner, original)
            self.assertNotIn('PRIVATE', json.dumps(report))


class UninstallPlanInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.tokens, self.factory_calls = Mock(), 0

    @contextmanager
    def factory(self):
        self.factory_calls += 1
        yield self.tokens

    def test_default_decline_does_not_open_host_or_secrets(self):
        for answer in ('', 'n', 'yes', '确认'):
            ui = Console([answer])
            self.assertEqual(run_uninstall_plan(factory=self.factory, terminal=ui), 130)
            ui.secret.assert_not_called()
        self.assertEqual(self.factory_calls, 0)

    def test_confirmation_only_authorizes_readonly_check(self):
        ui = Console(['y'])
        with patch('snellctl.uninstallplan.UninstallPlan.check', return_value={'result': SUCCESS, 'uninstall_authorized': False}) as check:
            self.assertEqual(run_uninstall_plan(factory=self.factory, terminal=ui), 0)
        check.assert_called_once_with()
        ui.secret.assert_not_called()
        self.assertIn('没有卸载或授权删除', ui.text)

    def test_noninteractive_and_terminal_change_refuse(self):
        for states in ([False], [True, False]):
            ui = Console(['y'])
            ui.interactive = Mock(side_effect=states)
            self.assertEqual(run_uninstall_plan(factory=self.factory, terminal=ui), 2)
        self.assertEqual(self.factory_calls, 0)

    def test_interrupted_and_failed_factory_are_redacted(self):
        ui = Console([KeyboardInterrupt()])
        self.assertEqual(run_uninstall_plan(factory=self.factory, terminal=ui), 130)
        ui = Console(['y'])
        self.assertEqual(run_uninstall_plan(factory=Mock(side_effect=RuntimeError('PRIVATE')), terminal=ui), 1)
        self.assertNotIn('PRIVATE', ui.text)

    def test_blocked_report_is_not_success(self):
        with patch('snellctl.uninstallplan.UninstallPlan.check', return_value={'result': 'blocked-preserve-all'}):
            self.assertEqual(run_uninstall_plan(factory=self.factory, terminal=Console(['y'])), 1)

    def test_cli_routes_and_rejects_targets_apply_yes_root_or_credentials(self):
        with patch('snellctl.uninstallplan.run_uninstall_plan', return_value=0) as run:
            self.assertEqual(main(['uninstall-plan']), 0)
        run.assert_called_once_with()
        for arg in ('--apply', '--experimental', '--yes', '--root', '--domain', '--token'):
            with self.subTest(arg=arg), redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit):
                main(['uninstall-plan', arg, 'PRIVATE'])
            self.assertNotIn('PRIVATE', output.getvalue())
