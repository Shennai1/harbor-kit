from dataclasses import replace
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from snellctl import packagedownload as stage
from snellctl.hostcommands import DebianCommands
from snellctl.hostprep import Command, HostFiles, PreparationError, Reply, STATE
from snellctl.packagejob import JobSpec
from snellctl.packageplan import ALL_PACKAGES
from snellctl.packagepolicy import ARCHITECTURES, RevisionChange
from snellctl.preflight import DEPENDENCIES
import test_maintenance


WORK = stage.CACHE + '/' + 'b' * 32
ORIGIN = 'https://deb.debian.org/debian trixie/main amd64 Packages'


def simulated(changes):
    rows = [f'{len(changes)} upgraded, 0 newly installed, 0 to remove and 0 not upgraded.']
    for prefix in ('Inst', 'Conf'):
        for c in changes:
            old = f' [{c.before}]' if prefix == 'Inst' else ''
            rows.append(f'{prefix} {c.name}{old} ({c.after} Debian:13/stable [{c.architecture}])')
    return '\n'.join(rows) + '\n'


def control(c):
    return f'Package: {c.name}\nVersion: {c.after}\nArchitecture: {c.architecture}\n'


def record(c, data):
    return (control(c) + f'Size: {len(data)}\nSHA256: {hashlib.sha256(data).hexdigest()}\n'
            f'Filename: pool/main/n/nginx/{c.name}_{c.after}_{c.architecture}.deb\n'
            'Description: example\n folded text\n .\n more text\n\n')


class FormatTests(unittest.TestCase):
    def setUp(self):
        self.change = RevisionChange('nginx', 'amd64', '1.2.3-1', '1.2.3-2')
        self.data = b'archive-content'
        self.text = record(self.change, self.data)

    def test_record_uses_size_sha256_and_exact_control_identity(self):
        value = stage.metadata(self.text, self.change)
        self.assertEqual(value.size, len(self.data))
        self.assertEqual(value.sha256, hashlib.sha256(self.data).hexdigest())
        self.assertEqual(value.filename, 'nginx_1.2.3-2_amd64.deb')

    def test_missing_duplicate_malformed_and_other_package_rejected(self):
        for text in (self.text + self.text, self.text.replace('Size:', 'Other:'),
                     self.text.replace('Size:', 'size: 20\nSize:'),
                     self.text.replace('SHA256:', 'MD5sum:'), self.text.replace('amd64', 'arm64'),
                     self.text.replace('Package: nginx', 'Package: other'),
                     self.text.replace('Version: 1.2.3-2', 'Version: 1.2.3-3'),
                     self.text.replace('Size: 15', 'Size: 00'), self.text.replace('Size: 15', 'Size: 999999999'),
                     self.text.replace('Filename: pool/', 'Filename: https://invalid/'),
                     self.text.replace('/n/nginx/', '/n/../'), self.text.replace('/n/nginx/', '/n//'),
                     self.text.replace('SHA256: ', 'SHA256: abc\n '), '\tbad\n' + self.text,
                     'not-a-field\n' + self.text, self.text + 'body', self.text + '\0'):
            with self.subTest(text=text), self.assertRaises(PreparationError):
                stage.metadata(text, self.change)

    def test_config_separates_download_state_and_real_install_marks(self):
        download = stage.configuration(WORK).decode()
        install = stage.configuration(WORK, install=True).decode()
        self.assertIn(WORK + '/state/extended_states', download)
        self.assertNotIn(WORK + '/state/extended_states', install)
        self.assertIn('Dir::State::extended_states "/var/lib/apt/extended_states"', install)
        for text in (download, install):
            self.assertIn('Acquire::https::Verify-Peer "true"', text)
            self.assertIn('APT::Get::AllowUnauthenticated "false"', text)
            self.assertIn(WORK + '/etc/parts', text)
            self.assertNotIn('/etc/apt/apt.conf', text)
        for value in ('/tmp/path', WORK + '/../other', WORK + '\n'):
            with self.assertRaises(PreparationError):
                stage.configuration(value)

    def test_command_gate_no_install_or_options_or_unsorted_duplicate_pins(self):
        pins = ('nginx=1.2.3-2',)
        c = stage.DownloadCommand((*stage.DOWNLOAD, *pins), capture_stderr=True, workspace=WORK, pins=pins)
        c.validate()
        for argv in (tuple(a for a in c.argv if a != '--download-only'), (*c.argv, '-o', 'evil=true'),
                     ('apt-get', 'upgrade'), ('apt-get', 'download', *pins),
                     ('apt-cache', '--no-all-versions', 'show', 'nginx=9.9-1')):
            with self.subTest(argv=argv), self.assertRaises(PreparationError):
                replace(c, argv=argv).validate()
        for altered in (replace(c, pins=pins + pins), replace(c, pins=('nginx=1;evil',)),
                        replace(c, capture_stderr=False), replace(c, timeout=True), replace(c, timeout=601),
                        replace(c, env=(('APT_CONFIG', '/evil'),)), replace(c, workspace='/tmp/x')):
            with self.assertRaises(PreparationError):
                altered.validate()

    def test_deb_command_is_field_only_with_fixed_path(self):
        c = stage.ArchiveCommand(('dpkg-deb', '--field', WORK + '/cache/archives/a.deb',
                                  'Package', 'Version', 'Architecture'), workspace=WORK)
        c.validate()
        for altered in (replace(c, argv=('dpkg-deb', '--extract', '/evil', '/')),
                        replace(c, argv=(*c.argv[:2], '/tmp/a.deb', *c.argv[3:])),
                        replace(c, argv=(*c.argv[:2], WORK + '/cache/archives/../a.deb', *c.argv[3:])),
                        replace(c, capture_stderr=True), replace(c, timeout=31)):
            with self.assertRaises(PreparationError):
                altered.validate()


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.files = HostFiles(self.root)
        self.addCleanup(self.files.close)
        self.file = self.root / 'data.deb'
        self.file.write_bytes(b'x' * (1024**2 + 3))
        self.file.chmod(0o644)

    def test_hash_streaming_and_bound(self):
        result = stage.fingerprint(self.files, '/data.deb', limit=2 * 1024**2)
        self.assertEqual(result[1], hashlib.sha256(self.file.read_bytes()).hexdigest())
        with self.assertRaises(PreparationError):
            stage.fingerprint(self.files, '/data.deb', limit=1)

    def test_links_permissions_directories_and_fifo_refused(self):
        for kind in ('link', 'hardlink', 'writable', 'executable', 'directory', 'fifo'):
            with self.subTest(kind=kind):
                target = self.root / kind
                if kind == 'link':
                    target.symlink_to(self.file)
                elif kind == 'hardlink':
                    os.link(self.file, target)
                elif kind == 'directory':
                    target.mkdir()
                elif kind == 'fifo':
                    os.mkfifo(target)
                else:
                    target.write_bytes(b'x')
                    target.chmod(0o666 if kind == 'writable' else 0o755)
                with self.assertRaises((PreparationError, OSError)):
                    stage.fingerprint(self.files, '/' + kind, limit=2 * 1024**2)
                if kind == 'directory':
                    target.rmdir()
                else:
                    target.unlink()

    def test_optional_absence_does_not_accept_broken_symlink(self):
        self.assertIsNone(stage.fingerprint(self.files, '/missing', limit=100, optional=True))
        (self.root / 'missing').symlink_to('/missing-target')
        with self.assertRaises(OSError):
            stage.fingerprint(self.files, '/missing', limit=100, optional=True)

    def test_mid_read_replacement_is_detected(self):
        real = os.stat
        def changed(*args, **kwargs):
            if args and args[0] == 'data.deb' and kwargs.get('dir_fd') is not None:
                self.file.unlink()
                self.file.write_bytes(b'x' * (1024**2 + 3))
                self.file.chmod(0o644)
            return real(*args, **kwargs)
        with patch('snellctl.packagedownload.os.stat', side_effect=changed), self.assertRaises(PreparationError):
            stage.fingerprint(self.files, '/data.deb', limit=2 * 1024**2)


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_maintenance.MaintenanceTests('test_complete_inventory_not_update_or_health_authority')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.host, self.prep, self.tokens = self.fixture.host, self.fixture.prep, self.fixture.tokens
        self.files = self.prep.files
        self.selected = dict(self.host.versions)
        old = self.selected['nginx']
        self.selected['nginx'] = '1.2.3-1+deb13u2'
        self.job = JobSpec('b' * 32, tuple(RevisionChange(n, ARCHITECTURES[n], old, self.selected['nginx'])
                                          for n in ('nginx', 'nginx-common')))
        self.data = {c.name: (c.name + '-synthetic-deb').encode() for c in self.job.changes}
        self.calls, self.interceptor = [], None
        self.host.local_override = self.reply
        self.engine = stage.PackageDownloads(self.tokens)
        with self.files.directory('/var/lib/apt', create=True):
            pass
        self.files.write_new(stage.EXTENDED, b'Package: nginx-common\nAuto-Installed: 1\n\n', mode=0o644)

    def path(self, value):
        return self.host.root / value.lstrip('/')

    def reply(self, c):
        self.calls.append(c)
        if self.interceptor:
            result = self.interceptor(c)
            if result is not None:
                return result
        if c.argv == ALL_PACKAGES:
            versions = {**self.host.versions, 'nginx-common': self.host.versions['nginx']}
            return Reply(0, ''.join(f'{n}\t{ARCHITECTURES[n]}\tii \t{v}\n' for n, v in versions.items()))
        if c.argv[:2] == ('dpkg', '--compare-versions'):
            return Reply(0)
        if type(c) is stage.DownloadCommand:
            if c.argv[:2] == ('apt-get', 'update'):
                self.files.write_new(WORK + '/lists/debian_InRelease', b'synthetic-authenticated-index', mode=0o644)
                return Reply(0)
            if c.argv[:2] == ('apt-cache', 'policy'):
                return Reply(0, ''.join(f'{n}:\n  Installed: {self.host.versions[n]}\n  Candidate: {v}\n'
                                       for n, v in self.selected.items()))
            if c.argv[:2] == ('apt-cache', 'madison'):
                return Reply(0, ''.join(f'{n} | {self.selected.get(n, self.selected["nginx"])} | {ORIGIN}\n'
                                       for n in c.argv[2:]))
            if c.argv[:3] == ('apt-cache', '--no-all-versions', 'show'):
                change = next(a for a in self.job.changes if c.argv[3] == a.name + '=' + a.after)
                return Reply(0, record(change, self.data[change.name]))
            if '--simulate' in c.argv:
                return Reply(0, simulated(self.job.changes))
            if '--download-only' in c.argv:
                for change in self.job.changes:
                    name = change.name + '_apt-cache-name.deb'
                    self.files.write_new(WORK + '/cache/archives/' + name, self.data[change.name], mode=0o644)
                return Reply(0)
            raise AssertionError('unexpected download command')
        if type(c) is stage.ArchiveCommand:
            change = next(a for a in self.job.changes if c.argv[2].endswith('/' + a.name + '_apt-cache-name.deb'))
            return Reply(0, control(change))
        return self.fixture.unit_reply(c)

    def run_stage(self):
        return self.engine.stage(self.job, consent=True)

    def test_success_refreshes_before_download_and_never_installs_or_controls_services(self):
        batch = self.run_stage()
        batch.verify(self.files)
        self.assertEqual(len(batch.archives), 2)
        actions = [c.argv for c in self.calls if c.argv[0] == 'apt-get']
        self.assertEqual(actions[0], ('apt-get', 'update', '--error-on=any'))
        self.assertEqual(sum('--download-only' in a for a in actions), 1)
        self.assertEqual(sum('--simulate' in a for a in actions), 2)
        self.assertTrue(all(a[1] in {'update', '--simulate', '--download-only'} for a in actions))
        self.assertFalse(any(c.argv[0] == 'systemctl' and c.argv[1] != 'show' for c in self.calls))
        self.assertFalse(any(c.argv[0] in {'certbot', 'ufw', 'iptables'} for c in self.calls))
        self.assertIsNone(self.files.info(STATE + '/package-update-intent.json'))
        self.assertIsNone(self.files.info(self.job.unit_path))

    def test_consent_required_before_any_work(self):
        with self.assertRaises(PreparationError):
            self.engine.stage(self.job)
        self.assertEqual(self.calls, [])
        self.assertIsNone(self.files.info(WORK))

    def test_existing_cache_is_not_adopted_or_retried(self):
        self.run_stage()
        self.calls.clear()
        with self.assertRaises(PreparationError):
            self.run_stage()
        self.assertFalse(any(type(c) is stage.DownloadCommand for c in self.calls))

    def test_refresh_failure_does_not_download(self):
        self.interceptor = lambda c: Reply(100, 'private-error') if c.argv[:2] == ('apt-get', 'update') else None
        with self.assertRaises(PreparationError) as error:
            self.run_stage()
        self.assertNotIn('private-error', str(error.exception))
        self.assertFalse(any('--download-only' in c.argv for c in self.calls))

    def test_refresh_warning_fails_closed(self):
        self.interceptor = lambda c: Reply(0, ' W: unsigned index\n') if c.argv[:2] == ('apt-get', 'update') else None
        with self.assertRaises(PreparationError):
            self.run_stage()

    def test_refresh_uncertainty_fails_closed(self):
        self.interceptor = lambda c: Reply(0, uncertain=True) if c.argv[:2] == ('apt-get', 'update') else None
        with self.assertRaises(PreparationError):
            self.run_stage()

    def test_new_dependency_or_incomplete_scope_refused_before_download(self):
        self.interceptor = lambda c: Reply(0, simulated(self.job.changes[:1])) if '--simulate' in c.argv else None
        with self.assertRaises(PreparationError):
            self.run_stage()
        self.assertFalse(any('--download-only' in c.argv for c in self.calls))

    def test_nonofficial_origin_refused(self):
        self.interceptor = lambda c: Reply(0, 'nginx | 1.2.3-1+deb13u2 | https://untrusted.invalid\n') if c.argv[:2] == ('apt-cache', 'madison') else None
        with self.assertRaises(PreparationError):
            self.run_stage()

    def test_no_remaining_changes_does_not_trigger_same_version_download(self):
        self.interceptor = lambda c: Reply(0, simulated(())) if '--simulate' in c.argv else None
        with self.assertRaises(PreparationError):
            self.run_stage()
        self.assertFalse(any('--download-only' in c.argv for c in self.calls))

    def test_download_failure_retains_cache_but_no_install_config(self):
        self.interceptor = lambda c: Reply(-1, uncertain=True) if '--download-only' in c.argv else None
        with self.assertRaises(PreparationError):
            self.run_stage()
        self.assertIsNotNone(self.files.info(WORK))
        self.assertIsNone(self.files.info(self.job.apt_config))

    def test_success_exit_without_all_archives_is_failure(self):
        self.interceptor = lambda c: Reply(0) if '--download-only' in c.argv else None
        with self.assertRaises(PreparationError):
            self.run_stage()

    def test_wrong_archive_bytes_are_rejected_before_dpkg_deb(self):
        def corrupt(c):
            if '--download-only' in c.argv:
                self.files.write_new(WORK + '/cache/archives/a.deb', b'corrupt', mode=0o644)
                return Reply(0)
        self.interceptor = corrupt
        with self.assertRaises(PreparationError):
            self.run_stage()
        self.assertFalse(any(c.argv[0] == 'dpkg-deb' for c in self.calls))

    def test_internal_package_identity_must_match_hash_bound_metadata(self):
        self.interceptor = lambda c: Reply(0, 'Package: other\nVersion: 1\nArchitecture: all\n') if c.argv[0] == 'dpkg-deb' else None
        with self.assertRaises(PreparationError):
            self.run_stage()
        self.assertIsNone(self.files.info(self.job.apt_config))

    def test_final_simulation_rechecks_complete_actions(self):
        seen = 0
        def mutate(c):
            nonlocal seen
            if '--simulate' in c.argv:
                seen += 1
                if seen == 2:
                    return Reply(0, simulated(()))
        self.interceptor = mutate
        with self.assertRaises(PreparationError):
            self.run_stage()
        self.assertEqual(seen, 2)

    def test_auto_marks_changed_during_download_rejected(self):
        def mutate(c):
            if c.argv[0] == 'dpkg-deb':
                self.path(stage.EXTENDED).write_bytes(b'changed')
        self.interceptor = mutate
        with self.assertRaises(PreparationError):
            self.run_stage()
        self.assertIsNone(self.files.info(self.job.apt_config))

    def tamper(self, target):
        batch = self.run_stage()
        batch.verify(self.files)
        self.path(target).write_bytes(b'tampered')
        with self.assertRaises(PreparationError):
            batch.verify(self.files)

    def test_verify_detects_subsequent_archive_change(self):
        self.tamper(WORK + '/cache/archives/nginx_apt-cache-name.deb')

    def test_verify_detects_subsequent_index_change(self):
        self.tamper(WORK + '/lists/debian_InRelease')

    def test_verify_detects_subsequent_install_config_change(self):
        self.tamper(WORK + '/install.conf')

    def test_verify_detects_subsequent_download_config_change(self):
        self.tamper(WORK + '/apt.conf')

    def test_verify_detects_subsequent_auto_marks_change(self):
        self.tamper(stage.EXTENDED)

    def test_sandbox_hook_injection_is_rejected_before_download(self):
        def tamper(c):
            if '--simulate' in c.argv:
                self.files.write_new(WORK + '/etc/parts/extra', b'DPkg::Pre-Invoke { "evil"; };', mode=0o644)
        self.interceptor = tamper
        with self.assertRaises(PreparationError):
            self.run_stage()
        self.assertFalse(any('--download-only' in c.argv for c in self.calls))

    def test_symlinked_partial_cache_not_followed(self):
        def tamper(c):
            if '--simulate' in c.argv:
                path = self.path(WORK + '/cache/archives/partial')
                path.symlink_to('/tmp')
        self.interceptor = tamper
        with self.assertRaises(PreparationError):
            self.run_stage()

    def test_locked_stage_rejects_parallel_management(self):
        def inspect(c):
            if '--download-only' in c.argv:
                with self.assertRaises(PreparationError):
                    with self.prep._lock():
                        self.fail('lock incorrectly acquired twice')
        self.interceptor = inspect
        self.run_stage()

    def test_installed_database_drift_during_download_rejected(self):
        def tamper(c):
            if c.argv[0] == 'dpkg-deb':
                self.path('/var/lib/dpkg/status').write_bytes(b'changed-status')
        self.interceptor = tamper
        with self.assertRaises(Exception):
            self.run_stage()
        self.assertIsNone(self.files.info(self.job.apt_config))

    def test_extra_archive_and_symlink_rejected(self):
        batch = self.run_stage()
        path = WORK + '/cache/archives/extra.deb'
        self.files.write_new(path, b'extra', mode=0o644)
        with self.assertRaises(PreparationError):
            batch.verify(self.files)
        self.path(path).unlink()
        self.path(path).symlink_to('/etc/passwd')
        with self.assertRaises(PreparationError):
            batch.verify(self.files)

    def test_interruption_restores_runner_not_services_or_cache(self):
        original = self.prep.runner
        def interrupt(c):
            if '--download-only' in c.argv:
                raise KeyboardInterrupt
        self.interceptor = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.run_stage()
        self.assertIs(self.prep.runner, original)
        self.assertIsNotNone(self.files.info(WORK))
        self.assertIsNone(self.files.info(self.job.apt_config))


class AdapterTests(unittest.TestCase):
    def test_archive_adapter_runs_only_fixed_field_query(self):
        command = stage.ArchiveCommand(('dpkg-deb', '--field', WORK + '/cache/archives/a.deb',
                                         'Package', 'Version', 'Architecture'), workspace=WORK)
        real = subprocess.Popen
        def harmless(args, **kwargs):
            self.assertEqual(args, ['/usr/bin/dpkg-deb', *command.argv[1:]])
            self.assertNotIn('APT_CONFIG', kwargs['env'])
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            return real([sys.executable, '-c', "print('Package: nginx')"], **kwargs)
        with patch.object(stage.ArchiveCommand, 'verify_files') as checked, \
             patch('snellctl.hostcommands.subprocess.Popen', side_effect=harmless):
            result = object.__new__(DebianCommands)(command)
        checked.assert_called_once()
        self.assertEqual(result.code, 0)

    def test_typed_archive_extract_request_rejected_before_process_start(self):
        command = stage.ArchiveCommand(('dpkg-deb', '--extract', WORK + '/cache/archives/a.deb', '/'), workspace=WORK)
        with patch('snellctl.hostcommands.subprocess.Popen') as spawn, self.assertRaises(PreparationError):
            object.__new__(DebianCommands)(command)
        spawn.assert_not_called()

    def test_download_uses_fixed_apt_config_and_no_inherited_environment(self):
        command = stage.DownloadCommand((*stage.DOWNLOAD, 'nginx=1.2.3-2'), capture_stderr=True,
                                         workspace=WORK, pins=('nginx=1.2.3-2',))
        real = subprocess.Popen
        def harmless(args, **kwargs):
            self.assertEqual(args, ['/usr/bin/apt-get', *command.argv[1:]])
            self.assertEqual(kwargs['env']['APT_CONFIG'], WORK + '/apt.conf')
            self.assertNotIn('http_proxy', kwargs['env'])
            return real([sys.executable, '-c', "print('download only')"], **kwargs)
        with patch.object(stage.DownloadCommand, 'verify_files') as checked, \
             patch('snellctl.hostcommands.subprocess.Popen', side_effect=harmless), \
             patch.dict(os.environ, {'http_proxy': 'private', 'APT_CONFIG': '/evil'}):
            result = object.__new__(DebianCommands)(command)
        checked.assert_called_once()
        self.assertEqual(result.code, 0)

    def test_plain_dpkg_deb_commands_never_launch(self):
        with patch('snellctl.hostcommands.subprocess.Popen') as spawn, self.assertRaises(PreparationError):
            object.__new__(DebianCommands)(Command(('dpkg-deb', '--extract', '/package.deb', '/')))
        spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
