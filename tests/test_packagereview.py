from dataclasses import replace
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from snellctl import packagecontents as contents
from snellctl import packagereview as review
from snellctl.hostcommands import DebianCommands
from snellctl.hostprep import Command, PreparationError, Reply
from snellctl.packageplan import ALL_PACKAGES
from snellctl.packageprompts import PackagePrompts
from test_packagedownload import control
import test_packagesubmit


def tar_bytes(entries):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data, kind in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
            if kind == tarfile.REGTYPE:
                member.size = len(data)
            elif kind in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                member.linkname = data.decode()
            archive.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return out.getvalue()


def section(entries, kind='--ctrl-tarfile'):
    return contents.inspect_tar(io.BytesIO(tar_bytes(entries)), kind)


class ContentsTests(unittest.TestCase):
    def test_reads_scripts_and_hashes_without_running_or_extracting(self):
        script = b'#!/bin/sh\nexit 99\n'
        value = json.loads(section([('./', b'', tarfile.DIRTYPE),
            ('./control', b'Package: certbot\n', tarfile.REGTYPE), ('./postinst', script, tarfile.REGTYPE)]))
        row = value['entries'][2]
        self.assertEqual(row['text'], script.decode())
        self.assertEqual(row['sha256'], hashlib.sha256(script).hexdigest())
        self.assertEqual(row['uid'], 0)

    def test_terminal_escape_in_script_is_json_escaped(self):
        text = section([('control', b'Package: certbot\n', tarfile.REGTYPE),
                        ('postinst', b'\x1b[2J\rnot a prompt\n', tarfile.REGTYPE)])
        self.assertNotIn('\x1b', text)
        self.assertIn('\\u001b', text)
        self.assertNotIn('\r', text)

    def test_payload_lists_links_without_following_them(self):
        text = section([('usr/bin/example', b'\x00\xffbinary', tarfile.REGTYPE),
                        ('usr/bin/link', b'/etc/private-not-opened', tarfile.SYMTYPE)], '--fsys-tarfile')
        rows = json.loads(text)['entries']
        self.assertNotIn('text', rows[0])
        self.assertEqual(rows[1]['target'], '/etc/private-not-opened')

    def test_unsafe_paths_and_duplicate_entries_are_rejected(self):
        for name in ('../escape', '/absolute', 'a/../b', 'a//b', 'a/./b', 'a\x1bb'):
            with self.subTest(name=name), self.assertRaises(PreparationError):
                section([(name, b'x', tarfile.REGTYPE)], '--fsys-tarfile')
        with self.assertRaises(PreparationError):
            section([('control', b'a', tarfile.REGTYPE), ('./control', b'a', tarfile.REGTYPE)])

    def test_unknown_control_names_or_links_are_rejected(self):
        for name, data, kind in [('new-hook', b'x', tarfile.REGTYPE),
                                 ('postinst', b'/outside', tarfile.SYMTYPE), ('pipe', b'', tarfile.FIFOTYPE)]:
            with self.subTest(name=name), self.assertRaises(PreparationError):
                section([('control', b'x', tarfile.REGTYPE), (name, data, kind)])

    def test_absolute_and_redundant_directory_names_are_rejected(self):
        for name in ('/', '//', '/etc/', 'a//'):
            with self.subTest(name=name), self.assertRaises(PreparationError):
                contents.path_name(name, directory=True)

    def test_missing_end_markers_are_rejected(self):
        data = tar_bytes([('control', b'ok', tarfile.REGTYPE)])
        with self.assertRaises(PreparationError):
            contents.inspect_tar(io.BytesIO(data[:1024]), '--ctrl-tarfile')

    def test_pax_extensions_require_separate_review(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w', format=tarfile.PAX_FORMAT) as archive:
            item = tarfile.TarInfo('control')
            item.size = 2
            item.pax_headers = {'comment': 'extended metadata'}
            archive.addfile(item, io.BytesIO(b'ok'))
        with self.assertRaises(PreparationError):
            contents.inspect_tar(io.BytesIO(out.getvalue()), '--ctrl-tarfile')

    def test_empty_links_and_sparse_entries_are_rejected(self):
        for entry in [('empty-link', b'', tarfile.SYMTYPE), ('sparse', b'', tarfile.GNUTYPE_SPARSE)]:
            with self.subTest(entry=entry), self.assertRaises(PreparationError):
                section([entry], '--fsys-tarfile')

    def test_missing_control_and_non_utf8_scripts_are_rejected(self):
        for entries in [[('postinst', b'x', tarfile.REGTYPE)],
                        [('control', b'\xff', tarfile.REGTYPE)], [('control', b'\x00', tarfile.REGTYPE)]]:
            with self.assertRaises((PreparationError, UnicodeError)):
                section(entries)

    def test_text_and_entry_budgets_fail_without_truncation(self):
        with patch.object(contents, 'TEXT_LIMIT', 3), self.assertRaises(PreparationError):
            section([('control', b'four', tarfile.REGTYPE)])
        with self.assertRaises(PreparationError):
            section([(f'f{i}', b'', tarfile.REGTYPE) for i in range(10001)], '--fsys-tarfile')

    def test_second_tar_archive_after_end_is_not_ignored(self):
        one = tar_bytes([('control', b'ok', tarfile.REGTYPE)])
        two = tar_bytes([('postinst', b'hidden', tarfile.REGTYPE)])
        with self.assertRaises(PreparationError):
            contents.inspect_tar(io.BytesIO(one + two), '--ctrl-tarfile')

    def test_truncated_tar_is_rejected(self):
        payload = tar_bytes([('control', b'a' * 4096, tarfile.REGTYPE)])
        with self.assertRaises((PreparationError, tarfile.TarError)):
            contents.inspect_tar(io.BytesIO(payload[:1000]), '--ctrl-tarfile')

    def test_decoder_output_and_time_are_bounded(self):
        for script, limit, timeout in [("print('x'*10000)", 512, 5),
                                        ('import time;time.sleep(5)', 512, 0.05)]:
            with subprocess.Popen([sys.executable, '-c', script], stdout=subprocess.PIPE,
                                  start_new_session=True) as process, tempfile.TemporaryFile() as output:
                try:
                    with self.assertRaises(PreparationError):
                        contents._capture(process, output, limit=limit, timeout=timeout)
                    self.assertLessEqual(output.tell(), limit)
                finally:
                    DebianCommands._stop(process)
                    process.stdout.close()

    def test_decoder_exit_failure_is_not_a_partial_report(self):
        with subprocess.Popen([sys.executable, '-c', "print('partial');raise SystemExit(1)"],
                              stdout=subprocess.PIPE, start_new_session=True) as process, tempfile.TemporaryFile() as out:
            try:
                with self.assertRaises(PreparationError):
                    contents._capture(process, out, limit=1024, timeout=5)
            finally:
                DebianCommands._stop(process)
                process.stdout.close()


class MaterialTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_packagesubmit.SubmissionTests('test_submit_once_records_private_files_and_never_runs_foreground_install')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.host, self.prep, self.batch = self.fixture.host, self.fixture.prep, self.fixture.batch
        self.files = self.prep.files
        self.old_script = '#!/bin/sh\nexit 0\n'
        self.new_script = '#!/bin/sh\necho candidate\n'
        self.control_version = self.batch.job.changes[0].after
        self.extra_payload = []
        self.intercept = None
        self.fixture.interceptor = self.reply

    def reply(self, command):
        if self.intercept:
            result = self.intercept(command)
            if result is not None:
                return result
        if type(command) is contents.ContentsCommand:
            if command.argv[1] == '--ctrl-tarfile':
                identity = control(replace(self.batch.job.changes[0], after=self.control_version))
                entries = [('control', identity.encode(), tarfile.REGTYPE),
                           ('postinst', self.new_script.encode(), tarfile.REGTYPE)]
            else:
                entries = [('usr/bin/certbot', b'not executed', tarfile.REGTYPE), *self.extra_payload]
            return Reply(0, section(entries, command.argv[1]))
        if command.argv[:2] == ('dpkg-query', '--control-list'):
            return Reply(0, 'list\npostinst\n')
        if command.argv[:2] == ('dpkg-query', '--control-show'):
            return Reply(0, self.old_script if command.argv[-1] == 'postinst' else '/usr/bin/certbot\n')

    def collect(self):
        return review.collect(self.prep, self.batch)

    def test_material_contains_old_new_scripts_and_manifest_not_an_approval(self):
        material = self.collect()
        data = json.loads(material.document)
        self.assertTrue(data['local_review_only_do_not_publish'])
        self.assertFalse(data['security_audit_passed'])
        row = data['packages'][0]
        self.assertEqual(row['comparison']['postinst'], 'changed')
        self.assertEqual(row['comparison']['preinst'], 'absent')
        self.assertIn('candidate_file_manifest', row)
        self.assertFalse(material.summary()['installation_authorized'])
        self.assertNotIn('exit 0', json.dumps(material.summary()))
        material.verify(self.prep)
        self.assertTrue(all(c.argv[0] in {'dpkg-query', 'dpkg-deb'} for c in self.host.calls))
        self.assertFalse(self.prep._exists('package-update-intent'))

    def test_matching_script_is_not_reported_changed(self):
        self.new_script = self.old_script
        self.assertEqual(json.loads(self.collect().document)['packages'][0]['comparison']['postinst'], 'unchanged')

    def test_existing_module_config_is_not_silently_approved(self):
        self.host.write(review.MODULES + '/50-extra.conf', b'load_module extra.so;\n', 0o644)
        with self.assertRaises(PreparationError):
            self.collect()

    def test_module_package_even_if_not_enabled_blocks(self):
        original = self.fixture.reply
        def intercept(command):
            if command.argv == ALL_PACKAGES:
                self.fixture.interceptor = None
                try:
                    result = original(command)
                finally:
                    self.fixture.interceptor = self.reply
                return Reply(0, result.output + 'libnginx-mod-extra\tamd64\tii \t1.0-1\n')
        self.intercept = intercept
        with self.assertRaises(PreparationError):
            self.collect()

    def test_candidate_dynamic_module_blocks(self):
        for name in ('usr/lib/nginx/modules/extra.so', 'etc/nginx/modules-enabled/extra.conf', 'usr/lib/nginx/modules'):
            self.extra_payload = [(name, b'unsupported', tarfile.REGTYPE)]
            with self.subTest(name=name), self.assertRaises(PreparationError):
                self.collect()

    def test_archive_identity_is_checked_again(self):
        self.control_version = '4.0.0-2+deb13u99'
        with self.assertRaises(PreparationError):
            self.collect()

    def test_unknown_installed_control_files_block(self):
        self.intercept = lambda c: Reply(0, 'list\nunknown-new-hook\n') if c.argv[:2] == ('dpkg-query', '--control-list') else None
        with self.assertRaises(PreparationError):
            self.collect()

    def test_failed_or_uncertain_archive_inspection_blocks(self):
        for result in (Reply(1, 'PRIVATE'), Reply(0, '{}', uncertain=True), Reply(0, '{}')):
            self.intercept = lambda c: result if type(c) is contents.ContentsCommand else None
            with self.assertRaises(PreparationError):
                self.collect()

    def test_installed_script_changed_after_review_is_rejected(self):
        material = self.collect()
        self.old_script += '# changed\n'
        with self.assertRaises(PreparationError):
            material.verify(self.prep)

    def test_module_added_after_review_is_rejected(self):
        material = self.collect()
        self.host.write(review.MODULES + '/new.conf', b'new', 0o644)
        with self.assertRaises(PreparationError):
            material.verify(self.prep)

    def test_cached_archive_changed_after_review_is_rejected(self):
        material = self.collect()
        self.host.path(self.batch.paths_and_fingerprints[0][0]).write_bytes(b'changed')
        with self.assertRaises(PreparationError):
            material.verify(self.prep)

    def test_pending_operation_blocks_collection(self):
        self.prep._record('token-change-intent', {'format': 1})
        with self.assertRaises(PreparationError):
            self.collect()
        self.assertEqual(self.host.calls, [])

    def test_contents_command_cannot_select_another_path_or_action(self):
        path, stamp = self.batch.paths_and_fingerprints[0]
        command = contents.ContentsCommand(('dpkg-deb', '--ctrl-tarfile', path),
                    workspace=review.CACHE + '/' + self.batch.job.job_id, expected=stamp)
        command.verify_files(self.files)
        for changed in (replace(command, argv=('dpkg-deb', '--extract', path)),
                        replace(command, argv=('dpkg-deb', '--ctrl-tarfile', '/outside.deb')),
                        replace(command, expected=()), replace(command, capture_stderr=True),
                        replace(command, timeout=60)):
            with self.assertRaises(PreparationError):
                changed.verify_files(self.files)

    def test_live_adapter_routes_only_typed_readonly_content_command(self):
        path, stamp = self.batch.paths_and_fingerprints[0]
        command = contents.ContentsCommand(('dpkg-deb', '--ctrl-tarfile', path),
                    workspace=review.CACHE + '/' + self.batch.job.job_id, expected=stamp)
        with patch.object(contents, 'inspect_command', return_value=Reply(0, 'inspected')) as run:
            result = object.__new__(DebianCommands)(command)
            self.assertEqual(result.output, 'inspected')
            run.assert_called_once()
        with self.assertRaises(PreparationError):
            object.__new__(DebianCommands)(Command(command.argv))

    def test_inspection_adapter_rechecks_archive_and_closes_decoder(self):
        path, stamp = self.batch.paths_and_fingerprints[0]
        command = contents.ContentsCommand(('dpkg-deb', '--ctrl-tarfile', path),
                    workspace=review.CACHE + '/' + self.batch.job.job_id, expected=stamp)
        payload = tar_bytes([('control', b'Package: certbot\n', tarfile.REGTYPE)])
        real = subprocess.Popen
        script = 'import sys;sys.stdout.buffer.write(' + repr(payload) + ')'
        with patch.object(contents.subprocess, 'Popen', side_effect=lambda *_a, **kw: real([sys.executable, '-c', script], **kw)):
            result = contents.inspect_command(command, self.files, DebianCommands._stop)
        self.assertEqual(result.code, 0)
        self.assertEqual(json.loads(result.output)['entries'][0]['path'], 'control')


class PromptTests(unittest.TestCase):
    def setUp(self):
        from test_packagejob import spec
        self.job, self.lines, self.questions = spec(), [], []
        self.answer, self.tty = 'y', True
        self.ui = self

    def interactive(self):
        return self.tty

    def say(self, text):
        self.lines.append(text)

    def ask(self, question):
        self.questions.append(question)
        return self.answer

    def test_all_questions_default_no_and_require_ascii_y(self):
        prompt = PackagePrompts(self.ui, self.job)
        for answer, expected in [('y', True), ('Y', True), ('', False), ('yes', False), ('是', False), ('n', False)]:
            self.answer = answer
            for stage in ('download', 'outage', 'install', 'restore', 'dns-test', 'renewal'):
                self.assertEqual(prompt(stage), expected)
        self.assertTrue(all('[y/n]' in q and '默认 n' in q for q in self.questions))

    def test_noninteractive_or_unknown_stage_refused(self):
        prompt = PackagePrompts(self.ui, self.job)
        with self.assertRaises(PreparationError):
            prompt('arbitrary')
        self.tty = False
        with self.assertRaises(PreparationError):
            prompt('install')
        with self.assertRaises(PreparationError):
            PackagePrompts(self.ui, self.job)


if __name__ == '__main__':
    unittest.main()
