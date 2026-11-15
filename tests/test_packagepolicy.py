from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import Mock

from snellctl.hostprep import PreparationError, Reply
from snellctl.packagepolicy import RevisionChange, revision_scope, upstream
from snellctl.preflight import DEPENDENCIES


class RevisionScopeTests(unittest.TestCase):
    def setUp(self):
        self.installed = {
            ('ca-certificates', 'all'): ('20250419+deb13u1', False),
            ('nginx', 'amd64'): ('1.26.3-3+deb13u9', False),
            ('nginx-common', 'all'): ('1.26.3-3+deb13u9', False),
            ('certbot', 'all'): ('4.0.0-2+deb13u1', False),
            ('python3-certbot', 'all'): ('4.0.0-2+deb13u1', False),
            ('python3-certbot-dns-cloudflare', 'all'): ('4.0.0-1', False),
            ('openssh-server', 'amd64'): ('1:10.0-1', False),
        }
        self.selected = {n: v for (n, a), (v, held) in self.installed.items() if n in DEPENDENCIES}
        self.available = {n: {v} for (n, a), (v, held) in self.installed.items()}
        self.changes = []
        self.runner = Mock(return_value=Reply(0))

    def add(self, name, version):
        arch = next(a for n, a in self.installed if n == name)
        old = self.installed[(name, arch)][0]
        self.changes.append(dict(name=name, architecture=arch, installed=old, candidate=version))
        self.available[name].add(version)
        if name in self.selected:
            self.selected[name] = version

    def nginx(self):
        self.add('nginx', '1.26.3-3+deb13u10')
        self.add('nginx-common', '1.26.3-3+deb13u10')

    def check(self):
        return revision_scope(self.installed, self.selected, self.changes, self.available, self.runner)

    def test_no_change_does_not_compare_or_build_install_request(self):
        self.assertEqual(self.check(), ())
        self.runner.assert_not_called()

    def test_nginx_pair_and_dpkg_revision_order(self):
        self.nginx()
        result = self.check()
        self.assertEqual([c.name for c in result], ['nginx', 'nginx-common'])
        for call in self.runner.call_args_list:
            self.assertEqual(call.args[0].argv,
                ('dpkg', '--compare-versions', '1.26.3-3+deb13u10', 'gt', '1.26.3-3+deb13u9'))
        with self.assertRaises(FrozenInstanceError):
            result[0].after = 'latest'

    def test_scope_is_independent_of_input_order_and_mutation(self):
        self.nginx()
        first = self.check()
        self.changes.reverse()
        self.assertEqual(self.check(), first)
        self.changes[0]['candidate'] = '0'
        self.assertEqual(first[0].after, '1.26.3-3+deb13u10')

    def test_python_component_revision_with_existing_dependencies(self):
        self.add('certbot', '4.0.0-2+deb13u2')
        self.add('python3-certbot', '4.0.0-2+deb13u2')
        self.assertEqual(len(self.check()), 2)

    def test_unknown_dependency_including_ssh_is_refused(self):
        self.add('openssh-server', '1:10.0-2')
        with self.assertRaises(PreparationError):
            self.check()
        self.runner.assert_not_called()

    def test_new_installation_and_missing_installed_version_are_refused(self):
        self.changes = [dict(name='python3-acme', architecture='all', installed=None, candidate='4.0.0-2')]
        with self.assertRaises(PreparationError):
            self.check()
        self.changes[0]['installed'] = '4.0.0-1'
        with self.assertRaises(PreparationError):
            self.check()

    def test_held_direct_package_is_refused_even_without_updates(self):
        self.installed[('certbot', 'all')] = ('4.0.0-2+deb13u1', True)
        with self.assertRaises(PreparationError):
            self.check()

    def test_held_dependency_and_wrong_old_version_are_refused(self):
        self.nginx()
        self.installed[('nginx-common', 'all')] = ('1.26.3-3+deb13u9', True)
        with self.assertRaises(PreparationError):
            self.check()
        self.installed[('nginx-common', 'all')] = ('1.26.3-3+deb13u8', False)
        with self.assertRaises(PreparationError):
            self.check()

    def test_unrelated_hold_is_preserved_not_claimed_or_changed(self):
        self.installed[('openssh-server', 'amd64')] = ('1:10.0-1', True)
        self.nginx()
        self.assertEqual(len(self.check()), 2)
        self.assertTrue(self.installed[('openssh-server', 'amd64')][1])

    def test_upstream_or_epoch_change_requires_separate_review(self):
        for version in ('1.28.0-1', '1:1.26.3-3+deb13u10'):
            with self.subTest(version=version), self.assertRaises(PreparationError):
                RevisionChange('nginx', 'amd64', '1.26.3-3+deb13u9', version)

    def test_native_package_version_change_is_not_inferred_to_be_revision_only(self):
        self.add('ca-certificates', '20250419+deb13u2')
        with self.assertRaises(PreparationError):
            self.check()

    def test_versions_are_not_compared_lexically(self):
        self.nginx()
        for reply in (Reply(1), Reply(2), Reply(-1, uncertain=True), Reply(0, 'PRIVATE')):
            self.runner.return_value = reply
            with self.subTest(reply=reply), self.assertRaises(PreparationError) as caught:
                self.check()
            self.assertNotIn('PRIVATE', str(caught.exception))

    def test_missing_official_index_version_is_refused(self):
        self.nginx()
        self.available['nginx-common'] = {'1.26.3-3+deb13u9'}
        with self.assertRaises(PreparationError):
            self.check()

    def test_noop_candidate_still_requires_fresh_official_presence(self):
        self.available['certbot'] = set()
        with self.assertRaises(PreparationError):
            self.check()

    def test_missing_extra_or_mismatched_selected_targets_are_refused(self):
        for mode in ('missing', 'extra', 'unmatched'):
            original = dict(self.selected)
            if mode == 'missing':
                del self.selected['nginx']
            elif mode == 'extra':
                self.selected['openssh-server'] = '1:10.0-1'
            else:
                self.selected['nginx'] = '1.26.3-3+deb13u10'
                self.available['nginx'].add(self.selected['nginx'])
            with self.subTest(mode=mode), self.assertRaises(PreparationError):
                self.check()
            self.selected = original

    def test_duplicate_unknown_fields_and_same_version_are_refused(self):
        self.nginx()
        original = [dict(c) for c in self.changes]
        for mode in ('duplicate', 'unknown', 'same'):
            self.changes = [dict(c) for c in original]
            if mode == 'duplicate':
                self.changes.append(dict(self.changes[0]))
            elif mode == 'unknown':
                self.changes[0]['url'] = 'PRIVATE'
            else:
                self.changes[0]['candidate'] = self.changes[0]['installed']
            with self.subTest(mode=mode), self.assertRaises(PreparationError):
                self.check()

    def test_nginx_common_must_match_and_cannot_be_omitted(self):
        self.add('nginx', '1.26.3-3+deb13u10')
        with self.assertRaises(PreparationError):
            self.check()
        del self.installed[('nginx-common', 'all')]
        with self.assertRaises(PreparationError):
            self.check()

    def test_architecture_switch_or_multiarch_is_refused(self):
        self.nginx()
        self.changes[0]['architecture'] = 'arm64'
        with self.assertRaises(PreparationError):
            self.check()
        self.changes[0]['architecture'] = 'amd64'
        self.installed[('nginx', 'arm64')] = ('1.26.3-3+deb13u9', False)
        with self.assertRaises(PreparationError):
            self.check()

    def test_canonical_version_and_argument_boundaries(self):
        self.assertEqual(upstream('2:1.2.3-rc1-4'), ('2', '1.2.3-rc1'))
        for value in ('1;id', '1\nRestart=yes', '1%u', '1$HOME', 'latest', 'a:1.2-1', '1:2:3-1',
                      '1:', '1:a-1', '1.2-', '01:1.2-1'):
            with self.subTest(value=value), self.assertRaises(PreparationError):
                upstream(value)

    def test_malformed_database_is_not_authority(self):
        for value in (('1.0', 'false'), ('1.0', False, 'extra'), ('PRIVATE', False)):
            self.installed[('nginx', 'amd64')] = value
            with self.subTest(value=value), self.assertRaises(PreparationError):
                self.check()

    def test_same_revision_and_downgrade_cannot_be_used_as_update(self):
        with self.assertRaises(PreparationError):
            RevisionChange('nginx', 'amd64', '1.26.3-3', '1.26.3-3')
        self.add('certbot', '4.0.0-1')
        self.runner.return_value = Reply(1)
        with self.assertRaises(PreparationError):
            self.check()


if __name__ == '__main__':
    unittest.main()
