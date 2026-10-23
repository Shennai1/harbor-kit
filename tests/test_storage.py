from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import errno
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from snellctl.__main__ import main
from snellctl.deployment import NodeSecrets, NodeSpec, file_targets
from snellctl.storage import MARKER, NEXT, NODES, PENDING, STAGE, STATE, SandboxStore, StoreError, initialize


class Interrupted(Exception):
    pass


class StorageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / "sandbox"
        initialize(self.root)
        self.spec = NodeSpec("node.example.net")

    def fail_at(self, event, index=-1, occurrence=1):
        count = 0

        def checkpoint(store, current, current_index=-1):
            nonlocal count
            if (current, current_index) == (event, index):
                count += 1
                if count == occurrence:
                    raise Interrupted()
        return patch.object(SandboxStore, "_checkpoint", checkpoint)

    def prepare(self, root=None, spec=None):
        with SandboxStore(root or self.root) as store:
            return store.prepare(spec or self.spec)

    def recover(self, action, root=None):
        with SandboxStore(root or self.root) as store:
            return store.recover(action)

    def assert_complete(self, root=None):
        root = root or self.root
        with SandboxStore(root) as store:
            report = store.status()
            self.assertEqual(report["pending"], "none")
            self.assertEqual(report["nodes"], [{"node": "main", "state": "candidates-intact"}])
        for target in file_targets(self.spec):
            path = root / target.path[1:]
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), target.mode)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(path.stat().st_uid, os.geteuid())
        for path in (PENDING, NEXT, STAGE):
            self.assertFalse((root / path).exists())

    def parents_for(self, relative):
        with SandboxStore(self.root) as store, store.tree.directory(str(Path(relative).parent), create=True):
            pass
        return self.root / relative

    def test_create_permissions_metadata_and_no_secret_database(self):
        keys = NodeSecrets("a" * 64, "b" * 64)
        with patch("snellctl.storage.new_node_secrets", return_value=keys):
            self.assertEqual(self.prepare(), "created")
        self.assert_complete()
        for name in (MARKER, f"{STATE}/lock", f"{NODES}/main.json"):
            path = self.root / name
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn(keys.psk, path.read_text())
            self.assertNotIn(keys.shadowtls_password, path.read_text())
        for name in (STATE, NODES, "etc/snellctl", "etc/snellctl/nodes/main"):
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o700)

    def test_repeat_preserves_keys_files_and_lock_inode(self):
        self.prepare()
        paths = [self.root / item.path[1:] for item in file_targets(self.spec)]
        paths += [self.root / f"{NODES}/main.json", self.root / f"{STATE}/lock"]
        before = [(path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns) for path in paths]
        with patch("snellctl.storage.new_node_secrets", side_effect=AssertionError("new keys")):
            self.assertEqual(self.prepare(), "unchanged")
        self.assertEqual(before, [(path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns) for path in paths])

    def test_changed_parameters_are_not_an_update(self):
        self.prepare()
        with patch("snellctl.storage.new_node_secrets", side_effect=AssertionError("new keys")), self.assertRaises(StoreError) as error:
            self.prepare(spec=replace(self.spec, domain="changed.example.net"))
        self.assertEqual(error.exception.code, "node-exists")
        self.assert_complete()

    def test_unowned_file_never_overwritten_or_adopted(self):
        path = self.parents_for("etc/snellctl/nodes/main/snell.conf")
        path.write_text("existing-user-data")
        with patch("snellctl.storage.new_node_secrets", side_effect=AssertionError("new keys")), self.assertRaises(StoreError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, "conflict")
        self.assertEqual(path.read_text(), "existing-user-data")
        self.assertFalse((self.root / STAGE).exists())

    def test_file_appearing_during_publication_is_not_overwritten(self):
        path = self.root / "etc/snellctl/nodes/main/shadowtls.json"

        def checkpoint(store, event, index=-1):
            if (event, index) == ("published", 0):
                path.write_text("created-by-another-operation")

        with patch.object(SandboxStore, "_checkpoint", checkpoint), self.assertRaises(StoreError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, "conflict")
        self.assertEqual(path.read_text(), "created-by-another-operation")
        self.assertTrue((self.root / PENDING).exists())
        for action in ("resume", "rollback"):
            with self.subTest(action=action), self.assertRaises(StoreError):
                self.recover(action)
        self.assertTrue((self.root / "etc/snellctl/nodes/main/snell.conf").exists())

    def test_identical_foreign_file_appearing_during_publication_is_not_adopted(self):
        path = self.root / "etc/snellctl/nodes/main/shadowtls.json"

        def checkpoint(store, event, index=-1):
            if (event, index) == ("published", 0):
                path.write_bytes((self.root / STAGE / "1").read_bytes())
                path.chmod(0o600)

        with patch.object(SandboxStore, "_checkpoint", checkpoint), self.assertRaises(StoreError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, "conflict")
        self.assertFalse((self.root / NODES / "main.json").exists())
        self.assertNotEqual(path.stat().st_ino, (self.root / STAGE / "1").stat().st_ino)

    def test_link_itself_refuses_racing_existing_target(self):
        original_link = os.link
        path = self.root / "etc/snellctl/nodes/main/shadowtls.json"

        def link(source, target, **kwargs):
            if target == "shadowtls.json":
                path.write_text("racing-user-file")
            return original_link(source, target, **kwargs)

        with patch("snellctl.storage.os.link", side_effect=link), self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(path.read_text(), "racing-user-file")
        self.assertTrue((self.root / PENDING).exists())

    def test_pending_journal_has_no_secret_values(self):
        keys = NodeSecrets("a" * 64, "b" * 64)
        with patch("snellctl.storage.new_node_secrets", return_value=keys), self.fail_at("prepared"), self.assertRaises(Interrupted):
            self.prepare()
        journal = (self.root / PENDING).read_text()
        self.assertNotIn(keys.psk, journal)
        self.assertNotIn(keys.shadowtls_password, journal)
        self.assertNotIn("node.example.net", journal)

    def test_leaf_symlink_and_parent_symlink_do_not_escape(self):
        outside = self.base / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("unchanged")
        path = self.parents_for("etc/snellctl/nodes/main/snell.conf")
        path.symlink_to(sentinel)
        with self.assertRaises(StoreError):
            self.prepare()
        self.assertTrue(path.is_symlink())
        self.assertEqual(sentinel.read_text(), "unchanged")
        other = self.base / "other"
        initialize(other)
        (other / "etc").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.prepare(root=other)
        self.assertEqual(list(outside.iterdir()), [sentinel])

    def test_existing_directory_permissions_not_silently_repaired(self):
        path = self.parents_for("etc/snellctl/nodes/main/snell.conf")
        path.parent.chmod(0o755)
        with self.assertRaises(StoreError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, "unsafe-directory")
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o755)

    def test_content_or_permission_drift_stops_repeat(self):
        self.prepare()
        path = self.root / "etc/snellctl/nodes/main/snell.conf"
        original = path.read_bytes()
        path.write_bytes(b"changed-by-user")
        with self.assertRaises(StoreError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, "changed")
        self.assertEqual(path.read_bytes(), b"changed-by-user")
        with SandboxStore(self.root) as store:
            self.assertEqual(store.status()["nodes"][0]["state"], "needs-attention")
        path.write_bytes(original)
        path.chmod(0o644)
        with self.assertRaises(StoreError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, "unsafe-file")

    def test_new_node_does_not_change_existing_node(self):
        self.prepare()
        before = {item.path: (self.root / item.path[1:]).read_bytes() for item in file_targets(self.spec)}
        other = NodeSpec("second.example.net", "second", 24443, 32001, 32443)
        with self.fail_at("published", 2), self.assertRaises(Interrupted):
            self.prepare(spec=other)
        self.assertEqual(self.recover("rollback"), "cancelled")
        self.assertEqual(before, {path: (self.root / path[1:]).read_bytes() for path in before})
        self.assert_complete()

    def test_pending_requires_explicit_recovery_without_new_keys(self):
        with self.fail_at("published", 0), self.assertRaises(Interrupted):
            self.prepare()
        with patch("snellctl.storage.new_node_secrets", side_effect=AssertionError("new keys")), self.assertRaises(StoreError) as error:
            self.prepare()
        self.assertEqual(error.exception.code, "recovery-required")

    def test_resume_all_publish_and_commit_boundaries(self):
        points = [("prepared", -1, 1), ("committed", -1, 1)]
        points += [("published", index, 1) for index in range(6)]
        points += [("cleanup", index, 1) for index in range(6)]
        points += [("record-linked", -1, 1), ("record-written", -1, 2), ("record-linked", -1, 2)]
        for case, (event, index, occurrence) in enumerate(points):
            with self.subTest(event=event, index=index, occurrence=occurrence):
                root = self.base / f"resume-{case}"
                initialize(root)
                with self.fail_at(event, index, occurrence), self.assertRaises(Interrupted):
                    self.prepare(root=root)
                # At least one key copy always survives without another RNG call.
                source = root / "etc/snellctl/nodes/main/snell.conf"
                if not source.exists():
                    source = root / STAGE / "0"
                original = source.read_bytes()
                with patch("snellctl.storage.new_node_secrets", side_effect=AssertionError("new keys")):
                    self.recover("resume", root=root)
                self.assertEqual((root / "etc/snellctl/nodes/main/snell.conf").read_bytes(), original)
                self.assert_complete(root)

    def test_orphan_preparation_can_only_be_cancelled(self):
        for case, point in enumerate([("staged", index, 1) for index in range(6)] + [("record-written", -1, 1)]):
            with self.subTest(point=point):
                root = self.base / f"orphan-{case}"
                initialize(root)
                with self.fail_at(*point), self.assertRaises(Interrupted):
                    self.prepare(root=root)
                with self.assertRaises(StoreError) as error:
                    self.recover("resume", root=root)
                self.assertEqual(error.exception.code, "incomplete-preparation")
                self.assertEqual(self.recover("rollback", root=root), "cancelled")
                self.assertFalse((root / STAGE).exists())
                self.assertTrue(all(not (root / item.path[1:]).exists() for item in file_targets(self.spec)))

    def test_rollback_all_publish_boundaries(self):
        for index in range(6):
            with self.subTest(index=index):
                root = self.base / f"rollback-{index}"
                initialize(root)
                with self.fail_at("published", index), self.assertRaises(Interrupted):
                    self.prepare(root=root)
                self.assertEqual(self.recover("rollback", root=root), "cancelled")
                for target in file_targets(self.spec):
                    self.assertFalse((root / target.path[1:]).exists())
                self.assertFalse((root / STAGE).exists())
                self.assertFalse((root / PENDING).exists())

    def test_interrupted_rollback_is_recoverable(self):
        for event, index in [("removed", 3), ("cancelled", -1)]:
            with self.subTest(event=event):
                root = self.base / event
                initialize(root)
                with self.fail_at("published", 5), self.assertRaises(Interrupted):
                    self.prepare(root=root)
                with self.fail_at(event, index), self.assertRaises(Interrupted):
                    self.recover("rollback", root=root)
                self.assertEqual(self.recover("rollback", root=root), "cancelled")
                self.assertFalse((root / PENDING).exists())
                self.assertFalse((root / STAGE).exists())

    def test_rollback_does_not_uninstall_a_committed_node(self):
        with self.fail_at("committed"), self.assertRaises(Interrupted):
            self.prepare()
        self.assertEqual(self.recover("rollback"), "committed-cleanup")
        self.assert_complete()

    def test_replaced_target_with_identical_bytes_is_not_owned(self):
        with self.fail_at("published", 3), self.assertRaises(Interrupted):
            self.prepare()
        path = self.root / "etc/snellctl/nodes/main/snell.conf"
        data = path.read_bytes()
        path.unlink()
        path.write_bytes(data)
        path.chmod(0o600)
        for action in ("resume", "rollback"):
            with self.subTest(action=action), self.assertRaises(StoreError) as error:
                self.recover(action)
            self.assertEqual(error.exception.code, "conflict")
        self.assertEqual(path.read_bytes(), data)
        self.assertTrue((self.root / "etc/nginx/conf.d/snellctl-main.conf").exists())
        self.assertTrue((self.root / PENDING).exists())

    def test_corrupt_or_redirected_journal_preserves_files(self):
        with self.fail_at("prepared"), self.assertRaises(Interrupted):
            self.prepare()
        journal = self.root / PENDING
        original = journal.read_bytes()
        journal.write_text("BROKEN_PRIVATE_TEXT")
        with self.assertRaises(StoreError) as error:
            self.recover("rollback")
        self.assertNotIn("BROKEN_PRIVATE_TEXT", str(error.exception))
        record = json.loads(original)
        record["files"][0]["path"] = "/../../outside"
        journal.write_text(json.dumps(record))
        with self.assertRaises(StoreError):
            self.recover("resume")
        self.assertTrue((self.root / STAGE / "0").exists())

    def test_truncated_or_changed_stage_is_preserved_not_regenerated(self):
        with self.fail_at("prepared"), self.assertRaises(Interrupted):
            self.prepare()
        stage = self.root / STAGE / "0"
        stage.write_bytes(b"truncated")
        with patch("snellctl.storage.new_node_secrets", side_effect=AssertionError("new keys")):
            for action in ("resume", "rollback"):
                with self.subTest(action=action), self.assertRaises(StoreError) as error:
                    self.recover(action)
                self.assertEqual(error.exception.code, "changed")
        self.assertEqual(stage.read_bytes(), b"truncated")
        self.assertTrue((self.root / PENDING).exists())

    def test_pending_symlink_is_not_followed_or_deleted(self):
        with self.fail_at("prepared"), self.assertRaises(Interrupted):
            self.prepare()
        outside = self.base / "outside-record"
        outside.write_text("keep")
        journal = self.root / PENDING
        journal.unlink()
        journal.symlink_to(outside)
        with self.assertRaises(OSError):
            self.recover("rollback")
        self.assertTrue(journal.is_symlink())
        self.assertEqual(outside.read_text(), "keep")

    def test_unknown_stage_file_is_not_removed(self):
        with self.fail_at("prepared"), self.assertRaises(Interrupted):
            self.prepare()
        unknown = self.root / STAGE / "user-note"
        unknown.write_text("keep")
        with self.assertRaises(StoreError) as error:
            self.recover("rollback")
        self.assertEqual(error.exception.code, "unknown-stage-file")
        self.assertEqual(unknown.read_text(), "keep")

    def test_fifo_metadata_is_rejected_without_blocking(self):
        path = self.root / NODES / "main.json"
        os.mkfifo(path, 0o600)
        with SandboxStore(self.root) as store, self.assertRaises(StoreError):
            store.status()

    def test_additional_hardlink_prevents_repeat(self):
        self.prepare()
        path = self.root / "etc/snellctl/nodes/main/snell.conf"
        outside = self.base / "extra-link"
        os.link(path, outside)
        with self.assertRaises(StoreError):
            self.prepare()
        self.assertTrue(outside.exists())

    def test_failed_partial_write_is_never_published(self):
        original_write = os.write
        calls = 0

        def write(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return original_write(fd, data[:3])
            raise OSError(errno.ENOSPC, "PRIVATE_ERROR")

        with patch("snellctl.storage.os.write", side_effect=write), self.assertRaises(OSError):
            self.prepare()
        self.assertTrue((self.root / STAGE / "0").exists())
        self.assertFalse((self.root / "etc/snellctl/nodes/main/snell.conf").exists())
        self.assertEqual(self.recover("rollback"), "cancelled")

    def test_fsync_failure_is_not_reported_as_success(self):
        with patch("snellctl.storage.os.fsync", side_effect=OSError(errno.EIO, "sync failure")), self.assertRaises(OSError):
            self.prepare()
        self.assertFalse((self.root / NODES / "main.json").exists())
        self.recover("rollback")

    def test_cross_filesystem_link_failure_keeps_recovery_materials(self):
        with patch("snellctl.storage.os.link", side_effect=OSError(errno.EXDEV, "different filesystem")), self.assertRaises(OSError):
            self.prepare()
        self.assertTrue((self.root / STAGE / "0").exists())
        self.assertFalse((self.root / "etc/snellctl/nodes/main/snell.conf").exists())
        self.recover("rollback")

    def test_real_process_exit_and_resume_keep_original_keys(self):
        code = """
import os, sys
from pathlib import Path
from snellctl.storage import SandboxStore
from snellctl.deployment import NodeSpec
with SandboxStore(Path(sys.argv[1])) as store:
    def checkpoint(event, index=-1):
        if event == 'published' and index == 2:
            os._exit(73)
    store._checkpoint = checkpoint
    store.prepare(NodeSpec('node.example.net'))
"""
        process = subprocess.run([sys.executable, "-c", code, str(self.root)], capture_output=True, timeout=15)
        self.assertEqual(process.returncode, 73, process.stderr.decode())
        original = (self.root / STAGE / "0").read_bytes()
        self.recover("resume")
        self.assert_complete()
        self.assertEqual((self.root / "etc/snellctl/nodes/main/snell.conf").read_bytes(), original)

    def test_separate_process_cannot_enter_held_lock(self):
        code = """
import sys
from pathlib import Path
from snellctl.storage import SandboxStore, StoreError
try:
    with SandboxStore(Path(sys.argv[1])) as store:
        store.status()
except StoreError as error:
    print(error.code)
    sys.exit(7)
"""
        with SandboxStore(self.root) as store, store._locked():
            process = subprocess.run([sys.executable, "-c", code, str(self.root)], capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 7)
        self.assertEqual(process.stdout.strip(), "busy")
        self.assertEqual(process.stderr, "")

    def test_shared_umask_does_not_make_secrets_public(self):
        old = os.umask(0)
        try:
            self.prepare()
        finally:
            os.umask(old)
        self.assert_complete()

    def test_initialize_refuses_populated_or_unsafe_roots(self):
        with self.assertRaises(StoreError):
            initialize(self.root)
        for root in (Path("/"), Path("relative"), self.base / "a/../b"):
            with self.subTest(root=root), self.assertRaises(StoreError):
                initialize(root)
        outside = self.base / "outside"
        outside.mkdir(mode=0o700)
        (outside / "keep").write_text("user-data")
        with self.assertRaises(StoreError):
            initialize(outside)
        self.assertEqual((outside / "keep").read_text(), "user-data")
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            with SandboxStore(alias):
                pass

    def test_no_marker_no_writes(self):
        (self.root / MARKER).unlink()
        with self.assertRaises(FileNotFoundError):
            with SandboxStore(self.root):
                pass
        self.assertFalse((self.root / "etc").exists())


class SandboxCliTests(unittest.TestCase):
    def test_module_cli_smoke_in_temporary_sandbox(self):
        with tempfile.TemporaryDirectory() as temp:
            root = str(Path(temp).resolve() / "sandbox")

            def command(*args):
                result = subprocess.run(
                    [sys.executable, "-m", "snellctl", "sandbox", *args, "--root", root],
                    capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout

            command("init")
            first = command("prepare", "--domain", "node.example.net")
            before = (Path(root) / "etc/snellctl/nodes/main/snell.conf").read_bytes()
            repeated = command("prepare", "--domain", "node.example.net")
            report = json.loads(command("status"))
            self.assertIn("尚未部署", first)
            self.assertIn("未重新生成密钥", repeated)
            self.assertEqual(report["pending"], "none")
            self.assertFalse(report["deployment_validated"])
            self.assertEqual((Path(root) / "etc/snellctl/nodes/main/snell.conf").read_bytes(), before)

    def test_cli_success_repeat_and_status_never_print_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = str(Path(temp).resolve() / "sandbox")
            output = io.StringIO()
            keys = NodeSecrets("a" * 64, "b" * 64)
            with redirect_stdout(output), patch("snellctl.storage.new_node_secrets", return_value=keys):
                self.assertEqual(main(["sandbox", "init", "--root", root]), 0)
                self.assertEqual(main(["sandbox", "prepare", "--root", root, "--domain", "node.example.net"]), 0)
                self.assertEqual(main(["sandbox", "prepare", "--root", root, "--domain", "node.example.net"]), 0)
                self.assertEqual(main(["sandbox", "status", "--root", root]), 0)
            self.assertNotIn(keys.psk, output.getvalue())
            self.assertNotIn(keys.shadowtls_password, output.getvalue())
            self.assertIn('"deployment_validated": false', output.getvalue())

    def test_cli_os_errors_are_sanitized(self):
        with patch("snellctl.storage.initialize", side_effect=OSError("PRIVATE_EXCEPTION_DATA")), redirect_stderr(io.StringIO()) as error:
            self.assertEqual(main(["sandbox", "init", "--root", "/private/tmp/uncreated"]), 1)
        self.assertNotIn("PRIVATE_EXCEPTION_DATA", error.getvalue())

    def test_cli_rejects_system_root(self):
        with redirect_stderr(io.StringIO()) as error:
            self.assertEqual(main(["sandbox", "init", "--root", "/"]), 1)
        self.assertIn("unsafe-root", error.getvalue())
