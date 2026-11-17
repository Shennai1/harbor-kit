from contextlib import contextmanager, redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from snellctl.__main__ import main
from snellctl.commandinstall import CommandInstallation, command_status
from snellctl.commandmanage import BLOCKED, LEGACY_MODULES, CommandManagement, run_command_management
from snellctl.entrypoint import (
    BASE, COMMAND, BACKUP, STAGE, INTENT, MODULES, PENDING_PATHS, WRAPPER,
    digest, management_lock, snapshot, verify_installation,
)
from snellctl.hostprep import PreparationError


class Terminal:
    def __init__(self, answers=("y", "y"), interactive=True):
        self.answers = iter(answers)
        self.is_interactive = interactive
        self.output = []

    def interactive(self):
        return self.is_interactive

    def say(self, text):
        self.output.append(text)

    def ask(self, prompt):
        value = next(self.answers)
        if isinstance(value, BaseException):
            raise value
        return value


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.root, self.source = self.home / "root", self.home / "source"
        self.root.mkdir(mode=0o700)
        (self.source / "snellctl").mkdir(parents=True, mode=0o700)
        package = Path(__file__).resolve().parents[1] / "snellctl"
        for name in MODULES:
            shutil.copyfile(package / name, self.source / "snellctl" / name)
            (self.source / "snellctl" / name).chmod(0o600)
        install = CommandInstallation(self.root, self.source)
        try:
            self.original = install.install(install.plan())
        finally:
            install.close()
        self.engine = CommandManagement(self.root, self.source)
        self.addCleanup(self.engine.close)
        self.node = self.path("/etc/snellctl/private-test")
        self.node.parent.mkdir(parents=True)
        self.node.write_text("NODE_SECRET_NOT_OUTPUT")

    def path(self, name):
        return self.root / name.lstrip("/")

    def change_source(self):
        path = self.source / "snellctl/__init__.py"
        path.write_bytes(path.read_bytes() + b"\n# candidate test version\n")

    def assert_clean(self):
        self.assertFalse(any(self.path(p).exists() for p in PENDING_PATHS))
        self.assertEqual(self.node.read_text(), "NODE_SECRET_NOT_OUTPUT")

    @contextmanager
    def factory(self):
        with management_lock(self.root, uid=os.geteuid(), exclusive=True):
            yield self.engine

    def test_plan_is_read_only(self):
        before = self.path(BASE + "/manifest.json").stat()
        self.engine.plan("update")
        self.engine.plan("remove")
        self.assertEqual(before.st_mtime_ns, self.path(BASE + "/manifest.json").stat().st_mtime_ns)
        self.assertFalse(self.engine.changes_attempted)
        self.assert_clean()

    def test_same_source_no_write_no_confirmation(self):
        ui = Terminal(())
        self.assertEqual(run_command_management("update", factory=self.factory, terminal=ui), 0)
        self.assertIn('"result": "command-already-current"', "\n".join(ui.output))
        self.assertFalse(self.engine.changes_attempted)
        self.assert_clean()

    def test_update_exact_target_and_node_preserved(self):
        self.change_source()
        expected = self.engine.plan("update")
        result = self.engine.execute(expected)
        self.assertEqual(result["result"], "command-updated")
        self.assertFalse(result["node_changes_attempted"])
        self.assertEqual(verify_installation(self.root, uid=os.geteuid()), expected["after"])
        self.assertEqual(self.path(COMMAND).read_bytes(), WRAPPER)
        self.assert_clean()

    def test_remove_only_management_files(self):
        result = self.engine.execute(self.engine.plan("remove"))
        self.assertEqual(result["result"], "command-removed")
        self.assertEqual(command_status(self.root, uid=os.geteuid())["result"], "not-installed")
        self.assertTrue(self.path("/usr/local/bin").is_dir())
        self.assertTrue(self.path("/usr/local/lib").is_dir())
        self.assert_clean()

    def test_reinstall_after_successful_removal(self):
        self.engine.execute(self.engine.plan("remove"))
        install = CommandInstallation(self.root, self.source)
        try:
            self.assertEqual(install.install(install.plan())["result"], "command-installed")
        finally:
            install.close()

    def test_removed_installation_cannot_be_removed_again(self):
        self.engine.execute(self.engine.plan("remove"))
        with self.assertRaises(Exception):
            self.engine.plan("remove")

    def test_legacy_layout_requires_reviewed_snapshot(self):
        self.path(BASE + "/snellctl/commandmanage.py").unlink()
        manifest = self.path(BASE + "/manifest.json")
        record = json.loads(manifest.read_bytes())
        record["files"].pop("snellctl/commandmanage.py")
        value = snapshot(record["files"])
        record["snapshot_sha256"] = value
        manifest.write_text(json.dumps(record))
        with self.assertRaises(PreparationError):
            self.engine.plan("update")
        with patch("snellctl.commandmanage.LEGACY_SNAPSHOT", value):
            plan = self.engine.plan("update")
            self.assertEqual(plan["before"]["modules"], LEGACY_MODULES)
            self.assertEqual(self.engine.execute(plan)["result"], "command-updated")
        self.assert_clean()

    def test_source_inside_installation_refused(self):
        self.engine.source = self.path(BASE)
        with self.assertRaises(PreparationError):
            self.engine.plan("remove")
        self.assertFalse(self.engine.changes_attempted)

    def test_symlink_source_inside_installation_refused(self):
        alias = self.home / "alias"
        alias.symlink_to(self.path(BASE), target_is_directory=True)
        self.engine.source = alias
        with self.assertRaises(PreparationError):
            self.engine.plan("update")

    def test_unknown_action_refused(self):
        with self.assertRaises(PreparationError):
            self.engine.plan("shell")

    def test_all_pending_paths_block_plan_status_and_first_install(self):
        for path in PENDING_PATHS:
            with self.subTest(path=path):
                item = self.path(path)
                item.symlink_to("missing")
                try:
                    with self.assertRaises(PreparationError):
                        self.engine.plan("remove")
                    with self.assertRaises(PreparationError):
                        command_status(self.root, uid=os.geteuid())
                finally:
                    item.unlink()

    def test_source_change_during_confirmation_refused(self):
        expected = self.engine.plan("update")
        self.change_source()
        with self.assertRaises(PreparationError):
            self.engine.execute(expected)
        self.assertFalse(self.engine.changes_attempted)

    def test_installed_change_during_confirmation_refused(self):
        expected = self.engine.plan("remove")
        self.path(BASE + "/snellctl/__init__.py").write_text("changed")
        with self.assertRaises(Exception):
            self.engine.execute(expected)
        self.assertFalse(self.engine.changes_attempted)

    def test_extra_file_and_wide_directory_refused(self):
        extra = self.path(BASE + "/unowned")
        extra.write_text("keep")
        with self.assertRaises(Exception):
            self.engine.plan("remove")
        self.assertTrue(extra.exists())
        extra.unlink()
        self.path(BASE).chmod(0o755)
        with self.assertRaises(PreparationError):
            self.engine.plan("remove")

    def test_symlink_hardlink_and_writable_file_refused(self):
        item = self.path(BASE + "/snellctl/__init__.py")
        data = item.read_bytes()
        for kind in ("symlink", "hardlink", "mode"):
            with self.subTest(kind=kind):
                item.unlink()
                if kind == "symlink":
                    item.symlink_to(self.node)
                elif kind == "hardlink":
                    os.link(self.node, item)
                else:
                    item.write_bytes(data)
                    item.chmod(0o666)
                with self.assertRaises(Exception):
                    self.engine.plan("remove")
        item.unlink()
        item.write_bytes(data)
        item.chmod(0o600)

    def test_cancellation_at_each_confirmation_has_no_writes(self):
        for answers in (("n",), ("y", "n"), ("",), (KeyboardInterrupt(),)):
            with self.subTest(answers=str(answers)):
                ui = Terminal(answers)
                self.assertEqual(run_command_management("remove", factory=self.factory, terminal=ui), 130)
                self.assertFalse(self.engine.changes_attempted)
                self.assert_clean()

    def test_noninteractive_no_factory(self):
        with patch("snellctl.commandmanage.real_command_management") as factory:
            self.assertEqual(run_command_management("remove", factory=factory, terminal=Terminal(interactive=False)), 2)
            factory.assert_not_called()

    def test_cli_opt_in_dispatch_and_extra_arguments(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            for verb, action in (("update-command", "update"), ("remove-command", "remove")):
                with patch("snellctl.commandmanage.run_command_management", return_value=0) as run:
                    self.assertEqual(main([verb]), 2)
                    run.assert_not_called()
                    self.assertEqual(main([verb, "--experimental"]), 0)
                    run.assert_called_once_with(action)
                for extra in ("--yes", "--root=/tmp/fake", "--url=https://example.invalid"):
                    with self.assertRaises(SystemExit) as result:
                        main([verb, "--experimental", extra])
                    self.assertEqual(result.exception.code, 2)

    def test_failures_keep_intent_and_block_retry(self):
        self.change_source()
        expected = self.engine.plan("update")
        with patch.object(self.engine, "_rename", side_effect=OSError("PRIVATE_ERROR")):
            with self.assertRaises(OSError):
                self.engine.execute(expected)
        self.assertTrue(self.path(INTENT).is_file())
        self.assertEqual(self.path(COMMAND).read_bytes(), BLOCKED)
        with self.assertRaises(PreparationError):
            self.engine.plan("update")
        self.assertEqual(self.node.read_text(), "NODE_SECRET_NOT_OUTPUT")

    def test_failure_after_old_rename_preserves_both_trees(self):
        self.change_source()
        original = self.engine._rename
        def fail_second(source, dest, identity):
            if source == STAGE:
                raise OSError("stop")
            return original(source, dest, identity)
        with patch.object(self.engine, "_rename", side_effect=fail_second):
            with self.assertRaises(OSError):
                self.engine.execute(self.engine.plan("update"))
        self.assertTrue(self.path(BACKUP).is_dir())
        self.assertTrue(self.path(STAGE).is_dir())
        self.assertFalse(self.path(BASE).exists())
        self.assertEqual(self.path(COMMAND).read_bytes(), BLOCKED)

    def test_remove_interruption_leaves_guard_and_does_not_touch_node(self):
        with patch.object(self.engine, "_remove_tree", side_effect=KeyboardInterrupt):
            ui = Terminal()
            self.assertEqual(run_command_management("remove", factory=self.factory, terminal=ui), 130)
        self.assertTrue(self.path(INTENT).is_file())
        self.assertEqual(self.path(COMMAND).read_bytes(), BLOCKED)
        self.assertEqual(self.node.read_text(), "NODE_SECRET_NOT_OUTPUT")

    def test_error_output_is_redacted(self):
        with patch.object(self.engine, "execute", side_effect=OSError("PRIVATE_ERROR")):
            ui = Terminal()
            self.assertEqual(run_command_management("remove", factory=self.factory, terminal=ui), 1)
        self.assertNotIn("PRIVATE_ERROR", "\n".join(ui.output))
        self.assertNotIn("NODE_SECRET_NOT_OUTPUT", "\n".join(ui.output))

    def test_shared_lock_blocks_exclusive_and_exclusive_blocks_launch(self):
        with management_lock(self.root, uid=os.geteuid()):
            with self.assertRaises(BlockingIOError):
                with management_lock(self.root, uid=os.geteuid(), exclusive=True):
                    self.fail("lock unexpectedly acquired")
        code = (
            "import os,runpy,sys;from pathlib import Path;root=Path(sys.argv[1]);"
            "ns=runpy.run_path(str(root/'usr/local/lib/harbor-kit/launcher.py'),run_name='test');"
            "sys.argv=['snellctl','--help'];raise SystemExit(ns['launch'](root,uid=os.geteuid()))"
        )
        with management_lock(self.root, uid=os.geteuid(), exclusive=True):
            result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(self.root)],
                                    capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("usage:", result.stdout)

    def test_pending_marker_blocks_new_launcher(self):
        self.path(INTENT).write_text("pending")
        code = (
            "import os,runpy,sys;from pathlib import Path;root=Path(sys.argv[1]);"
            "ns=runpy.run_path(str(root/'usr/local/lib/harbor-kit/launcher.py'),run_name='test');"
            "sys.argv=['snellctl','--help'];raise SystemExit(ns['launch'](root,uid=os.geteuid()))"
        )
        result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(self.root)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("usage:", result.stdout)

    def test_stage_write_failure_preserves_original_and_marker(self):
        self.change_source()
        original = self.engine.files.write_new
        def fail(path, *args, **kwargs):
            if path.startswith(STAGE + "/"):
                raise OSError("disk full")
            return original(path, *args, **kwargs)
        with patch.object(self.engine.files, "write_new", side_effect=fail):
            with self.assertRaises(OSError):
                self.engine.execute(self.engine.plan("update"))
        self.assertEqual(self.path(COMMAND).read_bytes(), WRAPPER)
        self.assertEqual(verify_installation(self.root, uid=os.geteuid()), self.original["snapshot_sha256"])
        self.assertTrue(self.path(INTENT).exists())
        with self.assertRaises(PreparationError):
            command_status(self.root, uid=os.geteuid())

    def test_partial_file_removal_preserves_intent_and_blocks_entry(self):
        original = self.engine.files.unlink_owned
        count = 0
        def fail(path, identity):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("stop")
            return original(path, identity)
        with patch.object(self.engine.files, "unlink_owned", side_effect=fail):
            with self.assertRaises(OSError):
                self.engine.execute(self.engine.plan("remove"))
        self.assertTrue(self.path(INTENT).exists())
        self.assertEqual(self.path(COMMAND).read_bytes(), BLOCKED)
        self.assertEqual(self.node.read_text(), "NODE_SECRET_NOT_OUTPUT")

    def test_final_marker_delete_failure_stays_pending(self):
        self.change_source()
        original = self.engine.files.unlink_owned
        def fail(path, identity):
            if path == INTENT:
                raise OSError("stop")
            return original(path, identity)
        with patch.object(self.engine.files, "unlink_owned", side_effect=fail):
            with self.assertRaises(OSError):
                self.engine.execute(self.engine.plan("update"))
        self.assertEqual(self.path(COMMAND).read_bytes(), WRAPPER)
        self.assertTrue(self.path(INTENT).exists())
        with self.assertRaises(PreparationError):
            command_status(self.root, uid=os.geteuid())

    def test_unowned_file_added_to_backup_is_not_deleted(self):
        self.change_source()
        original = self.engine._remove_tree
        def altered(base, *args):
            self.path(base + "/foreign").write_text("keep")
            return original(base, *args)
        with patch.object(self.engine, "_remove_tree", side_effect=altered):
            with self.assertRaises(PreparationError):
                self.engine.execute(self.engine.plan("update"))
        self.assertEqual(self.path(BACKUP + "/foreign").read_text(), "keep")
        self.assertEqual(self.path(COMMAND).read_bytes(), BLOCKED)
        self.assertTrue(self.path(INTENT).exists())

    def test_invalid_candidate_code_no_changes(self):
        (self.source / "snellctl/__init__.py").write_text("invalid python ?")
        with self.assertRaises(SyntaxError):
            self.engine.plan("update")
        self.assertFalse(self.engine.changes_attempted)
        self.assert_clean()

    def test_remove_keeps_node_programs_certificates_services_and_history(self):
        names = ("/opt/snellctl/program", "/var/lib/snellctl/preparation/owner.json",
                 "/etc/letsencrypt/credentials.ini", "/etc/ufw/user.rules",
                 "/etc/systemd/system/node.service")
        for name in names:
            p = self.path(name)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("untouched")
        before = {n: self.path(n).stat().st_mtime_ns for n in names}
        self.engine.execute(self.engine.plan("remove"))
        for name in names:
            self.assertEqual(self.path(name).read_text(), "untouched")
            self.assertEqual(self.path(name).stat().st_mtime_ns, before[name])

    def test_terminal_lost_before_write_stops(self):
        ui = Terminal()
        with patch.object(ui, "interactive", side_effect=(True, False)):
            self.assertEqual(run_command_management("remove", factory=self.factory, terminal=ui), 2)
        self.assertFalse(self.engine.changes_attempted)
        self.assert_clean()

    def test_pending_marker_prevents_fresh_install_after_partial_removal(self):
        self.engine.execute(self.engine.plan("remove"))
        self.path(INTENT).write_text("pending")
        install = CommandInstallation(self.root, self.source)
        try:
            with self.assertRaises(PreparationError):
                install.plan()
        finally:
            install.close()


if __name__ == "__main__":
    unittest.main()
