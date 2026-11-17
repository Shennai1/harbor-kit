from contextlib import contextmanager, redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.commandinstall import (
    CommandInstallation, _command_conflict_check, _platform_check, command_status,
    read_source, real_command_installation, run_command_install, run_command_status,
)
from snellctl.entrypoint import BASE, COMMAND, MODULES, WRAPPER, EntryError, Tree, verify_installation
from snellctl.hostprep import PreparationError


class Terminal:
    def __init__(self, answer="y", interactive=True):
        self.answer, self.is_interactive = answer, interactive
        self.output = []
        self.questions = 0

    def interactive(self):
        return self.is_interactive

    def say(self, value):
        self.output.append(value)

    def ask(self, prompt):
        self.questions += 1
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


class CommandFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.root, self.source = self.home / "root", self.home / "source"
        self.root.mkdir(mode=0o700)
        self.source.mkdir(mode=0o700)
        (self.source / "snellctl").mkdir(mode=0o700)
        package = Path(__file__).resolve().parents[1] / "snellctl"
        for name in MODULES:
            shutil.copyfile(package / name, self.source / "snellctl" / name)
            (self.source / "snellctl" / name).chmod(0o600)
        self.engine = CommandInstallation(self.root, self.source)
        self.addCleanup(self.engine.close)

    def path(self, name):
        return self.root / name.lstrip("/")

    def install(self):
        return self.engine.install(self.engine.plan())

    def manifest(self):
        return json.loads(self.path(BASE + "/manifest.json").read_bytes())

    def launch(self, args=(), *, env=None, cwd=None):
        # The production wrapper has no alternate-root option. Load a standalone
        # test bootstrap in a fresh isolated interpreter, never on host paths.
        code = (
            "import os,runpy,sys; from pathlib import Path; "
            "root=Path(sys.argv[1]); "
            "ns=runpy.run_path(str(root/'usr/local/lib/harbor-kit/launcher.py'),run_name='bootstrap_test'); "
            "sys.argv=['snellctl']+sys.argv[2:]; "
            "raise SystemExit(ns['launch'](root,uid=os.geteuid()))"
        )
        return subprocess.run([sys.executable, "-I", "-B", "-c", code, str(self.root), *args],
                              cwd=cwd or self.home, env=env, capture_output=True, text=True, timeout=15)

    def test_literal_module_list_is_complete_and_unique(self):
        actual = {p.name for p in (Path(__file__).resolve().parents[1] / "snellctl").glob("*.py")}
        self.assertEqual(set(MODULES), actual)
        self.assertEqual(len(MODULES), len(actual))

    def test_plan_and_missing_status_do_not_create_paths(self):
        data = self.engine.plan()
        self.assertEqual(data["command"], WRAPPER)
        self.assertEqual(data["launcher.py"], data["snellctl/entrypoint.py"])
        self.assertEqual(command_status(self.root, uid=os.geteuid())["result"], "not-installed")
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertFalse(self.engine.changes_attempted)

    def test_installs_exact_files_permissions_and_verifiable_record(self):
        result = self.install()
        self.assertEqual(result["result"], "command-installed")
        self.assertFalse(result["node_changes_attempted"])
        self.assertEqual(verify_installation(self.root, uid=os.geteuid()), result["snapshot_sha256"])
        self.assertEqual(command_status(self.root, uid=os.geteuid())["result"], "installed-code-verified")
        for relative in self.manifest()["files"]:
            target = self.path(COMMAND if relative == "command" else BASE + "/" + relative)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755 if relative == "command" else 0o600)
        for suffix in ("", "/snellctl"):
            self.assertEqual(stat.S_IMODE(self.path(BASE + suffix).stat().st_mode), 0o700)
        self.assertEqual(self.path(COMMAND).read_bytes(), WRAPPER)

    def test_does_not_copy_extra_files_or_touch_node_resources(self):
        (self.source / "private.ini").write_text("PRIVATE_SENTINEL")
        (self.source / "snellctl" / "extra.py").write_text("raise RuntimeError('never')")
        sentinels = ("/etc/snellctl/credentials/test", "/var/lib/snellctl/preparation/owner.json",
                     "/opt/snellctl/program", "/etc/ufw/user.rules", "/etc/systemd/system/test.service")
        for path in sentinels:
            self.path(path).parent.mkdir(parents=True, exist_ok=True)
            self.path(path).write_text("unchanged")
        before = {path: self.path(path).stat().st_mtime_ns for path in sentinels}
        self.install()
        for path in sentinels:
            self.assertEqual(self.path(path).read_text(), "unchanged")
            self.assertEqual(self.path(path).stat().st_mtime_ns, before[path])
        self.assertFalse(self.path(BASE + "/private.ini").exists())
        self.assertFalse(self.path(BASE + "/snellctl/extra.py").exists())

    def test_repeat_install_refused_without_changing_installed_bytes(self):
        self.install()
        original = self.path(BASE + "/manifest.json").read_bytes()
        with self.assertRaises(PreparationError):
            self.engine.plan()
        self.assertEqual(self.path(BASE + "/manifest.json").read_bytes(), original)

    def test_existing_command_file_directory_or_symlink_refused(self):
        target = self.path(COMMAND)
        target.parent.mkdir(parents=True)
        for kind in ("file", "directory", "link"):
            with self.subTest(kind=kind):
                if kind == "file":
                    target.write_text("other command")
                elif kind == "directory":
                    target.mkdir()
                else:
                    target.symlink_to("missing-target")
                with self.assertRaises(PreparationError):
                    self.engine.plan()
                self.assertFalse(self.engine.changes_attempted)
                target.rmdir() if kind == "directory" else target.unlink()

    def test_existing_empty_base_refused(self):
        self.path(BASE).mkdir(parents=True, mode=0o700)
        with self.assertRaises(PreparationError):
            self.engine.plan()
        self.assertFalse(self.path(COMMAND).exists())

    def test_target_parent_symlink_refused(self):
        (self.root / "usr").symlink_to(self.source, target_is_directory=True)
        with self.assertRaises((OSError, PreparationError)):
            self.engine.plan()
        self.assertFalse(self.engine.changes_attempted)

    def test_writable_parent_refused(self):
        (self.root / "usr").mkdir(mode=0o777)
        (self.root / "usr").chmod(0o777)
        with self.assertRaises(PreparationError):
            self.engine.plan()

    def test_source_change_between_plan_and_install_stops_before_writes(self):
        expected = self.engine.plan()
        with (self.source / "snellctl/__init__.py").open("ab") as stream:
            stream.write(b"\n# changed\n")
        with self.assertRaises(PreparationError):
            self.engine.install(expected)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_name_conflict_is_rechecked_before_writes(self):
        self.engine.conflict_check = Mock(side_effect=[None, PreparationError("conflict")])
        expected = self.engine.plan()
        with self.assertRaises(PreparationError):
            self.engine.install(expected)
        self.assertFalse(self.engine.changes_attempted)

    def test_source_invalid_syntax_or_metadata_rejected(self):
        target = self.source / "snellctl/__init__.py"
        original = target.read_bytes()
        for kind in ("syntax", "writable", "symlink", "hardlink", "fifo", "oversize"):
            with self.subTest(kind=kind):
                target.unlink()
                if kind == "symlink":
                    target.symlink_to(self.source / "snellctl/menu.py")
                elif kind == "hardlink":
                    os.link(self.source / "snellctl/menu.py", target)
                elif kind == "fifo":
                    os.mkfifo(target, 0o600)
                else:
                    target.write_bytes(b"invalid !" if kind == "syntax" else
                                       b"x" * (256 * 1024 + 1) if kind == "oversize" else original)
                    target.chmod(0o666 if kind == "writable" else 0o600)
                with self.assertRaises((EntryError, OSError, SyntaxError)):
                    self.engine.plan()
        self.assertFalse(self.engine.changes_attempted)

    def test_source_root_symlink_or_wrong_owner_rejected(self):
        link = self.home / "link"
        link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(OSError):
            read_source(link)
        with self.assertRaises(EntryError):
            Tree(self.source, os.geteuid() + 1)

    def test_failure_mid_copy_preserves_partial_tree_without_entry(self):
        expected = self.engine.plan()
        write = self.engine.files.write_new
        def fail(path, data, mode=0o600):
            if path.endswith("/menu.py"):
                raise OSError("private failure detail")
            write(path, data, mode)
        with patch.object(self.engine.files, "write_new", side_effect=fail):
            with self.assertRaises(OSError):
                self.engine.install(expected)
        self.assertTrue(self.engine.changes_attempted)
        self.assertTrue(self.path(BASE).is_dir())
        self.assertFalse(self.path(COMMAND).exists())
        with self.assertRaises(PreparationError):
            self.engine.plan()
        with self.assertRaises((OSError, EntryError)):
            command_status(self.root, uid=os.geteuid())

    def test_command_created_during_copy_is_not_overwritten(self):
        expected = self.engine.plan()
        write = self.engine.files.write_new
        def conflict(path, data, mode=0o600):
            if path == COMMAND:
                self.path(COMMAND).write_text("external")
            write(path, data, mode)
        with patch.object(self.engine.files, "write_new", side_effect=conflict):
            with self.assertRaises(FileExistsError):
                self.engine.install(expected)
        self.assertEqual(self.path(COMMAND).read_text(), "external")

    def test_failed_postcheck_does_not_claim_success_or_remove_files(self):
        expected = self.engine.plan()
        with patch("snellctl.commandinstall.verify_installation", side_effect=EntryError("secret")):
            with self.assertRaises(EntryError):
                self.engine.install(expected)
        self.assertTrue(self.path(COMMAND).exists())
        self.assertTrue(self.engine.changes_attempted)

    def test_manifest_invalid_formats_and_duplicate_fields_rejected(self):
        self.install()
        target = self.path(BASE + "/manifest.json")
        original = self.manifest()
        variants = [b"[]", b'{"format":1,"format":1}', b"null"]
        for key, value in (("format", True), ("kind", "other"), ("files", {}), ("snapshot_sha256", "0" * 64)):
            variants.append(json.dumps(dict(original, **{key: value})).encode())
        for data in variants:
            with self.subTest(data=data[:50]):
                target.write_bytes(data)
                with self.assertRaises(EntryError):
                    verify_installation(self.root, uid=os.geteuid())

    def test_installed_tampering_prevents_import(self):
        self.install()
        target = self.path(BASE + "/snellctl/__init__.py")
        with target.open("ab") as stream:
            stream.write(b"\nraise RuntimeError('PRIVATE_MARKER')\n")
        result = self.launch(["--version"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("校验未通过", result.stderr)
        self.assertNotIn("PRIVATE_MARKER", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_extra_module_or_bytecode_directory_refused(self):
        self.install()
        for name in ("extra.py", "__pycache__"):
            with self.subTest(name=name):
                target = self.path(BASE + "/snellctl/" + name)
                target.mkdir() if name == "__pycache__" else target.write_text("extra")
                with self.assertRaises(EntryError):
                    verify_installation(self.root, uid=os.geteuid())
                target.rmdir() if target.is_dir() else target.unlink()

    def test_installed_modes_links_and_content_checked(self):
        self.install()
        target = self.path(BASE + "/snellctl/menu.py")
        data = target.read_bytes()
        for kind in ("mode", "link", "hardlink", "content"):
            with self.subTest(kind=kind):
                target.unlink()
                if kind == "link":
                    target.symlink_to(self.source / "snellctl/menu.py")
                elif kind == "hardlink":
                    os.link(self.source / "snellctl/menu.py", target)
                else:
                    target.write_bytes(data + b"\n" if kind == "content" else data)
                    target.chmod(0o644 if kind == "mode" else 0o600)
                with self.assertRaises((EntryError, OSError)):
                    verify_installation(self.root, uid=os.geteuid())

    def test_wrapper_tampering_refused(self):
        self.install()
        self.path(COMMAND).write_bytes(WRAPPER + b"# other\n")
        with self.assertRaises(EntryError):
            verify_installation(self.root, uid=os.geteuid())

    def test_isolated_real_cli_help_ignores_cwd_and_pythonpath(self):
        self.install()
        evil = self.home / "evil"
        evil.mkdir()
        (evil / "snellctl.py").write_text("raise RuntimeError('INJECTED')")
        (evil / "sitecustomize.py").write_text("raise RuntimeError('INJECTED')")
        env = dict(os.environ, PYTHONPATH=str(evil))
        result = self.launch(["--help"], env=env, cwd=evil)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("install-command", result.stdout)
        self.assertIn("command-status", result.stdout)
        self.assertNotIn("INJECTED", result.stdout + result.stderr)
        self.assertEqual(list(self.path(BASE).rglob("__pycache__")), [])

    def test_isolated_real_cli_version_and_noninteractive_menu(self):
        from snellctl import __version__
        self.install()
        result = self.launch(["--version"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), __version__)
        self.assertEqual(self.launch().returncode, 2)

    def test_cli_parser_redacts_unknown_secret_and_disallows_override(self):
        self.install()
        for args in (("install-command", "--yes", "PRIVATE_MARKER"),
                     ("install-command", "--root", "PRIVATE_MARKER"),
                     ("command-status", "--source", "PRIVATE_MARKER")):
            with self.subTest(args=args):
                result = self.launch(args)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("PRIVATE_MARKER", result.stdout + result.stderr)


class CommandInteractionTests(unittest.TestCase):
    @contextmanager
    def factory(self):
        yield self.engine

    def setUp(self):
        self.engine = Mock(changes_attempted=False)
        self.engine.plan.return_value = {"snapshot": "test"}
        self.engine.install.return_value = {"result": "command-installed"}

    def test_success_confirms_once_and_carries_snapshot(self):
        ui = Terminal("Y")
        self.assertEqual(run_command_install(factory=self.factory, terminal=ui), 0)
        self.engine.install.assert_called_once_with(self.engine.plan.return_value)
        self.assertEqual(ui.questions, 1)

    def test_default_no_and_non_ascii_never_install(self):
        for answer in ("", "n", "yes", "是", "ｙ", "y extra"):
            with self.subTest(answer=answer):
                self.assertEqual(run_command_install(factory=self.factory, terminal=Terminal(answer)), 130)
        self.engine.install.assert_not_called()

    def test_eof_or_interrupt_before_confirm_never_install(self):
        for exc in (EOFError(), KeyboardInterrupt()):
            self.assertEqual(run_command_install(factory=self.factory, terminal=Terminal(exc)), 130)
        self.engine.install.assert_not_called()

    def test_nonterminal_never_enters_factory(self):
        factory = Mock(side_effect=AssertionError("entered"))
        self.assertEqual(run_command_install(factory=factory, terminal=Terminal(interactive=False)), 2)
        factory.assert_not_called()

    def test_terminal_lost_after_confirmation_never_installs(self):
        ui = Terminal()
        ui.interactive = Mock(side_effect=[True, False])
        self.assertEqual(run_command_install(factory=self.factory, terminal=ui), 2)
        self.engine.install.assert_not_called()

    def test_partial_failure_reports_attempt_without_exception_secret(self):
        self.engine.changes_attempted = True
        self.engine.install.side_effect = OSError("PRIVATE_MARKER")
        ui = Terminal()
        self.assertEqual(run_command_install(factory=self.factory, terminal=ui), 1)
        output = "\n".join(ui.output)
        self.assertNotIn("PRIVATE_MARKER", output)
        self.assertIn('"host_changes_attempted": true', output)
        self.assertIn('"automatic_retry": false', output)

    def test_no_experimental_flag_never_calls_install(self):
        with patch("snellctl.commandinstall.run_command_install") as run, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["install-command"]), 2)
        run.assert_not_called()

    def test_cli_dispatches_only_explicit_commands(self):
        with patch("snellctl.commandinstall.run_command_install", return_value=130) as run:
            self.assertEqual(main(["install-command", "--experimental"]), 130)
            run.assert_called_once_with()
        with patch("snellctl.commandinstall.run_command_status", return_value=1) as status:
            self.assertEqual(main(["command-status", "--json"]), 1)
            status.assert_called_once_with(json_output=True)

    def test_status_failures_are_redacted(self):
        output = io.StringIO()
        with patch("snellctl.commandinstall._platform_check"), \
             patch("snellctl.commandinstall.command_status", side_effect=OSError("PRIVATE_MARKER")), \
             redirect_stdout(output):
            self.assertEqual(run_command_status(json_output=True), 1)
        report = json.loads(output.getvalue())
        self.assertFalse(report["host_changes_attempted"])
        self.assertEqual(report["node_health"], "not-checked")
        self.assertNotIn("PRIVATE_MARKER", output.getvalue())

    def test_unsupported_platform_fails_before_opening_host(self):
        with patch("snellctl.commandinstall._platform_check", side_effect=PreparationError("unsupported")), \
             patch("snellctl.commandinstall.CommandInstallation") as engine:
            with self.assertRaises(PreparationError), real_command_installation():
                self.fail("must not yield")
        engine.assert_not_called()

    def test_platform_gate_requires_supported_root_host(self):
        with patch("snellctl.commandinstall.os.geteuid", return_value=0), \
             patch("snellctl.commandinstall.sys.platform", "linux"), \
             patch("snellctl.commandinstall.platform.machine", return_value="x86_64"), \
             patch("snellctl.commandinstall.platform.freedesktop_os_release", return_value={"ID": "debian", "VERSION_ID": "13"}):
            _platform_check()
            for target, value in (("os.geteuid", 1000), ("platform.machine", "aarch64"),
                                  ("platform.freedesktop_os_release", {"ID": "debian", "VERSION_ID": "12"})):
                with patch("snellctl.commandinstall." + target, return_value=value):
                    with self.assertRaises(PreparationError):
                        _platform_check()

    def test_search_path_and_standard_path_conflicts_rejected(self):
        for replies in (("/other/snellctl",), (None, "/usr/bin/snellctl")):
            with patch("snellctl.commandinstall.shutil.which", side_effect=replies):
                with self.assertRaises(PreparationError):
                    _command_conflict_check()
        with patch("snellctl.commandinstall.shutil.which", return_value=None):
            _command_conflict_check()


if __name__ == "__main__":
    unittest.main()
