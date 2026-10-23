from contextlib import redirect_stdout, redirect_stderr
import fcntl
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from snellctl.__main__ import main
from snellctl import cleanup
from snellctl.doctor import Result
from snellctl.hostprep import CREDENTIAL, STATE, HostFiles
from snellctl.menu import run_menu


SECRET = "PRIVATE-TOKEN-MUST-NOT-APPEAR"


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.unit_reply = Result(0, "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n")

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "dpkg-query":
            return Result(1, "ufw\tii \t0.36.2-9\nnginx\tii \t1.26.3-3+deb13u9\n")
        if args == ["ss", "-H", "-4", "-lntup"]:
            return Result(0, 'tcp LISTEN 0 128 0.0.0.0:54321 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
                          'tcp LISTEN 0 128 192.0.2.99:24443 0.0.0.0:* users:(("shadow-tls",pid=2,fd=3))\n')
        if args == ["ss", "-H", "-6", "-lntup"]:
            return Result(0, "")
        if args == ["ufw", "status", "verbose"]:
            return Result(0, "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
                          "54321/tcp ALLOW IN 192.0.2.99 # " + SECRET)
        if args == ["systemctl", "is-enabled", "ufw.service"]:
            return Result(0, "enabled\n")
        if args[:3] == ["systemctl", "show", "--no-pager"] and args[-1] in cleanup.UNITS:
            assert args[3] == "--property=" + ",".join(cleanup.PROPERTIES)
            return self.unit_reply
        raise AssertionError("unexpected system command")


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.runner = FakeRunner()
        self.write("/etc/os-release", b'ID=debian\nVERSION_ID="13"\n', 0o644)

    def write(self, path, content=b"fixture\n", mode=0o600):
        dest = self.root / path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
        dest.chmod(mode)
        return dest

    def records(self, extra=None):
        self.write(STATE + "/owner.json", b'{"format":1,"scope":"new-host-preparation"}\n')
        self.write(STATE + "/lock", b"")
        (self.root / STATE.lstrip("/")).chmod(0o700)
        for name, value in (extra or {}).items():
            self.write(STATE + "/" + name + ".json", json.dumps(value).encode())

    def collect(self, **overrides):
        args = dict(root=self.root, runner=self.runner, system="Linux", machine="x86_64", euid=0)
        args.update(overrides)
        return cleanup.collect(**args)

    def manual_files(self):
        for path, category in cleanup.PATHS:
            if category == "preserve-state" or path.endswith("50-snellctl.conf"):
                continue
            self.write(path, SECRET.encode())

    def test_manual_baseline_is_not_adopted_and_ports_are_observed(self):
        self.manual_files()
        report = self.collect()
        self.assertEqual(report["ownership"], "unrecorded-do-not-adopt")
        self.assertTrue(report["collection_complete"])
        self.assertFalse(report["cleanup_authorized"])
        self.assertEqual(report["state"], "review-required")
        self.assertEqual({s["port"] for s in report["environment"]["listeners"]}, {54321, 24443})
        self.assertEqual(cleanup.exit_code(report), 0)
        self.assertIn("不是可删除清单", cleanup.render(report))

    def test_empty_host_is_not_declared_clean_or_authorized(self):
        report = self.collect()
        self.assertEqual(report["ownership"], "unrecorded-do-not-adopt")
        self.assertTrue(all(p["status"] == "missing" for p in report["paths"]))
        self.assertFalse(report["cleanup_authorized"])
        self.assertIn("已经恢复为干净新机", cleanup.render(report))

    def test_no_secret_configs_unit_arguments_or_credentials_are_read(self):
        self.manual_files()
        with patch.object(HostFiles, "read", side_effect=AssertionError("unexpected file content read")):
            report = self.collect()
        for output in (json.dumps(report), cleanup.render(report)):
            self.assertNotIn(SECRET, output)
            self.assertNotIn("192.0.2.99", output)

    def test_report_does_not_expose_certificate_names_or_symlink_targets(self):
        self.manual_files()
        self.write("/etc/letsencrypt/live/README")
        certificate = self.root / "etc/letsencrypt/live" / (SECRET + ".example.net")
        certificate.mkdir()
        (certificate / "privkey.pem").symlink_to("/not-read/" + SECRET)
        self.write("/etc/nginx/sites-enabled/" + SECRET + "\nNAME")
        report = self.collect()
        directory = next(d for d in report["directories"] if d["path"] == "/etc/letsencrypt/live")
        self.assertEqual(directory["entries"], 2)
        self.assertEqual(directory["known_names"], 1)
        self.assertEqual(directory["other_names"], 1)
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertNotIn(SECRET, cleanup.render(report))

    def test_metadata_census_and_commands_do_not_change_files(self):
        self.manual_files()
        self.records({"activation-intent": {"private": SECRET}})
        def snapshot():
            return {str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_mode)
                    for p in self.root.rglob("*") if p.is_file()}
        before = snapshot()
        with patch.object(HostFiles, "write_new", side_effect=AssertionError("write")), \
             patch.object(HostFiles, "unlink_owned", side_effect=AssertionError("unlink")), \
             patch.object(HostFiles, "replace_owned", side_effect=AssertionError("replace")):
            self.collect()
        self.assertEqual(snapshot(), before)
        self.assertTrue(all(c[0] in {"dpkg-query", "ss", "ufw", "systemctl"} for c in self.runner.calls))
        self.assertFalse(any("ExecStart" in " ".join(c) for c in self.runner.calls))

    def test_records_are_progress_only_never_ownership_verification(self):
        self.manual_files()
        self.records({"activation-ready": {"files": {"/injected/" + SECRET: SECRET}}})
        report = self.collect()
        self.assertEqual(report["ownership"], "records-only-not-verified")
        self.assertEqual(report["installation_records"]["phases"]["activation"], "completion-recorded")
        self.assertFalse(report["cleanup_authorized"])
        self.assertNotIn(SECRET, json.dumps(report))

    def test_incomplete_operation_is_reported_and_state_preserved(self):
        self.records({"public-intent": {"private": SECRET}})
        report = self.collect()
        self.assertEqual(report["installation_records"]["phases"]["public"], "needs-inspection")
        self.assertTrue((self.root / STATE.lstrip("/") / "public-intent.json").is_file())
        self.assertIn("存在未确认完成的阶段", cleanup.render(report))

    def test_busy_lock_is_unknown_not_absence(self):
        self.records()
        with (self.root / STATE.lstrip("/") / "lock").open("rb") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            report = self.collect()
        self.assertEqual(report["ownership"], "unknown-preserve-state")
        self.assertFalse(report["collection_complete"])
        self.assertEqual(cleanup.exit_code(report), 1)

    def test_damaged_or_unsafe_owner_record_is_never_echoed(self):
        for content, mode in ((SECRET.encode(), 0o600), (b"{}", 0o644), (b"{}", 0o600)):
            with self.subTest(content=content, mode=mode):
                self.records()
                self.write(STATE + "/owner.json", content, mode)
                report = self.collect()
                self.assertEqual(report["ownership"], "unknown-preserve-state")
                self.assertNotIn(SECRET, json.dumps(report))

    def test_leaf_symlink_is_marked_and_never_followed(self):
        path = self.write(CREDENTIAL)
        path.unlink()
        path.symlink_to("/nonexistent/" + SECRET)
        report = self.collect()
        item = next(p for p in report["paths"] if p["path"] == CREDENTIAL)
        self.assertEqual((item["kind"], item["status"]), ("symlink", "needs-inspection"))
        self.assertFalse(report["collection_complete"])
        self.assertNotIn(SECRET, cleanup.render(report))

    def test_parent_symlink_is_unknown_not_missing(self):
        self.write("/etc/snellctl/placeholder")
        (self.root / "etc/snellctl/credentials").symlink_to("/nonexistent/" + SECRET)
        report = self.collect()
        item = next(p for p in report["paths"] if p["path"] == CREDENTIAL)
        self.assertEqual(item["status"], "unknown")
        item = next(d for d in report["directories"] if d["path"] == "/etc/snellctl/credentials")
        self.assertEqual(item["status"], "unknown")

    def test_unsafe_parent_permissions_are_not_treated_as_absence(self):
        path = self.write(CREDENTIAL)
        path.parent.chmod(0o777)
        report = self.collect()
        self.assertEqual(next(p for p in report["paths"] if p["path"] == CREDENTIAL)["status"], "unknown")
        self.assertFalse(report["collection_complete"])

    def test_hardlink_is_flagged_without_reading_it(self):
        path = self.write(CREDENTIAL)
        os.link(path, path.parent / "other")
        report = self.collect()
        item = next(p for p in report["paths"] if p["path"] == CREDENTIAL)
        self.assertTrue(item["multiple_file_links"])
        self.assertEqual(item["status"], "needs-inspection")

    def test_publicly_readable_credentials_require_inspection(self):
        self.write(CREDENTIAL, mode=0o644)
        report = self.collect()
        item = next(p for p in report["paths"] if p["path"] == CREDENTIAL)
        self.assertEqual(item["status"], "needs-inspection")
        self.assertFalse(report["collection_complete"])

    def test_directory_in_place_of_file_is_not_accepted(self):
        path = self.write(CREDENTIAL)
        path.unlink()
        path.mkdir(mode=0o700)
        report = self.collect()
        item = next(p for p in report["paths"] if p["path"] == CREDENTIAL)
        self.assertEqual((item["kind"], item["status"]), ("directory", "needs-inspection"))

    def test_special_file_is_only_lstat_not_opened(self):
        path = self.write(CREDENTIAL)
        path.unlink()
        os.mkfifo(path)
        report = self.collect()
        item = next(p for p in report["paths"] if p["path"] == CREDENTIAL)
        self.assertEqual(item["kind"], "other")
        self.assertEqual(item["status"], "needs-inspection")

    def test_census_is_bounded_and_hides_unrecognized_names(self):
        for index in range(4):
            self.write("/etc/nginx/conf.d/" + SECRET + str(index))
        with patch.object(cleanup, "ENTRY_LIMIT", 3):
            report = self.collect()
        item = next(d for d in report["directories"] if d["path"] == "/etc/nginx/conf.d")
        self.assertEqual(item["status"], "limited")
        self.assertEqual(item["entries"], 3)
        self.assertFalse(report["collection_complete"])
        self.assertNotIn(SECRET, cleanup.render(report))

    def test_additional_nodes_versions_sites_and_hooks_are_counted_not_owned(self):
        for path in ("/etc/snellctl/nodes/other/config", "/opt/snellctl/snell/9.9.9/binary",
                     "/etc/nginx/sites-enabled/elsewhere", "/etc/letsencrypt/renewal-hooks/pre/other"):
            self.write(path, SECRET.encode())
        report = self.collect()
        for path in ("/etc/snellctl/nodes", "/opt/snellctl/snell", "/etc/nginx/sites-enabled", "/etc/letsencrypt/renewal-hooks/pre"):
            self.assertEqual(next(d for d in report["directories"] if d["path"] == path)["other_names"], 1)
        self.assertFalse(report["cleanup_authorized"])

    def test_services_never_reveal_unrecognized_values_or_extra_output(self):
        self.runner.unit_reply = Result(0, "LoadState=loaded\nActiveState=" + SECRET +
                                       "\nSubState=running\nUnitFileState=enabled\nExecStart=" + SECRET)
        report = self.collect()
        self.assertTrue(all(s["status"] == "unknown" for s in report["services"].values()))
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertFalse(report["collection_complete"])

    def test_duplicate_service_properties_are_unknown(self):
        self.runner.unit_reply = Result(0, self.runner.unit_reply.stdout + "ActiveState=inactive\n")
        self.assertEqual(cleanup._unit(self.runner, cleanup.UNITS[0]), {"status": "unknown"})

    def test_unavailable_service_command_is_not_reported_as_stopped(self):
        self.runner.unit_reply = Result(-1, SECRET)
        report = self.collect()
        self.assertTrue(all(s == {"status": "unknown"} for s in report["services"].values()))
        self.assertFalse(report["collection_complete"])

    def test_not_found_service_is_distinct_from_failure(self):
        self.runner.unit_reply = Result(1, "LoadState=not-found\nUnitFileState=\n")
        report = self.collect()
        self.assertTrue(all(s == {"status": "not-found"} for s in report["services"].values()))
        self.assertTrue(report["collection_complete"])

    def test_debian12_inventory_does_not_enable_installation(self):
        self.write("/etc/os-release", b'ID=debian\nVERSION_ID="12"\n')
        report = self.collect()
        self.assertEqual(report["state"], "review-required")
        self.assertFalse(report["cleanup_authorized"])

    def test_no_commands_on_mac_unsupported_linux_or_nonroot(self):
        for args in ({"system": "Darwin"}, {"euid": 501}, {"machine": "unsupported"}):
            with self.subTest(args=args):
                self.runner.calls.clear()
                report = self.collect(**args)
                self.assertEqual(self.runner.calls, [])
                self.assertEqual(cleanup.exit_code(report), 2)
                self.assertFalse(report["cleanup_authorized"])

    def test_missing_os_release_is_unsupported_not_assumed_debian(self):
        (self.root / "etc/os-release").unlink()
        self.assertEqual(self.collect()["state"], "unsupported")
        self.assertEqual(self.runner.calls, [])

    def test_cli_json_uses_only_readonly_collector(self):
        report = self.collect()
        with patch("snellctl.cleanup.collect", return_value=report), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["cleanup-plan", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue()), report)

    def test_cli_has_no_apply_yes_root_or_secrets_arguments(self):
        for args in (["--apply"], ["--yes"], ["--root", str(self.root)], ["--token", SECRET]):
            with self.subTest(args=args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as error, \
                 patch("snellctl.cleanup.collect", side_effect=AssertionError("no collection")):
                with self.assertRaises(SystemExit) as raised:
                    main(["cleanup-plan", *args])
                self.assertEqual(raised.exception.code, 2)
                self.assertNotIn(SECRET, error.getvalue())

    def test_menu_exposes_only_the_readonly_inventory(self):
        report = self.collect()
        with patch("builtins.input", side_effect=["6", "0"]), \
             patch("snellctl.cleanup.collect", return_value=report), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(run_menu(), 0)
        self.assertIn("清理前只读盘点", output.getvalue())
        self.assertIn("不卸载", output.getvalue())


if __name__ == "__main__":
    unittest.main()
