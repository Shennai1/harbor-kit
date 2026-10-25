from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.client import ClientError, read_client
from snellctl.hostprep import PreparationError, Reply, STATE, CREDENTIAL
from snellctl.installer import installation_status, render_status
from snellctl.menu import run_menu
from snellctl.rotation import INTENT, KeyRotation, RotationPlan, run_rotation
from test_hostprep import TOKEN
from test_installer import Console
from test_publish import PublicHost, UFW_UNCHANGED
import test_publish


class RotationHost(PublicHost):
    def __call__(self, command):
        args = command.argv
        if (args[:2] == ("systemctl", "show") and args[-1] == "ActiveState,SubState,MainPID"
                and args[2] not in self.active):
            self.calls.append(command)
            return Reply(0, "ActiveState=inactive\nSubState=dead\nMainPID=0\n")
        return super().__call__(command)


class RotationTests(unittest.TestCase):
    """Real files/controllers; systemd, firewall and the TLS probe are simulated."""

    def setUp(self):
        with patch("test_publish.PublicHost", RotationHost):
            test_publish.PublicationTests.setUp(self)
        test_publish.PublicationTests.enable(self)
        self.rotation = KeyRotation(self.engine)
        self.before_keys = read_client(root=self.root).keys
        self.host.calls.clear()
        self.probe.reset_mock()

    def rotate(self, component="snell", **kwargs):
        plan = self.rotation.check(component)
        return self.rotation.rotate(plan, confirm_change=True, confirm_ssh_reconnected=True, **kwargs)

    def snapshot(self):
        result = {}
        for path in self.root.rglob("*"):
            info = path.lstat()
            value = str(path.readlink()) if path.is_symlink() else path.read_bytes() if path.is_file() else None
            result[str(path.relative_to(self.root))] = (info.st_mode, info.st_ino, value)
        return result

    def mutations(self):
        return [c.argv for c in self.host.calls if c.argv[:2] in {
            ("systemctl", "start"), ("systemctl", "stop"), ("systemctl", "disable"),
            ("systemctl", "enable"), ("systemctl", "restart"), ("systemctl", "reload"),
        }]

    def assert_pending(self):
        self.assertEqual(installation_status(root=self.root)["key_rotation"], "needs-inspection")
        with self.assertRaises(ClientError):
            read_client(root=self.root)
        with self.assertRaises(PreparationError):
            self.rotation.check("snell")
        with self.assertRaises(PreparationError):
            test_publish.PublicationTests.enable(self)
        self.assertIn("密钥更换：未确认完成", render_status(installation_status(root=self.root)))

    def assert_stopped(self):
        self.assertNotIn(self.spec.shadowtls_service, self.host.active)
        self.assertNotIn(self.spec.shadowtls_service, self.host.enabled)
        self.assertIn("ufw.service", self.host.enabled)
        self.assertIn("certbot.timer", self.host.enabled)
        self.assert_pending()

    def test_snell_only_changes_selected_file_and_current_manifests(self):
        before = self.snapshot()
        self.assertEqual(self.rotate(), "key-rotated-external-test-required")
        after = self.snapshot()
        changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
        self.assertEqual(changed, {"etc/snellctl/nodes/main/snell.conf",
                                  "var/lib/snellctl/preparation/public-files.json",
                                  "var/lib/snellctl/preparation/public-ready.json"})
        keys = read_client(root=self.root).keys
        self.assertNotEqual(keys.psk, self.before_keys.psk)
        self.assertNotEqual(keys.psk, self.before_keys.shadowtls_password)
        self.assertEqual(keys.shadowtls_password, self.before_keys.shadowtls_password)
        self.assertEqual(self.mutations(), [("systemctl", "stop", self.spec.snell_service),
                                           ("systemctl", "start", self.spec.snell_service)])
        self.assertEqual(self.prep.status()["key_rotation"], "none-pending")

    def test_shadow_only_keeps_snell_and_restarts_only_entry(self):
        self.rotate("shadowtls")
        keys = read_client(root=self.root).keys
        self.assertEqual(keys.psk, self.before_keys.psk)
        self.assertNotEqual(keys.shadowtls_password, self.before_keys.shadowtls_password)
        self.assertNotEqual(keys.shadowtls_password, self.before_keys.psk)
        self.assertEqual(self.mutations(), [("systemctl", "stop", self.spec.shadowtls_service),
                                           ("systemctl", "start", self.spec.shadowtls_service)])

    def test_sequential_rotations_use_current_records_not_activation_history(self):
        historical = self.host.path(STATE + "/activation-ready.json").read_bytes()
        self.rotate("snell")
        self.rotate("shadowtls")
        self.rotate("snell")
        self.assertEqual(self.host.path(STATE + "/activation-ready.json").read_bytes(), historical)
        self.assertEqual(test_publish.PublicationTests.enable(self), "already-public-enabled-external-test-required")
        self.assertEqual(self.prep._read_record("public-files"), self.prep._read_record("public-ready")["node"])
        self.assertNotEqual(read_client(root=self.root).keys, self.before_keys)

    def test_check_is_readonly_and_plan_has_no_keys(self):
        before = self.snapshot()
        plan = self.rotation.check("snell")
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.mutations(), [])
        self.assertNotIn(self.spec.domain, repr(plan))
        self.assertNotIn(self.before_keys.psk, repr(plan))
        self.assertNotIn(TOKEN, repr(plan))

    def test_only_current_key_config_and_manifests_are_written_no_credential_or_ufw_changes(self):
        paths = [CREDENTIAL, *UFW_UNCHANGED, "/etc/ufw/user.rules", self.spec.nginx_conf]
        before = {p: self.host.path(p).read_bytes() for p in paths}
        self.rotate()
        self.assertEqual(before, {p: self.host.path(p).read_bytes() for p in paths})
        for command in self.host.calls:
            self.assertNotIn(command.argv[0], {"apt-get", "certbot", "curl", "wget"})
            self.assertNotIn("ssh.service", command.argv)
            if command.argv[0] == "ufw":
                self.assertIn(command.argv[1], {"show", "status"})

    def test_confirmations_are_strict_before_any_commands(self):
        plan = self.rotation.check("snell")
        self.host.calls.clear()
        for name in ("confirm_change", "confirm_ssh_reconnected"):
            for value in (False, None, "yes", 1):
                flags = {"confirm_change": True, "confirm_ssh_reconnected": True, name: value}
                with self.assertRaises(PreparationError):
                    self.rotation.rotate(plan, **flags)
        self.assertEqual(self.host.calls, [])
        self.assertFalse(self.prep._exists(INTENT))

    def test_invalid_component_refused(self):
        before = self.snapshot()
        for component in ("both", "", "../snell", TOKEN):
            with self.assertRaises(PreparationError):
                self.rotation.check(component)
        self.assertEqual(before, self.snapshot())

    def test_stale_confirmation_after_another_success_is_refused(self):
        plan = self.rotation.check("shadowtls")
        self.rotate("snell")
        before = self.snapshot()
        self.host.calls.clear()
        with self.assertRaises(PreparationError):
            self.rotation.rotate(plan, confirm_change=True, confirm_ssh_reconnected=True)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.mutations(), [])

    def test_drift_after_confirmation_does_not_get_overwritten(self):
        plan = self.rotation.check("snell")
        path = self.spec.node_dir + "/snell.conf"
        self.host.write(path, b"foreign secret\n")
        with self.assertRaises(Exception):
            self.rotation.rotate(plan, confirm_change=True, confirm_ssh_reconnected=True)
        self.assertEqual(self.host.path(path).read_bytes(), b"foreign secret\n")
        self.assertFalse(self.prep._exists(INTENT))
        self.assertEqual(self.mutations(), [])

    def test_precheck_tls_failure_does_not_write_or_restart(self):
        self.probe.return_value = False
        before = self.snapshot()
        with self.assertRaises(PreparationError):
            self.rotation.check("snell")
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.mutations(), [])

    def test_unknown_firewall_and_nginx_version_drift_are_not_repaired(self):
        for change in (lambda: self.host.rules.append("ufw allow Nginx"),
                       lambda: setattr(self.host, "version", "1.30.4")):
            change()
            with self.assertRaises(PreparationError):
                self.rotation.check("snell")
            self.assertFalse(self.prep._exists(INTENT))
            self.assertEqual(self.mutations(), [])
            self.host.rules = self.host.rules[:2]

    def test_pending_corrupt_or_symlink_marker_blocks_before_commands(self):
        path = self.host.path(STATE + "/" + INTENT + ".json")
        for symlink in (False, True):
            if symlink:
                path.symlink_to("/missing")
            else:
                self.host.write(STATE + "/" + INTENT + ".json", b"broken " + TOKEN.encode())
            self.assert_pending()
            self.assertEqual(self.host.calls, [])
            path.unlink()

    def test_busy_lock_and_missing_public_record_stop_without_writes(self):
        before = self.snapshot()
        with self.prep._lock(), self.assertRaises(PreparationError):
            self.rotation.check("snell")
        self.assertEqual(before, self.snapshot())
        self.host.path(STATE + "/public-ready.json").unlink()
        with self.assertRaises(Exception):
            self.rotation.check("snell")
        self.assertEqual(self.mutations(), [])

    def test_existing_candidates_are_preserved_before_intent(self):
        paths = (self.spec.node_dir + "/snell.conf", self.spec.node_dir + "/shadowtls.json",
                 STATE + "/public-files.json", STATE + "/public-ready.json")
        for path in paths:
            candidate = self.host.path(path + ".snellctl-new")
            candidate.symlink_to("/unrelated")
            with self.assertRaises(PreparationError):
                self.rotation.check("snell")
            self.assertTrue(candidate.is_symlink())
            self.assertFalse(self.prep._exists(INTENT))
            candidate.unlink()

    def test_random_collision_is_retried_without_changing_other_key(self):
        with patch("snellctl.rotation.secrets.token_hex", side_effect=[self.before_keys.psk,
                   self.before_keys.shadowtls_password, "e" * 64]) as random:
            self.rotate()
        self.assertEqual(random.call_args_list[-1].args, (32,))
        self.assertEqual(read_client(root=self.root).keys.psk, "e" * 64)

    def test_exhausted_or_malformed_random_stops_before_intent(self):
        for value in (self.before_keys.psk, "bad\nsecret"):
            before = self.snapshot()
            with patch("snellctl.rotation.secrets.token_hex", return_value=value), self.assertRaises(Exception):
                self.rotate()
            self.assertEqual(before, self.snapshot())
            self.assertFalse(self.prep._exists(INTENT))

    def test_intent_exists_and_exports_block_before_first_stop(self):
        seen = []
        def inspect(command):
            if command.argv == ("systemctl", "stop", self.spec.snell_service):
                seen.append(self.prep._read_record(INTENT))
                with self.assertRaises(ClientError):
                    read_client(root=self.root)
        self.host.local_override = inspect
        self.rotate()
        self.assertGreaterEqual(len(seen), 1)
        self.assertTrue(all(item == seen[0] for item in seen))
        self.assertEqual(seen[0]["component"], "snell")
        for key in (self.before_keys.psk, self.before_keys.shadowtls_password, TOKEN):
            self.assertNotIn(key, json.dumps(seen))

    def test_uncertain_stop_leaves_old_config_but_disables_entry(self):
        path = self.host.path(self.spec.node_dir + "/snell.conf")
        before = path.read_bytes()
        self.host.local_override = lambda c: Reply(-1, uncertain=True) if c.argv == ("systemctl", "stop", self.spec.snell_service) else None
        with self.assertRaises(PreparationError):
            self.rotate()
        self.assertEqual(path.read_bytes(), before)
        self.assert_stopped()

    def test_stop_noop_or_lingering_port_never_changes_key(self):
        path = self.host.path(self.spec.node_dir + "/snell.conf")
        before = path.read_bytes()
        self.host.local_override = lambda c: Reply(0) if c.argv == ("systemctl", "stop", self.spec.snell_service) else None
        with self.assertRaises(PreparationError):
            self.rotate()
        self.assertEqual(path.read_bytes(), before)
        self.assert_stopped()

    def test_lingering_listener_after_stop_refuses_replacement(self):
        self.host.local_override = lambda c: Reply(0, "occupied\n") if c.argv == ("ss", "-H", "-lntu", "sport = :31001") else None
        with self.assertRaises(PreparationError):
            self.rotate()
        self.assert_stopped()
        self.assertEqual(self.prep._read_record("public-ready")["node"], self.prep._read_record("public-files"))

    def test_start_failure_does_not_restore_old_key(self):
        self.host.local_override = lambda c: Reply(1, TOKEN) if c.argv == ("systemctl", "start", self.spec.snell_service) else None
        with self.assertRaises(PreparationError) as error:
            self.rotate()
        self.assertNotIn(TOKEN, str(error.exception))
        text = self.host.path(self.spec.node_dir + "/snell.conf").read_text()
        self.assertNotIn(self.before_keys.psk, text)
        self.assert_stopped()

    def test_post_start_tls_failure_keeps_inspection_marker(self):
        def fail_probe(command):
            if command.argv == ("systemctl", "start", self.spec.snell_service):
                self.probe.return_value = False
        self.host.local_override = fail_probe
        with self.assertRaises(PreparationError):
            self.rotate()
        self.assert_stopped()

    def test_config_write_failure_blocks_export_and_retry(self):
        self.fail_manifest(self.spec.node_dir + "/snell.conf")

    def fail_manifest(self, target):
        original = self.prep.files.replace_owned
        def fail(path, *args, **kwargs):
            if path == target:
                raise OSError("disk full")
            return original(path, *args, **kwargs)
        with patch.object(self.prep.files, "replace_owned", side_effect=fail), self.assertRaises(PreparationError):
            self.rotate()
        self.assert_stopped()

    def test_first_manifest_failure_preserves_intent(self):
        self.fail_manifest(STATE + "/public-files.json")

    def test_second_manifest_failure_blocks_mismatched_pair(self):
        self.fail_manifest(STATE + "/public-ready.json")
        self.assertNotEqual(self.prep._read_record("public-files"), self.prep._read_record("public-ready")["node"])

    def test_interruption_after_service_stop_is_not_retried(self):
        self.host.local_override = lambda c: (_ for _ in ()).throw(KeyboardInterrupt()) if c.argv == ("systemctl", "start", self.spec.snell_service) else None
        with self.assertRaises(PreparationError):
            self.rotate()
        self.assert_stopped()

    def test_failure_to_disable_is_reported_uncertain_and_keeps_record(self):
        def fail(c):
            if c.argv in (("systemctl", "start", self.spec.snell_service),
                          ("systemctl", "disable", self.spec.shadowtls_service)):
                return Reply(1)
        self.host.local_override = fail
        with self.assertRaisesRegex(PreparationError, "结果不确定"):
            self.rotate()
        self.assert_pending()

    def test_unlink_fsync_failure_restores_absent_intent(self):
        original = self.prep.files.unlink_owned
        def fail(path, identity):
            original(path, identity)
            if path.endswith(INTENT + ".json"):
                raise OSError("fsync failed")
        with patch.object(self.prep.files, "unlink_owned", side_effect=fail), self.assertRaises(PreparationError):
            self.rotate()
        self.assert_stopped()

    def test_no_key_material_in_records_or_commands_after_success(self):
        self.rotate()
        keys = read_client(root=self.root).keys
        outputs = "\n".join(p.read_text() for p in self.host.path(STATE).glob("*.json")) + repr(self.host.calls)
        for key in (keys.psk, keys.shadowtls_password, self.before_keys.psk, TOKEN):
            self.assertNotIn(key, outputs)

    def test_intent_creation_failure_never_stops_services(self):
        original = self.prep.files.write_new
        def fail(path, *args, **kwargs):
            if path == STATE + "/" + INTENT + ".json":
                raise OSError("disk full")
            return original(path, *args, **kwargs)
        before = self.snapshot()
        with patch.object(self.prep.files, "write_new", side_effect=fail), self.assertRaises(OSError):
            self.rotate()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.mutations(), [])

    def test_permission_drift_is_not_repaired(self):
        path = self.host.path(self.spec.node_dir + "/snell.conf")
        path.chmod(0o644)
        with self.assertRaises(PreparationError):
            self.rotation.check("snell")
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.mutations(), [])

    def test_config_changed_during_atomic_write_is_not_overwritten(self):
        path = self.spec.node_dir + "/snell.conf"
        original = self.prep.files.write_new
        def race(target, content, mode=0o600):
            original(target, content, mode)
            if target == path + ".snellctl-new":
                self.host.write(path, b"foreign edit\n")
        with patch.object(self.prep.files, "write_new", side_effect=race), self.assertRaises(PreparationError):
            self.rotate()
        self.assertEqual(self.host.path(path).read_bytes(), b"foreign edit\n")
        self.assertEqual(self.host.path(path + ".snellctl-new").stat().st_mode & 0o777, 0o600)
        self.assert_stopped()

    def test_manifest_changed_during_service_start_is_preserved(self):
        target = STATE + "/public-files.json"
        def race(command):
            if command.argv == ("systemctl", "start", self.spec.snell_service):
                self.host.write(target, b'{"foreign": true}\n')
        self.host.local_override = race
        with self.assertRaises(PreparationError):
            self.rotate()
        self.assertEqual(json.loads(self.host.path(target).read_bytes()), {"foreign": True})
        self.assert_stopped()

    def test_intent_changed_during_service_start_is_not_removed(self):
        def race(command):
            if command.argv == ("systemctl", "start", self.spec.snell_service):
                self.host.write(STATE + "/" + INTENT + ".json", b'{"foreign": true}\n')
        self.host.local_override = race
        with self.assertRaises(PreparationError):
            self.rotate()
        self.assertEqual(self.prep._read_record(INTENT), {"foreign": True})
        self.assert_stopped()

    def test_disabled_timer_stops_precheck_without_restart(self):
        self.host.local_override = lambda c: Reply(0, "ActiveState=inactive\nSubState=dead\nUnitFileState=disabled\n") \
            if c.argv[:3] == ("systemctl", "show", "certbot.timer") and "Triggers" in c.argv[-1] else None
        with self.assertRaises(PreparationError):
            self.rotation.check("shadowtls")
        self.assertEqual(self.mutations(), [])
        self.assertFalse(self.prep._exists(INTENT))


class RotationWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.engine = Mock()
        self.plan = RotationPlan("snell", "node.example.net", 24443, "d" * 64)
        self.engine.check.return_value = self.plan
        self.engine.rotate.return_value = "key-rotated-external-test-required"
        self.ui = Console(["1", "y", "y"])

    @contextmanager
    def factory(self):
        yield self.engine

    def run_rotation(self):
        return run_rotation(factory=self.factory, terminal=self.ui)

    def test_sequence_has_no_token_prompt_no_client_secret_display(self):
        self.assertEqual(self.run_rotation(), 0)
        self.assertEqual([c[0] for c in self.engine.mock_calls], ["check", "rotate"])
        self.engine.rotate.assert_called_once_with(self.plan, confirm_change=True, confirm_ssh_reconnected=True)
        self.ui.secret.assert_not_called()
        self.assertIn("尚未验证客户端密钥认证", self.ui.text)
        self.assertIn("client 或菜单 5", self.ui.text)

    def test_shadowtls_selection_and_distinct_confirmation(self):
        self.ui = Console(["2", "y", "y"])
        self.engine.check.return_value = replace(self.plan, component="shadowtls")
        self.assertEqual(self.run_rotation(), 0)
        self.engine.check.assert_called_once_with("shadowtls")
        self.assertIn("ShadowTLS 密码", self.ui.prompts[-1])

    def test_noninteractive_never_opens_host_adapter(self):
        self.ui.interactive = lambda: False
        factory = Mock()
        self.assertEqual(run_rotation(factory=factory, terminal=self.ui), 2)
        factory.assert_not_called()

    def test_cancel_any_prompt_does_not_rotate(self):
        for index in range(3):
            answers = ["1", "y", "y"]
            answers[index] = ""
            self.ui = Console(answers)
            self.assertEqual(self.run_rotation(), 130)
        self.engine.rotate.assert_not_called()

    def test_eof_or_ctrl_c_each_prompt_does_not_rotate(self):
        for error in (EOFError, KeyboardInterrupt):
            for index in range(3):
                answers = ["1", "y", "y"]
                answers[index] = error()
                self.ui = Console(answers)
                self.assertEqual(self.run_rotation(), 130)
        self.engine.rotate.assert_not_called()

    def test_legacy_chinese_confirmation_cancels(self):
        self.ui = Console(["1", "y", "更换 Snell"])
        self.assertEqual(self.run_rotation(), 130)
        self.engine.rotate.assert_not_called()

    def test_tty_change_after_confirmation_prevents_write(self):
        self.ui.interactive = Mock(side_effect=[True, False])
        self.assertEqual(self.run_rotation(), 1)
        self.engine.rotate.assert_not_called()
        self.assertIn('"host_changes_attempted": false', self.ui.text)

    def test_precheck_failure_redacts_original_error(self):
        self.engine.check.side_effect = RuntimeError(TOKEN)
        self.assertEqual(self.run_rotation(), 1)
        self.engine.rotate.assert_not_called()
        self.assertNotIn(TOKEN, self.ui.text)
        self.assertIn('"host_changes_attempted": false', self.ui.text)

    def test_mutation_failure_never_claims_no_changes_or_rollback(self):
        self.engine.rotate.side_effect = RuntimeError(TOKEN)
        self.assertEqual(self.run_rotation(), 1)
        self.assertIn('"host_changes_attempted": true', self.ui.text)
        self.assertIn("旧密钥不保证可用", self.ui.text)
        self.assertNotIn(TOKEN, self.ui.text)
        self.assertNotIn("已回滚", self.ui.text)

    def test_unexpected_result_is_not_success(self):
        self.engine.rotate.return_value = "unknown"
        self.assertEqual(self.run_rotation(), 1)
        self.assertNotIn("所选密钥已更换", self.ui.text)


class RotationCliTests(unittest.TestCase):
    def test_opt_in_required(self):
        with patch("snellctl.rotation.run_rotation") as run, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["rotate-key"]), 2)
        run.assert_not_called()

    def test_dispatch_and_exit_code(self):
        with patch("snellctl.rotation.run_rotation", return_value=130) as run:
            self.assertEqual(main(["rotate-key", "--experimental"]), 130)
        run.assert_called_once_with()

    def test_no_secret_force_root_or_yes_argument(self):
        for option in ("--yes", "--force", "--key", "--token", "--root"):
            with redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit):
                main(["rotate-key", "--experimental", option, TOKEN])
            self.assertNotIn(TOKEN, output.getvalue())

    def test_menu_hidden_without_opt_in(self):
        with patch("builtins.input", side_effect=["8", "0"]), redirect_stdout(io.StringIO()) as output, \
                patch("snellctl.rotation.run_rotation") as run:
            self.assertEqual(run_menu(), 0)
        run.assert_not_called()
        self.assertNotIn("8. 单独", output.getvalue())

    def test_experimental_menu_dispatch_and_interruption_warning(self):
        with patch("builtins.input", side_effect=["8", EOFError()]), redirect_stdout(io.StringIO()) as output, \
                patch("snellctl.rotation.run_rotation", return_value=1) as run:
            self.assertEqual(run_menu(experimental=True), 130)
        run.assert_called_once_with()
        self.assertIn("可能已改变系统", output.getvalue())


if __name__ == "__main__":
    unittest.main()
