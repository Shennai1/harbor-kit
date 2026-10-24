from contextlib import contextmanager, redirect_stdout, redirect_stderr
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
from snellctl.portchange import INTENT, RECORDS, PortChange, PortPlan
from snellctl.portchange import _rule_args, run_port_change
from snellctl.rotation import KeyRotation
from test_installer import Console
from test_hostprep import TOKEN
from test_publish import UFW_UNCHANGED
from test_rotation import RotationHost
import test_publish


class PortHost(RotationHost):
    def __init__(self, root):
        super().__init__(root)
        self.capability = "cap_net_bind_service"

    def __call__(self, command):
        args = command.argv
        if self.local_override:
            result = self.local_override(command)
            if result is not None:
                self.calls.append(command)
                return result
        override = self.local_override
        self.local_override = None
        try:
            return self._dispatch(command)
        finally:
            self.local_override = override

    def _dispatch(self, command):
        args = command.argv
        if args[:2] == ("ufw", "delete"):
            self.calls.append(command)
            port = args[args.index("port") + 1]
            assert args == ("ufw", "delete", *_rule_args(int(port)))
            self.rules.remove(f"ufw allow {port}/tcp comment 'snellctl-main'")
            self.input4.remove(f"-A ufw-user-input -p tcp --dport {port} -j ACCEPT")
            self.write("/etc/ufw/user.rules", ("\n".join(self.input4) + "\n").encode(), 0o640)
            return Reply(0, "Rule deleted\n")
        if args == ("systemctl", "daemon-reload"):
            unit = self.path("/etc/systemd/system/snellctl-shadowtls-main.service")
            if unit.exists():
                self.capability = "cap_net_bind_service" if "AmbientCapabilities=" in unit.read_text() else ""
        if args[:2] == ("systemctl", "show") and args[-1] == "NeedDaemonReload,CapabilityBoundingSet,AmbientCapabilities":
            self.calls.append(command)
            return Reply(0, f"NeedDaemonReload=no\nCapabilityBoundingSet={self.capability}\nAmbientCapabilities={self.capability}\n")
        result = super().__call__(command)
        if args == ("ss", "-H", "-lntup"):
            path = self.path("/etc/snellctl/nodes/main/shadowtls.json")
            if path.exists():
                listen = json.loads(path.read_bytes())["server"]["listen"]
                return Reply(0, result.output.replace("0.0.0.0:443 ", listen + " "))
        return result


class PortChangeTests(unittest.TestCase):
    def setUp(self):
        with patch("test_publish.PublicHost", PortHost):
            test_publish.PublicationTests.setUp(self)
        test_publish.PublicationTests.enable(self)
        self.ports = PortChange(self.engine)
        self.before_keys = read_client(root=self.root).keys
        self.host.calls.clear()
        self.probe.reset_mock()

    def change(self, port=24443):
        return self.ports.change(self.ports.check(port), confirm_change=True, confirm_ssh_reconnected=True)

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.lstat().st_mode, p.lstat().st_ino,
                str(p.readlink()) if p.is_symlink() else p.read_bytes() if p.is_file() else None)
                for p in self.root.rglob("*")}

    def mutations(self):
        return [c.argv for c in self.host.calls if c.argv[:2] in {
            ("ufw", "allow"), ("ufw", "delete"), ("systemctl", "start"), ("systemctl", "stop"),
            ("systemctl", "disable"), ("systemctl", "daemon-reload"), ("systemctl", "enable") }]

    def assert_pending(self):
        report = installation_status(root=self.root)
        self.assertEqual(report["port_change"], "needs-inspection")
        self.assertIn("端口更换：未确认完成", render_status(report))
        with self.assertRaises(ClientError):
            read_client(root=self.root)
        with self.assertRaises(Exception):
            self.ports.check(25443)
        with self.assertRaises(Exception):
            KeyRotation(self.engine).check("snell")
        with self.assertRaises(PreparationError):
            test_publish.PublicationTests.enable(self)

    def assert_stopped(self):
        self.assert_pending()
        self.assertNotIn(self.spec.shadowtls_service, self.host.active)
        self.assertNotIn(self.spec.shadowtls_service, self.host.enabled)
        self.assertIn(self.spec.snell_service, self.host.active)
        self.assertIn("nginx.service", self.host.active)
        self.assertIn("ufw.service", self.host.enabled)
        self.assertIn("certbot.timer", self.host.enabled)

    def test_low_to_high_only_changes_entry_unit_firewall_and_current_records(self):
        before = self.snapshot()
        self.assertEqual(self.change(), "port-changed-external-test-required")
        after = self.snapshot()
        changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
        self.assertEqual(changed, {"etc/snellctl/nodes/main/shadowtls.json", "etc/ufw/user.rules",
                                  "etc/systemd/system/" + self.spec.shadowtls_service,
                                  *(STATE.lstrip("/") + "/" + n + ".json" for n in RECORDS)})
        data = read_client(root=self.root)
        self.assertEqual(data.public_port, 24443)
        self.assertEqual(data.keys, self.before_keys)
        self.assertIn(", 24443, psk=", data.surge_line("8.8.8.8"))
        self.assertEqual(self.host.capability, "")
        self.assertEqual(self.host.rules, ["ufw allow 54321/tcp comment 'SSH'",
                                          "ufw allow 24443/tcp comment 'snellctl-main'"])
        self.assertEqual(self.prep.status()["port_change"], "none-pending")
        self.assertEqual(self.mutations(), [
            ("systemctl", "stop", self.spec.shadowtls_service), ("systemctl", "daemon-reload"),
            ("ufw", *_rule_args(24443)), ("systemctl", "start", self.spec.shadowtls_service),
            ("ufw", "delete", *_rule_args(443))])

    def test_high_to_low_and_repeated_port_changes_keep_current_records_usable(self):
        self.change()
        self.change(25443)
        self.change(444)
        self.assertEqual(self.host.capability, "cap_net_bind_service")
        self.assertEqual(read_client(root=self.root).public_port, 444)
        self.assertEqual(read_client(root=self.root).keys, self.before_keys)
        self.assertEqual(self.engine.enable(replace(self.spec, public_port=444), ssh_port=54321,
                                           confirm_public=True, confirm_renewal=True, confirm_ssh_reconnected=True),
                         "already-public-enabled-external-test-required")

    def test_same_port_class_keeps_service_file_identity_and_no_reload(self):
        unit = self.spec.shadowtls_service
        path = "/etc/systemd/system/" + unit
        before = self.prep.files.identity(path)
        self.change(444)
        self.assertEqual(self.prep.files.identity(path), before)
        self.assertNotIn(("systemctl", "daemon-reload"), self.mutations())

    def test_key_rotation_and_port_change_can_alternate(self):
        rotate = KeyRotation(self.engine)
        for target in ("snell", "shadowtls"):
            rotate.rotate(rotate.check(target), confirm_change=True, confirm_ssh_reconnected=True)
            keys = read_client(root=self.root).keys
            self.change(24443 if target == "snell" else 443)
            self.assertEqual(read_client(root=self.root).keys, keys)

    def test_no_ssh_backend_token_certificate_or_ipv6_changes(self):
        paths = [CREDENTIAL, *UFW_UNCHANGED, self.spec.nginx_conf, self.spec.node_dir + "/snell.conf",
                 STATE + "/activation-ready.json", STATE + "/renewal-test-intent.json"]
        before = {p: self.host.path(p).read_bytes() for p in paths}
        self.change()
        self.assertEqual(before, {p: self.host.path(p).read_bytes() for p in paths})
        for c in self.host.calls:
            self.assertNotIn(c.argv[0], {"apt-get", "certbot", "curl", "wget", "nft"})
            self.assertNotIn("ssh.service", c.argv)
            if c.argv[0] in {"iptables", "ip6tables"}:
                self.assertEqual(c.argv[1], "-S")
            if c.argv[0] == "ufw":
                self.assertNotIn(c.argv[1], {"reset", "disable", "enable", "reload", "default"})

    def test_invalid_same_backend_or_ssh_ports_stop_without_writes(self):
        before = self.snapshot()
        for value in (False, True, "443", None, 0, -1, 65536, 443, 31001, 31443, 54321):
            with self.subTest(port=value), self.assertRaises(Exception):
                self.ports.check(value)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.mutations(), [])

    def test_confirmations_required_before_any_commands(self):
        plan = self.ports.check(24443)
        self.host.calls.clear()
        for key in ("confirm_change", "confirm_ssh_reconnected"):
            for value in (False, 1, "yes", None):
                with self.assertRaises(PreparationError):
                    self.ports.change(plan, **{"confirm_change": True, "confirm_ssh_reconnected": True, key: value})
        self.assertEqual(self.host.calls, [])

    def test_stale_plan_after_key_rotation_is_rejected(self):
        plan = self.ports.check(24443)
        rotation = KeyRotation(self.engine)
        rotation.rotate(rotation.check("snell"), confirm_change=True, confirm_ssh_reconnected=True)
        self.host.calls.clear()
        with self.assertRaises(PreparationError):
            self.ports.change(plan, confirm_change=True, confirm_ssh_reconnected=True)
        self.assertEqual(self.mutations(), [])
        self.assertFalse(self.prep._exists(INTENT))

    def test_vacancy_checks_tcp_udp_and_both_families(self):
        self.host.local_override = lambda c: Reply(0, 'udp UNCONN 0 0 [::]:24443 [::]:*\n') \
            if c.argv == ("ss", "-H", "-lntu", "sport = :24443") else None
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.mutations(), [])

    def test_new_port_rule_or_unknown_firewall_refused(self):
        for rule in ("ufw allow 24443/tcp", "ufw deny 24443/tcp", "ufw allow Nginx"):
            self.host.rules.append(rule)
            with self.assertRaises(PreparationError):
                self.change()
            self.host.rules.pop()
        self.assertEqual(self.mutations(), [])

    def test_firewall_drift_during_confirmation_is_not_repaired(self):
        plan = self.ports.check(24443)
        self.host.rules.append("ufw allow 60000/tcp comment 'foreign'")
        with self.assertRaises(PreparationError):
            self.ports.change(plan, confirm_change=True, confirm_ssh_reconnected=True)
        self.assertEqual(self.mutations(), [])

    def test_foreign_or_ambiguous_old_rule_never_deleted(self):
        self.host.rules[-1] = "ufw allow 443/tcp comment 'foreign'"
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.mutations(), [])

    def test_precheck_tls_failure_has_no_side_effects(self):
        self.probe.return_value = False
        before = self.snapshot()
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.mutations(), [])

    def test_existing_candidate_at_any_replaced_path_preserved(self):
        paths = [self.spec.node_dir + "/shadowtls.json", "/etc/systemd/system/" + self.spec.shadowtls_service,
                 *(STATE + "/" + n + ".json" for n in RECORDS)]
        for path in paths:
            candidate = self.host.path(path + ".snellctl-new")
            candidate.symlink_to("/missing")
            with self.assertRaises(PreparationError):
                self.change()
            self.assertTrue(candidate.is_symlink())
            self.assertFalse(self.prep._exists(INTENT))
            candidate.unlink()

    def test_corrupt_or_symlink_intent_blocks_reads_keys_and_publication(self):
        path = self.host.path(STATE + "/" + INTENT + ".json")
        for symlink in (False, True):
            if symlink:
                path.symlink_to("/missing")
            else:
                self.host.write(STATE + "/" + INTENT + ".json", b"broken")
            self.assert_pending()
            self.assertEqual(self.host.calls, [])
            path.unlink()

    def test_pending_key_rotation_blocks_port_change(self):
        self.prep._record("key-rotation-intent", {})
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.host.calls, [])

    def test_stop_noop_never_writes_new_configuration(self):
        before = self.host.path(self.spec.node_dir + "/shadowtls.json").read_bytes()
        self.host.local_override = lambda c: Reply(0) if c.argv == ("systemctl", "stop", self.spec.shadowtls_service) else None
        with self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(before, self.host.path(self.spec.node_dir + "/shadowtls.json").read_bytes())
        self.assert_pending()

    def test_failed_start_leaves_old_rule_and_stops_entry(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "start", self.spec.shadowtls_service) else None
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_stopped()
        self.assertIn("ufw allow 443/tcp comment 'snellctl-main'", self.host.rules)
        self.assertFalse(any(c.argv[:2] == ("ufw", "delete") for c in self.host.calls))

    def test_tls_failure_on_new_port_never_deletes_old_rule(self):
        self.probe.side_effect = lambda spec, port, cert: port != 24443
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_stopped()
        self.assertFalse(any(c.argv[:2] == ("ufw", "delete") for c in self.host.calls))

    def test_noop_ufw_add_or_delete_does_not_claim_success(self):
        for action in ("allow", "delete"):
            with self.subTest(action=action):
                # Each case has its own completed host and ownership state.
                self.setUp()
                self.host.local_override = lambda c: Reply(0) if c.argv[:2] == ("ufw", action) else None
                with self.assertRaises(PreparationError):
                    self.change()
                self.assert_stopped()

    def test_uncertain_delete_preserves_rules_without_blind_retries(self):
        self.host.local_override = lambda c: Reply(-1, uncertain=True) if c.argv[:2] == ("ufw", "delete") else None
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_stopped()
        self.assertEqual(sum(c.argv[:2] == ("ufw", "delete") for c in self.host.calls), 1)
        self.assertEqual(len(self.host.rules), 3)

    def test_ipv6_drift_on_add_is_detected_before_old_rule_deletion(self):
        def drift(c):
            if c.argv[:2] == ("ufw", "allow"):
                self.host.write("/etc/ufw/user6.rules", b"foreign change")
        self.host.local_override = drift
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_stopped()
        self.assertFalse(any(c.argv[:2] == ("ufw", "delete") for c in self.host.calls))

    def test_capability_mismatch_or_failed_reload_stops_before_ufw_change(self):
        self.host.local_override = lambda c: Reply(0, "NeedDaemonReload=yes\n") \
            if c.argv[-1] == "NeedDaemonReload,CapabilityBoundingSet,AmbientCapabilities" and self.prep._exists(INTENT) else None
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_stopped()
        self.assertFalse(any(c.argv[:2] == ("ufw", "allow") for c in self.host.calls))

    def test_record_failure_keeps_intent_and_blocks_export(self):
        original = self.prep.files.replace_owned
        def fail(path, *args, **kwargs):
            if path == STATE + "/public-ready.json":
                raise OSError("test failure")
            return original(path, *args, **kwargs)
        with patch.object(self.prep.files, "replace_owned", side_effect=fail), self.assertRaises(PreparationError):
            self.change()
        self.assert_stopped()

    def test_any_configuration_or_record_replacement_failure_keeps_intent(self):
        targets = [self.spec.node_dir + "/shadowtls.json", "/etc/systemd/system/" + self.spec.shadowtls_service,
                   *(STATE + "/" + name + ".json" for name in RECORDS)]
        for target in targets:
            with self.subTest(target=target):
                self.setUp()
                original = self.prep.files.replace_owned
                def fail(path, *args, **kwargs):
                    if path == target:
                        raise OSError("disk full")
                    return original(path, *args, **kwargs)
                with patch.object(self.prep.files, "replace_owned", side_effect=fail), self.assertRaises(PreparationError):
                    self.change()
                self.assert_stopped()

    def test_initial_capability_drift_stops_before_intent(self):
        self.host.capability = "cap_sys_admin"
        with self.assertRaises(PreparationError):
            self.change()
        self.assertFalse(self.prep._exists(INTENT))
        self.assertEqual(self.mutations(), [])

    def test_daemon_reload_failure_leaves_entry_stopped(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "daemon-reload") else None
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_stopped()
        self.assertEqual(len(self.host.rules), 2)

    def test_intent_created_before_stop_without_export_or_secrets(self):
        seen = []
        def inspect(c):
            if c.argv == ("systemctl", "stop", self.spec.shadowtls_service):
                seen.append(self.prep._read_record(INTENT))
                with self.assertRaises(ClientError):
                    read_client(root=self.root)
        self.host.local_override = inspect
        self.change()
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0]["old_port"], 443)
        self.assertEqual(seen[0]["new_port"], 24443)

    def test_intent_write_failure_has_no_service_or_firewall_effects(self):
        original = self.prep.files.write_new
        def fail(path, *args, **kwargs):
            if path.endswith(INTENT + ".json"):
                raise OSError("disk full")
            return original(path, *args, **kwargs)
        before = self.snapshot()
        with patch.object(self.prep.files, "write_new", side_effect=fail), self.assertRaises(OSError):
            self.change()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.mutations(), [])

    def test_busy_lock_refuses_operation_without_changes(self):
        before = self.snapshot()
        with self.prep._lock(), self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.host.calls, [])

    def test_atomic_config_write_does_not_overwrite_external_change(self):
        path = self.spec.node_dir + "/shadowtls.json"
        original = self.prep.files.write_new
        def race(target, *args, **kwargs):
            original(target, *args, **kwargs)
            if target == path + ".snellctl-new":
                self.host.write(path, b"foreign edit")
        with patch.object(self.prep.files, "write_new", side_effect=race), self.assertRaises(PreparationError):
            self.change()
        self.assertEqual(self.host.path(path).read_bytes(), b"foreign edit")
        self.assert_stopped()

    def test_manifest_or_intent_modified_during_start_is_preserved(self):
        for target in ("public-files", INTENT):
            with self.subTest(target=target):
                self.setUp()
                def race(c):
                    if c.argv == ("systemctl", "start", self.spec.shadowtls_service):
                        self.host.write(STATE + "/" + target + ".json", b'{"foreign": true}\n')
                self.host.local_override = race
                with self.assertRaises(PreparationError):
                    self.change()
                self.assertEqual(self.prep._read_record(target), {"foreign": True})
                self.assert_stopped()

    def test_final_probe_failure_after_old_rule_removed_blocks_success(self):
        deleted = False
        def mark(c):
            nonlocal deleted
            if c.argv[:2] == ("ufw", "delete"):
                deleted = True
        self.host.local_override = mark
        self.probe.side_effect = lambda *args: not deleted
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_stopped()
        self.assertNotIn("ufw allow 443/tcp comment 'snellctl-main'", self.host.rules)

    def test_failure_cleanup_uncertainty_is_explicit(self):
        def fail(c):
            if c.argv == ("systemctl", "disable", self.spec.shadowtls_service) or c.argv[:2] == ("ufw", "allow"):
                return Reply(-1, uncertain=True)
        self.host.local_override = fail
        with self.assertRaisesRegex(PreparationError, "结果不确定"):
            self.change()
        self.assert_pending()

    def test_no_secrets_in_success_records_or_command_arguments(self):
        self.change()
        text = "\n".join(p.read_text() for p in self.host.path(STATE).glob("*.json")) + repr(self.host.calls)
        for secret in (TOKEN, self.before_keys.psk, self.before_keys.shadowtls_password):
            self.assertNotIn(secret, text)

    def test_interruption_preserves_intent_and_no_fallback(self):
        def fail(c):
            if c.argv[:2] == ("ufw", "allow"):
                raise KeyboardInterrupt()
        self.host.local_override = fail
        with self.assertRaises(PreparationError):
            self.change()
        self.assert_stopped()

    def test_unlink_fsync_failure_restores_marker(self):
        original = self.prep.files.unlink_owned
        def fail(path, identity):
            original(path, identity)
            if path.endswith(INTENT + ".json"):
                raise OSError("fsync")
        with patch.object(self.prep.files, "unlink_owned", side_effect=fail), self.assertRaises(PreparationError):
            self.change()
        self.assert_stopped()

    def test_no_keys_or_token_in_intent(self):
        self.host.local_override = lambda c: Reply(1) if c.argv[:2] == ("ufw", "allow") else None
        with self.assertRaises(PreparationError):
            self.change()
        text = self.host.path(STATE + "/" + INTENT + ".json").read_text()
        for secret in (TOKEN, self.before_keys.psk, self.before_keys.shadowtls_password):
            self.assertNotIn(secret, text)


class PortWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.engine = Mock()
        self.plan = PortPlan("node.example.net", 443, 24443, 54321, "d" * 64)
        self.engine.check.return_value = self.plan
        self.engine.change.return_value = "port-changed-external-test-required"
        self.ui = Console(["24443", "已重连", "更换端口 24443"])

    @contextmanager
    def factory(self):
        yield self.engine

    def run_change(self):
        return run_port_change(factory=self.factory, terminal=self.ui)

    def test_sequence_confirms_exact_new_port_and_no_secret_display(self):
        self.assertEqual(self.run_change(), 0)
        self.engine.check.assert_called_once_with(24443)
        self.engine.change.assert_called_once_with(self.plan, confirm_change=True, confirm_ssh_reconnected=True)
        self.ui.secret.assert_not_called()
        self.assertIn("公网连接仍待客户端验证", self.ui.text)

    def test_cancel_or_eof_any_prompt_never_changes(self):
        for value in ("", EOFError(), KeyboardInterrupt()):
            for index in range(3):
                answers = ["24443", "已重连", "更换端口 24443"]
                answers[index] = value
                self.ui = Console(answers)
                self.assertEqual(self.run_change(), 130)
        self.engine.change.assert_not_called()

    def test_invalid_input_is_redacted_before_engine(self):
        for raw in ("0", "65536", "1;rm", "１２３", TOKEN, "1 2", "-3"):
            self.ui = Console([raw])
            self.assertEqual(self.run_change(), 1)
            self.assertNotIn(TOKEN, self.ui.text)
        self.engine.check.assert_not_called()

    def test_wrong_port_confirmation_cancels(self):
        self.ui = Console(["24443", "已重连", "更换端口 443"])
        self.assertEqual(self.run_change(), 130)
        self.engine.change.assert_not_called()

    def test_noninteractive_never_opens_adapter(self):
        self.ui.interactive = lambda: False
        factory = Mock()
        self.assertEqual(run_port_change(factory=factory, terminal=self.ui), 2)
        factory.assert_not_called()

    def test_tty_change_after_confirmation_never_changes(self):
        self.ui.interactive = Mock(side_effect=[True, False])
        self.assertEqual(self.run_change(), 1)
        self.engine.change.assert_not_called()

    def test_precheck_error_redacted(self):
        self.engine.check.side_effect = RuntimeError(TOKEN)
        self.assertEqual(self.run_change(), 1)
        self.assertNotIn(TOKEN, self.ui.text)
        self.assertIn('"host_changes_attempted": false', self.ui.text)

    def test_mutation_failure_and_unknown_result_never_claim_success(self):
        for fail in (True, False):
            self.setUp()
            if fail:
                self.engine.change.side_effect = RuntimeError(TOKEN)
            else:
                self.engine.change.return_value = "unknown"
            self.assertEqual(self.run_change(), 1)
            self.assertNotIn(TOKEN, self.ui.text)
            self.assertIn('"host_changes_attempted": true', self.ui.text)
            self.assertIn("不重试或重启", self.ui.text)

    def test_cli_requires_opt_in_and_routes_to_interactive_workflow(self):
        with patch("snellctl.portchange.run_port_change", return_value=130) as run, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["change-port"]), 2)
            run.assert_not_called()
            self.assertEqual(main(["change-port", "--experimental"]), 130)
            run.assert_called_once_with()

    def test_menu_hides_mutation_unless_experimental(self):
        for experimental in (False, True):
            with patch("snellctl.portchange.run_port_change", return_value=0) as run, \
                    patch("builtins.input", side_effect=["9", "0"]), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(run_menu(experimental=experimental), 0)
                self.assertEqual(run.call_count, int(experimental))
                self.assertEqual("9. 更换公网入口端口" in out.getvalue(), experimental)


if __name__ == "__main__":
    unittest.main()
