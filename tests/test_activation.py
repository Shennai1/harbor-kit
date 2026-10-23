from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from snellctl.activation import Activation, DEFAULT_LINK, PACKAGE_CONFIGS
from snellctl.deployment import NodeSpec, SNELL_BINARY, SHADOWTLS_BINARY, render_files, NodeSecrets
from snellctl.hostprep import Preparation, PreparationError, Reply, STATE, POLICY, UNITS
from test_hostprep import FakeHost, DOMAIN, TOKEN


class ActiveHost(FakeHost):
    def __init__(self, root):
        super().__init__(root)
        self.active = set()
        self.version = "1.26.3"
        self.pids = {"nginx.service": 100, "snellctl-snell-main.service": 101, "snellctl-shadowtls-main.service": 102}
        self.local_override = None
        self.default_md5 = {}

    def __call__(self, command):
        args = command.argv
        if self.local_override:
            value = self.local_override(command)
            if value is not None:
                self.calls.append(command)
                return value
        if args[0] == "apt-get" and "install" in args and "--simulate" not in args:
            result = super().__call__(command)
            for path in PACKAGE_CONFIGS:
                data = ("# package fixture " + path + "\n").encode()
                self.write(path, data, 0o644)
                self.default_md5[path] = hashlib.md5(data).hexdigest()
            for directory in ("/etc/nginx/sites-enabled", "/etc/nginx/conf.d", "/etc/nginx/modules-enabled"):
                self.path(directory).mkdir(parents=True, exist_ok=True)
            self.path(DEFAULT_LINK).symlink_to("/etc/nginx/sites-available/default")
            return result
        if args[0] == "dpkg-query" and "-f=${Conffiles}\n" in args:
            self.calls.append(command)
            return Reply(0, "".join(f" {p} {h}\n" for p, h in self.default_md5.items()))
        if args == ("nginx", "-v"):
            self.calls.append(command)
            return Reply(0, "nginx version: nginx/" + self.version + "\n")
        if args == ("nginx", "-T"):
            self.calls.append(command)
            configs = ["/etc/nginx/nginx.conf", "/etc/nginx/mime.types"]
            if self.path(DEFAULT_LINK).is_symlink():
                configs.append(DEFAULT_LINK)
            if self.path("/etc/nginx/conf.d/snellctl-main.conf").exists():
                configs.append("/etc/nginx/conf.d/snellctl-main.conf")
            return Reply(0, "".join(f"# configuration file {p}:\n" for p in configs))
        if args[0] == "ss":
            self.calls.append(command)
            if args == ("ss", "-H", "-lntup") and set(self.pids) <= self.active:
                return Reply(0, "\n".join([
                    'tcp LISTEN 0 511 127.0.0.1:31443 0.0.0.0:* users:(("nginx",pid=100,fd=5))',
                    'tcp LISTEN 0 4096 127.0.0.1:31001 0.0.0.0:* users:(("snell-server",pid=101,fd=5))',
                    'udp UNCONN 0 4096 127.0.0.1:31001 0.0.0.0:* users:(("snell-server",pid=101,fd=6))',
                    'tcp LISTEN 0 1024 127.0.0.1:443 0.0.0.0:* users:(("shadow-tls",pid=102,fd=5))',
                    'tcp LISTEN 0 128 0.0.0.0:54321 0.0.0.0:* users:(("sshd",pid=999,fd=7))',
                ]) + "\n")
            return Reply(0)
        if args[0] in {SNELL_BINARY, SHADOWTLS_BINARY}:
            self.calls.append(command)
            return Reply(0, "snell-server v5.0.1 (test)\n" if args[0] == SNELL_BINARY else "shadow-tls 0.2.25\n")
        if args[:2] in {("systemctl", "start"), ("systemctl", "stop")}:
            self.calls.append(command)
            (self.active.add if args[1] == "start" else self.active.discard)(args[2])
            return Reply(0)
        if args[:2] == ("systemctl", "show") and args[2] in self.active:
            self.calls.append(command)
            prefix = "/usr/lib/systemd/system/" if args[2] == "nginx.service" else "/etc/systemd/system/"
            return Reply(0, "ActiveState=active\nSubState=running\nExecMainStatus=0\nNRestarts=0\nDropInPaths=\n"
                         f"MainPID={self.pids[args[2]]}\nFragmentPath={prefix + args[2]}\n")
        if args == ("nginx", "-t") or args[0] == "systemd-analyze":
            self.calls.append(command)
            return Reply(0)
        if args[:2] == ("certbot", "renew"):
            self.calls.append(command)
            return Reply(0, "Hook 'deploy-hook' ran with output:\n snellctl: nginx reload command succeeded\n")
        return super().__call__(command)


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.host = ActiveHost(self.root)
        self.prep = Preparation(self.root, self.host)
        self.addCleanup(self.prep.files.close)
        self.prep.initialize()
        self.prep.packages()
        self.prep.credential(TOKEN)
        self.prep.certificate(DOMAIN, production=False, agree_tos=True)
        self.prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True)
        self.probe = Mock(return_value=True)
        self.engine = Activation(self.prep, self.probe, readiness_timeout=0)
        self.spec = NodeSpec(DOMAIN)
        self.downloads = {"snell": b"test archive", "shadow-tls": b"test executable"}
        verify = patch("snellctl.activation.verify", side_effect=lambda a, data: b"TEST-BINARY-" + a.name.encode())
        self.verify = verify.start()
        self.addCleanup(verify.stop)

    def activate(self):
        return self.engine.activate(self.spec, self.downloads)

    def test_full_local_flow_no_public_entry_or_firewall_changes(self):
        self.assertEqual(self.activate(), "local-active-public-entry-not-enabled")
        config = json.loads(self.host.path(self.spec.node_dir + "/shadowtls.json").read_bytes())
        self.assertEqual(config["server"]["listen"], "127.0.0.1:443")
        self.assertEqual(self.host.active, set(self.host.pids))
        self.assertFalse(self.host.path(DEFAULT_LINK).is_symlink())
        self.assertTrue(self.host.path(POLICY).exists())
        for unit in UNITS[1:]:
            self.assertTrue(self.host.path("/etc/systemd/system/" + unit).is_symlink())
        for command in self.host.calls:
            self.assertNotIn(command.argv[0], {"ufw", "iptables", "ip6tables", "nft"})
            self.assertNotIn("enable", command.argv)
            self.assertNotIn("unmask", command.argv)
        self.assertEqual([call.args[1] for call in self.probe.call_args_list], [31443, 443])
        self.assertEqual(self.verify.call_count, 2)

    def test_actual_nginx_version_overrides_preview(self):
        self.host.version = "1.22.1"
        self.activate()
        text = self.host.path(self.spec.nginx_conf).read_text()
        self.assertIn("ssl http2", text)
        self.assertNotIn("http2 on", text)

    def test_repeat_does_not_rotate_keys_or_start_again(self):
        self.activate()
        data = self.host.path(self.spec.node_dir + "/snell.conf").read_bytes()
        before = len([c for c in self.host.calls if c.argv[:2] == ("systemctl", "start")])
        with patch("snellctl.activation.new_node_secrets", side_effect=AssertionError("must not rotate")):
            self.assertEqual(self.activate(), "already-local-active")
        self.assertEqual(data, self.host.path(self.spec.node_dir + "/snell.conf").read_bytes())
        self.assertEqual(before, len([c for c in self.host.calls if c.argv[:2] == ("systemctl", "start")]))

    def test_mismatched_repeat_stops(self):
        self.activate()
        with self.assertRaises(PreparationError):
            self.engine.activate(replace(self.spec, public_port=444), self.downloads)

    def test_foreign_file_not_overwritten(self):
        self.host.write(self.spec.nginx_conf, b"foreign", 0o644)
        with self.assertRaises(PreparationError):
            self.activate()
        self.assertEqual(self.host.path(self.spec.nginx_conf).read_bytes(), b"foreign")
        self.assertFalse(self.host.path(STATE + "/activation-intent.json").exists())

    def test_changed_global_config_stops_before_intent(self):
        self.host.write("/etc/nginx/nginx.conf", b"foreign;", 0o644)
        with self.assertRaises(PreparationError):
            self.activate()
        self.assertEqual(self.host.active, set())
        self.assertTrue(self.host.path(DEFAULT_LINK).is_symlink())

    def test_extra_loaded_configuration_rejected(self):
        self.host.local_override = lambda c: Reply(0, "# configuration file /foreign:\n") if c.argv == ("nginx", "-T") else None
        with self.assertRaises(PreparationError):
            self.activate()
        self.assertEqual(self.host.active, set())

    def test_occupied_port_stops_before_writing(self):
        self.host.local_override = lambda c: Reply(0, "busy") if c.argv[0] == "ss" else None
        with self.assertRaises(PreparationError):
            self.activate()
        self.assertFalse(self.host.path("/opt/snellctl").exists())

    def test_download_reverified_before_install(self):
        from snellctl.artifacts import ArtifactError, verify
        self.verify.side_effect = verify
        with self.assertRaises(ArtifactError):
            self.activate()
        self.assertFalse(self.host.path("/opt/snellctl").exists())

    def test_extra_service_dropin_rejected(self):
        self.host.path("/etc/systemd/system/nginx.service.d").mkdir()
        with self.assertRaises(PreparationError):
            self.activate()

    def test_config_validation_failure_keeps_start_guard(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("nginx", "-t") else None
        with self.assertRaises(PreparationError):
            self.activate()
        self.assertTrue(self.host.path("/etc/systemd/system/nginx.service").is_symlink())
        self.assertEqual(self.host.active, set())
        with self.assertRaises(PreparationError):
            self.activate()

    def test_probe_failure_stops_only_attempted_services_and_keeps_intent(self):
        self.probe.side_effect = PreparationError("PRIVATE-TEST-DETAIL")
        with self.assertRaises(PreparationError) as error:
            self.activate()
        self.assertNotIn("PRIVATE", str(error.exception))
        self.assertEqual(self.host.active, set())
        stopped = [c.argv[2] for c in self.host.calls if c.argv[:2] == ("systemctl", "stop")]
        self.assertEqual(stopped, [self.spec.shadowtls_service, self.spec.snell_service, "nginx.service"])
        self.assertTrue(self.host.path(STATE + "/activation-intent.json").exists())
        self.assertFalse(self.host.path(STATE + "/activation-ready.json").exists())

    def test_uncertain_start_also_stopped(self):
        self.host.local_override = lambda c: Reply(-1, uncertain=True) if c.argv == ("systemctl", "start", self.spec.shadowtls_service) else None
        with self.assertRaises(PreparationError):
            self.activate()
        self.assertEqual(self.host.active, set())
        self.assertIn(("systemctl", "stop", self.spec.shadowtls_service), [c.argv for c in self.host.calls])

    def test_failed_stop_not_reported_as_stopped(self):
        self.probe.return_value = False
        self.host.local_override = lambda c: Reply(1) if c.argv[:2] == ("systemctl", "stop") else None
        with self.assertRaisesRegex(PreparationError, "未能确认"):
            self.activate()

    def test_public_or_incomplete_listener_does_not_pass(self):
        for line in ('tcp LISTEN 0 1024 0.0.0.0:443 0.0.0.0:* users:(("shadow-tls",pid=102,fd=7))\n', ""):
            with self.subTest(line=line):
                self.host.local_override = lambda c: Reply(0, line) if c.argv == ("ss", "-H", "-lntup") else None
                self.host.active = set(self.host.pids)
                with self.assertRaises(PreparationError):
                    self.engine._running(self.spec)

    def test_file_drift_blocks_repeat(self):
        self.activate()
        self.host.write(self.spec.node_dir + "/snell.conf", b"external change")
        with self.assertRaises(PreparationError):
            self.activate()

    def test_incomplete_file_manifest_does_not_skip_validation(self):
        self.activate()
        path = self.host.path(STATE + "/activation-ready.json")
        record = json.loads(path.read_text())
        record["files"] = {}
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(PreparationError, "清单不完整"):
            self.activate()

    def test_runtime_service_override_stops_before_unmasking(self):
        self.host.write("/run/systemd/system/nginx.service", b"foreign", 0o644)
        with self.assertRaises(PreparationError):
            self.activate()
        self.assertTrue(self.host.path("/etc/systemd/system/nginx.service").is_symlink())

    def test_interrupt_does_not_retry_or_discard_node_secrets(self):
        self.probe.side_effect = KeyboardInterrupt
        with self.assertRaises(PreparationError):
            self.activate()
        path = self.host.path(self.spec.node_dir + "/snell.conf")
        data = path.read_bytes()
        with self.assertRaises(PreparationError):
            self.activate()
        self.assertEqual(data, path.read_bytes())
        self.assertEqual(self.host.active, set())

    def test_state_contains_no_secret_copy(self):
        self.activate()
        secret = json.loads(self.host.path(self.spec.node_dir + "/shadowtls.json").read_text())["server"]["password"]
        for path in self.host.path(STATE).glob("*.json"):
            self.assertNotIn(secret, path.read_text())
            self.assertNotIn(TOKEN, path.read_text())

    def test_renewal_requires_confirmation(self):
        self.activate()
        with self.assertRaises(PreparationError):
            self.engine.test_renewal(self.spec, confirm_test=False)

    def test_renewal_checks_hook_and_served_cert_without_enabling_timer(self):
        self.activate()
        self.assertEqual(self.engine.test_renewal(self.spec, confirm_test=True), "renewal-tested-timer-still-blocked")
        command = next(c for c in self.host.calls if c.argv[:2] == ("certbot", "renew"))
        self.assertIn("--no-directory-hooks", command.argv)
        self.assertIn("--deploy-hook", command.argv)
        self.assertIn("--run-deploy-hooks", command.argv)
        self.assertTrue(command.capture_stderr)
        self.assertEqual(self.engine.test_renewal(self.spec, confirm_test=True), "already-renewal-tested")
        self.assertEqual(len([c for c in self.host.calls if c.argv[:2] == ("certbot", "renew")]), 1)
        self.assertTrue(self.host.path("/etc/systemd/system/certbot.timer").is_symlink())

    def test_zero_exit_without_hook_marker_not_success(self):
        self.activate()
        self.host.local_override = lambda c: Reply(0, "hook failed: PRIVATE") if c.argv[:2] == ("certbot", "renew") else None
        with self.assertRaises(PreparationError) as error:
            self.engine.test_renewal(self.spec, confirm_test=True)
        self.assertNotIn("PRIVATE", str(error.exception))
        with self.assertRaises(PreparationError):
            self.engine.test_renewal(self.spec, confirm_test=True)
        self.assertFalse(self.host.path(STATE + "/renewal-test-ready.json").exists())

    def test_hook_success_without_post_reload_health_is_not_pass(self):
        self.activate()
        self.probe.side_effect = [True, True, PreparationError("post reload failed")]
        with self.assertRaises(PreparationError):
            self.engine.test_renewal(self.spec, confirm_test=True)
        self.assertFalse(self.host.path(STATE + "/renewal-test-ready.json").exists())

    def test_template_defaults_and_explicit_loopback(self):
        keys = NodeSecrets("a" * 64, "b" * 64)
        self.assertIn('"listen": "0.0.0.0:443"', render_files(self.spec, keys)[1].content)
        self.assertIn('"listen": "127.0.0.1:443"', render_files(self.spec, keys, public_entry=False)[1].content)
        with self.assertRaises(ValueError):
            render_files(self.spec, keys, public_entry="false")


if __name__ == "__main__":
    unittest.main()
