from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.activation import Activation, BINARIES, _binding
from snellctl.client import ClientData, ClientError, public_ipv4, read_client, real_reader, run_client
from snellctl.deployment import NodeSecrets, NodeSpec, render_files
from snellctl.hostprep import HostFiles, Preparation, STATE
from snellctl.menu import run_menu
from snellctl.publish import Publication
from test_hostprep import FakeHost, DOMAIN, TOKEN
from test_publish import PublicHost


KEYS = NodeSecrets("a" * 64, "b" * 64)
ADDRESS = "8.8.4.4"  # Public literal fixture; tests never connect to it.


class ClientFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.host = FakeHost(self.root)
        self.prep = Preparation(self.root, self.host)
        self.addCleanup(self.prep.files.close)
        self.prep.initialize()
        self.spec = NodeSpec(DOMAIN)
        self.seed(self.spec)

    def seed(self, spec):
        manifest = {}
        for item in render_files(spec, KEYS):
            self.host.write(item.target.path, item.content.encode(), item.target.mode)
            manifest[item.target.path] = self.item(item.target.path)
        for path in BINARIES:
            self.host.write(path, b"non-executable test fixture bytes", 0o755)
            manifest[path] = self.item(path)
        for path in ("/etc/snellctl", "/etc/snellctl/nodes", "/etc/snellctl/nodes/main"):
            self.host.path(path).chmod(0o700)
        node = {"binding": _binding(spec), "files": manifest}
        self.record("public-ready", {"binding": _binding(spec), "node": node, "ssh_port": 54321})
        self.record("public-files", node)
        for name in ("renewal-test-ready", "renewal-enable-ready"):
            self.record(name, {"binding": _binding(spec)})
        self.record("certificate-ready", {"domain_sha256": hashlib.sha256(spec.domain.encode()).hexdigest()})
        self.record("public-firewall-added", {"port": spec.public_port, "family": 4, "protocol": "tcp", "comment": "snellctl-main"})

    def item(self, path):
        source = self.host.path(path)
        info = source.stat()
        return {"mode": info.st_mode & 0o777, "identity": [info.st_dev, info.st_ino],
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}

    def record(self, name, data):
        self.host.write(STATE + "/" + name + ".json", (json.dumps(data) + "\n").encode(), 0o600)

    def update_manifest(self, path):
        node = json.loads(self.host.path(STATE + "/public-files.json").read_bytes())
        node["files"][path] = self.item(path)
        self.record("public-files", node)
        ready = json.loads(self.host.path(STATE + "/public-ready.json").read_bytes())
        ready["node"] = node
        self.record("public-ready", ready)

    def read(self):
        return read_client(root=self.root)

    def unchanged_snapshot(self):
        result = {}
        for path in self.root.rglob("*"):
            if path.is_file():
                info = path.stat()
                result[str(path.relative_to(self.root))] = (path.read_bytes(), info.st_mode, info.st_ino, info.st_mtime_ns)
        return result

    def test_reads_current_data_and_produces_one_safe_line(self):
        data = self.read()
        line = data.surge_line(ADDRESS)
        self.assertEqual(line, f"snellctl-main = snell, {ADDRESS}, 443, psk={'a' * 64}, version=5, "
                         f"shadow-tls-password={'b' * 64}, shadow-tls-version=3, shadow-tls-sni={DOMAIN}, block-quic=on")
        for forbidden in ("skip-cert-verify", "udp-relay", "udp-port", "reuse=", "\n", "\r", TOKEN, "PRIVATE KEY"):
            self.assertNotIn(forbidden, line)
        self.assertNotIn(DOMAIN, repr(data))
        self.assertNotIn(KEYS.psk, repr(data))
        self.assertNotIn(KEYS.shadowtls_password, repr(data))

    def test_custom_domain_ports_and_legacy_syntax_from_disk(self):
        spec = NodeSpec("alt.example.org", public_port=24443, snell_port=32001, tls_port=32443, nginx_version="1.22.1")
        self.seed(spec)
        data = self.read()
        self.assertEqual((data.domain, data.public_port), ("alt.example.org", 24443))
        line = data.surge_line(ADDRESS)
        self.assertNotIn("32001", line)
        self.assertNotIn("32443", line)
        self.assertIn("shadow-tls-sni=alt.example.org", line)

    def test_repeat_export_does_not_write_rotate_or_execute(self):
        before = self.unchanged_snapshot()
        calls = len(self.host.calls)
        with patch("snellctl.deployment.secrets.token_hex", side_effect=AssertionError("new key")), \
             patch("subprocess.Popen", side_effect=AssertionError("command")), \
             patch("socket.create_connection", side_effect=AssertionError("network")):
            self.assertEqual(self.read(), self.read())
        self.assertEqual(before, self.unchanged_snapshot())
        self.assertEqual(calls, len(self.host.calls))

    def test_does_not_read_cloudflare_certificates_or_logs(self):
        original = HostFiles.read
        paths = []
        def tracked(files, path, **kwargs):
            paths.append(path)
            return original(files, path, **kwargs)
        with patch.object(HostFiles, "read", new=tracked):
            self.read()
        self.assertFalse(any("credentials" in p or "privkey.pem" in p or "/var/log/" in p for p in paths))
        self.assertFalse(any(p.startswith("/etc/letsencrypt/live/") for p in paths))

    def test_incomplete_publication_refuses_secrets(self):
        self.host.path(STATE + "/public-ready.json").unlink()
        with self.assertRaises(ClientError):
            self.read()

    def test_missing_owner_not_recognized_as_manual_deployment(self):
        self.host.path(STATE + "/owner.json").unlink()
        with self.assertRaises(ClientError):
            self.read()

    def test_busy_lock_stops_without_removing_lock(self):
        before = self.host.path(STATE + "/lock").stat().st_ino
        with self.prep._lock(), self.assertRaises(ClientError):
            self.read()
        self.assertEqual(self.host.path(STATE + "/lock").stat().st_ino, before)

    def test_modified_key_does_not_silently_export_changed_secret(self):
        path = self.host.path(self.spec.node_dir + "/snell.conf")
        path.write_bytes(path.read_bytes().replace(b"a" * 64, b"c" * 64))
        with self.assertRaises(ClientError) as raised:
            self.read()
        self.assertNotIn("c" * 64, str(raised.exception))

    def test_each_managed_file_must_remain_owned_and_unchanged(self):
        for path in (*BINARIES, *(t.target.path for t in render_files(self.spec, KEYS))):
            with self.subTest(path=path):
                target = self.host.path(path)
                content = target.read_bytes()
                target.write_bytes(content + b"modified")
                with self.assertRaises(ClientError):
                    self.read()
                target.write_bytes(content)

    def test_same_content_replacement_is_not_automatically_adopted(self):
        target = self.host.path(self.spec.node_dir + "/shadowtls.json")
        replacement = target.with_suffix(".replacement")
        replacement.write_bytes(target.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, target)
        with self.assertRaises(ClientError):
            self.read()

    def test_private_file_permission_and_parent_directory_are_checked(self):
        for path in (self.spec.node_dir + "/snell.conf", self.spec.node_dir + "/shadowtls.json",
                     "/etc/snellctl", "/etc/snellctl/nodes", self.spec.node_dir):
            target = self.host.path(path)
            old = target.stat().st_mode & 0o777
            target.chmod(0o644 if target.is_file() else 0o755)
            with self.subTest(path=path), self.assertRaises(ClientError):
                self.read()
            target.chmod(old)

    def test_symlink_hardlink_and_fifo_not_read(self):
        target = self.host.path(self.spec.node_dir + "/snell.conf")
        content = target.read_bytes()
        target.unlink()
        other = target.with_suffix(".other")
        other.write_bytes(content)
        other.chmod(0o600)
        for kind in ("symlink", "hardlink", "fifo"):
            if kind == "symlink":
                target.symlink_to(other)
            elif kind == "hardlink":
                os.link(other, target)
            else:
                os.mkfifo(target, 0o600)
            with self.subTest(kind=kind), self.assertRaises(ClientError):
                self.read()
            target.unlink()

    def test_extra_or_traversal_manifest_path_not_followed(self):
        node = json.loads(self.host.path(STATE + "/public-files.json").read_bytes())
        node["files"]["/etc/snellctl/credentials/cloudflare-main.ini"] = {"mode": 0o600}
        self.record("public-files", node)
        self.record("public-ready", {"binding": _binding(self.spec), "node": node})
        with self.assertRaises(ClientError):
            self.read()

    def test_mismatched_records_and_bad_json_are_not_printed(self):
        for name in ("public-ready", "public-files", "certificate-ready", "renewal-test-ready", "renewal-enable-ready", "public-firewall-added"):
            target = self.host.path(STATE + "/" + name + ".json")
            content = target.read_bytes()
            for broken in (TOKEN.encode(), json.dumps({"binding": "d" * 64, "private": TOKEN}).encode()):
                target.write_bytes(broken)
                with self.subTest(name=name), self.assertRaises(ClientError) as raised:
                    self.read()
                self.assertNotIn(TOKEN, str(raised.exception))
            target.write_bytes(content)

    def test_service_dropin_and_runtime_replacement_refused(self):
        for path, directory in (("/etc/systemd/system/snellctl-snell-main.service.d", True),
                                ("/run/systemd/system/snellctl-shadowtls-main.service", False),
                                ("/usr/lib/systemd/system/nginx.service.d", True)):
            target = self.host.path(path)
            target.mkdir() if directory else target.write_bytes(b"unexpected service")
            with self.subTest(path=path), self.assertRaises(ClientError):
                self.read()
            target.rmdir() if directory else target.unlink()

    def test_unsupported_json_options_or_duplicate_keys_rejected_even_with_matching_hash(self):
        path = self.spec.node_dir + "/shadowtls.json"
        original = self.host.path(path).read_bytes()
        cases = (original.replace(b'"v3": true', b'"v3": false'),
                 original.replace(b'"v3": true', b'"v3": 1'),
                 original.replace(b'"v3": true', b'"v3": true, "v3": true'),
                 original.replace(b'"strict": true', b'"strict": false'),
                 original.replace(b'"wildcard_sni": "off"', b'"wildcard_sni": "all"'),
                 original.replace(b'"0.0.0.0:443"', b'"127.0.0.1:443"'),
                 original.replace(b'"127.0.0.1:31001"', b'"127.0.0.1:32001"'))
        for data in cases:
            self.host.path(path).write_bytes(data)
            self.update_manifest(path)
            with self.subTest(data=data[:30]), self.assertRaises(ClientError):
                self.read()

    def test_unsupported_nginx_or_snell_edits_not_general_parser(self):
        for path, before, after in ((self.spec.nginx_conf, b"return 404;", b"return 200;"),
                                    (self.spec.nginx_conf, b"server_name node.example.net;", b"server_name first.example.net second.example.net;"),
                                    (self.spec.node_dir + "/snell.conf", b"127.0.0.1:31001", b"0.0.0.0:31001"),
                                    (self.spec.node_dir + "/snell.conf", b"[snell-server]", b"[DEFAULT]\nsecret=private\n[snell-server]")):
            content = self.host.path(path).read_bytes()
            self.host.path(path).write_bytes(content.replace(before, after))
            self.update_manifest(path)
            with self.subTest(path=path), self.assertRaises(ClientError):
                self.read()
            self.host.path(path).write_bytes(content)
            self.update_manifest(path)

    def test_key_validation_rejects_injection_and_identical_keys(self):
        path = self.spec.node_dir + "/snell.conf"
        content = self.host.path(path).read_bytes()
        for key in (b"bad,key=value", b"UPPERCASE", b"b" * 64, b"a" * 63):
            self.host.path(path).write_bytes(content.replace(b"a" * 64, key))
            self.update_manifest(path)
            with self.subTest(key=key[:5]), self.assertRaises(ClientError):
                self.read()

    def test_snapshot_detects_identity_change_after_read(self):
        path = self.spec.node_dir + "/snell.conf"
        original = HostFiles.identity
        count = 0
        def changed(files, candidate):
            nonlocal count
            value = original(files, candidate)
            if candidate == path:
                count += 1
                if count == 2:
                    return [value[0], value[1] + 1]
            return value
        with patch.object(HostFiles, "identity", new=changed), self.assertRaises(ClientError):
            self.read()


class ClientFormatTests(unittest.TestCase):
    def test_ipv4_only_no_config_injection(self):
        for value in (None, 1, "", "example.net", "::1", "2001:4860:4860::8888", "127.0.0.1", "10.0.0.1",
                      "192.168.1.1", "100.64.0.1", "169.254.1.1", "0.0.0.0", "255.255.255.255", "224.0.0.1",
                      "192.0.2.1", "8.8.8.8:443", "https://8.8.8.8", "8.8.8.8, skip-cert-verify=true",
                      "8.8.8.8\nAnother = direct", "8.8.8.08", " 8.8.8.8 ", "\x1b[2J"):
            with self.subTest(value=value), self.assertRaises(ClientError):
                public_ipv4(value)
        self.assertEqual(public_ipv4(ADDRESS), ADDRESS)

    def test_data_values_validated_before_formatting(self):
        for domain, port, keys in (("evil;value", 443, KEYS), (DOMAIN, 0, KEYS), (DOMAIN, True, KEYS),
                                  (DOMAIN, 65536, KEYS), (DOMAIN, 443, "RAW KEY")):
            with self.assertRaises((ValueError, ClientError)):
                ClientData(domain, port, keys)


class Console:
    def __init__(self, answers=None):
        self.answers = iter([ADDRESS, "显示"] if answers is None else answers)
        self.messages = []
        self.interactive = Mock(return_value=True)

    def say(self, value):
        self.messages.append(value)

    def ask(self, _prompt):
        value = next(self.answers)
        if isinstance(value, BaseException):
            raise value
        return value


class ClientDisplayTests(unittest.TestCase):
    def setUp(self):
        self.ui = Console()
        self.reader = Mock(return_value=ClientData(DOMAIN, 24443, KEYS))

    def run_display(self):
        return run_client(reader=self.reader, terminal=self.ui)

    def test_only_explicit_confirmation_reads_and_shows_one_line(self):
        self.assertEqual(self.run_display(), 0)
        self.reader.assert_called_once_with()
        lines = [line for line in self.ui.messages if KEYS.psk in line or KEYS.shadowtls_password in line]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0].count("\n"), 0)
        self.assertIn(", 24443,", lines[0])
        self.assertIn("不代表服务健康", "\n".join(self.ui.messages))

    def test_enter_or_any_other_answer_cancels_before_reading(self):
        for answer in ("", "y", "yes", "显示密钥"):
            self.ui = Console([ADDRESS, answer])
            self.assertEqual(self.run_display(), 130)
        self.reader.assert_not_called()

    def test_pipe_rejected_without_reading_or_prompting(self):
        self.ui.interactive.return_value = False
        self.assertEqual(self.run_display(), 2)
        self.reader.assert_not_called()

    def test_terminal_becomes_redirected_before_read(self):
        self.ui.interactive.side_effect = [True, False]
        self.assertEqual(self.run_display(), 2)
        self.reader.assert_not_called()

    def test_terminal_changes_before_display_do_not_leak(self):
        self.ui.interactive.side_effect = [True, True, False]
        self.assertEqual(self.run_display(), 1)
        self.assertNotIn(KEYS.psk, "\n".join(self.ui.messages))

    def test_bad_address_stops_before_read_and_is_not_echoed(self):
        self.ui = Console(["PRIVATE-INJECTION"])
        self.assertEqual(self.run_display(), 1)
        self.reader.assert_not_called()
        self.assertNotIn("PRIVATE-INJECTION", "\n".join(self.ui.messages))

    def test_reader_failure_cannot_echo_exception_secret(self):
        self.reader.side_effect = RuntimeError(TOKEN + KEYS.psk)
        self.assertEqual(self.run_display(), 1)
        text = "\n".join(self.ui.messages)
        self.assertNotIn(TOKEN, text)
        self.assertNotIn(KEYS.psk, text)
        self.assertNotIn("Traceback", text)

    def test_eof_and_ctrl_c_before_display(self):
        for error in (EOFError(), KeyboardInterrupt()):
            self.ui = Console([error])
            self.assertEqual(self.run_display(), 130)
        self.reader.assert_not_called()

    def test_interrupted_output_does_not_claim_no_secrets_displayed(self):
        say = self.ui.say
        def interrupted(message):
            if message.startswith("snellctl-main ="):
                raise KeyboardInterrupt
            say(message)
        self.ui.say = interrupted
        self.assertEqual(self.run_display(), 130)
        self.assertIn("可能已显示部分密钥", "\n".join(self.ui.messages))

    def test_platform_or_nonroot_reader_denied_before_files(self):
        with patch("snellctl.client.platform.system", return_value="Darwin"), \
             patch("snellctl.client.read_client") as reader, self.assertRaises(ClientError):
            real_reader()
        reader.assert_not_called()
        with patch("snellctl.client.platform.system", return_value="Linux"), \
             patch("snellctl.client.os.geteuid", return_value=1000), \
             patch("snellctl.client.read_client") as reader, self.assertRaises(ClientError):
            real_reader()
        reader.assert_not_called()

    def test_cli_dispatch(self):
        with patch("snellctl.client.run_client", return_value=130) as action:
            self.assertEqual(main(["client"]), 130)
        action.assert_called_once_with()

    def test_no_file_json_or_automatic_confirmation_options(self):
        for args in (["--json"], ["--output", "/tmp/private.conf"], ["--yes"], ["--root", "/tmp"], ["--token", TOKEN]):
            with redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit):
                main(["client", *args])
            self.assertNotIn(TOKEN, output.getvalue())

    def test_default_menu_exposes_only_confirmed_read_operation(self):
        with patch("builtins.input", side_effect=["5", "0"]), redirect_stdout(io.StringIO()), \
             patch("snellctl.client.run_client", return_value=0) as action:
            self.assertEqual(run_menu(), 0)
        action.assert_called_once_with()


class CompletedInstallExportTests(unittest.TestCase):
    def test_real_controllers_records_can_be_exported_without_extra_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            host = PublicHost(root)
            with Preparation(root, host) as prep:
                prep.initialize()
                prep.packages()
                prep.credential(TOKEN)
                prep.certificate(DOMAIN, production=False, agree_tos=True)
                prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True)
                local = Activation(prep, Mock(return_value=True), readiness_timeout=0)
                spec = NodeSpec(DOMAIN)
                with patch("snellctl.activation.verify", return_value=b"test binary"), \
                     patch("snellctl.activation.new_node_secrets", return_value=KEYS):
                    local.activate(spec, {"snell": b"fixture", "shadow-tls": b"fixture"})
                local.test_renewal(spec, confirm_test=True)
                Publication(local).enable(spec, ssh_port=54321, confirm_public=True,
                                          confirm_renewal=True, confirm_ssh_reconnected=True)
                calls = len(host.calls)
                data = read_client(root=root)
                self.assertEqual(data, ClientData(DOMAIN, 443, KEYS))
                self.assertEqual(len(host.calls), calls)
