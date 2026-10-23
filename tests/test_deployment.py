import configparser
from dataclasses import replace
import json
import subprocess
import unittest
from unittest.mock import patch

from snellctl.deployment import (
    NodeSecrets, NodeSpec, file_targets, new_node_secrets, preview, render_files, render_preview,
)


class SpecTests(unittest.TestCase):
    def test_parameters_are_not_fixed_to_the_test_vps(self):
        spec = NodeSpec("edge.example.net", "second", 24443, 32001, 32443)
        report = preview(spec)
        self.assertEqual(report["node"], "second")
        self.assertEqual(report["listeners"], {
            "shadowtls_tcp": "0.0.0.0:24443", "snell_tcp_udp": "127.0.0.1:32001",
            "nginx_tcp": "127.0.0.1:32443",
        })
        self.assertTrue(all("second" in item["path"] for item in report["files"]))
        self.assertEqual(report["credential_path"], "/etc/snellctl/credentials/cloudflare-second.ini")

    def test_invalid_domains_cannot_inject_config_or_paths(self):
        for domain in ("", "localhost", "EXAMPLE.net", "example.net.", "*.example.net", "1.2.3.4",
                       "https://example.net", "example.net/x", "example.net;", "example.net\nuser root;",
                       "example.net'", "example.net%a", "a..net", "a.-net", "a.net-",
                       "a." + "x" * 64 + ".net", ".".join(["a" * 63] * 4), "\x1b[2J.example.net"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                NodeSpec(domain)

    def test_longest_valid_domain_and_ascii_idn(self):
        domain = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
        self.assertEqual(len(domain), 253)
        self.assertEqual(NodeSpec(domain).domain, domain)
        self.assertEqual(NodeSpec("xn--fsqu00a.example.net").domain, "xn--fsqu00a.example.net")

    def test_node_name_is_a_safe_single_component(self):
        for node in ("../main", "/main", "Main", "main\nX=y", "%i", "a" * 33, "-main", "a b", ""):
            with self.subTest(node=node), self.assertRaises(ValueError):
                NodeSpec("node.example.net", node=node)

    def test_port_ranges_and_types(self):
        base = NodeSpec("node.example.net")
        for name in ("public_port", "snell_port", "tls_port"):
            for port in (0, -1, 65536, True, 443.0, "443", None):
                with self.subTest(name=name, port=port), self.assertRaises(ValueError):
                    replace(base, **{name: port})
        for name in ("snell_port", "tls_port"):
            with self.assertRaises(ValueError):
                replace(base, **{name: 1023})
        self.assertEqual(replace(base, public_port=65535).public_port, 65535)

    def test_port_collisions_are_rejected(self):
        for ports in ((31001, 31001, 31443), (443, 31443, 31443), (31443, 31001, 31443)):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                NodeSpec("node.example.net", "main", *ports)

    def test_invalid_nginx_versions_are_rejected(self):
        for version in ("1.18.0", "1.19.3", "1.26", "1.26.3-3+deb13u9", "nginx/1.26.3", "1.26.3\n", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                NodeSpec("node.example.net", nginx_version=version)

    def test_preview_does_not_generate_secrets_or_claim_readiness(self):
        with patch("snellctl.deployment.secrets.token_hex", side_effect=AssertionError("unexpected key generation")):
            report = preview(NodeSpec("node.example.net"))
            output = render_preview(report)
        self.assertEqual(report["mode"], "preview-only")
        self.assertFalse(report["environment_checked"])
        self.assertIn("未执行", output)
        self.assertIn("未检查当前机器", output)
        self.assertNotIn("password", json.dumps(report))
        self.assertNotIn("psk", json.dumps(report))


class TemplateTests(unittest.TestCase):
    def setUp(self):
        self.spec = NodeSpec("node.example.net")
        self.keys = NodeSecrets("a" * 64, "b" * 64)
        self.files = render_files(self.spec, self.keys)

    def by_suffix(self, suffix):
        return next(item for item in self.files if item.target.path.endswith(suffix))

    def test_snell_ini_uses_loopback_and_supplied_key(self):
        config = configparser.ConfigParser(interpolation=None)
        config.read_string(self.by_suffix("/snell.conf").content)
        self.assertEqual(dict(config["snell-server"]), {"listen": "127.0.0.1:31001", "psk": self.keys.psk})

    def test_shadowtls_fixed_backends_and_protocol(self):
        config = json.loads(self.by_suffix("/shadowtls.json").content)
        self.assertTrue(config["v3"])
        self.assertTrue(config["strict"])
        server = config["server"]
        self.assertEqual(server["listen"], "0.0.0.0:443")
        self.assertEqual(server["server_addr"], "127.0.0.1:31001")
        self.assertEqual(server["tls_addr"], {
            "dispatch": {}, "fallback": "127.0.0.1:31443", "wildcard_sni": "off",
        })
        self.assertEqual(server["wildcard_sni"], "off")
        self.assertEqual(server["password"], self.keys.shadowtls_password)

    def test_nginx_only_loopback_and_rejects_unknown_sni(self):
        content = self.by_suffix("/snellctl-main.conf").content
        listens = [line.strip() for line in content.splitlines() if line.strip().startswith("listen ")]
        self.assertEqual(listens, ["listen 127.0.0.1:31443 ssl default_server;", "listen 127.0.0.1:31443 ssl;"])
        self.assertIn("ssl_reject_handshake on;", content)
        self.assertIn("server_name node.example.net;", content)
        self.assertIn("http2 on;", content)
        self.assertEqual(content.count("return 404;"), 2)
        self.assertEqual(content.count("access_log off;"), 2)
        self.assertNotIn("proxy_pass", content)
        self.assertIn("/etc/letsencrypt/live/node.example.net/privkey.pem", content)

    def test_legacy_and_modern_http2_boundary(self):
        for version, modern in (("1.19.4", False), ("1.22.1", False), ("1.25.0", False),
                                ("1.25.1", True), ("1.26.3", True)):
            with self.subTest(version=version):
                content = render_files(replace(self.spec, nginx_version=version), self.keys)[2].content
                self.assertEqual("http2 on;" in content, modern)
                self.assertEqual(content.count("ssl http2"), 0 if modern else 2)

    def test_service_credentials_and_hardening(self):
        for item in self.files:
            if not item.target.path.endswith(".service"):
                continue
            config = configparser.ConfigParser(interpolation=None)
            config.read_string(item.content)
            service = config["Service"]
            self.assertEqual(service["DynamicUser"], "yes")
            self.assertEqual(service["ProtectSystem"], "strict")
            self.assertEqual(service["NoNewPrivileges"], "yes")
            self.assertEqual(service["LimitCORE"], "0")
            self.assertIn("%d/", service["ExecStart"])
            self.assertIn("/etc/snellctl/nodes/main/", service["LoadCredential"])
            self.assertNotIn(self.keys.psk, item.content)
            self.assertNotIn(self.keys.shadowtls_password, item.content)
        snell = self.by_suffix("/snellctl-snell-main.service").content
        self.assertIn("CapabilityBoundingSet=\n", snell)
        self.assertNotIn("CAP_NET_BIND_SERVICE", snell)

    def test_bind_capability_only_for_low_public_port(self):
        for port, low in ((443, True), (1023, True), (1024, False), (24443, False)):
            with self.subTest(port=port):
                content = render_files(replace(self.spec, public_port=port), self.keys)[4].content
                self.assertEqual("AmbientCapabilities=CAP_NET_BIND_SERVICE" in content, low)
                self.assertEqual("CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in content, low)
                self.assertIn("Environment=RUST_LOG=warn", content)
                self.assertIn("UnsetEnvironment=CONFIG_FILE", content)

    def test_hook_is_scoped_to_lineage_and_has_valid_shell_syntax(self):
        hook = self.files[-1].content
        self.assertIn('[ "$RENEWED_LINEAGE" = \'/etc/letsencrypt/live/node.example.net\' ] || exit 0', hook)
        self.assertLess(hook.index("/usr/sbin/nginx -t"), hook.index("systemctl reload"))
        self.assertIn("set -eu", hook)
        check = subprocess.run(["sh", "-n"], input=hook, text=True, capture_output=True, check=False)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_no_keys_in_repr_or_public_candidates(self):
        for text in (repr(self.keys), repr(self.files), render_preview(preview(self.spec))):
            self.assertNotIn(self.keys.psk, text)
            self.assertNotIn(self.keys.shadowtls_password, text)
        for item in self.files:
            if item.target.sensitive:
                self.assertEqual(item.target.mode, 0o600)
            else:
                self.assertNotIn(self.keys.psk, item.content)
                self.assertNotIn(self.keys.shadowtls_password, item.content)
        self.assertEqual(self.files[-1].target.mode, 0o700)

    def test_deterministic_render_does_not_regenerate_keys(self):
        with patch("snellctl.deployment.secrets.token_hex", side_effect=AssertionError("rotation")):
            self.assertEqual(render_files(self.spec, self.keys), self.files)
        self.assertEqual(tuple(item.target for item in self.files), file_targets(self.spec))

    def test_nondefault_parameters_reach_every_candidate(self):
        spec = NodeSpec("alternate.example.org", "other", 24443, 32001, 32443)
        candidates = render_files(spec, self.keys)
        combined = "\n".join(item.content for item in candidates)
        for stale in ("node.example.net", "snellctl-main", "nodes/main", ":31001", ":31443", ":443"):
            self.assertNotIn(stale, combined)
        self.assertIn("0.0.0.0:24443", combined)
        self.assertIn("127.0.0.1:32001", combined)
        self.assertIn("127.0.0.1:32443", combined)
        self.assertEqual(len({item.target.path for item in candidates}), len(candidates))


class SecretTests(unittest.TestCase):
    def test_generation_uses_independent_secure_values(self):
        with patch("snellctl.deployment.secrets.token_hex", side_effect=["a" * 64, "b" * 64]) as generate:
            keys = new_node_secrets()
        self.assertEqual([call.args for call in generate.call_args_list], [(32,), (32,)])
        self.assertNotEqual(keys.psk, keys.shadowtls_password)

    def test_generation_handles_accidental_equal_values(self):
        with patch("snellctl.deployment.secrets.token_hex", side_effect=["a" * 64, "a" * 64, "b" * 64]):
            self.assertNotEqual(new_node_secrets().shadowtls_password, "a" * 64)

    def test_invalid_secret_errors_do_not_echo_input(self):
        for secret in ("not-a-real-secret", "x" * 64, "A" * 64, "a" * 63, "a" * 64 + "\n"):
            with self.subTest(secret=secret), self.assertRaises(ValueError) as error:
                NodeSecrets(secret, "b" * 64)
            self.assertNotIn(secret, str(error.exception))
        with self.assertRaises(ValueError):
            NodeSecrets("a" * 64, "a" * 64)
