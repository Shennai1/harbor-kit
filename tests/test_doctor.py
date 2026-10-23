import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from snellctl.doctor import Result, collect, os_release, parse_listeners, parse_packages, parse_ufw, render


class ParseTests(unittest.TestCase):
    def test_os_release_is_data_and_restricts_output(self):
        self.assertEqual(os_release('ID=debian\nVERSION_ID="12"\nSECRET=abc\n'), {"ID": "debian", "VERSION_ID": "12"})
        self.assertEqual(os_release('ID=$(touch /tmp/never)\n'), {})

    def test_removed_packages_are_not_installed(self):
        text = 'ufw\trc \t0.36.2-1\nnginx\tii \t1.22.1-9+deb12u10\nunknown\tii \t1\n'
        self.assertEqual(parse_packages(text), {"nginx": "1.22.1-9+deb12u10"})

    def test_listeners_keep_family_and_hide_addresses(self):
        text = (
            'tcp LISTEN 0 128 203.0.113.99:50021 0.0.0.0:* users:(("sshd",pid=42,fd=3))\n'
            'tcp LISTEN 0 511 127.0.0.1:8443 0.0.0.0:* users:(("nginx",pid=43,fd=3))\n'
            'udp UNCONN 0 0 0.0.0.0:5355 0.0.0.0:*\n'
        )
        listeners, skipped = parse_listeners(text, "IPv4")
        self.assertEqual(skipped, 0)
        self.assertEqual([x["bind_scope"] for x in listeners], ["specific-address", "loopback", "wildcard"])
        self.assertEqual(listeners[0]["processes"], ["SSH"])
        self.assertNotIn("203.0.113.99", json.dumps(listeners))

    def test_ipv6_wildcard_and_loopback_are_distinct(self):
        records, skipped = parse_listeners(
            'tcp LISTEN 0 1024 *:443 *:*\n'
            'tcp LISTEN 0 10 [::1]:8443 [::]:*\n'
            'udp UNCONN 0 0 [fe80::1234%eth0]:546 [::]:*\n', "IPv6",
        )
        self.assertEqual(skipped, 0)
        self.assertEqual([x["family"] for x in records], ["IPv6"] * 3)
        self.assertEqual([x["bind_scope"] for x in records], ["wildcard", "loopback", "specific-address"])

    def test_malformed_socket_output_is_not_success(self):
        records, skipped = parse_listeners('unexpected text\ntcp LISTEN 0 1 INVALID:443 *:*\n', "IPv4")
        self.assertEqual(records, [])
        self.assertEqual(skipped, 2)

    def test_arbitrary_process_names_are_not_reported(self):
        records, _ = parse_listeners('tcp LISTEN 0 1 *:80 *:* users:(("token-secret",pid=3,fd=2))', "IPv4")
        self.assertNotIn("token-secret", json.dumps(records))

    def test_ufw_does_not_disclose_source_rules(self):
        result = parse_ufw(Result(0, 'Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n443 ALLOW 203.0.113.99\n'))
        self.assertEqual(result["status"], "active")
        self.assertEqual(result["default_policy"]["incoming"], "deny")
        self.assertNotIn("203.0.113.99", json.dumps(result))

    def test_failed_ufw_command_is_unknown(self):
        self.assertEqual(parse_ufw(Result(1, "Status: active"))["status"], "unknown")


class CollectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text('ID=debian\nVERSION_ID=12\n')
        self.commands = []

    def runner(self, args):
        self.commands.append(args)
        if args[0] == "dpkg-query":
            return Result(1, 'ufw\tii \t0.36.2-1\n')
        if args[0] == "ufw":
            return Result(0, 'Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n')
        if args[0] == "systemctl":
            return Result(0, "enabled\n")
        return Result(0)

    def report(self, **kwargs):
        return collect(self.root, self.runner, "Linux", "x86_64", **kwargs)

    def test_commands_are_readonly_and_never_read_service_arguments(self):
        report = self.report()
        self.assertTrue(report["platform_supported"])
        self.assertEqual(report["findings"], [])
        self.assertEqual([x[0] for x in self.commands], ["dpkg-query", "ss", "ss", "ufw", "systemctl"])
        self.assertIn(["systemctl", "is-enabled", "ufw.service"], self.commands)
        self.assertEqual(report["external_connectivity"], "not-tested")

    def test_non_linux_does_not_run_linux_commands(self):
        report = collect(self.root, self.runner, "Darwin", "arm64")
        self.assertFalse(report["platform_supported"])
        self.assertEqual(self.commands, [])

    def test_unknown_os_stops_checks(self):
        (self.root / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID=24.04\n')
        report = self.report()
        self.assertFalse(report["platform_supported"])
        self.assertEqual(self.commands, [])

    def test_supported_debian_13_arm64(self):
        (self.root / "etc/os-release").write_text('ID=debian\nVERSION_ID=13\n')
        self.assertTrue(collect(self.root, self.runner, "Linux", "aarch64")["platform_supported"])

    def test_existing_node_is_reported_without_leaking_ip(self):
        def runner(args):
            if args[0] == "ss" and "-4" in args:
                return Result(0, 'tcp LISTEN 0 128 203.0.113.99:443 *:* users:(("shadow-tls",pid=5,fd=6))')
            return self.runner(args)
        report = collect(self.root, runner, "Linux", "x86_64")
        self.assertIn("existing-node", [x["code"] for x in report["findings"]])
        self.assertNotIn("203.0.113.99", render(report))

    def test_old_scripts_are_not_read(self):
        (self.root / "root").mkdir()
        (self.root / "root/cn_geo_block.sh").write_text("SECRET_DO_NOT_PRINT")
        report = self.report()
        self.assertIn("legacy-geo-script", [x["code"] for x in report["findings"]])
        self.assertNotIn("SECRET_DO_NOT_PRINT", json.dumps(report))

    def test_permission_error_is_not_treated_as_absence(self):
        original = Path.stat

        def stat(path, *args, **kwargs):
            if path.name == "cn_geo_block.sh":
                raise PermissionError("SECRET_DO_NOT_PRINT")
            return original(path, *args, **kwargs)

        with patch.object(Path, "stat", stat):
            report = self.report()
        self.assertIn("legacy-geo-script-unknown", [x["code"] for x in report["findings"]])
        self.assertNotIn("SECRET_DO_NOT_PRINT", json.dumps(report))

    def test_all_command_failures_are_reported(self):
        report = collect(self.root, lambda args: Result(-1), "Linux", "x86_64")
        codes = [x["code"] for x in report["findings"]]
        self.assertIn("packages-unavailable", codes)
        self.assertIn("listeners-unavailable-IPv4", codes)
        self.assertIn("listeners-unavailable-IPv6", codes)
        self.assertIn("ufw-unknown", codes)

    def test_active_ufw_does_not_imply_boot_or_policy_is_known(self):
        def runner(args):
            if args[0] == "ufw":
                return Result(0, "Status: active\n")
            if args[0] == "systemctl":
                return Result(-1)
            return self.runner(args)
        report = collect(self.root, runner, "Linux", "x86_64")
        codes = [x["code"] for x in report["findings"]]
        self.assertIn("ufw-boot-unconfirmed", codes)
        self.assertIn("ufw-policy-unknown", codes)

    def test_active_ufw_allow_policy_is_reported(self):
        def runner(args):
            if args[0] == "ufw":
                return Result(0, "Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n")
            return self.runner(args)
        report = collect(self.root, runner, "Linux", "x86_64")
        self.assertIn("ufw-default-allow", [x["code"] for x in report["findings"]])


if __name__ == "__main__":
    unittest.main()
