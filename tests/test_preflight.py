import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from snellctl.deployment import NodeSpec
from snellctl.doctor import Result
from snellctl.preflight import DEPENDENCIES, candidates, check, render


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
        self.calls = []
        self.overrides = {}
        self.spec = NodeSpec("node.example.net")

    def runner(self, args):
        self.calls.append(args)
        key = " ".join(args[:2])
        if key in self.overrides:
            return self.overrides[key]
        if args[0] == "dpkg-query":
            return Result(1, "ufw\tii \t0.36.2-9\n")
        if args[:3] == ["ss", "-H", "-4"]:
            return Result(0, 'tcp LISTEN 0 128 0.0.0.0:54321 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n')
        if args[0] == "ss":
            return Result(0)
        if args[0] == "ufw":
            return Result(0, "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n")
        if args[0] == "systemctl":
            return Result(0, "enabled\n")
        if args[0] == "dpkg":
            return Result(0)
        if args[0] == "apt-cache":
            return Result(0, "".join(f"{name}:\n  Installed: (none)\n  Candidate: 1.2.3-1+deb13u1\n" for name in DEPENDENCIES))
        if args[0] == "apt-get":
            return Result(0, "Inst nginx (1.2.3-1 Debian:13/stable [amd64])\nConf nginx (1.2.3-1 Debian:13/stable [amd64])\n")
        raise AssertionError(args)

    def check(self, **kwargs):
        return check(self.spec, root=self.root, runner=self.runner, system=kwargs.get("system", "Linux"), machine=kwargs.get("machine", "x86_64"), euid=kwargs.get("euid", 0))

    def assert_block(self, code, **kwargs):
        report = self.check(**kwargs)
        self.assertIn(code, [item["code"] for item in report["blockers"]])
        self.assertFalse(report["limited_checks_passed"])
        self.assertFalse(report["install_ready"])
        return report

    def test_new_host_limited_checks_only(self):
        report = self.check()
        self.assertTrue(report["limited_checks_passed"])
        self.assertFalse(report["install_ready"])
        self.assertFalse(report["apt_indexes_refreshed"])
        self.assertTrue(report["pending"])
        apt = [cmd for cmd in self.calls if cmd[0] == "apt-get"]
        self.assertEqual(apt, [["apt-get", "--simulate", "--no-remove", "--no-install-recommends", "install", *DEPENDENCIES]])
        self.assertNotIn("0.0.0.0", json.dumps(report))

    def test_mac_never_runs_linux_commands(self):
        self.assert_block("unvalidated-platform", system="Darwin")
        self.assertEqual(self.calls, [])

    def test_debian12_arm_not_enabled_for_install_preflight(self):
        self.assert_block("unvalidated-platform", machine="aarch64")
        (self.root / "etc/os-release").write_text('ID=debian\nVERSION_ID="12"\n')
        self.assert_block("unvalidated-platform")
        self.assertFalse(any(cmd[0].startswith("apt") for cmd in self.calls))

    def test_nonroot_does_not_try_apt_or_sudo(self):
        self.assert_block("root-required", euid=1000)
        self.assertFalse(any(cmd[0] in {"sudo", "apt-get", "apt-cache"} for cmd in self.calls))

    def test_port_conflict_including_ipv6(self):
        self.overrides["ss -H"] = Result(0, "tcp LISTEN 0 128 [::]:443 [::]:*\n")
        self.assert_block("port-conflict")

    def test_existing_sockets_and_firewall_block(self):
        self.overrides["ufw status"] = Result(0, "Status: inactive\n")
        self.assert_block("ufw-inactive")
        self.assertFalse(any(cmd[0] == "apt-get" for cmd in self.calls))

    def test_existing_managed_path_even_dangling_symlink(self):
        (self.root / "etc/snellctl").symlink_to("missing")
        self.assert_block("existing-managed-path")

    def test_old_firewall_persistence_not_removed(self):
        self.overrides["dpkg-query -W"] = Result(1, "iptables-persistent\tii \t1.0.23\n")
        self.assert_block("other-firewall-persistence")
        self.assertFalse(any(cmd[0] == "apt-get" for cmd in self.calls))

    def test_old_nginx_and_certbot_not_adopted(self):
        self.overrides["dpkg-query -W"] = Result(1, "nginx\tii \t1.26.3-3\ncertbot\tii \t4.0.0\n")
        self.assert_block("existing-nginx")
        self.assert_block("existing-certbot")

    def test_missing_ssh_confirmation(self):
        self.overrides["ss -H"] = Result(0)
        self.assert_block("ssh-unconfirmed")

    def test_package_audit_or_error_blocks(self):
        for result in [Result(0, "incomplete package SECRET"), Result(-1)]:
            self.overrides["dpkg --audit"] = result
            report = self.assert_block("dpkg-audit")
            self.assertNotIn("SECRET", json.dumps(report))

    def test_missing_or_failed_candidates(self):
        for result in [Result(-1), Result(0, "nginx:\n  Candidate: (none)\n")]:
            self.overrides["apt-cache policy"] = result
            self.assert_block("apt-candidates")

    def test_simulation_failure_or_removal(self):
        for result in [Result(100, "private source URL"), Result(0, "Remv ufw [0.36.2]\n"), Result(0, "Purg ufw\n")]:
            self.overrides["apt-get --simulate"] = result
            report = self.assert_block("apt-simulation")
            self.assertNotIn("private source", json.dumps(report))

    def test_candidates_do_not_publish_repository_or_untrusted_names(self):
        text = "nginx:\n  Candidate: 1.26.3-3+deb13u9\n  500 https://user:secret@private/repo\nunknown:\n  Candidate: SECRET\n"
        self.assertEqual(candidates(text), {"nginx": "1.26.3-3+deb13u9"})

    def test_cli_preflight_dispatch(self):
        from snellctl.__main__ import main
        report = self.check()
        output = io.StringIO()
        with patch("snellctl.preflight.check", return_value=report), contextlib.redirect_stdout(output):
            self.assertEqual(main(["preflight", "--domain", "node.example.net", "--json"]), 0)
        self.assertFalse(json.loads(output.getvalue())["install_ready"])
        self.assertIn("不刷新软件源", render(report))
