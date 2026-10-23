from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from snellctl.activation import Activation
from snellctl.deployment import NodeSpec
from snellctl.hostprep import Preparation, PreparationError, Reply, STATE, POLICY
from snellctl.publish import Publication, Rule, parse_rules, input_rules, renewal_dropin, RENEW_DROPIN, UFW_UNCHANGED
from test_activation import ActiveHost
from test_hostprep import DOMAIN, TOKEN


class PublicHost(ActiveHost):
    def __init__(self, root):
        super().__init__(root)
        self.rules = ["ufw allow 54321/tcp comment 'SSH'"]
        self.enabled = {"ufw.service"}
        self.input4 = ["-A ufw-user-input -p tcp --dport 54321 -j ACCEPT"]
        for path in UFW_UNCHANGED:
            self.write(path, b"# original firewall fixture\n", 0o640)
        self.write("/etc/ufw/user.rules", ("\n".join(self.input4) + "\n").encode(), 0o640)

    def __call__(self, command):
        args = command.argv
        if self.local_override:
            result = self.local_override(command)
            if result is not None:
                self.calls.append(command)
                return result
        result = None
        if args == ("ufw", "status", "verbose"):
            result = Reply(0, "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n")
        elif args == ("ufw", "show", "added"):
            result = Reply(0, "Added user rules (see 'ufw status' for running firewall):\n" + "\n".join(self.rules) + "\n")
        elif args[:2] == ("ufw", "allow"):
            port = args[args.index("port") + 1]
            comment = args[args.index("comment") + 1]
            # UFW 0.36.2 shortens a wildcard IPv4-only rule in show added.
            self.rules.append(f"ufw allow {port}/tcp comment '{comment}'")
            self.input4.append(f"-A ufw-user-input -p tcp --dport {port} -j ACCEPT")
            self.write("/etc/ufw/user.rules", ("\n".join(self.input4) + "\n").encode(), 0o640)
            result = Reply(0, "Rule added\n")
        elif args[0] in {"iptables", "ip6tables"}:
            if args[-1] == "INPUT":
                result = Reply(0, "-P INPUT DROP\n-A INPUT -j ufw-before-input\n")
            elif args[-1] == "ufw-user-input":
                result = Reply(0, "-N ufw-user-input\n" + "\n".join(self.input4).replace("-p tcp", "-p tcp -m tcp") + "\n")
            else:
                result = Reply(0, "-N ufw6-user-input\n-A ufw6-user-input -p tcp -m tcp --dport 54321 -j ACCEPT\n")
        elif args == ("ss", "-H", "-lntp"):
            result = Reply(0, 'LISTEN 0 128 0.0.0.0:54321 0.0.0.0:* users:(("sshd",pid=999,fd=7))\n')
        elif args[:2] == ("systemctl", "is-enabled"):
            result = Reply(0, "enabled\n") if args[2] in self.enabled else Reply(1, "disabled\n")
        elif args[:2] == ("systemctl", "enable"):
            self.enabled.add(args[-1])
            if "--now" in args:
                self.active.add(args[-1])
            result = Reply(0)
        elif args[:2] == ("systemctl", "disable"):
            self.enabled.discard(args[-1])
            result = Reply(0)
        elif args[:2] == ("systemctl", "show") and args[-1] == "UnitFileState":
            result = Reply(0, "UnitFileState=" + ("enabled" if args[2] in self.enabled else "disabled") + "\n")
        elif args[:3] == ("systemctl", "start", "certbot.service"):
            result = Reply(0)
        elif args[:2] == ("systemctl", "show") and args[2] in {"certbot.service", "certbot.timer"}:
            unit = args[2]
            if args[-1] == "LoadState,FragmentPath,DropInPaths":
                drop = RENEW_DROPIN if unit == "certbot.service" else ""
                result = Reply(0, f"LoadState=loaded\nFragmentPath=/usr/lib/systemd/system/{unit}\nDropInPaths={drop}\n")
            elif args[-1] == "ActiveState,SubState,Result,ExecMainStatus":
                result = Reply(0, "ActiveState=inactive\nSubState=dead\nResult=success\nExecMainStatus=0\n")
            elif args[-1] == "ActiveState,SubState,UnitFileState,Triggers,NextElapseUSecRealtime":
                result = Reply(0, "ActiveState=active\nSubState=waiting\nUnitFileState=enabled\nTriggers=certbot.service\nNextElapseUSecRealtime=Thu 2026-10-22 12:00:00 UTC\n")
        if result is not None:
            self.calls.append(command)
            return result
        result = super().__call__(command)
        if args[0] == "apt-get" and "install" in args and "--simulate" not in args:
            sums = []
            for unit in ("certbot.service", "certbot.timer"):
                path = "/usr/lib/systemd/system/" + unit
                data = ("# package fixture " + unit + "\n").encode()
                self.write(path, data, 0o644)
                sums.append(hashlib.md5(data).hexdigest() + "  " + path.lstrip("/"))
            self.write("/var/lib/dpkg/info/certbot.md5sums", ("\n".join(sums) + "\n").encode(), 0o644)
        if args == ("ss", "-H", "-lntup"):
            path = self.path("/etc/snellctl/nodes/main/shadowtls.json")
            if path.exists() and json.loads(path.read_bytes())["server"]["listen"].startswith("0.0.0.0:"):
                return Reply(result.code, result.output.replace("127.0.0.1:443", "0.0.0.0:443"))
        return result


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.host = PublicHost(self.root)
        self.prep = Preparation(self.root, self.host)
        self.addCleanup(self.prep.files.close)
        self.prep.initialize()
        self.prep.packages()
        self.prep.credential(TOKEN)
        self.prep.certificate(DOMAIN, production=False, agree_tos=True)
        self.prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True)
        self.probe = Mock(return_value=True)
        self.local = Activation(self.prep, self.probe, readiness_timeout=0)
        self.spec = NodeSpec(DOMAIN)
        with patch("snellctl.activation.verify", side_effect=lambda a, data: b"BINARY-" + a.name.encode()):
            self.local.activate(self.spec, {"snell": b"test", "shadow-tls": b"test"})
        self.local.test_renewal(self.spec, confirm_test=True)
        self.engine = Publication(self.local)
        self.start_calls = len(self.host.calls)

    def enable(self, **kwargs):
        values = dict(ssh_port=54321, confirm_public=True, confirm_renewal=True, confirm_ssh_reconnected=True)
        values.update(kwargs)
        return self.engine.enable(self.spec, **values)

    def new_calls(self):
        return [c.argv for c in self.host.calls[self.start_calls:]]

    def test_complete_publication_keeps_keys_ssh_and_ipv6(self):
        old = json.loads(self.host.path(self.spec.node_dir + "/shadowtls.json").read_bytes())
        untouched = {p: self.host.path(p).read_bytes() for p in UFW_UNCHANGED}
        self.assertEqual(self.enable(), "public-enabled-external-test-required")
        new = json.loads(self.host.path(self.spec.node_dir + "/shadowtls.json").read_bytes())
        old["server"]["listen"] = "0.0.0.0:443"
        self.assertEqual(new, old)
        self.assertEqual(untouched, {p: self.host.path(p).read_bytes() for p in UFW_UNCHANGED})
        self.assertEqual(self.host.rules[0], "ufw allow 54321/tcp comment 'SSH'")
        self.assertEqual(parse_rules("\n".join(self.host.rules))[-1], Rule("allow", 443, "any", "snellctl-main"))
        self.assertFalse(self.host.path(POLICY).exists())
        self.assertTrue({"nginx.service", self.spec.snell_service, self.spec.shadowtls_service, "certbot.timer"} <= self.host.enabled)
        for args in self.new_calls():
            self.assertNotEqual(args[0], "nft")
            if args[0] in {"iptables", "ip6tables"}:
                self.assertEqual(args[1], "-S")
            if args[0] == "ufw":
                self.assertNotIn(args[1], {"reset", "disable", "reload", "enable", "delete", "default"})
            self.assertNotIn("sshd.service", args)

    def test_confirmation_required_before_side_effects(self):
        for name in ("confirm_public", "confirm_renewal", "confirm_ssh_reconnected"):
            with self.subTest(name=name), self.assertRaises(PreparationError):
                self.enable(**{name: False})
        self.assertFalse(self.host.path(STATE + "/public-intent.json").exists())

    def test_ssh_port_not_assumed_and_conflicts_rejected(self):
        for port in (22, 443, 31001, 31443, True, 70000):
            with self.subTest(port=port), self.assertRaises(PreparationError):
                self.enable(ssh_port=port)
        self.assertFalse(self.host.path(STATE + "/public-intent.json").exists())

    def test_inactive_firewall_not_enabled_automatically(self):
        self.host.local_override = lambda c: Reply(0, "Status: inactive\n") if c.argv == ("ufw", "status", "verbose") else None
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertNotIn(("ufw", "enable"), self.new_calls())

    def test_existing_public_rule_is_not_claimed(self):
        self.host.rules.append("ufw allow 443/tcp comment 'someone else'")
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertEqual(len(self.host.rules), 2)

    def test_unrecognized_rule_stops_before_writes(self):
        self.host.rules.append("ufw allow Nginx")
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertFalse(self.host.path(RENEW_DROPIN).exists())

    def test_geo_rules_not_bypassed(self):
        self.host.write("/etc/ufw/before.rules", b"-A ufw-before-input -j CN_GEO_BLOCK\n")
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertFalse(self.host.path(RENEW_DROPIN).exists())

    def test_repeat_checks_but_does_not_append_rules_or_restart(self):
        self.enable()
        self.host.calls.clear()
        self.assertEqual(self.enable(), "already-public-enabled-external-test-required")
        self.assertFalse(any(c.argv[:2] == ("ufw", "allow") for c in self.host.calls))
        self.assertFalse(any(c.argv[:2] == ("systemctl", "start") for c in self.host.calls))
        self.assertEqual(len(self.host.rules), 2)

    def test_repeat_parameter_change_rejected(self):
        self.enable()
        with self.assertRaises(PreparationError):
            self.engine.enable(replace(self.spec, public_port=444), ssh_port=54321, confirm_public=True,
                               confirm_renewal=True, confirm_ssh_reconnected=True)

    def test_disabled_autorenew_is_not_accepted(self):
        path = self.host.path("/etc/letsencrypt/renewal/" + DOMAIN + ".conf")
        path.write_bytes(path.read_bytes() + b"autorenew = False\n")
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertFalse(self.host.path(RENEW_DROPIN).exists())

    def test_repeat_firewall_drift_requires_review(self):
        self.enable()
        self.host.rules.append("ufw allow 2222/tcp")
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertEqual(len(self.host.rules), 3)

    def test_local_activation_cannot_be_reused_after_publication(self):
        self.enable()
        with self.assertRaises(PreparationError):
            self.local.activate(self.spec, {})

    def test_production_task_failure_keeps_entry_private(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "start", "certbot.service") else None
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertEqual(json.loads(self.host.path(self.spec.node_dir + "/shadowtls.json").read_bytes())["server"]["listen"], "127.0.0.1:443")
        self.assertNotIn("certbot.timer", self.host.enabled)
        self.assertEqual(len(self.host.rules), 1)
        with self.assertRaises(PreparationError):
            self.enable()

    def test_vendor_timer_change_stops_without_overwriting(self):
        self.host.write("/usr/lib/systemd/system/certbot.timer", b"foreign", 0o644)
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertEqual(self.host.path("/usr/lib/systemd/system/certbot.timer").read_bytes(), b"foreign")

    def test_existing_certbot_dropin_not_overwritten(self):
        self.host.write(RENEW_DROPIN, b"foreign", 0o644)
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertEqual(self.host.path(RENEW_DROPIN).read_bytes(), b"foreign")

    def test_policy_changed_during_renewal_is_not_deleted(self):
        def edit(command):
            if command.argv == ("systemctl", "start", "certbot.service"):
                self.host.write(POLICY, b"#!/bin/sh\nexit 101\n", 0o755)
        self.host.local_override = edit
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertEqual(self.host.path(POLICY).read_bytes(), b"#!/bin/sh\nexit 101\n")

    def test_uncertain_ufw_add_stops_entry_without_deleting_rules(self):
        def fail(command):
            if command.argv[:2] == ("ufw", "allow"):
                self.host.rules.append("ufw allow from 0.0.0.0/0 to any port 443 proto tcp comment 'snellctl-main'")
                return Reply(-1, uncertain=True)
        self.host.local_override = fail
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertNotIn(self.spec.shadowtls_service, self.host.active)
        self.assertNotIn(self.spec.shadowtls_service, self.host.enabled)
        self.assertEqual(len(self.host.rules), 2)
        self.assertNotIn(("ufw", "delete"), [a[:2] for a in self.new_calls()])

    def test_firewall_duplicate_skip_not_reported_as_added(self):
        self.host.local_override = lambda c: Reply(0, "Skipping adding existing rule\n") if c.argv[:2] == ("ufw", "allow") else None
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertFalse(self.host.path(STATE + "/public-ready.json").exists())

    def test_ipv6_mutation_detected(self):
        def mutate(command):
            if command.argv[:2] == ("ufw", "allow"):
                self.host.write("/etc/ufw/user6.rules", b"unexpected ipv6 change")
        self.host.local_override = mutate
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertNotIn(self.spec.shadowtls_service, self.host.active)

    def test_shortened_ufw_display_requires_real_ipv4_rule(self):
        def wrong_family(command):
            if command.argv[:2] == ("ufw", "allow"):
                self.host.rules.append("ufw allow 443/tcp comment 'snellctl-main'")
                return Reply(0)
        self.host.local_override = wrong_family
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertNotIn(self.spec.shadowtls_service, self.host.active)

    def test_unsaved_kernel_change_stops_before_side_effects(self):
        self.host.input4.append("-A ufw-user-input -p tcp --dport 8080 -j ACCEPT")
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertFalse(self.host.path(RENEW_DROPIN).exists())

    def test_kernel_default_accept_is_not_accepted(self):
        self.host.local_override = lambda c: Reply(0, "-P INPUT ACCEPT\n") if c.argv == ("iptables", "-S", "INPUT") else None
        with self.assertRaises(PreparationError):
            self.enable()

    def test_restart_failure_leaves_renewal_but_disables_public_entry(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "start", self.spec.shadowtls_service) else None
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertNotIn(self.spec.shadowtls_service, self.host.enabled)
        self.assertIn("certbot.timer", self.host.enabled)
        self.assertFalse(self.host.path(STATE + "/public-ready.json").exists())

    def test_failure_after_enable_disables_only_entry(self):
        def fail(command):
            if command.argv == ("systemctl", "is-enabled", self.spec.shadowtls_service):
                return Reply(1)
        self.host.local_override = fail
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertNotIn(self.spec.shadowtls_service, self.host.enabled)
        self.assertIn("ufw.service", self.host.enabled)
        self.assertIn("certbot.timer", self.host.enabled)

    def test_cleanup_failure_is_explicit(self):
        def fail(command):
            if command.argv == ("systemctl", "start", self.spec.shadowtls_service):
                return Reply(1)
            if command.argv == ("systemctl", "disable", self.spec.shadowtls_service):
                return Reply(1)
        self.host.local_override = fail
        with self.assertRaisesRegex(PreparationError, "无法确认"):
            self.enable()

    def test_interruption_preserves_intent_and_stops_entry(self):
        self.host.local_override = lambda c: (_ for _ in ()).throw(KeyboardInterrupt()) if c.argv[:2] == ("ufw", "allow") else None
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertNotIn(self.spec.shadowtls_service, self.host.active)
        self.assertTrue(self.host.path(STATE + "/public-intent.json").exists())
        with self.assertRaises(PreparationError):
            self.enable()

    def test_atomic_replacement_does_not_follow_existing_candidate(self):
        candidate = self.host.path(self.spec.node_dir + "/shadowtls.json.snellctl-new")
        candidate.symlink_to("/unrelated")
        with self.assertRaises(PreparationError):
            self.enable()
        self.assertTrue(candidate.is_symlink())
        self.assertEqual(json.loads(self.host.path(self.spec.node_dir + "/shadowtls.json").read_bytes())["server"]["listen"], "127.0.0.1:443")

    def test_atomic_replacement_does_not_overwrite_target_drift(self):
        path = self.spec.node_dir + "/shadowtls.json"
        original_write = self.prep.files.write_new
        def race(target, content, mode=0o600):
            original_write(target, content, mode)
            if target == path + ".snellctl-new":
                self.host.write(path, b"external edit")
        with patch.object(self.prep.files, "write_new", side_effect=race):
            with self.assertRaises(PreparationError):
                self.enable()
        self.assertEqual(self.host.path(path).read_bytes(), b"external edit")

    def test_future_renew_hook_accepts_only_owned_hook(self):
        self.enable()
        path = self.host.path("/etc/letsencrypt/renewal/" + DOMAIN + ".conf")
        hook = "/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-main-nginx"
        original = path.read_bytes()
        path.write_bytes(original + ("renew_hook = " + hook + "\n").encode())
        self.assertEqual(self.enable(), "already-public-enabled-external-test-required")
        path.write_bytes(original + b"renew_hook = /foreign/script\n")
        with self.assertRaises(PreparationError):
            self.enable()

    def test_no_secrets_or_full_rules_in_state(self):
        self.enable()
        config = json.loads(self.host.path(self.spec.node_dir + "/shadowtls.json").read_bytes())
        for path in self.host.path(STATE).glob("*.json"):
            text = path.read_text()
            self.assertNotIn(TOKEN, text)
            self.assertNotIn(config["server"]["password"], text)
            self.assertNotIn("ufw allow", text)


class FirewallAndTimerTests(unittest.TestCase):
    def test_kernel_and_saved_rules_normalize_implied_tcp_module(self):
        running = input_rules("-N ufw-user-input\n-A ufw-user-input -s 0.0.0.0/0 -p tcp -m tcp --dport 443 -j ACCEPT\n")
        saved = input_rules("*filter\n:ufw-user-input - [0:0]\n-A ufw-user-input -p tcp --dport 443 -j ACCEPT\nCOMMIT\n", saved=True)
        self.assertEqual(running, saved)

    def test_supported_rules_and_comments_are_data(self):
        self.assertEqual(parse_rules("ufw allow 54321/tcp comment 'SSH; touch /not-executed'"),
                         [Rule("allow", 54321, comment="SSH; touch /not-executed")])
        for command in (
            "ufw allow in proto tcp from 0.0.0.0/0 to any port 443 comment 'snellctl-main'",
            "ufw allow from 0.0.0.0/0 to any port 443 proto tcp comment 'snellctl-main'",
        ):
            self.assertEqual(parse_rules(command), [Rule("allow", 443, "0.0.0.0/0", "snellctl-main")])

    def test_unsupported_rules_fail_closed(self):
        for command in ("ufw allow 443/udp", "ufw allow 1:65535/tcp", "ufw route allow 443/tcp",
                        "ufw allow out 443/tcp", "ufw allow Nginx", "ufw allow from bad to any port 443 proto tcp",
                        "ufw allow 70000/tcp", "ufw allow 443/tcp; rm -rf /", "unexpected output"):
            with self.subTest(command=command), self.assertRaises(PreparationError):
                parse_rules(command)

    def test_timer_uses_isolated_environment_and_scoped_hook(self):
        output = renewal_dropin(NodeSpec("node.example.net")).decode()
        self.assertIn("/usr/bin/env -i PATH=", output)
        self.assertIn("--cert-name node.example.net", output)
        self.assertIn("--no-directory-hooks --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/50-snellctl-main-nginx", output)
        self.assertIn("ExecStartPost=/usr/sbin/nginx -t", output)
        self.assertIn("ExecStartPost=/usr/bin/systemctl reload nginx.service", output)
        self.assertNotIn("--force-renewal", output)
        self.assertNotIn("--dry-run", output)
        self.assertNotIn("--server", output)
        self.assertNotIn(TOKEN, output)


if __name__ == "__main__":
    unittest.main()
