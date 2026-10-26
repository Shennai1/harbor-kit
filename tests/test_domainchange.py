from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.client import ClientError, read_client
from snellctl.domainchange import DomainChange, DomainPlan, INTENT, RECORDS, certificate_paths, log_directory, run_domain_change
from snellctl.hostprep import CREDENTIAL, DOMAIN_CURRENT, PRODUCTION, STAGING, STATE, Preparation, PreparationError, Reply, domain_credential
from snellctl.installer import installation_status, render_status
from snellctl.menu import run_menu
from snellctl.portchange import PortChange
from snellctl.publish import RENEW_DROPIN, renewal_dropin
from snellctl.rotation import KeyRotation
from snellctl.tokenchange import TokenChange, CURRENT
from snellctl.tokendiag import TokenDiagnostic
from snellctl.tokenresume import TokenResume
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
from test_tokenchange import TokenHost, NEW_TOKEN, THIRD_TOKEN, success_output
import test_tokenchange
import test_publish


NEW_DOMAIN = "other.example.org"


def dns_output(domain):
    return (f"dns-01 challenge for {domain}\nWaiting 60 seconds for DNS changes to propagate\n"
            "The dry run was successful.\n")


class DomainHost(TokenHost):
    def _dispatch(self, command):
        args = command.argv
        if args[:2] == ("certbot", "certonly") and "cloudflare-domain-" in " ".join(args):
            self.calls.append(command)
            domain = args[args.index("-d") + 1]
            if "--dry-run" not in args:
                self.certificate(domain)
                path = self.path("/etc/letsencrypt/renewal/" + domain + ".conf")
                path.write_text(path.read_text().replace(CREDENTIAL, args[args.index("--dns-cloudflare-credentials") + 1]))
                return Reply(0, "Successfully received certificate.\n")
            return Reply(0, dns_output(domain))
        if args[:2] == ("certbot", "renew") and "--dns-cloudflare-credentials" in args:
            self.calls.append(command)
            return Reply(0, success_output().replace(DOMAIN, args[args.index("--cert-name") + 1]))
        if args == ("systemctl", "show", "certbot.service", "-p", "NeedDaemonReload"):
            self.calls.append(command)
            return Reply(0, "NeedDaemonReload=no\n")
        if args == ("systemctl", "reload", "nginx.service"):
            self.calls.append(command)
            return Reply(0)
        return super()._dispatch(command)


class DomainChangeTests(unittest.TestCase):
    def setUp(self):
        with patch("test_publish.PublicHost", DomainHost):
            test_publish.PublicationTests.setUp(self)
        test_publish.PublicationTests.enable(self)
        self.tokens = TokenChange(self.engine)
        self.domains = DomainChange(self.tokens)
        self.new = replace(self.spec, domain=NEW_DOMAIN)
        self.before_keys = read_client(root=self.root).keys
        self.old = self.host.path(CREDENTIAL).read_bytes()
        self.host.calls.clear()
        self.probe.reset_mock()

    snapshot = test_tokenchange.TokenChangeTests.snapshot

    def change(self, domain=NEW_DOMAIN, token=NEW_TOKEN):
        return self.domains.change(self.domains.check(domain), token, confirm_change=True, agree_tos=True,
                                   confirm_issue=True, confirm_ssh_reconnected=True)

    def assert_success(self, report):
        self.assertEqual(report["result"], "domain-changed-external-test-required", report)
        self.assertTrue(report["renewal_restored_verified"])
        self.assertTrue(report["report_saved"])
        self.assertNotIn("failure_phase", report)
        self.assertFalse(self.prep._exists(INTENT))

    def assert_pending(self):
        self.assertEqual(installation_status(root=self.root)["domain_change"], "needs-inspection")
        self.assertIn("域名更换", render_status(installation_status(root=self.root)))
        with self.assertRaises(ClientError):
            read_client(root=self.root)
        for action in (self.tokens.check, lambda: PortChange(self.engine).check(24443),
                       lambda: KeyRotation(self.engine).check("snell"), lambda: self.domains.check("next.example.com")):
            with self.assertRaises(Exception):
                action()

    def certbot_calls(self):
        return [c for c in self.host.calls if c.argv[0] == "certbot"]

    def test_check_is_read_only_and_repr_is_redacted(self):
        before = self.snapshot()
        plan = self.domains.check(NEW_DOMAIN)
        self.assertEqual(self.snapshot(), before)
        for secret in (DOMAIN, NEW_DOMAIN, plan.revision):
            self.assertNotIn(secret, repr(plan))
        self.assertEqual(self.certbot_calls(), [])

    def test_success_preserves_old_credential_lineage_keys_ports_firewall(self):
        before = self.snapshot()
        report = self.change()
        self.assert_success(report)
        client = read_client(root=self.root)
        self.assertEqual((client.domain, client.public_port, client.keys), (NEW_DOMAIN, 443, self.before_keys))
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertEqual(self.prep.credential_path(self.new), domain_credential(self.new))
        self.assertEqual(self.prep._read_record(CURRENT), {"format": 1, **self.tokens._credential(domain_credential(self.new))})
        self.assertEqual(self.host.path(RENEW_DROPIN).read_bytes(), renewal_dropin(self.new))
        self.tokens.check()
        after = self.snapshot()
        changed_existing = {p for p in before if before[p] != after.get(p)}
        self.assertEqual(changed_existing, {self.spec.nginx_conf.lstrip("/"), RENEW_DROPIN.lstrip("/"),
                         "etc/letsencrypt/renewal-hooks/deploy/50-snellctl-main-nginx",
                         *(STATE.lstrip("/") + "/" + n + ".json" for n in RECORDS)})
        self.assertIn("certbot.timer", self.host.active)
        self.assertIn("certbot.timer", self.host.enabled)
        self.assertFalse(report["renewal_paused_verified_after"])
        for c in self.host.calls:
            self.assertNotIn(c.argv[:2], {("ufw", "allow"), ("ufw", "delete"), ("systemctl", "restart"),
                                        ("systemctl", "stop"), ("certbot", "delete"), ("certbot", "revoke")})
            for secret in (NEW_TOKEN, TOKEN, self.before_keys.psk, self.before_keys.shadowtls_password):
                self.assertNotIn(secret, repr(c))

    def test_staging_production_and_renewal_use_target_permanent_credential(self):
        self.assert_success(self.change())
        calls = self.certbot_calls()
        self.assertEqual(len(calls), 3)
        self.assertEqual([c.argv[c.argv.index("--server") + 1] for c in calls], [STAGING, PRODUCTION, STAGING])
        for c in calls:
            args = c.argv
            self.assertEqual(args[args.index("--cert-name") + 1], NEW_DOMAIN)
            self.assertEqual(args[args.index("--dns-cloudflare-credentials") + 1], domain_credential(self.new))
            self.assertIn("--no-directory-hooks", args)
            self.assertNotIn("--force-renewal", args)
            self.assertEqual(c.timeout, 600)
        self.assertIn("--dry-run", calls[0].argv)
        self.assertNotIn("--dry-run", calls[1].argv)
        self.assertIn("--no-random-sleep-on-renew", calls[2].argv)
        self.assertIn("--run-deploy-hooks", calls[2].argv)

    def test_existing_current_metadata_is_replaced(self):
        self.prep._record(CURRENT, {"format": 1, **self.tokens._credential(CREDENTIAL)})
        self.assert_success(self.change())
        self.assertEqual(self.prep._read_record(CURRENT), {"format": 1, **self.tokens._credential(domain_credential(self.new))})

    def test_can_change_again_to_an_unused_domain(self):
        self.assert_success(self.change())
        old_new = self.host.path(domain_credential(self.new)).read_bytes()
        self.assert_success(self.change("third.example.com", THIRD_TOKEN))
        self.assertEqual(read_client(root=self.root).domain, "third.example.com")
        self.assertEqual(self.host.path(domain_credential(self.new)).read_bytes(), old_new)
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)

    def test_token_rotation_after_domain_change_uses_new_path(self):
        self.assert_success(self.change())
        self.host.calls.clear()
        self.tokens.change(self.tokens.check(), THIRD_TOKEN, confirm_change=True)
        self.assertIn(THIRD_TOKEN.encode(), self.host.path(domain_credential(self.new)).read_bytes())
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertEqual(read_client(root=self.root).keys, self.before_keys)
        self.assertEqual(self.certbot_calls()[-1].argv[self.certbot_calls()[-1].argv.index("--dns-cloudflare-credentials") + 1],
                         domain_credential(self.new))

    def test_token_diagnosis_recheck_resume_after_domain_change(self):
        self.assert_success(self.change())
        failure = (f"dns-01 challenge for {NEW_DOMAIN}\n"
                   "Encountered CloudFlareAPIError adding TXT record: 10000 Authentication error\n")
        self.host.local_override = lambda c: Reply(1, failure) if c.argv[:2] == ("certbot", "renew") else None
        with self.assertRaises(PreparationError):
            self.tokens.change(self.tokens.check(), THIRD_TOKEN, confirm_change=True)
        diag = TokenDiagnostic(self.tokens)
        self.assertEqual(diag.run(diag.check(), confirm_probe=True)["result"], "command-failed")
        self.host.local_override = None
        diag = TokenDiagnostic(self.tokens, after_permission_fix=True)
        self.assertEqual(diag.run(diag.check(), confirm_probe=True)["result"], "candidate-probe-passed-not-committed")
        resume = TokenResume(self.tokens)
        self.assertEqual(resume.finish(resume.check(), confirm_finish=True)["result"], "token-changed-renewal-tested")
        self.assertIn(THIRD_TOKEN.encode(), self.host.path(domain_credential(self.new)).read_bytes())
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.tokens.check()

    def test_reload_probe_retries_without_repeating_reload_or_certbot(self):
        failures = [True, True]
        def probe(spec, port, certificate):
            if spec.domain == NEW_DOMAIN and failures:
                failures.pop()
                raise PreparationError("workers still reloading")
            return True
        self.probe.side_effect = probe
        self.engine.local.readiness_timeout = 2
        with patch("snellctl.domainchange.time.sleep"):
            self.assert_success(self.change())
        self.assertEqual(len(self.certbot_calls()), 3)
        self.assertEqual(sum(c.argv == ("systemctl", "reload", "nginx.service") for c in self.host.calls), 1)

    def test_reload_probe_does_not_retry_file_drift(self):
        self.engine.local.readiness_timeout = 2
        def probe(spec, port, certificate):
            if spec.domain == NEW_DOMAIN:
                self.host.path(spec.nginx_conf).write_text("foreign change")
                raise PreparationError("workers still reloading")
            return True
        self.probe.side_effect = probe
        with patch("snellctl.domainchange.time.sleep") as sleep:
            report = self.change()
        self.assertEqual(report["failure_phase"], "new-tls-check")
        self.assertEqual(sleep.call_count, 1)
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assertEqual(self.host.path(self.new.nginx_conf).read_text(), "foreign change")

    def test_other_pending_change_during_dns_stops_before_switch(self):
        def inject(c):
            if c.argv[:2] == ("certbot", "certonly"):
                self.prep._record("token-change-intent", {})
        self.host.local_override = inject
        report = self.change()
        self.assertFalse(report["switch_attempted"])
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assertFalse(report["old_renewal_restored_verified"])
        self.assertEqual(len(self.certbot_calls()), 1)

    def test_missing_domain_mapping_cannot_fall_back_to_retired_credential(self):
        self.assert_success(self.change())
        self.host.path(STATE + "/" + DOMAIN_CURRENT + ".json").unlink()
        with self.assertRaises(PreparationError):
            self.tokens.check()

    def test_foreign_renewal_credential_rejected_after_domain_change(self):
        self.assert_success(self.change())
        path = self.host.path("/etc/letsencrypt/renewal/" + NEW_DOMAIN + ".conf")
        path.write_text(path.read_text().replace(domain_credential(self.new), "/foreign/credential.ini"))
        with self.assertRaises(PreparationError):
            self.tokens.check()

    def test_key_and_port_changes_remain_compatible(self):
        self.assert_success(self.change())
        ports = PortChange(self.engine)
        ports.change(ports.check(24443), confirm_change=True, confirm_ssh_reconnected=True)
        keys = KeyRotation(self.engine)
        keys.rotate(keys.check("snell"), confirm_change=True, confirm_ssh_reconnected=True)
        self.tokens.check()
        client = read_client(root=self.root)
        self.assertEqual((client.domain, client.public_port), (NEW_DOMAIN, 24443))

    def test_old_configuration_stays_in_place_until_certificate_verified(self):
        expected = {p: self.host.path(p).read_bytes() for p in (CREDENTIAL, self.spec.nginx_conf, RENEW_DROPIN)}
        def inspect(c):
            if c.argv[:2] == ("certbot", "certonly"):
                self.assertEqual(expected, {p: self.host.path(p).read_bytes() for p in expected})
        self.host.local_override = inspect
        self.assert_success(self.change())

    def test_invalid_or_same_domain_rejected_without_writes(self):
        before = self.snapshot()
        for domain in (DOMAIN, "https://other.example.org", "Other.example.org", "*.example.org", "x;rm.example.org", ""):
            with self.subTest(domain=domain), self.assertRaises(Exception):
                self.domains.check(domain)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.certbot_calls(), [])

    def test_existing_target_lineage_credential_or_logs_not_claimed(self):
        for path in (*certificate_paths(self.new), domain_credential(self.new), log_directory(self.new)):
            p = self.host.path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.symlink_to("/foreign")
            with self.subTest(path=path), self.assertRaises(Exception):
                self.domains.check(NEW_DOMAIN)
            self.assertTrue(p.is_symlink())
            p.unlink()
        self.assertFalse(self.prep._exists(INTENT))

    def test_missing_confirmation_invalid_token_no_commands(self):
        plan = self.domains.check(NEW_DOMAIN)
        self.host.calls.clear()
        values = dict(confirm_change=True, agree_tos=True, confirm_issue=True, confirm_ssh_reconnected=True)
        for key in values:
            for value in (False, None, 1):
                with self.subTest(key=key, value=value), self.assertRaises(PreparationError):
                    self.domains.change(plan, NEW_TOKEN, **{**values, key: value})
        for token in ("", "short", NEW_TOKEN + "\n", "x" * 257, None):
            with self.assertRaises(PreparationError):
                self.domains.change(plan, token, **values)
        self.assertEqual(self.host.calls, [])

    def test_confirmation_time_drift_rejects_before_intent(self):
        plan = self.domains.check(NEW_DOMAIN)
        p = self.host.path(RENEW_DROPIN)
        p.rename(p.with_name("external-backup"))
        self.host.write(RENEW_DROPIN, renewal_dropin(self.spec), 0o644)
        with self.assertRaises(Exception):
            self.domains.change(plan, NEW_TOKEN, confirm_change=True, agree_tos=True, confirm_issue=True, confirm_ssh_reconnected=True)
        self.assertFalse(self.prep._exists(INTENT))

    def test_dns_failure_preserves_old_node_and_restores_old_renewal(self):
        self.host.local_override = lambda c: Reply(1, "CloudFlareAPIError: " + NEW_TOKEN) if c.argv[:2] == ("certbot", "certonly") else None
        report = self.change()
        self.assertEqual(report["failure_phase"], "new-domain-dry-run")
        self.assertTrue(report["old_renewal_restored_verified"])
        self.assertFalse(report["switch_attempted"])
        self.assertIn("certbot.timer", self.host.enabled)
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), self.old)
        self.assertEqual(len(self.certbot_calls()), 1)
        self.assert_pending()
        self.assertNotIn(NEW_TOKEN, json.dumps(report))

    def test_production_failure_preserves_old_node(self):
        self.host.local_override = lambda c: Reply(1) if c.argv[:2] == ("certbot", "certonly") and "--dry-run" not in c.argv else None
        report = self.change()
        self.assertEqual(report["failure_phase"], "new-certificate-issue")
        self.assertFalse(report["switch_attempted"])
        self.assertTrue(report["old_renewal_restored_verified"])
        self.assert_pending()

    def test_zero_exit_without_dns_evidence_is_not_success(self):
        self.host.local_override = lambda c: Reply(0, "No tasks were run") if c.argv[:2] == ("certbot", "certonly") else None
        report = self.change()
        self.assertEqual(report["result"], "stopped")
        self.assertEqual(len(self.certbot_calls()), 1)
        self.assertTrue(report["old_renewal_restored_verified"])

    def test_timeout_is_uncertain_and_never_retried(self):
        self.host.local_override = lambda c: Reply(-1, uncertain=True) if c.argv[:2] == ("certbot", "certonly") else None
        report = self.change()
        self.assertIsNone(report["dns_test"]["exit_code"])
        self.assertTrue(report["dns_test"]["execution_uncertain"])
        self.assertEqual(len(self.certbot_calls()), 1)
        self.assert_pending()

    def test_interrupt_keeps_inspection_marker_and_private_report(self):
        def interrupt(c):
            if c.argv[:2] == ("certbot", "certonly"):
                raise KeyboardInterrupt(NEW_TOKEN)
        self.host.local_override = interrupt
        report = self.change()
        self.assertEqual(report["failure_phase"], "new-domain-dry-run")
        self.assertTrue(report["report_saved"])
        self.assertNotIn(NEW_TOKEN, json.dumps(report))
        self.assert_pending()

    def test_bad_new_certificate_blocks_configuration_switch(self):
        self.host.local_override = lambda c: Reply(1) if c.argv[:2] == ("openssl", "verify") and NEW_DOMAIN in c.argv else None
        report = self.change()
        self.assertFalse(report["switch_attempted"])
        self.assertTrue(report["old_renewal_restored_verified"])
        self.assert_pending()

    def test_old_credential_drift_during_dns_is_not_overwritten_or_renewed(self):
        def edit(c):
            if c.argv[:2] == ("certbot", "certonly"):
                self.host.write(CREDENTIAL, b"foreign\n")
        self.host.local_override = edit
        report = self.change()
        self.assertFalse(report["old_renewal_restored_verified"])
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assertEqual(self.host.path(CREDENTIAL).read_bytes(), b"foreign\n")
        self.assertFalse(report["switch_attempted"])

    def test_new_credential_drift_prevents_switch(self):
        def edit(c):
            if c.argv[:2] == ("certbot", "certonly"):
                self.host.write(domain_credential(self.new), b"foreign\n")
        self.host.local_override = edit
        report = self.change()
        self.assertFalse(report["switch_attempted"])
        self.assertEqual(self.host.path(domain_credential(self.new)).read_bytes(), b"foreign\n")
        self.assert_pending()

    def test_reload_failure_retains_changed_files_and_pauses_renewal(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "reload", "nginx.service") else None
        report = self.change()
        self.assertTrue(report["switch_attempted"])
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assertIn(NEW_DOMAIN.encode(), self.host.path(self.spec.nginx_conf).read_bytes())
        self.assertFalse(report["renewal_restored_verified"])
        self.assert_pending()

    def test_new_tls_failure_is_not_success(self):
        self.probe.side_effect = lambda spec, port, cert: spec.domain != NEW_DOMAIN
        report = self.change()
        self.assertEqual(report["failure_phase"], "new-tls-check")
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assert_pending()

    def test_new_renewal_failure_is_not_success(self):
        self.host.local_override = lambda c: Reply(1) if c.argv[:2] == ("certbot", "renew") else None
        report = self.change()
        self.assertEqual(report["failure_phase"], "new-renewal-test")
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assert_pending()

    def test_failed_timer_enable_stays_pending(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "enable", "--now", "certbot.timer") else None
        report = self.change()
        self.assertEqual(report["failure_phase"], "renewal-enable")
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assert_pending()

    def test_timer_zero_exit_without_state_change_is_failure(self):
        self.host.local_override = lambda c: Reply(0) if c.argv == ("systemctl", "enable", "--now", "certbot.timer") else None
        report = self.change()
        self.assertEqual(report["failure_phase"], "enabled-postcheck")
        self.assertFalse(report["renewal_restored_verified"])
        self.assert_pending()

    def test_failed_pause_cannot_claim_old_renewal_restored(self):
        self.host.local_override = lambda c: Reply(1) if c.argv == ("systemctl", "disable", "--now", "certbot.timer") else None
        report = self.change()
        self.assertFalse(report["renewal_paused_verified_after"])
        self.assertFalse(report["old_renewal_restored_verified"])
        self.assertFalse(report["switch_attempted"])
        self.assert_pending()

    def test_active_certbot_never_killed(self):
        self.host.local_override = lambda c: Reply(0, "ActiveState=active\nSubState=running\nMainPID=10\nJob=\n") \
            if c.argv[-1] == "ActiveState,SubState,MainPID,Job" else None
        with self.assertRaises(PreparationError):
            self.domains.check(NEW_DOMAIN)
        self.assertFalse(self.prep._exists(INTENT))
        self.assertNotIn(("systemctl", "stop", "certbot.service"), [c.argv for c in self.host.calls])

    def test_private_log_and_report_permissions_and_redaction(self):
        report = self.change()
        self.assert_success(report)
        base = self.host.path(log_directory(self.new))
        for path in [base, *base.rglob("*")]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
        self.assertEqual(json.loads((base / "report.json").read_bytes()), report)
        for secret in (DOMAIN, NEW_DOMAIN, TOKEN, NEW_TOKEN, self.before_keys.psk):
            self.assertNotIn(secret, json.dumps(report))
        self.assertEqual(self.host.path(domain_credential(self.new)).stat().st_mode & 0o777, 0o600)

    def test_report_write_failure_is_honest(self):
        original = self.files_write = self.prep.files.write_new
        def fail(path, content, mode=0o600):
            if path.endswith("/report.json"):
                raise OSError("private")
            return original(path, content, mode)
        with patch.object(self.prep.files, "write_new", side_effect=fail):
            report = self.change()
        self.assertEqual(report["result"], "domain-changed-external-test-required")
        self.assertFalse(report["report_saved"])

    def test_lock_held_during_all_certificate_requests(self):
        def inspect(c):
            if c.argv[0] == "certbot":
                with Preparation(self.root, self.host) as prep:
                    with self.assertRaises(PreparationError):
                        with prep._lock():
                            self.fail("unlocked")
        self.host.local_override = inspect
        self.assert_success(self.change())

    def test_foreign_marker_not_removed(self):
        def edit(c):
            if c.argv == ("systemctl", "enable", "--now", "certbot.timer"):
                self.host.write(STATE + "/" + INTENT + ".json", b'{"foreign": true}\n')
        self.host.local_override = edit
        report = self.change()
        self.assertEqual(report["result"], "stopped")
        self.assertEqual(self.prep._read_record(INTENT), {"foreign": True})

    def test_cleanup_fsync_failure_recreates_marker(self):
        original = self.prep.files.unlink_owned
        def fail(path, identity):
            original(path, identity)
            if path == STATE + "/" + INTENT + ".json":
                raise OSError("fsync")
        with patch.object(self.prep.files, "unlink_owned", side_effect=fail):
            report = self.change()
        self.assertEqual(report["result"], "stopped")
        self.assertTrue(report["renewal_paused_verified_after"])
        self.assert_pending()

    def test_metadata_binding_drift_rejected(self):
        self.assert_success(self.change())
        self.host.write(STATE + "/" + DOMAIN_CURRENT + ".json", b'{"format": 1, "domain_sha256": "wrong"}\n')
        with self.assertRaises(Exception):
            self.tokens.check()
        with self.assertRaises(ClientError):
            read_client(root=self.root)


class DomainWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.engine = Mock()
        self.engine.phase = "not-started"
        self.engine.check.return_value = DomainPlan(DOMAIN, NEW_DOMAIN, "d" * 64)
        self.engine.change.return_value = {"result": "domain-changed-external-test-required"}
        self.ui = Console([NEW_DOMAIN, "y", "y", "y", "y"])
        self.ui.secret.return_value = NEW_TOKEN

    @contextmanager
    def factory(self):
        yield Mock()

    def run_change(self):
        with patch("snellctl.domainchange.DomainChange", return_value=self.engine):
            return run_domain_change(factory=self.factory, terminal=self.ui)

    def test_confirmations_hidden_input_and_success(self):
        self.assertEqual(self.run_change(), 0)
        self.ui.secret.assert_called_once_with()
        self.engine.change.assert_called_once_with(self.engine.check.return_value, NEW_TOKEN,
            confirm_change=True, agree_tos=True, confirm_issue=True, confirm_ssh_reconnected=True)
        self.assertNotIn(NEW_TOKEN, self.ui.text)
        self.assertIn("shadow-tls-sni", self.ui.text)

    def test_each_confirmation_defaults_to_cancel_before_reading_secret(self):
        for index in range(4):
            for answer in ("", "n", "yes", EOFError(), KeyboardInterrupt()):
                self.ui = Console([NEW_DOMAIN, *(["y"] * index), answer])
                self.assertNotEqual(self.run_change(), 0)
                self.ui.secret.assert_not_called()
        self.engine.change.assert_not_called()

    def test_empty_domain_cancels_without_inspection(self):
        self.ui = Console([""])
        self.assertEqual(self.run_change(), 130)
        self.engine.check.assert_not_called()

    def test_noninteractive_does_not_open_engine(self):
        self.ui.interactive = lambda: False
        factory = Mock()
        self.assertEqual(run_domain_change(factory=factory, terminal=self.ui), 2)
        factory.assert_not_called()

    def test_tty_loss_before_or_after_token_stops(self):
        for states in ([True, False], [True, True, False]):
            self.ui = Console([NEW_DOMAIN, "y", "y", "y", "y"])
            self.ui.interactive = Mock(side_effect=states)
            self.assertEqual(self.run_change(), 1)
        self.engine.change.assert_not_called()

    def test_failure_redacted_and_no_success_claim(self):
        self.engine.change.side_effect = RuntimeError(NEW_TOKEN)
        self.assertEqual(self.run_change(), 1)
        self.assertNotIn(NEW_TOKEN, self.ui.text)
        self.assertNotIn("服务端切换及续期演练通过", self.ui.text)

    def test_cli_opt_in_and_secret_flags_not_supported(self):
        with patch("snellctl.domainchange.run_domain_change", return_value=130) as run, redirect_stderr(io.StringIO()):
            self.assertEqual(main(["change-domain"]), 2)
            run.assert_not_called()
            self.assertEqual(main(["change-domain", "--experimental"]), 130)
            run.assert_called_once_with()
        for option in ("--token", "--yes", "--force", "--root", "--domain"):
            with redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
                main(["change-domain", "--experimental", option, NEW_TOKEN])
            self.assertNotIn(NEW_TOKEN, err.getvalue())

    def test_menu_opt_in(self):
        for experimental in (False, True):
            with patch("snellctl.domainchange.run_domain_change", return_value=0) as run, \
                    patch("builtins.input", side_effect=["11", "0"]), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(run_menu(experimental=experimental), 0)
                self.assertEqual(run.call_count, int(experimental))
                self.assertEqual("11. 更换域名和证书" in out.getvalue(), experimental)
