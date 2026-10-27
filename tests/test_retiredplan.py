from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import PurePosixPath
import unittest
from unittest.mock import Mock, patch

from snellctl.__main__ import main
from snellctl.domaininventory import Inventory
from snellctl.hostprep import CREDENTIAL, HostFiles, Reply, STATE, domain_credential
from snellctl.menu import run_menu
from snellctl.retiredplan import RetiredPlan, run_retired_plan
from test_hostprep import DOMAIN, TOKEN
from test_installer import Console
import test_domainchange


class PlanHost(test_domainchange.DomainHost):
    def _dispatch(self, command):
        args = command.argv
        if args[:2] == ("openssl", "x509") and args[-2:] == ("-ext", "subjectAltName"):
            self.calls.append(command)
            domain = PurePosixPath(args[3]).parent.name
            return Reply(0, "X509v3 Subject Alternative Name:\n    DNS:" + domain + "\n")
        return super()._dispatch(command)


class RetiredScopeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_domainchange.DomainChangeTests(methodName="test_check_is_read_only_and_repr_is_redacted")
        self.addCleanup(self.fixture.doCleanups)
        with patch("test_domainchange.DomainHost", PlanHost):
            self.fixture.setUp()
        self.fixture.assert_success(self.fixture.change())
        self.host, self.prep = self.fixture.host, self.fixture.prep
        self.enrich_renewals()
        self.engine = RetiredPlan(self.fixture.tokens)
        self.host.calls.clear()

    def enrich_renewals(self):
        for path in self.host.path("/etc/letsencrypt/renewal").glob("*.conf"):
            content = path.read_text()
            if "archive_dir = " in content:
                continue
            name = path.stem
            top = f"archive_dir = /etc/letsencrypt/archive/{name}\n"
            for part in ("cert", "chain", "fullchain", "privkey"):
                top += f"{part} = /etc/letsencrypt/live/{name}/{part}.pem\n"
            path.write_text(top + content)

    def check(self, domain=DOMAIN):
        return self.engine.check(domain)

    def blocked(self, report, reason=None):
        self.assertEqual(report["result"], "blocked-preserve-all", report)
        self.assertFalse(report["cleanup_authorized"])
        self.assertFalse(report["host_changes_attempted"])
        self.assertTrue(report["all_assets_preserved"])
        if reason:
            self.assertEqual(report["reason"], reason, report)

    def test_scope_passes_but_not_ownership_or_deletion_authority(self):
        report = self.check()
        self.assertEqual(report["result"], "scope-checked-confirmation-required", report)
        self.assertFalse(report["cleanup_authorized"])
        self.assertFalse(report["report_saved"])
        self.assertTrue(report["history"]["initial_domain_digest_match"])
        self.assertTrue(report["history"]["current_domain_change_success_record"])
        self.assertFalse(report["history"]["historical_file_ownership_proven"])
        self.assertEqual(report["current_service_health"], "local-checks-passed")
        self.assertEqual(report["target_counts"]["archive_files"], 4)

    def test_no_files_services_rules_or_timer_modified(self):
        before = self.fixture.snapshot()
        active, enabled, rules = set(self.host.active), set(self.host.enabled), list(self.host.rules)
        with patch.object(HostFiles, "write_new", side_effect=AssertionError("write")), \
             patch.object(HostFiles, "replace_owned", side_effect=AssertionError("replace")), \
             patch.object(HostFiles, "unlink_owned", side_effect=AssertionError("unlink")):
            report = self.check()
        self.assertEqual(report["result"], "scope-checked-confirmation-required", report)
        self.assertEqual(before, self.fixture.snapshot())
        self.assertEqual((active, enabled, rules), (self.host.active, self.host.enabled, self.host.rules))
        prefixes = {("nginx", "-v"), ("nginx", "-T"), ("dpkg-query", "-W"),
                    ("systemctl", "show"), ("systemctl", "is-enabled"), ("ufw", "show"), ("ufw", "status"),
                    ("iptables", "-S"), ("ip6tables", "-S"), ("ss", "-H"),
                    ("openssl", "x509"), ("openssl", "verify"), ("openssl", "pkey")}
        self.assertTrue(self.host.calls)
        for call in self.host.calls:
            self.assertIn(call.argv[:2], prefixes)
        self.assertTrue(self.fixture.probe.called)

    def test_old_token_and_old_private_keys_and_raw_logs_are_not_read(self):
        original = HostFiles.read
        def guarded(files, path, **kwargs):
            self.assertNotEqual(path, CREDENTIAL)
            self.assertFalse("/archive/" + DOMAIN + "/privkey" in path)
            self.assertFalse(path.endswith("command-output.txt") or "/var/log/" in path)
            return original(files, path, **kwargs)
        with patch.object(HostFiles, "read", new=guarded):
            report = self.check()
        self.assertEqual(report["result"], "scope-checked-confirmation-required", report)

    def test_report_contains_no_domains_paths_keys_or_fingerprints(self):
        output = json.dumps(self.check())
        for value in (DOMAIN, test_domainchange.NEW_DOMAIN, TOKEN, test_domainchange.NEW_TOKEN,
                      str(self.fixture.root), CREDENTIAL, self.fixture.before_keys.psk,
                      self.fixture.before_keys.shadowtls_password):
            self.assertNotIn(value, output)

    def test_current_domain_rejected_before_system_checks(self):
        self.blocked(self.check(test_domainchange.NEW_DOMAIN), "target-is-current-domain")
        self.assertEqual(self.host.calls, [])

    def test_invalid_targets_rejected_before_commands(self):
        for domain in ("other-1", "", "https://old.example.org", "../outside", "OLD.example.org", "*.example.org"):
            with self.subTest(domain=domain):
                self.blocked(self.check(domain))
        self.assertEqual(self.host.calls, [])

    def test_unrelated_certificate_not_adopted_by_name_or_permissions(self):
        self.host.certificate("unrelated.example.org")
        self.enrich_renewals()
        self.blocked(self.check("unrelated.example.org"), "target-history-not-found")

    def test_success_report_for_previous_target_is_only_a_hint(self):
        self.fixture.assert_success(self.fixture.change("third.example.net"))
        self.enrich_renewals()
        report = self.check(test_domainchange.NEW_DOMAIN)
        self.assertEqual(report["result"], "scope-checked-confirmation-required", report)
        self.assertFalse(report["history"]["initial_domain_digest_match"])
        self.assertTrue(report["history"]["target_domain_change_success_record"])
        self.assertFalse(report["history"]["historical_file_ownership_proven"])

    def test_existing_history_is_not_used_to_repair_missing_record(self):
        self.host.path(STATE + "/dns-test-ready.json").unlink()
        self.blocked(self.check())

    def test_shared_current_credential_blocks(self):
        path = self.host.path("/etc/letsencrypt/renewal/" + DOMAIN + ".conf")
        path.write_text(path.read_text().replace(CREDENTIAL, domain_credential(self.fixture.new)))
        self.blocked(self.check(), "current-credential-shared")

    def test_shared_other_renewal_credential_blocks(self):
        self.host.certificate("shared.example.org")
        self.enrich_renewals()
        self.blocked(self.check(), "credential-shared-with-other-renewal")

    def test_external_credential_path_not_opened(self):
        path = self.host.path("/etc/letsencrypt/renewal/" + DOMAIN + ".conf")
        path.write_text(path.read_text().replace(CREDENTIAL, "/root/secret.ini"))
        self.blocked(self.check(), "inventory-incomplete")

    def test_certbot_archive_paths_cannot_escape_or_cross_lineages(self):
        path = self.host.path("/etc/letsencrypt/renewal/" + DOMAIN + ".conf")
        data = path.read_text()
        for destination in ("/root", "/etc/letsencrypt/archive/" + test_domainchange.NEW_DOMAIN):
            with self.subTest(destination=destination):
                path.write_text(data.replace("/etc/letsencrypt/archive/" + DOMAIN, destination))
                self.blocked(self.check(), "renewal-paths")

    def test_other_renewal_cross_referencing_target_files_blocks(self):
        path = self.host.path("/etc/letsencrypt/renewal/" + test_domainchange.NEW_DOMAIN + ".conf")
        path.write_text(path.read_text().replace("/live/" + test_domainchange.NEW_DOMAIN, "/live/" + DOMAIN))
        self.blocked(self.check(), "renewal-paths")

    def test_target_renewal_extra_hook_blocks(self):
        path = self.host.path("/etc/letsencrypt/renewal/" + DOMAIN + ".conf")
        path.write_text(path.read_text() + "pre_hook = echo private\n")
        self.blocked(self.check(), "target-renewal-hooks")

    def test_unknown_top_level_and_duplicate_configuration_block(self):
        path = self.host.path("/etc/letsencrypt/renewal/" + DOMAIN + ".conf")
        data = path.read_text()
        for prefix in ("unknown = value\n", "version = 4.0.0\n", "[DEFAULT]\nsecret = PRIVATE\n"):
            with self.subTest(prefix=prefix):
                path.write_text(prefix + data)
                report = self.check()
                self.blocked(report)
                self.assertNotIn("PRIVATE", json.dumps(report))

    def test_san_must_be_exact_single_domain(self):
        for san in ("DNS:" + DOMAIN + ", DNS:another.example.org", "DNS:*.example.org", "IP Address:192.0.2.1"):
            with self.subTest(san=san):
                self.host.local_override = lambda c: Reply(0, "X509v3 Subject Alternative Name:\n" + san) if c.argv[-2:] == ("-ext", "subjectAltName") else None
                self.blocked(self.check(), "target-san-not-single-domain")

    def test_additional_complete_archive_generation_is_counted(self):
        for part in ("cert", "chain", "fullchain", "privkey"):
            self.host.write("/etc/letsencrypt/archive/" + DOMAIN + "/" + part + "2.pem", b"fixture")
        report = self.check()
        self.assertEqual(report["result"], "scope-checked-confirmation-required", report)
        self.assertEqual(report["target_counts"]["archive_generations"], 2)

    def test_incomplete_archive_generation_blocks(self):
        self.host.write("/etc/letsencrypt/archive/" + DOMAIN + "/cert2.pem", b"fixture")
        self.blocked(self.check(), "target-incomplete-generation")

    def test_unknown_archive_and_live_entries_block(self):
        for directory in ("archive", "live"):
            path = f"/etc/letsencrypt/{directory}/{DOMAIN}/unknown"
            with self.subTest(directory=directory):
                self.host.write(path, b"PRIVATE")
                self.blocked(self.check(), "target-" + directory + "-entries")
                self.host.path(path).unlink()

    def test_unsafe_old_credential_metadata_and_hardlinks_block(self):
        target = self.host.path(CREDENTIAL)
        target.chmod(0o644)
        self.blocked(self.check(), "inventory-incomplete")
        target.chmod(0o600)
        os.link(target, self.host.path("/etc/snellctl/credentials/linked.ini"))
        self.blocked(self.check(), "inventory-incomplete")

    def test_symlink_escape_and_fifo_block_without_reading(self):
        path = self.host.path("/etc/letsencrypt/archive/" + DOMAIN + "/privkey1.pem")
        path.unlink()
        path.symlink_to("/root/PRIVATE")
        self.blocked(self.check(), "inventory-incomplete")
        path.unlink()
        os.mkfifo(path, 0o600)
        self.blocked(self.check(), "inventory-incomplete")

    def test_extra_inactive_nginx_site_and_hook_block(self):
        for path in ("/etc/nginx/sites-available/unused", "/etc/letsencrypt/renewal-hooks/pre/external"):
            with self.subTest(path=path):
                self.host.write(path, b"external")
                self.blocked(self.check(), "extra-nginx-or-renewal-hook-scope")
                self.host.path(path).unlink()

    def test_active_certbot_is_not_stopped(self):
        self.host.local_override = lambda c: Reply(0, "ActiveState=active\nSubState=running\nMainPID=123\nJob=\n") if c.argv[-1] == "ActiveState,SubState,MainPID,Job" else None
        self.blocked(self.check())
        self.assertFalse(any(c.argv[:2] == ("systemctl", "stop") for c in self.host.calls))

    def test_timer_disabled_is_not_reenabled(self):
        self.host.active.discard("certbot.timer")
        self.host.enabled.discard("certbot.timer")
        self.blocked(self.check())
        self.assertNotIn("certbot.timer", self.host.enabled)

    def test_failed_current_tls_does_not_reload(self):
        self.fixture.probe.return_value = False
        self.blocked(self.check())
        self.assertFalse(any(c.argv[:2] == ("systemctl", "reload") for c in self.host.calls))

    def test_busy_lock_and_pending_intent_preserve_all(self):
        with self.prep._lock():
            self.blocked(self.check())
        self.prep._record("domain-change-intent", {"private": "SECRET"})
        before = self.fixture.snapshot()
        self.blocked(self.check())
        self.assertEqual(before, self.fixture.snapshot())

    def test_target_change_during_scan_discards_success(self):
        def progress(phase):
            if phase == "unchanged-health-check":
                self.host.path(CREDENTIAL).write_bytes(b"modified old token")
        self.engine.progress = progress
        self.blocked(self.check())

    def test_scan_limit_blocks(self):
        with patch("snellctl.domaininventory.LIMIT", 1):
            self.blocked(self.check(), "inventory-incomplete")

    def test_errors_are_redacted(self):
        self.host.local_override = lambda c: (_ for _ in ()).throw(RuntimeError("PRIVATE"))
        report = self.check()
        self.blocked(report)
        self.assertNotIn("PRIVATE", json.dumps(report))


class RetiredPlanInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.tokens = Mock()
        self.factory_calls = 0

    @contextmanager
    def factory(self):
        self.factory_calls += 1
        yield self.tokens

    def test_decline_before_engine_access(self):
        for answer in ("n", "", "yes", "确认"):
            ui = Console([DOMAIN, answer])
            self.assertEqual(run_retired_plan(factory=self.factory, terminal=ui), 130)
        self.assertEqual(self.factory_calls, 0)

    def test_cancel_invalid_input_and_interruption(self):
        for value, expected in (("", 130), ("other-1", 1), ("PRIVATE", 1), (KeyboardInterrupt(), 130)):
            ui = Console([value])
            self.assertEqual(run_retired_plan(factory=self.factory, terminal=ui), expected)
            self.assertNotIn("PRIVATE", ui.text)
        self.assertEqual(self.factory_calls, 0)

    def test_no_token_prompt_and_confirmation_not_deletion_consent(self):
        ui = Console([DOMAIN, "y"])
        report = {"result": "scope-checked-confirmation-required", "cleanup_authorized": False}
        with patch("snellctl.retiredplan.RetiredPlan.check", return_value=report) as check:
            self.assertEqual(run_retired_plan(factory=self.factory, terminal=ui), 0)
        check.assert_called_once_with(DOMAIN)
        ui.secret.assert_not_called()
        self.assertIn("没有授权删除", ui.text)

    def test_noninteractive_and_terminal_change_refuse(self):
        for states in ([False], [True, False]):
            ui = Console([DOMAIN, "y"])
            ui.interactive = Mock(side_effect=states)
            self.assertEqual(run_retired_plan(factory=self.factory, terminal=ui), 2)
        self.assertEqual(self.factory_calls, 0)

    def test_cli_menu_and_no_apply_or_domain_arguments(self):
        with patch("snellctl.retiredplan.run_retired_plan", return_value=0) as run:
            self.assertEqual(main(["retired-domain-plan"]), 0)
            with patch("builtins.input", side_effect=["13", "0"]), redirect_stdout(io.StringIO()):
                self.assertEqual(run_menu(), 0)
            self.assertEqual(run.call_count, 2)
        for arg in ("--domain", "--apply", "--yes", "--token", "--root"):
            with self.subTest(arg=arg), redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit):
                main(["retired-domain-plan", arg, "PRIVATE"])
            self.assertNotIn("PRIVATE", output.getvalue())
