from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
import unittest
from unittest.mock import patch

from snellctl.__main__ import main
from snellctl.deployment import NodeSpec
from snellctl.domaininventory import Inventory, collect, exit_code, render
from snellctl.hostprep import CREDENTIAL, HostFiles, STATE
from snellctl.menu import run_menu
from snellctl.publish import RENEW_DROPIN, renewal_dropin
import test_client
import test_domainchange


class InventoryTests(unittest.TestCase):
    setUp = test_client.ClientFilesTests.setUp
    seed = test_client.ClientFilesTests.seed
    item = test_client.ClientFilesTests.item
    record = test_client.ClientFilesTests.record
    unchanged_snapshot = test_client.ClientFilesTests.unchanged_snapshot

    def prepare(self):
        self.host.certificate(self.spec.domain)
        self.host.write(CREDENTIAL, b"dns_cloudflare_api_token = SECRET-DO-NOT-READ\n")
        self.host.path("/etc/snellctl/credentials").chmod(0o700)
        self.host.write(RENEW_DROPIN, renewal_dropin(self.spec), 0o644)
        record = self.prep._read_record("renewal-enable-ready")
        record["identity"] = self.prep.files.identity(RENEW_DROPIN)
        self.record("renewal-enable-ready", record)

    def collect(self):
        return collect(root=self.root, system="Linux", euid=0)

    def test_current_references(self):
        self.prepare()
        report = self.collect()
        self.assertEqual(report["state"], "review-required", report)
        self.assertTrue(report["collection_complete"])
        self.assertFalse(report["cleanup_authorized"])
        self.assertEqual(report["credentials"][0]["referenced_by_observed_renewals"], ["current"])
        self.assertEqual(report["lineages"][0]["credential"], "current")
        self.assertEqual(report["current_service_health"], "not-checked")
        self.assertEqual(exit_code(report), 0)

    def test_other_lineage_can_share_current_credential(self):
        self.prepare()
        self.host.certificate("another.example.org")
        report = self.collect()
        self.assertTrue(report["collection_complete"], report)
        self.assertEqual(report["credentials"][0]["referenced_by_observed_renewals"], ["current", "other-1"])
        self.assertFalse(report["lineages"][1]["selected_by_managed_renewal_file"])
        self.assertEqual(report["lineages"][1]["ownership"], "not-established")

    def test_custom_ports_not_fixed_to_test_server(self):
        self.spec = NodeSpec("custom.example.net", public_port=15443, snell_port=15001, tls_port=15444)
        self.seed(self.spec)
        self.prepare()
        self.assertTrue(self.collect()["collection_complete"])

    def test_unreferenced_credential_still_preserved(self):
        self.prepare()
        self.host.write("/etc/snellctl/credentials/unused.ini", b"never read")
        report = self.collect()
        extra = report["credentials"][1]
        self.assertEqual(extra["referenced_by_observed_renewals"], [])
        self.assertTrue(extra["preserve"])
        self.assertFalse(report["cleanup_authorized"])
        self.assertEqual(report["global_reference_check"], "not-performed")

    def test_no_commands_network_writes_or_secret_reads(self):
        self.prepare()
        before = self.unchanged_snapshot()
        original = HostFiles.read
        reads = []
        def checked(files, path, **kwargs):
            reads.append(path)
            self.assertFalse(any(piece in path for piece in (
                "/credentials/", "/archive/", "/live/", "/var/log/")), path)
            return original(files, path, **kwargs)
        with patch.object(HostFiles, "read", new=checked), \
             patch.object(HostFiles, "write_new", side_effect=AssertionError("write")), \
             patch.object(HostFiles, "unlink_owned", side_effect=AssertionError("delete")), \
             patch("subprocess.Popen", side_effect=AssertionError("command")), \
             patch("socket.create_connection", side_effect=AssertionError("network")):
            report = self.collect()
        self.assertTrue(report["collection_complete"], report)
        self.assertEqual(before, self.unchanged_snapshot())
        self.assertTrue(any(path.endswith("snell.conf") for path in reads))

    def test_output_redacts_domains_keys_names_and_paths(self):
        self.prepare()
        secret_name = "very-private-credential.ini"
        self.host.write("/etc/snellctl/credentials/" + secret_name, b"SECRET")
        report = self.collect()
        output = json.dumps(report) + render(report)
        for value in (self.spec.domain, test_client.KEYS.psk, test_client.KEYS.shadowtls_password,
                      "SECRET", secret_name, str(self.root), CREDENTIAL):
            self.assertNotIn(value, output)

    def test_external_credential_not_opened_or_printed(self):
        self.prepare()
        self.host.certificate("external.example.org")
        path = self.host.path("/etc/letsencrypt/renewal/external.example.org.conf")
        path.write_text(path.read_text().replace(CREDENTIAL, "/root/private-token.ini"))
        report = self.collect()
        self.assertFalse(report["collection_complete"])
        self.assertIn("unresolved-credential-reference", report["findings"])
        self.assertNotIn("/root/private-token.ini", json.dumps(report))

    def test_missing_credential_is_not_a_completed_inventory(self):
        self.prepare()
        self.host.path(CREDENTIAL).unlink()
        self.assertFalse(self.collect()["collection_complete"])

    def test_unsafe_credential_types_are_never_followed(self):
        self.prepare()
        path = self.host.path(CREDENTIAL)
        for kind in ("symlink", "fifo", "directory", "hardlink", "permissions"):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == "symlink":
                    path.symlink_to("/etc/shadow")
                elif kind == "fifo":
                    os.mkfifo(path, 0o600)
                elif kind == "directory":
                    path.mkdir()
                else:
                    path.write_bytes(b"SECRET")
                    path.chmod(0o644 if kind == "permissions" else 0o600)
                    if kind == "hardlink":
                        os.link(path, path.with_suffix(".link"))
                report = self.collect()
                self.assertFalse(report["collection_complete"])
                self.assertFalse(report["cleanup_authorized"])
                if kind == "directory":
                    path.rmdir()
                else:
                    path.unlink()
                if kind == "hardlink":
                    path.with_suffix(".link").unlink()
                path.write_bytes(b"restored")
                path.chmod(0o600)

    def test_malformed_other_renewal_is_partial_and_redacted(self):
        self.prepare()
        self.host.certificate("broken.example.org")
        path = self.host.path("/etc/letsencrypt/renewal/broken.example.org.conf")
        for content in (b"not-an-ini SECRET", b"[DEFAULT]\nsecret = SECRET\n[renewalparams]\n",
                        b"[renewalparams]\na = SECRET\na = SECRET\n", b"\xff"):
            with self.subTest(content=content):
                path.write_bytes(content)
                report = self.collect()
                self.assertFalse(report["collection_complete"])
                self.assertNotIn("SECRET", json.dumps(report))

    def test_unsafe_renewal_file_is_not_read(self):
        self.prepare()
        path = self.host.path("/etc/letsencrypt/renewal/" + self.spec.domain + ".conf")
        path.unlink()
        os.mkfifo(path, 0o600)
        self.assertEqual(self.collect()["state"], "unverified-preserve-all")

    def test_current_credential_reference_mismatch_refuses_snapshot(self):
        self.prepare()
        path = self.host.path("/etc/letsencrypt/renewal/" + self.spec.domain + ".conf")
        path.write_text(path.read_text().replace(CREDENTIAL, "/tmp/wrong.ini"))
        report = self.collect()
        self.assertEqual(report["state"], "unverified-preserve-all")
        self.assertEqual(report["lineages"], [])

    def test_current_dropin_modified_or_replaced_stops(self):
        self.prepare()
        path = self.host.path(RENEW_DROPIN)
        data = path.read_bytes()
        path.write_bytes(data + b"# drift\n")
        self.assertEqual(self.collect()["state"], "unverified-preserve-all")
        path.write_bytes(data)
        new = path.with_suffix(".new")
        new.write_bytes(data)
        new.chmod(0o644)
        os.replace(new, path)
        self.assertEqual(self.collect()["state"], "unverified-preserve-all")

    def test_links_must_not_escape_their_lineage(self):
        self.prepare()
        path = self.host.path("/etc/letsencrypt/live/" + self.spec.domain + "/privkey.pem")
        for target in ("/root/private", "../../archive/other.example.org/privkey1.pem", "../../../etc/shadow"):
            with self.subTest(target=target):
                path.unlink()
                path.symlink_to(target)
                report = self.collect()
                self.assertFalse(report["collection_complete"])
                self.assertNotIn(target, json.dumps(report))

    def test_archive_private_key_permissions(self):
        self.prepare()
        self.host.path("/etc/letsencrypt/archive/" + self.spec.domain + "/privkey1.pem").chmod(0o644)
        self.assertFalse(self.collect()["collection_complete"])

    def test_parent_symlink_refuses_snapshot(self):
        self.prepare()
        path = self.host.path("/etc/letsencrypt/renewal")
        path.rename(path.with_name("saved"))
        path.symlink_to("saved")
        self.assertEqual(self.collect()["state"], "unverified-preserve-all")

    def test_busy_and_pending_leave_records_untouched(self):
        self.prepare()
        with self.prep._lock():
            self.assertEqual(self.collect()["state"], "unverified-preserve-all")
        for name in ("domain-change-intent", "key-rotation-intent", "port-change-intent", "token-change-intent"):
            with self.subTest(name=name):
                self.record(name, {"private": "SECRET"})
                before = self.unchanged_snapshot()
                self.assertEqual(self.collect()["state"], "unverified-preserve-all")
                self.assertEqual(before, self.unchanged_snapshot())
                self.host.path(STATE + "/" + name + ".json").unlink()

    def test_directory_and_union_limits_cannot_authorize_cleanup(self):
        self.prepare()
        self.host.certificate("other.example.org")
        with patch("snellctl.domaininventory.LIMIT", 1):
            report = self.collect()
        self.assertFalse(report["collection_complete"])
        self.assertIn("directory-limit", report["findings"])
        self.assertFalse(report["cleanup_authorized"])

    def test_unknown_entries_are_counted_but_names_hidden(self):
        self.prepare()
        self.host.write("/etc/letsencrypt/renewal/PRIVATE-backup", b"SECRET")
        report = self.collect()
        self.assertIn("unrecognized-entry", report["findings"])
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_changed_metadata_discards_partial_snapshot(self):
        self.prepare()
        original = Inventory.recheck
        def change_then_check(inventory):
            self.host.write("/etc/snellctl/credentials/concurrent.ini", b"SECRET")
            return original(inventory)
        with patch.object(Inventory, "recheck", new=change_then_check):
            report = self.collect()
        self.assertEqual(report["state"], "unverified-preserve-all")
        self.assertEqual(report["credentials"], [])

    def test_no_root_or_unsupported_platform_never_reads(self):
        with patch("snellctl.domaininventory.Preparation", side_effect=AssertionError("read")):
            for system, uid, state in (("Darwin", 0, "unsupported"), ("Linux", 1000, "root-required")):
                report = collect(root=self.root, system=system, euid=uid)
                self.assertEqual(report["state"], state)
                self.assertEqual(exit_code(report), 2)


class ChangedDomainInventoryTests(unittest.TestCase):
    def test_real_domain_change_fixture_retains_two_separate_references(self):
        fixture = test_domainchange.DomainChangeTests(methodName="test_check_is_read_only_and_repr_is_redacted")
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.assert_success(fixture.change())
        before = fixture.snapshot()
        calls = len(fixture.host.calls)
        report = collect(root=fixture.root, system="Linux", euid=0)
        self.assertTrue(report["collection_complete"], report)
        self.assertEqual(report["credentials"][0]["referenced_by_observed_renewals"], ["current"])
        self.assertEqual(report["credentials"][1]["referenced_by_observed_renewals"], ["other-1"])
        self.assertEqual(before, fixture.snapshot())
        self.assertEqual(calls, len(fixture.host.calls))
        self.assertNotIn(test_domainchange.NEW_DOMAIN, json.dumps(report))


class InventoryInterfaceTests(unittest.TestCase):
    def test_cli_and_menu_read_only_dispatch(self):
        report = collect(system="Darwin")
        with patch("snellctl.domaininventory.collect", return_value=report) as collector, \
             redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["domain-inventory", "--json"]), 2)
        self.assertEqual(json.loads(output.getvalue()), report)
        collector.assert_called_once_with()
        with patch("snellctl.domaininventory.collect", return_value=report) as collector, \
             patch("builtins.input", side_effect=["12", "0"]), redirect_stdout(io.StringIO()):
            self.assertEqual(run_menu(), 0)
        collector.assert_called_once_with()

    def test_no_mutating_or_secret_arguments(self):
        for option in ("--apply", "--delete", "--yes", "--token", "--root"):
            with self.subTest(option=option), redirect_stderr(io.StringIO()) as output, self.assertRaises(SystemExit):
                main(["domain-inventory", option, "SECRET"])
            self.assertNotIn("SECRET", output.getvalue())
