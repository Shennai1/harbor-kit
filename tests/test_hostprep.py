import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from snellctl.deployment import NodeSpec
from snellctl.hostprep import (
    APT_LISTS, CREDENTIAL, DEPENDENCIES, POLICY, POLICY_BYTES, PRODUCTION,
    SOURCES, STAGING, STATE, UNITS, Command, Preparation, PreparationError, Reply,
)


DOMAIN = "node.example.net"
TOKEN = "synthetic_test_token_not_a_real_credential_123456"
PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n"


class FakeHost:
    """Commands never escape the test root or reach APT, systemd, DNS or a CA."""

    def __init__(self, root):
        self.root = root
        self.calls = []
        self.override = None
        self.installed = False
        self.versions = {name: "1.2.3-1+deb13u1" for name in DEPENDENCIES}
        for path in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system",
                     "/usr/sbin", "/usr/share/keyrings"):
            self.path(path).mkdir(parents=True, exist_ok=True)
        self.write("/etc/os-release", b'ID=debian\nVERSION_ID="13"\n', 0o644)
        self.write("/usr/share/keyrings/debian-archive-keyring.gpg", b"fake keyring", 0o644)

    def path(self, path):
        return self.root / path.lstrip("/")

    def write(self, path, value, mode=0o600):
        file = self.path(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(value)
        file.chmod(mode)

    def certificate(self, domain=DOMAIN):
        data = {"cert": b"certificate\n", "chain": b"chain\n", "fullchain": b"certificate\nchain\n", "privkey": b"TEST-PRIVATE-KEY\n"}
        live = self.path("/etc/letsencrypt/live/" + domain)
        live.mkdir(parents=True)
        for name, value in data.items():
            self.write("/etc/letsencrypt/archive/" + domain + "/" + name + "1.pem", value)
            (live / (name + ".pem")).symlink_to("../../archive/" + domain + "/" + name + "1.pem")
        self.write("/etc/letsencrypt/renewal/" + domain + ".conf", (
            "version = 4.0.0\n[renewalparams]\nauthenticator = dns-cloudflare\n"
            "server = " + PRODUCTION + "\ndns_cloudflare_credentials = " + CREDENTIAL + "\nkey_type = ecdsa\n"
        ).encode())

    def __call__(self, command):
        self.calls.append(command)
        if self.override:
            value = self.override(command)
            if value is not None:
                return value
        args = command.argv
        if args[:2] == ("dpkg", "--print-architecture"):
            return Reply(0, "amd64\n")
        if args[:2] == ("systemctl", "show"):
            path = self.path("/etc/systemd/system/" + args[2])
            masked = path.is_symlink() and os.readlink(path) == "/dev/null"
            return Reply(0, "LoadState=" + ("masked" if masked else "not-found") + "\nActiveState=inactive\n")
        if args[:2] == ("systemctl", "daemon-reload") or args[:2] == ("dpkg", "--audit"):
            return Reply(0)
        if args[0] == "apt-get":
            if "install" in args and "--simulate" not in args:
                self.installed = True
                self.write("/etc/letsencrypt/cli.ini", b"max-log-backups = 0\npreconfigured-renewal = True\n", 0o644)
            return Reply(0)
        if args[0] == "apt-cache":
            return Reply(0, "".join(f"{name}:\n  Candidate: {version}\n" for name, version in self.versions.items()))
        if args[0] == "dpkg-query":
            return Reply(0, "".join(f"{name}\tii \t{version}\n" for name, version in self.versions.items()) if self.installed else "")
        if args[0] == "certbot":
            if "--dry-run" not in args:
                self.certificate(args[args.index("-d") + 1])
            return Reply(0, "raw output must not be logged: " + TOKEN)
        if args[0] == "openssl":
            return Reply(0, PUBLIC_KEY if "-pubkey" in args or "-pubout" in args else "OK\n")
        raise AssertionError(args)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.host = FakeHost(self.root)
        self.prep = Preparation(self.root, self.host)
        self.addCleanup(self.prep.files.close)

    def packages(self):
        self.prep.initialize()
        self.assertEqual(self.prep.packages(), "packages-prepared-services-blocked")

    def credentials(self):
        self.packages()
        self.prep.credential(TOKEN)

    def tested(self):
        self.credentials()
        self.assertEqual(self.prep.certificate(DOMAIN, production=False, agree_tos=True), "dns-test-passed")

    def issued(self):
        self.tested()
        self.assertEqual(self.prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True), "certificate-verified-services-blocked")

    def assert_no_install(self):
        self.assertFalse(any(c.argv[0] == "apt-get" and "install" in c.argv and "--simulate" not in c.argv for c in self.host.calls))

    def test_complete_flow_preserves_masks_and_does_not_touch_firewall(self):
        self.issued()
        for unit in UNITS:
            self.assertEqual(os.readlink(self.host.path("/etc/systemd/system/" + unit)), "/dev/null")
        self.assertEqual(self.host.path(POLICY).read_bytes(), POLICY_BYTES)
        for command in self.host.calls:
            self.assertNotIn(command.argv[0], {"ufw", "iptables", "ip6tables", "nft", "pip"})
            self.assertNotIn("unmask", command.argv)
            self.assertNotIn("enable", command.argv)
            self.assertNotIn("autoremove", command.argv)
        self.assertTrue(self.host.path(STATE + "/certificate-ready.json").exists())

    def test_real_symlink_os_release_supported(self):
        self.host.write("/usr/lib/os-release", self.host.path("/etc/os-release").read_bytes(), 0o644)
        self.host.path("/etc/os-release").unlink()
        self.host.path("/etc/os-release").symlink_to("../usr/lib/os-release")
        self.prep.initialize()
        self.assertTrue(self.host.path(STATE + "/owner.json").exists())

    def test_platform_rejected_before_writes(self):
        self.host.write("/etc/os-release", b'ID=debian\nVERSION_ID="12"\n', 0o644)
        with self.assertRaises(PreparationError):
            self.prep.initialize()
        self.assertFalse(self.host.path(STATE).exists())
        self.assertEqual(self.host.calls, [])

    def test_existing_policy_unit_config_and_certificate_not_overwritten(self):
        for path in (POLICY, "/etc/systemd/system/nginx.service", "/etc/nginx", "/etc/letsencrypt"):
            with self.subTest(path=path):
                self.host.write(path, b"foreign")
                with self.assertRaises(PreparationError):
                    self.prep.initialize()
                self.assertEqual(self.host.path(path).read_bytes(), b"foreign")
                self.host.path(path).unlink()
        self.assertFalse(self.host.path(STATE).exists())

    def test_initialize_not_repeated(self):
        self.prep.initialize()
        with self.assertRaises(PreparationError):
            self.prep.initialize()

    def test_directory_appearing_during_initialize_not_adopted(self):
        def race(command):
            if command.argv[:3] == ("systemctl", "show", "certbot.timer"):
                directory = self.host.path(STATE)
                directory.mkdir(parents=True, mode=0o700)
                (directory / "foreign").write_bytes(b"preserve")
        self.host.override = race
        with self.assertRaises(FileExistsError):
            self.prep.initialize()
        self.assertEqual(self.host.path(STATE + "/foreign").read_bytes(), b"preserve")
        self.assertFalse(self.host.path(STATE + "/owner.json").exists())

    def test_all_sources_update_failure_happens_before_masks(self):
        self.prep.initialize()
        self.host.override = lambda c: Reply(100, "https://secret@bad-source") if c.argv[0] == "apt-get" else None
        with self.assertRaises(PreparationError) as raised:
            self.prep.packages()
        self.assertNotIn("secret", str(raised.exception))
        self.assertFalse(self.host.path(POLICY).exists())
        self.assert_no_install()

    def test_private_signed_debian_cache_without_forcing_root_acquisition(self):
        self.packages()
        updates = [c.argv for c in self.host.calls if c.argv[0] == "apt-get" and "update" in c.argv]
        self.assertEqual(len(updates), 2)
        self.assertIn("--error-on=any", updates[0])
        self.assertIn("Dir::State::lists=" + APT_LISTS, updates[1])
        self.assertEqual(self.host.path(STATE + "/debian.sources").read_bytes(), SOURCES)
        self.assertIn(b"Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg", SOURCES)
        self.assertNotIn("APT::Sandbox::User=root", updates[1])
        self.assertEqual(stat.S_IMODE(self.host.path(APT_LISTS).stat().st_mode), 0o755)

    def test_restrictive_umask_keeps_apt_directory_traversable_and_state_private(self):
        old_mask = os.umask(0o077)
        try:
            self.packages()
        finally:
            os.umask(old_mask)
        self.assertEqual(stat.S_IMODE(self.host.path(APT_LISTS).stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.host.path("/var/lib/snellctl").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.host.path(STATE).stat().st_mode), 0o700)

    def test_plan_involving_removal_stops(self):
        self.prep.initialize()
        self.host.override = lambda c: Reply(0, "Remv ufw [0.36.2]\n") if "--simulate" in c.argv else None
        with self.assertRaises(PreparationError):
            self.prep.packages()
        self.assert_no_install()
        self.assertFalse(self.host.path(POLICY).exists())

    def test_package_intent_precedes_install_and_failure_retains_protection(self):
        self.prep.initialize()

        def fail(command):
            if command.argv[0] == "apt-get" and "install" in command.argv and "--simulate" not in command.argv:
                self.assertTrue(self.host.path(STATE + "/packages-intent.json").exists())
                self.assertTrue(self.host.path(POLICY).exists())
                return Reply(100)
        self.host.override = fail
        with self.assertRaises(PreparationError):
            self.prep.packages()
        before = len(self.host.calls)
        with self.assertRaises(PreparationError):
            self.prep.packages()
        self.assertEqual(before, len(self.host.calls))
        self.assertFalse(self.host.path(STATE + "/packages-ready.json").exists())
        self.assertTrue(self.host.path(POLICY).exists())

    def test_mask_already_active_not_assumed_safe(self):
        self.prep.initialize()

        def active(c):
            if c.argv[:2] == ("systemctl", "show"):
                return Reply(0, "LoadState=masked\nActiveState=active\n")
        self.host.override = active
        with self.assertRaises(PreparationError):
            self.prep.packages()
        self.assert_no_install()

    def test_repeated_packages_only_check_no_second_install(self):
        self.packages()
        before = len(self.host.calls)
        self.assertEqual(self.prep.packages(), "already-prepared")
        self.assertFalse(any(c.argv[0] == "apt-get" for c in self.host.calls[before:]))

    def test_external_policy_replacement_or_modification_blocks(self):
        self.packages()
        self.host.path(POLICY).write_bytes(b"changed")
        with self.assertRaises(PreparationError):
            self.prep.packages()
        self.assertEqual(self.host.path(POLICY).read_bytes(), b"changed")

    def test_symlinked_state_is_not_followed(self):
        self.prep.initialize()
        owner = self.host.path(STATE + "/owner.json")
        owner.rename(owner.with_name("elsewhere"))
        owner.symlink_to("elsewhere")
        with self.assertRaises(OSError):
            self.prep.packages()
        self.assert_no_install()

    def test_lock_conflict_stops_commands(self):
        self.prep.initialize()
        before = len(self.host.calls)
        with self.prep._lock(), Preparation(self.root, self.host) as second:
            with self.assertRaises(PreparationError):
                second.packages()
        self.assertEqual(before, len(self.host.calls))

    def test_credentials_private_not_in_records_commands_or_return_value(self):
        self.credentials()
        path = self.host.path(CREDENTIAL)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        for record in self.host.path(STATE).glob("*.json"):
            self.assertNotIn(TOKEN, record.read_text())
        self.assertNotIn(TOKEN, repr(self.host.calls))
        with self.assertRaises(PreparationError):
            self.prep.credential("another_fake_token_for_testing_123456")
        self.assertIn(TOKEN, path.read_text())

    def test_credential_injection_rejected_without_file_write(self):
        for token in ("", "short", "x" * 257, TOKEN + "\nserver = bad", TOKEN + " "):
            with self.subTest(token_length=len(token)), self.assertRaises(PreparationError):
                self.prep.credential(token)
        self.assertFalse(self.host.path(CREDENTIAL).exists())

    def test_explicit_consent_and_test_required(self):
        self.credentials()
        for kwargs in ({"production": False, "agree_tos": False}, {"production": True, "agree_tos": True},
                       {"production": True, "agree_tos": True, "confirm_issue": True}):
            with self.assertRaises(PreparationError):
                self.prep.certificate(DOMAIN, **kwargs)
        self.assertFalse(any(c.argv[0] == "certbot" for c in self.host.calls))

    def test_production_mode_cannot_be_truthy_text(self):
        with self.assertRaises(PreparationError):
            self.prep.certificate(DOMAIN, production="false", agree_tos=True, confirm_issue=True)
        self.assertEqual(self.host.calls, [])

    def test_staging_command_does_not_use_nginx_installer_or_expose_token(self):
        self.tested()
        command = next(c for c in self.host.calls if c.argv[0] == "certbot")
        self.assertIn(STAGING, command.argv)
        self.assertIn("--dry-run", command.argv)
        self.assertIn("certonly", command.argv)
        self.assertNotIn("--nginx", command.argv)
        self.assertNotIn("--force-renewal", command.argv)
        self.assertIn("--no-directory-hooks", command.argv)
        self.assertEqual(dict(command.env)["HOME"], STATE + "/home")
        self.assertNotIn(TOKEN, repr(command))
        self.assertFalse(self.host.path("/etc/letsencrypt/live/" + DOMAIN).exists())

    def test_global_hook_stops_before_certbot(self):
        self.credentials()
        self.host.write("/etc/letsencrypt/cli.ini", b"deploy-hook = echo SECRET\n")
        with self.assertRaises(PreparationError) as raised:
            self.prep.certificate(DOMAIN, production=False, agree_tos=True)
        self.assertNotIn("SECRET", str(raised.exception))
        self.assertFalse(any(c.argv[0] == "certbot" for c in self.host.calls))

    def test_isolated_home_cannot_contain_other_cf_credentials(self):
        self.credentials()
        self.host.write(STATE + "/home/.cloudflare.cfg", b"SECRET")
        with self.assertRaises(PreparationError):
            self.prep.certificate(DOMAIN, production=False, agree_tos=True)

    def test_credential_permissions_or_format_change_blocks(self):
        self.credentials()
        self.host.path(CREDENTIAL).chmod(0o644)
        with self.assertRaises(PreparationError):
            self.prep.certificate(DOMAIN, production=False, agree_tos=True)
        self.host.write(CREDENTIAL, b"dns_cloudflare_api_key = SECRET\n")
        with self.assertRaises(PreparationError):
            self.prep.certificate(DOMAIN, production=False, agree_tos=True)

    def test_production_requires_same_tested_domain(self):
        self.tested()
        with self.assertRaises(PreparationError):
            self.prep.certificate("other.example.net", production=True, agree_tos=True, confirm_issue=True)
        self.assertFalse(any(c.argv[0] == "certbot" and "--dry-run" not in c.argv for c in self.host.calls))

    def test_certbot_failure_or_timeout_is_not_retried(self):
        self.tested()
        self.host.override = lambda c: Reply(1, TOKEN, uncertain=True) if c.argv[0] == "certbot" else None
        with self.assertRaises(PreparationError) as raised:
            self.prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True)
        self.assertNotIn(TOKEN, str(raised.exception))
        before = sum(c.argv[0] == "certbot" for c in self.host.calls)
        with self.assertRaises(PreparationError):
            self.prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True)
        self.assertEqual(sum(c.argv[0] == "certbot" for c in self.host.calls), before)
        self.assertFalse(self.host.path(STATE + "/certificate-ready.json").exists())

    def test_certificate_success_output_without_files_not_accepted(self):
        self.tested()
        self.host.override = lambda c: Reply(0, "Congratulations!") if c.argv[0] == "certbot" else None
        with self.assertRaises((OSError, PreparationError)):
            self.prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True)
        self.assertFalse(self.host.path(STATE + "/certificate-ready.json").exists())

    def test_existing_lineage_is_not_adopted(self):
        self.tested()
        self.host.certificate()
        before = len(self.host.calls)
        with self.assertRaises(PreparationError):
            self.prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True)
        self.assertFalse(any(c.argv[0] == "certbot" for c in self.host.calls[before:]))

    def test_certificate_chain_hostname_and_key_checks_are_mandatory(self):
        self.issued()
        calls = [c.argv for c in self.host.calls if c.argv[0] == "openssl"]
        self.assertTrue(any("-checkend" in c and "604800" in c for c in calls))
        self.assertTrue(any("-verify_hostname" in c and DOMAIN in c and "-purpose" in c for c in calls))
        self.assertTrue(any(c[1] == "pkey" and "-pubout" in c for c in calls))

    def test_verification_failure_cannot_publish_ready_record(self):
        self.tested()
        self.host.override = lambda c: Reply(1, "untrusted chain") if c.argv[:2] == ("openssl", "verify") else None
        with self.assertRaises(PreparationError):
            self.prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True)
        self.assertFalse(self.host.path(STATE + "/certificate-ready.json").exists())

    def test_key_mismatch_not_accepted(self):
        self.tested()
        self.host.override = lambda c: Reply(0, PUBLIC_KEY + "different") if c.argv[:2] == ("openssl", "pkey") else None
        with self.assertRaises(PreparationError):
            self.prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True)

    def test_repeated_issue_checks_existing_cert_without_reissuing(self):
        self.issued()
        before = len(self.host.calls)
        self.assertEqual(self.prep.certificate(DOMAIN, production=True, agree_tos=True, confirm_issue=True), "already-completed")
        self.assertFalse(any(c.argv[0] == "certbot" for c in self.host.calls[before:]))

    def test_lineage_escape_and_fullchain_drift_rejected(self):
        self.issued()
        link = self.host.path("/etc/letsencrypt/live/" + DOMAIN + "/privkey.pem")
        link.unlink()
        link.symlink_to("/etc/shadow")
        with self.assertRaises(PreparationError):
            self.prep._verify_certificate(NodeSpec(DOMAIN))
        link.unlink()
        link.symlink_to("../../archive/" + DOMAIN + "/privkey1.pem")
        self.host.write("/etc/letsencrypt/archive/" + DOMAIN + "/fullchain1.pem", b"different")
        with self.assertRaises(PreparationError):
            self.prep._verify_certificate(NodeSpec(DOMAIN))

    def test_renewal_config_hooks_rejected(self):
        self.issued()
        path = self.host.path("/etc/letsencrypt/renewal/" + DOMAIN + ".conf")
        path.write_bytes(path.read_bytes() + b"deploy_hook = dangerous\n")
        with self.assertRaises(PreparationError):
            self.prep._verify_certificate(NodeSpec(DOMAIN))

    def test_policy_script_syntax_and_scoped_effect_using_real_shell(self):
        self.packages()
        script = self.host.path(POLICY)
        syntax = subprocess.run(["/bin/sh", "-n", str(script)], capture_output=True, timeout=5)
        self.assertEqual(syntax.returncode, 0)
        for arguments, expected in [(["nginx", "start"], 101), (["--quiet", "nginx", "restart"], 101),
                                    (["certbot.service", "start"], 101), (["ssh", "restart"], 0), (["cron", "start"], 0)]:
            result = subprocess.run(["/bin/sh", str(script), *arguments], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, expected)
            self.assertEqual(result.stdout + result.stderr, b"")

    def test_response_repr_hides_external_output(self):
        self.assertNotIn(TOKEN, repr(Reply(1, TOKEN)))

    def test_state_contains_no_duplicate_private_key_or_token(self):
        self.issued()
        for path in self.host.path(STATE).glob("*.json"):
            value = path.read_bytes()
            self.assertNotIn(TOKEN.encode(), value)
            self.assertNotIn(b"TEST-PRIVATE-KEY", value)
        self.assertEqual(json.loads(self.host.path(STATE + "/certificate-ready.json").read_bytes()), {"domain_sha256": hashlib.sha256(DOMAIN.encode()).hexdigest()})

    def test_status_reports_records_not_deployment_or_renewal_success(self):
        self.issued()
        report = self.prep.status()
        self.assertFalse(report["deploy_ready"])
        self.assertFalse(report["renewal_enabled_by_this_engine"])
        self.assertEqual(report["phases"]["certificate"], "completion-recorded")
        self.assertNotIn(TOKEN, json.dumps(report))
        self.assertNotIn(DOMAIN, json.dumps(report))

    def test_failed_protection_requires_inspection_even_without_package_intent(self):
        self.prep.initialize()
        self.prep._record("guards-intent", {"format": 1})
        report = self.prep.status()
        self.assertEqual(report["phases"]["guards"], "needs-inspection")
        self.assertEqual(report["phases"]["packages"], "needs-inspection")

    def test_relaxed_state_permissions_are_rejected(self):
        self.prep.initialize()
        self.host.path(STATE).chmod(0o755)
        with self.assertRaises(PreparationError):
            self.prep.packages()
        self.assert_no_install()
