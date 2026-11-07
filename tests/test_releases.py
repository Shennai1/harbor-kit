from contextlib import redirect_stdout, redirect_stderr
from dataclasses import FrozenInstanceError
import hashlib
import io
import json
import unittest
from unittest.mock import patch

from snellctl import artifacts, releases
from snellctl.__main__ import main
from snellctl.activation import _binding, BINARIES
from snellctl.client import ClientData
from snellctl.deployment import NodeSecrets, NodeSpec, preview, render_files
from snellctl.hostcommands import DebianCommands, PROGRAMS
from snellctl.hostprep import Command, PreparationError


class ReleaseTests(unittest.TestCase):
    def test_single_source_preserves_artifact_imports(self):
        self.assertIs(artifacts.Artifact, releases.Artifact)
        self.assertIs(artifacts.CATALOG, releases.CATALOG)
        self.assertEqual(tuple(p.artifact for p in releases.BASELINES), releases.CATALOG)
        self.assertEqual(tuple(p.binary_path for p in releases.BASELINES), BINARIES)

    def test_program_and_wire_protocol_versions_are_distinct(self):
        snell, shadow = releases.BASELINES
        self.assertEqual((snell.artifact.version, snell.protocol), ("5.0.1", 5))
        self.assertEqual((shadow.artifact.version, shadow.protocol), ("0.2.25", 3))
        self.assertEqual(preview(NodeSpec("edge.example.net"))["versions"]["shadowtls_protocol"], 3)

    def test_registry_is_immutable(self):
        with self.assertRaises(FrozenInstanceError):
            releases.BASELINES[0].protocol = 6
        with self.assertRaises(FrozenInstanceError):
            releases.CATALOG[0].version = "6.0.0"

    def test_lookup_rejects_unknown_names_and_does_not_echo(self):
        for name in ("latest", "Snell", "nginx", "../private-input", "shadowtls", [], None):
            with self.subTest(name=name), self.assertRaises(ValueError) as error:
                releases.baseline(name)
            self.assertNotIn(str(name), str(error.exception))

    def test_ambiguous_catalog_rejected(self):
        with patch.object(releases, "BASELINES", releases.BASELINES * 2):
            with self.assertRaises(ValueError):
                releases.baseline("snell")

    def test_snell_timestamped_version_output(self):
        p = releases.baseline("snell")
        self.assertTrue(p.matches_version_output("2026-01-01 12:00:00.000 [server_main] <NOTIFY> snell-server v5.0.1 (test)\n"))
        self.assertTrue(p.matches_version_output("snell-server v5.0.1\n"))

    def test_shadow_version_output(self):
        p = releases.baseline("shadow-tls")
        self.assertTrue(p.matches_version_output("shadow-tls 0.2.25\n"))
        self.assertTrue(p.matches_version_output("shadow-tls 0.2.25"))

    def test_version_prefix_substring_suffix_and_duplicates_rejected(self):
        for p in releases.BASELINES:
            good = p.version_prefix + p.artifact.version
            for output in ("", p.artifact.version, "foreign-" + good, good + "0\n", good + "-rc1\n",
                           good + "+local\n", good + ";\n", good + "\n" + good,
                           good + "\n" + p.version_prefix + "999.0.0\n", good + "\x00", None, b"text"):
                with self.subTest(component=p.artifact.name, output=output):
                    self.assertFalse(p.matches_version_output(output))

    def test_oversized_version_output_rejected(self):
        p = releases.baseline("snell")
        self.assertFalse(p.matches_version_output("x" * 65536 + p.version_prefix + p.artifact.version))

    def test_adapter_scope_is_still_exact_version_commands(self):
        runner = object.__new__(DebianCommands)
        for p in releases.BASELINES:
            self.assertIn((p.binary_path, "--version"), releases.VERSION_COMMANDS)
            self.assertEqual(PROGRAMS[p.binary_path], p.binary_path)
            for args in ((p.binary_path, "server"), (p.binary_path, "--version", "extra"),
                         (p.binary_path.replace(p.artifact.version, "999.0.0"), "--version")):
                with self.subTest(args=args), self.assertRaises(PreparationError), \
                     patch("snellctl.hostcommands.subprocess.Popen", side_effect=AssertionError("no process")):
                    runner(Command(args))


class ComparisonTests(unittest.TestCase):
    def check(self, component, current, target, decision):
        result = releases.compare_versions(component, current, target)
        self.assertEqual(result["decision"], decision)
        for field in ("host_checked", "upstream_checked", "host_changes_attempted", "download_attempted",
                      "update_implemented", "update_authorized", "update_ready"):
            self.assertIs(result[field], False)
        self.assertEqual(result["security_patch_status"], "not-assessed")
        self.assertFalse({"url", "path", "sha256", "commands", "binary"} & result.keys())
        return result

    def test_same_reviewed_versions_do_nothing(self):
        for p in releases.BASELINES:
            self.check(p.artifact.name, p.artifact.version, p.artifact.version, "same-reviewed-version-no-action")

    def test_snell_major_upgrade_requires_separate_migration(self):
        self.check("snell", "5.0.1", "6.0.0", "protocol-migration-required")

    def test_unknown_patch_is_not_automatically_accepted(self):
        self.check("snell", "5.0.1", "5.0.2", "target-version-not-reviewed")
        self.check("shadow-tls", "0.2.25", "0.2.26", "target-version-not-reviewed")

    def test_unknown_shadow_release_does_not_infer_wire_protocol(self):
        result = self.check("shadow-tls", "0.2.25", "3.0.0", "target-version-not-reviewed")
        self.assertEqual(result["managed_protocol"], 3)

    def test_numeric_comparison_not_lexical(self):
        self.check("snell", "5.0.1", "5.0.10", "target-version-not-reviewed")
        self.check("shadow-tls", "0.2.25", "0.2.9", "downgrade-not-supported")

    def test_downgrade_is_not_recovery_authorization(self):
        self.check("snell", "5.0.1", "5.0.0", "downgrade-not-supported")
        self.check("snell", "5.0.1", "4.1.1", "downgrade-not-supported")

    def test_unknown_current_version_never_claims_no_action(self):
        self.check("snell", "6.0.0", "6.0.0", "current-version-not-reviewed")
        self.check("snell", "5.0.2", "5.0.1", "current-version-not-reviewed")

    def test_only_canonical_versions_without_paths_urls_or_aliases(self):
        bad = ("latest", "v5.0.1", "5.0", "5.0.1-rc1", "5.0.1+local", "05.0.1", "5.00.1", "5.0.01",
               "5.0.1\n", " 5.0.1", "5.0.1 ", "5.0.1/../private", "https://private.invalid", "5.0.1000",
               "５.０.１", "-5.0.1", "5.0.1\x00", "5.0.1\x1b[2J", "", 5, None, [], {})
        for value in bad:
            for field in ("current", "target"):
                values = {"component": "snell", "current": "5.0.1", "target": "5.0.1", field: value}
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    releases.compare_versions(**values)

    def test_compare_performs_no_io(self):
        with patch("builtins.open", side_effect=AssertionError("no file")), \
             patch("os.open", side_effect=AssertionError("no file")), \
             patch("socket.socket", side_effect=AssertionError("no network")), \
             patch("subprocess.Popen", side_effect=AssertionError("no process")):
            self.check("snell", "5.0.1", "6.0.0", "protocol-migration-required")


class ComparisonCliTests(unittest.TestCase):
    def run_cli(self, args):
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            code = main(["artifacts", "compare", *args])
        return code, out.getvalue(), err.getvalue()

    def test_cli_same_version_is_offline_noninteractive(self):
        with patch("builtins.input", side_effect=AssertionError("no prompt")), \
             patch("snellctl.artifacts.fetch", side_effect=AssertionError("no download")):
            code, output, error = self.run_cli(["--component", "snell", "--current", "5.0.1", "--target", "5.0.1"])
        self.assertEqual(code, 0)
        self.assertEqual(error, "")
        self.assertFalse(json.loads(output)["host_checked"])

    def test_cli_rejected_selection_does_not_download(self):
        with patch("snellctl.artifacts.download", side_effect=AssertionError("no download")):
            code, output, _ = self.run_cli(["--component", "snell", "--current", "5.0.1", "--target", "6.0.0"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output)["decision"], "protocol-migration-required")

    def test_cli_invalid_value_redacted(self):
        for args in (["--component", "PRIVATE", "--current", "5.0.1", "--target", "5.0.1"],
                     ["--component", "snell", "--current", "PRIVATE", "--target", "5.0.1"],
                     ["--component", "snell", "--current", "5.0.1", "--target", "PRIVATE"]):
            code, output, error = self.run_cli(args)
            self.assertEqual(code, 2)
            self.assertNotIn("PRIVATE", output + error)

    def test_cli_missing_or_extra_arguments_redacted(self):
        for args in ([], ["--output", "PRIVATE"], ["--yes", "PRIVATE"]):
            with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                with self.assertRaises(SystemExit) as raised:
                    main(["artifacts", "compare", *args])
            self.assertEqual(raised.exception.code, 2)
            self.assertNotIn("PRIVATE", out.getvalue() + err.getvalue())


class PublishedBaselineCompatibilityTests(unittest.TestCase):
    """Hashes captured before the registry change using synthetic example data."""

    def test_existing_templates_and_record_binding_remain_byte_identical(self):
        keys = NodeSecrets("a" * 64, "b" * 64)
        cases = (
            (NodeSpec("edge.example.net"), "7c6e3493a495b41ff7e580abfcb0f7446b1accb881a3a74ba2a64ebdf292b78d",
             ("36a778c5a2341438c744289833fb1d1a97b1757baee5c35bebefe6ba91252522",
              "319cfc9cf8019be772307be7959152c1c5fdff391b90dca9f43d07787d60c0ef")),
            (NodeSpec("other.example.org", public_port=24443, snell_port=32001, tls_port=32443),
             "5257b9061653629d62ca4af8706ddf4b311d13df4c2a63aaabb6795618417910",
             ("dac182823b8ec1f8ad5d70d5bdbdf2a2d4f9d10ac2a2fe7b149af1c7ebeb7870",
              "3848cf369a7f134068fdd15ba423364f139cf669892ad714afeed73566ebb8db")),
            (NodeSpec("old.example.net", nginx_version="1.22.1"),
             "1fdd293577e44e76f355ad3c96233b928083bd515bdf10f0ec3ce4bfd38a8f19",
             ("4d3f0d6f602f45195b93e8c59d9440393abda6a4e0f7eebe72629898324700d6",
              "0dda7ebfd0696190f7c085637ad9769dabe6d8853aaeac51d16ee09b761db7fb")),
        )
        for spec, binding, hashes in cases:
            self.assertEqual(_binding(spec), binding)
            for public, expected in zip((False, True), hashes, strict=True):
                with self.subTest(domain=spec.domain, public=public):
                    content = json.dumps([(f.target.path, f.target.mode, f.target.sensitive, f.content)
                                          for f in render_files(spec, keys, public_entry=public)],
                                         ensure_ascii=True, separators=(",", ":")).encode()
                    self.assertEqual(hashlib.sha256(content).hexdigest(), expected)

    def test_existing_catalog_and_command_allowlist_unchanged(self):
        for value, expected in (
            (artifacts.catalog_report(), "df44a15f05aa77657128d7d49e5d993e3f69e2679674510101031aaead4605b5"),
            (PROGRAMS, "c50754f7421b14de7e60eae80197ab422e194c8d445e2309d4f46009057c557a"),
        ):
            self.assertEqual(hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest(), expected)

    def test_existing_surge_export_unchanged(self):
        line = ClientData("edge.example.net", 443, NodeSecrets("a" * 64, "b" * 64)).surge_line("8.8.8.8")
        self.assertEqual(hashlib.sha256(line.encode()).hexdigest(),
                         "67be84c0b0a75f7568218e987236488c27b688de9eff34eb1663a33f3d6681ee")
