from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import public_source


class PublicSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "README.md"
        self.source.write_text("# Test public source\n", encoding="utf-8")
        scope = patch.object(public_source, "PUBLIC_FILES", ("README.md",))
        scope.start()
        self.addCleanup(scope.stop)

    def test_unknown_and_private_files_are_not_read_or_exported(self):
        (self.root / "private-note.txt").write_bytes(b"private\xff")
        report = public_source.collect(self.root)
        self.assertEqual([e["path"] for e in report["tree_elements"]], ["README.md"])
        self.assertNotIn("private", json.dumps(report))

    def test_snapshot_is_stable_and_changes_with_source(self):
        first = public_source.collect(self.root)
        self.assertEqual(first, public_source.collect(self.root))
        self.source.write_text("changed\n", encoding="utf-8")
        self.assertNotEqual(first["snapshot_sha256"], public_source.collect(self.root)["snapshot_sha256"])

    def test_symlink_and_parent_symlink_are_rejected(self):
        self.source.unlink()
        self.source.symlink_to("elsewhere")
        with self.assertRaises(public_source.ExportError):
            public_source.collect(self.root)
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        with patch.object(public_source, "PUBLIC_FILES", ("link/README.md",)), self.assertRaises(public_source.ExportError):
            public_source.collect(self.root)

    def test_missing_hardlinked_and_nonregular_files_are_rejected(self):
        os.link(self.source, self.root / "linked")
        with self.assertRaises(public_source.ExportError):
            public_source.collect(self.root)
        self.source.unlink()
        with self.assertRaises(public_source.ExportError):
            public_source.collect(self.root)
        os.mkfifo(self.source)
        with self.assertRaises(public_source.ExportError):
            public_source.collect(self.root)

    def test_size_limits_and_encoding_are_enforced(self):
        with patch.object(public_source, "FILE_LIMIT", 5), self.assertRaises(public_source.ExportError):
            public_source.collect(self.root)
        with patch.object(public_source, "TOTAL_LIMIT", 5), self.assertRaises(public_source.ExportError):
            public_source.collect(self.root)
        for data in (b"bad\xff", b"bad\x00"):
            self.source.write_bytes(data)
            with self.assertRaises(public_source.ExportError):
                public_source.collect(self.root)

    def test_secret_patterns_refuse_without_echoing_values(self):
        samples = ("gh" + "p_" + "Q" * 30, "cf" + "ut_" + "W" * 30,
                   "-----BEGIN " + "PRIVATE KEY-----", "/Users/" + "private-user/project/")
        for sample in samples:
            with self.subTest(kind=sample[:2]):
                self.source.write_text(sample, encoding="utf-8")
                with self.assertRaises(public_source.ExportError) as result:
                    public_source.collect(self.root)
                self.assertNotIn(sample, str(result.exception))

    def test_duplicate_allowlist_is_rejected(self):
        with patch.object(public_source, "PUBLIC_FILES", ("README.md", "README.md")), self.assertRaises(public_source.ExportError):
            public_source.collect(self.root)

    def test_default_cli_emits_fingerprints_not_content(self):
        report = public_source.collect(self.root)
        with patch.object(public_source, "collect", return_value=report), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(public_source.main([]), 0)
        result = json.loads(output.getvalue())
        self.assertIn("files", result)
        self.assertNotIn("tree_elements", result)
        self.assertNotIn("Test public source", output.getvalue())

    def test_tree_export_is_bounded_and_failure_does_not_emit_partial_source(self):
        report = public_source.collect(self.root)
        with patch.object(public_source, "collect", return_value=report), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(public_source.main(["--tree", "--offset", "1", "--limit", "1"]), 0)
        self.assertEqual(json.loads(output.getvalue())["tree_elements"], [])
        with patch.object(public_source, "collect", side_effect=public_source.ExportError("review required")), \
             redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()):
            self.assertEqual(public_source.main([]), 1)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
