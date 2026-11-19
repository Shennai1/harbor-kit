from contextlib import redirect_stderr, redirect_stdout
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import public_source, source_bundle


class SourceBundleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "README.md").write_text("# Example\n", encoding="utf-8")
        (self.root / "src").mkdir()
        (self.root / "src/demo.py").write_text("VALUE = 1\n", encoding="utf-8")
        self.output = self.base / "bundle"
        scope = patch.object(public_source, "PUBLIC_FILES", ("src/demo.py", "README.md"))
        scope.start()
        self.addCleanup(scope.stop)

    def test_archive_manifest_checksums_and_metadata_match(self):
        result = source_bundle.build(self.root, self.output)
        manifest = json.loads((self.output / "manifest.json").read_bytes())
        self.assertEqual(result["result"], "built-not-published")
        self.assertEqual(result["public_files"], 2)
        self.assertFalse(manifest["signed"])
        self.assertFalse(manifest["tests_run_by_builder"])
        self.assertFalse(manifest["formal_release"])
        self.assertEqual(manifest["source_revision"], "not-verified")
        self.assertNotIn(str(self.root), json.dumps(manifest))
        archive = self.output / manifest["archive"]["name"]
        self.assertEqual(archive.stat().st_size, manifest["archive"]["bytes"])
        with tarfile.open(archive, "r:gz") as tar:
            self.assertEqual(tar.getnames(), ["harbor-kit-source/README.md", "harbor-kit-source/src/demo.py"])
            for member, record in zip(tar.getmembers(), manifest["files"]):
                self.assertTrue(member.isfile())
                self.assertEqual((member.uid, member.gid, member.mtime, member.mode), (0, 0, 0, 0o644))
                self.assertEqual((member.uname, member.gname), ("", ""))
                data = tar.extractfile(member).read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"])
                self.assertEqual(len(data), record["bytes"])
        for line in (self.output / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)

    def test_same_source_is_reproducible_despite_mtime_and_output_name(self):
        source_bundle.build(self.root, self.output)
        os.utime(self.root / "README.md", (123, 456))
        (self.root / "README.md").chmod(0o600)
        second = self.base / "another"
        source_bundle.build(self.root, second)
        for file in self.output.iterdir():
            self.assertEqual(file.read_bytes(), (second / file.name).read_bytes())

    def test_changed_content_changes_archive_and_snapshot(self):
        first = source_bundle.build(self.root, self.output)
        (self.root / "README.md").write_text("changed\n")
        second = source_bundle.build(self.root, self.base / "another")
        self.assertNotEqual(first["snapshot_sha256"], second["snapshot_sha256"])
        self.assertNotEqual(first["archive_sha256"], second["archive_sha256"])

    def test_unlisted_private_files_are_excluded(self):
        (self.root / "private.txt").write_bytes(b"PRIVATE-CONTENT\xff")
        source_bundle.build(self.root, self.output)
        for file in self.output.iterdir():
            data = gzip.decompress(file.read_bytes()) if file.suffix == ".gz" else file.read_bytes()
            self.assertNotIn(b"PRIVATE-CONTENT", data)
            self.assertNotIn(b"private.txt", data)

    def test_existing_directory_file_and_symlink_are_never_overwritten(self):
        original = self.base / "original"
        original.mkdir()
        for kind in ("directory", "file", "link", "dangling"):
            target = self.base / kind
            if kind == "directory":
                target.mkdir()
            elif kind == "file":
                target.write_text("keep")
            else:
                target.symlink_to(original if kind == "link" else self.base / "missing")
            with self.subTest(kind=kind), self.assertRaises(FileExistsError):
                source_bundle.build(self.root, target)
        self.assertEqual((self.base / "file").read_text(), "keep")
        self.assertEqual(list(original.iterdir()), [])

    def test_output_cannot_pollute_source_but_work_is_allowed(self):
        for target in (self.root, self.root / "new", self.root / "src/new"):
            with self.assertRaises(source_bundle.BundleError):
                source_bundle.build(self.root, target)
        (self.root / "work").mkdir()
        source_bundle.build(self.root, self.root / "work/bundle")

    def test_secret_or_symlink_source_rejected_before_output_creation(self):
        file = self.root / "README.md"
        file.write_text("gh" + "p_" + "x" * 30)
        with self.assertRaises(public_source.ExportError):
            source_bundle.build(self.root, self.output)
        self.assertFalse(self.output.exists())
        file.unlink()
        file.symlink_to(self.root / "src/demo.py")
        with self.assertRaises(public_source.ExportError):
            source_bundle.build(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_source_drift_leaves_archive_without_completion_manifest(self):
        before = public_source.collect(self.root)
        after = {**before, "snapshot_sha256": "0" * 64}
        with patch.object(source_bundle, "collect", side_effect=[before, after]):
            with self.assertRaises(source_bundle.BundleError):
                source_bundle.build(self.root, self.output)
        self.assertEqual(len(list(self.output.glob("*.tar.gz"))), 1)
        self.assertFalse((self.output / "manifest.json").exists())
        self.assertFalse((self.output / "SHA256SUMS").exists())

    def test_archive_path_escape_is_rejected_before_writes(self):
        for name in ("../escape", "/absolute", "src/../escape", "src\\escape", "src//demo.py"):
            report = public_source.collect(self.root)
            report["tree_elements"][0]["path"] = name
            with self.subTest(name=name), patch.object(source_bundle, "collect", return_value=report):
                with self.assertRaises(source_bundle.BundleError):
                    source_bundle.build(self.root, self.output)
            self.assertFalse(self.output.exists())

    def test_empty_public_scope_rejected_before_writes(self):
        with patch.object(public_source, "PUBLIC_FILES", ()):
            with self.assertRaises(source_bundle.BundleError):
                source_bundle.build(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_archive_write_failure_does_not_create_manifest_or_checksums(self):
        with patch.object(tarfile.TarFile, "addfile", side_effect=OSError("write failed")):
            with self.assertRaises(OSError):
                source_bundle.build(self.root, self.output)
        self.assertTrue(self.output.is_dir())
        self.assertFalse((self.output / "manifest.json").exists())
        self.assertFalse((self.output / "SHA256SUMS").exists())

    def test_cli_interruption_is_not_success(self):
        with patch.object(source_bundle, "build", side_effect=KeyboardInterrupt):
            with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()):
                self.assertEqual(source_bundle.main(["--output", str(self.output)]), 130)
            self.assertEqual(stdout.getvalue(), "")

    def test_cli_returns_summary_or_failure_without_source_contents(self):
        with patch.object(source_bundle, "build", return_value={"result": "built-not-published"}) as build:
            with redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(source_bundle.main(["--output", str(self.output)]), 0)
            self.assertEqual(json.loads(stdout.getvalue())["result"], "built-not-published")
            self.assertEqual(build.call_args.args[1], self.output)
        with patch.object(source_bundle, "build", side_effect=OSError("PRIVATE")):
            with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(source_bundle.main(["--output", str(self.output)]), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("PRIVATE", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
