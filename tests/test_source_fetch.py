from contextlib import nullcontext, redirect_stderr, redirect_stdout
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from snellctl import artifacts
from tools import source_fetch as f


COMMIT = "1" * 40
ROOT = "harbor-kit-" + COMMIT
FILES = {"README.md": b"# Test\n", "tools/public_source.py": b"raise RuntimeError('must not execute')\n",
         "snellctl/__main__.py": b"raise RuntimeError('must not execute')\n"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(files):
    rows = [{"path": name, "bytes": len(data), "sha256": digest(data)} for name, data in sorted(files.items())]
    return digest(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())


def pack(files=None, extras=(), edit=None):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT,
                      pax_headers={"comment": COMMIT}) as tar:
        directory = tarfile.TarInfo(ROOT)
        directory.type, directory.mode = tarfile.DIRTYPE, 0o775
        tar.addfile(directory)
        for name, data in (FILES if files is None else files).items():
            entry = tarfile.TarInfo(ROOT + "/" + name)
            entry.size, entry.mode = len(data), 0o664
            if edit:
                edit(entry)
            tar.addfile(entry, io.BytesIO(data))
        for entry, data in extras:
            tar.addfile(entry, io.BytesIO(data))
    return gzip.compress(out.getvalue(), mtime=0)


class SourceFetchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.output = self.base / "stage"
        self.data = pack()

    def fetch(self, data=None, **kwargs):
        data = self.data if data is None else data
        return f.fetch(self.output, COMMIT, digest(data), snapshot(FILES),
                       downloader=lambda artifact: data, **kwargs)

    def reject(self, data, **limits):
        with (patch.multiple(f, **limits) if limits else nullcontext()), \
             self.assertRaises((f.FetchError, ValueError, tarfile.TarError, OSError, EOFError)):
            f.verify(data, COMMIT, digest(data), snapshot(FILES))

    def test_stages_exact_source_with_private_modes_and_receipt_last(self):
        original = f._write
        names = []
        def track(fd, name, data):
            names.append(name)
            original(fd, name, data)
        with patch.object(f, "_write", side_effect=track), patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError):
            report = self.fetch()
        self.assertEqual(names[-1], "receipt.json")
        self.assertEqual(report["result"], "verified-source-staged")
        self.assertFalse(report["downloaded_code_executed"])
        self.assertFalse(report["installation_attempted"])
        self.assertFalse(report["signed"])
        self.assertFalse(report["tests_run"])
        self.assertEqual(json.loads((self.output / "receipt.json").read_bytes()), report)
        self.assertEqual((self.output / "source.tar.gz").read_bytes(), self.data)
        actual = {p.relative_to(self.output / "source").as_posix(): p.read_bytes()
                  for p in (self.output / "source").rglob("*") if p.is_file()}
        self.assertEqual(actual, FILES)
        for p in (self.output, *self.output.rglob("*")):
            self.assertEqual(p.stat().st_mode & 0o777, 0o700 if p.is_dir() else 0o600)

    def test_pins_are_required_lowercase_full_and_fixed_repository(self):
        item = f.pins(COMMIT, digest(self.data), snapshot(FILES))
        self.assertEqual(item.url, "https://codeload.github.com/Shennai1/harbor-kit/tar.gz/" + COMMIT)
        self.assertEqual(item.redirect_hosts, ("codeload.github.com",))
        self.assertEqual(item.max_download, f.ARCHIVE_LIMIT)
        for value in ("main", "latest", "1" * 39, "A" * 40, COMMIT + "\n", "https://example.net"):
            with self.subTest(value=value), patch.object(f, "_new_directory") as new:
                with self.assertRaises(f.FetchError):
                    f.fetch(self.output, value, digest(self.data), snapshot(FILES))
                new.assert_not_called()
        for a, s in (("x" * 64, snapshot(FILES)), (digest(self.data), "0" * 63)):
            with self.assertRaises(f.FetchError):
                f.pins(COMMIT, a, s)

    def test_wrong_archive_hash_prevents_decompression(self):
        with patch.object(gzip, "GzipFile", side_effect=AssertionError):
            with self.assertRaises(f.FetchError):
                f.verify(self.data, COMMIT, "0" * 64, snapshot(FILES))

    def test_wrong_snapshot_leaves_only_empty_stage(self):
        with self.assertRaises(f.FetchError):
            f.fetch(self.output, COMMIT, digest(self.data), "0" * 64, downloader=lambda _: self.data)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_corrupt_truncated_or_non_gzip_archive_is_rejected(self):
        for data in (b"not gzip", self.data[:-8], self.data[:-1] + b"x", gzip.compress(b"bad tar")):
            with self.subTest(size=len(data)):
                self.reject(data)

    def test_archive_expanded_file_total_and_entry_limits(self):
        for limits in ({"ARCHIVE_LIMIT": 10}, {"TAR_LIMIT": 20}, {"FILE_LIMIT": 4},
                       {"TOTAL_LIMIT": 10}, {"ENTRY_LIMIT": 2}):
            self.reject(self.data, **limits)

    def test_paths_are_canonical_and_cannot_escape(self):
        for name in ("../escape", "/absolute", "a//b", "a/./b", "a/../b", "a\\b", "x\nname",
                     ".git/config", "x/" + "a" * 241, "other-root/file"):
            def edit(entry):
                if entry.name.endswith("README.md"):
                    entry.name = name if name.startswith(("/", "other-root")) else ROOT + "/" + name
            with self.subTest(name=name):
                self.reject(pack(edit=edit))

    def test_symlinks_hardlinks_devices_fifo_and_sparse_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE,
                     tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE):
            entry = tarfile.TarInfo(ROOT + "/bad")
            entry.type, entry.linkname = kind, "target" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
            with self.subTest(kind=kind):
                self.reject(pack(extras=[(entry, b"")]))

    def test_duplicate_case_alias_and_file_directory_conflicts(self):
        for name, kind in (("README.md", tarfile.REGTYPE), ("readme.md", tarfile.REGTYPE),
                           ("tools", tarfile.REGTYPE), ("README.md", tarfile.DIRTYPE),
                           ("TOOLS/extra.py", tarfile.REGTYPE)):
            entry = tarfile.TarInfo(ROOT + "/" + name)
            entry.type = kind
            self.reject(pack(extras=[(entry, b"")]))

    def test_unknown_metadata_executable_and_special_modes_rejected(self):
        for mode in (0o755, 0o4644, 0o2644):
            self.reject(pack(edit=lambda entry: setattr(entry, "mode", mode)))
        for header in ({"path": ROOT + "/README.md"}, {"comment": "2" * 40}, {"GNU.sparse.size": "9"}):
            self.reject(pack(edit=lambda entry: setattr(entry, "pax_headers", header)))

    def test_empty_missing_required_binary_or_extra_files_rejected(self):
        for files in ({}, {"README.md": b"x"}, {**FILES, "bad": b"\xff"},
                      {**FILES, "bad": b"\x00"}, {**FILES, "extra": b"unexpected"}):
            self.reject(pack(files))

    def test_unreferenced_directory_is_rejected(self):
        directory = tarfile.TarInfo(ROOT + "/empty")
        directory.type = tarfile.DIRTYPE
        self.reject(pack(extras=[(directory, b"")]))

    def test_existing_destinations_and_parent_links_rejected_before_download(self):
        downloader = Mock()
        real = self.base / "real"
        real.mkdir()
        cases = [self.base / name for name in ("file", "directory", "link", "dangling")]
        cases[0].write_text("keep")
        cases[1].mkdir()
        cases[2].symlink_to(real)
        cases[3].symlink_to(self.base / "missing")
        for target in [*cases, cases[2] / "new", Path("relative"), self.base / ".." / "new"]:
            with self.subTest(target=target), self.assertRaises((OSError, artifacts.ArtifactError)):
                f.fetch(target, COMMIT, digest(self.data), snapshot(FILES), downloader=downloader)
        downloader.assert_not_called()
        self.assertEqual(cases[0].read_text(), "keep")
        self.assertEqual(list(real.iterdir()), [])

    def test_network_failure_and_interrupt_leave_no_completion(self):
        for index, error in enumerate((artifacts.ArtifactError("network"), KeyboardInterrupt())):
            target = self.base / str(index)
            with self.assertRaises(type(error)):
                f.fetch(target, COMMIT, digest(self.data), snapshot(FILES), downloader=Mock(side_effect=error))
            self.assertEqual(list(target.iterdir()), [])

    def test_mid_write_failure_and_interrupt_keep_partial_source_without_receipt(self):
        original = f._write
        for index, error in enumerate((OSError("disk full"), KeyboardInterrupt())):
            self.output = self.base / str(index)
            def fail(fd, name, data):
                if name == "__main__.py":
                    raise error
                original(fd, name, data)
            with patch.object(f, "_write", side_effect=fail), self.assertRaises(type(error)):
                self.fetch()
            self.assertTrue((self.output / "source.tar.gz").is_file())
            self.assertTrue((self.output / "source/README.md").is_file())
            self.assertFalse((self.output / "receipt.json").exists())

    def test_injected_directory_symlink_cannot_write_outside_stage(self):
        external = self.base / "external"
        external.mkdir()
        original = f._write
        def inject(fd, name, data):
            original(fd, name, data)
            if name == "source.tar.gz":
                os.symlink(str(external), "source", dir_fd=fd)
        with patch.object(f, "_write", side_effect=inject), self.assertRaises(OSError):
            self.fetch()
        self.assertEqual(list(external.iterdir()), [])
        self.assertFalse((self.output / "receipt.json").exists())

    def test_restrictive_umask_refuses_instead_of_claiming_completion(self):
        previous = os.umask(0o777)
        try:
            with self.assertRaises((OSError, artifacts.ArtifactError)):
                self.fetch()
        finally:
            os.umask(previous)
            if self.output.exists():
                self.output.chmod(0o700)
        self.assertFalse((self.output / "receipt.json").exists())

    def test_cli_success_failure_interruption_and_missing_pins(self):
        args = ["--commit", COMMIT, "--archive-sha256", digest(self.data),
                "--snapshot-sha256", snapshot(FILES), "--output", str(self.output)]
        with patch.object(f, "download", return_value=self.data), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(f.main(args), 0)
        self.assertEqual(json.loads(out.getvalue())["result"], "verified-source-staged")
        for error, code in ((OSError("PRIVATE"), 1), (KeyboardInterrupt(), 130)):
            with patch.object(f, "fetch", side_effect=error), redirect_stderr(io.StringIO()) as err, redirect_stdout(io.StringIO()) as out:
                self.assertEqual(f.main(args), code)
                self.assertEqual(out.getvalue(), "")
                self.assertNotIn("PRIVATE", err.getvalue())
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            f.main(["--output", str(self.output)])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
