import contextlib
from dataclasses import replace
import hashlib
import http.client
import io
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import zipfile

from snellctl import artifacts as a


def elf():
    data = bytearray(80)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 3, 62, 1)
    struct.pack_into("<H", data, 52, 64)
    return bytes(data)


def archive(entries=None):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, content in entries or [("snell-server", elf())]:
            zipped.writestr(name, content)
    return out.getvalue()


def pinned(artifact, content, **changes):
    return replace(artifact, sha256=hashlib.sha256(content).hexdigest(), **changes)


class FakeResponse(io.BytesIO):
    def __init__(self, data, *, status=200, headers=None, url=a.CATALOG[0].url):
        super().__init__(data)
        self.status = status
        self.headers = headers or {}
        self.url = url

    def geturl(self):
        return self.url


class ArtifactTests(unittest.TestCase):
    def test_catalog_matches_pinned_baseline(self):
        report = a.catalog_report()
        self.assertEqual([x["version"] for x in report["artifacts"]], ["5.0.1", "0.2.25"])
        self.assertIn("not-upstream-signature", report["checksum_basis"])
        for item in a.CATALOG:
            self.assertRegex(item.sha256, r"^[a-f0-9]{64}$")
            a._allowed_url(item.url, item.redirect_hosts)

    def test_verify_zip_and_raw(self):
        for item, data in zip(a.CATALOG, [archive(), elf()]):
            self.assertEqual(a.verify(pinned(item, data), data), elf())

    def test_hash_mismatch_stops_before_unzip(self):
        with patch.object(zipfile, "ZipFile", side_effect=AssertionError("must not unzip")):
            with self.assertRaises(a.ArtifactError):
                a.verify(a.CATALOG[0], b"untrusted response")

    def test_unsafe_or_extra_zip_entries(self):
        for entries in [
            [("../snell-server", elf())], [("/snell-server", elf())],
            [("sub/snell-server", elf())], [("snell-server/", b"")],
            [("snell-server", elf()), ("extra", elf())], [],
        ]:
            with self.subTest(entries=entries):
                if not entries:
                    content = b"not a zip"
                else:
                    content = archive(entries)
                with self.assertRaises(a.ArtifactError):
                    a.verify(pinned(a.CATALOG[0], content), content)

    def test_symlink_zip_entry(self):
        entry = zipfile.ZipInfo("snell-server")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        content = archive([(entry, elf())])
        with self.assertRaises(a.ArtifactError):
            a.verify(pinned(a.CATALOG[0], content), content)

    def test_oversized_download_and_payload(self):
        content = archive()
        for changes in [{"max_download": 1}, {"max_binary": 1}]:
            with self.assertRaises(a.ArtifactError):
                a.verify(pinned(a.CATALOG[0], content, **changes), content)

    def test_wrong_elf_architecture_class_endian_and_header(self):
        for offset, value in [(0, 0), (4, 1), (5, 2), (6, 0), (16, 1), (18, 183), (20, 0), (52, 0)]:
            content = bytearray(elf())
            content[offset] = value
            with self.subTest(offset=offset), self.assertRaises(a.ArtifactError):
                a.verify(pinned(a.CATALOG[1], content), content)
        with self.assertRaises(a.ArtifactError):
            a.verify(pinned(a.CATALOG[1], b"short"), b"short")

    def test_redirect_policy(self):
        hosts = a.CATALOG[1].redirect_hosts
        a._allowed_url("https://release-assets.githubusercontent.com/path?sig=secret", hosts)
        for url in [
            "http://github.com/file", "file:///etc/passwd", "https://github.com.evil.test/file",
            "https://evil.test/github.com", "https://user:pass@github.com/file",
            "https://github.com:444/file", "https://github.com/file#fragment",
            "https://github.com/file\n", "https://github.com:bad/file", "https://[::1]/file",
        ]:
            with self.subTest(url=url), self.assertRaises(a.ArtifactError):
                a._allowed_url(url, hosts)

    def test_redirect_checked_before_following(self):
        handler = a._Redirects(a.CATALOG[0].redirect_hosts)
        req = urllib.request.Request(a.CATALOG[0].url)
        with self.assertRaises(a.ArtifactError):
            handler.redirect_request(req, None, 302, "redirect", {}, "http://dl.nssurge.com/file")

    def transfer(self, response, artifact=a.CATALOG[0]):
        with patch.object(urllib.request, "build_opener") as build:
            build.return_value.open.return_value = response
            result = a.download(artifact)
            self.assertEqual(build.return_value.open.call_args.kwargs["timeout"], 20)
            return result

    def test_download_success_bounded_stream(self):
        self.assertEqual(self.transfer(FakeResponse(b"data", headers={"Content-Length": "4"})), b"data")

    def test_bad_http_responses(self):
        for response in [
            FakeResponse(b"data", status=206), FakeResponse(b"data", status=404),
            FakeResponse(b"data", headers={"Content-Encoding": "gzip"}),
            FakeResponse(b"data", headers={"Content-Length": "-1"}),
            FakeResponse(b"data", headers={"Content-Length": "100000000"}),
            FakeResponse(b"data", headers={"Content-Length": "5"}),
            FakeResponse(b""), FakeResponse(b"data", url="https://evil.test/file"),
        ]:
            with self.subTest(response=response), self.assertRaises(a.ArtifactError):
                self.transfer(response)

    def test_stream_overflow_without_length(self):
        with self.assertRaises(a.ArtifactError):
            self.transfer(FakeResponse(b"12345"), replace(a.CATALOG[0], max_download=4))

    def test_transfer_time_limit(self):
        with patch.object(a.time, "monotonic", side_effect=[0, 181]):
            with self.assertRaises(a.ArtifactError):
                self.transfer(FakeResponse(b"data"))

    def test_network_error_does_not_expose_url_or_remote_text(self):
        with patch.object(urllib.request, "build_opener") as build:
            build.return_value.open.side_effect = urllib.error.URLError("sig=SECRET")
            with self.assertRaises(a.ArtifactError) as raised:
                a.download(a.CATALOG[0])
            self.assertNotIn("SECRET", str(raised.exception))

    def test_truncated_http_body_has_safe_error(self):
        response = FakeResponse(b"data")
        with patch.object(response, "read1", side_effect=http.client.IncompleteRead(b"SECRET")):
            with self.assertRaises(a.ArtifactError) as raised:
                self.transfer(response)
        self.assertNotIn("SECRET", str(raised.exception))


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "stage"
        self.contents = [archive(), elf()]
        self.catalog = tuple(pinned(item, data) for item, data in zip(a.CATALOG, self.contents))

    def fetch(self, path=None):
        data = iter(self.contents)
        with patch.object(a, "CATALOG", self.catalog):
            return a.fetch(path or self.path, downloader=lambda artifact: next(data))

    def test_stage_real_files_no_execute_permissions(self):
        report = self.fetch()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o700)
        self.assertEqual(set(p.name for p in self.path.iterdir()), {"snell.zip", "snell-server", "shadow-tls", "receipt.json"})
        for path in self.path.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse(report["installed"])
        self.assertEqual(json.loads((self.path / "receipt.json").read_text()), report)

    def test_existing_directory_not_reused_no_download(self):
        self.path.mkdir()
        with patch.object(a, "download", side_effect=AssertionError("no network")):
            with self.assertRaises(a.ArtifactError):
                self.fetch()

    def test_symlink_parent_or_leaf_rejected(self):
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        for path in [self.root / "link" / "stage", self.root / "link"]:
            with self.assertRaises((a.ArtifactError, OSError)):
                self.fetch(path)
        self.assertFalse(self.path.exists())

    def test_root_relative_and_traversal_rejected(self):
        for path in [Path("/"), Path("relative"), self.root / ".." / "unsafe"]:
            with self.assertRaises(a.ArtifactError):
                self.fetch(path)

    def test_second_failure_has_no_completion_receipt(self):
        self.contents[1] = b"corrupt"
        with self.assertRaises(a.ArtifactError):
            self.fetch()
        self.assertTrue((self.path / "snell-server").exists())
        self.assertFalse((self.path / "shadow-tls").exists())
        self.assertFalse((self.path / "receipt.json").exists())

    def test_foreign_file_not_overwritten(self):
        def downloader(item):
            (self.path / item.binary).write_bytes(b"foreign")
            return self.contents[0]
        with patch.object(a, "CATALOG", self.catalog), self.assertRaises(FileExistsError):
            a.fetch(self.path, downloader=downloader)
        self.assertEqual((self.path / "snell-server").read_bytes(), b"foreign")
        self.assertFalse((self.path / "receipt.json").exists())

    def test_fsync_failure_no_false_success(self):
        with patch.object(a.os, "fsync", side_effect=OSError("full")), self.assertRaises(OSError):
            self.fetch()
        self.assertFalse((self.path / "receipt.json").exists())

    def test_cli_list_does_not_contact_network(self):
        from snellctl.__main__ import main
        out = io.StringIO()
        with patch.object(a, "download", side_effect=AssertionError("network")), contextlib.redirect_stdout(out):
            self.assertEqual(main(["artifacts", "list"]), 0)
        self.assertEqual(json.loads(out.getvalue())["target"], "linux-amd64")

    def test_cli_error_is_sanitized(self):
        from snellctl.__main__ import main
        out = io.StringIO()
        with patch.object(a, "fetch", side_effect=OSError("SECRET")), contextlib.redirect_stdout(out):
            self.assertEqual(main(["artifacts", "fetch", "--output", str(self.path)]), 1)
        self.assertNotIn("SECRET", out.getvalue())

    def test_cli_subprocess_listing(self):
        result = subprocess.run([sys.executable, "-m", "snellctl", "artifacts", "list"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(json.loads(result.stdout)["artifacts"]), 2)

    def test_cli_cancellation_leaves_no_success_claim(self):
        from snellctl.__main__ import main
        output = io.StringIO()
        with patch.object(a, "fetch", side_effect=KeyboardInterrupt), contextlib.redirect_stdout(output):
            self.assertEqual(main(["artifacts", "fetch", "--output", str(self.path)]), 130)
        self.assertIn("已取消", output.getvalue())
