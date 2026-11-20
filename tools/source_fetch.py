"""Stage pinned GitHub source without importing, executing or installing it."""

import argparse
from dataclasses import dataclass
import gzip
import hashlib
import http.client
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib


ARCHIVE_LIMIT = 4 * 1024 * 1024
TAR_LIMIT = 8 * 1024 * 1024
FILE_LIMIT = 256 * 1024
TOTAL_LIMIT = 4 * 1024 * 1024
ENTRY_LIMIT = 512
REQUIRED_FILES = {"README.md", "tools/public_source.py", "snellctl/__main__.py"}


class FetchError(Exception):
    pass


@dataclass(frozen=True)
class Archive:
    url: str
    max_download: int
    redirect_hosts: tuple[str, ...]


def _allowed_url(url, hosts):
    try:
        parsed = urllib.parse.urlsplit(url)
        valid = (parsed.scheme == "https" and parsed.hostname in hosts
                 and parsed.port in (None, 443) and not parsed.username
                 and not parsed.password and not parsed.fragment
                 and not any(ord(c) < 33 or ord(c) == 127 for c in url))
    except ValueError:
        valid = False
    if not valid:
        raise FetchError("Download URL or redirect is outside the fixed HTTPS host.")


class _Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 2

    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _allowed_url(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(archive):
    _allowed_url(archive.url, archive.redirect_hosts)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _Redirects(archive.redirect_hosts),
    )
    request = urllib.request.Request(
        archive.url, headers={"User-Agent": "harbor-kit-source-fetch/1", "Accept-Encoding": "identity"},
    )
    started = time.monotonic()
    try:
        with opener.open(request, timeout=20) as response:
            _allowed_url(response.geturl(), archive.redirect_hosts)
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise FetchError("Unexpected download response.")
            size = response.headers.get("Content-Length")
            if size is not None and (not size.isdecimal() or not 0 < int(size) <= archive.max_download):
                raise FetchError("Invalid archive content length.")
            content = bytearray()
            while True:
                if time.monotonic() - started > 180:
                    raise FetchError("Download time limit exceeded.")
                chunk = response.read1(min(65536, archive.max_download + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > archive.max_download:
                    raise FetchError("Archive download exceeds size limit.")
            if not content or (size is not None and len(content) != int(size)):
                raise FetchError("Incomplete archive download.")
            return bytes(content)
    except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
        raise FetchError("Source download failed; check network, system time and trusted CA.") from None


def _new_directory(path):
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise FetchError("Stage must be a new absolute directory without parent traversal.")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        try:
            os.mkdir(path.name, 0o700, dir_fd=fd)
        except FileExistsError:
            raise FetchError("Stage already exists; refusing to overwrite or reuse it.") from None
        new_fd = os.open(path.name, flags, dir_fd=fd)
        try:
            info = os.fstat(new_fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise FetchError("Unexpected stage owner or permissions.")
            os.fsync(fd)
        except BaseException:
            os.close(new_fd)
            raise
        return new_fd
    finally:
        os.close(fd)


def _write(fd, name, content):
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    with os.fdopen(out, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(fd)


def pins(commit, archive_sha256, snapshot_sha256):
    for value, length in ((commit, 40), (archive_sha256, 64), (snapshot_sha256, 64)):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % length, value):
            raise FetchError("Expected full lowercase commit and SHA-256 values; no moving refs.")
    return Archive("https://codeload.github.com/Shennai1/harbor-kit/tar.gz/" + commit,
                   ARCHIVE_LIMIT, ("codeload.github.com",))


def verify(content, commit, archive_sha256, snapshot_sha256):
    pins(commit, archive_sha256, snapshot_sha256)
    if (not isinstance(content, bytes) or not 0 < len(content) <= ARCHIVE_LIMIT
            or hashlib.sha256(content).hexdigest() != archive_sha256):
        raise FetchError("Archive size or SHA-256 mismatch; nothing extracted.")
    # Bound decompression before parsing tar headers (including hidden PAX headers).
    with gzip.GzipFile(fileobj=io.BytesIO(content), mode="rb") as compressed:
        raw = compressed.read(TAR_LIMIT + 1)
    if len(raw) > TAR_LIMIT:
        raise FetchError("Expanded archive exceeds limit.")
    root = "harbor-kit-" + commit
    seen, folded, directories, files = set(), set(), set(), {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for member in tar:
            name = member.name
            path = PurePosixPath(name)
            if (len(seen) >= ENTRY_LIMIT or len(name) > 240 or str(path) != name
                    or path.is_absolute() or not path.parts or path.parts[0] != root
                    or any(part in {".", "..", ".git"}
                           or not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in path.parts)
                    or name in seen or name.casefold() in folded):
                raise FetchError("Noncanonical, duplicate or unsupported archive path.")
            seen.add(name)
            folded.add(name.casefold())
            if (member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}
                    or member.sparse is not None or member.linkname or member.mode & 0o7000
                    or any(k != "comment" or v != commit for k, v in member.pax_headers.items())):
                raise FetchError("Unsupported archive entry or metadata.")
            relative = path.relative_to(root).as_posix()
            if member.isdir():
                if member.size != 0:
                    raise FetchError("Directory payload is not supported.")
                directories.add(relative)
                continue
            if relative == "." or member.mode & 0o111 or not 0 <= member.size <= FILE_LIMIT:
                raise FetchError("Unexpected source file size or mode.")
            total += member.size
            if total > TOTAL_LIMIT:
                raise FetchError("Source files exceed total limit.")
            data = tar.extractfile(member).read(FILE_LIMIT + 1)
            if len(data) != member.size:
                raise FetchError("Truncated source file.")
            text = data.decode("utf-8")
            if "\x00" in text:
                raise FetchError("Binary source content is not supported.")
            files[relative] = data
    parents = {parent.as_posix() for name in files for parent in PurePosixPath(name).parents}
    if (not REQUIRED_FILES <= files.keys() or "." not in directories
            or files.keys() & parents or not directories <= parents
            or len({name.casefold() for name in parents | files.keys()}) != len(parents | files.keys())):
        raise FetchError("Source layout is missing, conflicting or unsupported.")
    records = [{"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
               for name, data in sorted(files.items())]
    digest = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != snapshot_sha256:
        raise FetchError("Source snapshot mismatch; nothing extracted.")
    return files


def _directory(fd, parts):
    current = os.dup(fd)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=current)
                os.fsync(current)
            except FileExistsError:
                pass
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = following
            info = os.fstat(current)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise FetchError("Unexpected staging directory permissions or owner.")
        return current
    except BaseException:
        os.close(current)
        raise


def fetch(output, commit, archive_sha256, snapshot_sha256, *, downloader=None):
    artifact = pins(commit, archive_sha256, snapshot_sha256)
    # Existing directories and symlink parents are rejected before network access.
    fd = _new_directory(Path(output))
    try:
        content = (download if downloader is None else downloader)(artifact)
        files = verify(content, commit, archive_sha256, snapshot_sha256)
        _write(fd, "source.tar.gz", content)
        for name, data in sorted(files.items()):
            parts = PurePosixPath(name).parts
            parent = _directory(fd, ("source", *parts[:-1]))
            try:
                _write(parent, parts[-1], data)
            finally:
                os.close(parent)
        report = {"format": 1, "operation": "source-fetch", "result": "verified-source-staged",
                  "repository": "Shennai1/harbor-kit", "commit": commit,
                  "archive_sha256": archive_sha256, "snapshot_sha256": snapshot_sha256,
                  "public_files": len(files), "source_directory": "source",
                  "verification_basis": "operator-supplied-pins-not-author-signature",
                  "downloaded_code_executed": False, "installation_attempted": False,
                  "tests_run": False, "automatic_retry": False, "signed": False}
        _write(fd, "receipt.json", (json.dumps(report, indent=2) + "\n").encode())
        return report
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Download pinned source only; never install or execute it.")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--snapshot-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = fetch(args.output, args.commit, args.archive_sha256, args.snapshot_sha256)
    except KeyboardInterrupt:
        print("Source fetch interrupted; retain partial output. Nothing installed or executed.", file=sys.stderr)
        return 130
    except (OSError, ValueError, FetchError, tarfile.TarError, EOFError, zlib.error):
        print("Source fetch stopped; do not use partial output. No overwrite, retry or cleanup.", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
