"""Pinned upstream downloads. Staging only: no binary execution or installation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import ssl
import stat
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

from .deployment import SNELL_VERSION, SHADOWTLS_VERSION


class ArtifactError(Exception):
    """Messages are fixed strings, never server responses or signed redirect URLs."""


@dataclass(frozen=True)
class Artifact:
    name: str
    version: str
    url: str
    sha256: str
    filename: str
    binary: str
    archive: bool
    max_download: int
    max_binary: int
    redirect_hosts: tuple[str, ...]


CATALOG = (
    Artifact(
        "snell", SNELL_VERSION,
        "https://dl.nssurge.com/snell/snell-server-v5.0.1-linux-amd64.zip",
        "9bea1c2b9e35b73b31634856c04d18c393072b9e5dcde6a32781d8b8f908c539",
        "snell.zip", "snell-server", True, 8 * 1024**2, 32 * 1024**2,
        ("dl.nssurge.com",),
    ),
    Artifact(
        "shadow-tls", SHADOWTLS_VERSION,
        "https://github.com/ihciah/shadow-tls/releases/download/v0.2.25/"
        "shadow-tls-x86_64-unknown-linux-musl",
        "a173f5f2d57f45211b68e10ceeddc15b1791077b914fa89747bc705fddc71532",
        "shadow-tls", "shadow-tls", False, 32 * 1024**2, 32 * 1024**2,
        ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"),
    ),
)


def catalog_report() -> dict:
    return {
        "format": 1, "target": "linux-amd64", "executes_downloads": False,
        "checksum_basis": "manually-tested-baseline-not-upstream-signature",
        "artifacts": [
            {"name": a.name, "version": a.version, "url": a.url, "sha256": a.sha256}
            for a in CATALOG
        ],
    }


def _allowed_url(url: str, hosts: tuple[str, ...]) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        valid = (
            parsed.scheme == "https" and parsed.hostname in hosts
            and parsed.port in {None, 443} and parsed.username is None
            and parsed.password is None and not parsed.fragment
            and not any(ord(c) < 33 or ord(c) == 127 for c in url)
        )
    except ValueError:
        valid = False
    if not valid:
        raise ArtifactError("下载地址或重定向不在允许的 HTTPS 来源范围，已停止。")


class _Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5
    max_repeats = 2

    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _allowed_url(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(artifact: Artifact) -> bytes:
    """Bounded transfer; timeout is not a hard deadline for OS DNS resolution."""
    _allowed_url(artifact.url, artifact.redirect_hosts)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _Redirects(artifact.redirect_hosts),
    )
    request = urllib.request.Request(
        artifact.url, headers={"User-Agent": "snellctl-artifact-staging/1", "Accept-Encoding": "identity"},
    )
    started = time.monotonic()
    try:
        with opener.open(request, timeout=20) as response:
            _allowed_url(response.geturl(), artifact.redirect_hosts)
            if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                raise ArtifactError("下载响应状态或编码不符合要求，已停止。")
            size = response.headers.get("Content-Length")
            if size is not None and (not size.isdecimal() or not 0 < int(size) <= artifact.max_download):
                raise ArtifactError("下载文件长度无效或超过上限，已停止。")
            content = bytearray()
            while True:
                if time.monotonic() - started > 180:
                    raise ArtifactError("下载超过时间限制，已停止。")
                chunk = response.read1(min(65536, artifact.max_download + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > artifact.max_download:
                    raise ArtifactError("下载文件超过大小上限，已停止。")
            if not content or (size is not None and len(content) != int(size)):
                raise ArtifactError("下载为空或不完整，已停止。")
            return bytes(content)
    except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
        raise ArtifactError("官方文件下载失败；请检查网络、系统时间与受信证书，未使用备用镜像。") from None


def _elf_amd64(payload: bytes) -> None:
    # Check the fixed ELF header without executing or trusting file extensions.
    if len(payload) < 64 or payload[:7] != b"\x7fELF\x02\x01\x01":
        raise ArtifactError("程序不是预期的 64 位小端 ELF 文件，已停止。")
    kind, machine, version = struct.unpack_from("<HHI", payload, 16)
    if kind not in {2, 3} or machine != 62 or version != 1 or struct.unpack_from("<H", payload, 52)[0] != 64:
        raise ArtifactError("程序的 ELF 架构或头部不符合 amd64 要求，已停止。")


def verify(artifact: Artifact, content: bytes) -> bytes:
    if not 0 < len(content) <= artifact.max_download:
        raise ArtifactError("下载文件大小不符合要求，已停止。")
    if hashlib.sha256(content).hexdigest() != artifact.sha256:
        raise ArtifactError("文件指纹与已测试基线不一致，已停止；不会自动接受新指纹。")
    payload = content
    if artifact.archive:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                entries = archive.infolist()
                if len(entries) != 1:
                    raise ArtifactError("压缩包条目与预期不符，已停止。")
                entry = entries[0]
                kind = stat.S_IFMT(entry.external_attr >> 16)
                if (
                    entry.filename != artifact.binary or entry.is_dir()
                    or kind not in {0, stat.S_IFREG} or entry.flag_bits & 1
                    or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or not 0 < entry.file_size <= artifact.max_binary
                ):
                    raise ArtifactError("压缩包含非预期路径、文件类型或大小，已停止。")
                # Read exactly one whitelisted entry into memory, never extractall.
                with archive.open(entry) as source:
                    payload = source.read(artifact.max_binary + 1)
                if len(payload) != entry.file_size:
                    raise ArtifactError("解压长度不符，已停止。")
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error):
            raise ArtifactError("压缩包校验失败，已停止。") from None
    if not 0 < len(payload) <= artifact.max_binary:
        raise ArtifactError("程序文件超过大小上限，已停止。")
    _elf_amd64(payload)
    return payload


def _new_directory(path: Path) -> int:
    """Create one new private directory through no-follow directory descriptors."""
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise ArtifactError("暂存目录必须是新的绝对路径，不能使用系统根目录或上级跳转。")
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
            raise ArtifactError("暂存目录已存在，不覆盖、不复用；请指定另一个新目录。") from None
        new_fd = os.open(path.name, flags, dir_fd=fd)
        try:
            st = os.fstat(new_fd)
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
                raise ArtifactError("暂存目录归属或权限不符合要求，已停止。")
            os.fsync(fd)
        except BaseException:
            os.close(new_fd)
            raise
        return new_fd
    finally:
        os.close(fd)


def _write(fd: int, name: str, content: bytes) -> None:
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    with os.fdopen(out, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(fd)


def fetch(directory: Path, *, downloader=download) -> dict:
    """Leave failed/incomplete stages for inspection; never delete unknown files."""
    fd = _new_directory(directory)
    try:
        report = catalog_report()
        report.update({"status": "verified-staging-only", "installed": False, "files": []})
        for artifact in CATALOG:
            content = downloader(artifact)
            payload = verify(artifact, content)
            if artifact.archive:
                _write(fd, artifact.filename, content)
            _write(fd, artifact.binary, payload)
            report["files"].append({
                "name": artifact.binary, "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(), "mode": "0600",
            })
        # The receipt is the completion marker, not authorization to execute.
        _write(fd, "receipt.json", (json.dumps(report, indent=2) + "\n").encode())
        return report
    finally:
        os.close(fd)


def run(args) -> int:
    try:
        if args.artifact_action == "list":
            print(json.dumps(catalog_report(), ensure_ascii=False, indent=2))
        else:
            report = fetch(Path(args.output))
            print(json.dumps(report, ensure_ascii=False, indent=2))
            print("下载与文件校验通过；暂存文件没有执行权限，未安装或启动服务。")
        return 0
    except (ArtifactError, OSError) as exc:
        print(str(exc) if isinstance(exc, ArtifactError) else "本地暂存失败；未覆盖已有文件，请检查目录权限与磁盘空间。")
        return 1
    except KeyboardInterrupt:
        print("已取消下载；暂存目录可能不完整，未安装或启动服务。")
        return 130
