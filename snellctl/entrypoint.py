"""Standalone, standard-library-only verification before importing installed code."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys


BASE = "/usr/local/lib/harbor-kit"
COMMAND = "/usr/local/bin/snellctl"
WRAPPER = ("#!/bin/sh\nexec /usr/bin/python3 -I -B " + BASE + '/launcher.py "$@"\n').encode()
MODULES = (
    "__init__.py", "__main__.py", "activation.py", "aptreview.py", "artifacts.py",
    "cleanup.py", "client.py", "commandinstall.py", "deployment.py", "doctor.py",
    "domainchange.py", "domaininventory.py", "entrypoint.py", "hostcommands.py", "hostprep.py",
    "installer.py", "maintenance.py", "menu.py", "packagebaseline.py", "packagecontents.py",
    "packagedownload.py", "packagefinish.py", "packageflow.py", "packageguards.py",
    "packageinspection.py", "packagejob.py", "packagematerial.py", "packageplan.py",
    "packagepolicy.py", "packageprompts.py", "packageresume.py", "packagereview.py",
    "packagestatus.py", "packagesubmit.py", "packageupdate.py", "portchange.py", "preflight.py",
    "publish.py", "reinstall.py", "reinstallplan.py", "releases.py", "renewalprobe.py",
    "retiredcancel.py", "retiredcleanup.py", "retiredplan.py", "retiredrenewal.py", "rotation.py",
    "sandbox_cli.py", "storage.py", "tlsprobe.py", "tokenchange.py", "tokendiag.py", "tokenresume.py",
    "uninstall.py", "uninstallplan.py",
)
FILE_LIMIT = 256 * 1024
TOTAL_LIMIT = 2 * 1024 * 1024


class EntryError(Exception):
    pass


class Tree:
    """Fixed-root no-follow reads; alternate roots are for library tests only."""

    def __init__(self, root, uid):
        root = Path(root)
        if not root.is_absolute() or ".." in root.parts:
            raise EntryError("invalid root")
        self.uid = uid
        self.fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in root.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
                os.close(self.fd)
                self.fd = child
            self._directory_check(self.fd)
        except BaseException:
            os.close(self.fd)
            raise

    def _directory_check(self, fd):
        info = os.fstat(fd)
        if info.st_uid != self.uid or info.st_mode & 0o022:
            raise EntryError("unsafe directory")

    def close(self):
        os.close(self.fd)

    @contextmanager
    def directory(self, path):
        path = Path(path)
        if not path.is_absolute() or ".." in path.parts:
            raise EntryError("invalid path")
        fd = os.dup(self.fd)
        try:
            for part in path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                self._directory_check(fd)
            yield fd
        finally:
            os.close(fd)

    def read(self, path, *, mode=None, limit=FILE_LIMIT):
        path = Path(path)
        with self.directory(str(path.parent)) as fd:
            src = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(src, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != self.uid
                    or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > limit
                    or (mode is not None and stat.S_IMODE(before.st_mode) != mode)):
                raise EntryError("unsafe file")
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if (len(data) > limit or (before.st_mtime_ns, before.st_ctime_ns, before.st_size)
                    != (after.st_mtime_ns, after.st_ctime_ns, after.st_size)):
                raise EntryError("file changed")
            return data

    def names(self, path):
        with self.directory(path) as fd:
            return set(os.listdir(fd))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(hashes):
    return digest(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode())


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EntryError("duplicate field")
        result[key] = value
    return result


def verify_installation(root=Path("/"), *, uid=0):
    tree = Tree(root, uid)
    try:
        if tree.names(BASE) != {"manifest.json", "launcher.py", "snellctl"}:
            raise EntryError("unexpected installation layout")
        if tree.names(BASE + "/snellctl") != set(MODULES):
            raise EntryError("unexpected module layout")
        raw = tree.read(BASE + "/manifest.json", mode=0o600, limit=32768)
        record = json.loads(raw, object_pairs_hook=_unique)
        paths = {"snellctl/" + name for name in MODULES} | {"launcher.py", "command"}
        if (not isinstance(record, dict) or set(record) != {"format", "kind", "files", "snapshot_sha256"}
                or type(record["format"]) is not int or record["format"] != 1
                or record["kind"] != "harbor-kit-command" or not isinstance(record["files"], dict)
                or set(record["files"]) != paths):
            raise EntryError("invalid manifest")
        hashes = record["files"]
        if any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
               for value in hashes.values()) or record["snapshot_sha256"] != snapshot(hashes):
            raise EntryError("invalid hashes")
        total = 0
        for relative in sorted(paths):
            path = COMMAND if relative == "command" else BASE + "/" + relative
            data = tree.read(path, mode=0o755 if relative == "command" else 0o600)
            total += len(data)
            if total > TOTAL_LIMIT or digest(data) != hashes[relative]:
                raise EntryError("installed content changed")
            if relative == "command" and data != WRAPPER:
                raise EntryError("unexpected entry command")
        if hashes["launcher.py"] != hashes["snellctl/entrypoint.py"]:
            raise EntryError("launcher mismatch")
        if tree.read(BASE + "/manifest.json", mode=0o600, limit=32768) != raw:
            raise EntryError("manifest changed")
        return record["snapshot_sha256"]
    finally:
        tree.close()


def launch(root=Path("/"), *, uid=0):
    # Production always uses the fixed root; no environment or CLI path override.
    try:
        if os.geteuid() != uid or sys.version_info < (3, 11):
            raise EntryError("root and Python 3.11 required")
        if any(name == "snellctl" or name.startswith("snellctl.") for name in sys.modules):
            raise EntryError("package already imported")
        verify_installation(root, uid=uid)
    except (EOFError, KeyboardInterrupt):
        print("启动校验已中断；未调用管理菜单。", file=sys.stderr)
        return 130
    except Exception:
        print("快捷入口校验未通过；需 root 和完整受管代码。未调用菜单，不自动修复。", file=sys.stderr)
        return 1
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(Path(root) / BASE.lstrip("/")))
    try:
        runpy.run_module("snellctl", run_name="__main__", alter_sys=True)
    except (EOFError, KeyboardInterrupt):
        print("管理命令已中断；可能已有操作，请核对对应记录，不自动重试。", file=sys.stderr)
        return 130
    except Exception:
        print("管理命令异常退出；可能已有操作，请保留现场。原始异常未显示。", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(launch())
