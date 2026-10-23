"""Create-only configuration transactions, restricted to an explicit sandbox.

The journal contains no configuration bodies. Staged files anchor published
inodes until commit, so rollback never claims an unrelated file by its name.
No services, package tools, network calls or production-root mode exist here.
"""

from contextlib import contextmanager
from dataclasses import asdict
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .deployment import (
    NodeSpec, SNELL_VERSION, SHADOWTLS_VERSION, file_targets, new_node_secrets, render_files,
)


STATE = ".snellctl-state"
MARKER = ".snellctl-sandbox"
MARKER_BYTES = b'{"format":1,"mode":"sandbox-only"}\n'
PENDING = f"{STATE}/pending.json"
STAGE = f"{STATE}/stage"
NEXT = f"{STATE}/record.next"
NODES = f"{STATE}/nodes"
LIMIT = 65536


class StoreError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def _fail(code: str, message: str) -> None:
    raise StoreError(code, message)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _parts(path: str) -> list[str]:
    parts = path.split("/") if path else []
    if any(part in {"", ".", ".."} for part in parts):
        _fail("unsafe-path", "路径不是安全的相对路径。")
    return parts


def _open_absolute(path: Path) -> int:
    raw = os.fspath(path)
    if not path.is_absolute() or raw == "/" or ".." in path.parts:
        _fail("unsafe-root", "请指定独立测试目录的绝对路径，不能使用系统根目录。")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


class _Tree:
    def __init__(self, root: Path):
        self.fd = _open_absolute(root)
        info = os.fstat(self.fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(self.fd)
            _fail("unsafe-root", "测试目录必须归当前用户所有，权限必须为 0700。")

    def close(self):
        os.close(self.fd)

    @contextmanager
    def directory(self, path: str, *, create: bool = False):
        fd = os.dup(self.fd)
        prefix = []
        try:
            for part in _parts(path):
                prefix.append(part)
                relative = "/".join(prefix)
                private = relative == STATE or relative.startswith(STATE + "/") or relative == "etc/snellctl" or relative.startswith("etc/snellctl/")
                if create:
                    try:
                        os.mkdir(part, 0o700 if private else 0o755, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                info = os.fstat(child)
                if info.st_uid != os.geteuid() or info.st_mode & (0o077 if private else 0o022):
                    os.close(child)
                    _fail("unsafe-directory", "目录所有者或权限不符；未接管或修改其权限。")
                os.close(fd)
                fd = child
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def parent(self, path: str, *, create: bool = False):
        parts = _parts(path)
        if not parts:
            _fail("unsafe-path", "不能将测试根目录作为文件操作。")
        with self.directory("/".join(parts[:-1]), create=create) as fd:
            yield fd, parts[-1]

    def info(self, path: str):
        try:
            with self.parent(path) as (fd, name):
                return os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def names(self, path: str) -> list[str]:
        with self.directory(path) as fd:
            return os.listdir(fd)

    def read(self, path: str, mode: int, *, max_links: int = 1) -> bytes:
        with self.parent(path) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != mode or not 1 <= info.st_nlink <= max_links
                    or info.st_size > LIMIT):
                _fail("unsafe-file", "文件类型、所有者、权限、链接数或大小不符；保留现场。")
            data = bytearray()
            while chunk := os.read(fd, min(8192, LIMIT + 1 - len(data))):
                data.extend(chunk)
                if len(data) > LIMIT:
                    _fail("unsafe-file", "文件超过大小限制；保留现场。")
            return bytes(data)
        finally:
            os.close(fd)

    def write_new(self, path: str, data: bytes, mode: int):
        with self.parent(path, create=True) as (parent, name):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written == 0:
                        raise OSError(errno.EIO, "short write")
                    view = view[written:]
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(parent)

    def link_new(self, source: str, target: str):
        with self.parent(source) as (src_fd, src_name), self.parent(target, create=True) as (dst_fd, dst_name):
            os.link(src_name, dst_name, src_dir_fd=src_fd, dst_dir_fd=dst_fd, follow_symlinks=False)
            os.fsync(dst_fd)

    def unlink(self, path: str):
        with self.parent(path) as (parent, name):
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)

    def rmdir(self, path: str):
        with self.parent(path) as (parent, name):
            os.rmdir(name, dir_fd=parent)
            os.fsync(parent)


def initialize(root: Path) -> str:
    """Initialize an empty, private sandbox; never adopt a populated directory."""
    root = Path(root)
    if not root.is_absolute() or root == Path("/") or ".." in root.parts:
        _fail("unsafe-root", "请指定独立测试目录的绝对路径，不能使用系统根目录。")
    # Open parents without resolving symlinks, including an alias such as /tmp.
    parent_fd = _open_absolute(root.parent) if root.parent != Path("/") else os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            os.mkdir(root.name, 0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
    finally:
        os.close(parent_fd)
    tree = _Tree(root)
    try:
        if tree.names(""):
            _fail("not-empty", "测试目录不是空目录；不会覆盖或自动接管。")
        with tree.directory(NODES, create=True):
            pass
        tree.write_new(f"{STATE}/lock", b"", 0o600)
        tree.write_new(MARKER, MARKER_BYTES, 0o600)
    finally:
        tree.close()
    return "initialized"


class SandboxStore:
    def __init__(self, root: Path):
        self.tree = _Tree(Path(root))
        try:
            if self.tree.read(MARKER, 0o600) != MARKER_BYTES:
                _fail("not-sandbox", "缺少有效的测试目录标记；拒绝写入。")
        except BaseException:
            self.tree.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.tree.close()

    @contextmanager
    def _locked(self):
        with self.tree.parent(f"{STATE}/lock") as (parent, name):
            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                _fail("unsafe-lock", "锁文件异常；拒绝继续。")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _fail("busy", "已有操作正在进行，请等待完成；不要删除锁文件。")
            yield
        finally:
            os.close(fd)

    def _checkpoint(self, event: str, index: int = -1):
        """Fault-injection boundary used by tests, not a user-facing option."""

    @staticmethod
    def _node_spec(node: str) -> NodeSpec:
        try:
            return NodeSpec("placeholder.example.net", node=node)
        except ValueError:
            _fail("invalid-record", "记录中的节点标识无效；保留现场。")

    def _record(self, path: str) -> dict:
        try:
            record = json.loads(self.tree.read(path, 0o600, max_links=2))
        except (ValueError, UnicodeError):
            _fail("invalid-record", "状态记录损坏；未自动清理或覆盖。")
        if not isinstance(record, dict) or set(record) != {"format", "node", "parameters_sha256", "files"} or type(record["format"]) is not int or record["format"] != 1:
            _fail("invalid-record", "状态记录格式不受支持；保留现场。")
        spec = self._node_spec(record["node"])
        entries = record["files"]
        targets = file_targets(spec)
        if not isinstance(entries, list) or len(entries) != len(targets):
            _fail("invalid-record", "状态记录中的文件清单不符；保留现场。")
        hashes = [record["parameters_sha256"]]
        for entry, target in zip(entries, targets, strict=True):
            if (not isinstance(entry, dict) or set(entry) != {"path", "mode", "sha256"}
                    or entry["path"] != target.path or type(entry["mode"]) is not int or entry["mode"] != target.mode):
                _fail("invalid-record", "记录包含非本节点目标或无效权限；拒绝操作。")
            hashes.append(entry["sha256"])
        if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes):
            _fail("invalid-record", "记录中的校验摘要无效；保留现场。")
        return record

    def _publish_record(self, path: str, record: dict):
        self.tree.write_new(NEXT, _json_bytes(record), 0o600)
        self._checkpoint("record-written")
        self.tree.link_new(NEXT, path)
        self._checkpoint("record-linked")
        self.tree.unlink(NEXT)

    def _clear_next(self):
        if self.tree.info(NEXT) is not None:
            self.tree.read(NEXT, 0o600, max_links=2)
            self.tree.unlink(NEXT)

    def _has_pending(self) -> bool:
        return any(self.tree.info(path) is not None for path in (PENDING, STAGE, NEXT))

    @staticmethod
    def _manifest(node: str) -> str:
        return f"{NODES}/{node}.json"

    def _verify(self, entry: dict, path: str, *, max_links: int = 1):
        if _digest(self.tree.read(path, entry["mode"], max_links=max_links)) != entry["sha256"]:
            _fail("changed", "文件内容已改变；不会覆盖或删除，请先检查。")

    def _verify_committed(self, record: dict, *, max_links: int = 1):
        for entry in record["files"]:
            self._verify(entry, entry["path"][1:], max_links=max_links)

    def _stage_names(self) -> list[str]:
        if self.tree.info(STAGE) is None:
            return []
        names = self.tree.names(STAGE)
        allowed = {str(index) for index in range(len(file_targets(NodeSpec("placeholder.example.net"))))}
        if not set(names) <= allowed:
            _fail("unknown-stage-file", "准备目录存在未知文件，未自动清理。")
        return names

    def _check_pending_files(self, record: dict):
        if set(self._stage_names()) != {str(index) for index in range(len(record["files"]))}:
            _fail("incomplete-stage", "恢复材料不完整；未重建密钥或修改目标文件。")
        for index, entry in enumerate(record["files"]):
            source, target = f"{STAGE}/{index}", entry["path"][1:]
            self._verify(entry, source, max_links=2)
            src, dst = self.tree.info(source), self.tree.info(target)
            if dst is not None:
                if (src.st_dev, src.st_ino) != (dst.st_dev, dst.st_ino):
                    _fail("conflict", "目标存在非本次写入的文件；保留双方文件，停止恢复。")
                self._verify(entry, target, max_links=2)
            if src.st_nlink != (2 if dst is not None else 1):
                _fail("unexpected-link", "候选文件存在非预期硬链接；停止恢复。")

    def _finish_commit(self, record: dict):
        self._verify_committed(record, max_links=2)
        names = self._stage_names()
        for index, entry in enumerate(record["files"]):
            if self.tree.info(entry["path"][1:]).st_nlink != (2 if str(index) in names else 1):
                _fail("unexpected-link", "已提交文件存在非预期硬链接；停止清理。")
        for name in names:
            entry = record["files"][int(name)]
            self._verify(entry, f"{STAGE}/{name}", max_links=2)
            src, dst = self.tree.info(f"{STAGE}/{name}"), self.tree.info(entry["path"][1:])
            if (src.st_dev, src.st_ino) != (dst.st_dev, dst.st_ino):
                _fail("conflict", "准备文件与已提交目标不一致；保留现场。")
        self._clear_next()
        for name in names:
            self.tree.unlink(f"{STAGE}/{name}")
            self._checkpoint("cleanup", int(name))
        if self.tree.info(STAGE) is not None:
            self.tree.rmdir(STAGE)
        self.tree.unlink(PENDING)

    def _resume(self, record: dict) -> str:
        manifest = self._manifest(record["node"])
        if self.tree.info(manifest) is not None:
            if self._record(manifest) != record:
                _fail("conflict", "已提交记录与待恢复操作不一致；保留现场。")
            self._finish_commit(record)
            return "committed-cleanup"
        self._check_pending_files(record)
        self._clear_next()
        for index, entry in enumerate(record["files"]):
            if self.tree.info(entry["path"][1:]) is None:
                self.tree.link_new(f"{STAGE}/{index}", entry["path"][1:])
                self._checkpoint("published", index)
        self._check_pending_files(record)
        self._publish_record(manifest, record)
        self._checkpoint("committed")
        self._finish_commit(record)
        return "created"

    def prepare(self, spec: NodeSpec) -> str:
        with self._locked():
            if self._has_pending():
                _fail("recovery-required", "存在未完成操作，请先明确选择继续或取消。")
            params = _digest(_json_bytes({"template_format": 1, "spec": asdict(spec),
                                         "snell": SNELL_VERSION, "shadowtls": SHADOWTLS_VERSION}))
            manifest = self._manifest(spec.node)
            if self.tree.info(manifest) is not None:
                record = self._record(manifest)
                if record["node"] != spec.node or record["parameters_sha256"] != params:
                    _fail("node-exists", "节点已存在且参数不同；此命令不更新既有配置。")
                self._verify_committed(record)
                return "unchanged"
            for target in file_targets(spec):
                if self.tree.info(target.path[1:]) is not None:
                    _fail("conflict", "目标路径已有文件或链接；不会覆盖，也不会自动认领。")
            candidates = render_files(spec, new_node_secrets())
            record = {"format": 1, "node": spec.node, "parameters_sha256": params, "files": []}
            for index, candidate in enumerate(candidates):
                data = candidate.content.encode("ascii")
                self.tree.write_new(f"{STAGE}/{index}", data, candidate.target.mode)
                record["files"].append({"path": candidate.target.path, "mode": candidate.target.mode,
                                        "sha256": _digest(data)})
                self._checkpoint("staged", index)
            self._publish_record(PENDING, record)
            self._checkpoint("prepared")
            return self._resume(record)

    def _discard_orphan(self) -> str:
        names = self._stage_names()
        for name in names:
            path = f"{STAGE}/{name}"
            info = self.tree.info(path)
            if stat.S_IMODE(info.st_mode) not in {0o600, 0o644, 0o700}:
                _fail("unsafe-file", "未发布的准备文件权限异常；保留现场。")
            self.tree.read(path, stat.S_IMODE(info.st_mode))
        self._clear_next()
        for name in names:
            self.tree.unlink(f"{STAGE}/{name}")
        if self.tree.info(STAGE) is not None:
            self.tree.rmdir(STAGE)
        return "cancelled"

    def recover(self, action: str) -> str:
        if action not in {"resume", "rollback"}:
            _fail("invalid-action", "恢复操作必须明确选择 resume 或 rollback。")
        with self._locked():
            if self.tree.info(PENDING) is None:
                if not self._has_pending():
                    return "nothing-pending"
                if action == "resume":
                    _fail("incomplete-preparation", "准备阶段未完成，尚未发布目标文件；请取消后重新准备。")
                return self._discard_orphan()
            record = self._record(PENDING)
            if action == "resume" or self.tree.info(self._manifest(record["node"])) is not None:
                return self._resume(record)
            self._check_pending_files(record)
            for index in reversed(range(len(record["files"]))):
                target = record["files"][index]["path"][1:]
                if self.tree.info(target) is not None:
                    self.tree.unlink(target)
                    self._checkpoint("removed", index)
            self.tree.unlink(PENDING)
            self._checkpoint("cancelled")
            return self._discard_orphan()

    def status(self) -> dict:
        with self._locked():
            pending_record = self._record(PENDING) if self.tree.info(PENDING) is not None else None
            nodes = []
            for name in sorted(self.tree.names(NODES)):
                if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}\.json", name):
                    _fail("unknown-record", "发现未知状态记录，未输出其内容。")
                record = self._record(f"{NODES}/{name}")
                if name != record["node"] + ".json":
                    _fail("invalid-record", "记录名称与节点不符；保留现场。")
                try:
                    self._verify_committed(record, max_links=2 if record == pending_record else 1)
                    state = "candidates-intact"
                except (OSError, StoreError):
                    state = "needs-attention"
                nodes.append({"node": record["node"], "state": state})
            pending = "none"
            if pending_record is not None:
                pending = "committed-cleanup" if self.tree.info(self._manifest(pending_record["node"])) is not None else "publishing"
            elif self._has_pending():
                pending = "incomplete-preparation"
            return {"mode": "sandbox-only", "pending": pending, "nodes": nodes,
                    "services_started": False, "deployment_validated": False}
