"""Restricted package staging. No installation or service-control API.

Refreshes its own indexes; old reports cannot supply package URLs or hashes.
The caller still needs maintenance consent, locks, script/module review, a
one-time dispatcher and post-install recovery before using these artifacts.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from email import policy
from email.parser import Parser
import hashlib
import os
from pathlib import PurePosixPath
import re
import stat

from . import aptreview as apt
from .domaininventory import Inventory
from .hostprep import Command, PreparationError, Reply
from .packagejob import JobSpec
from .packageplan import PackagePlan
from .packagepolicy import ARCHITECTURES, RevisionChange, revision_scope
from .preflight import DEPENDENCIES


CACHE = "/var/cache/snellctl/package-update"
EXTENDED = "/var/lib/apt/extended_states"
MAX_DEB = 64 * 1024**2
MAX_TOTAL = 256 * 1024**2
SIMULATE = ("apt-get", "--simulate", "--no-remove", "--only-upgrade", "--no-install-recommends", "install")
DOWNLOAD = ("apt-get", "--download-only", "--no-remove", "--only-upgrade",
            "--no-install-recommends", "--assume-yes", "install")


def require(condition):
    if not condition:
        raise PreparationError("Package download or staged-file verification requires inspection.")


def workspace_ok(path):
    return isinstance(path, str) and re.fullmatch(re.escape(CACHE) + r"/[0-9a-f]{32}", path) is not None


def configuration(path, *, install=False):
    require(workspace_ok(path) and type(install) is bool)
    return apt._configuration(path, extended_states=EXTENDED if install else None)


def fields(text):
    """Read one Deb822-style record with the standard RFC822 parser, fail closed."""
    require(isinstance(text, str) and 0 < len(text) <= 65536
            and all(c in "\n\t" or ord(c) >= 32 for c in text) and "\x7f" not in text)
    message = Parser(policy=policy.compat32).parsestr(text)
    require(not message.defects and not message.get_payload())
    result = {}
    for key, value in message.raw_items():
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", key) and key.lower() not in result)
        result[key.lower()] = value
    require(result)
    return result


@dataclass(frozen=True)
class Archive:
    change: RevisionChange
    size: int
    sha256: str
    filename: str

    def __post_init__(self):
        require(type(self.change) is RevisionChange and type(self.size) is int and 0 < self.size <= MAX_DEB
                and isinstance(self.sha256, str) and re.fullmatch(r"[0-9a-f]{64}", self.sha256))
        require(isinstance(self.filename, str) and len(self.filename) <= 255
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+%:~_-]*\.deb", self.filename))


def metadata(text, change):
    row = fields(text)
    require(type(change) is RevisionChange and row.get("package") == change.name
            and row.get("version") == change.after and row.get("architecture") == change.architecture)
    size, digest, filename = row.get("size", ""), row.get("sha256", ""), row.get("filename", "")
    require(re.fullmatch(r"[1-9][0-9]{0,9}", size) and len(filename) <= 512
            and re.fullmatch(r"pool/main/[A-Za-z0-9+./~_-]+\.deb", filename)
            and all(part not in {".", "..", ""} for part in filename.split("/")))
    # APT's cache name can differ from the repository filename, notably epochs.
    return Archive(change, int(size), digest, PurePosixPath(filename).name)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def fingerprint(files, path, *, limit, optional=False):
    """Bounded streaming hash without following links or buffering a whole .deb."""
    if optional and files.info(path) is None:
        return None
    with files.parent(path) as (directory, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) in {0o600, 0o644} and before.st_size <= limit)
            digest, total = hashlib.sha256(), 0
            while True:
                chunk = stream.read(min(1024**2, limit - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                require(total <= limit)
                digest.update(chunk)
            after = os.fstat(stream.fileno())
            linked = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(total == before.st_size and _identity(before) == _identity(after) == _identity(linked))
    return _identity(before), digest.hexdigest()


@dataclass(frozen=True)
class DownloadCommand(Command):
    workspace: str = ""
    pins: tuple[str, ...] = ()

    def validate(self):
        require(workspace_ok(self.workspace) and self.env == Command(("unused",)).env
                and self.capture_stderr is True and type(self.timeout) in {int, float} and 0 < self.timeout <= 600)
        require(type(self.pins) is tuple and 0 < len(self.pins) <= 8)
        names = []
        for pin in self.pins:
            require(isinstance(pin, str))
            name, sep, version = pin.partition("=")
            require(sep and name in ARCHITECTURES and apt.version_ok(version))
            names.append(name)
        require(names == sorted(set(names)))
        if self.argv == ("apt-get", "update", "--error-on=any"):
            return
        if self.argv == ("apt-cache", "policy", *DEPENDENCIES):
            return
        if self.argv == ("apt-cache", "madison", *sorted(set(names) | set(DEPENDENCIES))):
            return
        if self.argv[:3] == ("apt-cache", "--no-all-versions", "show"):
            require(len(self.argv) == 4 and self.argv[3] in self.pins)
            return
        require(self.argv in {(*SIMULATE, *self.pins), (*DOWNLOAD, *self.pins)})

    def verify_files(self, files):
        self.validate()
        apt._verify_files(files, self.workspace, configuration(self.workspace))


@dataclass(frozen=True)
class ArchiveCommand(Command):
    workspace: str = ""

    def validate(self):
        require(workspace_ok(self.workspace) and len(self.argv) == 6 and self.argv[:2] == ("dpkg-deb", "--field")
                and self.argv[3:] == ("Package", "Version", "Architecture")
                and self.capture_stderr is False and self.env == Command(("unused",)).env
                and type(self.timeout) in {int, float} and 0 < self.timeout <= 30)
        path = PurePosixPath(self.argv[2])
        require(str(path.parent) == self.workspace + "/cache/archives"
                and str(path) == self.argv[2] and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+%:~_-]*\.deb", path.name))

    def verify_files(self, files):
        self.validate()
        fingerprint(files, self.argv[2], limit=MAX_DEB)


@dataclass(frozen=True)
class InstallSimulationCommand(Command):
    job: JobSpec | None = None

    def verify_files(self, files):
        require(type(self.job) is JobSpec and self.argv == self.job.install_argv(simulate=True)
                and self.env == Command(("unused",)).env and self.capture_stderr is True
                and type(self.timeout) in {int, float} and 0 < self.timeout <= 120)
        path = CACHE + "/" + self.job.job_id
        apt._verify_files(files, path, configuration(path))
        require(files.read(self.job.apt_config, mode=0o644) == configuration(path, install=True))


@dataclass(frozen=True)
class DownloadedPackages:
    job: JobSpec
    archives: tuple[Archive, ...]
    paths_and_fingerprints: tuple
    indexes: tuple
    extended_state: tuple | None

    def verify(self, files):
        path = CACHE + "/" + self.job.job_id
        apt._verify_files(files, path, configuration(path))
        require(files.read(self.job.apt_config, mode=0o644) == configuration(path, install=True))
        require(index_snapshot(files, path) == self.indexes
                and fingerprint(files, EXTENDED, limit=16 * 1024**2, optional=True) == self.extended_state)
        require(archive_names(files, path) == tuple(PurePosixPath(p).name for p, _ in self.paths_and_fingerprints))
        for file, expected in self.paths_and_fingerprints:
            require(fingerprint(files, file, limit=MAX_DEB) == expected)


def index_snapshot(files, path):
    with files.directory(path + "/lists") as fd:
        names = sorted(os.listdir(fd))
        require(0 < len(names) <= 128)
        result = []
        for name in names:
            if name in {"lock", "partial", "auxfiles"}:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode) if name == "lock" else stat.S_ISDIR(info.st_mode))
                continue
            require(re.fullmatch(r"[A-Za-z0-9_.:%+~\-]{1,255}", name))
            result.append((name, fingerprint(files, path + "/lists/" + name, limit=256 * 1024**2)))
        require(result and sum(value[0][2] for _, value in result) <= 1024**3)
        return tuple(result)


def archive_names(files, path):
    with files.directory(path + "/cache/archives") as fd:
        names = sorted(os.listdir(fd))
        require(len(names) <= 10)
        result = []
        for name in names:
            if name in {"lock", "partial"}:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                require(stat.S_ISREG(info.st_mode) if name == "lock" else stat.S_ISDIR(info.st_mode))
                continue
            require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+%:~_-]*\.deb", name))
            result.append(name)
        return tuple(result)


class PackageDownloads(PackagePlan):
    """Cache-only stage, also used by the opt-in material CLI; no resume API."""

    @contextmanager
    def _commands(self):
        original = self.prep.runner
        with super()._commands():
            inherited = self.prep.runner
            def guarded(command):
                if type(command) in {DownloadCommand, ArchiveCommand}:
                    require(command.workspace == self.workspace)
                    command.verify_files(self.files)
                    return original(command)
                return inherited(command)
            self.prep.runner = guarded
            try:
                yield
            finally:
                self.prep.runner = inherited

    def _apt(self, args, timeout=60):
        result = self.prep.runner(DownloadCommand(tuple(args), timeout, capture_stderr=True,
                                                  workspace=self.workspace, pins=self.pins))
        require(isinstance(result, Reply) and result.code == 0 and not result.uncertain
                and not any(line.lstrip().startswith(("W:", "E:", "N:")) for line in result.output.splitlines()))
        return result.output

    def stage(self, job, *, consent=False):
        require(type(job) is JobSpec and consent is True)
        self.workspace = CACHE + "/" + job.job_id
        self.pins = tuple(c.name + "=" + c.after for c in job.changes)
        with self._commands(), self.prep._lock():
            self._phase("download-state-check")
            watched = Inventory(self.files)
            before = self._snapshot(watched)
            extended = fingerprint(self.files, EXTENDED, limit=16 * 1024**2, optional=True)
            self._phase("download-cache-preparation")
            apt._prepare(self.files, self.workspace, configuration(self.workspace))
            self._phase("download-index-refresh")
            self._apt(("apt-get", "update", "--error-on=any"), timeout=600)
            indexes = index_snapshot(self.files, self.workspace)
            self._phase("download-scope-check")
            selected = apt.candidates(self._apt(("apt-cache", "policy", *DEPENDENCIES)), before[2])
            names = sorted({c.name for c in job.changes} | set(DEPENDENCIES))
            available = apt.repository_versions(self._apt(("apt-cache", "madison", *names)), names)
            def scope():
                rows = apt.simulation(self._apt((*SIMULATE, *self.pins), timeout=120))
                require(revision_scope(before[5], selected, rows, available, self.prep.runner) == job.changes)
            scope()
            archives = tuple(metadata(self._apt(("apt-cache", "--no-all-versions", "show", pin)), change)
                             for pin, change in zip(self.pins, job.changes))
            require(sum(a.size for a in archives) <= MAX_TOTAL)
            require(not archive_names(self.files, self.workspace))
            self._phase("download-only")
            self._apt((*DOWNLOAD, *self.pins), timeout=600)
            self._phase("download-archive-verification")
            paths, found = [], {}
            for name in archive_names(self.files, self.workspace):
                path = self.workspace + "/cache/archives/" + name
                stamp = fingerprint(self.files, path, limit=MAX_DEB)
                matches = [a for a in archives if (a.size, a.sha256) == (stamp[0][2], stamp[1])]
                require(len(matches) == 1 and matches[0].change.name not in found)
                archive = matches[0]
                result = self.prep.runner(ArchiveCommand(("dpkg-deb", "--field", path, "Package", "Version", "Architecture"),
                                                         workspace=self.workspace))
                require(isinstance(result, Reply) and result.code == 0 and not result.uncertain)
                require(fields(result.output) == {"package": archive.change.name, "version": archive.change.after,
                                                  "architecture": archive.change.architecture})
                require(fingerprint(self.files, path, limit=MAX_DEB) == stamp)
                paths.append((path, stamp))
                found[archive.change.name] = archive
            require(len(found) == len(archives))
            self._phase("download-final-recheck")
            scope()
            require(index_snapshot(self.files, self.workspace) == indexes and self._snapshot(watched) == before
                    and fingerprint(self.files, EXTENDED, limit=16 * 1024**2, optional=True) == extended)
            watched.recheck()
            self.files.write_new(job.apt_config, configuration(self.workspace, install=True), mode=0o644)
            batch = DownloadedPackages(job, archives, tuple(paths), indexes, extended)
            batch.verify(self.files)
            return batch
