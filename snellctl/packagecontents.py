"""Bounded, non-extracting inspection of an already authenticated Debian archive."""

from dataclasses import dataclass
import hashlib
import json
import os
import selectors
import subprocess
import tarfile
import tempfile
import time

from .hostprep import Command, PreparationError, Reply
from .packagedownload import ArchiveCommand, MAX_DEB, fingerprint


LIMITS = {"--ctrl-tarfile": 4 * 1024**2, "--fsys-tarfile": 128 * 1024**2}
TEXT_LIMIT = 128 * 1024
REPORT_LIMIT = 4 * 1024**2
CONTROL_NAMES = frozenset({"control", "preinst", "postinst", "prerm", "postrm", "config",
                           "conffiles", "triggers", "templates", "md5sums", "shlibs", "symbols"})
SCRIPT_NAMES = frozenset({"preinst", "postinst", "prerm", "postrm", "config"})


def require(value):
    if not value:
        raise PreparationError("Package contents require separate inspection; nothing was executed or extracted.")


@dataclass(frozen=True)
class ContentsCommand(Command):
    workspace: str = ""
    expected: tuple = ()

    def verify_files(self, files):
        require(len(self.argv) == 3 and self.argv[0] == "dpkg-deb" and self.argv[1] in LIMITS)
        ArchiveCommand(("dpkg-deb", "--field", self.argv[2], "Package", "Version", "Architecture"),
                       self.timeout, self.env, self.capture_stderr, self.workspace).validate()
        require(fingerprint(files, self.argv[2], limit=MAX_DEB) == self.expected)


def path_name(value, *, directory=False):
    require(isinstance(value, str) and len(value) <= 1024 and not value.startswith("/"))
    if value.startswith("./"):
        value = value[2:]
    if directory:
        value = value.removesuffix("/")
    if value in {"", "."}:
        require(directory)
        return "."
    require(not value.startswith("/") and all(p not in {"", ".", ".."} for p in value.split("/"))
            and all(32 <= ord(c) < 127 for c in value))
    return value


def inspect_tar(stream, kind):
    """Parse tar metadata/regular bytes only; never follow links or call extract()."""
    require(kind in LIMITS)
    control = kind == "--ctrl-tarfile"
    rows, seen, text_total = [], set(), 0
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        for item in archive:
            require(len(rows) < (64 if control else 10000))
            name = path_name(item.name, directory=item.isdir())
            require(name not in seen and item.sparse is None and not item.pax_headers
                    and item.type in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE}
                    and 0 <= item.size <= LIMITS[kind] and 0 <= item.mode <= 0o7777
                    and item.uid >= 0 and item.gid >= 0 and (item.isfile() or item.size == 0))
            seen.add(name)
            if control:
                require((name == "." and item.isdir()) or (name in CONTROL_NAMES and item.isfile()))
            row = {"path": name, "kind": "file" if item.isfile() else "directory" if item.isdir() else
                   "symlink" if item.issym() else "hardlink", "mode": format(item.mode, "04o"), "size": item.size,
                   "uid": item.uid, "gid": item.gid}
            if item.issym() or item.islnk():
                require(0 < len(item.linkname) <= 1024 and all(32 <= ord(c) < 127 for c in item.linkname))
                # Targets are inventory text only, never opened or resolved.
                row["target"] = item.linkname
            if item.isfile():
                digest = hashlib.sha256()
                content, total = [], 0
                with archive.extractfile(item) as source:
                    while chunk := source.read(65536):
                        total += len(chunk)
                        digest.update(chunk)
                        if control and name != "md5sums":
                            require(total <= TEXT_LIMIT)
                            content.append(chunk)
                require(total == item.size)
                row["sha256"] = digest.hexdigest()
                if control and name != "md5sums":
                    data = b"".join(content)
                    text_total += len(data)
                    require(text_total <= 512 * 1024)
                    row["text"] = data.decode("utf-8", errors="strict")
                    require("\x00" not in row["text"])
            rows.append(row)
        # Do not accept a second hidden archive after the tar end markers.
        stream.seek(archive.offset)
        tail = stream.read()
        require(len(tail) >= 1024 and not any(tail))
    require(rows and (not control or "control" in seen))
    result = json.dumps({"format": 1, "kind": kind, "entries": rows}, ensure_ascii=True, sort_keys=True)
    require(len(result) <= REPORT_LIMIT)
    return result


def _capture(process, output, *, limit, timeout):
    """Bound producer output on disk and by elapsed time, including blocked pipes."""
    deadline, total = time.monotonic() + timeout, 0
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            require(selector.select(remaining))
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            total += len(chunk)
            require(total <= limit)
            output.write(chunk)
    require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0 and total > 0)
    output.seek(0)


def inspect_command(command, files, stop):
    """Adapter-only path. `stop` can stop this read-only decoder, never APT."""
    require(type(command) is ContentsCommand)
    command.verify_files(files)
    process = None
    try:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(["/usr/bin/dpkg-deb", *command.argv[1:]], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=dict(command.env), cwd="/",
                start_new_session=True, umask=0o077)
            completed = False
            try:
                _capture(process, output, limit=LIMITS[command.argv[1]], timeout=command.timeout)
                result = inspect_tar(output, command.argv[1])
                command.verify_files(files)
                completed = True
                return Reply(0, result)
            finally:
                if not completed or process.poll() is None:
                    stop(process)
                process.stdout.close()
    except (OSError, ValueError, UnicodeError, tarfile.TarError, PreparationError, subprocess.TimeoutExpired):
        return Reply(-1, uncertain=True)
