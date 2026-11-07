"""Isolated APT index/simulation commands, never package installation."""

from dataclasses import dataclass
import re

from .hostprep import Command, PreparationError, SOURCES
from .preflight import DEPENDENCIES


CACHE = "/var/cache/snellctl/package-review"
VERSION = r"[0-9][A-Za-z0-9.+:~\-]{0,99}"
PACKAGE = r"[a-z0-9][a-z0-9+.-]{0,99}"
EMPTY_DIRS = ("parts", "sourceparts", "preferencesparts", "trustedparts")
EMPTY_FILES = ("main", "preferences", "trusted")
ORIGINS = {
    "https://deb.debian.org/debian trixie/main amd64 Packages",
    "https://deb.debian.org/debian trixie-updates/main amd64 Packages",
    "https://security.debian.org/debian-security trixie-security/main amd64 Packages",
}


def require(condition):
    if not condition:
        raise PreparationError("APT 检查输入、配置或输出不符合受限格式。")


def workspace_ok(path):
    return isinstance(path, str) and re.fullmatch(re.escape(CACHE) + r"/[0-9a-f]{32}", path) is not None


def version_ok(value):
    return isinstance(value, str) and re.fullmatch(VERSION, value, re.ASCII) is not None


def package_ok(value):
    return isinstance(value, str) and re.fullmatch(PACKAGE, value, re.ASCII) is not None


def configuration(path):
    require(workspace_ok(path))
    # APT_CONFIG is read BEFORE system fragments; -o/-c would be too late.
    options = {
        "Dir::Etc": path + "/etc",
        "Dir::Etc::main": path + "/etc/main",
        "Dir::Etc::parts": path + "/etc/parts",
        "Dir::Etc::sourcelist": path + "/etc/debian.sources",
        "Dir::Etc::sourceparts": path + "/etc/sourceparts",
        "Dir::Etc::preferences": path + "/etc/preferences",
        "Dir::Etc::preferencesparts": path + "/etc/preferencesparts",
        "Dir::Etc::trusted": path + "/etc/trusted",
        "Dir::Etc::trustedparts": path + "/etc/trustedparts",
        "Dir::State": path + "/state",
        "Dir::State::lists": path + "/lists",
        "Dir::State::status": "/var/lib/dpkg/status",
        "Dir::State::extended_states": path + "/state/extended_states",
        "Dir::Cache": path + "/cache",
        "Dir::Cache::archives": path + "/cache/archives",
        "Dir::Cache::pkgcache": "",
        "Dir::Cache::srcpkgcache": "",
        "Dir::Log": path + "/log",
        "APT::Architecture": "amd64",
        "APT::Sandbox::User": "_apt",
        "APT::Get::AllowUnauthenticated": "false",
        "APT::Get::Allow-Downgrades": "false",
        "APT::Get::Allow-Change-Held-Packages": "false",
        "Acquire::AllowInsecureRepositories": "false",
        "Acquire::AllowWeakRepositories": "false",
        "Acquire::AllowDowngradeToInsecureRepositories": "false",
        "Acquire::https::Verify-Peer": "true",
        "Acquire::https::Verify-Host": "true",
        "Acquire::Check-Valid-Until": "true",
        "Acquire::Check-Date": "true",
        "Acquire::https::Timeout": "30",
        "Acquire::Languages": "none",
        "Acquire::Retries": "0",
        "APT::Get::List-Cleanup": "false",
    }
    return (''.join(f'{key} "{value}";\n' for key, value in options.items())
            + '#clear APT::Architectures;\nAPT::Architectures { "amd64"; };\n').encode("ascii")


def prepare(files, path):
    require(workspace_ok(path) and files.info(path) is None)
    # Only public index/config data live here. Traversability preserves _apt sandboxing.
    for part in (path, path + "/etc", path + "/state", path + "/lists", path + "/cache",
                 path + "/cache/archives", path + "/log", *(path + "/etc/" + d for d in EMPTY_DIRS)):
        with files.directory(part, create=True):
            pass
    files.write_new(path + "/apt.conf", configuration(path), mode=0o644)
    files.write_new(path + "/etc/debian.sources", SOURCES, mode=0o644)
    for name in EMPTY_FILES:
        files.write_new(path + "/etc/" + name, b"", mode=0o644)


@dataclass(frozen=True)
class AptReviewCommand(Command):
    workspace: str = ""

    def validate(self):
        require(workspace_ok(self.workspace) and self.env == Command(("unused",)).env
                and self.capture_stderr is True and 0 < self.timeout <= 600)
        if self.argv == ("apt-get", "update", "--error-on=any"):
            return
        if self.argv == ("apt-cache", "policy", *DEPENDENCIES):
            return
        if self.argv[:2] == ("apt-cache", "madison"):
            names = self.argv[2:]
            require(0 < len(names) <= 128 and len(set(names)) == len(names) and all(package_ok(n) for n in names))
            return
        prefix = ("apt-get", "--simulate", "--no-remove", "--no-install-recommends", "install")
        require(self.argv[:len(prefix)] == prefix and len(self.argv) == len(prefix) + len(DEPENDENCIES))
        for name, arg in zip(DEPENDENCIES, self.argv[len(prefix):]):
            require(arg.startswith(name + "=") and version_ok(arg[len(name) + 1:]))

    def verify_files(self, files):
        self.validate()
        require(files.read(self.workspace + "/apt.conf", mode=0o644) == configuration(self.workspace))
        require(files.read(self.workspace + "/etc/debian.sources", mode=0o644) == SOURCES)
        for name in EMPTY_FILES:
            require(files.read(self.workspace + "/etc/" + name, mode=0o644) == b"")
        import os
        for name in EMPTY_DIRS:
            with files.directory(self.workspace + "/etc/" + name) as fd:
                require(not os.listdir(fd))


def candidates(output, installed):
    """Read only exact package headers/selection fields, not human origin labels."""
    result, selected, fields = {}, None, {}
    for line in output.splitlines():
        if line and not line[0].isspace():
            require(line.endswith(":") and line[:-1] in DEPENDENCIES)
            selected = line[:-1]
            require(selected not in result)
            result[selected], fields[selected] = {}, set()
        elif line.strip().startswith(("Installed:", "Candidate:")):
            require(selected is not None)
            key, value = line.strip().split(":", 1)
            value = value.strip()
            require(key not in fields[selected] and version_ok(value))
            fields[selected].add(key)
            result[selected][key] = value
    require(set(result) == set(DEPENDENCIES))
    require(all(fields[n] == {"Installed", "Candidate"} and result[n]["Installed"] == installed[n]
                for n in DEPENDENCIES))
    return {n: result[n]["Candidate"] for n in DEPENDENCIES}


def repository_versions(output, names):
    versions = {name: set() for name in names}
    for line in output.splitlines():
        if not line.strip():
            continue
        row = [field.strip() for field in line.split("|")]
        require(len(row) == 3 and row[0] in versions and version_ok(row[1]) and row[2] in ORIGINS)
        versions[row[0]].add(row[1])
    return versions


def simulation(output):
    changes, configured, summary = {}, {}, None
    for line in output.splitlines():
        if line.startswith(("Remv ", "Purg ")):
            raise PreparationError("模拟方案涉及删除，停止。")
        if line.startswith("Inst "):
            match = re.fullmatch(rf"Inst ({PACKAGE})(?::amd64)?(?: \[({VERSION})\])? "
                                 rf"\(({VERSION}) [^\r\n()]+ \[(amd64|all)\]\)", line)
            require(match is not None)
            name, old, new, arch = match.groups()
            require(name not in changes and len(changes) < 128)
            changes[name] = {"name": name, "installed": old, "candidate": new, "architecture": arch}
        elif line.startswith("Conf "):
            match = re.fullmatch(rf"Conf ({PACKAGE})(?::amd64)? \(({VERSION}) [^\r\n()]+ \[(amd64|all)\]\)", line)
            require(match is not None and match[1] not in configured)
            configured[match[1]] = (match[2], match[3])
        elif re.match(r"\d+ upgraded,", line):
            match = re.fullmatch(r"(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.", line)
            require(match is not None and summary is None)
            summary = tuple(map(int, match.groups()))
        elif re.match(r"(?:Inst|Conf|Remv|Purg)(?:\s|$)", line.strip()):
            raise PreparationError("无法完整识别模拟动作，停止。")
    require(summary is not None and summary[2] == 0 and set(changes) == set(configured))
    require(all(configured[n] == (item["candidate"], item["architecture"]) for n, item in changes.items()))
    require(summary[0] == sum(c["installed"] is not None for c in changes.values())
            and summary[1] == sum(c["installed"] is None for c in changes.values()))
    return list(changes.values())
