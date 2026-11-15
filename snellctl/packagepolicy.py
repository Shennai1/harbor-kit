"""Internal revision-update scope checks, not live review or authorization.

Inputs must come from a fresh locked review, never from an old JSON report.
Nothing here installs packages, starts services, or accepts a user-selected URL.
"""

from dataclasses import dataclass
import re

from .aptreview import package_ok, version_ok
from .hostprep import Command, PreparationError, Reply
from .preflight import DEPENDENCIES


ARCHITECTURES = {
    "ca-certificates": "all", "nginx": "amd64", "nginx-common": "all",
    "certbot": "all", "python3-certbot": "all", "python3-acme": "all",
    "python3-certbot-dns-cloudflare": "all", "python3-cloudflare": "all",
}


def require(condition):
    if not condition:
        raise PreparationError("Package revision scope requires separate review.")


def upstream(version):
    """Keep epoch and upstream exact; Debian ordering is delegated to dpkg."""
    require(version_ok(version))
    epoch, separator, rest = version.partition(":")
    if separator:
        require(re.fullmatch(r"0|[1-9][0-9]*", epoch) is not None and ":" not in rest)
    else:
        epoch, rest = "0", version
    name, separator, revision = rest.rpartition("-")
    require(bool(rest) and rest[0] in "0123456789"
            and (not separator or (name and re.fullmatch(r"[A-Za-z0-9.+~]+", revision) is not None)))
    # Native packages such as ca-certificates have no Debian revision separator.
    return epoch, name if separator else rest


@dataclass(frozen=True)
class RevisionChange:
    name: str
    architecture: str
    before: str
    after: str

    def __post_init__(self):
        require(isinstance(self.name, str) and self.name in ARCHITECTURES
                and self.architecture == ARCHITECTURES[self.name])
        require(version_ok(self.before) and version_ok(self.after) and self.before != self.after
                and upstream(self.before) == upstream(self.after))


def revision_scope(installed, selected, changes, available, runner):
    """Return immutable deltas; a nonempty result still does NOT permit execution.

    installed is package_rows()'s complete installed set; changes is simulation()'s
    complete action list; available is the fresh official-index version mapping.
    The caller must separately prove freshness, sources, guards and consent.
    """
    require(isinstance(installed, dict) and 0 < len(installed) <= 10000 and isinstance(selected, dict)
            and set(selected) == set(DEPENDENCIES) and all(version_ok(v) for v in selected.values()))
    require(isinstance(changes, list) and len(changes) <= len(ARCHITECTURES)
            and isinstance(available, dict) and callable(runner))
    normalized = {}
    for key, value in installed.items():
        require(isinstance(key, tuple) and len(key) == 2
                and isinstance(value, tuple) and len(value) == 2)
        name, arch = key
        require(package_ok(name) and isinstance(arch, str) and re.fullmatch(r"[a-z0-9-]{1,32}", arch)
                and version_ok(value[0]) and type(value[1]) is bool)
        if name in ARCHITECTURES:
            require(arch == ARCHITECTURES[name] and name not in normalized)
            normalized[name] = value
    require(all(n in normalized and normalized[n][1] is False for n in DEPENDENCIES))
    result = {}
    for row in changes:
        require(isinstance(row, dict)
                and set(row) == {"name", "architecture", "installed", "candidate"})
        delta = RevisionChange(row["name"], row["architecture"], row["installed"], row["candidate"])
        require(delta.name not in result and normalized.get(delta.name) == (delta.before, False))
        require(isinstance(available.get(delta.name), (set, frozenset))
                and delta.after in available[delta.name])
        reply = runner(Command(("dpkg", "--compare-versions", delta.after, "gt", delta.before)))
        require(isinstance(reply, Reply) and not reply.uncertain and reply.code == 0 and not reply.output)
        result[delta.name] = delta
    for name in DEPENDENCIES:
        require(isinstance(available.get(name), (set, frozenset)) and selected[name] in available[name])
        require((result[name].after if name in result else normalized[name][0]) == selected[name])
    # Debian's nginx binary and common files must remain at the same revision.
    if "nginx" in result or "nginx-common" in result:
        require("nginx-common" in normalized and normalized["nginx-common"][1] is False)
        require(all(normalized[n][0] == normalized["nginx"][0] for n in ("nginx", "nginx-common")))
        require(all((result[n].after if n in result else normalized[n][0]) == selected["nginx"]
                    for n in ("nginx", "nginx-common")))
    return tuple(result[name] for name in sorted(result))
