"""Reviewed binary baselines and offline selection rules, not an updater.

Changing a baseline alone is not a deployment migration. Existing records and
templates still require an independently reviewed update implementation.
"""

from dataclasses import dataclass
import re


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


@dataclass(frozen=True)
class Program:
    artifact: Artifact
    protocol: int
    version_prefix: str

    @property
    def binary_path(self):
        item = self.artifact
        return f"/opt/snellctl/{item.name}/{item.version}/{item.binary}"

    def matches_version_output(self, output):
        if not isinstance(output, str) or len(output) > 65536:
            return False
        # Snell prefixes its version line with a timestamp. Require one version
        # marker, not an arbitrary occurrence of the desired numeric substring.
        versions = re.findall(r"(?<![\w-])" + re.escape(self.version_prefix) + r"([^\s]+)", output)
        return versions == [self.artifact.version]


BASELINES = (
    Program(Artifact(
        "snell", "5.0.1",
        "https://dl.nssurge.com/snell/snell-server-v5.0.1-linux-amd64.zip",
        "9bea1c2b9e35b73b31634856c04d18c393072b9e5dcde6a32781d8b8f908c539",
        "snell.zip", "snell-server", True, 8 * 1024**2, 32 * 1024**2,
        ("dl.nssurge.com",),
    ), 5, "snell-server v"),
    Program(Artifact(
        "shadow-tls", "0.2.25",
        "https://github.com/ihciah/shadow-tls/releases/download/v0.2.25/"
        "shadow-tls-x86_64-unknown-linux-musl",
        "a173f5f2d57f45211b68e10ceeddc15b1791077b914fa89747bc705fddc71532",
        "shadow-tls", "shadow-tls", False, 32 * 1024**2, 32 * 1024**2,
        ("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"),
    ), 3, "shadow-tls "),
)
CATALOG = tuple(program.artifact for program in BASELINES)
VERSION_COMMANDS = frozenset((program.binary_path, "--version") for program in BASELINES)


def baseline(component):
    matches = [program for program in BASELINES if type(component) is str and program.artifact.name == component]
    if len(matches) != 1:
        raise ValueError("Unsupported or ambiguous component; input omitted.")
    return matches[0]


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){2}", value):
        raise ValueError("Expected a canonical three-part version; input omitted.")
    return tuple(int(part) for part in value.split("."))


def compare_versions(component, current, target):
    """Only compare caller-supplied numbers; never select a download or command."""
    program = baseline(component)
    before, after = _version(current), _version(target)
    if current != program.artifact.version:
        decision = "current-version-not-reviewed"
    elif before == after:
        decision = "same-reviewed-version-no-action"
    elif after < before:
        decision = "downgrade-not-supported"
    elif component == "snell" and after[0] != program.protocol:
        decision = "protocol-migration-required"
    else:
        # A ShadowTLS program version is not its wire protocol version. Unknown
        # releases need review even when the numeric change looks like a patch.
        decision = "target-version-not-reviewed"
    return {
        "format": 1, "operation": "offline-version-comparison", "component": component,
        "current": current, "target": target, "decision": decision,
        "version_basis": "caller-supplied-not-host-observation",
        "managed_protocol": program.protocol, "host_checked": False, "upstream_checked": False,
        "security_patch_status": "not-assessed", "host_changes_attempted": False,
        "download_attempted": False, "update_implemented": False,
        "update_authorized": False, "update_ready": False,
    }
