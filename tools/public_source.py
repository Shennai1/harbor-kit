"""Export only explicitly reviewed public source files; never upload anything."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


PUBLIC_FILES = (
    ".gitignore", "README.md",
    "docs/cleanup-inventory.md", "docs/client-export.md", "docs/design.md",
    "docs/downloads-and-preflight.md", "docs/host-preparation.md", "docs/install-wizard.md",
    "docs/key-rotation.md", "docs/local-activation.md", "docs/new-host-acceptance.md", "docs/port-change.md", "docs/public-enablement.md",
    "docs/roadmap.md", "docs/source-delivery.md", "docs/storage.md",
    "snellctl/__init__.py", "snellctl/__main__.py", "snellctl/activation.py",
    "snellctl/artifacts.py", "snellctl/cleanup.py", "snellctl/client.py",
    "snellctl/deployment.py", "snellctl/doctor.py", "snellctl/hostcommands.py",
    "snellctl/hostprep.py", "snellctl/installer.py", "snellctl/menu.py",
    "snellctl/portchange.py", "snellctl/preflight.py", "snellctl/publish.py", "snellctl/rotation.py", "snellctl/sandbox_cli.py",
    "snellctl/storage.py", "snellctl/tlsprobe.py", "snellctl/tokenchange.py", "snellctl/tokendiag.py",
    "tests/fixtures/tls-test.cnf", "tests/test_activation.py", "tests/test_artifacts.py",
    "tests/test_cleanup.py", "tests/test_cli.py", "tests/test_client.py", "tests/test_confirmation.py",
    "tests/test_deployment.py", "tests/test_doctor.py", "tests/test_hostcommands.py",
    "tests/test_hostprep.py", "tests/test_installer.py", "tests/test_preflight.py",
    "tests/test_portchange.py", "tests/test_public_source.py", "tests/test_publish.py", "tests/test_resume.py", "tests/test_rotation.py", "tests/test_storage.py",
    "tests/test_tlsprobe.py", "tests/test_tokenchange.py", "tests/test_tokendiag.py", "docs/token-change.md", "tools/public_source.py",
)
SENSITIVE = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_|github_pat_|cfut_)[A-Za-z0-9_]{20,}"),
    re.compile(r"/Users/[A-Za-z0-9._-]+/"),
)
FILE_LIMIT = 256 * 1024
TOTAL_LIMIT = 2 * 1024 * 1024


class ExportError(Exception):
    pass


def collect(root):
    """Capture a bounded snapshot; filenames come only from the literal allowlist."""
    root = Path(root)
    entries = []
    summary = []
    total = 0
    if len(PUBLIC_FILES) != len(set(PUBLIC_FILES)):
        raise ExportError("Public allowlist contains duplicate paths.")
    for relative in sorted(PUBLIC_FILES):
        path = root / relative
        try:
            for parent in Path(relative).parents:
                if (root / parent).is_symlink():
                    raise ExportError("Symlink parent in public source: " + relative)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > FILE_LIMIT:
                    raise ExportError("Unexpected source file metadata: " + relative)
                data = stream.read(FILE_LIMIT + 1)
                after = os.fstat(stream.fileno())
                if (info.st_mtime_ns, info.st_size) != (after.st_mtime_ns, after.st_size):
                    raise ExportError("Source changed during export: " + relative)
            if len(data) > FILE_LIMIT:
                raise ExportError("Source file exceeds limit: " + relative)
            text = data.decode("utf-8")
        except (OSError, UnicodeError):
            raise ExportError("Cannot safely read public source: " + relative) from None
        if "\x00" in text or any(pattern.search(text) for pattern in SENSITIVE):
            raise ExportError("Potential sensitive or binary content; review locally: " + relative)
        total += len(data)
        if total > TOTAL_LIMIT:
            raise ExportError("Public source exceeds total size limit.")
        entries.append({"path": relative, "mode": "100644", "type": "blob", "content": text})
        summary.append({"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    snapshot = hashlib.sha256(json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"snapshot_sha256": snapshot, "file_count": len(entries), "total_bytes": total,
            "files": summary, "tree_elements": entries}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Review/export the fixed public-source allowlist. No upload or write.")
    parser.add_argument("--tree", action="store_true", help="include public file contents for repository delivery")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args(argv)
    if args.offset < 0 or not 1 <= args.limit <= 100:
        parser.error("invalid export range")
    try:
        report = collect(Path(__file__).resolve().parents[1])
    except ExportError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if args.tree:
        report["tree_elements"] = report["tree_elements"][args.offset:args.offset + args.limit]
        del report["files"]
    else:
        del report["tree_elements"]
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
