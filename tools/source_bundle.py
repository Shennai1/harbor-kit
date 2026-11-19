"""Build a local, unsigned source bundle from the reviewed public allowlist."""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile

from .public_source import ExportError, collect


class BundleError(Exception):
    pass


def build(root, output):
    root = Path(root).resolve(strict=True)
    output = Path(output)
    parent = output.parent.resolve(strict=True)
    target = parent / output.name
    if target == root or (root in target.parents and root / "work" not in target.parents):
        raise BundleError("Use a new output directory outside source, or below work/.")
    snapshot = collect(root)
    if not snapshot["tree_elements"]:
        raise BundleError("Public source is empty.")
    for entry in snapshot["tree_elements"]:
        name = entry["path"]
        path = PurePosixPath(name)
        if (path.is_absolute() or ".." in path.parts or str(path) != name
                or "\\" in name or entry["mode"] != "100644" or entry["type"] != "blob"):
            raise BundleError("Unexpected archive path or file type.")

    target.mkdir(mode=0o700)
    name = "harbor-kit-source-" + snapshot["snapshot_sha256"] + ".tar.gz"
    archive = target / name
    # No source timestamps, local user names or gzip output filename enter the archive.
    with archive.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for entry in snapshot["tree_elements"]:
                    data = entry["content"].encode("utf-8")
                    info = tarfile.TarInfo("harbor-kit-source/" + entry["path"])
                    info.size, info.mode, info.mtime = len(data), 0o644, 0
                    tar.addfile(info, io.BytesIO(data))
    if collect(root)["snapshot_sha256"] != snapshot["snapshot_sha256"]:
        raise BundleError("Source changed during packaging; retain partial output for inspection.")
    manifest = {
        "format": 1,
        "kind": "local-public-source-bundle",
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "archive": {"name": name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "bytes": archive.stat().st_size, "root": "harbor-kit-source", "file_mode": "0644"},
        "files": snapshot["files"],
        "source_revision": "not-verified",
        "tests_run_by_builder": False,
        "signed": False,
        "formal_release": False,
    }
    data = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with (target / "manifest.json").open("xb") as stream:
        stream.write(data)
    checksums = (manifest["archive"]["sha256"] + "  " + name + "\n"
                 + hashlib.sha256(data).hexdigest() + "  manifest.json\n")
    with (target / "SHA256SUMS").open("x", encoding="ascii") as stream:
        stream.write(checksums)
    return {"operation": "source-bundle", "result": "built-not-published", "signed": False,
            "tests_run_by_builder": False, "snapshot_sha256": snapshot["snapshot_sha256"],
            "archive_sha256": manifest["archive"]["sha256"], "public_files": len(snapshot["files"])}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build unsigned public source; no upload, install or tests.")
    parser.add_argument("--output", required=True, type=Path, help="new directory; parent must exist")
    args = parser.parse_args(argv)
    try:
        result = build(Path(__file__).resolve().parents[1], args.output)
    except KeyboardInterrupt:
        print("Source bundle interrupted; retain partial output, do not publish it.", file=sys.stderr)
        return 130
    except (OSError, ExportError, BundleError, tarfile.TarError, ValueError):
        print("Source bundle stopped; do not publish partial output or overwrite it. No automatic cleanup.", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
