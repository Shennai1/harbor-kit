"""Collect review material, not a security verdict or installation authorization."""

from dataclasses import dataclass
import hashlib
import json

from .domaininventory import Inventory
from .hostprep import Command, Reply
from .packagecontents import ContentsCommand, CONTROL_NAMES, SCRIPT_NAMES, REPORT_LIMIT, TEXT_LIMIT, require
from .packagedownload import CACHE, DownloadedPackages, fields
from .packageplan import ALL_PACKAGES, package_rows


INSTALLED_NAMES = CONTROL_NAMES - {"control"} | {"list"}
MODULES = "/etc/nginx/modules-enabled"


def _reply(prep, command, limit=REPORT_LIMIT):
    result = prep.runner(command)
    require(type(result) is Reply and result.code == 0 and result.uncertain is False
            and isinstance(result.output, str) and len(result.output) <= limit
            and "\ufffd" not in result.output)
    return result.output


def installed_controls(prep, change):
    listing = _reply(prep, Command(("dpkg-query", "--control-list", change.name)), 4096)
    names = listing.splitlines()
    require(names and len(names) == len(set(names)) and set(names) <= INSTALLED_NAMES)
    rows = []
    for name in sorted(names):
        text = _reply(prep, Command(("dpkg-query", "--control-show", change.name, name)),
                      512 * 1024 if name in {"list", "md5sums"} else TEXT_LIMIT)
        require("\x00" not in text)
        row = {"name": name, "sha256": hashlib.sha256(text.encode()).hexdigest()}
        if name not in {"list", "md5sums"}:
            row["text"] = text
        rows.append(row)
    return rows


def module_check(files):
    watched = Inventory(files)
    names, state = watched.scan(MODULES)
    require(state in {"missing", "observed"} and not names and not watched.issues)
    return watched


def database_check(prep, job):
    rows = package_rows(_reply(prep, Command(ALL_PACKAGES)))
    require(not any(n.startswith("libnginx-mod-") or n in {"nginx-full", "nginx-extras", "nginx-light"}
                    for n, _a in rows))
    for change in job.changes:
        require(rows.get((change.name, change.architecture)) == (change.before, False)
                and sum(n == change.name for n, _a in rows) == 1)
    return rows


@dataclass(frozen=True)
class ReviewMaterial:
    batch: DownloadedPackages
    document: str
    installed: tuple
    database: tuple
    modules: tuple

    def verify(self, prep):
        """Recheck the reviewed inputs before maintenance and again before submit."""
        self.batch.verify(prep.files)
        require(tuple(sorted(database_check(prep, self.batch.job).items())) == self.database)
        watched = module_check(prep.files)
        require(tuple(sorted(watched.watched.items())) == self.modules)
        observed = tuple(json.dumps(installed_controls(prep, c), sort_keys=True, ensure_ascii=True)
                         for c in self.batch.job.changes)
        require(observed == self.installed)
        watched.recheck()
        require(tuple(sorted(database_check(prep, self.batch.job).items())) == self.database)
        self.batch.verify(prep.files)

    def summary(self):
        """No script text or arbitrary archive paths in the shareable summary."""
        return {"format": 1, "operation": "package-material-review", "material_collected": True,
                "packages": [a.change.name for a in self.batch.archives], "security_audit_passed": False,
                "installation_authorized": False, "additional_nginx_modules": "not-supported",
                "installed_controls_compared": True, "report_saved": False}


def collect(prep, batch):
    require(type(batch) is DownloadedPackages and tuple(a.change for a in batch.archives) == batch.job.changes
            and len(batch.paths_and_fingerprints) == len(batch.archives))
    with prep._lock():
        prep._no_pending_change()
        batch.verify(prep.files)
        database = database_check(prep, batch.job)
        modules = module_check(prep.files)
        rows, old = [], []
        for change in batch.job.changes:
            matches = [a for a in batch.archives if a.change == change]
            require(len(matches) == 1)
            archive = matches[0]
            paths = [(p, stamp) for p, stamp in batch.paths_and_fingerprints if stamp[1] == archive.sha256]
            require(len(paths) == 1)
            path, stamp = paths[0]
            sections = {}
            for kind in ("--ctrl-tarfile", "--fsys-tarfile"):
                command = ContentsCommand(("dpkg-deb", kind, path), workspace=CACHE + "/" + batch.job.job_id,
                                          expected=stamp)
                command.verify_files(prep.files)
                text = _reply(prep, command)
                section = json.loads(text)
                require(type(section) is dict and set(section) == {"format", "kind", "entries"}
                        and section["format"] == 1 and section["kind"] == kind
                        and type(section["entries"]) is list and section["entries"])
                sections[kind] = section["entries"]
            control, data = sections["--ctrl-tarfile"], sections["--fsys-tarfile"]
            identity = [r for r in control if r["path"] == "control"]
            require(len(identity) == 1)
            values = fields(identity[0]["text"])
            require(values.get("package") == change.name and values.get("version") == change.after
                    and values.get("architecture") == change.architecture)
            require(not any((r["path"] in {"usr/lib/nginx/modules", "etc/nginx/modules-enabled"}
                             or r["path"].startswith(("usr/lib/nginx/modules/", "etc/nginx/modules-enabled/")))
                            and r["kind"] != "directory" for r in data))
            installed = installed_controls(prep, change)
            old.append(json.dumps(installed, sort_keys=True, ensure_ascii=True))
            previous = {r["name"]: r for r in installed}
            proposed = {r["path"]: r for r in control}
            comparison = {}
            for name in sorted(SCRIPT_NAMES | {"triggers", "conffiles"}):
                a, b = previous.get(name), proposed.get(name)
                comparison[name] = ("absent" if a is None and b is None else "added" if a is None else
                                    "removed" if b is None else "unchanged" if a["sha256"] == b["sha256"] else "changed")
            rows.append({"package": change.name, "before": change.before, "after": change.after,
                         "archive_sha256": archive.sha256, "installed_control_files": installed,
                         "candidate_control_files": control, "candidate_file_manifest": data,
                         "comparison": comparison})
        document = json.dumps({"format": 1, "security_audit_passed": False,
                              "local_review_only_do_not_publish": True, "packages": rows},
                             sort_keys=True, ensure_ascii=True, indent=2)
        require(len(document) <= 8 * 1024**2)
        material = ReviewMaterial(batch, document, tuple(old), tuple(sorted(database.items())),
                                  tuple(sorted(modules.watched.items())))
        material.verify(prep)
        return material
