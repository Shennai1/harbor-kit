"""Private pre-install evidence, not a serialized credential or recovery grant.

Only a digest of the complete in-memory baseline is stored. Recovery rebuilds
it from unchanged live resources, reverses the exact reviewed package revisions
in memory, and compares the digest. It never writes those old versions back.
"""

from dataclasses import asdict
import hashlib
import json
import re

from .hostprep import PreparationError
from .packageguards import GuardLease
from .packagedownload import DownloadedPackages


NAME = "restoration-baseline.json"
BOOT = "/proc/sys/kernel/random/boot_id"
VENDORS = {"/usr/lib/systemd/system/nginx.service": "nginx-common",
           "/usr/lib/systemd/system/certbot.service": "certbot",
           "/usr/lib/systemd/system/certbot.timer": "certbot"}


def require(condition):
    if not condition:
        raise PreparationError("Package restoration evidence is incomplete; preserve the state.")


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode("ascii")


def boot_id(files):
    value = files.read(BOOT, limit=64).decode("ascii")
    require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", value))
    return value.strip()


def digest(before):
    data, versions, database, package_record, preserved = before
    plan, spec, record, credential, current, unchanged = data
    value = {"data": [asdict(plan), asdict(spec), record, credential, current, unchanged],
             "versions": versions, "database": [[*key, *row] for key, row in sorted(database.items())],
             "package_record": package_record, "preserved": preserved}
    return hashlib.sha256(encoded(value)).hexdigest()


def save(lease, batch):
    require(type(lease) is GuardLease and type(batch) is DownloadedPackages
            and lease.active and lease.job == batch.job)
    files = lease.engine.files
    value = {"format": 1, "job_id": lease.job.job_id, "changes": [asdict(c) for c in lease.job.changes],
             "boot_id": boot_id(files), "before_sha256": digest(lease.before),
             "vendor_files": {path: lease.before[4][path] for path in VENDORS},
             "extended_sha256": None if batch.extended_state is None else batch.extended_state[1],
             "guards_ready": lease.engine.tokens._snapshot(lease.job.directory + "/guards-ready.json", 0o600)}
    files.write_new(lease.job.directory + "/" + NAME, encoded(value))
    require(read(files, lease.job) == value)


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def _snapshot(value):
    return (type(value) is dict and set(value) == {"identity", "sha256"}
            and type(value["identity"]) is list and len(value["identity"]) == 2
            and all(type(n) is int and n >= 0 for n in value["identity"])
            and _hash(value["sha256"]))


def read(files, job):
    raw = files.read(job.directory + "/" + NAME, mode=0o600, limit=16384)
    value = json.loads(raw)
    require(type(value) is dict and set(value) == {"format", "job_id", "changes", "boot_id", "before_sha256",
                                                   "vendor_files", "extended_sha256", "guards_ready"})
    require(type(value["format"]) is int and value["format"] == 1 and value["job_id"] == job.job_id
            and value["changes"] == [asdict(c) for c in job.changes] and raw == encoded(value)
            and value["boot_id"] == boot_id(files) and _hash(value["before_sha256"])
            and (value["extended_sha256"] is None or _hash(value["extended_sha256"]))
            and type(value["vendor_files"]) is dict and set(value["vendor_files"]) == set(VENDORS)
            and all(_snapshot(s) for s in value["vendor_files"].values()) and _snapshot(value["guards_ready"]))
    return value
