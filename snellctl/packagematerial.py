"""Private material persistence; a saved document is never update authority."""

from dataclasses import asdict, dataclass
import hashlib
import json
import stat

from .domaininventory import Inventory
from .packagecontents import require
from .packagedownload import CACHE, fingerprint


MATERIAL_LIMIT = 8 * 1024**2


@dataclass(frozen=True)
class SavedMaterial:
    job: object
    path: str
    directory_identity: tuple
    document_stamp: tuple
    receipt_stamp: tuple

    def verify(self, prep, material):
        """Bind the exact displayed files to this in-memory review, including mode."""
        files = prep.files
        directory = CACHE + "/" + self.job.job_id + "/review"
        require(material.batch.job == self.job and self.path == directory + "/material.json")
        with files.directory(directory, private=True):
            require(tuple(files.identity(directory)) == self.directory_identity)
            for path, stamp, limit in ((self.path, self.document_stamp, MATERIAL_LIMIT + 1),
                                       (directory + "/complete.json", self.receipt_stamp, 65536)):
                require(stat.S_IMODE(files.info(path).st_mode) == 0o600
                        and fingerprint(files, path, limit=limit) == stamp)
            expected = material.document.encode("ascii") + b"\n"
            require(self.document_stamp[1] == hashlib.sha256(expected).hexdigest())
        return True


def save_material(prep, plan, material, report, phase):
    files, job = prep.files, material.batch.job
    with prep._lock():
        prep._no_pending_change()
        watched = Inventory(files)
        before = plan._snapshot(watched)
        material.verify(prep)
        document = material.document.encode("ascii") + b"\n"
        require(len(document) <= MATERIAL_LIMIT + 1)
        directory = CACHE + "/" + job.job_id + "/review"
        phase("private-material-write")
        report["material_write_attempted"] = True
        files.private_directory_new(directory)
        path = directory + "/material.json"
        files.write_new(path, document)
        stamp = fingerprint(files, path, limit=MATERIAL_LIMIT + 1)
        require(stamp[0][2] == len(document) and stamp[1] == hashlib.sha256(document).hexdigest()
                and files.read(path, mode=0o600, limit=MATERIAL_LIMIT + 1) == document)
        phase("saved-material-recheck")
        material.verify(prep)
        require(plan._snapshot(watched) == before)
        watched.recheck()
        require(fingerprint(files, path, limit=MATERIAL_LIMIT + 1) == stamp)
        receipt = (json.dumps({"format": 1, "operation": "package-review-material", "job_id": job.job_id,
                              "material_bytes": len(document), "material_sha256": stamp[1],
                              "changes": [asdict(c) for c in job.changes],
                              "security_audit_passed": False, "update_authorized": False,
                              "reusable_for_installation": False}, sort_keys=True) + "\n").encode("ascii")
        with files.directory(directory, private=True):
            files.write_new(directory + "/complete.json", receipt)
            require(files.read(directory + "/complete.json", mode=0o600) == receipt)
            saved = SavedMaterial(job, path, tuple(files.identity(directory)), stamp,
                                  fingerprint(files, directory + "/complete.json", limit=65536))
            saved.verify(prep, material)
        report.update(material_saved_verified=True, review_receipt_saved=True, material_summary=material.summary())
        return saved
