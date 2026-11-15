"""Internal update coordinator and narrowly gated post-install continuation.

No CLI, default live runner, automatic module/script approval, reboot recovery
or installation retry. Reconnect can only enter restoration before its first
attempt, after the original background invocation has certainly succeeded.
"""

import json
import os

from .activation import _binding
from . import packagebaseline as baseline
from .client import _read_deployment_snapshot
from .domaininventory import Inventory
from .hostprep import PreparationError, STATE
from .maintenance import Maintenance
from .packagedownload import DownloadedPackages, PackageDownloads
from .packagefinish import PackageFinish, RestorationEvidence
from .packageguards import PackageGuards, RestorationLease, PRESERVED_PATHS
from .packagejob import JobObserver, JobSpec
from .packageplan import ALL_PACKAGES, package_rows
from .packagereview import collect as collect_review
from .packagesubmit import _claim, _submission_records, encoded, snapshot, submit


OTHER_PENDING = ("reinstall-intent", "uninstall-intent", "uninstall-ready", "retired-cleanup-intent",
                 "domain-change-intent", "key-rotation-intent", "port-change-intent", "token-change-intent")
RESTORE_PREFIXES = ("postinstall-", "nginx-restore-", "renewal-unmask-", "package-record-commit-",
                    "restoration-resume-")


def require(condition):
    if not condition:
        raise PreparationError("Package coordination requires inspection; no installation retry is permitted.")


class PackageFlow:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.files
        self.progress, self.phase = progress, "not-started"
        self.downloads = PackageDownloads(tokens, progress=self._phase)
        self.guards = PackageGuards(tokens, progress=self._phase)

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def run(self, job, *, review, confirm_download=False, confirm_outage=False, confirm_install=False,
            confirm_restore=False, confirm_dns_test=False, confirm_renewal=False, wait_budget=120):
        """Review must explicitly approve the freshly staged modules/scripts.

        The callback receives the verified batch, not an old simulated plan. No
        default approval exists. This internal API is not an operator interface.
        """
        require(type(job) is JobSpec and callable(review) and type(wait_budget) is int and 1 <= wait_budget <= 900
                and all(v is True for v in (confirm_download, confirm_outage, confirm_install,
                                            confirm_restore, confirm_dns_test, confirm_renewal)))
        return self._run(job, review=review, decision=lambda stage: True, verify_review=lambda: None,
                         wait_budget=wait_budget)

    def run_staged(self, job, *, review, confirm, wait_budget=120):
        """Internal staged interface; independent material review cannot default to yes.

        `review` receives bounded local-only ReviewMaterial, not a plan or hash.
        `confirm` receives a fixed stage identifier. Only exact True proceeds.
        No default live adapter, CLI, saved approval or automatic retry exists.
        """
        require(type(job) is JobSpec and callable(review) and callable(confirm)
                and type(wait_budget) is int and 1 <= wait_budget <= 900)
        material = None
        def review_batch(batch):
            nonlocal material
            self._phase("collect-package-review-material")
            material = collect_review(self.prep, batch)
            self._phase("independent-material-review")
            return review(material)
        def verify_review():
            require(material is not None)
            material.verify(self.prep)
        return self._run(job, review=review_batch, decision=confirm, verify_review=verify_review,
                         wait_budget=wait_budget)

    def _run(self, job, *, review, decision, verify_review, wait_budget):
        report = {"format": 1, "operation": "package-update-flow", "result": "stopped-inspection-required",
                  "cache_changes_attempted": False, "maintenance_attempted": False,
                  "upgrade_completed": False, "external_acceptance_required": True, "automatic_retry": False}
        try:
            self._phase("download-confirmation")
            if decision("download") is not True:
                report["result"] = "cancelled-before-download"
                return report
            self._phase("fresh-download")
            report["cache_changes_attempted"] = True
            batch = self.downloads.stage(job, consent=True)
            require(type(batch) is DownloadedPackages and batch.job == job)
            self._phase("staged-module-and-script-review")
            if review(batch) is not True:
                report["result"] = "review-not-approved-cache-preserved"
                return report
            self._phase("maintenance-confirmation")
            if decision("outage") is not True or decision("install") is not True:
                report["result"] = "cancelled-before-maintenance-cache-preserved"
                return report
            self._phase("review-input-recheck")
            batch.verify(self.files)
            verify_review()
            self._phase("maintenance-entry")
            report["maintenance_attempted"] = True
            with self.guards.protected(job, confirm_outage=True) as lease:
                self._phase("guarded-review-recheck")
                verify_review()
                self._phase("submit-once")
                report["submission"] = submit(lease, batch, consent=True, review_confirmed=True)
                if report["submission"]["result"] != "submitted-postchecks-required":
                    return report
                self._phase("observe-background-install")
                report["observation"] = JobObserver(job, self.files, self.prep.runner).wait(budget=wait_budget)
                if report["observation"]["result"] != "command-exited-success":
                    return report
                self._phase("restoration-confirmation")
                if any(decision(stage) is not True for stage in ("restore", "dns-test", "renewal")):
                    report["result"] = "restoration-not-authorized-inspection-required"
                    return report
                report["postinstall"] = PackageFinish(lease, batch, progress=self._phase).finish(
                    confirm_restore=True, confirm_dns_test=True, confirm_renewal=True)
                report["result"] = report["postinstall"]["result"]
        except (KeyboardInterrupt, EOFError):
            report["result"] = "interrupted-inspection-required"
        except Exception:
            pass
        finally:
            report["phase"] = self.phase
        return report

    def _resume_check(self, job):
        """Caller holds the original preparation lock; no state is written."""
        self._phase("resume-records-check")
        require(not any(self.prep._exists(name) for name in OTHER_PENDING))
        watched = Inventory(self.files)
        Maintenance(self.tokens)._platform(watched)
        submission = _submission_records(self.files, job)
        ready = json.loads(self.files.read(job.directory + "/submission-ready.json", mode=0o600))
        require(ready["format"] == 2)
        saved = baseline.read(self.files, job)
        self.tokens._expect(job.directory + "/guards-ready.json", saved["guards_ready"], 0o600)
        guards = json.loads(self.files.read(job.directory + "/guards-ready.json", mode=0o600))
        with self.files.directory(job.directory, private=True) as fd:
            require(not any(name.startswith(RESTORE_PREFIXES) for name in os.listdir(fd)))
        self._phase("original-installation-result")
        claim = _claim(self.files, job)
        observer = JobObserver(job, self.files, self.prep.runner)
        observed = observer.sample()
        require(claim is not None and observed.state == "command-exited-success"
                and claim[0]["invocation"] == observed.invocation)
        self._phase("rebuild-original-baseline")
        spec, _keys, record = _read_deployment_snapshot(self.prep)
        spec = self.tokens.local._version(spec)
        require(record["binding"] == _binding(spec))
        self.tokens.public._validate_node(spec, record["ssh_port"])
        data = self.tokens._evidence(spec, record)
        versions = self.prep._read_record("packages-ready")["versions"]
        database = package_rows(self.prep._run(ALL_PACKAGES))
        for change in job.changes:
            require(database.get((change.name, change.architecture)) == (change.after, False))
            database[(change.name, change.architecture)] = (change.before, False)
        package_record = self.tokens._snapshot(STATE + "/packages-ready.json", 0o600)
        preserved = {path: (saved["vendor_files"][path] if path in baseline.VENDORS else
                           self.tokens._snapshot(path)) for path in PRESERVED_PATHS}
        before = data, versions, database, package_record, preserved
        require(baseline.digest(before) == saved["before_sha256"])
        lease = RestorationLease(self.guards, job, before)
        try:
            lease.owned = guards["owned"]
            evidence = RestorationEvidence(job, saved["extended_sha256"])
            finish = PackageFinish(lease, evidence, progress=self._phase)
            finish.observer = observer
            self._phase("paused-postinstall-check")
            finish._check()
            require(_submission_records(self.files, job) == submission and _claim(self.files, job) == claim
                    and baseline.read(self.files, job) == saved)
            watched.recheck()
            return lease, finish
        except BaseException:
            lease.active = False
            raise

    def resume(self, job, *, confirm_restore=False, confirm_dns_test=False, confirm_renewal=False):
        """One explicit continuation before any restoration attempt, never APT."""
        require(type(job) is JobSpec and all(v is True for v in (confirm_restore, confirm_dns_test, confirm_renewal)))
        report = {"format": 1, "operation": "package-restoration-resume", "result": "inspection-required",
                  "host_changes_attempted": False, "installation_submission_attempted": False,
                  "upgrade_completed": False, "external_acceptance_required": True, "automatic_retry": False,
                  "report_saved": False}
        lease, started = None, False
        try:
            with self.prep._lock():
                lease, finish = self._resume_check(job)
                self._phase("restoration-resume-intent")
                report["host_changes_attempted"] = True
                self.files.write_new(job.directory + "/restoration-resume-intent.json", encoded({
                    "format": 1, "job_id": job.job_id, "restore_confirmed": True,
                    "dns_test_confirmed": True, "renewal_confirmed": True}))
                started = True
                lease.resume_stamp = snapshot(self.files, job.directory + "/restoration-resume-intent.json", 0o600)
                report["postinstall"] = finish.finish(confirm_restore=True, confirm_dns_test=True, confirm_renewal=True)
                report["result"] = report["postinstall"]["result"]
        except (KeyboardInterrupt, EOFError):
            report["result"] = "interrupted-inspection-required"
        except Exception:
            pass
        finally:
            if lease is not None:
                lease.active = False
        report["phase"] = self.phase
        if started:
            try:
                report["report_saved"] = True
                self.files.write_new(job.directory + "/restoration-resume-result.json", encoded(report))
            except (OSError, PreparationError):
                report["report_saved"] = False
        return report
