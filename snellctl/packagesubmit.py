"""Internal one-time package submission and read-only recovery observation.

Not a complete upgrader: no CLI, default live runner, service restoration,
package-record migration or success finalizer. Never retry uncertain submission.
"""

from dataclasses import asdict
import hashlib
import json
import os
import re

from . import aptreview as apt
from . import packagebaseline
from .hostprep import Command, PreparationError, Reply, STATE
from .packagedownload import CACHE, DownloadCommand, DownloadedPackages, InstallSimulationCommand
from .packageguards import GuardLease, INTENT
from .packagejob import JobObserver, JobSpec
from .packagepolicy import RevisionChange, revision_scope
from .preflight import DEPENDENCIES


def require(condition):
    if not condition:
        raise PreparationError("Package submission requires inspection; never retry or remove its records.")


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode("ascii")


def update_intent(job):
    return {"format": 1, "operation": "package-update", "job_id": job.job_id,
            "changes": [asdict(c) for c in job.changes], "outage_confirmed": True}


def snapshot(files, path, mode):
    data = files.read(path, mode=mode)
    return {"identity": files.identity(path), "sha256": hashlib.sha256(data).hexdigest()}


def read_active_job(files):
    """Caller holds the preparation lock; no caller-supplied task selection."""
    path = STATE + "/" + INTENT + ".json"
    before = snapshot(files, path, 0o600)
    data = files.read(path, mode=0o600)
    value = json.loads(data)
    require(type(value) is dict and type(value.get("changes")) is list and 1 <= len(value["changes"]) <= 8)
    job = JobSpec(value["job_id"], tuple(RevisionChange(**c) for c in value["changes"]))
    # Canonical bytes reject duplicate keys, altered authority and booleans as integers.
    require(data == encoded(update_intent(job)) and snapshot(files, path, 0o600) == before)
    return job, before


def expected_files(job):
    return {job.unit_path: (0o644, job.unit_bytes()),
            job.directory + "/launch.py": (0o600, job.launcher_bytes()),
            job.directory + "/armed.json": (0o600, job.authority_bytes("armed")),
            job.directory + "/submission-attempt.json": (0o600, job.authority_bytes("submission-attempt"))}


def _reply(result):
    require(isinstance(result, Reply) and not result.uncertain and result.code == 0)
    require(isinstance(result.output, str) and not any(
        line.lstrip().startswith(("W:", "E:", "N:")) for line in result.output.splitlines()))
    return result.output


def _scope(lease, batch):
    job, files, runner = batch.job, lease.engine.files, lease.engine.prep.runner
    pins = tuple(c.name + "=" + c.after for c in job.changes)
    names = sorted(set(DEPENDENCIES) | {c.name for c in job.changes})
    command = DownloadCommand(("apt-cache", "madison", *names), capture_stderr=True,
                              workspace=CACHE + "/" + job.job_id, pins=pins)
    command.verify_files(files)
    available = apt.repository_versions(_reply(runner(command)), names)
    command = InstallSimulationCommand(job.install_argv(simulate=True), 120, capture_stderr=True, job=job)
    command.verify_files(files)
    rows = apt.simulation(_reply(runner(command)))
    selected = {n: next((c.after for c in job.changes if c.name == n), v) for n, v in lease.before[1].items()}
    require(revision_scope(lease.before[2], selected, rows, available, runner) == job.changes)


def _vacant(files, job):
    for path in (job.unit_path, "/run/systemd/system/" + job.unit,
                 "/usr/lib/systemd/system/" + job.unit):
        require(files.info(path) is None and files.info(path + ".d") is None)
    for name in ("submission-intent.json", "submission-ready.json", "submission-attempt.json",
                 "submission-result.json", "armed.json", "execution-claim.json", "launch.py", "apt.log", "home",
                 packagebaseline.NAME):
        require(files.info(job.directory + "/" + name) is None)


def _unused_runtime(files, job):
    with files.directory(job.directory + "/home", private=True) as fd:
        require(not os.listdir(fd))
    require(files.read(job.directory + "/apt.log", mode=0o600, limit=1) == b"")
    require(files.info(job.directory + "/execution-claim.json") is None)
    return (files.identity(job.directory + "/home"), files.identity(job.directory + "/apt.log"))


def submit(lease, batch, *, consent=False, review_confirmed=False):
    """Submit at most once from an active guard lease; never finalize an upgrade.

    review_confirmed is an explicit caller assertion of separate module/script
    review, not an automatic audit. The staged coordinator requires that review
    and independently rechecks its inputs before reaching this internal API.
    """
    require(type(lease) is GuardLease and type(batch) is DownloadedPackages
            and lease.active and lease.job == batch.job and consent is True and review_confirmed is True)
    require(tuple(a.change for a in batch.archives) == batch.job.changes)
    engine, job = lease.engine, batch.job
    files, prep = engine.files, engine.prep
    report = {"format": 1, "operation": "package-job-submit", "result": "blocked-before-submission",
              "host_changes_attempted": False, "submission_attempted": False, "submission_acknowledged": False,
              "upgrade_completed": False, "postchecks_required": True, "automatic_retry": False,
              "guard_removal_attempted": False, "report_saved": False, "phase": "preflight"}
    record_started = False
    try:
        lease.verify()
        batch.verify(files)
        _vacant(files, job)
        _scope(lease, batch)
        lease.verify()
        batch.verify(files)
        require(not prep._run(["dpkg", "--audit"]).strip())
        report["phase"] = "restoration-baseline"
        report["host_changes_attempted"] = True
        packagebaseline.save(lease, batch)
        baseline_stamp = snapshot(files, job.directory + "/" + packagebaseline.NAME, 0o600)
        report["phase"] = "submission-intent"
        files.write_new(job.directory + "/submission-intent.json", encoded({
            "format": 1, "job_id": job.job_id, "review_confirmed": True, "upgrade_consent": True}))
        record_started = True
        report["phase"] = "private-launcher-and-unit"
        files.private_directory_new(job.directory + "/home")
        files.write_new(job.directory + "/apt.log", b"")
        runtime_stamp = _unused_runtime(files, job)
        files.write_new(job.directory + "/launch.py", job.launcher_bytes())
        files.write_new(job.unit_path, job.unit_bytes(), mode=0o644)
        unit_stamp = snapshot(files, job.unit_path, 0o644)
        launcher_stamp = snapshot(files, job.directory + "/launch.py", 0o600)
        prep._run(["systemd-analyze", "verify", job.unit_path])
        prep._run(["systemctl", "daemon-reload"])
        report["phase"] = "loaded-job-check"
        require(JobObserver(job, files, prep.runner).sample().state == "not-started")
        lease.verify()
        batch.verify(files)
        require(snapshot(files, job.unit_path, 0o644) == unit_stamp
                and snapshot(files, job.directory + "/launch.py", 0o600) == launcher_stamp)
        report["phase"] = "durable-attempt"
        # Even a crash before systemctl is called leaves a non-retryable attempt.
        files.write_new(job.directory + "/submission-attempt.json", job.authority_bytes("submission-attempt"))
        files.write_new(job.directory + "/armed.json", job.authority_bytes("armed"))
        files.write_new(job.directory + "/submission-ready.json", encoded({
            "format": 2, "job_id": job.job_id, "restoration_baseline": baseline_stamp,
            "files": {p: snapshot(files, p, mode) for p, (mode, _) in expected_files(job).items()},
            "maintenance_intent": snapshot(files, STATE + "/" + INTENT + ".json", 0o600)}))
        lease.verify()
        batch.verify(files)
        _submission_records(files, job)
        require(_unused_runtime(files, job) == runtime_stamp)
        report["phase"] = "submit-once"
        report["submission_attempted"] = True
        # Only this enqueue command is timed out; APT is a separate systemd job.
        result = prep.runner(Command(("systemctl", "start", "--no-block", job.unit), timeout=30))
        report["submission_acknowledged"] = (isinstance(result, Reply) and result.code == 0
                                               and not result.uncertain and not result.output)
        report["result"] = "submitted-postchecks-required" if report["submission_acknowledged"] else "submission-uncertain-inspect-only"
    except (KeyboardInterrupt, EOFError):
        report["result"] = "interrupted-inspect-only"
    except Exception:
        report["result"] = "submission-uncertain-inspect-only" if report["submission_attempted"] else "blocked-before-submission"
    if record_started:
        try:
            report["report_saved"] = True
            files.write_new(job.directory + "/submission-result.json", encoded(report))
        except (KeyboardInterrupt, EOFError):
            report.update(report_saved=False, result="interrupted-inspect-only")
        except (OSError, PreparationError):
            report["report_saved"] = False
    return report


def _submission_records(files, job):
    with files.directory(job.directory, private=True):
        pass
    expected = encoded(update_intent(job))
    require(files.read(STATE + "/" + INTENT + ".json", mode=0o600) == expected)
    require(files.read(job.directory + "/submission-intent.json", mode=0o600) == encoded({
        "format": 1, "job_id": job.job_id, "review_confirmed": True, "upgrade_consent": True}))
    raw = files.read(job.directory + "/submission-ready.json", mode=0o600)
    ready = json.loads(raw)
    require(isinstance(ready, dict) and type(ready.get("format")) is int and ready["format"] in {1, 2})
    keys = {"format", "job_id", "files", "maintenance_intent"}
    if ready["format"] == 2:
        keys.add("restoration_baseline")
        require(snapshot(files, job.directory + "/" + packagebaseline.NAME, 0o600) == ready.get("restoration_baseline"))
    require(set(ready) == keys and ready["job_id"] == job.job_id)
    require(isinstance(ready["files"], dict) and set(ready["files"]) == set(expected_files(job)))
    for path, (mode, data) in expected_files(job).items():
        require(files.read(path, mode=mode) == data and snapshot(files, path, mode) == ready["files"][path])
    require(snapshot(files, STATE + "/" + INTENT + ".json", 0o600) == ready["maintenance_intent"])
    return snapshot(files, job.directory + "/submission-ready.json", 0o600)


def _claim(files, job):
    path = job.directory + "/execution-claim.json"
    if files.info(path) is None:
        return None
    raw = files.read(path, mode=0o600, limit=4096)
    value = json.loads(raw)
    require(isinstance(value, dict) and set(value) == {"format", "job_id", "invocation"}
            and type(value["format"]) is int and value["format"] == 1 and value["job_id"] == job.job_id
            and isinstance(value["invocation"], str) and re.fullmatch(r"[0-9a-f]{32}", value["invocation"]))
    require(raw == encoded(value))
    return value, snapshot(files, path, 0o600)


def observe_submission(prep, job):
    """Read-only snapshot after disconnect; does not authorize resubmission."""
    require(type(job) is JobSpec)
    report = {"format": 1, "operation": "package-submission-observation", "result": "inspection-required",
              "host_changes_attempted": False, "task_stop_attempted": False, "automatic_retry": False,
              "upgrade_completed": False, "postchecks_required": True, "execution_claim_matches": False}
    try:
        with prep._lock():
            before = _submission_records(prep.files, job)
            claim = _claim(prep.files, job)
            observed = JobObserver(job, prep.files, prep.runner).sample()
            require(_submission_records(prep.files, job) == before and _claim(prep.files, job) == claim)
            if claim is None:
                if observed.state in {"not-started", "running-or-queued"}:
                    report["result"] = "execution-not-proven-do-not-resubmit"
            else:
                require(observed.invocation == claim[0]["invocation"])
                report.update(result=observed.state, execution_claim_matches=True)
    except (KeyboardInterrupt, EOFError):
        report["result"] = "observation-interrupted-task-not-stopped"
    except Exception:
        pass
    return report
