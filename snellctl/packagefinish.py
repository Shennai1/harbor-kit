"""Internal package postchecks and ordered service restoration.

Requires a locked original or separately revalidated restoration lease. It is
not a CLI, a reboot recovery API, a package repairer or an automatic retry.
No failure path kills Certbot, rolls back packages or removes remaining guards.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
import os
import re
import stat

from .activation import _binding, _digest
from .hostprep import Command, POLICY, POLICY_BYTES, STATE, UNITS, PreparationError, Reply
from .packagedownload import DownloadedPackages, EXTENDED, fingerprint
from .packageguards import GuardLease, RestorationLease, INTENT
from .packagejob import JobObserver, JobSpec
from .packagebaseline import VENDORS
from .packageplan import ALL_PACKAGES, package_rows
from .packagesubmit import _claim, _submission_records, encoded, snapshot
from .publish import _rules_digest
from .tokendiag import summarize
from .tokenchange import CURRENT, dry_run_args


def require(condition):
    if not condition:
        raise PreparationError("Package postchecks require inspection; no automatic recovery or retry.")


@dataclass(frozen=True)
class RestorationEvidence:
    job: JobSpec
    extended_sha256: str | None

    def __post_init__(self):
        require(type(self.job) is JobSpec and (self.extended_sha256 is None or
                (isinstance(self.extended_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", self.extended_sha256))))


class PackageFinish:
    def __init__(self, lease, batch, progress=lambda phase: None):
        require((type(lease), type(batch)) in {(GuardLease, DownloadedPackages),
                                              (RestorationLease, RestorationEvidence)}
                and lease.active and lease.job == batch.job)
        self.extended_sha256 = (batch.extended_sha256 if type(batch) is RestorationEvidence else
                               None if batch.extended_state is None else batch.extended_state[1])
        self.lease, self.batch, self.job = lease, batch, lease.job
        self.engine, self.tokens = lease.engine, lease.engine.tokens
        self.prep, self.files = self.tokens.prep, self.tokens.files
        self.progress, self.phase = progress, "not-started"
        self.data, self.versions, self.database, self.package_record, self.preserved = lease.before
        _plan, self.spec, self.record, self.credential, self.current, self.unchanged = self.data
        self.after = dict(self.versions)
        self.expected_database = dict(self.database)
        for change in self.job.changes:
            require(self.database.get((change.name, change.architecture)) == (change.before, False))
            self.expected_database[(change.name, change.architecture)] = (change.after, False)
            if change.name in self.after:
                self.after[change.name] = change.after
        self.observer = JobObserver(self.job, self.files, self.prep.runner)
        self.submission = self.claim = self.vendor_stamps = self.marker = None
        self.removed = set()
        self.committed = None

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def _write(self, name, value):
        self.files.write_new(self.job.directory + "/" + name + ".json", encoded(value))

    def _task(self):
        require(self.lease.active)
        self.tokens._expect(STATE + "/" + INTENT + ".json", self.lease.intent, 0o600)
        before = _submission_records(self.files, self.job)
        claim = _claim(self.files, self.job)
        observed = self.observer.sample()
        require(claim is not None and observed.state == "command-exited-success"
                and observed.invocation == claim[0]["invocation"])
        require(_submission_records(self.files, self.job) == before and _claim(self.files, self.job) == claim)
        if self.submission is None:
            self.submission, self.claim = before, claim
        require((before, claim) == (self.submission, self.claim))
        if type(self.lease) is RestorationLease and self.lease.resume_stamp is not None:
            self.tokens._expect(self.job.directory + "/restoration-resume-intent.json", self.lease.resume_stamp, 0o600)
        if self.marker is not None:
            self.tokens._expect(self.job.directory + "/postinstall-intent.json", self.marker, 0o600)

    def _packages(self):
        require(package_rows(self.prep._run(ALL_PACKAGES)) == self.expected_database
                and self.prep._installed() == self.after
                and not self.prep._run(["dpkg", "--audit"]).strip())
        # APT can replace this file without changing its contents. Content drift
        # is conservatively rejected, never repaired with automatic apt-mark writes.
        current = fingerprint(self.files, EXTENDED, limit=16 * 1024**2, optional=True)
        require((None if current is None else current[1]) == self.extended_sha256)
        expected = self.package_record if self.committed is None else self.committed
        self.tokens._expect(STATE + "/packages-ready.json", expected, 0o600)
        require(self.prep._read_record("packages-ready") ==
                {"versions": self.versions if self.committed is None else self.after})

    def _preserved(self, *, allow_renewal=False):
        self.tokens.local._verify_owned(self.spec, self.record["node"])
        self.tokens._expect_records(self.unchanged)
        if self.current is not None:
            self.tokens._expect(STATE + "/" + CURRENT + ".json", self.current, 0o600)
        else:
            require(not self.prep._exists(CURRENT))
        require(self.tokens._credential(self.prep.credential_path(self.spec)) == self.credential)
        if not allow_renewal:
            require(self.tokens._lineage(self.spec) == self.unchanged["lineage"])
        for path, value in self.preserved.items():
            if path not in VENDORS:
                self.tokens._expect(path, value)
        rules, hashes, running = self.tokens.public._firewall(self.record["ssh_port"])
        require(_rules_digest(rules) == self.record["rules_sha256"] and hashes == self.record["unchanged_ufw"]
                and _digest(json.dumps(running).encode()) == self.record["ipv4_input_sha256"])
        for unit in (self.spec.snell_service, self.spec.shadowtls_service):
            require(self.engine._fields(unit, ("ActiveState", "SubState", "UnitFileState")) ==
                    dict(ActiveState="active", SubState="running", UnitFileState="enabled"))
        for unit in UNITS:
            require(self.files.info("/run/systemd/system/" + unit) is None)
        self.engine._overrides(UNITS)

    def _vendor_files(self):
        changed = {c.name for c in self.job.changes}
        stamps = {}
        for path, package in VENDORS.items():
            text = self.files.read("/var/lib/dpkg/info/" + package + ".md5sums", limit=1024**2).decode("ascii")
            matches = [m[1] for line in text.splitlines()
                       if (m := re.fullmatch(r"([a-f0-9]{32})  " + re.escape(path.lstrip("/")), line))]
            content = self.files.read(path, mode=0o644)
            require(len(matches) == 1 and hashlib.md5(content, usedforsecurity=False).hexdigest() == matches[0])
            if package not in changed:
                self.tokens._expect(path, self.preserved[path])
            stamps[path] = snapshot(self.files, path, 0o644)
        if self.vendor_stamps is None:
            self.vendor_stamps = stamps
        require(stamps == self.vendor_stamps)
        require(self.tokens.local._version(self.spec) == self.spec and self.record["binding"] == _binding(self.spec))
        self.tokens.local._nginx_package_config()
        self.tokens.local._nginx_dump({"/etc/nginx/nginx.conf", "/etc/nginx/mime.types", self.spec.nginx_conf})
        self.prep._certbot_config()

    def _guards(self):
        require(set(self.lease.owned) == {POLICY, *("/etc/systemd/system/" + u for u in UNITS)})
        ready = json.loads(self.files.read(self.job.directory + "/guards-ready.json", mode=0o600))
        require(ready == {"format": 1, "owned": self.lease.owned, "packages_before": self.versions})
        for path, identity in self.lease.owned.items():
            if path in self.removed:
                require(self.files.info(path) is None)
                continue
            require(self.files.identity(path) == identity)
            if path == POLICY:
                require(self.files.read(path, mode=0o755) == POLICY_BYTES)
            else:
                info = self.files.info(path)
                require(stat.S_ISLNK(info.st_mode) and info.st_uid == os.geteuid()
                        and info.st_nlink == 1 and self.files.readlink(path) == "/dev/null")
                self.engine._masked(path.rsplit("/", 1)[-1])

    def _check(self, *, nginx=False, renewal_loaded=False, renewal_enabled=False):
        self._task()
        self._packages()
        self._preserved(allow_renewal=renewal_enabled)
        self._vendor_files()
        self._guards()
        if not nginx:
            require(not self.prep._run(["ss", "-H", "-lntu", "sport = :" + str(self.spec.tls_port)]).strip())
        else:
            hook = "/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-main-nginx"
            self.tokens.local._health(self.spec, self.record["node"], public_entry=True,
                                      check_guards=False, allowed_deploy_hook=hook)
            require(self.prep._run(["systemctl", "is-enabled", "nginx.service"]).strip() == "enabled")
        if renewal_loaded:
            self.tokens.public._renewal_health(self.spec, self.prep._read_record("renewal-enable-ready"),
                                               timer=renewal_enabled)
            for unit in ("certbot.service", "certbot.timer"):
                require(self.engine._fields(unit, ("NeedDaemonReload",)) == {"NeedDaemonReload": "no"})
            if not renewal_enabled:
                self.tokens._paused()
        self._packages()
        self._preserved(allow_renewal=renewal_enabled)
        self._task()

    def _remove_mask(self, unit):
        path = "/etc/systemd/system/" + unit
        self._guards()
        self.files.unlink_owned(path, self.lease.owned[path])
        self.removed.add(path)

    def finish(self, *, confirm_restore=False, confirm_dns_test=False, confirm_renewal=False):
        require(self.lease.active and confirm_restore is True and confirm_dns_test is True and confirm_renewal is True)
        report = {"format": 1, "operation": "package-postinstall", "result": "stopped-inspection-required",
                  "host_changes_attempted": False, "nginx_start_attempted": False, "local_tls_verified": False,
                  "renewal_test_attempted": False, "renewal_test_passed": False,
                  "package_record_committed": False, "renewal_enable_attempted": False,
                  "renewal_restored_verified": False, "guards_removed_verified": False,
                  "completion_recorded": False, "intent_removed_verified": False, "report_saved": False,
                  "upgrade_completed": False, "external_acceptance_required": True,
                  "automatic_retry": False, "partial_restoration_resume_supported": False,
                  "continuation_mode": "same-boot-before-restoration" if type(self.lease) is RestorationLease else "original-session"}
        started = False
        try:
            self._phase("postinstall-preflight")
            for name in ("postinstall-intent", "postinstall-result", "postinstall-complete"):
                require(self.files.info(self.job.directory + "/" + name + ".json") is None)
            self._check()
            self._phase("postinstall-intent")
            report["host_changes_attempted"] = True
            self._write("postinstall-intent", {"format": 1, "job_id": self.job.job_id,
                        "changes": [asdict(c) for c in self.job.changes], "versions_before": self.versions,
                        "versions_after": self.after, "restore_confirmed": True, "dns_test_confirmed": True,
                        "renewal_confirmed": True})
            started = True
            self.marker = self.tokens._snapshot(self.job.directory + "/postinstall-intent.json", 0o600)
            self._check()
            self._phase("nginx-restore")
            self._write("nginx-restore-attempt", {"format": 1})
            self._remove_mask("nginx.service")
            self.prep._run(["systemctl", "daemon-reload"])
            self.prep._run(["systemd-analyze", "verify", "nginx.service"])
            require(self.engine._fields("nginx.service", ("LoadState", "ActiveState", "SubState", "Job", "NeedDaemonReload")) ==
                    dict(LoadState="loaded", ActiveState="inactive", SubState="dead", Job="", NeedDaemonReload="no"))
            report["nginx_start_attempted"] = True
            self.prep._run(["systemctl", "start", "nginx.service"])
            self.tokens.local._wait_running(self.spec, public_entry=True)
            self._check(nginx=True)
            report["local_tls_verified"] = True
            self._phase("renewal-unmask")
            self._write("renewal-unmask-attempt", {"format": 1})
            for unit in ("certbot.service", "certbot.timer"):
                self._remove_mask(unit)
            self.prep._run(["systemctl", "daemon-reload"])
            self.prep._run(["systemd-analyze", "verify", "certbot.service", "certbot.timer"])
            self._check(nginx=True, renewal_loaded=True)
            self._phase("renewal-test")
            self._write("postinstall-renewal-test-attempt", {"format": 1})
            args = dry_run_args(self.spec, self.prep.credential_path(self.spec))
            args.append("--no-random-sleep-on-renew")
            report["renewal_test_attempted"] = True
            reply = self.prep.runner(Command(tuple(args), timeout=600, capture_stderr=True))
            require(isinstance(reply, Reply))
            result = summarize(self.spec, reply)
            self._write("postinstall-renewal-test-result", result)
            require(not reply.uncertain and reply.code == 0 and all(result["evidence"].values())
                    and not any(result["signals"].values()) and not result["error_types_seen"] and not result["errno_seen"])
            self._check(nginx=True, renewal_loaded=True)
            report["renewal_test_passed"] = True
            self._phase("package-record-commit")
            self._write("package-record-commit-attempt", {"format": 1})
            self.files.replace_owned(STATE + "/packages-ready.json", encoded({"versions": self.after}),
                identity=self.package_record["identity"], digest=self.package_record["sha256"], mode=0o600)
            self.committed = self.tokens._snapshot(STATE + "/packages-ready.json", 0o600)
            self._packages()
            report["package_record_committed"] = True
            self._check(nginx=True, renewal_loaded=True)
            self._phase("renewal-enable")
            self._write("postinstall-renewal-enable-attempt", {"format": 1})
            report["renewal_enable_attempted"] = True
            self.prep._run(["systemctl", "enable", "--now", "certbot.timer"])
            self._phase("enabled-postcheck")
            self._check(nginx=True, renewal_loaded=True, renewal_enabled=True)
            report["renewal_restored_verified"] = True
            self._phase("policy-remove")
            self._write("postinstall-policy-remove-attempt", {"format": 1})
            self._guards()
            self.files.unlink_owned(POLICY, self.lease.owned[POLICY])
            self.removed.add(POLICY)
            self._check(nginx=True, renewal_loaded=True, renewal_enabled=True)
            report["guards_removed_verified"] = True
            self._phase("completion-record")
            self._write("postinstall-complete", {"format": 1, "result": "local-postchecks-passed",
                        "versions": self.after, "external_acceptance_required": True})
            report["completion_recorded"] = True
            self._check(nginx=True, renewal_loaded=True, renewal_enabled=True)
            self._phase("intent-remove")
            self.files.unlink_owned(STATE + "/" + INTENT + ".json", self.lease.intent["identity"])
            require(not self.prep._exists(INTENT))
            report.update(intent_removed_verified=True, result="packages-restored-external-test-required")
        except (KeyboardInterrupt, EOFError):
            report["result"] = "interrupted-inspection-required"
        except Exception:
            pass
        report["phase"] = self.phase
        if started:
            try:
                report["report_saved"] = True
                self._write("postinstall-result", report)
            except (OSError, PreparationError):
                report["report_saved"] = False
        return report
