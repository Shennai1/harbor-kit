"""Internal, fail-closed maintenance entry; no package execution or CLI.

The caller must have reviewed/downloaded the update and obtained consent before
entering this context. It holds the preparation lock across the caller's work.
Exit NEVER removes masks, resumes services, retries, or declares an update done.
"""

from contextlib import contextmanager
from dataclasses import asdict
import json
import os
import stat

from .activation import PACKAGE_CONFIGS, _digest
from .domaininventory import Inventory
from .hostprep import POLICY, POLICY_BYTES, STATE, UNITS, PreparationError
from .maintenance import Maintenance
from .packagejob import JobSpec
from .packageplan import ALL_PACKAGES, package_rows
from .publish import RENEW_DROPIN, _rules_digest
from .retiredcleanup import RetiredCleanup
from .tokenchange import CURRENT, _json_bytes


INTENT = "package-update-intent"
UNIT_FIELDS = ("LoadState", "ActiveState", "SubState", "UnitFileState",
               "NeedDaemonReload", "Job")
PRESERVED_PATHS = frozenset({*PACKAGE_CONFIGS, RENEW_DROPIN,
                           "/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-main-nginx",
                           *("/usr/lib/systemd/system/" + u for u in UNITS)})


def require(condition):
    if not condition:
        raise PreparationError("Package maintenance guards require inspection; preserve the current state.")


class GuardLease:
    """Pre-install checks only, valid within the owning locked context."""

    def __init__(self, engine, job, before):
        self.engine, self.job, self.before = engine, job, before
        self.active = True
        self.owned = {}
        self.intent = engine.tokens._snapshot(STATE + "/" + INTENT + ".json", 0o600)

    def verify(self):
        require(self.active)
        engine, files = self.engine, self.engine.files
        engine.tokens._expect(STATE + "/" + INTENT + ".json", self.intent, 0o600)
        engine._unchanged(self.before)
        require(files.read(POLICY, mode=0o755) == POLICY_BYTES)
        require(set(self.owned) == {POLICY, *("/etc/systemd/system/" + u for u in UNITS)})
        for path, identity in self.owned.items():
            require(files.identity(path) == identity)
            if path != POLICY:
                info = files.info(path)
                require(stat.S_ISLNK(info.st_mode) and info.st_uid == os.geteuid()
                        and info.st_nlink == 1 and files.readlink(path) == "/dev/null")
        for unit in UNITS:
            engine._masked(unit)
        require(not engine.prep._run(["ss", "-H", "-lntu", "sport = :" + str(self.before[0][1].tls_port)]).strip())


class RestorationLease(GuardLease):
    """Only for revalidated post-install work; never accepted by submit()."""

    resume_stamp = None

    def verify(self):
        raise PreparationError("A restoration lease cannot authorize another installation.")


class PackageGuards:
    """Requires an explicitly supplied live checker/runner; imports do nothing."""

    def __init__(self, tokens, progress=lambda phase: None, *, clock=None, sleep=None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.files
        self.progress, self.phase = progress, "not-started"
        self.waiter = RetiredCleanup(tokens, clock=clock, sleep=sleep)

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def _fields(self, unit, fields):
        output = self.prep._run(["systemctl", "show", "--all", unit, "-p", ",".join(fields)])
        require(len(output) <= 16384 and output.isascii()
                and all(c == "\n" or 32 <= ord(c) <= 126 for c in output))
        pairs = [line.split("=", 1) for line in output.splitlines()]
        require(len(pairs) == len(fields) and all(len(p) == 2 for p in pairs)
                and {p[0] for p in pairs} == set(fields))
        return dict(pairs)

    def _masked(self, unit):
        expected = dict(LoadState="masked", ActiveState="inactive", SubState="dead",
                        UnitFileState="masked", NeedDaemonReload="no", Job="")
        if unit.endswith(".service"):
            expected.update(MainPID="0", ControlPID="0")
        require(self._fields(unit, tuple(expected)) == expected)

    def _vacant_paths(self, job):
        require(self.files.info(POLICY) is None and self.files.info(job.directory) is None)
        for unit in (*UNITS, job.unit):
            for prefix in ("/etc/systemd/system/", "/run/systemd/system/"):
                require(self.files.info(prefix + unit) is None)
        self._overrides((*UNITS, job.unit))
        require(self.files.info("/usr/lib/systemd/system/" + job.unit) is None)

    def _overrides(self, units):
        for unit in units:
            for prefix in ("/etc/systemd/system/", "/run/systemd/system/", "/usr/lib/systemd/system/"):
                directory = prefix + unit + ".d"
                if directory == "/etc/systemd/system/certbot.service.d":
                    with self.files.directory(directory) as fd:
                        require(set(os.listdir(fd)) == {"50-snellctl.conf"})
                else:
                    require(self.files.info(directory) is None)

    def _before(self, job):
        self.prep._no_pending_change()
        watched = Inventory(self.files)
        Maintenance(self.tokens)._platform(watched)
        self._vacant_paths(job)
        data = self.tokens._check()
        versions = self.prep._installed()
        require(self.prep._read_record("packages-ready") == {"versions": versions})
        database = package_rows(self.prep._run(ALL_PACKAGES))
        for change in job.changes:
            require(database.get((change.name, change.architecture)) == (change.before, False))
            self.prep._run(["dpkg", "--compare-versions", change.after, "gt", change.before])
        require(not self.prep._run(["dpkg", "--audit"]).strip())
        for unit in UNITS:
            fields = (*UNIT_FIELDS, "FragmentPath", "DropInPaths")
            state = self._fields(unit, fields)
            expected = dict(LoadState="loaded", NeedDaemonReload="no", Job="",
                            FragmentPath="/usr/lib/systemd/system/" + unit,
                            DropInPaths=RENEW_DROPIN if unit == "certbot.service" else "")
            if unit == "certbot.service":
                expected.update(ActiveState="inactive", SubState="dead", UnitFileState="static")
            else:
                expected.update(ActiveState="active", UnitFileState="enabled",
                                SubState="waiting" if unit == "certbot.timer" else "running")
            require(state == expected)
        package_record = self.tokens._snapshot(STATE + "/packages-ready.json", mode=0o600)
        preserved = {path: self.tokens._snapshot(path) for path in PRESERVED_PATHS}
        watched.recheck()
        self._vacant_paths(job)
        return data, versions, database, package_record, preserved

    def _unchanged(self, before):
        data, versions, database, package_record, preserved = before
        _plan, spec, record, credential, current, unchanged = data
        self.tokens.local._verify_owned(spec, record["node"])
        self.tokens._expect(STATE + "/packages-ready.json", package_record, mode=0o600)
        self.tokens._expect_records(unchanged)
        for path, snapshot in preserved.items():
            self.tokens._expect(path, snapshot)
        if current is not None:
            self.tokens._expect(STATE + "/" + CURRENT + ".json", current, 0o600)
        else:
            require(not self.prep._exists(CURRENT))
        require(self.tokens._credential(self.prep.credential_path(spec)) == credential
                and self.tokens._lineage(spec) == unchanged["lineage"]
                and self.prep._installed() == versions
                and package_rows(self.prep._run(ALL_PACKAGES)) == database)
        # Compare the complete recorded firewall, not only the entry port.
        rules, hashes, running = self.tokens.public._firewall(record["ssh_port"])
        require(_rules_digest(rules) == record["rules_sha256"] and hashes == record["unchanged_ufw"]
                and _digest(json.dumps(running).encode()) == record["ipv4_input_sha256"])
        for unit in (spec.snell_service, spec.shadowtls_service):
            require(self._fields(unit, ("ActiveState", "SubState", "UnitFileState")) ==
                    {"ActiveState": "active", "SubState": "running", "UnitFileState": "enabled"})
        for unit in UNITS:
            require(self.files.info("/run/systemd/system/" + unit) is None)
        self._overrides(UNITS)

    def _record(self, job, name, value):
        self.files.write_new(job.directory + "/" + name + ".json", _json_bytes(value))

    @contextmanager
    def protected(self, job, *, confirm_outage=False):
        """Internal boundary, not a standalone maintenance/recovery command.

        This context itself never submits APT or removes guards. The caller's
        separately verified post-install coordinator owns any restoration.
        """
        require(type(job) is JobSpec and confirm_outage is True)
        lease = None
        with self.prep._lock():
            self._phase("guard-preflight")
            before = self._before(job)
            self._phase("maintenance-intent")
            self.prep._record(INTENT, {"format": 1, "operation": "package-update", "job_id": job.job_id,
                                       "changes": [asdict(c) for c in job.changes], "outage_confirmed": True})
            try:
                self.files.private_directory_new(job.directory)
                self._record(job, "guards-intent", {"format": 1})
                lease = GuardLease(self, job, before)
                self._phase("policy-create")
                self.files.write_new(POLICY, POLICY_BYTES, 0o755)
                lease.owned[POLICY] = self.files.identity(POLICY)
                self._record(job, "policy-created", {"identity": lease.owned[POLICY]})
                self._phase("renewal-pause")
                self._record(job, "pause-attempt", {"format": 1})
                self.prep._run(["systemctl", "disable", "--now", "certbot.timer"])
                self._phase("renewal-wait")
                wait = {}
                self.waiter._wait_paused(wait)
                self._record(job, "pause-observed", wait)
                data = before[0]
                self.tokens._health_paused(data[1], data[2], data[5])
                self._unchanged(before)
                self._phase("mask-create")
                for unit in UNITS:
                    self.files.mask_new(unit)
                    path = "/etc/systemd/system/" + unit
                    lease.owned[path] = self.files.identity(path)
                    self._record(job, "mask-" + unit, {"identity": lease.owned[path]})
                self._record(job, "masks-created", {"owned": lease.owned})
                self.prep._run(["systemctl", "daemon-reload"])
                # A renewal queued after our samples must not be forcibly stopped.
                for unit in ("certbot.service", "certbot.timer"):
                    self._masked(unit)
                self._phase("nginx-stop")
                self._record(job, "nginx-stop-attempt", {"format": 1})
                self.prep._run(["systemctl", "stop", "nginx.service"])
                self._phase("guards-verify")
                lease.verify()
                self._record(job, "guards-ready", {"format": 1, "owned": lease.owned,
                                                    "packages_before": before[1]})
                self._phase("protected-coordinator")
                yield lease
            except BaseException:
                # Only constant phase names are persisted, never exception text.
                try:
                    self._record(job, "guards-stopped", {"format": 1, "phase": self.phase,
                                                         "automatic_retry": False})
                except (OSError, PreparationError):
                    pass
                raise
            finally:
                if lease is not None:
                    lease.active = False
