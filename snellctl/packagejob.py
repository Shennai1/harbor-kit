"""Package-job templates and read-only observer; no launch/write API here.

The future coordinator must stage and verify files, acquire locks, install start
guards and record explicit consent before it can use a job. Templates are not
authorization. Observation never stops, retries or finalizes an upgrade.
"""

from dataclasses import asdict, dataclass, field
import json
import math
import re
import time

from .hostprep import Command, PreparationError, Reply, STATE
from .packagepolicy import RevisionChange


FIELDS = ("Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath",
          "DropInPaths", "NeedDaemonReload", "MainPID", "ControlPID", "Job", "Result",
          "ExecMainCode", "ExecMainStatus", "ExecMainStartTimestampMonotonic",
          "ExecMainExitTimestampMonotonic", "InvocationID", "Type", "RemainAfterExit",
          "Restart", "NRestarts", "TimeoutStartUSec")


def require(condition):
    if not condition:
        raise PreparationError("Package job specification or observation requires inspection.")


@dataclass(frozen=True)
class JobSpec:
    job_id: str
    changes: tuple[RevisionChange, ...]

    def __post_init__(self):
        require(isinstance(self.job_id, str) and re.fullmatch(r"[0-9a-f]{32}", self.job_id) is not None)
        require(type(self.changes) is tuple and 0 < len(self.changes) <= 8
                and all(type(c) is RevisionChange for c in self.changes))
        require(tuple(sorted(c.name for c in self.changes)) == tuple(c.name for c in self.changes)
                and len({c.name for c in self.changes}) == len(self.changes))

    @property
    def unit(self):
        return "snellctl-package-update-" + self.job_id + ".service"

    @property
    def unit_path(self):
        return "/etc/systemd/system/" + self.unit

    @property
    def directory(self):
        return STATE + "/package-jobs/" + self.job_id

    @property
    def apt_config(self):
        # Never reuse the read-only review configuration for real dpkg writes.
        return "/var/cache/snellctl/package-update/" + self.job_id + "/install.conf"

    def install_argv(self, *, simulate=False):
        require(type(simulate) is bool)
        return ("apt-get", *(("--simulate",) if simulate else ()), "--no-download", "--no-remove",
                "--only-upgrade", "--no-install-recommends", "--assume-yes", "-o", "DPkg::Lock::Timeout=0",
                "install", *(c.name + "=" + c.after for c in self.changes))

    def authority_bytes(self, kind):
        require(kind in {"armed", "submission-attempt"})
        return (json.dumps({"format": 1, "kind": kind, "job_id": self.job_id,
                            "changes": [asdict(c) for c in self.changes]}, sort_keys=True) + "\n").encode("ascii")

    def launcher_bytes(self):
        # This private standalone launcher imports only the system standard library.
        environment = dict(PATH="/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL="C", DEBIAN_FRONTEND="noninteractive",
                           NEEDRESTART_MODE="l", HOME=self.directory + "/home", APT_CONFIG=self.apt_config)
        constants = (f"DIRECTORY = {self.directory!r}\nJOB_ID = {self.job_id!r}\n"
                     f"ARMED = {self.authority_bytes('armed')!r}\n"
                     f"ATTEMPT = {self.authority_bytes('submission-attempt')!r}\n"
                     f"ARGV = {('/usr/bin/apt-get', *self.install_argv()[1:])!r}\nENVIRONMENT = {environment!r}\n")
        return (constants + _LAUNCHER).encode("ascii")

    def unit_bytes(self):
        # All substitutions use fixed paths or restricted canonical identifiers.
        return (f"[Unit]\nDescription=Reviewed package update job\nRefuseManualStop=yes\n"
                f"ConditionPathExists={self.directory}/armed.json\n\n"
                f"[Service]\nType=oneshot\nUser=root\nGroup=root\nRemainAfterExit=yes\n"
                f"Restart=no\nTimeoutStartSec=infinity\nRuntimeMaxSec=infinity\n"
                f"WorkingDirectory=/\nUMask=0077\nLimitCORE=0\nStandardInput=null\n"
                f"StandardOutput=append:{self.directory}/apt.log\n"
                f"StandardError=append:{self.directory}/apt.log\n"
                f"ExecStart=/usr/bin/python3 -I -S -B {self.directory}/launch.py\n").encode("ascii")


_LAUNCHER = '''
import json
import os
import re
import stat
import sys


def require(value):
    if not value:
        raise ValueError("invalid execution state")


def directory():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in DIRECTORY.split("/")[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid in {0, os.geteuid()} and not info.st_mode & 0o022)
        require(os.fstat(fd).st_uid == os.geteuid() and stat.S_IMODE(os.fstat(fd).st_mode) == 0o700)
        return fd
    except BaseException:
        os.close(fd)
        raise


def exact(fd, name, expected):
    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(source, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(expected))
        require(stream.read(len(expected) + 1) == expected)


def run():
    os.umask(0o077)
    invocation = os.environ.get("INVOCATION_ID", "")
    require(re.fullmatch(r"[0-9a-f]{32}", invocation) is not None)
    fd = directory()
    try:
        exact(fd, "armed.json", ARMED)
        exact(fd, "submission-attempt.json", ATTEMPT)
        # Creation consumes this job even if execution fails or power is lost next.
        out = os.open("execution-claim.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=fd)
        with os.fdopen(out, "wb") as stream:
            stream.write((json.dumps({"format": 1, "job_id": JOB_ID, "invocation": invocation},
                                    sort_keys=True) + "\\n").encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chdir("/")
    os.execve(ARGV[0], ARGV, ENVIRONMENT)


if __name__ == "__main__":
    try:
        run()
    except BaseException:
        print("Package job refused or interrupted; inspect retained state, do not retry.", file=sys.stderr)
        sys.exit(125)
'''


@dataclass(frozen=True)
class Observation:
    state: str
    invocation: str = field(default="", repr=False)
    started: int = field(default=0, repr=False)


def observation(spec, reply):
    require(type(spec) is JobSpec and isinstance(reply, Reply) and not reply.uncertain and reply.code == 0)
    require(isinstance(reply.output, str) and len(reply.output) <= 16384 and reply.output.isascii()
            and all(ch in "\n" or 32 <= ord(ch) <= 126 for ch in reply.output))
    rows = reply.output.splitlines()
    fields = {}
    for line in rows:
        key, separator, value = line.partition("=")
        require(separator and key in FIELDS and key not in fields)
        fields[key] = value
    require(set(fields) == set(FIELDS))
    expected = {"Id": spec.unit, "LoadState": "loaded", "UnitFileState": "static",
                "FragmentPath": spec.unit_path, "DropInPaths": "", "NeedDaemonReload": "no",
                "Type": "oneshot", "RemainAfterExit": "yes", "Restart": "no", "NRestarts": "0",
                "TimeoutStartUSec": "infinity"}
    require(all(fields[k] == v for k, v in expected.items()))
    numeric = ("MainPID", "ControlPID", "ExecMainCode", "ExecMainStatus",
               "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic")
    require(all(re.fullmatch(r"0|[1-9][0-9]{0,19}", fields[k]) is not None for k in numeric))
    numbers = {k: int(fields[k]) for k in numeric}
    invocation = fields["InvocationID"]
    require(invocation == "" or re.fullmatch(r"[0-9a-f]{32}", invocation) is not None)
    started, exited = (numbers["ExecMainStartTimestampMonotonic"], numbers["ExecMainExitTimestampMonotonic"])
    active, sub = fields["ActiveState"], fields["SubState"]
    busy = bool(numbers["MainPID"] or numbers["ControlPID"] or fields["Job"])
    if active in {"activating", "deactivating"} or busy:
        return Observation("running-or-queued", invocation, started)
    if (active, sub) == ("inactive", "dead") and not started and not exited and not invocation:
        if fields["Result"] == "success" and not numbers["ExecMainCode"] and not numbers["ExecMainStatus"]:
            return Observation("not-started")
    if started and exited >= started and invocation:
        code, status = numbers["ExecMainCode"], numbers["ExecMainStatus"]
        if ((active, sub) == ("active", "exited") and fields["Result"] == "success"
                and code == 1 and status == 0):
            return Observation("command-exited-success", invocation, started)
        if ((active, sub) == ("failed", "failed") and fields["Result"] in
                {"exit-code", "signal", "core-dump", "timeout", "oom-kill"}
                and code in {1, 2, 3} and (code != 1 or status != 0)):
            return Observation("command-exited-failure", invocation, started)
    return Observation("inconclusive", invocation, started)


class JobObserver:
    """Only queries an already-staged unit. Never dispatches or removes it."""

    def __init__(self, spec, files, runner, *, invocation=None, started=None):
        require(type(spec) is JobSpec and callable(runner))
        require((invocation is None and started is None) or
                (isinstance(invocation, str) and re.fullmatch(r"[0-9a-f]{32}", invocation) is not None
                 and type(started) is int and started > 0))
        self.spec, self.files, self.runner = spec, files, runner
        self.invocation, self.started = invocation, started

    def _unit(self):
        require(self.files.read(self.spec.unit_path, mode=0o644) == self.spec.unit_bytes())
        return self.files.identity(self.spec.unit_path)

    def sample(self, timeout=5):
        require(isinstance(timeout, (int, float)) and not isinstance(timeout, bool)
                and math.isfinite(timeout) and 0 < timeout <= 5)
        before = self._unit()
        reply = self.runner(Command(("systemctl", "show", "--all", self.spec.unit,
                                     "-p", ",".join(FIELDS)), timeout=timeout))
        require(self._unit() == before)
        value = observation(self.spec, reply)
        # Once observed, never accept another invocation or a reset/GC'ed result.
        if self.invocation is not None:
            require(value.invocation == self.invocation)
        elif value.invocation:
            self.invocation = value.invocation
        if self.started is not None:
            require(value.started == self.started)
        elif value.started:
            self.started = value.started
        return value

    def wait(self, *, budget=120, interval=1, clock=time.monotonic, sleep=time.sleep):
        require(type(budget) is int and 1 <= budget <= 900
                and isinstance(interval, (int, float)) and not isinstance(interval, bool)
                and math.isfinite(interval) and 0 < interval <= 10)
        report = {"format": 1, "operation": "package-job-observation", "result": "observation-failed",
                  "host_changes_attempted": False, "task_stop_attempted": False, "automatic_retry": False,
                  "upgrade_completed": False, "postchecks_required": True, "samples": 0,
                  "last_state": "not-observed"}
        deadline = clock() + budget
        # The cap also bounds tests or a faulty injected clock which never advances.
        for _ in range(math.ceil(budget / interval) + 1):
            remaining = deadline - clock()
            if remaining <= 0:
                break
            try:
                report["samples"] += 1
                value = self.sample(timeout=min(5, remaining))
                report["last_state"] = value.state
                if value.state != "running-or-queued":
                    report["result"] = value.state
                    return report
                sleep(max(0, min(interval, deadline - clock())))
            except (KeyboardInterrupt, EOFError):
                report["result"] = "observation-interrupted-task-not-stopped"
                return report
            except Exception:
                return report
        report["result"] = "wait-budget-exhausted-task-not-stopped"
        return report
