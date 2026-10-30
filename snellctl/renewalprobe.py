"""One no-deletion pause probe for an already restored pre-delete cleanup stop."""

from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import signal

from .activation import _digest
from .hostprep import STATE, PreparationError
from .installer import Terminal, confirm
from .retiredcleanup import INTENT
from .retiredplan import _require
from .retiredrenewal import RetiredRenewal
from .tokenchange import CURRENT, _json_bytes, real_token_change


SUCCESS = "pause-probe-passed-cleanup-still-pending"
UNITS = {"certbot.timer", "certbot.service", "nginx.service", "ufw.service",
         "snellctl-snell-main.service", "snellctl-shadowtls-main.service"}
PROPERTIES = {"ActiveState", "SubState", "MainPID", "Job", "UnitFileState", "LoadState",
              "FragmentPath", "DropInPaths", "ExecMainStatus", "NRestarts", "Triggers", "NextElapseUSecRealtime"}


def read_only_command(argv):
    if not isinstance(argv, tuple) or not argv or not all(isinstance(x, str) for x in argv):
        return False
    if argv in {("nginx", "-v"), ("nginx", "-T"), ("ss", "-H", "-lntp"), ("ss", "-H", "-lntup"),
                ("ufw", "status", "verbose"), ("ufw", "show", "added"),
                ("dpkg-query", "-W", "-f=${Conffiles}\n", "nginx-common"),
                ("iptables", "-S", "INPUT"), ("ip6tables", "-S", "INPUT"),
                ("iptables", "-S", "ufw-user-input"), ("ip6tables", "-S", "ufw6-user-input")}:
        return True
    if argv[0] == "systemctl":
        return ((len(argv) == 3 and argv[1] == "is-enabled" and argv[2] in UNITS)
                or (len(argv) == 5 and argv[1] == "show" and argv[2] in UNITS and argv[3] == "-p"
                    and bool(argv[4]) and set(argv[4].split(",")) <= PROPERTIES))
    if argv[:3] == ("openssl", "x509", "-in"):
        return argv[4:] in {("-noout", "-checkend", "604800"), ("-pubkey", "-noout"),
                           ("-noout", "-ext", "subjectAltName")}
    if argv[:3] == ("openssl", "pkey", "-in"):
        return len(argv) == 5 and argv[4] == "-pubout"
    return (len(argv) == 11 and argv[:5] == ("openssl", "verify", "-purpose", "sslserver", "-verify_hostname")
            and argv[6:9] == ("-CAfile", "/etc/ssl/certs/ca-certificates.crt", "-untrusted"))


@dataclass(frozen=True)
class PauseProbePlan:
    revision: str = field(repr=False)


class RenewalPauseProbe:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.files
        self.progress, self.phase = progress, "not-started"
        self.renewal = RetiredRenewal(tokens, self._phase)
        self.cleanup = self.renewal.cleanup
        self.permitted = None
        self.host_changes_attempted = False

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def _failure(self, error):
        self.cleanup.phase = self.phase
        return self.cleanup._check_failure(error)

    @contextmanager
    def _commands(self):
        original = self.prep.runner
        def guarded(command):
            if command.argv == self.permitted:
                self.permitted = None
            elif not read_only_command(command.argv):
                raise PreparationError("验证命令不在只读或单次定时器操作范围内。")
            return original(command)
        self.prep.runner = guarded
        try:
            yield
        finally:
            self.permitted = None
            self.prep.runner = original

    def _timer(self, report, key, action):
        _require(action in {"disable", "enable"}, "probe-timer-action")
        self.permitted = ("systemctl", action, "--now", "certbot.timer")
        try:
            self.cleanup._timer_command(report, key, action)
        finally:
            self.permitted = None

    def _check(self):
        plan, _history, before, old = self.renewal._check(restored=True)
        marker = before[5]["records"][STATE + "/" + INTENT + ".json"]
        directory = STATE + "/renewal-pause-probe-" + _digest(_json_bytes(marker))
        _require(self.files.info(directory) is None, "pause-probe-already-attempted")
        return PauseProbePlan(plan.revision), directory, before, old

    def check(self):
        self._phase("preparation-lock")
        with self._commands(), self.prep._lock():
            return self._check()[0]

    def _restore(self, report, before):
        self._phase("restore-configuration-check")
        _plan, spec, _record, credential, current, unchanged = before
        self.tokens._expect_records(unchanged)
        self.tokens._expect(self.prep.credential_path(spec), credential, 0o600)
        if current is not None:
            self.tokens._expect(STATE + "/" + CURRENT + ".json", current, 0o600)
        renewal = self.prep._read_record("renewal-enable-ready")
        self.tokens.public._renewal_health(spec, renewal, timer=False)
        self._phase("renewal-restore")
        self._timer(report, "restore_command", "enable")
        self._phase("restored-timer-check")
        self.tokens.public._renewal_health(spec, renewal, timer=True)
        report["renewal_restored_verified"] = True

    def probe(self, plan, *, confirm_probe):
        if not isinstance(plan, PauseProbePlan) or confirm_probe is not True:
            raise PreparationError("必须明确确认无删除的暂停、等待及恢复验证。")
        with self._commands(), self.prep._lock():
            checked, directory, before, old = self._check()
            _require(checked == plan, "confirmation-snapshot-changed")
            report = {"format": 1, "operation": "renewal-pause-probe", "result": "stopped",
                      "host_changes_attempted": False, "pause_attempted": False,
                      "wait_passed": False, "paused_health_passed": False, "renewal_restored_verified": False,
                      "old_resources_unchanged_verified": False, "cleanup_marker_unchanged_verified": False,
                      "certbot_delete_attempted": False, "credential_delete_attempted": False,
                      "cleanup_completed": False, "cleanup_still_pending": "not-confirmed",
                      "current_service_health": "not-confirmed", "report_saved": False, "automatic_retry": False}
            pause_attempted = False
            directory_identity = None
            try:
                self._phase("probe-records")
                report["host_changes_attempted"] = self.host_changes_attempted = True
                self.files.private_directory_new(directory)
                directory_identity = self.files.identity(directory)
                self.files.write_new(directory + "/started.json", _json_bytes({"format": 1,
                    "operation": report["operation"], "revision": plan.revision}), 0o600)
                self._phase("renewal-pause")
                report["pause_attempted"] = pause_attempted = True
                self._timer(report, "pause_command", "disable")
                self._phase("renewal-pause-wait")
                self.cleanup._wait_paused(report)
                report["wait_passed"] = True
                self._phase("paused-health-check")
                self.cleanup._health(before, paused=True)
                old.recheck()
                report["paused_health_passed"] = True
            except (Exception, KeyboardInterrupt) as error:
                report.update(self._failure(error))
            finally:
                # Restore scheduling even after a failed wait; never stop a renewal.
                # Changed renewal configuration is not silently re-enabled.
                if pause_attempted:
                    try:
                        self._restore(report, before)
                    except (Exception, KeyboardInterrupt) as error:
                        report["restoration_failure"] = self._failure(error)
                try:
                    self._phase("cleanup-marker-check")
                    marker_path = STATE + "/" + INTENT + ".json"
                    self.tokens._expect(marker_path, before[5]["records"][marker_path], 0o600)
                    report["cleanup_marker_unchanged_verified"] = True
                    report["cleanup_still_pending"] = True
                except (Exception, KeyboardInterrupt) as error:
                    report["marker_check_failure"] = self._failure(error)
                try:
                    self._phase("final-state-check")
                    self.cleanup._health(before, paused=False)
                    report["current_service_health"] = "local-checks-passed"
                    old.recheck()
                    report["old_resources_unchanged_verified"] = True
                except (Exception, KeyboardInterrupt) as error:
                    report["postcheck_failure"] = self._failure(error)
                if (report["wait_passed"] and report["paused_health_passed"] and report["renewal_restored_verified"]
                        and report["old_resources_unchanged_verified"] and report["cleanup_marker_unchanged_verified"]
                        and "failure_phase" not in report and "restoration_failure" not in report
                        and "postcheck_failure" not in report):
                    report["result"] = SUCCESS
                elif report["renewal_restored_verified"]:
                    report["result"] = "probe-stopped-renewal-restored"
                try:
                    _require(directory_identity is not None and self.files.identity(directory) == directory_identity,
                             "probe-report-directory-changed")
                    with self.files.directory(directory, private=True):
                        self.files.write_new(directory + "/report.json", _json_bytes({**report, "report_saved": True}), 0o600)
                    report["report_saved"] = True
                except (Exception, KeyboardInterrupt):
                    pass
            return report


@contextmanager
def ignore_ssh_hangup():
    previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        yield
    finally:
        signal.signal(signal.SIGHUP, previous)


def run_renewal_pause_probe(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("暂停验证需要交互终端，不接受自动确认。")
        return 2
    engine = None
    try:
        ui.say("无删除验证：仅限删除前失败且已经恢复续期的现有清理现场；每个现场只执行一次。")
        with factory() as tokens:
            engine = RenewalPauseProbe(tokens, lambda p: ui.say("验证阶段：" + p))
            plan = engine.check()
            ui.say("将暂停定时器，最多用 90 秒等待现有任务自然结束，然后核对并恢复续期；不强制中止 Certbot。")
            ui.say("不删除证书、凭据或清理标记，不改节点、SSH/UFW，不直接执行 Certbot；恢复后可能触发真实到期续签。")
            ui.say("捕获到验证失败也会核查并尝试恢复；配置改变、断电或强制终止不能保证恢复，不自动重试。")
            ui.say("记录保存在新的 root-only 目录，原失败和恢复记录不改动。保持本会话，不并行管理。")
            if not confirm(ui, "已确认备用 SSH 和恢复控制台可用，允许暂停并恢复续期，且不删除任何资源？"):
                return 130
            if not ui.interactive():
                return 2
            # Retain the worker after ordinary terminal HUP; this is not a crash watchdog.
            with ignore_ssh_hangup():
                engine.progress = lambda _phase: None
                report = engine.probe(plan, confirm_probe=True)
        try:
            ui.say(json.dumps(report, ensure_ascii=False, indent=2))
            if report["result"] == SUCCESS:
                ui.say("暂停、等待及恢复验证通过；旧资源和清理标记仍保留，不代表清理完成。无需修改 Surge。")
                return 0
            ui.say("验证未通过；查看 JSON 中续期恢复状态，不重试、不删除记录或重启。只分享最后 JSON。")
            return 1
        except OSError:
            # A lost terminal must not trigger another timer operation or overwrite the saved result.
            return 1
    except (KeyboardInterrupt, EOFError):
        ui.say("验证中断，不能据此判断续期状态；保留记录，不自动重试。")
        return 130
    except Exception as error:
        result = {"format": 1, "operation": "renewal-pause-probe", "result": "precheck-or-delivery-failed",
                  "host_changes_attempted": engine.host_changes_attempted if engine is not None else False,
                  "cleanup_completed": False}
        if engine is not None:
            result.update(engine._failure(error))
        ui.say(json.dumps(result, ensure_ascii=False, indent=2))
        return 1
