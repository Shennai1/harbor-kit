"""Restore renewal after a pre-deletion cleanup stop; retain every cleanup record."""

from dataclasses import dataclass, field
import json
import re

from .activation import _binding, _digest
from .client import _read_deployment_snapshot
from .deployment import NodeSpec
from .domaininventory import Inventory
from .hostprep import DOMAIN_CURRENT, STATE, Command, PreparationError, Reply
from .installer import Terminal, confirm
from .retiredcleanup import INTENT, RetiredCleanup
from .retiredplan import _require
from .tokenchange import CURRENT, UNCHANGED_RECORDS, _json_bytes, real_token_change


STARTED = "renewal-restore-started.json"
REPORT = "renewal-restore-report.json"
SUCCESS = "renewal-restored-cleanup-still-pending"


@dataclass(frozen=True)
class RenewalRestorePlan:
    revision: str = field(repr=False)


class RetiredRenewal:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.files
        self.progress, self.phase = progress, "not-started"
        self.cleanup = RetiredCleanup(tokens)

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def _check(self, *, restored=False):
        self._phase("pending-cleanup-records")
        for name in ("key-rotation-intent", "port-change-intent", "token-change-intent", "domain-change-intent"):
            _require(not self.prep._exists(name), "other-change-pending")
        marker_path = STATE + "/" + INTENT + ".json"
        snapshots = {marker_path: self.tokens._snapshot(marker_path, 0o600)}
        intent = self.prep._read_record(INTENT)
        _require(set(intent) == {"format", "operation", "target_domain", "credential_path", "credential_metadata",
                                 "target_counts", "revision", "log_directory", "operator_confirmed_ownership",
                                 "operator_confirmed_delete"}, "cleanup-intent-structure")
        _require(type(intent["format"]) is int and intent["format"] == 1
                 and intent["operation"] == "retired-domain-cleanup"
                 and intent["operator_confirmed_ownership"] is True and intent["operator_confirmed_delete"] is True
                 and isinstance(intent["revision"], str) and re.fullmatch(r"[a-f0-9]{64}", intent["revision"]),
                 "cleanup-intent-values")
        target = NodeSpec(intent["target_domain"])
        directory = intent["log_directory"]
        _require(isinstance(directory, str) and re.fullmatch(re.escape(STATE) + r"/retired-cleanup-[a-f0-9]{32}", directory),
                 "cleanup-log-path")
        inventory = Inventory(self.files)
        names, state = inventory.scan(directory, private=True)
        expected = sorted(["report.json", STARTED, REPORT] if restored else ["report.json"])
        _require(state == "observed" and names == expected, "cleanup-logs-or-restore-already-started")
        report_path = directory + "/report.json"
        snapshots[report_path] = self.tokens._snapshot(report_path, 0o600)
        failed = json.loads(self.files.read(report_path, mode=0o600))
        _require(isinstance(failed, dict) and type(failed.get("format")) is int and failed["format"] == 1
                 and failed.get("operation") == "retired-domain-cleanup" and failed.get("result") == "stopped"
                 and failed.get("failure_phase") in {"renewal-pause", "renewal-pause-check"} and "certbot" not in failed,
                 "not-supported-pre-delete-stop")
        _require(all(failed.get(k) is True for k in ("host_changes_attempted", "report_saved", "operator_confirmed_ownership"))
                 and all(failed.get(k) is False for k in ("certbot_delete_attempted", "certificate_removed_verified",
                    "credential_delete_attempted", "credential_removed_verified", "renewal_restored_verified",
                    "automatic_retry")), "deletion-or-restore-not-excluded")

        if restored:
            self._phase("restoration-success-records")
            for name in (STARTED, REPORT):
                snapshots[directory + "/" + name] = self.tokens._snapshot(directory + "/" + name, 0o600)
            started = json.loads(self.files.read(directory + "/" + STARTED, mode=0o600))
            result = json.loads(self.files.read(directory + "/" + REPORT, mode=0o600))
            _require(isinstance(started, dict) and set(started) == {"format", "operation", "revision"}
                     and type(started["format"]) is int and started["format"] == 1
                     and started["operation"] == "retired-cleanup-renewal-restore"
                     and isinstance(started["revision"], str) and re.fullmatch(r"[a-f0-9]{64}", started["revision"]),
                     "restore-attempt-record-invalid")
            _require(isinstance(result, dict) and type(result.get("format")) is int and result["format"] == 1
                     and result.get("operation") == started["operation"] and result.get("result") == SUCCESS
                     and result.get("current_service_health") == "local-checks-passed"
                     and all(result.get(k) is True for k in ("host_changes_attempted", "renewal_enable_attempted",
                         "renewal_restored_verified", "old_resources_unchanged_verified", "cleanup_still_pending", "report_saved"))
                     and all(result.get(k) is False for k in ("cleanup_completed", "automatic_retry"))
                     and result.get("enable_command") == {"exit_code": 0, "execution_uncertain": False},
                     "restoration-not-confirmed")
            _require(type(result["enable_command"]["exit_code"]) is int
                     and result["enable_command"]["execution_uncertain"] is False,
                     "restoration-command-types")

        self._phase("enabled-current-deployment" if restored else "paused-current-deployment")
        if restored:
            self.tokens._idle()
        else:
            self.tokens._paused()
        spec, _keys, record = _read_deployment_snapshot(self.prep)
        spec = self.tokens.local._version(spec)
        _require(target.domain != spec.domain and record["binding"] == _binding(spec), "current-deployment-binding")
        self.tokens.public._validate_node(spec, record["ssh_port"])
        credential = self.tokens._credential(self.prep.credential_path(spec))
        current = None
        if self.prep._exists(CURRENT):
            _require(self.prep._read_record(CURRENT) == {"format": 1, **credential}, "current-credential-record")
            current = self.tokens._snapshot(STATE + "/" + CURRENT + ".json", 0o600)
        for name in UNCHANGED_RECORDS:
            path = STATE + "/" + name + ".json"
            snapshots[path] = self.tokens._snapshot(path, 0o600)
        if self.prep._exists(DOMAIN_CURRENT):
            path = STATE + "/" + DOMAIN_CURRENT + ".json"
            snapshots[path] = self.tokens._snapshot(path, 0o600)
        unchanged = {"records": snapshots, "lineage": self.tokens._lineage(spec)}
        before = (None, spec, record, credential, current, unchanged)
        self.cleanup._health(before, paused=not restored)

        self._phase("old-resources-still-present")
        old = Inventory(self.files)
        old_path, counts = self.cleanup.scope._target(old, target, self.prep.credential_path(spec))
        _require(old_path == intent["credential_path"] and counts == intent["target_counts"], "old-resource-scope-changed")
        _require(isinstance(intent["credential_metadata"], list) and len(intent["credential_metadata"]) == 9
                 and all(type(x) is int for x in intent["credential_metadata"])
                 and tuple(intent["credential_metadata"]) == old.watched[old_path], "old-credential-metadata-changed")
        self._phase("confirmation-snapshot")
        self.cleanup._health(before, paused=not restored)
        inventory.recheck()
        old.recheck()
        revision = _digest(_json_bytes({"before": before[2:], "directory": inventory.watched, "old": old.watched}))
        return RenewalRestorePlan(revision), directory, before, old

    def check(self):
        self._phase("preparation-lock")
        with self.prep._lock():
            return self._check()[0]

    def restore(self, plan, *, confirm_restore):
        if not isinstance(plan, RenewalRestorePlan) or confirm_restore is not True:
            raise PreparationError("需要明确确认只恢复自动续期，不继续清理。")
        with self.prep._lock():
            checked, directory, before, old = self._check()
            _require(checked == plan, "confirmation-snapshot-changed")
            report = {"format": 1, "operation": "retired-cleanup-renewal-restore", "result": "stopped",
                      "host_changes_attempted": False, "renewal_enable_attempted": False,
                      "renewal_restored_verified": False, "old_resources_unchanged_verified": False,
                      "cleanup_still_pending": True, "cleanup_completed": False, "automatic_retry": False,
                      "report_saved": False, "current_service_health": "not-confirmed"}
            try:
                self._phase("restore-attempt-record")
                report["host_changes_attempted"] = True
                self.files.write_new(directory + "/" + STARTED, _json_bytes({"format": 1,
                    "operation": report["operation"], "revision": plan.revision}), 0o600)
                attempt = self.tokens._snapshot(directory + "/" + STARTED, 0o600)
                self.cleanup._health(before, paused=True)
                old.recheck()
                self._phase("renewal-enable")
                report["renewal_enable_attempted"] = True
                reply = self.prep.runner(Command(("systemctl", "enable", "--now", "certbot.timer")))
                _require(isinstance(reply, Reply), "renewal-enable-result-unrecognized")
                report["enable_command"] = {"exit_code": reply.code, "execution_uncertain": reply.uncertain}
                _require(reply.code == 0 and not reply.uncertain, "renewal-enable-failed-or-uncertain")
                self._phase("enabled-postcheck")
                # Enabling may trigger a legitimate current-certificate renewal.
                self.cleanup._health(before, paused=False)
                self.tokens._expect(directory + "/" + STARTED, attempt, 0o600)
                old.recheck()
                report.update(result=SUCCESS, renewal_restored_verified=True,
                              old_resources_unchanged_verified=True, current_service_health="local-checks-passed")
            except (Exception, KeyboardInterrupt) as error:
                self.cleanup.phase = self.phase
                report.update(self.cleanup._check_failure(error))
                # Do not disable a restored timer or stop an active Certbot job.
            finally:
                try:
                    with self.files.directory(directory, private=True):
                        self.files.write_new(directory + "/" + REPORT, _json_bytes({**report, "report_saved": True}), 0o600)
                    report["report_saved"] = True
                except (Exception, KeyboardInterrupt):
                    pass
            return report


def run_retired_renewal(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("恢复续期需要交互终端，不接受自动确认。")
        return 2
    engine = None
    try:
        ui.say("受限恢复：仅处理旧域名清理在删除前暂停续期后停止的现场；不继续清理，不清除待核查标记。")
        with factory() as tokens:
            engine = RetiredRenewal(tokens, lambda p: ui.say("恢复核查阶段：" + p))
            plan = engine.check()
            ui.say("将保留全部旧资源、失败记录和清理标记，只启用现用证书的自动续期，可能触发真实到期续签。")
            ui.say("不修改节点密钥、SNI、端口或 SSH/UFW；失败不自动重试或回退，请保持连接且不要并行管理。")
            if not confirm(ui, "确认只恢复自动续期，保留清理待核查状态？"):
                return 130
            if not ui.interactive():
                return 2
            report = engine.restore(plan, confirm_restore=True)
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        if report["result"] == SUCCESS:
            ui.say("自动续期已恢复并核对；旧资源及清理标记保留。清理尚未完成，不重跑或手动删标记。无需修改 Surge。")
            return 0
        ui.say("恢复未确认完成；保留现场，不重试或重启，先核对定时器状态。只分享 JSON。")
        return 1
    except (KeyboardInterrupt, EOFError):
        ui.say("操作中断；保留记录，核对续期状态，不自动重试。")
        return 130
    except Exception as error:
        result = {"format": 1, "operation": "retired-cleanup-renewal-restore", "result": "precheck-failed",
                  "host_changes_attempted": False, "cleanup_still_pending": True}
        if engine is not None:
            engine.cleanup.phase = engine.phase
            result.update(engine.cleanup._check_failure(error))
        ui.say(json.dumps(result, ensure_ascii=False, indent=2))
        return 1
