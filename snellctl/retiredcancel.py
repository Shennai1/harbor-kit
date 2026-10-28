"""Close a restored pre-delete cleanup attempt without deleting retired resources."""

from dataclasses import dataclass, field
import json

from .hostprep import STATE, PreparationError
from .installer import Terminal, confirm
from .retiredcleanup import INTENT
from .retiredplan import _require
from .retiredrenewal import RetiredRenewal
from .tokenchange import _json_bytes, real_token_change


ARCHIVE = "cancelled-cleanup-intent.json"
STARTED = "cleanup-cancel-started.json"
REPORT = "cleanup-cancel-report.json"
SUCCESS = "cleanup-cancelled-resources-preserved"


@dataclass(frozen=True)
class CleanupCancelPlan:
    revision: str = field(repr=False)


class RetiredCancel:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.files
        self.progress, self.phase = progress, "not-started"
        self.renewal = RetiredRenewal(tokens, self._phase)

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def _check(self):
        plan, directory, before, old = self.renewal._check(restored=True)
        return CleanupCancelPlan(plan.revision), directory, before, old

    def check(self):
        self._phase("preparation-lock")
        with self.prep._lock():
            return self._check()[0]

    def _failure(self, error):
        self.renewal.cleanup.phase = self.phase
        return self.renewal.cleanup._check_failure(error)

    def cancel(self, plan, *, confirm_cancel):
        if not isinstance(plan, CleanupCancelPlan) or confirm_cancel is not True:
            raise PreparationError("需要单独确认取消失败清理并保留旧资源。")
        with self.prep._lock():
            checked, directory, before, old = self._check()
            _require(checked == plan, "confirmation-snapshot-changed")
            marker_path = STATE + "/" + INTENT + ".json"
            marker = before[5]["records"][marker_path]
            report = {"format": 1, "operation": "retired-cleanup-cancel", "result": "stopped",
                      "host_changes_attempted": False, "history_archived_verified": False,
                      "active_intent_remove_attempted": False, "active_intent_removed_verified": False,
                      "cleanup_still_pending": True, "cleanup_completed": False,
                      "old_resources_preserved_verified": False, "renewal_enabled_verified": False,
                      "current_service_health": "not-confirmed", "report_saved": False,
                      "automatic_retry": False}
            try:
                self._phase("archive-original-intent")
                original = self.files.read(marker_path, mode=0o600)
                self.tokens._expect(marker_path, marker, 0o600)
                report["host_changes_attempted"] = True
                self.files.write_new(directory + "/" + ARCHIVE, original, 0o600)
                archived = self.tokens._snapshot(directory + "/" + ARCHIVE, 0o600)
                _require(archived["sha256"] == marker["sha256"], "archived-intent-mismatch")
                self._phase("cancel-attempt-record")
                self.files.write_new(directory + "/" + STARTED, _json_bytes({"format": 1,
                    "operation": report["operation"], "revision": plan.revision,
                    "state": "ready-for-marker-removal-not-completed", "archived_intent": archived}), 0o600)
                attempt = self.tokens._snapshot(directory + "/" + STARTED, 0o600)
                self._phase("enabled-health-and-history-check")
                self.renewal.cleanup._health(before, paused=False)
                old.recheck()
                self._phase("active-marker-remove")
                # Archive and authorization are durable before the final marker unlink.
                # A crash here is inspected from both marker presence and these records.
                self.tokens._expect_records(before[5])
                self.tokens._expect(directory + "/" + ARCHIVE, archived, 0o600)
                self.tokens._expect(directory + "/" + STARTED, attempt, 0o600)
                old.recheck()
                report.update(history_archived_verified=True, old_resources_preserved_verified=True,
                              renewal_enabled_verified=True, current_service_health="local-checks-passed")
                report["active_intent_remove_attempted"] = True
                self.files.unlink_owned(marker_path, marker["identity"])
                _require(self.files.info(marker_path) is None, "active-marker-still-present")
                report.update(result=SUCCESS, active_intent_removed_verified=True, cleanup_still_pending=False)
            except (Exception, KeyboardInterrupt) as error:
                report.update(self._failure(error))
                # Unlink may have succeeded before a directory fsync error. Do not
                # recreate an obsolete intent or change any running service here.
                report["cleanup_still_pending"] = "not-confirmed"
                try:
                    pending = self.files.info(marker_path) is not None
                    report["cleanup_still_pending"] = pending
                    report["active_intent_removed_verified"] = not pending
                except (Exception, KeyboardInterrupt):
                    pass
            finally:
                try:
                    with self.files.directory(directory, private=True):
                        self.files.write_new(directory + "/" + REPORT, _json_bytes({**report, "report_saved": True}), 0o600)
                    report["report_saved"] = True
                except (Exception, KeyboardInterrupt):
                    pass
            return report


def run_retired_cancel(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("取消失败清理需要交互终端，不接受自动确认。")
        return 2
    engine = None
    try:
        ui.say("受限取消：仅限删除前停止且已成功恢复续期的清理尝试；不删除旧证书或凭据，不重试清理。")
        with factory() as tokens:
            engine = RetiredCancel(tokens, lambda p: ui.say("取消核查阶段：" + p))
            plan = engine.check()
            ui.say("将归档原清理标记，保留原失败及续期恢复记录，核查后解除本次清理阻断；不表示清理已完成。")
            ui.say("不启停续期、不执行 Certbot、不改节点、SSH/UFW 或云端资源；不安装快捷入口。")
            ui.say("请保持连接且不要并行管理。中断或失败不自动重试，保留记录；只分享最后 JSON。")
            if not confirm(ui, "确认取消本次失败清理，归档记录并保留全部旧资源？"):
                return 130
            if not ui.interactive():
                return 2
            report = engine.cancel(plan, confirm_cancel=True)
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        if report["result"] == SUCCESS:
            ui.say("本次失败清理已取消，活动阻断已解除，历史及旧资源保留；自动续期未改变。无需修改 Surge 或重启。")
            if not report["report_saved"]:
                ui.say("最终报告未保存，请保留本次 JSON；原标记归档和取消尝试记录已保存，不要重复执行。")
            return 0
        ui.say("取消未确认完成；标记可能已归档并移除，以 JSON 和现场核查为准。不重试、不手动删除记录或重启。")
        return 1
    except (KeyboardInterrupt, EOFError):
        ui.say("操作中断；保留现场，核对记录，不自动重试。")
        return 130
    except Exception as error:
        result = {"format": 1, "operation": "retired-cleanup-cancel", "result": "precheck-failed",
                  "host_changes_attempted": False, "cleanup_completed": False}
        if engine is not None:
            result.update(engine._failure(error))
        ui.say(json.dumps(result, ensure_ascii=False, indent=2))
        return 1
