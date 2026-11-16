"""Opt-in operator adapter for a fresh, explicitly reviewed package update."""

import json
import uuid

from .installer import Terminal, confirm
from .packagecontents import require
from .packageflow import PackageFlow
from .packageinspection import NO_CHANGE, selected_changes
from .packagejob import JobSpec
from .packagematerial import save_material
from .packageplan import PackagePlan, SUCCESS as PLAN_OK
from .packageprompts import PackagePrompts
from .tokenchange import real_token_change


SUCCESS = "packages-restored-external-test-required"


class PackageUpdate:
    def __init__(self, tokens, ui):
        self.prep, self.tokens, self.ui = tokens.prep, tokens, ui
        self.phase, self.saved, self.job = "not-started", None, None
        self.plan = PackagePlan(tokens, self._phase)
        self.flow = PackageFlow(tokens, self._phase)
        self.report = {"format": 1, "operation": "package-update", "result": "stopped-inspection-required",
                       "host_changes_attempted": False, "maintenance_attempted": False,
                       "installation_submit_attempted": False, "material_write_attempted": False,
                       "material_saved_verified": False, "review_receipt_saved": False,
                       "operator_review_confirmed": False, "security_audit_passed": False,
                       "upgrade_completed": False, "automatic_retry": False}

    def _phase(self, phase):
        self.phase = phase
        if phase in {"isolated-cache-preparation", "fresh-download", "private-material-write"}:
            self.report["host_changes_attempted"] = True
        if phase == "maintenance-entry":
            self.report.update(host_changes_attempted=True, maintenance_attempted=True)
        if phase == "submit-once":
            self.report["installation_submit_attempted"] = True
        self.ui.say("更新阶段：" + phase)

    def _confirm(self, question):
        require(self.ui.interactive())
        value = confirm(self.ui, question)
        require(self.ui.interactive())
        return value

    def _review(self, material):
        require(material.batch.job == self.job and self.saved is None)
        self.ui.say("本轮材料含本机维护脚本及候选文件清单，可能含敏感内容；只能在本机阅读，不要上传或贴入对话。")
        if not self._confirm("确认保存本轮 root-only 审查材料？"):
            return False
        self.saved = save_material(self.prep, self.plan, material, self.report, self._phase)
        self.ui.say("本轮材料位置（不要分享文件内容）：" + self.saved.path)
        self.ui.say("请在另一 SSH 会话阅读该文件的新旧控制资料、脚本差异及候选文件清单；本工具未完成安全审计。")
        self.ui.say("只有你或可信审查者已核查具体内容、接受脚本及依赖变更时才确认；仅下载成功不算审查。无法判断请选 n。")
        self.report["operator_review_confirmed"] = self._confirm("已完成本轮材料独立审查，允许进入停机和安装确认？")
        if self.report["operator_review_confirmed"]:
            self.saved.verify(self.prep, material)
        return self.report["operator_review_confirmed"]

    def _review_check(self, material):
        require(self.saved is not None and self.report["operator_review_confirmed"] is True)
        return self.saved.verify(self.prep, material)

    def run(self, *, consent=False):
        require(consent is True and self.ui.interactive())
        try:
            self._phase("fresh-candidate-plan")
            planned = self.plan.check()
            self.report["host_changes_attempted"] |= planned.get("host_changes_attempted") is True
            if planned.get("result") != PLAN_OK:
                return self.report
            self._phase("revision-scope-check")
            with self.prep._lock():
                self.prep._no_pending_change()
                changes = selected_changes(planned, self.prep)
            if not changes:
                self.report["result"] = NO_CHANGE
                return self.report
            self.job = JobSpec(uuid.uuid4().hex, changes)
            prompts = PackagePrompts(self.ui, self.job)
            def decision(stage):
                value = prompts(stage)
                require(self.ui.interactive())
                return value
            self.report["flow"] = self.flow.run_staged(
                self.job, review=self._review, confirm=decision, review_check=self._review_check)
            self.report["result"] = self.report["flow"]["result"]
        except (EOFError, KeyboardInterrupt):
            self.report["result"] = "interrupted-inspection-required"
        except Exception:
            pass
        finally:
            self.report["phase"] = self.phase
        return self.report


def run_package_update(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        return 2
    try:
        ui.say("实验版实际软件包更新：仅完整受管 Debian 13 / amd64 main，尚未实机升级验收。")
        ui.say("与只收集材料不同，本入口经分段确认后会暂停续期、停止 Nginx 并提交一次后台安装。")
        ui.say("先检查本轮候选，无更新就结束；不接受旧报告、指定版本、自动确认或降级测试。")
        ui.say("请勿并行运行 APT/Certbot 或其他管理；不自动回退、重启或重试，断线后可能需要单独核查恢复。")
        if not confirm(ui, "确认先联网检查并保留独立缓存，后续仍逐项确认？"):
            return 130
        if not ui.interactive():
            return 2
        with factory() as tokens:
            engine = PackageUpdate(tokens, ui)
            report = engine.run(consent=True)
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        if report["result"] == NO_CHANGE:
            ui.say("本次候选无变化，未停机或安装；不为测试降级或重装。")
        elif report["result"] == SUCCESS:
            ui.say("安装后的本机及续期验收通过；仍需客户端实际使用和重启验收，本命令不会重启。")
        elif report["maintenance_attempted"]:
            ui.say("维护尚未确认完成，服务或续期可能停用。用 package-update-status --json 只读查看原任务；")
            ui.say("不要重跑更新、重启、停止后台任务、删除标记或手动解除启动保护。只分享脱敏 JSON。")
        else:
            ui.say("本次未进入维护安装；独立缓存和可能的材料保留，不代表审查或升级完成。")
        if report["result"] in {NO_CHANGE, SUCCESS}:
            return 0
        return 130 if report["result"].startswith(("cancelled-", "interrupted-", "review-not-approved-")) else 1
    except (EOFError, KeyboardInterrupt):
        ui.say("已中断。若已进入维护，后台任务可能继续；只读查询 package-update-status --json，不重试或重启。")
        return 130
    except Exception:
        ui.say("更新未确认完成，原始异常未显示。保留现场，只读查询 package-update-status --json；不要重试或解除保护。")
        return 1
