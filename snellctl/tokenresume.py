"""Complete one pending Token replacement after a successful permission recheck."""

from dataclasses import dataclass, field
import json
import time

from .activation import _digest
from .hostprep import STATE, Command, PreparationError, Reply
from .installer import Terminal, confirm
from .tokenchange import CANDIDATE, CURRENT, INTENT, _json_bytes, dry_run_args, real_token_change
from .tokendiag import (RECHECK_LOGS, RECHECK_REPORT, RECHECK_STARTED,
                       TokenDiagnostic, summarize)


STARTED = "token-resume-started"
REPORT = "token-resume-report"
LOGS = STATE + "/token-resume-logs"


@dataclass(frozen=True)
class ResumePlan:
    domain: str = field(repr=False)
    revision: str = field(repr=False)


class TokenResume:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens = tokens
        self.prep = tokens.prep
        self.files = tokens.files
        self.progress = progress
        self.phase = "not-started"

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def _successful_recheck(self, spec, record):
        self._phase("recheck-evidence-check")
        with self.files.directory(RECHECK_LOGS, private=True):
            pass
        paths = (STATE + "/" + RECHECK_STARTED + ".json", STATE + "/" + RECHECK_REPORT + ".json",
                 RECHECK_LOGS + "/command-output.txt")
        snapshots = {p: self.tokens._snapshot(p, 0o600) for p in paths}
        if self.prep._read_record(RECHECK_STARTED) != {"format": 1, "binding": record["binding"]}:
            raise PreparationError("复测不属于当前部署。")
        report = self.prep._read_record(RECHECK_REPORT)
        result = report.get("certbot", {})
        if (report.get("format") != 1 or report.get("operation") != "token-candidate-diagnostic"
                or report.get("attempt") != "after-permission-fix"
                or report.get("result") != "candidate-probe-passed-not-committed"
                or any(report.get(key) is not True for key in (
                    "certbot_attempted", "postcheck_passed", "renewal_paused_verified_after", "report_saved"))
                or "failure_phase" in report or not isinstance(result, dict)
                or type(result.get("exit_code")) is not int or result["exit_code"] != 0
                or result.get("execution_uncertain") is not False):
            raise PreparationError("需要已完成且后置核查通过的权限复测。")
        text = self.files.read(paths[2], mode=0o600, limit=1024**2).decode("utf-8", "replace")
        evidence = summarize(spec, Reply(0, text))
        if (result != evidence or not all(evidence["evidence"].values())
                or any(evidence["signals"].values()) or evidence["error_types_seen"] or evidence["errno_seen"]):
            raise PreparationError("复测报告与保存输出不一致，或仍有错误证据。")
        for path, snapshot in snapshots.items():
            self.tokens._expect(path, snapshot, 0o600)
        return snapshots

    def _absent(self, paths):
        if any(self.files.info(p) is not None for p in paths):
            raise PreparationError("发现其他变更或临时文件，停止接续。")

    def _check(self):
        self._phase("resume-state-check")
        for name in (STARTED, REPORT):
            if self.prep._exists(name):
                raise PreparationError("本次接续已开始或完成，不重复执行。")
        self._absent([LOGS])
        diagnostic = TokenDiagnostic(self.tokens, self._phase, after_permission_fix=True)
        _plan, spec, record, unchanged = diagnostic._pending_snapshot()
        unchanged["records"].update(self._successful_recheck(spec, record))
        self.tokens._health_paused(spec, record, unchanged)
        self._absent(unchanged["absent"])
        revision = _digest(_json_bytes({"record": record, "unchanged": unchanged}))
        return ResumePlan(spec.domain, revision), spec, record, unchanged

    def check(self):
        with self.prep._lock():
            return self._check()[0]

    def finish(self, plan, *, confirm_finish):
        if not isinstance(plan, ResumePlan) or confirm_finish is not True:
            raise PreparationError("需要明确确认替换凭据和恢复自动续期。")
        with self.prep._lock():
            checked, spec, record, unchanged = self._check()
            credential_path = self.prep.credential_path(spec)
            if checked != plan:
                raise PreparationError("确认期间现场变化，未执行接续。")
            intent = self.prep._read_record(INTENT)
            intent_path = STATE + "/" + INTENT + ".json"
            current_path = STATE + "/" + CURRENT + ".json"
            old = unchanged["records"].pop(credential_path)
            candidate = unchanged["records"].pop(CANDIDATE)
            current = unchanged["records"].pop(current_path, None)
            unchanged["absent"] = [p for p in unchanged["absent"] if p != current_path]
            marker = unchanged["records"][intent_path]
            report = {"format": 1, "operation": "token-change-resume", "result": "stopped",
                      "host_changes_attempted": False, "credential_replace_attempted": False,
                      "fixed_path_test_passed": False, "renewal_restored_verified": False,
                      "renewal_paused_verified_after": False, "report_saved": False,
                      "automatic_retry": False}
            started = time.monotonic()
            try:
                self._phase("resume-records")
                report["host_changes_attempted"] = True
                self.prep._record(STARTED, {"format": 1, "binding": record["binding"], "revision": plan.revision})
                self.files.private_directory_new(LOGS)
                self.tokens._health_paused(spec, record, unchanged)
                self._absent(unchanged["absent"])
                self.tokens._expect(credential_path, old, 0o600)
                self.tokens._expect(CANDIDATE, candidate, 0o600)
                content = self.files.read(CANDIDATE, mode=0o600)
                if _digest(content) != candidate["sha256"]:
                    raise PreparationError("候选凭据在核对后变化。")
                self._phase("credential-replace")
                report["credential_replace_attempted"] = True
                self.files.replace_owned(credential_path, content, identity=old["identity"], digest=old["sha256"], mode=0o600)
                saved = self.tokens._credential(credential_path)
                if saved["sha256"] != candidate["sha256"]:
                    raise PreparationError("正式凭据替换结果不符。")
                self._phase("fixed-path-dry-run")
                args = dry_run_args(spec, credential_path)
                args[args.index("--logs-dir") + 1] = LOGS
                args.append("--no-random-sleep-on-renew")
                reply = self.prep.runner(Command(tuple(args), 600, capture_stderr=True))
                report["certbot"] = summarize(spec, reply)
                self._phase("capture-output")
                self.files.write_new(LOGS + "/command-output.txt", reply.output.encode(), 0o600)
                self._phase("fixed-path-result")
                if (reply.uncertain or reply.code != 0 or not all(report["certbot"]["evidence"].values())
                        or any(report["certbot"]["signals"].values())
                        or report["certbot"]["error_types_seen"] or report["certbot"]["errno_seen"]):
                    raise PreparationError("正式凭据路径的演练未完整通过。")
                self._phase("paused-postcheck")
                self.tokens._health_paused(spec, record, unchanged)
                self._absent(unchanged["absent"])
                self.tokens._expect(credential_path, saved, 0o600)
                self.tokens._expect(CANDIDATE, candidate, 0o600)
                report["fixed_path_test_passed"] = True
                self._phase("credential-record")
                value = {"format": 1, **saved}
                if current is None:
                    self.prep._record(CURRENT, value)
                else:
                    self.files.replace_owned(current_path, _json_bytes(value), identity=current["identity"],
                                             digest=current["sha256"], mode=0o600)
                committed = self.tokens._snapshot(current_path, 0o600)
                if self.prep._read_record(CURRENT) != value:
                    raise PreparationError("当前凭据记录不符。")
                self.tokens._expect(CANDIDATE, candidate, 0o600)
                self.files.unlink_owned(CANDIDATE, candidate["identity"])
                self._phase("renewal-enable")
                self.tokens._health_paused(spec, record, unchanged)
                self.tokens._expect(credential_path, saved, 0o600)
                self.tokens._expect(current_path, committed, 0o600)
                self._absent([*unchanged["absent"], CANDIDATE])
                self.prep._run(["systemctl", "enable", "--now", "certbot.timer"])
                self._phase("enabled-postcheck")
                # A real due renewal may now run; validate its live certificate
                # instead of requiring the pre-enable certificate bytes to persist.
                self.tokens.public._public_health(spec, record)
                self.tokens._expect_records(unchanged)
                self.tokens._expect(credential_path, saved, 0o600)
                self.tokens._expect(current_path, committed, 0o600)
                self._absent([*unchanged["absent"], CANDIDATE])
                self._phase("intent-cleanup")
                self.tokens._expect(intent_path, marker, 0o600)
                self.files.unlink_owned(intent_path, marker["identity"])
                report["renewal_restored_verified"] = True
                report["result"] = "token-changed-renewal-tested"
            except BaseException:
                report["failure_phase"] = self.phase
                try:
                    self.tokens._failure(intent)
                except BaseException:
                    pass
                try:
                    self.tokens._paused()
                    report["renewal_paused_verified_after"] = True
                except BaseException:
                    pass
            finally:
                report["elapsed_seconds"] = int(time.monotonic() - started)
                try:
                    digest = self.tokens._credential(credential_path)["sha256"]
                    report["fixed_credential_matches"] = ("after" if digest == intent["after_sha256"] else
                                                          "before" if digest == intent["before_sha256"] else "neither")
                except BaseException:
                    report["fixed_credential_matches"] = "unreadable"
                try:
                    self.prep._record(REPORT, {**report, "report_saved": True})
                    report["report_saved"] = True
                except BaseException:
                    pass
            return report


def run_token_resume(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("Token 接续仅允许交互终端，不接受令牌或自动确认参数。")
        return 2
    engine = None
    try:
        with factory() as tokens:
            engine = TokenResume(tokens, lambda phase: ui.say("接续阶段：" + phase))
            ui.say("实验版 Token 接续：仅限权限复测已通过、旧凭据尚未替换的当前现场；不通用恢复或回退。")
            plan = engine.check()
            ui.say(f"证书域名：{plan.domain}；使用已验证的候选，不重新输入令牌。")
            ui.say("将替换正式凭据，再执行一次 DNS 演练及 Nginx 重载，成功后恢复自动续期并清理候选/更换意图。")
            ui.say("恢复定时器后可能发生真实到期续签；不修改节点密钥、域名、端口或 SSH/UFW，不需更改 Surge。")
            ui.say("失败不自动回退或重试，正式凭据可能已替换，自动续期可能仍停用；保留新旧令牌。")
            ui.say("请保持 SSH 连接，不与其他 Certbot/root 操作并行；只分享最后 JSON，不分享原始日志。")
            if not confirm(ui, "确认完成本次 Token 更换、执行验证并恢复自动续期？"):
                ui.say("已取消；未替换凭据或恢复续期。")
                return 130
            if not ui.interactive():
                raise PreparationError("终端状态改变。")
            ui.say("DNS 传播等待 60 秒，演练命令最长 10 分钟；已关闭随机等待，请勿重复运行。")
            report = engine.finish(plan, confirm_finish=True)
            ui.say(json.dumps(report, indent=2))
            if report["result"] == "token-changed-renewal-tested":
                ui.say("本次 Token 更换完成，正式路径演练及状态核对通过，自动续期已恢复。无需修改 Surge。")
                ui.say("历史诊断和本次日志保留在 root-only 目录；确认旧令牌无其他用途后再考虑撤销。")
                return 0
            ui.say("接续未确认完成，保留现场，不重试或删除记录；检查 JSON 中的阶段和续期暂停结果。")
            return 1
    except (Exception, KeyboardInterrupt):
        ui.say(json.dumps({"format": 1, "operation": "token-change-resume", "result": "stopped",
                           "phase": engine.phase if engine else "platform", "automatic_retry": False}))
        ui.say("未确认接续完成；不显示原始异常。保留凭据和记录，不重试、重启或撤销旧令牌。")
        return 1
