"""One candidate probe for a pending Token change; never finish or roll it back."""

from dataclasses import dataclass, field
import json
import re
import time

from .activation import _binding, _digest
from .client import _read_deployment_snapshot
from .hostprep import CREDENTIAL, STATE, Command, PreparationError, Reply
from .installer import Terminal, confirm
from .tokenchange import (CANDIDATE, CURRENT, INTENT, UNCHANGED_RECORDS, _json_bytes,
                          dry_run_args, dry_run_evidence, real_token_change)


STARTED = "token-diagnostic-started"
REPORT = "token-diagnostic-report"
LOGS = STATE + "/token-diagnostic-logs"
SIGNALS = {
    "cloudflare_api_error": r"CloudFlareAPIError|Error communicating with the Cloudflare API",
    "zone_lookup_error": r"Error determining zone_id|Unable to determine zone_id",
    "dns_challenge_failed": r"Challenge failed for domain|Some challenges have failed|All challenges have failed",
    "hook_failed": r"Hook 'deploy-hook' reported error code [1-9]",
    "network_error": r"ConnectionError|ConnectTimeout|ReadTimeout|NameResolutionError|SSLError",
    "lock_error": r"Another instance of Certbot is already running|LockError|already locked",
    "storage_error": r"PermissionError|Permission denied|No space left|Read-only file system",
    "argument_or_plugin_error": r"unrecognized arguments|requested.*plugin does not appear to be installed",
    "traceback_present": r"Traceback \(most recent call last\)",
    "log_rotation_seen": r"doRollover",
}
ERROR_TYPES = ("PermissionError", "FileNotFoundError", "FileExistsError", "OSError",
               "ValueError", "TypeError", "AttributeError", "AssertionError", "ImportError",
               "ModuleNotFoundError", "PluginError", "CertStorageError", "CloudFlareAPIError")


def summarize(spec, reply):
    if (not isinstance(reply, Reply) or type(reply.code) is not int
            or type(reply.uncertain) is not bool or not isinstance(reply.output, str)):
        raise PreparationError("诊断执行器没有返回明确结果。")
    return {
        "exit_code": None if reply.uncertain else reply.code,
        "execution_uncertain": reply.uncertain,
        "output_characters": len(reply.output),
        "evidence": dry_run_evidence(spec, reply.output),
        "signals": {k: bool(re.search(v, reply.output, re.I)) for k, v in SIGNALS.items()},
        "error_types_seen": [x for x in ERROR_TYPES if re.search(r"\b" + x + r"\b", reply.output)],
        "errno_seen": sorted({int(x) for x in re.findall(r"\[Errno ([0-9]{1,3})\]", reply.output)}),
    }


@dataclass(frozen=True)
class DiagnosticPlan:
    revision: str = field(repr=False)


class TokenDiagnostic:
    def __init__(self, token_change, progress=lambda phase: None):
        self.tokens = token_change
        self.prep = token_change.prep
        self.files = token_change.files
        self.progress = progress
        self.phase = "not-started"

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def _check(self):
        self._phase("pending-state-check")
        for name in ("key-rotation-intent", "port-change-intent", STARTED, REPORT):
            if self.prep._exists(name):
                raise PreparationError("已有其他变更或本次诊断记录，不重复执行。")
        for path in (LOGS, CREDENTIAL + ".snellctl-new", STATE + "/" + CURRENT + ".json.snellctl-new"):
            if self.files.info(path) is not None:
                raise PreparationError("发现不应存在的临时文件，保留现场。")
        intent = self.prep._read_record(INTENT)
        if (set(intent) != {"format", "binding", "before_sha256", "after_sha256"}
                or type(intent["format"]) is not int or intent["format"] != 1
                or any(not isinstance(intent[k], str) or not re.fullmatch(r"[a-f0-9]{64}", intent[k])
                       for k in ("binding", "before_sha256", "after_sha256"))
                or intent["before_sha256"] == intent["after_sha256"]):
            raise PreparationError("Token 更换意图不符合受限诊断范围。")
        self._phase("credential-check")
        with self.files.directory("/etc/snellctl/credentials", private=True):
            pass
        old, candidate = self.tokens._credential(CREDENTIAL), self.tokens._credential(CANDIDATE)
        if old["sha256"] != intent["before_sha256"] or candidate["sha256"] != intent["after_sha256"]:
            raise PreparationError("只允许旧凭据尚未替换、候选仍匹配本轮输入的现场。")
        if self.prep._exists(CURRENT) and self.prep._read_record(CURRENT) != {"format": 1, **old}:
            raise PreparationError("当前凭据记录不匹配。")
        self._phase("deployment-check")
        # Only this diagnostic permits this exact pending Token state. Ordinary
        # management/export still calls read_deployment and refuses every intent.
        spec, _keys, record = _read_deployment_snapshot(self.prep)
        spec = self.tokens.local._version(spec)
        if record["binding"] != _binding(spec) or record["binding"] != intent["binding"]:
            raise PreparationError("当前部署和更换意图不一致。")
        self.tokens.public._validate_node(spec, record["ssh_port"])
        snapshots = {STATE + "/" + name + ".json": self.tokens._snapshot(STATE + "/" + name + ".json", 0o600)
                     for name in (*UNCHANGED_RECORDS, INTENT)}
        snapshots.update({CREDENTIAL: old, CANDIDATE: candidate})
        if self.prep._exists(CURRENT):
            path = STATE + "/" + CURRENT + ".json"
            snapshots[path] = self.tokens._snapshot(path, 0o600)
        absent = [STATE + "/" + name + ".json" for name in ("key-rotation-intent", "port-change-intent")]
        absent += [CREDENTIAL + ".snellctl-new", STATE + "/" + CURRENT + ".json.snellctl-new"]
        if not self.prep._exists(CURRENT):
            absent.append(STATE + "/" + CURRENT + ".json")
        unchanged = {"lineage": self.tokens._lineage(spec), "records": snapshots, "absent": absent}
        self._phase("paused-health-check")
        self.tokens._health_paused(spec, record, unchanged)
        revision = _digest(_json_bytes({"record": record, "unchanged": unchanged}))
        return DiagnosticPlan(revision), spec, record, unchanged

    def check(self):
        with self.prep._lock():
            return self._check()[0]

    def run(self, plan, *, confirm_probe):
        if not isinstance(plan, DiagnosticPlan) or confirm_probe is not True:
            raise PreparationError("需要明确确认单次 DNS 诊断。")
        with self.prep._lock():
            checked, spec, record, unchanged = self._check()
            if checked != plan:
                raise PreparationError("确认期间现场发生变化，停止诊断。")
            report = {"format": 1, "operation": "token-candidate-diagnostic", "result": "stopped",
                      "certbot_attempted": False, "postcheck_passed": False,
                      "renewal_paused_verified_after": False, "report_saved": False}
            started = time.monotonic()
            try:
                self._phase("diagnostic-records")
                self.prep._record(STARTED, {"format": 1, "binding": record["binding"]})
                self.files.private_directory_new(LOGS)
                self._phase("candidate-dry-run")
                args = dry_run_args(spec, CANDIDATE)
                args[args.index("--logs-dir") + 1] = LOGS
                args.append("--no-random-sleep-on-renew")
                report["certbot_attempted"] = True
                reply = self.prep.runner(Command(tuple(args), 600, capture_stderr=True))
                report["certbot"] = summarize(spec, reply)
                self._phase("capture-output")
                # Raw data stays local/root-only; only fixed labels, booleans and
                # numeric exit/errno values are permitted in the shareable report.
                self.files.write_new(LOGS + "/command-output.txt", reply.output.encode(), 0o600)
                self._phase("postcheck")
                self.tokens._health_paused(spec, record, unchanged)
                if any(self.files.info(path) is not None for path in unchanged["absent"]):
                    raise PreparationError("演练期间出现了其他变更记录或临时文件。")
                report["postcheck_passed"] = True
                report["result"] = ("execution-uncertain" if reply.uncertain else
                                    "command-failed" if reply.code != 0 else
                                    "evidence-incomplete" if not all(report["certbot"]["evidence"].values()) else
                                    "candidate-probe-passed-not-committed")
            except (Exception, KeyboardInterrupt):
                report["failure_phase"] = self.phase
            finally:
                report["elapsed_seconds"] = int(time.monotonic() - started)
                try:
                    self.tokens._paused()
                    report["renewal_paused_verified_after"] = True
                except (Exception, KeyboardInterrupt):
                    pass
                try:
                    self.prep._record(REPORT, {**report, "report_saved": True})
                    report["report_saved"] = True
                except (Exception, KeyboardInterrupt):
                    pass
            return report


def run_token_diagnostic(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("候选令牌诊断只允许交互终端，不接受自动确认或 Token 参数。")
        return 2
    diagnostic = None
    try:
        with factory() as engine:
            diagnostic = TokenDiagnostic(engine, lambda phase: ui.say("诊断阶段：" + phase))
            ui.say("只诊断已有的候选令牌，不继续更换；自动续期须处于暂停状态。")
            plan = diagnostic.check()
            ui.say("将单独执行一次 DNS 演练，访问 Cloudflare/测试 CA、增删验证 TXT，并通过既有钩子重载 Nginx。")
            ui.say("不替换正式凭据或证书、不修改 SSH/UFW，不启用续期、不删除候选或更换意图。")
            ui.say("诊断会写入 root-only 记录和独立日志；原始日志可能敏感，只分享最后的 JSON。请勿并行运行 Certbot。")
            if not confirm(ui, "确认使用已有候选令牌执行单次诊断？"):
                ui.say("已取消；未执行新的演练。")
                return 130
            if not ui.interactive():
                raise PreparationError("终端状态改变。")
            ui.say("已关闭演练前的随机等待；DNS 传播仍等待 60 秒，整次命令最长等待 10 分钟。请保持连接。")
            report = diagnostic.run(plan, confirm_probe=True)
            ui.say(json.dumps(report, indent=2))
            ui.say("诊断结束不等于更换完成，自动续期未由本命令恢复。保留新旧令牌与现场，不重复执行。")
            return 0 if report["result"] == "candidate-probe-passed-not-committed" else 1
    except (Exception, KeyboardInterrupt):
        ui.say(json.dumps({"format": 1, "operation": "token-candidate-diagnostic", "result": "stopped",
                           "phase": diagnostic.phase if diagnostic else "platform"}))
        ui.say("未确认诊断完成；不显示原始异常。保留现场，不重试或删除记录。")
        return 1
