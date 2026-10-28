"""Explicit one-lineage deletion, never a general uninstall or retry engine."""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time
import uuid

from .activation import _digest
from .deployment import NodeSpec
from .domaininventory import BASE, ROOTS, Inventory
from .hostprep import STATE, Command, PreparationError, Reply
from .installer import Terminal, confirm
from .retiredplan import PARTS, RetiredPlan, ScopeBlocked, _require
from .tokenchange import CURRENT, _json_bytes, real_token_change


INTENT = "retired-cleanup-intent"
SUCCESS = "retired-domain-cleaned"


def lineage_paths(domain):
    return (ROOTS["live"] + "/" + domain, ROOTS["archive"] + "/" + domain,
            ROOTS["renewal"] + "/" + domain + ".conf")


def delete_args(domain, logs):
    return ["certbot", "delete", "--non-interactive", "--cert-name", domain,
            "--config-dir", BASE, "--work-dir", "/var/lib/letsencrypt", "--logs-dir", logs,
            "--no-directory-hooks", "--max-log-backups", "0"]


@dataclass(frozen=True)
class CleanupPlan:
    domain: str = field(repr=False)
    revision: str = field(repr=False)
    counts: dict = field(repr=False)


class RetiredCleanup:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.files
        self.progress, self.phase = progress, "not-started"
        self.scope = RetiredPlan(tokens, self._phase)
        self.linux_style_live_links = 0

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def _preserved_tree(self, excluded):
        """Bounded metadata only; no old Token, private key or ACME account reads."""
        inventory = Inventory(self.files)
        result = {}
        self.linux_style_live_links = 0

        def visit(path, depth):
            if path in excluded:
                return
            _require(depth <= 8 and len(result) < 2048, "preserved-tree-limit")
            item = inventory.info(path)
            if item is None:
                result[path] = None
                return
            _require(item.st_uid == os.geteuid(), "preserved-owner")
            link = stat.S_ISLNK(item.st_mode)
            # Linux symlink permission bits are always 0777 and are not access rights.
            # Keep the owner, no-follow path and archive-target checks instead.
            if not link:
                _require(not item.st_mode & 0o022, "preserved-metadata")
            fingerprint = inventory.watched[path]
            # Removing a child legitimately changes shared directory size/times.
            if path in ROOTS.values():
                fingerprint = fingerprint[:5]
            result[path] = fingerprint
            if stat.S_ISDIR(item.st_mode):
                names, state = inventory.scan(path)
                _require(state == "observed", "preserved-tree-incomplete")
                for name in names:
                    visit(path + "/" + name, depth + 1)
            elif link:
                relative = PurePosixPath(path).relative_to(BASE).parts
                _require(len(relative) == 3 and relative[0] == "live"
                         and relative[2] in {part + ".pem" for part in PARTS}, "preserved-symlink")
                name, part = relative[1], relative[2][:-4]
                NodeSpec(name)
                destination = self.files.readlink(path)
                match = re.fullmatch(r"\.\./\.\./archive/" + re.escape(name) + "/" + part
                                     + r"([1-9][0-9]{0,9})\.pem", destination)
                _require(match is not None, "preserved-symlink-target")
                archive = ROOTS["archive"] + "/" + name + "/" + part + match[1] + ".pem"
                _require(inventory.metadata(archive, "file", private=part == "privkey") == "observed",
                         "preserved-symlink-target-metadata")
                if stat.S_IMODE(item.st_mode) == 0o777:
                    self.linux_style_live_links += 1
                result[path] = (fingerprint, destination)
            else:
                _require(stat.S_ISREG(item.st_mode) and item.st_nlink == 1, "preserved-file-type")

        for path in (*ROOTS.values(), BASE + "/accounts"):
            visit(path, 0)
        inventory.recheck()
        return result

    def _check(self, domain):
        data = self.scope.inspect_locked(domain)
        target, before, inventory, credential, counts, _history = data
        self._phase("preserved-resources-check")
        preserved = self._preserved_tree((*lineage_paths(domain), credential))
        self._phase("snapshot-recheck")
        inventory.recheck()
        revision = _digest(_json_bytes({"current": before[0].revision, "target": inventory.watched,
                                       "preserved": preserved}))
        return CleanupPlan(target.domain, revision, counts), data, preserved

    def check(self, domain):
        self._phase("preparation-lock")
        with self.prep._lock():
            return self._check(domain)[0]

    def _check_failure(self, error):
        reason = (error.code if isinstance(error, ScopeBlocked) else "interrupted"
                  if isinstance(error, (KeyboardInterrupt, EOFError)) else "unreadable-busy-unsupported-or-check-failed")
        result = {"failure_phase": self.phase, "reason": reason}
        trace = error.__traceback__
        while trace is not None:
            source = Path(trace.tb_frame.f_code.co_filename)
            if source.parent == Path(__file__).parent and re.fullmatch(r"[a-z_]+\.py", source.name):
                result["failure_location"] = {"module": source.name, "line": trace.tb_lineno}
            trace = trace.tb_next
        if isinstance(error, OSError):
            result["failure_category"] = "os-error"
            if type(error.errno) is int:
                result["errno"] = error.errno
        return result

    def _timer_command(self, report, key, action):
        report[key] = {"attempted": True, "exit_code": None, "execution_uncertain": True}
        reply = self.prep.runner(Command(("systemctl", action, "--now", "certbot.timer")))
        _require(isinstance(reply, Reply), "timer-command-result-unrecognized")
        report[key].update(exit_code=reply.code, execution_uncertain=reply.uncertain)
        _require(reply.code == 0 and not reply.uncertain, "timer-command-failed-or-uncertain")

    def inspect_only(self, domain):
        report = {"format": 1, "operation": "retired-cleanup-check", "result": "blocked-preserve-all",
                  "host_changes_attempted": False, "cleanup_authorized": False, "report_saved": False,
                  "certbot_attempted": False, "renewal_pause_attempted": False,
                  "current_service_health": "not-confirmed", "global_reference_check": "not-performed"}
        try:
            plan = self.check(domain)
            report.update(result="cleanup-check-passed-no-changes", target_counts=plan.counts,
                          current_service_health="local-checks-passed")
        except (Exception, KeyboardInterrupt) as error:
            report.update(self._check_failure(error))
        report["linux_style_live_links_checked"] = self.linux_style_live_links
        return report

    def _absent(self, paths):
        _require(all(self.files.info(path) is None for path in paths), "deleted-resources-still-present")

    def _health(self, before, *, paused):
        _plan, spec, record, credential, current, unchanged = before
        if paused:
            self.tokens._health_paused(spec, record, unchanged)
        else:
            # A legitimate renewal may start when the timer is re-enabled.
            self.tokens.public._public_health(spec, record)
            self.tokens._expect_records(unchanged)
        self.tokens._expect(self.prep.credential_path(spec), credential, 0o600)
        if current is not None:
            self.tokens._expect(STATE + "/" + CURRENT + ".json", current, 0o600)

    def clean(self, plan, *, confirm_ownership, confirm_delete):
        if (not isinstance(plan, CleanupPlan) or confirm_ownership is not True or confirm_delete is not True):
            raise PreparationError("必须分别确认旧资源归属及不可撤销的本机删除。")
        with self.prep._lock():
            checked, data, preserved = self._check(plan.domain)
            _require(checked == plan, "confirmation-snapshot-changed")
            target, before, inventory, credential, counts, _history = data
            paths = lineage_paths(target.domain)
            credential_metadata = inventory.watched[credential]
            credential_identity = list(credential_metadata[:2])
            directory = STATE + "/retired-cleanup-" + uuid.uuid4().hex
            intent = {"format": 1, "operation": "retired-domain-cleanup", "target_domain": target.domain,
                      "credential_path": credential, "credential_metadata": credential_metadata,
                      "target_counts": counts, "revision": plan.revision, "log_directory": directory,
                      "operator_confirmed_ownership": True, "operator_confirmed_delete": True}
            report = {"format": 1, "operation": "retired-domain-cleanup", "result": "stopped",
                      "host_changes_attempted": False, "certbot_delete_attempted": False,
                      "certificate_removed_verified": False, "credential_delete_attempted": False,
                      "credential_removed_verified": False, "preserved_scope_verified_before_enable": False,
                      "current_service_health": "not-confirmed", "renewal_restored_verified": False,
                      "renewal_paused_verified_after": False, "report_saved": False,
                      "automatic_retry": False, "global_reference_check": "not-performed",
                      "historical_file_ownership_proven": False, "operator_confirmed_ownership": True}
            timer_attempted = False
            started = time.monotonic()
            try:
                self._phase("intent-record")
                report["host_changes_attempted"] = True
                self.prep._record(INTENT, intent)
                marker = self.tokens._snapshot(STATE + "/" + INTENT + ".json", 0o600)
                self.files.private_directory_new(directory)
                self._phase("renewal-pause")
                timer_attempted = True
                self._timer_command(report, "pause_command", "disable")
                self._phase("renewal-pause-check")
                self._health(before, paused=True)
                self._phase("before-delete-recheck")
                self.scope._references(inventory, target, credential)
                _require(self._preserved_tree((*paths, credential)) == preserved, "preserved-scope-changed")
                inventory.recheck()
                self.tokens._expect(STATE + "/" + INTENT + ".json", marker, 0o600)
                self._phase("certificate-delete")
                report["certbot_delete_attempted"] = True
                reply = self.prep.runner(Command(tuple(delete_args(target.domain, directory)), 120, capture_stderr=True))
                _require(isinstance(reply, Reply), "delete-result-unrecognized")
                report["certbot"] = {"exit_code": reply.code, "execution_uncertain": reply.uncertain}
                self.files.write_new(directory + "/command-output.txt", reply.output.encode(), 0o600)
                _require(reply.code == 0 and not reply.uncertain, "delete-command-failed-or-uncertain")
                self._phase("certificate-delete-postcheck")
                # Certbot can return success after individual file-removal errors.
                self._absent(paths)
                report["certificate_removed_verified"] = True
                self._health(before, paused=True)
                _require(self._preserved_tree((*paths, credential)) == preserved, "preserved-scope-changed")
                old = Inventory(self.files)
                old.info(credential)
                _require(old.watched[credential] == credential_metadata, "old-credential-changed")
                self._phase("credential-delete")
                report["credential_delete_attempted"] = True
                old.recheck()
                self.files.unlink_owned(credential, credential_identity)
                self._absent((*paths, credential))
                report["credential_removed_verified"] = True
                self._phase("paused-postcheck")
                self._health(before, paused=True)
                _require(self._preserved_tree((*paths, credential)) == preserved, "preserved-scope-changed")
                report["preserved_scope_verified_before_enable"] = True
                self._phase("renewal-enable")
                self.tokens._expect(STATE + "/" + INTENT + ".json", marker, 0o600)
                self._timer_command(report, "enable_command", "enable")
                self._phase("enabled-postcheck")
                self._health(before, paused=False)
                self._absent((*paths, credential))
                self._phase("intent-cleanup")
                self.tokens._expect(STATE + "/" + INTENT + ".json", marker, 0o600)
                self.files.unlink_owned(STATE + "/" + INTENT + ".json", marker["identity"])
                report.update(result=SUCCESS, current_service_health="local-checks-passed",
                              renewal_restored_verified=True)
            except BaseException as error:
                report.update(self._check_failure(error))
                # Never repeat deletion or stop an in-progress Certbot service.
                if timer_attempted:
                    fallback_phase = "fallback-intent-check"
                    try:
                        if not self.prep._exists(INTENT):
                            self.prep._record(INTENT, intent)
                        fallback_phase = "fallback-pause-command"
                        self._timer_command(report, "fallback_pause_command", "disable")
                        fallback_phase = "fallback-pause-check"
                        self.tokens._paused()
                        report["renewal_paused_verified_after"] = True
                    except BaseException as fallback_error:
                        report["fallback_pause_failure"] = {**self._check_failure(fallback_error),
                                                            "failure_phase": fallback_phase}
            finally:
                report["elapsed_seconds"] = int(time.monotonic() - started)
                try:
                    with self.files.directory(directory, private=True):
                        self.files.write_new(directory + "/report.json", _json_bytes({**report, "report_saved": True}))
                    report["report_saved"] = True
                except BaseException:
                    pass
            return report


def run_retired_cleanup(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("旧域名清理需要交互终端；不接受域名参数、管道或自动确认。")
        return 2
    try:
        ui.say("实验版旧域名清理：仅限完整受管 main，尚待实机验收；不是卸载或通用恢复。")
        domain = ui.ask("要删除本机资源的旧完整小写域名（不是现用域名；留空取消）：").strip()
        if not domain:
            return 130
        NodeSpec(domain)
        with factory() as tokens:
            engine = RetiredCleanup(tokens, lambda phase: ui.say("清理阶段：" + phase))
            try:
                plan = engine.check(domain)
            except Exception as error:
                ui.say(json.dumps({"format": 1, "operation": "retired-domain-cleanup",
                                   "result": "precheck-failed", "host_changes_attempted": False,
                                   **engine._check_failure(error)}, ensure_ascii=False, indent=2))
                ui.say("停止于只读核查，尚未暂停续期或删除；保留现场，只分享脱敏 JSON。")
                return 1
            ui.say(f"仅处理旧域名：{domain}；证书归档 {plan.counts['archive_generations']} 代，独立本机凭据 1 份。")
            ui.say("检查范围有限，历史记录不构成完整归属证明；不能替你排除其他站点、脚本、容器或任务的引用。")
            if not confirm(ui, "确认这些旧证书和本机凭据属于已淘汰的测试节点，且没有其他用途或消费者？"):
                ui.say("已取消；没有修改或删除。")
                return 130
            ui.say("将暂停续期，用 Certbot 删除指定旧证书组及续期配置，再删除独立本机凭据；本次不备份，不可撤销。")
            ui.say("不改现用节点、SSH/UFW，不卸载软件，不撤销 CF Token 或证书，不删除 DNS、ACME 账户或历史日志。")
            ui.say("成功后恢复续期，可能触发真实到期续签；失败保留待核查标记，续期可能停用，不自动回退或重试。")
            ui.say("请保持 SSH 连接，不并行运行 Certbot 或其他管理操作；只分享最后 JSON，不分享原始日志。")
            if not confirm(ui, "确认不可撤销地删除上述旧本机资源，并在核查通过后恢复自动续期？"):
                ui.say("已取消；没有修改或删除。")
                return 130
            if not ui.interactive():
                raise PreparationError("终端状态改变。")
            report = engine.clean(plan, confirm_ownership=True, confirm_delete=True)
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        if report["result"] == SUCCESS:
            ui.say("旧本机资源已清理，现用节点本机检查通过，自动续期已恢复。无需修改 Surge，请再测试延迟及实际使用。")
            return 0
        ui.say("清理未确认完成，文件可能已部分删除、续期可能暂停。保留现场，查看 install-status；不要重试、删标记或直接重启。")
        return 1
    except (KeyboardInterrupt, EOFError):
        ui.say("已取消；若已进入写入阶段，请核对 install-status，不重试或删除记录。")
        return 130
    except Exception:
        ui.say("未完成清理：输入、归属或现场核对未通过。保留现有文件和记录；原始异常未显示。")
        return 1


def run_retired_cleanup_check(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("清理只读复核需要交互终端，不接受域名参数或自动确认。")
        return 2
    try:
        ui.say("只读复核旧域名清理条件；没有删除入口，不暂停续期、不执行 Certbot、不修复权限。")
        domain = ui.ask("本次复核的旧完整小写域名（留空取消）：").strip()
        if not domain:
            return 130
        NodeSpec(domain)
        ui.say(f"仅检查：{domain}。会读取现用受限配置作内存核验及检查本机 TLS；不显示秘密。")
        if not confirm(ui, "确认只读复核，不执行删除？"):
            return 130
        if not ui.interactive():
            return 2
        with factory() as tokens:
            engine = RetiredCleanup(tokens, lambda phase: ui.say("只读核查阶段：" + phase))
            report = engine.inspect_only(domain)
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        ui.say("本次没有执行清理或更改续期状态，通过也不授权删除。只分享最后 JSON。")
        return 0 if report["result"] == "cleanup-check-passed-no-changes" else 1
    except (KeyboardInterrupt, EOFError):
        ui.say("已取消只读复核；未执行删除或续期变更。")
        return 130
    except Exception:
        ui.say("未完成只读复核；输入或环境不符合要求，原始异常未显示。未执行删除或续期变更。")
        return 1
