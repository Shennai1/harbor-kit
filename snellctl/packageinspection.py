"""Operator-facing package material collection, with no installation capability."""

from contextlib import contextmanager
from dataclasses import asdict
import json
import uuid

from . import aptreview
from .hostprep import Command
from .installer import Terminal, confirm
from .maintenance import READ_COMMANDS
from .packagecontents import ContentsCommand, require
from .packagedownload import ArchiveCommand, CACHE, DownloadCommand, DownloadedPackages, PackageDownloads
from .packagejob import JobSpec
from .packagematerial import MATERIAL_LIMIT, save_material
from .packageplan import ALL_PACKAGES, PackagePlan, SUCCESS as PLAN_OK, package_rows
from .packagepolicy import ARCHITECTURES, revision_scope
from .packagereview import INSTALLED_NAMES, collect
from .preflight import DEPENDENCIES
from .tokenchange import real_token_change


SUCCESS = "package-review-material-saved-no-upgrade"
NO_CHANGE = "no-package-changes-no-upgrade"


def selected_changes(report, prep):
    """Only a just-produced plan is used here; the CLI accepts no saved plan input.

    Downloads independently refresh indexes and rederive this exact scope before
    fetching. These values are not package authentication or update authority.
    """
    require(type(report) is dict and report.get("format") == 1 and report.get("result") == PLAN_OK
            and all(report.get(k) is True for k in ("apt_indexes_refreshed", "simulation_completed",
                                                    "local_state_unchanged_verified")))
    rows, changes = report.get("candidates"), report.get("proposed_changes")
    require(type(rows) is list and len(rows) == len(DEPENDENCIES) and type(changes) is list and len(changes) <= 8)
    selected, available = {}, {}
    database = package_rows(prep._run(ALL_PACKAGES))
    for row in rows:
        require(type(row) is dict and set(row) == {"name", "installed", "candidate", "direction"})
        name, old, new = row["name"], row["installed"], row["candidate"]
        require(isinstance(name, str) and name in DEPENDENCIES and name not in selected
                and aptreview.version_ok(old) and aptreview.version_ok(new)
                and database.get((name, ARCHITECTURES[name])) == (old, False)
                and row["direction"] == ("unchanged" if old == new else "upgrade"))
        selected[name], available[name] = new, {new}
    deltas = []
    for row in changes:
        require(type(row) is dict and set(row) == {"name", "architecture", "installed", "candidate", "direction", "role"}
                and isinstance(row["name"], str) and row["name"] in ARCHITECTURES
                and row["direction"] == "upgrade"
                and row["role"] == ("direct" if row["name"] in DEPENDENCIES else "dependency")
                and aptreview.version_ok(row["candidate"]))
        available.setdefault(row["name"], set()).add(row["candidate"])
        deltas.append({k: row[k] for k in ("name", "architecture", "installed", "candidate")})
    return revision_scope(database, selected, deltas, available, prep.runner)


class PackageInspection:
    def __init__(self, tokens, progress=lambda phase: None):
        self.prep, self.files, self.progress = tokens.prep, tokens.files, progress
        self.phase, self.job, self.material_path = "not-started", None, None
        self.plan = PackagePlan(tokens, self._phase)
        self.downloads = PackageDownloads(tokens, self._phase)

    def _phase(self, name):
        self.phase = name
        self.progress(name)

    @contextmanager
    def _commands(self):
        original = self.prep.runner
        def guarded(c):
            require(isinstance(c, Command) and c.env == Command(("unused",)).env
                    and type(c.timeout) in {int, float} and 0 < c.timeout <= 600
                    and type(c.capture_stderr) is bool)
            if type(c) is aptreview.AptReviewCommand:
                require(c.workspace == self.plan.workspace)
                c.verify_files(self.files)
            elif type(c) in {DownloadCommand, ArchiveCommand, ContentsCommand}:
                require(self.job is not None and c.workspace == CACHE + "/" + self.job.job_id)
                if type(c) is DownloadCommand:
                    require(c.pins == tuple(v.name + "=" + v.after for v in self.job.changes))
                c.verify_files(self.files)
            else:
                require(type(c) is Command and c.capture_stderr == (c.argv == ("nginx", "-v")))
                args = c.argv
                allowed = args in READ_COMMANDS | {ALL_PACKAGES}
                if args[:2] == ("dpkg", "--compare-versions"):
                    allowed = (len(args) == 5 and args[3] == "gt"
                               and aptreview.version_ok(args[2]) and aptreview.version_ok(args[4]))
                names = {v.name for v in self.job.changes} if self.job else set()
                if args[:2] == ("dpkg-query", "--control-list"):
                    allowed = len(args) == 3 and args[2] in names
                elif args[:2] == ("dpkg-query", "--control-show"):
                    allowed = len(args) == 4 and args[2] in names and args[3] in INSTALLED_NAMES
                require(allowed)
            return original(c)
        self.prep.runner = guarded
        try:
            yield
        finally:
            self.prep.runner = original

    def _save(self, material, report):
        require(material.batch.job == self.job)
        saved = save_material(self.prep, self.plan, material, report, self._phase)
        self.material_path = saved.path
        report["result"] = SUCCESS

    def inspect(self, *, consent=False, decision):
        require(consent is True and callable(decision))
        report = {"format": 1, "operation": "package-update-review", "result": "stopped-no-upgrade",
                  "host_changes_attempted": False, "download_attempted": False,
                  "material_write_attempted": False, "material_saved_verified": False, "review_receipt_saved": False,
                  "update_authorized": False, "installation_attempted": False,
                  "packages_changed_by_this_operation": False, "services_changed_by_this_operation": False,
                  "current_service_health": "not-checked", "security_audit_passed": False, "automatic_retry": False}
        try:
            with self._commands():
                self._phase("fresh-candidate-plan")
                # Plan catches its own failures; retain whether its cache write was attempted.
                planned = self.plan.check()
                report["host_changes_attempted"] = planned.get("host_changes_attempted") is True
                if planned.get("result") != PLAN_OK:
                    return report
                self._phase("revision-scope-check")
                with self.prep._lock():
                    self.prep._no_pending_change()
                    changes = selected_changes(planned, self.prep)
                if not changes:
                    report["result"] = NO_CHANGE
                    return report
                self.job = JobSpec(uuid.uuid4().hex, changes)
                report["changes"] = [asdict(c) for c in changes]
                self._phase("download-confirmation")
                if decision("download", report["changes"]) is not True:
                    report["result"] = "cancelled-before-download"
                    return report
                report.update(host_changes_attempted=True, download_attempted=True)
                batch = self.downloads.stage(self.job, consent=True)
                require(type(batch) is DownloadedPackages and batch.job == self.job)
                self._phase("package-material-collection")
                material = collect(self.prep, batch)
                self._phase("private-material-confirmation")
                if decision("save", report["changes"]) is not True:
                    report["result"] = "cancelled-before-material-save"
                    return report
                self._save(material, report)
        except (KeyboardInterrupt, EOFError):
            report["result"] = "interrupted-no-upgrade"
        except Exception:
            pass
        finally:
            report["phase"] = self.phase
        return report


def run_package_review(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        return 2
    try:
        ui.say("实验版升级包审查材料：仅完整受管 Debian 13 / amd64 main，不执行升级。")
        ui.say("先联网刷新独立官方索引；有受支持的更新才分别确认下载和本机材料保存。")
        ui.say("不停止节点/续期，不改 SSH/UFW，不安装快捷入口；不接受旧报告、指定版本或自动确认。")
        ui.say("请勿并行运行 APT/Certbot 或其他管理操作；无更新就结束，不为测试降级或重装。")
        if not confirm(ui, "确认联网检查并保留独立缓存，不升级？"):
            return 130
        if not ui.interactive():
            return 2
        def decision(stage, changes):
            if not ui.interactive():
                raise EOFError
            if stage == "download":
                for c in changes:
                    ui.say(f"{c['name']}：{c['before']} -> {c['after']}")
                ui.say("下载前会再次刷新索引、复核精确范围；变化就停止，不安装、不执行包内脚本。")
                return confirm(ui, "确认下载上述软件包并读取新旧版本控制资料？")
            require(stage == "save")
            ui.say("完整材料含本机维护脚本及候选文件清单，可能含本地敏感内容；不能直接分享给 AI 或上传。")
            ui.say("仅保存到新建 root-only 目录；不会把材料或确认当作安全审查结论及安装授权。")
            return confirm(ui, "确认保存仅供本机人工审查的材料？")
        with factory() as tokens:
            engine = PackageInspection(tokens, lambda phase: ui.say("审查阶段：" + phase))
            report = engine.inspect(consent=True, decision=decision)
            if report["material_saved_verified"]:
                ui.say("本机材料位置（不要分享文件内容）：" + engine.material_path)
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        if report["result"] == NO_CHANGE:
            ui.say("本次候选没有变化，正常结束；不代表全部软件最新或安全，不为测试降级或重装。")
        elif report["result"] == SUCCESS:
            ui.say("审查材料已保存并核对，尚未进行人工安全审核，也没有授予安装许可。")
        ui.say("本次没有升级、停机或恢复操作。只分享最后 JSON；缓存及可能的部分材料保留，不自动清理。")
        if report["result"] in {SUCCESS, NO_CHANGE}:
            return 0
        return 130 if report["result"].startswith(("cancelled-", "interrupted-")) else 1
    except (KeyboardInterrupt, EOFError):
        ui.say("已中断；缓存或部分材料可能保留，本命令没有执行升级或停止服务。")
        return 130
    except Exception:
        ui.say("审查未完成；缓存或部分材料可能保留，原始异常未显示，本命令没有执行升级。")
        return 1
