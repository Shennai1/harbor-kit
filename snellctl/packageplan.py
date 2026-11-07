"""Online Debian candidate review; cache writes only, no upgrade executor."""

from contextlib import contextmanager
import json
import re
import uuid

from . import aptreview
from .client import read_deployment
from .domaininventory import Inventory
from .hostprep import Command, PreparationError, Reply, STATE
from .installer import Terminal, confirm
from .maintenance import Maintenance, READ_COMMANDS, SUCCESS as INVENTORY_OK
from .preflight import DEPENDENCIES
from .retiredplan import ScopeBlocked, _require
from .tokenchange import real_token_change


SUCCESS = "package-candidates-reviewed-no-upgrade"
ALL_PACKAGES = ("dpkg-query", "-W", "-f=${Package}\t${Architecture}\t${db:Status-Abbrev}\t${Version}\n")
LIMITATIONS = (
    "仅检查完整受管 Debian 13 / amd64 main；不是升级执行器，不安装菜单或快捷入口。",
    "经确认会联网下载官方签名索引，写入新的独立 APT 缓存；不是纯只读，不更新系统原有索引。",
    "隔离系统 APT 配置、源、偏好、代理及 hooks；方案仅基于官方 main，不等于系统原有更新策略。",
    "签名、TLS、有效期检查交给 APT，信任本机 Debian 密钥环；不证明已安装包来源或漏洞修复状态。",
    "模拟四个直接目标及其拟变化依赖，不更新其他软件，不查询 Snell/ShadowTLS 上游。",
    "保留 hold，不执行降级或卸载；额外依赖变化只列出供复核，不授予更新许可。",
    "不读取 CF Token、证书材料或原始日志；读取节点配置及包数据库用于内存核验，不输出秘密。",
    "不暂停续期、不改服务、SSH/UFW、安装记录或系统配置；观察到状态改变会停止而非自动修复。",
    "协作锁和前后复查不是全系统原子快照，不能阻止其他 root/APT 操作；结果不能复用于稍后的安装。",
    "无论结果如何都不自动重试或删除检查缓存；缓存含公共索引和固定配置，不含复制的节点秘密。",
)


def package_rows(output):
    rows, installed = output.splitlines(), {}
    _require(0 < len(rows) <= 10000, "package-database-unrecognized")
    seen = set()
    for line in rows:
        fields = line.split("\t")
        _require(len(fields) == 4, "package-database-unrecognized")
        name, arch, status, version = fields
        _require(aptreview.package_ok(name) and re.fullmatch(r"[a-z0-9-]{1,32}", arch)
                 and aptreview.version_ok(version) and (name, arch) not in seen,
                 "package-database-unrecognized")
        seen.add((name, arch))
        _require(status in {"ii ", "hi ", "rc ", "pc "}, "package-database-needs-review")
        if status in {"ii ", "hi "}:
            installed[(name, arch)] = (version, status == "hi ")
    return installed


class PackagePlan:
    def __init__(self, tokens, progress=None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.prep.files
        self.inventory = Maintenance(tokens)
        self.progress = progress or (lambda _phase: None)
        self.phase = "not-started"
        self.workspace = None

    def _phase(self, value):
        self.phase = value
        self.progress(value)

    @contextmanager
    def _commands(self):
        original = self.prep.runner
        def guarded(command):
            if isinstance(command, aptreview.AptReviewCommand):
                command.validate()
                _require(command.workspace == self.workspace, "unexpected-apt-workspace")
                command.verify_files(self.files)
            elif command.argv[:2] == ("dpkg", "--compare-versions"):
                _require(len(command.argv) == 5 and command.argv[3] == "gt"
                         and all(aptreview.version_ok(v) for v in (command.argv[2], command.argv[4]))
                         and not command.capture_stderr, "unexpected-version-command")
            else:
                _require(command.argv in READ_COMMANDS | {ALL_PACKAGES}
                         and command.capture_stderr == (command.argv == ("nginx", "-v")),
                         "unexpected-package-review-command")
            _require(command.env == Command(("unused",)).env, "unexpected-command-environment")
            return original(command)
        self.prep.runner = guarded
        try:
            yield
        finally:
            self.prep.runner = original

    def _snapshot(self, watched):
        maintenance = self.inventory
        maintenance._platform(watched)
        deployment = read_deployment(self.prep)
        spec = self.tokens.local._version(deployment[0])
        maintenance._files(watched, spec)
        maintenance._source(watched)
        direct, held = maintenance._packages()
        _require(not held and self.prep._read_record("packages-ready") == {"versions": direct},
                 "installed-packages-drifted-or-held")
        _require(not self.prep._run(["dpkg", "--audit"]).strip(), "package-audit-needs-review")
        units = maintenance._units()
        _require(all(v == "expected-state-observed" for v in units[0].values()), "service-state-needs-review")
        watched.info("/var/lib/dpkg/status")
        database = self.prep._run(ALL_PACKAGES)
        packages = package_rows(database)
        for name, version in direct.items():
            _require(sum(n == name for n, _ in packages) == 1
                     and any(packages.get((name, a)) == (version, False) for a in ("amd64", "all")),
                     "direct-package-database-mismatch")
        return deployment, spec, direct, units, database, packages

    def _apt(self, args, timeout=60):
        command = aptreview.AptReviewCommand(tuple(args), timeout, capture_stderr=True, workspace=self.workspace)
        result = self.prep.runner(command)
        _require(isinstance(result, Reply) and not result.uncertain and result.code == 0, "apt-command-failed-or-uncertain")
        # Never treat a partial refresh, sandbox fallback or warning as verified success.
        _require(not any(line.startswith(("W:", "E:", "N:")) for line in result.output.splitlines()),
                 "apt-output-needs-review")
        return result.output

    def _direction(self, old, new):
        if old == new:
            return "unchanged"
        result = self.prep.runner(Command(("dpkg", "--compare-versions", new, "gt", old)))
        _require(isinstance(result, Reply) and not result.uncertain and result.code in {0, 1}
                 and not result.output, "version-comparison-failed")
        return "upgrade" if result.code == 0 else "downgrade"

    def check(self):
        report = {"format": 1, "operation": "package-update-plan", "scope": "managed-main",
                  "result": "blocked-no-upgrade", "host_changes_attempted": False,
                  "cache_retained": False, "cache_state": "not-created",
                  "apt_indexes_refreshed": False, "simulation_completed": False,
                  "update_implemented": False, "update_authorized": False, "update_ready": False,
                  "packages_changed_by_this_operation": False, "services_changed_by_this_operation": False,
                  "report_saved": False, "automatic_retry": False, "security_patch_status": "not-assessed",
                  "current_service_health": "not-checked", "limitations": list(LIMITATIONS)}
        try:
            self._phase("local-maintenance-check")
            _require(self.inventory.check()["result"] == INVENTORY_OK, "local-maintenance-review-required")
            with self._commands(), self.prep._lock():
                self._phase("locked-state-check")
                watched = Inventory(self.files)
                before = self._snapshot(watched)
                self._phase("isolated-cache-preparation")
                self.workspace = aptreview.CACHE + "/" + uuid.uuid4().hex
                report["host_changes_attempted"] = True
                report["cache_state"] = "creation-attempted-may-be-partial"
                aptreview.prepare(self.files, self.workspace)
                report["cache_retained"] = True
                report["cache_state"] = "created-and-retained"
                self._phase("signed-index-refresh")
                self._apt(("apt-get", "update", "--error-on=any"), timeout=600)
                report["apt_indexes_refreshed"] = True
                self._phase("candidate-selection")
                selected = aptreview.candidates(self._apt(("apt-cache", "policy", *DEPENDENCIES)), before[2])
                available = aptreview.repository_versions(self._apt(("apt-cache", "madison", *DEPENDENCIES)), DEPENDENCIES)
                _require(all(selected[n] in available[n] for n in DEPENDENCIES), "candidate-not-in-official-indexes")
                direct = [{"name": n, "installed": before[2][n], "candidate": selected[n],
                           "direction": self._direction(before[2][n], selected[n])} for n in DEPENDENCIES]
                _require(not any(p["direction"] == "downgrade" for p in direct), "candidate-downgrade-refused")
                self._phase("dependency-simulation")
                changes = aptreview.simulation(self._apt(("apt-get", "--simulate", "--no-remove", "--no-install-recommends",
                                                         "install", *(n + "=" + selected[n] for n in DEPENDENCIES)), timeout=120))
                report["simulation_completed"] = True
                self._phase("dependency-origin-and-hold-check")
                names = tuple(c["name"] for c in changes)
                origins = aptreview.repository_versions(self._apt(("apt-cache", "madison", *names)), names) if names else {}
                for item in changes:
                    name, arch, old, new = item["name"], item["architecture"], item["installed"], item["candidate"]
                    _require(new in origins[name], "dependency-not-in-official-indexes")
                    previous = before[5].get((name, arch))
                    _require((previous is None and old is None) or previous == (old, False),
                             "dependency-installed-state-or-hold-mismatch")
                    _require(not any(n == name and a != arch for n, a in before[5]), "dependency-architecture-change")
                    direction = "install" if old is None else self._direction(old, new)
                    _require(direction in {"install", "upgrade"}, "dependency-downgrade-or-reinstall-refused")
                    item.update(direction=direction, role="direct" if name in DEPENDENCIES else "dependency")
                changed = {c["name"]: c["candidate"] for c in changes}
                _require(all(changed.get(p["name"], p["installed"]) == p["candidate"] for p in direct),
                         "simulation-does-not-match-selected-candidates")
                self._phase("unchanged-state-check")
                _require(self._snapshot(watched) == before, "host-state-changed-during-review")
                watched.recheck()
                report.update(result=SUCCESS, candidates=direct, proposed_changes=changes,
                              additional_dependencies_require_review=any(p["role"] == "dependency" for p in changes),
                              source_scope="fresh-isolated-debian-trixie-main-indexes",
                              repository_authentication="apt-verified-with-local-debian-keyring",
                              installed_package_origins="not-proven", local_state_unchanged_verified=True,
                              required_before_update=["separate-reviewed-update-executor", "dependency-and-module-review",
                                                      "fresh-source-and-live-recheck", "explicit-upgrade-consent",
                                                      "package-start-guards-and-maintenance-records", "client-and-reboot-acceptance"])
        except ScopeBlocked as error:
            report.update(failure_phase=self.phase, reason=error.code)
        except (KeyboardInterrupt, EOFError):
            report.update(failure_phase=self.phase, reason="interrupted")
        except Exception:
            report.update(failure_phase=self.phase, reason="unreadable-busy-unsupported-or-check-failed")
        return report


def run_package_plan(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        return 2
    try:
        ui.say("实验版 Debian 更新方案检查：仅完整受管 main，尚未实机验收；不会升级软件。")
        ui.say("将联网刷新独立官方索引并模拟依赖；写入新检查缓存，不改变系统原有 APT 源、索引或偏好。")
        ui.say("忽略系统自定义源、hooks 和代理；保留 hold，不安装、不启停服务、不改 SSH/UFW 或续期。")
        ui.say("请勿并行运行 APT/Certbot 或其他管理；输出仅供复核，不证明最新、安全或允许升级。")
        if not confirm(ui, "确认联网检查并保留独立缓存，不执行升级？"):
            return 130
        if not ui.interactive():
            return 2
        with factory() as tokens:
            report = PackagePlan(tokens, lambda phase: ui.say("检查阶段：" + phase)).check()
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        ui.say("没有升级或重启。只分享最后 JSON；缓存可能已写入，不要据此手动更新或修改归属记录。")
        return 0 if report["result"] == SUCCESS else 1
    except (KeyboardInterrupt, EOFError):
        ui.say("已中断；检查缓存可能保留，没有执行升级。")
        return 130
    except Exception:
        ui.say("检查未完成，原始异常未显示；缓存可能保留，没有执行升级。")
        return 1
