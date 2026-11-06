"""Offline component inventory, not an upgrade plan or a health verdict."""

from contextlib import contextmanager
import json
import os
import re
import stat

from .activation import BINARIES, PACKAGE_CONFIGS, _binding
from .artifacts import CATALOG
from .client import read_deployment
from .deployment import file_targets
from .doctor import os_release
from .domaininventory import Inventory
from .hostprep import DEPENDENCIES, SOURCES, STATE, PreparationError
from .installer import Terminal, confirm
from .publish import RENEW_DROPIN, renewal_dropin
from .retiredplan import ScopeBlocked, _require
from .tokenchange import UNCHANGED_RECORDS, real_token_change


SUCCESS = "component-inventory-complete-no-changes"
REVIEW = "component-inventory-review-required"
PACKAGE_QUERY = ("dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\t${Version}\n", *DEPENDENCIES)
UNIT_FIELDS = "LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload"
UNITS = ("snellctl-snell-main.service", "snellctl-shadowtls-main.service", "nginx.service",
         "certbot.service", "certbot.timer")
READ_COMMANDS = {PACKAGE_QUERY, ("dpkg", "--print-architecture"), ("dpkg", "--audit"),
                 ("nginx", "-v"), ("dpkg-query", "-W", "-f=${Conffiles}\n", "nginx-common")}
READ_COMMANDS.update(("systemctl", "show", unit, "-p", UNIT_FIELDS) for unit in UNITS)
LIMITATIONS = (
    "仅盘点本工具完整受管的 Debian 13 / amd64 main；不是升级、修复或升级授权。",
    "Snell/ShadowTLS 版本来自受管路径和代码目录，文件仅与本机归属摘要核对，不执行这两个程序。",
    "固定下载来源及指纹是已测试基线，不是本次重新下载或上游签名验证，也不证明正在运行的程序版本。",
    "只查询四个直接安装目标；不是全部依赖、Nginx 模块或全机软件包盘点。",
    "专用 Debian 源模板及公共密钥环只作本地核对，不证明已安装包的下载来源或新候选的可信度。",
    "不刷新 APT、不查询上游或漏洞库；没有最新版本、安全补丁状态、升级候选或依赖方案结论。",
    "读取受管节点配置作内存核验，不输出密钥、域名、端口或摘要；不读取 CF Token、证书材料或日志。",
    "服务查询仅作状态观察；不检查 TLS、证书有效期、监听、防火墙或公网连接，不执行 Certbot。",
    "复用已有协作锁并复查文件和版本，不是全系统原子快照，不能阻止其他 root 或软件包管理操作。",
    "不修改服务、配置、防火墙或软件包，不保存报告，不安装快捷入口；文件读取可能更新访问时间。",
)


def _versions(value):
    _require(isinstance(value, dict) and set(value) == set(DEPENDENCIES)
             and all(isinstance(v, str) and re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]{0,99}", v)
                     for v in value.values()), "package-versions-unrecognized")
    return value


class Maintenance:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.files
        self.phase, self.progress = "not-started", progress

    def _phase(self, name):
        self.phase = name
        self.progress(name)

    @contextmanager
    def _commands(self):
        original = self.prep.runner
        def guarded(command):
            if (command.argv not in READ_COMMANDS
                    or command.capture_stderr != (command.argv == ("nginx", "-v"))):
                raise PreparationError("组件盘点只允许固定的本地只读查询。")
            return original(command)
        self.prep.runner = guarded
        try:
            yield
        finally:
            self.prep.runner = original

    def _platform(self, inventory):
        path = "/etc/os-release"
        info = inventory.info(path)
        if info is not None and stat.S_ISLNK(info.st_mode):
            _require(info.st_uid == os.geteuid(), "platform-link-owner")
            _require(self.files.readlink(path) in {"../usr/lib/os-release", "/usr/lib/os-release"},
                     "platform-link-target")
            path = "/usr/lib/os-release"
            inventory.info(path)
        _require(os_release(self.files.read(path).decode("utf-8")) == {"ID": "debian", "VERSION_ID": "13"}
                 and self.prep._run(["dpkg", "--print-architecture"]).strip() == "amd64", "unsupported-platform")

    def _source(self, inventory):
        path = STATE + "/debian.sources"
        inventory.info(path)
        _require(self.files.read(path, mode=0o600) == SOURCES, "dedicated-source-template-changed")
        for name in ("debian-archive-keyring.gpg", "debian-archive-keyring.pgp"):
            inventory.info("/usr/share/keyrings/" + name)
        self.prep._check_archive_keyring()

    def _packages(self):
        output = self.prep._run(PACKAGE_QUERY)
        rows = [line.split("\t") for line in output.splitlines()]
        _require(len(rows) == len(DEPENDENCIES) and all(len(row) == 3 for row in rows)
                 and {r[0] for r in rows} == set(DEPENDENCIES), "package-query-unrecognized")
        # A held installed package is observable, but not silently eligible for updates.
        _require(all(row[1] in {"ii ", "hi "} for row in rows), "package-not-fully-installed")
        versions = _versions({row[0]: row[2] for row in rows})
        return versions, sorted(row[0] for row in rows if row[1] == "hi ")

    def _units(self):
        result, snapshot = {}, {}
        for unit in UNITS:
            output = self.prep._run(["systemctl", "show", unit, "-p", UNIT_FIELDS])
            rows = [line.split("=", 1) for line in output.splitlines()]
            _require(len(rows) == len(UNIT_FIELDS.split(",")) and all(len(row) == 2 for row in rows)
                     and {r[0] for r in rows} == set(UNIT_FIELDS.split(",")), "unit-query-unrecognized")
            fields = dict(rows)
            snapshot[unit] = fields
            prefix = "/etc/systemd/system/" if unit.startswith("snellctl-") else "/usr/lib/systemd/system/"
            expected = {"LoadState": "loaded", "FragmentPath": prefix + unit,
                        "DropInPaths": RENEW_DROPIN if unit == "certbot.service" else "", "NeedDaemonReload": "no"}
            if unit == "certbot.service":
                expected.update(ActiveState="inactive", SubState="dead", UnitFileState="static")
            elif unit == "certbot.timer":
                expected.update(ActiveState="active", SubState="waiting", UnitFileState="enabled")
            else:
                expected.update(ActiveState="active", SubState="running", UnitFileState="enabled")
            # Never emit untrusted property values, which may contain local paths or secrets.
            result[unit] = "expected-state-observed" if fields == expected else "review-required"
        return result, snapshot

    def _files(self, inventory, spec):
        for path in (*BINARIES, *(t.path for t in file_targets(spec)), RENEW_DROPIN, *PACKAGE_CONFIGS):
            inventory.info(path)
        for name in (*UNCHANGED_RECORDS, "packages-ready", "owner", "domain-current", "reinstall-ready"):
            inventory.info(STATE + "/" + name + ".json")
        _require(self.files.read(RENEW_DROPIN, mode=0o644) == renewal_dropin(spec)
                 and self.files.identity(RENEW_DROPIN) == self.prep._read_record("renewal-enable-ready").get("identity"),
                 "renewal-integration-changed")
        self.tokens.local._nginx_package_config()

    def check(self):
        report = {"format": 1, "operation": "maintenance-plan", "scope": "managed-main",
                  "result": "blocked-preserve-all", "host_changes_attempted": False, "report_saved": False,
                  "all_assets_preserved": True, "collection_complete": False, "update_implemented": False,
                  "update_authorized": False, "update_ready": False, "apt_indexes_refreshed": False,
                  "upstream_checked": False, "security_patch_status": "not-assessed",
                  "current_service_health": "not-checked", "limitations": list(LIMITATIONS)}
        try:
            self._phase("preparation-lock")
            with self._commands(), self.prep._lock():
                inventory = Inventory(self.files)
                inventory.info(STATE + "/lock")
                self._phase("platform-check")
                self._platform(inventory)
                self._phase("managed-files-and-records")
                before = read_deployment(self.prep)
                spec = self.tokens.local._version(before[0])
                _require(spec.node == "main" and _binding(spec) == before[2]["binding"], "deployment-version-binding-changed")
                self._files(inventory, spec)
                self._phase("package-inventory")
                record = self.prep._read_record("packages-ready")
                _require(set(record) == {"versions"}, "package-record-unrecognized")
                recorded = _versions(record["versions"])
                installed, held = self._packages()
                audit_clean = not self.prep._run(["dpkg", "--audit"]).strip()
                self._phase("dedicated-source-check")
                self._source(inventory)
                self._phase("service-observation")
                units, unit_snapshot = self._units()
                self._phase("unchanged-state-check")
                _require(read_deployment(self.prep) == before, "deployment-changed-during-check")
                _require(self.tokens.local._version(before[0]) == spec, "nginx-version-changed-during-check")
                _require(self.prep._read_record("packages-ready") == record
                         and self._packages() == (installed, held), "packages-changed-during-check")
                _require((not self.prep._run(["dpkg", "--audit"]).strip()) == audit_clean,
                         "package-audit-changed-during-check")
                _require(self._units() == (units, unit_snapshot), "services-changed-during-check")
                inventory.recheck()
                findings = []
                if installed != recorded:
                    findings.append("package-version-drift")
                if held:
                    findings.append("held-packages-present")
                if not audit_clean:
                    findings.append("dpkg-audit-needs-review")
                if any(value != "expected-state-observed" for value in units.values()):
                    findings.append("service-state-needs-review")
                report.update(result=REVIEW if findings else SUCCESS, collection_complete=True, findings=findings,
                              platform={"os": "debian", "version": "13", "arch": "amd64"},
                              managed_configuration="disk-templates-and-ownership-records-match",
                              programs=[{"name": item.name, "managed_version": item.version,
                                         "configured_upstream": item.url,
                                         "file_check": "matches-local-ownership-record",
                                         "version_basis": "managed-baseline-not-runtime-query",
                                         "upstream_signature_verified": False}
                                        for item in CATALOG],
                              packages=[{"name": name, "installed": installed[name], "recorded": recorded[name],
                                         "matches_record": installed[name] == recorded[name], "held": name in held}
                                        for name in DEPENDENCIES],
                              package_audit="empty" if audit_clean else "review-required",
                              package_scope="direct-install-targets-not-full-dependency-closure",
                              nginx_reported_version=spec.nginx_version, units=units,
                              package_source={"dedicated_template": "matches-tool-debian-template",
                                              "archive_keyring": "local-file-check-passed",
                                              "installed_package_origin": "not-proven",
                                              "candidate_versions": "not-queried"},
                              required_before_update=["fresh-upstream-and-security-review", "signed-index-refresh-and-dependency-review",
                                                      "separate-reviewed-update-implementation", "operator-confirmation",
                                                      "fresh-live-checks-and-client-acceptance"])
        except ScopeBlocked as error:
            report.update(failure_phase=self.phase, reason=error.code)
        except (KeyboardInterrupt, EOFError):
            report.update(failure_phase=self.phase, reason="interrupted")
        except Exception:
            report.update(failure_phase=self.phase, reason="unreadable-busy-unsupported-or-check-failed")
        return report


def run_maintenance(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("组件盘点需要交互终端，不接受自动确认或版本参数。")
        return 2
    try:
        ui.say("只读组件维护盘点：仅限完整受管 main，没有升级执行入口。")
        ui.say("读取节点配置作内存核验，不显示密钥；不读取 CF Token、证书材料或原始日志。")
        ui.say("不联网、不刷新软件源、不签发、不改配置/服务/防火墙，不安装快捷命令；请勿并行管理。")
        ui.say("结果只表示本地观察，不代表最新或安全版本，也不授权升级。")
        if not confirm(ui, "确认只读盘点组件，保留全部资源及运行状态？"):
            ui.say("已取消，未执行盘点或更改。")
            return 130
        if not ui.interactive():
            return 2
        with factory() as tokens:
            report = Maintenance(tokens, lambda phase: ui.say("盘点阶段：" + phase)).check()
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        ui.say("本次未升级、修复或重启。只分享最后 JSON；不要因此手动替换程序或重跑安装。")
        return 0 if report["result"] == SUCCESS else 1
    except (KeyboardInterrupt, EOFError):
        ui.say("已中断，未执行组件变更。")
        return 130
    except Exception:
        ui.say("盘点未完成，原始异常未显示；没有执行组件变更。")
        return 1
