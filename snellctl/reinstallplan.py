"""Read-only review of a completed uninstall; never permission to reinstall."""

from contextlib import contextmanager
import hashlib
import json
from pathlib import PurePosixPath
import re

from .activation import BINARIES, PACKAGE_CONFIGS
from .client import _no_duplicate_keys
from .deployment import NodeSpec, file_targets
from .domaininventory import Inventory
from .hostprep import DEPENDENCIES, DOMAIN_CURRENT, POLICY, STATE, PreparationError
from .installer import Terminal, confirm
from .publish import RENEW_DROPIN, UFW_UNCHANGED
from .retiredplan import ScopeBlocked, _require
from .tokenchange import real_token_change
from .uninstall import COMPLETE, GONE_FIELDS, SUCCESS as UNINSTALL_SUCCESS


SUCCESS = "reinstall-scope-checked-no-changes"
PENDING = ("reinstall-intent", "uninstall-intent", "retired-cleanup-intent", "domain-change-intent",
           "key-rotation-intent", "port-change-intent", "token-change-intent")
PACKAGE_QUERY = ("dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\t${Version}\n", *DEPENDENCIES)
GONE = {"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "Job": ""}
NODE_UNITS = ("snellctl-snell-main.service", "snellctl-shadowtls-main.service")
VENDOR_UNITS = ("nginx.service", "certbot.service", "certbot.timer")
STOPPED = {"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead",
           "UnitFileState": "disabled", "Job": "", "DropInPaths": "", "NeedDaemonReload": "no"}
SERVICE_EXPECTED = {}
for _unit in VENDOR_UNITS:
    SERVICE_EXPECTED[_unit] = {**STOPPED, "FragmentPath": "/usr/lib/systemd/system/" + _unit}
    if _unit.endswith(".service"):
        SERVICE_EXPECTED[_unit].update(MainPID="0", ControlPID="0")
    if _unit == "certbot.service":
        SERVICE_EXPECTED[_unit]["UnitFileState"] = "static"
SSH_FIELDS = "LoadState,ActiveState,SubState,UnitFileState,MainPID"
UNIT_QUERIES = {("systemctl", "show", unit, "-p", ",".join(fields))
                for unit, fields in SERVICE_EXPECTED.items()}
UNIT_QUERIES.update(("systemctl", "show", unit, "-p", GONE_FIELDS) for unit in NODE_UNITS)
UNIT_QUERIES.add(("systemctl", "show", "ssh.service", "-p", SSH_FIELDS))
READ_COMMANDS = UNIT_QUERIES | {
    PACKAGE_QUERY, ("dpkg", "--audit"), ("dpkg-query", "-W", "-f=${Conffiles}\n", "nginx-common"),
    ("ss", "-H", "-lntp"), ("ss", "-H", "-lntup"), ("ufw", "status", "verbose"),
    ("ufw", "show", "added"), ("systemctl", "is-enabled", "ufw.service"),
    ("iptables", "-S", "INPUT"), ("iptables", "-S", "ufw-user-input"),
    ("ip6tables", "-S", "INPUT"), ("ip6tables", "-S", "ufw6-user-input"),
}
LIMITATIONS = (
    "仅支持本工具已成功卸载的 Debian 13 / amd64 main；不是新机安装、重装执行器或损坏现场恢复。",
    "记录只提供历史关联，仍须核对当前状态；通过不证明资源全机独占，也不授权重装或删除历史。",
    "不读取 CF Token、节点密钥、证书私钥、ACME 账户内容或原始日志；只读指定记录及公共系统配置。",
    "不联网、不运行 Certbot 或 Nginx 测试、不刷新 APT、不改服务或防火墙，不写入持久报告。",
    "软件包本地摘要仅检测配置改变，不证明来源信任、版本最新或漏洞已修复。",
    "只观察旧入口及已知程序监听；新域名、端口、DNS、凭据和证书尚未选择或验证。",
    "SSH 监听与规则不证明新连接或云安全组可用；没有检查全部内核规则、任务或容器。",
    "复用原协作锁并复查已读元数据和状态，不是全系统原子快照，无法阻止外部 root 并发变更。",
    "保留软件包、ACME 账户、空目录和历史；重装为独立实验入口，不能直接重跑新机安装。",
)


def _hex_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


class ReinstallPlan:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.files
        self.progress, self.phase = progress, "not-started"

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    @contextmanager
    def _commands(self):
        original = self.prep.runner
        def guarded(command):
            if command.argv not in READ_COMMANDS or command.capture_stderr:
                raise PreparationError("重装预检查只允许固定的只读查询。")
            return original(command)
        self.prep.runner = guarded
        try:
            yield
        finally:
            self.prep.runner = original

    def _json(self, inventory, path):
        inventory.info(path)
        value = json.loads(self.files.read(path, mode=0o600), object_pairs_hook=_no_duplicate_keys)
        _require(isinstance(value, dict), "record-unrecognized")
        return value

    def _record(self, inventory, name):
        return self._json(inventory, STATE + "/" + name + ".json")

    def _absent(self, inventory, path):
        _require(inventory.info(path) is None, "unexpected-resource-preserve-all")

    def _directory(self, inventory, path, expected=(), *, private=False, missing=False):
        names, state = inventory.scan(path, private=private)
        _require((state == "observed" and set(names) == set(expected)) or
                 (missing and state == "missing" and not expected), "directory-layout-unrecognized")

    def _history(self, inventory):
        inventory.info(STATE + "/lock")
        _require(self._record(inventory, "owner") == {"format": 1, "scope": "new-host-preparation"},
                 "owner-record-unrecognized")
        for name in PENDING:
            self._absent(inventory, STATE + "/" + name + ".json")
        complete = self._record(inventory, COMPLETE)
        _require(set(complete) == {"format", "operation", "result", "directory", "revision"}
                 and type(complete["format"]) is int and complete["format"] == 1
                 and complete["operation"] == "managed-uninstall" and complete["result"] == UNINSTALL_SUCCESS
                 and _hex_digest(complete["revision"]), "uninstall-completion-unrecognized")
        directory = complete["directory"]
        _require(isinstance(directory, str) and
                 re.fullmatch(re.escape(STATE) + r"/uninstall-[a-f0-9]{32}", directory) is not None,
                 "uninstall-history-path-unrecognized")
        _require(inventory.metadata(directory, "directory", private=True) == "observed", "uninstall-history-metadata")
        report = self._json(inventory, directory + "/report.json")
        _require(type(report.get("format")) is int and report["format"] == 1
                 and report.get("operation") == "managed-uninstall" and report.get("result") == UNINSTALL_SUCCESS
                 and report.get("reinstall_ready") is False and report.get("automatic_retry") is False
                 and all(report.get(key) is True for key in (
                     "node_stopped_verified", "entry_rule_removed_verified", "certificate_removed_verified",
                     "credential_removed_verified", "renewal_disabled_verified", "ssh_and_other_rules_verified",
                     "completion_recorded", "report_saved", "final_state_verified")), "uninstall-report-not-success")
        attempt = self._json(inventory, directory + "/certificate-attempt.json")
        _require(set(attempt) == {"domain"}, "certificate-attempt-unrecognized")
        spec = NodeSpec(attempt["domain"])
        domain_digest = hashlib.sha256(spec.domain.encode()).hexdigest()
        _require(self._record(inventory, "certificate-ready") == {"domain_sha256": domain_digest},
                 "certificate-history-mismatch")
        if inventory.info(STATE + "/" + DOMAIN_CURRENT + ".json") is not None:
            _require(self._record(inventory, DOMAIN_CURRENT) == {"format": 1, "domain_sha256": domain_digest},
                     "domain-history-mismatch")
        public = self._record(inventory, "public-ready")
        binding, ssh_port = public.get("binding"), public.get("ssh_port")
        _require(_hex_digest(binding) and type(ssh_port) is int and 1 <= ssh_port <= 65535,
                 "public-history-unrecognized")
        node = public.get("node")
        _require(isinstance(node, dict) and node.get("binding") == binding
                 and self._record(inventory, "public-files") == node
                 and self._record(inventory, "renewal-test-ready") == {"binding": binding}
                 and self._record(inventory, "renewal-enable-ready").get("binding") == binding,
                 "deployment-history-mismatch")
        expected = {**{path: 0o755 for path in BINARIES}, **{t.path: t.mode for t in file_targets(spec)}}
        entries = node.get("files")
        _require(isinstance(entries, dict) and set(entries) == set(expected), "recorded-file-scope-unrecognized")
        for path, mode in expected.items():
            item = entries[path]
            _require(isinstance(item, dict) and set(item) == {"mode", "identity", "sha256"}
                     and type(item["mode"]) is int and item["mode"] == mode and _hex_digest(item["sha256"])
                     and isinstance(item["identity"], list) and len(item["identity"]) == 2
                     and all(type(n) is int and n >= 0 for n in item["identity"]), "recorded-file-metadata-unrecognized")
            self._absent(inventory, path)
        rule = self._record(inventory, "public-firewall-added")
        old_port = rule.get("port")
        _require(type(old_port) is int and 1 <= old_port <= 65535 and old_port != ssh_port
                 and rule == {"port": old_port, "family": 4, "protocol": "tcp", "comment": "snellctl-main"},
                 "entry-history-unrecognized")
        return ssh_port, old_port

    def _layout(self, inventory):
        for path, expected in (("/etc/snellctl", ("nodes", "credentials")),
                               ("/etc/snellctl/nodes", ("main",)), ("/etc/snellctl/nodes/main", ()),
                               ("/etc/snellctl/credentials", ())):
            self._directory(inventory, path, expected, private=True)
        programs = [PurePosixPath(path) for path in BINARIES]
        self._directory(inventory, "/opt/snellctl", {p.parent.parent.name for p in programs})
        for path in programs:
            self._directory(inventory, str(path.parent.parent), {path.parent.name})
            self._directory(inventory, str(path.parent))
        for path in ("/etc/nginx/conf.d", "/etc/nginx/sites-enabled", "/etc/nginx/modules-enabled",
                     "/etc/letsencrypt/renewal", "/etc/letsencrypt/archive",
                     "/etc/letsencrypt/renewal-hooks/pre", "/etc/letsencrypt/renewal-hooks/post",
                     "/etc/letsencrypt/renewal-hooks/deploy"):
            self._directory(inventory, path, missing=True)
        self._directory(inventory, "/etc/nginx/sites-available", {"default"})
        names, state = inventory.scan("/etc/letsencrypt/live")
        _require(state == "observed" and set(names) <= {"README"}, "live-certificate-resources-remain")
        if names:
            _require(inventory.metadata("/etc/letsencrypt/live/README", "file") == "observed", "unsafe-readme")
        # Account contents and raw historical logs are neither opened nor interpreted.
        accounts = inventory.metadata("/etc/letsencrypt/accounts", "directory")
        _require(accounts in {"observed", "missing"}, "account-directory-metadata")
        for prefix in ("/etc/systemd/system/", "/run/systemd/system/"):
            for unit in (*NODE_UNITS, *VENDOR_UNITS):
                self._absent(inventory, prefix + unit)
                self._directory(inventory, prefix + unit + ".d", missing=True)
        for unit in NODE_UNITS:
            self._absent(inventory, "/usr/lib/systemd/system/" + unit)
        self._absent(inventory, RENEW_DROPIN)
        self._absent(inventory, POLICY)
        self._directory(inventory, STATE + "/home", private=True)
        inventory.info("/etc/letsencrypt/cli.ini")
        self.prep._certbot_config()
        return accounts

    def _packages(self, inventory):
        _require(not self.prep._run(["dpkg", "--audit"]).strip(), "package-audit-not-empty")
        output = self.prep._run(PACKAGE_QUERY)
        rows = [line.split("\t") for line in output.splitlines()]
        _require(len(rows) == len(DEPENDENCIES) and all(len(row) == 3 for row in rows), "packages-unrecognized")
        _require({r[0] for r in rows} == set(DEPENDENCIES) and all(
            r[1].strip() == "ii" and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,100}", r[2]) for r in rows),
            "packages-not-installed")
        for path in PACKAGE_CONFIGS:
            inventory.info(path)
        self.tokens.local._nginx_package_config()
        for package, units in (("nginx-common", ("nginx.service",)), ("certbot", VENDOR_UNITS[1:])):
            path = "/var/lib/dpkg/info/" + package + ".md5sums"
            inventory.info(path)
            sums = self.files.read(path, limit=1024**2).decode("ascii").splitlines()
            for unit in units:
                path = "/usr/lib/systemd/system/" + unit
                inventory.info(path)
                expected = hashlib.md5(self.files.read(path), usedforsecurity=False).hexdigest() + "  " + path[1:]
                _require(sums.count(expected) == 1, "vendor-unit-not-verified")
        return dict((r[0], r[2]) for r in rows)

    def _fields(self, unit, properties):
        lines = self.prep._run(["systemctl", "show", unit, "-p", properties]).splitlines()
        pairs = [line.split("=", 1) for line in lines]
        _require(all(len(pair) == 2 for pair in pairs), "unit-fields-unrecognized")
        fields = dict(pairs)
        _require(len(fields) == len(pairs) and set(fields) == set(properties.split(",")), "unit-fields-unrecognized")
        return fields

    def _state(self, ssh_port, old_port):
        for unit in NODE_UNITS:
            _require(self._fields(unit, GONE_FIELDS) == GONE, "node-unit-not-removed")
        for unit, fields in SERVICE_EXPECTED.items():
            _require(self._fields(unit, ",".join(fields)) == fields, "vendor-service-not-idle-disabled-or-unmodified")
        ssh = self._fields("ssh.service", SSH_FIELDS)
        _require(ssh == {"LoadState": "loaded", "ActiveState": "active", "SubState": "running",
                         "UnitFileState": "enabled", "MainPID": ssh["MainPID"]}
                 and re.fullmatch(r"[1-9][0-9]*", ssh["MainPID"]) is not None, "ssh-service-not-running")
        firewall = self.tokens.public._firewall(ssh_port)
        _require(not any(r.comment.startswith("snellctl-") or r.port == old_port for r in firewall[0]),
                 "old-entry-rule-or-port-reused")
        listeners = self.prep._run(["ss", "-H", "-lntup"])
        for line in listeners.splitlines():
            fields = line.split()
            _require(len(fields) >= 7 and fields[0] in {"tcp", "udp"} and ":" in fields[4], "listener-output-unrecognized")
            port = fields[4].rsplit(":", 1)[1]
            _require(port.isascii() and port.isdigit() and 1 <= int(port) <= 65535, "listener-output-unrecognized")
            _require(int(port) != old_port and not any('"' + name + '"' in line for name in (
                "nginx", "snell-server", "shadow-tls")), "old-entry-or-program-listener-present")
        return firewall, listeners, ssh

    def check(self):
        report = {"format": 1, "operation": "reinstall-plan", "scope": "uninstalled-managed-main",
                  "result": "blocked-preserve-all", "host_changes_attempted": False, "report_saved": False,
                  "all_assets_preserved": True, "reinstall_implemented": True, "reinstall_authorized": False,
                  "reinstall_ready": False, "current_state": "not-confirmed", "apt_indexes_refreshed": False,
                  "global_reference_check": "not-performed", "limitations": list(LIMITATIONS)}
        try:
            self._phase("preparation-lock")
            with self._commands(), self.prep._lock():
                inventory = Inventory(self.files)
                self._phase("completed-uninstall-records")
                ssh_port, old_port = self._history(inventory)
                self._phase("retained-layout-check")
                accounts = self._layout(inventory)
                self._phase("installed-package-check")
                packages = self._packages(inventory)
                for path in (*UFW_UNCHANGED, "/etc/ufw/user.rules"):
                    inventory.info(path)
                self._phase("stopped-services-and-ssh-check")
                state = self._state(ssh_port, old_port)
                self._phase("unchanged-state-check")
                _require(self._packages(inventory) == packages and self._state(ssh_port, old_port) == state,
                         "observed-state-changed")
                inventory.recheck()
                report.update(result=SUCCESS, current_state="uninstalled-local-checks-passed",
                              retained_packages="installed-and-local-config-checks-passed",
                              acme_account_directory=accounts, acme_account_contents_read=False,
                              historical_records="preserved-not-reset", new_deployment_parameters="not-selected",
                              required_before_reinstall=["separate-experimental-reinstall-consent",
                                  "history-generation-and-interruption-handling", "fresh-apt-trust-and-package-review",
                                  "new-parameters-credentials-and-node-keys", "explicit-installation-and-ca-consent",
                                  "fresh-host-check-and-client-reboot-acceptance"])
        except ScopeBlocked as error:
            report.update(failure_phase=self.phase, reason=error.code)
        except (KeyboardInterrupt, EOFError):
            report.update(failure_phase=self.phase, reason="interrupted")
        except Exception:
            report.update(failure_phase=self.phase, reason="unreadable-busy-unsupported-or-check-failed")
        return report


def run_reinstall_plan(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("重装预检查需要交互终端；不接受自动确认、域名、路径或秘密参数。")
        return 2
    try:
        ui.say("只读重装预检查：仅限本工具已成功卸载的 main；本命令不执行重装。")
        ui.say("核对卸载记录、保留目录、软件包、服务和 SSH/UFW；不读取秘密或 ACME 账户内容。")
        ui.say("不联网、不签发、不安装、不启停服务、不删除历史，也不安装快捷命令。请勿并行管理或运行 Certbot。")
        if not confirm(ui, "确认只读检查卸载后的状态，保留全部资源？"):
            ui.say("已取消，未执行核查或变更。")
            return 130
        if not ui.interactive():
            return 2
        with factory() as tokens:
            report = ReinstallPlan(tokens, lambda phase: ui.say("核查阶段：" + phase)).check()
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        ui.say("没有执行重装。通过也不能重跑新机安装或删除状态目录；只分享最后 JSON。")
        return 0 if report["result"] == SUCCESS else 1
    except (KeyboardInterrupt, EOFError):
        ui.say("预检查中断，没有执行安装、配置变更或删除。")
        return 130
    except Exception:
        ui.say("预检查未完成，环境未核对；原始异常未显示，没有执行安装或删除。")
        return 1
