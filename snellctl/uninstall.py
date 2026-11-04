"""Single managed-node removal, with durable intent and no automatic retry."""

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import stat
import time
import uuid

from .activation import _digest
from .domaininventory import Inventory
from .hostprep import STATE, Command, PreparationError, Reply, read_owned_files
from .installer import Terminal, confirm
from .portchange import _input_rule, _rule_args
from .publish import RENEW_DROPIN, _rules_digest
from .renewalprobe import ignore_ssh_hangup, read_only_command
from .retiredcleanup import RetiredCleanup, delete_args, lineage_paths
from .retiredplan import _require
from .tokenchange import _json_bytes, real_token_change
from .uninstallplan import UninstallPlan


INTENT = "uninstall-intent"
COMPLETE = "uninstall-ready"
SUCCESS = "managed-node-uninstalled-history-preserved"
STOP_FIELDS = "ActiveState,SubState,MainPID,ControlPID,Job,UnitFileState,NeedDaemonReload"
GONE_FIELDS = "LoadState,ActiveState,SubState,MainPID,Job"


@dataclass(frozen=True)
class UninstallTicket:
    domain: str = field(repr=False)
    public_port: int
    ssh_port: int
    revision: str = field(repr=False)


class Uninstall:
    def __init__(self, tokens, progress=lambda phase: None, *, clock=None, sleep=None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.files
        self.progress, self.phase = progress, "not-started"
        self.scope = UninstallPlan(tokens, self._phase)
        self.cleanup = RetiredCleanup(tokens, clock=clock, sleep=sleep)
        self.permitted = None

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def failure(self, error):
        self.cleanup.phase = self.phase
        return self.cleanup._check_failure(error)

    @contextmanager
    def _commands(self):
        original = self.prep.runner
        units = {"nginx.service", "snellctl-snell-main.service", "snellctl-shadowtls-main.service", "certbot.service"}
        def guarded(command):
            argv = command.argv
            if argv == self.permitted:
                self.permitted = None
            elif not (read_only_command(argv) or
                      (len(argv) == 5 and argv[:2] == ("systemctl", "show") and argv[2] in units
                       and argv[3] == "-p" and argv[4] in {STOP_FIELDS, GONE_FIELDS})):
                raise PreparationError("卸载命令不在已核查的单次操作范围内。")
            return original(command)
        self.prep.runner = guarded
        try:
            yield
        finally:
            self.permitted = None
            self.prep.runner = original

    def _command(self, argv, report, name, *, timeout=120, capture=False):
        report[name] = {"attempted": True, "exit_code": None, "execution_uncertain": True}
        self.permitted = tuple(argv)
        try:
            reply = self.prep.runner(Command(tuple(argv), timeout, capture_stderr=capture))
        finally:
            self.permitted = None
        _require(isinstance(reply, Reply), "command-result-unrecognized")
        report[name].update(exit_code=reply.code, execution_uncertain=reply.uncertain)
        _require(reply.code == 0 and not reply.uncertain, "command-failed-or-uncertain")
        return reply.output

    def _fields(self, unit, properties):
        output = self.prep._run(["systemctl", "show", unit, "-p", properties])
        pairs = [line.split("=", 1) for line in output.splitlines()]
        _require(all(len(pair) == 2 for pair in pairs), "unit-fields-unrecognized")
        fields = dict(pairs)
        _require(len(fields) == len(pairs), "unit-fields-duplicated")
        return fields

    def _stopped(self, unit):
        _require(self._fields(unit, STOP_FIELDS) == {
            "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0",
            "Job": "", "UnitFileState": "disabled", "NeedDaemonReload": "no"}, "service-not-disabled-and-stopped")

    def _gone(self, unit):
        _require(self._fields(unit, GONE_FIELDS) == {"LoadState": "not-found", "ActiveState": "inactive",
                 "SubState": "dead", "MainPID": "0", "Job": ""}, "removed-service-still-loaded")

    def _no_listeners(self, spec):
        for line in self.prep._run(["ss", "-H", "-lntup"]).splitlines():
            fields = line.split()
            _require(len(fields) >= 7 and fields[0] in {"tcp", "udp"} and ":" in fields[4], "listener-output-unrecognized")
            port = fields[4].rsplit(":", 1)[1]
            _require(port.isdigit(), "listener-output-unrecognized")
            _require(int(port) not in {spec.public_port, spec.snell_port, spec.tls_port}
                     and not any('"' + name + '"' in line for name in ("nginx", "snell-server", "shadow-tls")),
                     "managed-listener-still-present")

    def _inspect(self):
        before, inventory, _generations = self.scope.inspect_locked()
        spec, record = before[1:3]
        credential = self.prep.credential_path(spec)
        files = dict(record["node"]["files"])
        for path, mode in ((RENEW_DROPIN, 0o644), (credential, 0o600)):
            files[path] = {**self.tokens._snapshot(path, mode), "mode": mode}
        # Removing Nginx boot registration must not act on a locally edited unit.
        vendor = "/usr/lib/systemd/system/nginx.service"
        sums = self.files.read("/var/lib/dpkg/info/nginx-common.md5sums", limit=1024**2).decode("ascii")
        expected = hashlib.md5(self.files.read(vendor), usedforsecurity=False).hexdigest() + "  " + vendor[1:]
        _require(expected in sums.splitlines(), "nginx-vendor-unit-not-verified")
        for path in (vendor, "/var/lib/dpkg/info/nginx-common.md5sums", "/usr/lib/systemd/system/certbot.service",
                     "/usr/lib/systemd/system/certbot.timer", "/etc/nginx/nginx.conf", "/etc/nginx/mime.types",
                     "/etc/nginx/sites-available/default", "/etc/letsencrypt/cli.ini", STATE + "/home"):
            inventory.info(path)
        self.prep._certbot_config()
        names = {}
        for path, meta in tuple(inventory.watched.items()):
            if meta is not None and stat.S_ISDIR(meta[2]):
                names[path], state = inventory.scan(path)
                _require(state == "observed", "scope-directory-unreadable")
        preserved = self.cleanup._preserved_tree((*lineage_paths(spec.domain), credential))
        firewall = self.tokens.public._firewall(record["ssh_port"])
        inventory.recheck()
        revision = _digest(_json_bytes({"current": before[0].revision, "watched": inventory.watched,
                                       "names": names, "files": files, "preserved": preserved,
                                       "firewall": [_rules_digest(firewall[0]), firewall[1], firewall[2]]}))
        ticket = UninstallTicket(spec.domain, spec.public_port, record["ssh_port"], revision)
        return ticket, before, inventory, names, files, preserved, firewall

    def check(self):
        self._phase("preparation-lock")
        with self._commands(), self.prep._lock():
            return self._inspect()[0]

    @staticmethod
    def _removed(path, deleted):
        return any(path == item or path.startswith(item + "/") for item in deleted)

    def _scope_unchanged(self, inventory, names, deleted):
        current = Inventory(self.files)
        for path, old in inventory.watched.items():
            current.info(path)
            new = current.watched[path]
            if self._removed(path, deleted):
                _require(new is None, "removed-resource-reappeared")
            elif old is not None and stat.S_ISDIR(old[2]):
                _require(new is not None and new[:5] == old[:5], "scope-directory-changed")
                listed, state = current.scan(path)
                expected = [name for name in names[path] if not self._removed(path + "/" + name, deleted)]
                _require(state == "observed" and listed == expected, "scope-directory-entries-changed")
            else:
                _require(new == old, "scope-resource-changed")
        current.recheck()

    def _remaining(self, files, deleted):
        entries = {path: value for path, value in files.items() if path not in deleted}
        read_owned_files(self.files, {p: v["mode"] for p, v in entries.items()}, {"files": entries})

    def remove(self, ticket, *, confirm_ownership, confirm_recovery, confirm_final_state, confirm_delete):
        if (not isinstance(ticket, UninstallTicket) or
                any(value is not True for value in (confirm_ownership, confirm_recovery, confirm_final_state, confirm_delete))):
            raise PreparationError("必须分别确认独占用途、备用连接、最终服务状态及不可撤销删除。")
        with self._commands(), self.prep._lock():
            checked, before, inventory, names, files, preserved, firewall = self._inspect()
            _require(ticket == checked, "confirmation-snapshot-changed")
            spec, record = before[1:3]
            credential = self.prep.credential_path(spec)
            units = (spec.shadowtls_service, spec.snell_service, "nginx.service")
            hook = "/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-main-nginx"
            directory = STATE + "/uninstall-" + uuid.uuid4().hex
            intent = {"format": 1, "operation": "managed-uninstall", "revision": ticket.revision,
                      "directory": directory, "domain": spec.domain, "public_port": spec.public_port,
                      "ssh_port": ticket.ssh_port, "final_state": "packages-kept-services-disabled",
                      "operator_confirmed_ownership": True, "operator_confirmed_delete": True}
            report = {"format": 1, "operation": "managed-uninstall", "result": "stopped",
                      "host_changes_attempted": False, "node_stop_attempted": False,
                      "node_stopped_verified": False, "firewall_delete_attempted": False,
                      "entry_rule_removed_verified": False, "files_removed": 0,
                      "certbot_delete_attempted": False, "certificate_removed_verified": False,
                      "credential_removed_verified": False, "renewal_disabled_verified": False,
                      "ssh_and_other_rules_verified": False, "completion_recorded": False,
                      "report_saved": False, "automatic_retry": False, "reinstall_ready": False,
                      "final_state_verified": False}
            deleted, stopped = set(), set()
            current_firewall = firewall
            marker = None
            started = time.monotonic()

            def guard():
                self.tokens._expect(STATE + "/" + INTENT + ".json", marker, 0o600)
                self.tokens._paused()
                self.tokens._expect_records(before[5])
                self._remaining(files, deleted)
                self._scope_unchanged(inventory, names, deleted)
                self.prep._certbot_config()
                _require(self.cleanup._preserved_tree((*lineage_paths(spec.domain), credential)) == preserved,
                         "preserved-resources-changed")
                _require(self.tokens.public._firewall(ticket.ssh_port) == current_firewall, "firewall-delta-mismatch")
                for unit in stopped:
                    if "/etc/systemd/system/" + unit not in deleted:
                        self._stopped(unit)
                if len(stopped) == len(units):
                    self._no_listeners(spec)

            def remove_file(path):
                guard()
                # Persist the attempted action before unlink; no recovery guesses from absence.
                self.files.write_new(directory + "/file-attempt-" + str(len(deleted)) + ".json",
                                     _json_bytes({"path": path, "identity": files[path]["identity"]}))
                self.files.unlink_owned(path, files[path]["identity"])
                _require(self.files.info(path) is None, "file-delete-not-confirmed")
                deleted.add(path)
                report["files_removed"] += 1

            try:
                self._phase("intent-record")
                report["host_changes_attempted"] = True
                self.prep._record(INTENT, intent)
                marker = self.tokens._snapshot(STATE + "/" + INTENT + ".json", 0o600)
                self.files.private_directory_new(directory)
                self._phase("renewal-pause")
                self._command(["systemctl", "disable", "--now", "certbot.timer"], report, "pause_command")
                self.cleanup._wait_paused(report)
                self.tokens._health_paused(spec, record, before[5])
                guard()
                self._phase("node-stop")
                for index, unit in enumerate(units):
                    guard()
                    report["node_stop_attempted"] = True
                    self._command(["systemctl", "disable", "--now", unit], report, "stop_command_" + str(index))
                    self._stopped(unit)
                    stopped.add(unit)
                self._no_listeners(spec)
                report["node_stopped_verified"] = True
                self._phase("entry-rule-remove")
                guard()
                rules, hashes, running = firewall
                expected_rules = [r for r in rules if r.comment != "snellctl-main"]
                expected_running = list(running)
                expected_running.remove(_input_rule(spec.public_port))
                report["firewall_delete_attempted"] = True
                self._command(["ufw", "delete", *_rule_args(spec.public_port)], report, "firewall_command")
                current_firewall = (expected_rules, hashes, expected_running)
                guard()
                report["entry_rule_removed_verified"] = True
                self._phase("certificate-references-remove")
                for path in (spec.nginx_conf, hook):
                    remove_file(path)
                self.tokens.local._nginx_package_config()
                self.tokens.local._nginx_dump({"/etc/nginx/nginx.conf", "/etc/nginx/mime.types"})
                self._phase("certificate-delete")
                guard()
                for unit in units:
                    self._stopped(unit)
                self._no_listeners(spec)
                self.files.write_new(directory + "/certificate-attempt.json", _json_bytes({"domain": spec.domain}))
                report["certbot_delete_attempted"] = True
                self._command(delete_args(spec.domain, directory), report, "certbot", capture=True)
                self.cleanup._absent(lineage_paths(spec.domain))
                deleted.update(lineage_paths(spec.domain))
                report["certificate_removed_verified"] = True
                self._phase("managed-files-remove")
                remove_file(credential)
                report["credential_removed_verified"] = True
                for path in files:
                    if path not in deleted:
                        remove_file(path)
                self._phase("service-manager-reload")
                self._command(["systemctl", "daemon-reload"], report, "daemon_reload")
                self._phase("final-check")
                guard()
                for unit in units[:2]:
                    self._gone(unit)
                self._stopped("nginx.service")
                self._no_listeners(spec)
                self.tokens.public._vendor_certbot()
                _require(self._fields("certbot.service", "LoadState,FragmentPath,DropInPaths") == {
                    "LoadState": "loaded", "FragmentPath": "/usr/lib/systemd/system/certbot.service", "DropInPaths": ""},
                    "renewal-override-still-loaded")
                self.tokens.local._nginx_dump({"/etc/nginx/nginx.conf", "/etc/nginx/mime.types"})
                report.update(renewal_disabled_verified=True, ssh_and_other_rules_verified=True)
                self._phase("completion-record")
                self.prep._record(COMPLETE, {"format": 1, "operation": "managed-uninstall", "result": SUCCESS,
                                           "directory": directory, "revision": ticket.revision})
                report["completion_recorded"] = True
                self.tokens._expect(STATE + "/" + INTENT + ".json", marker, 0o600)
                self.files.unlink_owned(STATE + "/" + INTENT + ".json", marker["identity"])
                report.update(result=SUCCESS, final_state_verified=True)
            except BaseException as error:
                report.update(self.failure(error))
                # No deletion retry or implicit service restart, including after partial removal.
            finally:
                report["elapsed_seconds"] = int(time.monotonic() - started)
                try:
                    self.files.write_new(directory + "/report.json", _json_bytes({**report, "report_saved": True}))
                    report["report_saved"] = True
                except BaseException:
                    pass
            return report


def run_uninstall(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("卸载仅允许交互终端，不接受自动确认、目标路径或秘密参数。")
        return 2
    try:
        ui.say("实验版受管节点卸载：尚未实机验收；不是卸载第三方节点或恢复新机。")
        with factory() as tokens:
            engine = Uninstall(tokens)
            ui.say("正在只读检查当前受管节点及卸载范围，暂未停止或删除。")
            try:
                ticket = engine.check()
            except Exception as error:
                ui.say(json.dumps({"operation": "managed-uninstall", "result": "precheck-failed",
                                   "host_changes_attempted": False, **engine.failure(error)}, ensure_ascii=False))
                return 1
            ui.say(f"卸载目标：{ticket.domain}；IPv4 TCP {ticket.public_port}；保留 SSH TCP {ticket.ssh_port}。")
            if not confirm(ui, "确认节点、证书、本机凭据和程序只用于本项目，没有其他消费者？"):
                return 130
            if not confirm(ui, "已用独立 SSH 新连接确认登录，并确认恢复控制台可用？"):
                return 130
            ui.say("将停止并禁用节点、Nginx 和续期定时器。保留软件包、SSH/UFW、其他规则、ACME 账户和历史记录。")
            if not confirm(ui, "接受卸载后 Nginx 和续期保持停用，不自动恢复这些服务？"):
                return 130
            ui.say("将永久删除当前节点配置、专用服务、两个程序、证书组、独立本机凭据及唯一工具入口规则。")
            ui.say("不撤销云端 Token、DNS 或证书；不备份，不自动重试或回退。中断可能留下部分删除和停用状态。")
            ui.say("保留的历史和目录意味着不能直接重跑新机安装。不要并行管理或运行 Certbot。")
            if not confirm(ui, "确认现用节点将不可用，允许执行上述不可撤销卸载？"):
                return 130
            if not ui.interactive():
                return 2
            # No terminal writes during mutations; hard termination still requires inspection.
            with ignore_ssh_hangup():
                report = engine.remove(ticket, confirm_ownership=True, confirm_recovery=True,
                                       confirm_final_state=True, confirm_delete=True)
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        if report["result"] == SUCCESS:
            ui.say("受管节点已卸载，Nginx/续期已停用，SSH及其他规则核对通过。历史及软件包保留，不代表可直接重装。")
            return 0
        ui.say("卸载未确认完成，节点或续期可能停用、资源可能部分删除。保留现场查看 install-status，不重跑、不删标记或直接重启。")
        return 1
    except (KeyboardInterrupt, EOFError):
        ui.say("操作中断；若已开始卸载，先核查 install-status，不重跑或手动删记录。")
        return 130
    except Exception:
        ui.say("操作未确认完成，原始异常不显示。若已进入写入阶段，保留现场核查，不自动重试。")
        return 1
