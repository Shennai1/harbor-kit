"""Opt-in IPv4 entry port replacement, with bounded UFW edits and no rollback.

Only current ownership records advance. Historical installation records remain
unchanged. The durable intent blocks readers across non-atomic system changes;
it cannot stop services on power loss or implement automatic crash recovery.
"""

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field, replace
import json

from .activation import _binding, _digest
from .client import read_deployment
from .deployment import render_files
from .hostprep import STATE, PreparationError
from .installer import Terminal, confirm, real_installation
from .publish import Rule, _rules_digest


INTENT = "port-change-intent"
RECORDS = ("public-files", "public-ready", "public-firewall-added",
           "renewal-test-ready", "renewal-enable-ready")


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def _input_rule(port):
    return ("-A", "ufw-user-input", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")


def _rule_args(port):
    return ["allow", "in", "proto", "tcp", "from", "0.0.0.0/0", "to", "any",
            "port", str(port), "comment", "snellctl-main"]


@dataclass(frozen=True)
class PortPlan:
    domain: str = field(repr=False)
    old_port: int
    new_port: int
    ssh_port: int
    revision: str = field(repr=False)


class PortChange:
    def __init__(self, publication):
        self.public = publication
        self.local = publication.local
        self.prep = publication.prep
        self.files = publication.files

    def _vacant(self, port):
        if self.prep._run(["ss", "-H", "-lntu", "sport = :" + str(port)]).strip():
            raise PreparationError("端口已有 TCP/UDP 监听，不接管。")

    def _snapshot(self, name, expected):
        path = STATE + "/" + name + ".json"
        identity = self.files.identity(path)
        data = self.files.read(path, mode=0o600)
        if json.loads(data) != expected or identity != self.files.identity(path):
            raise PreparationError("记录发生变化，停止更换。")
        return identity, _digest(data)

    @staticmethod
    def _with_firewall(record, firewall):
        rules, hashes, running = firewall
        result = deepcopy(record)
        result.update(rules_sha256=_rules_digest(rules), unchanged_ufw=hashes,
                      ipv4_input_sha256=_digest(json.dumps(running).encode()))
        return result

    def _expect_firewall(self, ssh_port, expected):
        actual = self.public._firewall(ssh_port)
        if actual != expected:
            raise PreparationError("防火墙增量或原有规则发生变化；保留现场。")
        return actual

    def _check(self, new_port):
        if type(new_port) is not int or not 1 <= new_port <= 65535:
            raise PreparationError("新端口须为 1 至 65535 的整数。")
        spec, keys, record = read_deployment(self.prep)
        spec = self.local._version(spec)
        if record["binding"] != _binding(spec) or new_port == spec.public_port:
            raise PreparationError("参数与记录不符或新旧端口相同；未更换。")
        new_spec = replace(spec, public_port=new_port)
        self.public._validate_node(new_spec, record["ssh_port"])
        self.public._public_health(spec, record)
        self._capabilities(spec)
        firewall = self.public._firewall(record["ssh_port"])
        if self._with_firewall(record, firewall) != record:
            raise PreparationError("防火墙在核对期间改变。")
        rules, _hashes, running = firewall
        owned = [r for r in rules if r.port == spec.public_port or r.comment == "snellctl-main"]
        if (len(owned) != 1 or owned[0] not in (
                Rule("allow", spec.public_port, "any", "snellctl-main"),
                Rule("allow", spec.public_port, "0.0.0.0/0", "snellctl-main"))
                or running.count(_input_rule(spec.public_port)) != 1
                or any(r.port == new_port for r in rules)):
            raise PreparationError("无法确认唯一的旧端口归属，或新端口已有规则。")
        self._vacant(new_port)
        records = {name: self.prep._read_record(name) for name in RECORDS}
        if records["public-ready"] != record:
            raise PreparationError("部署记录发生变化。")
        for path in (spec.node_dir + "/shadowtls.json", "/etc/systemd/system/" + spec.shadowtls_service,
                     *(STATE + "/" + name + ".json" for name in RECORDS)):
            if self.files.info(path + ".snellctl-new") is not None:
                raise PreparationError("发现未处理的候选文件；不覆盖、不清理。")
        plan = PortPlan(spec.domain, spec.public_port, new_port, record["ssh_port"],
                        _digest(_json_bytes(records)))
        return plan, spec, new_spec, keys, records, firewall, owned[0]

    def check(self, new_port):
        with self.prep._lock():
            return self._check(new_port)[0]

    def _capabilities(self, spec):
        capabilities = "cap_net_bind_service" if spec.public_port < 1024 else ""
        fields = self.public._fields(spec.shadowtls_service,
                                     "NeedDaemonReload,CapabilityBoundingSet,AmbientCapabilities")
        if fields != {"NeedDaemonReload": "no", "CapabilityBoundingSet": capabilities,
                      "AmbientCapabilities": capabilities}:
            raise PreparationError("ShadowTLS 实际加载的绑定权限不符。")

    def _health(self, spec, record, renewal):
        self.public._public_health(spec, record, renewal_record=renewal)
        self._capabilities(spec)

    def _fail_closed(self, spec, intent):
        uncertain = False
        try:
            if not self.prep._exists(INTENT):
                self.prep._record(INTENT, intent)
        except BaseException:
            uncertain = True
        for action in ("stop", "disable"):
            try:
                self.prep._run(["systemctl", action, spec.shadowtls_service])
            except BaseException:
                uncertain = True
        try:
            if (self.public._fields(spec.shadowtls_service, "ActiveState,SubState,MainPID") !=
                    {"ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}
                    or self.public._fields(spec.shadowtls_service, "UnitFileState") != {"UnitFileState": "disabled"}):
                uncertain = True
        except BaseException:
            uncertain = True
        raise PreparationError("端口更换未完成；不回退或删除遗留规则，必须人工核查。" +
                               ("入口停用或记录结果不确定。" if uncertain else "入口已停止并禁用。")) from None

    def change(self, plan, *, confirm_change, confirm_ssh_reconnected):
        if not isinstance(plan, PortPlan) or confirm_change is not True or confirm_ssh_reconnected is not True:
            raise PreparationError("需确认目标端口和独立 SSH 新连接。")
        with self.prep._lock():
            current, spec, new_spec, keys, records, before, old_rule = self._check(plan.new_port)
            if current != plan:
                raise PreparationError("确认期间部署已经变化，请重新检查；未更换端口。")
            originals = {name: self._snapshot(name, value) for name, value in records.items()}
            intent = {"format": 1, "before_binding": _binding(spec), "after_binding": _binding(new_spec),
                      "old_port": spec.public_port, "new_port": new_spec.public_port}
            self.prep._record(INTENT, intent)
            try:
                intent_snapshot = self._snapshot(INTENT, intent)
                self.prep._run(["systemctl", "stop", spec.shadowtls_service])
                if self.public._fields(spec.shadowtls_service, "ActiveState,SubState,MainPID") != {
                        "ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}:
                    raise PreparationError("旧入口未确认停止。")
                self._vacant(spec.public_port)
                self._vacant(new_spec.public_port)
                updated = deepcopy(records)
                binding = _binding(new_spec)
                node = updated["public-files"]
                node["binding"] = binding
                # Crossing 1024 changes the systemd capability template as well.
                unit_changed = False
                for item in render_files(new_spec, keys):
                    path, mode = item.target.path, item.target.mode
                    old = node["files"][path]
                    content = item.content.encode()
                    if _digest(content) == old["sha256"]:
                        continue
                    if path not in {spec.node_dir + "/shadowtls.json",
                                    "/etc/systemd/system/" + spec.shadowtls_service}:
                        raise PreparationError("端口更换不应改变其他配置。")
                    self.files.replace_owned(path, content, identity=old["identity"], digest=old["sha256"], mode=mode)
                    node["files"][path] = {"identity": self.files.identity(path), "mode": mode, "sha256": _digest(content)}
                    unit_changed |= path.endswith(".service")
                self.local._verify_owned(new_spec, node)
                if unit_changed:
                    self.prep._run(["systemd-analyze", "verify", "/etc/systemd/system/" + spec.shadowtls_service])
                    self.prep._run(["systemctl", "daemon-reload"])
                self._capabilities(new_spec)
                self._expect_firewall(plan.ssh_port, before)
                self._vacant(new_spec.public_port)
                self.prep._run(["ufw", *_rule_args(new_spec.public_port)])
                added = self.public._firewall(plan.ssh_port)
                added_rules = added[0]
                if (len(added_rules) != len(before[0]) + 1 or added_rules[:-1] != before[0]
                        or added_rules[-1] not in (Rule("allow", plan.new_port, "any", "snellctl-main"),
                                                  Rule("allow", plan.new_port, "0.0.0.0/0", "snellctl-main"))
                        or added[1] != before[1] or added[2] != [*before[2], _input_rule(plan.new_port)]):
                    raise PreparationError("新规则增量不符，不删除旧规则。")
                updated["public-ready"].update(binding=binding, node=node)
                # DNS, certificate, reload hook and timer config are unchanged.
                # Rebind their current compatibility records, not their history.
                for name in ("renewal-test-ready", "renewal-enable-ready"):
                    updated[name]["binding"] = binding
                updated["public-firewall-added"]["port"] = plan.new_port
                self.prep._run(["systemctl", "start", spec.shadowtls_service])
                self.local._wait_running(new_spec, public_entry=True)
                candidate = self._with_firewall(updated["public-ready"], added)
                self._health(new_spec, candidate, updated["renewal-enable-ready"])
                self._vacant(plan.old_port)
                self._expect_firewall(plan.ssh_port, added)
                # Delete by full IPv4 rule, never by a mutable display index.
                self.prep._run(["ufw", "delete", *_rule_args(plan.old_port)])
                expected_rules = list(added[0])
                expected_rules.remove(old_rule)
                expected_running = list(added[2])
                expected_running.remove(_input_rule(plan.old_port))
                final = self._expect_firewall(plan.ssh_port, (expected_rules, before[1], expected_running))
                updated["public-ready"] = self._with_firewall(updated["public-ready"], final)
                self._health(new_spec, updated["public-ready"], updated["renewal-enable-ready"])
                # The intent protects readers until all five records agree.
                for name in RECORDS:
                    identity, digest = originals[name]
                    self.files.replace_owned(STATE + "/" + name + ".json", _json_bytes(updated[name]),
                                             identity=identity, digest=digest, mode=0o600)
                for name in RECORDS:
                    self._snapshot(name, updated[name])
                self.public._public_health(new_spec, updated["public-ready"])
                self._capabilities(new_spec)
                self._vacant(plan.old_port)
                if self._snapshot(INTENT, intent) != intent_snapshot:
                    raise PreparationError("端口更换意图发生变化，保留现场。")
                self.files.unlink_owned(STATE + "/" + INTENT + ".json", intent_snapshot[0])
            except BaseException:
                self._fail_closed(spec, intent)
            return "port-changed-external-test-required"


@contextmanager
def real_port_change():
    with real_installation() as installation:
        yield PortChange(installation.public)


def run_port_change(*, factory=real_port_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("端口更换仅允许交互终端；不接受管道或自动确认。")
        return 2
    attempted = False
    try:
        ui.say("实验版公网端口更换：仅限本工具完整部署的 main / IPv4 TCP，仍需逐台验收。")
        raw = ui.ask("新的公网 TCP 端口（留空取消）：").strip()
        if not raw:
            ui.say("已取消；未读取或更换节点配置。")
            return 130
        if not raw.isascii() or not raw.isdecimal() or len(raw) > 5 or not 1 <= int(raw) <= 65535:
            raise PreparationError("端口格式无效。")
        with factory() as engine:
            ui.say("正在只读核对端口、配置、服务、TLS、续期及防火墙。")
            plan = engine.check(int(raw))
            ui.say(f"IPv4 TCP {plan.old_port} -> {plan.new_port}；保留 SSH {plan.ssh_port}。")
            ui.say("会中断节点连接；不更换密钥、域名、证书或本机后端端口，不新增 IPv6/UDP 放行。")
            ui.say("新入口本机检查通过后，删除本工具的旧 IPv4 放行规则；客户端需改用新端口。")
            ui.say("云安全组和公网可达性无法代查；请先确认新端口在服务商处可用。")
            ui.say("失败会尝试停止并禁用入口，不自动回退或清理防火墙；断电/强制终止可能绕过停用。")
            ui.say("保留本会话，通过不依赖本节点的连接另开 SSH，确认登录和恢复控制台可用。")
            if not confirm(ui, "已确认独立 SSH 新连接和恢复控制台可用？"):
                ui.say("已取消；未更换端口。")
                return 130
            if not confirm(ui, f"确认将公网端口从 {plan.old_port} 更换为 {plan.new_port}？"):
                ui.say("已取消；未更换端口。")
                return 130
            if not ui.interactive():
                raise PreparationError("终端状态改变。")
            attempted = True
            result = engine.change(plan, confirm_change=True, confirm_ssh_reconnected=True)
            if result != "port-changed-external-test-required":
                raise PreparationError("更换结果未明确成功。")
            ui.say("端口已更换，旧规则已移除，本机检查通过；公网连接仍待客户端验证。")
            ui.say("在 Surge 中只改端口，或用 client / 菜单 5 确认显示完整配置；不要发送含密钥配置给 AI。")
            return 0
    except (Exception, KeyboardInterrupt) as exc:
        ui.say("端口更换未确认完成，不能保证入口已停止或旧端口仍可用。查看 install-status，保留现场，不重试或重启。" if attempted
               else "已停止：核查端口范围、冲突、完成记录及服务状态；未执行端口更换，原始错误未显示。")
        ui.say("snellctl-diagnostic: " + json.dumps({"format": 1, "operation": "port-change",
                                                    "host_changes_attempted": attempted, "result": "stopped"}))
        return 130 if isinstance(exc, (EOFError, KeyboardInterrupt)) else 1
