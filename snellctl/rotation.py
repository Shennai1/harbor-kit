"""One-key rotation for a verified, completed main node; no rollback or retry.

The intent spans service changes and both current manifests. Its presence blocks
client export and further mutations. A hard kill/power loss can bypass cleanup;
the intent is a stop-for-inspection marker, not a crash recovery transaction.
"""

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field, replace
import json
import secrets

from .activation import _binding, _digest
from .client import read_deployment
from .deployment import render_files
from .hostprep import STATE, PreparationError
from .installer import Terminal, confirm, real_installation


INTENT = "key-rotation-intent"
LABELS = {"snell": "Snell PSK", "shadowtls": "ShadowTLS 密码"}


@dataclass(frozen=True)
class RotationPlan:
    component: str
    domain: str = field(repr=False)
    public_port: int
    revision: str = field(repr=False)


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


class KeyRotation:
    def __init__(self, publication):
        self.public = publication
        self.local = publication.local
        self.prep = publication.prep
        self.files = publication.files

    def _check(self, component):
        if component not in LABELS:
            raise PreparationError("仅允许单独更换 Snell 或 ShadowTLS 密钥。")
        spec, keys, record = read_deployment(self.prep)
        spec = self.local._version(spec)
        if record["binding"] != _binding(spec):
            raise PreparationError("当前版本与部署记录不一致，停止更换。")
        self.public._validate_node(spec, record["ssh_port"])
        for path in (spec.node_dir + "/snell.conf", spec.node_dir + "/shadowtls.json",
                     STATE + "/public-files.json", STATE + "/public-ready.json"):
            if self.files.info(path + ".snellctl-new") is not None:
                raise PreparationError("发现未处理的候选文件；不覆盖、不清理。")
        self.public._public_health(spec, record)
        revision = _digest(_json_bytes(record))
        return RotationPlan(component, spec.domain, spec.public_port, revision), spec, keys, record

    def check(self, component):
        with self.prep._lock():
            plan, _spec, _keys, _record = self._check(component)
            return plan

    def _record_snapshot(self, name, expected):
        path = STATE + "/" + name + ".json"
        identity = self.files.identity(path)
        content = self.files.read(path, mode=0o600)
        if json.loads(content) != expected or self.files.identity(path) != identity:
            raise PreparationError("当前记录被修改，停止更换。")
        return identity, _digest(content)

    def _stop(self, unit, port):
        self.prep._run(["systemctl", "stop", unit])
        fields = self.public._fields(unit, "ActiveState,SubState,MainPID")
        if fields != {"ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}:
            raise PreparationError("无法确认旧服务已停止。")
        if self.prep._run(["ss", "-H", "-lntu", "sport = :" + str(port)]).strip():
            raise PreparationError("旧服务端口仍有监听，停止更换。")

    def rotate(self, plan, *, confirm_change, confirm_ssh_reconnected):
        if not isinstance(plan, RotationPlan) or confirm_change is not True or confirm_ssh_reconnected is not True:
            raise PreparationError("需确认更换目标及独立 SSH 已重新连接。")
        with self.prep._lock():
            current, spec, keys, record = self._check(plan.component)
            if current != plan:
                raise PreparationError("确认期间部署已经变化，请重新检查；未更换密钥。")
            for _ in range(8):
                fresh = secrets.token_hex(32)
                if fresh not in {keys.psk, keys.shadowtls_password}:
                    break
            else:
                raise PreparationError("未生成独立的新密钥，停止更换。")
            snell = plan.component == "snell"
            new_keys = replace(keys, **({"psk": fresh} if snell else {"shadowtls_password": fresh}))
            path = spec.node_dir + ("/snell.conf" if snell else "/shadowtls.json")
            unit = spec.snell_service if snell else spec.shadowtls_service
            port = spec.snell_port if snell else spec.public_port
            content = next(item.content.encode() for item in render_files(spec, new_keys) if item.target.path == path)
            old = record["node"]["files"][path]
            originals = {"public-files": self._record_snapshot("public-files", record["node"]),
                         "public-ready": self._record_snapshot("public-ready", record)}
            intent = {"format": 1, "component": plan.component, "binding": record["binding"],
                      "before_sha256": old["sha256"], "after_sha256": _digest(content)}
            self.prep._record(INTENT, intent)
            try:
                intent_identity, intent_digest = self._record_snapshot(INTENT, intent)
                self._stop(unit, port)
                self.files.replace_owned(path, content, identity=old["identity"], digest=old["sha256"], mode=0o600)
                updated = deepcopy(record)
                updated["node"]["files"][path] = {
                    "identity": self.files.identity(path), "mode": 0o600, "sha256": _digest(content),
                }
                self.local._verify_owned(spec, updated["node"])
                self.prep._run(["systemctl", "start", unit])
                self.local._wait_running(spec, public_entry=True)
                self.public._public_health(spec, updated)
                # These two replacements are not atomic together. The intent
                # prevents readers accepting either intermediate manifest pair.
                for name, value in (("public-files", updated["node"]), ("public-ready", updated)):
                    identity, digest = originals[name]
                    self.files.replace_owned(STATE + "/" + name + ".json", _json_bytes(value),
                                             identity=identity, digest=digest, mode=0o600)
                self._record_snapshot("public-files", updated["node"])
                self._record_snapshot("public-ready", updated)
                self.public._public_health(spec, updated)
                if self._record_snapshot(INTENT, intent) != (intent_identity, intent_digest):
                    raise PreparationError("更换意图记录发生变化，保留现场。")
                self.files.unlink_owned(STATE + "/" + INTENT + ".json", intent_identity)
            except BaseException:
                uncertain = False
                # An unlink followed by a failed fsync may already have removed
                # the marker. Restore only an absent marker, never overwrite it.
                try:
                    if not self.prep._exists(INTENT):
                        self.prep._record(INTENT, intent)
                except BaseException:
                    uncertain = True
                for target in dict.fromkeys((spec.shadowtls_service, unit)):
                    for action in ("stop", "disable"):
                        try:
                            self.prep._run(["systemctl", action, target])
                        except BaseException:
                            uncertain = True
                    try:
                        if (self.public._fields(target, "ActiveState,SubState,MainPID") !=
                                {"ActiveState": "inactive", "SubState": "dead", "MainPID": "0"}
                                or self.public._fields(target, "UnitFileState") != {"UnitFileState": "disabled"}):
                            uncertain = True
                    except BaseException:
                        uncertain = True
                raise PreparationError("密钥更换未完成，保留现场且不恢复旧密钥；" +
                                       ("停用或记录结果不确定，必须立即人工核查。" if uncertain else
                                        "入口及所选服务已执行停止与禁用，必须人工核查。")) from None
            return "key-rotated-external-test-required"


@contextmanager
def real_rotation():
    with real_installation() as installation:
        yield KeyRotation(installation.public)


def run_rotation(*, factory=real_rotation, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("密钥更换仅允许交互终端；不接受管道或自动确认。")
        return 2
    attempted = False
    try:
        ui.say("实验版密钥更换：仅限本工具完整部署的 main 节点；仍需逐台验收，不提供自动恢复。")
        ui.say("1. 仅更换 Snell PSK\n2. 仅更换 ShadowTLS 密码\n其他输入取消")
        component = {"1": "snell", "2": "shadowtls"}.get(ui.ask("选择：").strip())
        if component is None:
            ui.say("已取消；未读取或更换节点密钥。")
            return 130
        with factory() as engine:
            ui.say("正在只读核对现有配置、服务、TLS、续期与防火墙。")
            plan = engine.check(component)
            ui.say(f"目标：{LABELS[component]}；{plan.domain}；IPv4 TCP {plan.public_port}。")
            ui.say("会短暂中断节点连接，客户端必须更新；只生成所选的新随机密钥，不显示、不备份旧密钥。")
            ui.say("失败会尝试停止并禁用入口，保留待核查记录；不自动恢复。断电或强制终止可能绕过停用处理。")
            ui.say("请保留当前会话，通过不依赖本节点的连接另开 SSH，确认登录及恢复控制台可用。")
            if not confirm(ui, "已确认独立 SSH 新连接和恢复控制台可用？"):
                ui.say("已取消；未更换密钥。")
                return 130
            if not confirm(ui, f"确认仅更换 {LABELS[component]}？"):
                ui.say("已取消；未更换密钥。")
                return 130
            if not ui.interactive():
                raise PreparationError("终端状态改变。")
            attempted = True
            result = engine.rotate(plan, confirm_change=True, confirm_ssh_reconnected=True)
            if result != "key-rotated-external-test-required":
                raise PreparationError("更换结果未明确成功。")
            ui.say("所选密钥已更换，服务与本机 TLS 检查通过；尚未验证客户端密钥认证。")
            ui.say("使用 client 或菜单 5 单独确认显示新配置，在 Surge 中更新后测试延迟及实际使用；不要发送配置给 AI。")
            return 0
    except (Exception, KeyboardInterrupt) as exc:
        ui.say("更换未确认完成：不能保证入口已停止，旧密钥不保证可用。查看 install-status，保留现场；不要重试或重启。" if attempted
               else "已停止：检查完成记录、配置归属及当前服务；未执行密钥更换，原始错误内容未显示。")
        ui.say("snellctl-diagnostic: " + json.dumps({"format": 1, "operation": "key-rotation",
                                                    "host_changes_attempted": attempted, "result": "stopped"}))
        return 130 if isinstance(exc, (EOFError, KeyboardInterrupt)) else 1
