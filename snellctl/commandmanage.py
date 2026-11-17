"""External-source management-code replacement/removal; never manage node assets."""

from contextlib import contextmanager
import json
import os
from pathlib import Path

from .commandinstall import _platform_check, read_source
from .entrypoint import (
    BASE, COMMAND, BACKUP, INTENT, STAGE, MODULES, LEGACY_MODULES, LEGACY_SNAPSHOT, PENDING_PATHS,
    WRAPPER, Tree, digest, management_lock, snapshot, verify_installation,
)
from .hostprep import HostFiles, PreparationError
from .installer import Terminal, confirm


BLOCKED = b'#!/bin/sh\nprintf "%s\\n" "snellctl maintenance incomplete; inspect from verified external source." >&2\nexit 1\n'


class CommandManagement:
    def __init__(self, root, source):
        self.root, self.source = Path(root), Path(source)
        self.files = HostFiles(self.root)
        self.changes_attempted = False
        self.phase = "precheck"

    def close(self):
        self.files.close()

    def _external_source(self):
        installed = self.root / BASE.lstrip("/")
        if self.source.resolve().is_relative_to(installed.resolve()):
            raise PreparationError("请从单独核验的外部源码运行，不允许运行中的管理代码替换或移除自身。")

    def _read_tree(self, base, modules):
        tree = Tree(self.root, os.geteuid())
        try:
            for directory in (base, base + "/snellctl"):
                with self.files.directory(directory, private=True):
                    pass
            if (tree.names(base) != {"manifest.json", "launcher.py", "snellctl"}
                    or tree.names(base + "/snellctl") != set(modules)):
                raise PreparationError("管理目录存在额外或缺失文件，停止。")
            paths = ["manifest.json", "launcher.py"] + ["snellctl/" + n for n in modules]
            return {p: tree.read(base + "/" + p, mode=0o600) for p in paths}
        finally:
            tree.close()

    def _installed(self):
        with self.files.directory(BASE + "/snellctl") as fd:
            names = set(os.listdir(fd))
        modules = MODULES if names == set(MODULES) else LEGACY_MODULES
        value = verify_installation(self.root, uid=os.geteuid(), modules=modules)
        if modules == LEGACY_MODULES and value != LEGACY_SNAPSHOT:
            raise PreparationError("旧版来源不在已审查基线内，不接管。")
        data = self._read_tree(BASE, modules)
        return {"snapshot": value, "modules": modules, "data": data,
                "base_identity": self.files.identity(BASE),
                "command_identity": self.files.identity(COMMAND)}

    def plan(self, action):
        if action not in ("update", "remove"):
            raise PreparationError("未知管理操作。")
        self._external_source()
        if any(self.files.info(path) is not None for path in PENDING_PATHS):
            raise PreparationError("已有维护现场，不重试或接管。")
        before = self._installed()
        target = read_source(self.source) if action == "update" else None
        after = snapshot({p: digest(d) for p, d in target.items()}) if target else None
        return {"action": action, "before": before, "target": target, "after": after}

    def _replace_command(self, expected, data):
        if self.files.read(COMMAND, mode=0o755) != expected:
            raise PreparationError("快捷入口已改变，停止。")
        self.files.replace_owned(COMMAND, data, identity=self.files.identity(COMMAND),
                                 digest=digest(expected), mode=0o755)

    def _rename(self, source, dest, identity):
        if self.files.identity(source) != identity or self.files.info(dest) is not None:
            raise PreparationError("切换目录身份或目标异常。")
        with self.files.directory("/usr/local/lib") as fd:
            os.rename(Path(source).name, Path(dest).name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)

    def _remove_tree(self, base, expected, modules, identity):
        if self.files.identity(base) != identity or self._read_tree(base, modules) != expected:
            raise PreparationError("待移除代码已改变，停止。")
        for relative, data in expected.items():
            path = base + "/" + relative
            item = self.files.identity(path)
            if self.files.read(path, mode=0o600, limit=256 * 1024) != data:
                raise PreparationError("待移除文件已改变，停止。")
            self.files.unlink_owned(path, item)
        for path in (base + "/snellctl", base):
            with self.files.parent(path) as (fd, name):
                os.rmdir(name, dir_fd=fd)
                os.fsync(fd)

    def execute(self, expected):
        current = self.plan(expected["action"])
        if current != expected:
            raise PreparationError("确认期间管理代码发生变化，停止。")
        action, before, target = current["action"], current["before"], current["target"]
        if action == "update" and current["after"] == before["snapshot"]:
            return self._report("command-already-current", current)
        self.phase = "intent-record"
        self.changes_attempted = True
        intent = json.dumps({"format": 1, "operation": "command-" + action,
                             "before": before["snapshot"], "after": current["after"]}, sort_keys=True).encode()
        self.files.write_new(INTENT, intent)
        intent_identity = self.files.identity(INTENT)
        if action == "update":
            self.phase = "stage-code"
            self.files.private_directory_new(STAGE)
            with self.files.directory(STAGE + "/snellctl", create=True, private=True):
                pass
            staged = {p: d for p, d in target.items() if p != "command"}
            hashes = {p: digest(d) for p, d in target.items()}
            staged["manifest.json"] = json.dumps({"format": 1, "kind": "harbor-kit-command",
                "files": hashes, "snapshot_sha256": current["after"]}, sort_keys=True).encode()
            for relative, data in staged.items():
                self.files.write_new(STAGE + "/" + relative, data)
            if self._read_tree(STAGE, MODULES) != staged:
                raise PreparationError("候选代码核查失败。")
        self.phase = "entry-block"
        if self._installed() != before:
            raise PreparationError("已安装代码改变，停止。")
        self._replace_command(WRAPPER, BLOCKED)
        if action == "update":
            self.phase = "directory-switch"
            stage_identity = self.files.identity(STAGE)
            self._rename(BASE, BACKUP, before["base_identity"])
            self._rename(STAGE, BASE, stage_identity)
            if self._read_tree(BASE, MODULES) != staged:
                raise PreparationError("切换后代码核查失败。")
            self.phase = "old-code-remove"
            self._remove_tree(BACKUP, before["data"], before["modules"], before["base_identity"])
            self.phase = "entry-publish"
            self._replace_command(BLOCKED, WRAPPER)
            if verify_installation(self.root, uid=os.geteuid()) != current["after"]:
                raise PreparationError("更新后入口核查失败。")
        else:
            self.phase = "code-remove"
            self._remove_tree(BASE, before["data"], before["modules"], before["base_identity"])
            if self.files.read(COMMAND, mode=0o755) != BLOCKED:
                raise PreparationError("移除时入口改变，停止。")
            self.files.unlink_owned(COMMAND, self.files.identity(COMMAND))
        self.phase = "intent-cleanup"
        if self.files.read(INTENT, mode=0o600) != intent:
            raise PreparationError("维护标记改变，保留现场。")
        self.files.unlink_owned(INTENT, intent_identity)
        if any(self.files.info(path) is not None for path in PENDING_PATHS):
            raise PreparationError("存在剩余维护现场，停止。")
        if action == "remove" and any(self.files.info(p) is not None for p in (BASE, COMMAND)):
            raise PreparationError("移除后仍有受管代码。")
        self.phase = "complete"
        return self._report("command-updated" if action == "update" else "command-removed", current)

    def _report(self, result, plan):
        return {"format": 1, "operation": "command-" + plan["action"], "result": result,
                "host_changes_attempted": self.changes_attempted, "node_changes_attempted": False,
                "automatic_retry": False, "snapshot_sha256": plan["after"], "node_health": "not-checked"}


@contextmanager
def real_command_management():
    _platform_check()
    engine = CommandManagement(Path("/"), Path(__file__).absolute().parent.parent)
    try:
        engine._external_source()
        with management_lock(uid=os.geteuid(), exclusive=True):
            yield engine
    finally:
        engine.close()


def run_command_management(action, *, factory=real_command_management, terminal=None):
    ui = terminal or Terminal()
    engine = None
    try:
        if not ui.interactive():
            ui.say("管理代码维护仅限交互终端；未执行更改。")
            return 2
        ui.say("实验版管理代码维护，未实机验收；仅从单独下载并核验的外部源码运行。")
        ui.say("不联网，不执行软件包、节点、证书、服务或防火墙操作；本地摘要不是作者签名。")
        with factory() as engine:
            expected = engine.plan(action)
            if action == "update" and expected["after"] == expected["before"]["snapshot"]:
                ui.say(json.dumps(engine.execute(expected), ensure_ascii=False, indent=2))
                return 0
            ui.say("处理范围：" + BASE + " 和 " + COMMAND + "；维护暂存/标记仅位于相邻固定路径。")
            ui.say("请退出其他 snellctl 菜单/管理进程；旧版入口没有协作锁，不能自动证明无并发操作。")
            ui.say("中断可能使快捷命令不可用；保留外部源码和现场，不重试、不手动删标记，不自动回退。")
            if not confirm(ui, "已退出其他管理操作，并确认独立 SSH 可用？"):
                ui.say("已取消，未修改管理代码。")
                return 130
            prompt = ("确认用本次核验源码替换管理代码，成功后删除旧代码？" if action == "update"
                      else "确认永久移除管理代码及快捷命令，保留正在运行的节点和全部节点资源？")
            if not confirm(ui, prompt):
                ui.say("已取消，未修改管理代码。")
                return 130
            if not ui.interactive():
                return 2
            result = engine.execute(expected)
            ui.say(json.dumps(result, ensure_ascii=False, indent=2))
            ui.say("管理代码操作完成；不表示节点健康。无需修改客户端或重启。")
            return 0
    except (EOFError, KeyboardInterrupt):
        code = 130
    except Exception:
        code = 1
    ui.say(json.dumps({"format": 1, "operation": "command-" + action, "result": "stopped",
        "host_changes_attempted": engine is not None and engine.changes_attempted,
        "phase": engine.phase if engine else "precheck", "node_changes_attempted": False,
        "automatic_retry": False}, ensure_ascii=False))
    ui.say("未确认完成；保留外部源码及维护现场，不重试、覆盖或手动清理。原始异常未显示。")
    return code
