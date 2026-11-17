"""Opt-in first installation of management code, independent of node resources."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import shutil
import sys

from .entrypoint import BASE, COMMAND, MODULES, TOTAL_LIMIT, WRAPPER, Tree, digest, snapshot, verify_installation
from .hostprep import HostFiles, PreparationError
from .installer import Terminal, confirm


def read_source(source):
    tree = Tree(source, os.geteuid())
    try:
        result = {}
        for name in MODULES:
            data = tree.read("/snellctl/" + name)
            compile(data, name, "exec")
            result["snellctl/" + name] = data
        result["launcher.py"] = result["snellctl/entrypoint.py"]
        result["command"] = WRAPPER
        if sum(map(len, result.values())) > TOTAL_LIMIT:
            raise PreparationError("管理代码超过范围。")
        return result
    finally:
        tree.close()


class CommandInstallation:
    def __init__(self, root, source, *, conflict_check=lambda: None):
        self.root, self.source = Path(root), Path(source)
        self.files = HostFiles(self.root)
        self.changes_attempted = False
        self.conflict_check = conflict_check

    def close(self):
        self.files.close()

    def plan(self):
        self.conflict_check()
        if self.files.info(BASE) is not None or self.files.info(COMMAND) is not None:
            raise PreparationError("命令或安装目录已存在，不覆盖或接管。")
        for path in ("/usr/local/lib", "/usr/local/bin"):
            info = self.files.info(path)
            if info is not None:
                with self.files.directory(path):
                    pass
        return read_source(self.source)

    def install(self, expected):
        current = self.plan()
        if current != expected:
            raise PreparationError("确认期间源码发生变化，未安装。")
        self.changes_attempted = True
        self.files.private_directory_new(BASE)
        with self.files.directory(BASE + "/snellctl", create=True, private=True):
            pass
        with self.files.directory("/usr/local/bin", create=True):
            pass
        for relative, data in current.items():
            if relative != "command":
                self.files.write_new(BASE + "/" + relative, data)
        hashes = {path: digest(data) for path, data in current.items()}
        record = {"format": 1, "kind": "harbor-kit-command", "files": hashes,
                  "snapshot_sha256": snapshot(hashes)}
        self.files.write_new(BASE + "/manifest.json", json.dumps(record, sort_keys=True).encode())
        # Publish last, with exclusive creation; no existing command is replaced.
        self.files.write_new(COMMAND, WRAPPER, mode=0o755)
        if verify_installation(self.root, uid=os.geteuid()) != record["snapshot_sha256"]:
            raise PreparationError("安装后核对未通过，保留现场。")
        return {"format": 1, "operation": "command-install", "result": "command-installed",
                "host_changes_attempted": True, "installed_code_verified": True,
                "node_changes_attempted": False, "automatic_retry": False,
                "snapshot_sha256": record["snapshot_sha256"]}


def _platform_check():
    if (os.geteuid() != 0 or sys.platform != "linux" or sys.version_info < (3, 11)
            or platform.machine() != "x86_64"):
        raise PreparationError("仅支持 root 下的 Debian 13 / amd64。")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "debian" or release.get("VERSION_ID") != "13":
        raise PreparationError("仅支持 Debian 13。")


def _command_conflict_check():
    for path in (os.environ.get("PATH", ""), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"):
        if shutil.which("snellctl", path=path) is not None:
            raise PreparationError("搜索路径已有同名命令，不覆盖或更改优先级。")


@contextmanager
def real_command_installation():
    _platform_check()
    _command_conflict_check()
    engine = CommandInstallation(Path("/"), Path(__file__).absolute().parent.parent,
                                 conflict_check=_command_conflict_check)
    try:
        yield engine
    finally:
        engine.close()


def run_command_install(*, factory=real_command_installation, terminal=None):
    ui = terminal or Terminal()
    engine = None
    try:
        if not ui.interactive():
            ui.say("快捷命令安装仅限交互终端；未执行安装。")
            return 2
        ui.say("实验版快捷命令首次安装：只复制本轮已核验源码，不联网，不修改节点、服务、续期或防火墙。")
        ui.say("请先按固定提交和归档校验取得可信源码；本机摘要不是上游签名或安全审计。")
        with factory() as engine:
            expected = engine.plan()
            ui.say("安装目录：" + BASE + "；快捷命令：" + COMMAND + "。已有目标会拒绝，不覆盖、不自动更新。")
            ui.say("默认打开查询菜单；变更仍须 menu --experimental 及原有独立确认。")
            ui.say("中断可能留下部分代码或入口，保留现场并查询 command-status；不自动清理、接续或重试。")
            if not confirm(ui, "确认从当前可信源码安装永久快捷命令？"):
                ui.say("已取消，未安装快捷命令。")
                return 130
            if not ui.interactive():
                ui.say("终端状态改变；未开始安装。")
                return 2
            result = engine.install(expected)
            ui.say(json.dumps(result, ensure_ascii=False, indent=2))
            ui.say("快捷命令已安装并核对。新 SSH 中可运行 snellctl；无需重启或更改客户端。")
            return 0
    except (EOFError, KeyboardInterrupt):
        code = 130
    except Exception:
        code = 1
    ui.say(json.dumps({"format": 1, "operation": "command-install", "result": "stopped",
                       "host_changes_attempted": engine is not None and engine.changes_attempted,
                       "node_changes_attempted": False, "automatic_retry": False}, ensure_ascii=False))
    ui.say("未确认安装完成，保留代码和现场；不要重跑、覆盖或手动删目录。原始异常未显示。")
    return code


def command_status(root=Path("/"), *, uid=0):
    files = HostFiles(root)
    try:
        if files.info(BASE) is None and files.info(COMMAND) is None:
            return {"format": 1, "operation": "command-status", "result": "not-installed",
                    "host_changes_attempted": False, "node_health": "not-checked"}
        value = verify_installation(root, uid=uid)
        return {"format": 1, "operation": "command-status", "result": "installed-code-verified",
                "host_changes_attempted": False, "snapshot_sha256": value, "node_health": "not-checked"}
    finally:
        files.close()


def run_command_status(*, json_output=False):
    try:
        _platform_check()
        result = command_status()
        code = 0
    except (EOFError, KeyboardInterrupt):
        result = {"format": 1, "operation": "command-status", "result": "interrupted",
                  "host_changes_attempted": False, "node_health": "not-checked"}
        code = 130
    except Exception:
        result = {"format": 1, "operation": "command-status", "result": "unavailable-or-needs-inspection",
                  "host_changes_attempted": False, "node_health": "not-checked"}
        code = 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return code
