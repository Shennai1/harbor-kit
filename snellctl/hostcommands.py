"""Explicit Linux-only adapter for the internal preparation engine.

Only the explicitly experimental installation wizard wires this adapter to CLI.
"""

import os
from pathlib import Path
import platform
import signal
import subprocess
import tempfile

from .doctor import os_release
from .hostprep import Command, PreparationError, Reply
from .deployment import SNELL_BINARY, SHADOWTLS_BINARY


PROGRAMS = {name: "/usr/bin/" + name for name in (
    "apt-get", "apt-cache", "dpkg", "dpkg-query", "systemctl", "certbot", "openssl", "systemd-analyze",
)}
PROGRAMS.update({"nginx": "/usr/sbin/nginx", "ss": "/usr/bin/ss",
                 "ufw": "/usr/sbin/ufw",
                 "iptables": "/usr/sbin/iptables", "ip6tables": "/usr/sbin/ip6tables",
                 SNELL_BINARY: SNELL_BINARY, SHADOWTLS_BINARY: SHADOWTLS_BINARY})


class DebianCommands:
    def __init__(self):
        if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() != 0:
            raise PreparationError("真实执行适配器只允许 Debian 13 / amd64 的 root 进程。")
        try:
            release = os_release(Path("/etc/os-release").read_text(encoding="utf-8"))
        except (OSError, UnicodeError):
            raise PreparationError("无法核对真实执行环境。") from None
        if release != {"ID": "debian", "VERSION_ID": "13"}:
            raise PreparationError("真实执行适配器仅限 Debian 13。")
        if not Path("/run/systemd/system").is_dir():
            raise PreparationError("未检测到运行中的 systemd 系统环境。")

    def __call__(self, command: Command) -> Reply:
        if (not isinstance(command, Command) or not command.argv
                or command.argv[0] not in PROGRAMS or not 0 < command.timeout <= 900
                or command.env != Command(("unused",)).env):
            raise PreparationError("拒绝不受支持的系统命令或环境。")
        if command.argv[0] in {SNELL_BINARY, SHADOWTLS_BINARY} and command.argv[1:] != ("--version",):
            raise PreparationError("直接运行节点程序只允许版本检查。")
        if command.argv[0] in {"iptables", "ip6tables"}:
            chain = "ufw-user-input" if command.argv[0] == "iptables" else "ufw6-user-input"
            if command.argv[1:] not in {("-S", "INPUT"), ("-S", chain)}:
                raise PreparationError("内核规则工具仅允许读取指定链，不允许修改。")
        capture_allowed = (command.argv in {("nginx", "-v"), (SNELL_BINARY, "--version"), (SHADOWTLS_BINARY, "--version")}
                           or (command.argv[:2] == ("certbot", "renew") and "--dry-run" in command.argv))
        if type(command.capture_stderr) is not bool or (command.capture_stderr and not capture_allowed):
            raise PreparationError("仅版本检查或续期演练允许内部捕获错误输出。")
        args = [PROGRAMS[command.argv[0]], *command.argv[1:]]
        try:
            # Anonymous local output avoids pipe deadlocks and unbounded RAM capture.
            with tempfile.TemporaryFile() as output:
                with subprocess.Popen(
                    args, stdin=subprocess.DEVNULL, stdout=output,
                    stderr=output if command.capture_stderr else subprocess.DEVNULL,
                    env=dict(command.env), cwd="/", start_new_session=True, umask=0o077,
                ) as process:
                    try:
                        process.wait(timeout=command.timeout)
                    except (subprocess.TimeoutExpired, KeyboardInterrupt):
                        self._stop(process)
                        return Reply(-1, uncertain=True)
                    size = output.tell()
                    if size > 1024**2:
                        return Reply(-1, uncertain=True)
                    output.seek(0)
                    text = output.read().decode("utf-8", errors="replace")
                    return Reply(process.returncode, text)
        except OSError:
            # The operation may have started before the local I/O error.
            return Reply(-1, uncertain=True)

    @staticmethod
    def _stop(process):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
