"""Limited read-only new-host preflight; never refresh APT or change services."""

from __future__ import annotations

import os
from pathlib import Path
import re

from .deployment import NodeSpec, SNELL_BINARY, SHADOWTLS_BINARY, file_targets
from .doctor import collect, run_readonly


DEPENDENCIES = ("ca-certificates", "nginx", "certbot", "python3-certbot-dns-cloudflare")
PENDING = [
    "实际安装前须成功刷新全部 APT 软件源，并重新核对候选版本、来源信任与依赖方案。",
    "尚未检查全部 nftables/iptables、云安全组、UFW 自定义规则及 SSH 新连接可达性。",
    "尚未完成 Nginx 安装启动保护、DNS/凭据验证、证书签发和服务运行验收。",
]


def candidates(text: str) -> dict:
    result = {}
    package = None
    for line in text.splitlines():
        if line and not line[0].isspace():
            package = line.removesuffix(":")
        elif package in DEPENDENCIES:
            match = re.fullmatch(r"\s+Candidate: ([A-Za-z0-9.+:~_-]{1,100})", line)
            if match:
                result[package] = match[1]
    return result


def check(spec: NodeSpec, *, root=Path("/"), runner=run_readonly, system=None, machine=None, euid=None) -> dict:
    base = collect(root=root, runner=runner, system=system, machine=machine)
    report = {
        "format": 1, "mode": "read-only-preflight", "install_ready": False,
        "limited_checks_passed": False, "apt_indexes_refreshed": False,
        "environment": base, "candidates": {}, "blockers": [], "pending": list(PENDING),
    }

    def block(code, message):
        report["blockers"].append({"code": code, "message": message})

    if base["os"] != {"id": "debian", "version": "13", "arch": "amd64"}:
        block("unvalidated-platform", "此轮安装预检查仅接入已验证的 Debian 13 / amd64。")
        return report
    if (os.geteuid() if euid is None else euid) != 0:
        block("root-required", "目标机需要 root 权限才能完整检查；本工具不会自行请求提权。")
        return report
    report["blockers"].extend(base["findings"])
    if base["ufw"].get("default_policy") != {"incoming": "deny", "outgoing": "allow"}:
        block("ufw-policy", "首版要求保留已启用的 UFW 默认拒绝入站、允许出站策略；不会自动重置规则。")
    if any(p in base["packages"] for p in ("certbot", "python3-certbot-dns-cloudflare")):
        block("existing-certbot", "检测到现有证书组件；新机模式不会接管已有账户或续期任务。")
    ports = {spec.public_port, spec.snell_port, spec.tls_port}
    if any(row["port"] in ports for row in base["listeners"]):
        block("port-conflict", "拟用端口已存在监听；不会关闭现有进程。")
    if not any("SSH" in row["processes"] and row["protocol"] == "tcp" for row in base["listeners"]):
        block("ssh-unconfirmed", "未确认 SSH 监听，不能继续远程部署。")

    paths = {target.path for target in file_targets(spec)} | {
        "/etc/snellctl", "/opt/snellctl", "/etc/letsencrypt", SNELL_BINARY, SHADOWTLS_BINARY,
    }
    for path in sorted(paths):
        try:
            (root / path.lstrip("/")).lstat()
        except FileNotFoundError:
            continue
        except OSError:
            block("path-unknown", "无法确认某个部署目标路径的状态，已停止。")
            break
        else:
            block("existing-managed-path", "检测到已有部署文件或目录；新机模式不会覆盖或自动认领。")
            break
    # Do not inspect APT on a host already known to conflict with a fresh install.
    if report["blockers"]:
        return report
    audit = runner(["dpkg", "--audit"])
    if audit.code != 0 or audit.stdout.strip():
        block("dpkg-audit", "软件包状态未通过检查；先修复未完成的软件包操作。")
        return report
    policy = runner(["apt-cache", "policy", *DEPENDENCIES])
    report["candidates"] = candidates(policy.stdout) if policy.code == 0 else {}
    if set(report["candidates"]) != set(DEPENDENCIES):
        block("apt-candidates", "无法确认全部必需软件包的候选版本；不会使用过期结果继续安装。")
        return report
    simulation = runner([
        "apt-get", "--simulate", "--no-remove", "--no-install-recommends", "install", *DEPENDENCIES,
    ])
    if simulation.code != 0 or re.search(r"^(?:Remv|Purg)\s", simulation.stdout, re.M):
        block("apt-simulation", "依赖模拟失败或涉及卸载现有软件包，已停止。")
        return report
    report["limited_checks_passed"] = True
    return report


def render(report: dict) -> str:
    lines = ["新机部署预检查（只读，不安装、不刷新软件源）"]
    lines.append("结果：本轮有限检查通过。" if report["limited_checks_passed"] else "结果：存在阻断项。")
    for item in report["blockers"]:
        lines.append("  - " + item["message"])
    if report["candidates"]:
        lines.append("当前本地索引中的候选版本（不代表最新安全版本）：")
        lines.extend(f"  {name}: {version}" for name, version in report["candidates"].items())
    lines.append("尚不能据此安装：")
    lines.extend("  - " + message for message in report["pending"])
    return "\n".join(lines)
