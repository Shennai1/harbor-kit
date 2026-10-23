"""Read-only preflight. Never read service arguments, credentials or raw logs."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import platform
import re
import subprocess
from typing import Callable


PACKAGES = (
    "nginx", "nginx-common", "ufw", "ipset", "iptables-persistent",
    "netfilter-persistent", "ipset-persistent", "certbot",
    "python3-certbot-dns-cloudflare",
)
ARCHES = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
PROCESS_NAMES = {
    "sshd": "SSH", "nginx": "Nginx", "shadow-tls": "ShadowTLS",
    "snell-server": "Snell", "snell-server-v5": "Snell", "xray": "Xray",
}


@dataclass(frozen=True)
class Result:
    code: int
    stdout: str = ""


def run_readonly(args: list[str]) -> Result:
    try:
        process = subprocess.run(
            args, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=12, check=False, stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        return Result(process.returncode, process.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return Result(-1)


def os_release(text: str) -> dict[str, str]:
    # Parse as data; sourcing os-release would execute shell expressions.
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in {"ID", "VERSION_ID"}:
            value = value.strip().strip("\"'")
            if re.fullmatch(r"[A-Za-z0-9._-]{1,40}", value):
                values[key] = value
    return values


def parse_packages(text: str) -> dict[str, str]:
    packages = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            continue
        name, status, version = fields
        name = name.split(":", 1)[0]
        if name in PACKAGES and status.strip() == "ii":
            if re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,100}", version):
                packages[name] = version
    return packages


def parse_listeners(text: str, family: str) -> tuple[list[dict], int]:
    listeners = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 6 or fields[0] not in {"tcp", "udp"}:
            skipped += 1
            continue
        host, sep, port = fields[4].rpartition(":")
        if not sep or not port.isdigit() or not 0 < int(port) <= 65535:
            skipped += 1
            continue
        host = host.strip("[]").split("%", 1)[0]
        try:
            if host == "*":
                scope = "wildcard"
            else:
                addr = ipaddress.ip_address(host)
                scope = "loopback" if addr.is_loopback else (
                    "wildcard" if addr.is_unspecified else "specific-address"
                )
        except ValueError:
            skipped += 1
            continue
        # Only publish known executable labels; never echo arbitrary process text.
        names = re.findall(r'\("([^"\n]+)",pid=', line)
        labels = sorted({PROCESS_NAMES[n] for n in names if n in PROCESS_NAMES})
        listeners.append({
            "family": family, "protocol": fields[0], "port": int(port),
            "bind_scope": scope, "processes": labels,
        })
    return listeners, skipped


def parse_ufw(result: Result) -> dict:
    if result.code != 0:
        return {"status": "unknown", "default_policy": "unknown"}
    status = re.search(r"^Status: (active|inactive)$", result.stdout, re.M)
    policy = re.search(
        r"^Default: (deny|allow|reject) \(incoming\), "
        r"(deny|allow|reject) \(outgoing\), (.+)$", result.stdout, re.M,
    )
    # Whitelist tokens rather than copying rules that may contain source IPs.
    return {
        "status": status.group(1) if status else "unknown",
        "default_policy": {
            "incoming": policy.group(1), "outgoing": policy.group(2),
        } if policy else "unknown",
    }


def collect(
    root: Path = Path("/"),
    runner: Callable[[list[str]], Result] = run_readonly,
    system: str | None = None,
    machine: str | None = None,
) -> dict:
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    arch = ARCHES.get(machine, "unsupported")
    report = {
        "report_format": 1, "mode": "read-only", "platform_supported": False,
        "os": {"id": "unknown", "version": "unknown", "arch": arch},
        "packages": {}, "listeners": [], "ufw": {"status": "unknown"},
        "findings": [], "external_connectivity": "not-tested",
    }

    def finding(code: str, message: str) -> None:
        report["findings"].append({"code": code, "message": message})

    if system != "Linux":
        finding("unsupported-os", "部署目标需为 Debian 12/13；未运行 Linux 管理命令。")
        return report
    try:
        release = os_release((root / "etc/os-release").read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        finding("os-release-unavailable", "无法读取系统发行版，停止后续检查。")
        return report
    report["os"].update({
        "id": release.get("ID", "unknown"), "version": release.get("VERSION_ID", "unknown"),
    })
    if release.get("ID") != "debian" or release.get("VERSION_ID") not in {"12", "13"} or arch == "unsupported":
        finding("unsupported-platform", "当前发行版或架构不在首版计划支持范围。")
        return report
    report["platform_supported"] = True

    packages = runner([
        "dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Abbrev}\t${Version}\n",
        *PACKAGES,
    ])
    report["packages"] = parse_packages(packages.stdout)
    # dpkg-query returns 1 when only some requested packages are installed.
    if packages.code not in {0, 1}:
        finding("packages-unavailable", "无法检查软件包；不判断是否已安装。")
    if any(p in report["packages"] for p in ("nginx", "nginx-common")):
        finding("existing-nginx", "检测到已有 Nginx 软件包，安装前需要核对其配置归属。")
    if any(p in report["packages"] for p in (
        "iptables-persistent", "netfilter-persistent", "ipset-persistent",
    )):
        finding("other-firewall-persistence", "检测到防火墙持久化组件；需要核对规则管理方式。")

    for flag, family in (("-4", "IPv4"), ("-6", "IPv6")):
        sockets = runner(["ss", "-H", flag, "-lntup"])
        if sockets.code != 0:
            finding("listeners-unavailable-" + family, family + " 监听检查失败或无权限。")
            continue
        parsed, skipped = parse_listeners(sockets.stdout, family)
        report["listeners"].extend(parsed)
        if skipped:
            finding("listeners-unparsed-" + family, family + " 有未识别的监听记录，结果不完整。")
    if any("ShadowTLS" in x["processes"] or "Snell" in x["processes"] for x in report["listeners"]):
        finding("existing-node", "检测到已有节点进程；该机器不属于空白新机。")

    report["ufw"] = parse_ufw(runner(["ufw", "status", "verbose"]))
    if report["ufw"]["status"] == "unknown":
        finding("ufw-unknown", "UFW 状态未知，可能未安装或权限不足；不能据此认定没有防火墙。")
    enabled = runner(["systemctl", "is-enabled", "ufw.service"])
    report["ufw"]["boot"] = enabled.stdout.strip() if enabled.stdout.strip() in {
        "enabled", "disabled", "masked", "static", "indirect",
    } else "unknown"
    if report["ufw"]["status"] == "inactive":
        finding("ufw-inactive", "UFW 未启用；其他防火墙规则和云安全组尚未检查。")
    if report["ufw"]["status"] == "active":
        if report["ufw"]["boot"] != "enabled":
            finding("ufw-boot-unconfirmed", "UFW 当前启用，但未确认其开机启用状态。")
        policy = report["ufw"].get("default_policy")
        if policy == "unknown":
            finding("ufw-policy-unknown", "无法识别 UFW 默认策略，需要进一步检查。")
        elif policy["incoming"] == "allow":
            finding("ufw-default-allow", "UFW 默认允许入站，需要核对是否符合预期。")

    for filename, code, message in (
        ("root/cn_geo_block.sh", "legacy-geo-script", "发现旧地理阻断脚本路径；未执行或读取脚本。"),
        ("root/.acme.sh/acme.sh", "existing-acme", "发现 acme.sh 安装路径；未读取账户或凭据。"),
    ):
        try:
            (root / filename).stat()
        except FileNotFoundError:
            continue
        except OSError:
            finding(code + "-unknown", "权限不足，无法确认旧组件路径是否存在。")
        else:
            finding(code, message)
    return report


def render(report: dict) -> str:
    osinfo = report["os"]
    lines = [
        "只读环境检查",
        f"系统：{osinfo['id']} {osinfo['version']} / {osinfo['arch']}",
        "外部连通性：未测试；监听记录不代表公网可达。",
        "软件包：",
    ]
    lines.extend(f"  {name}: {version}" for name, version in sorted(report["packages"].items()))
    if not report["packages"]:
        lines.append("  未检出所查询的已安装包，或检查未完成。")
    lines.append("监听：")
    scopes = {"wildcard": "所有本机地址", "loopback": "仅回环", "specific-address": "指定地址（已隐藏）"}
    for listener in report["listeners"]:
        labels = ", ".join(listener["processes"]) or "未识别/无权限"
        lines.append(
            f"  {listener['family']} {listener['protocol']}/{listener['port']} "
            f"{scopes[listener['bind_scope']]} {labels}"
        )
    if not report["listeners"]:
        lines.append("  未检出或检查未完成。")
    ufw = report["ufw"]
    lines.append(f"UFW：{ufw['status']}；开机状态：{ufw.get('boot', 'unknown')}")
    if isinstance(ufw.get("default_policy"), dict):
        lines.append(f"默认策略：入站 {ufw['default_policy']['incoming']} / 出站 {ufw['default_policy']['outgoing']}")
    lines.append("需注意：")
    lines.extend("  - " + item["message"] for item in report["findings"])
    if not report["findings"]:
        lines.append("  此次有限检查未发现需注意项，不等于完整安全审计通过。")
    return "\n".join(lines)
