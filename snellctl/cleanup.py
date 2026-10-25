"""Bounded, metadata-only cleanup inventory. Never authorizes or runs removal."""

import os
from pathlib import Path
import platform
import stat

from .doctor import collect as doctor, render as render_doctor, run_readonly
from .hostprep import CREDENTIAL, POLICY, STATE, HostFiles, PreparationError
from .installer import installation_status


# These are search locations, not an ownership declaration or an unlink list.
PATHS = (
    ("/etc/snellctl/nodes/main/snell.conf", "node-review"),
    ("/etc/snellctl/nodes/main/shadowtls.json", "node-review"),
    ("/etc/systemd/system/snellctl-snell-main.service", "node-review"),
    ("/etc/systemd/system/snellctl-shadowtls-main.service", "node-review"),
    ("/etc/nginx/conf.d/snellctl-main.conf", "shared-review"),
    ("/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-main-nginx", "shared-review"),
    (CREDENTIAL, "shared-review"),
    ("/opt/snellctl/snell/5.0.1/snell-server", "shared-review"),
    ("/opt/snellctl/shadow-tls/0.2.25/shadow-tls", "shared-review"),
    ("/etc/systemd/system/certbot.service.d/50-snellctl.conf", "shared-review"),
    (STATE, "preserve-state"),
    (POLICY, "preserve-state"),
    ("/etc/systemd/system/nginx.service", "preserve-state"),
    ("/etc/systemd/system/certbot.service", "preserve-state"),
    ("/etc/systemd/system/certbot.timer", "preserve-state"),
)

# Only count immediate children; never report names or traverse their targets.
DIRECTORIES = (
    ("/etc/snellctl/nodes", frozenset({"main"})),
    ("/etc/snellctl/credentials", frozenset({"cloudflare-main.ini"})),
    ("/opt/snellctl/snell", frozenset({"5.0.1"})),
    ("/opt/snellctl/shadow-tls", frozenset({"0.2.25"})),
    ("/etc/nginx/conf.d", frozenset({"snellctl-main.conf"})),
    ("/etc/nginx/sites-enabled", frozenset()),
    ("/etc/letsencrypt/live", frozenset({"README"})),
    ("/etc/letsencrypt/archive", frozenset()),
    ("/etc/letsencrypt/renewal", frozenset()),
    ("/etc/letsencrypt/renewal-hooks/pre", frozenset()),
    ("/etc/letsencrypt/renewal-hooks/post", frozenset()),
    ("/etc/letsencrypt/renewal-hooks/deploy", frozenset({"50-snellctl-main-nginx"})),
    ("/etc/systemd/system/snellctl-snell-main.service.d", frozenset()),
    ("/etc/systemd/system/snellctl-shadowtls-main.service.d", frozenset()),
    ("/etc/systemd/system/nginx.service.d", frozenset()),
    ("/etc/systemd/system/certbot.service.d", frozenset({"50-snellctl.conf"})),
    ("/etc/systemd/system/certbot.timer.d", frozenset()),
)
ENTRY_LIMIT = 256
PRIVATE_MODES = {
    "/etc/snellctl/nodes/main/snell.conf": 0o600,
    "/etc/snellctl/nodes/main/shadowtls.json": 0o600,
    CREDENTIAL: 0o600, STATE: 0o700,
}
UNITS = (
    "snellctl-snell-main.service", "snellctl-shadowtls-main.service",
    "nginx.service", "certbot.service", "certbot.timer", "ufw.service", "ssh.service",
)
PROPERTIES = {
    "LoadState": {"loaded", "not-found", "masked", "error", "bad-setting", "merged", "stub"},
    "ActiveState": {"active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance", "refreshing"},
    "SubState": {"running", "dead", "exited", "waiting", "failed", "start", "start-pre", "start-post", "stop", "stop-sigterm", "stop-sigkill", "stop-post", "auto-restart", "elapsed", "reload"},
    "UnitFileState": {"enabled", "disabled", "static", "masked", "masked-runtime", "enabled-runtime", "indirect", "linked", "linked-runtime", "generated", "transient", "alias", "bad"},
}
LIMITATIONS = (
    "只盘点 main 的约定路径和固定目录；不认领手工或第三方部署，不生成删除命令。",
    "文件只检查元数据；未读取节点配置、CF Token、证书私钥、站点内容或服务启动参数。",
    "目录计数不是引用分析；自定义 include、外部路径、容器、其他节点及计划任务可能未覆盖。",
    "安装阶段记录不是当前文件归属证明；未核对内容摘要，不能作为删除授权。",
    "保留 SSH、UFW 及全部现有规则、内核、软件源和无关业务；入口规则需另行逐条核对。",
    "Nginx/Certbot 软件包、证书、续期任务、凭据和程序版本可能共享；确认无其他引用前保留。",
    "不查询 Cloudflare/ACME，不吊销证书或令牌；不表示外网可达或已经恢复为干净新机。",
    "结果是非原子只读快照，其他进程仍可能改动文件或服务；实际清理前必须重新核对并确认。",
)


def _metadata(files, path):
    try:
        info = files.info(path)
        if info is None:
            return {"status": "missing"}
        kind = ("file" if stat.S_ISREG(info.st_mode) else
                "directory" if stat.S_ISDIR(info.st_mode) else
                "symlink" if stat.S_ISLNK(info.st_mode) else "other")
        expected_owner = info.st_uid == os.geteuid()
        expected_kind = "directory" if path == STATE else "file"
        safe = expected_owner and not info.st_mode & 0o022 and kind == expected_kind
        if kind == "file" and info.st_nlink != 1:
            safe = False
        if path in PRIVATE_MODES and stat.S_IMODE(info.st_mode) != PRIVATE_MODES[path]:
            safe = False
        return {
            "status": "observed" if safe else "needs-inspection", "kind": kind,
            "mode": format(stat.S_IMODE(info.st_mode), "04o"),
            "expected_owner": expected_owner,
            "multiple_file_links": kind == "file" and info.st_nlink != 1,
        }
    except (OSError, PreparationError):
        return {"status": "unknown"}


def _census(files, path, known):
    try:
        with files.directory(path) as fd, os.scandir(fd) as entries:
            counts = {"entries": 0, "known_names": 0, "other_names": 0, "symlinks": 0}
            for entry in entries:
                if counts["entries"] == ENTRY_LIMIT:
                    return {"status": "limited", **counts}
                counts["entries"] += 1
                counts["known_names" if entry.name in known else "other_names"] += 1
                counts["symlinks"] += int(entry.is_symlink())
            return {"status": "observed", **counts}
    except FileNotFoundError:
        return {"status": "missing"}
    except (OSError, PreparationError):
        return {"status": "unknown"}


def _unit(runner, unit):
    result = runner(["systemctl", "show", "--no-pager", "--property=" + ",".join(PROPERTIES), unit])
    fields = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in PROPERTIES:
            if key in fields:
                return {"status": "unknown"}
            fields[key] = value if value in PROPERTIES[key] else "unknown"
    if fields.get("LoadState") == "not-found" and result.code in {0, 1}:
        return {"status": "not-found"}
    if result.code != 0 or set(fields) != set(PROPERTIES) or "unknown" in fields.values():
        return {"status": "unknown"}
    return {"status": "observed", **fields}


def collect(*, root=Path("/"), runner=run_readonly, system=None, machine=None, euid=None):
    system = platform.system() if system is None else system
    euid = os.geteuid() if euid is None else euid
    report = {
        "report_format": 1, "mode": "read-only-cleanup-inventory", "scope": "main",
        "collection_complete": False, "cleanup_authorized": False,
        "state": "unsupported", "environment": None, "paths": [], "directories": [],
        "services": {}, "installation_records": None, "ownership": "not-checked",
        "limitations": list(LIMITATIONS),
    }
    if system != "Linux":
        return report
    if euid != 0:
        report["state"] = "root-required"
        return report
    environment = doctor(root=root, runner=runner, system=system, machine=machine)
    report["environment"] = environment
    if not environment["platform_supported"]:
        return report
    report["state"] = "review-required"
    try:
        files = HostFiles(root)
    except (OSError, PreparationError):
        report["state"] = "unreadable"
        return report
    try:
        for path, category in PATHS:
            report["paths"].append({"path": path, "category": category, **_metadata(files, path)})
        for path, known in DIRECTORIES:
            report["directories"].append({"path": path, **_census(files, path, known)})
    finally:
        files.close()
    records = installation_status(root=root)
    report["installation_records"] = records
    report["ownership"] = {
        "absent": "unrecorded-do-not-adopt", "records-found": "records-only-not-verified",
        "unreadable-or-busy": "unknown-preserve-state",
    }[records["state"]]
    report["services"] = {unit: _unit(runner, unit) for unit in UNITS}
    expected_findings = {"existing-nginx", "existing-node", "other-firewall-persistence", "legacy-geo-script", "existing-acme"}
    report["collection_complete"] = (
        all(item["status"] in {"missing", "observed"} for item in report["paths"] + report["directories"])
        and all(item["status"] != "unknown" for item in report["services"].values())
        and records["state"] != "unreadable-or-busy"
        and all(item["code"] in expected_findings for item in environment["findings"])
    )
    return report


def exit_code(report):
    if report["state"] in {"unsupported", "root-required"}:
        return 2
    return 0 if report["collection_complete"] else 1


def render(report):
    lines = ["清理前只读盘点（main）；没有执行或授权卸载。"]
    if report["state"] == "unsupported":
        lines.append("仅支持 Debian 12/13 的只读盘点；Debian 12 安装适配仍未完成。")
    elif report["state"] == "root-required":
        lines.append("请在目标 VPS 的 root 会话运行；本工具不自行提权。")
    elif report["state"] == "unreadable":
        lines.append("无法安全读取文件系统，保留现场。")
    else:
        lines.append("有限盘点已完成，仍须确认清理范围。" if report["collection_complete"] else
                     "盘点含未知、受限或需核查项；不能据此进行删除。")
        labels = {
            "unrecorded-do-not-adopt": "没有安装器记录：可能为手工/其他来源，不能自动认领。",
            "records-only-not-verified": "找到安装阶段记录：尚未验证文件内容及当前归属。",
            "unknown-preserve-state": "记录不可读或正在使用：保留锁和全部状态材料。",
        }
        lines.append(labels[report["ownership"]])
        pending = [name for name, value in report["installation_records"].get("phases", {}).items()
                   if value == "needs-inspection"]
        if pending:
            lines.append("存在未确认完成的阶段，须先核查中断现场：" + ", ".join(pending))
        if report["installation_records"].get("key_rotation") == "needs-inspection":
            lines.append("存在未确认完成的密钥更换，保留状态文件与候选配置，先核查现场。")
        if report["installation_records"].get("port_change") == "needs-inspection":
            lines.append("存在未确认完成的端口更换，保留防火墙、状态文件与候选配置，先核查现场。")
        if report["installation_records"].get("token_change") == "needs-inspection":
            lines.append("存在未确认完成的 Token 更换；自动续期可能停用，保留凭据和记录，先核查现场。")
        lines.append("相关路径（未列出的约定路径本次未发现；不是可删除清单）：")
        for item in report["paths"]:
            if item["status"] != "missing":
                lines.append(f"  {item['path']}: {item['status']} / {item.get('kind', 'unknown')} / {item['category']}")
        lines.append("共享目录（仅计数，不显示证书域名或其他文件名）：")
        for item in report["directories"]:
            if item["status"] != "missing":
                count = f"{item['entries']} 项，非约定名称 {item['other_names']} 项" if "entries" in item else "未确认"
                lines.append(f"  {item['path']}: {item['status']} / {count}")
        lines.append("服务状态（不读取启动参数）：")
        for unit, item in report["services"].items():
            values = "/".join(item[p] for p in PROPERTIES) if item["status"] == "observed" else item["status"]
            lines.append(f"  {unit}: {values}")
    if report["environment"] is not None:
        lines.extend(("", render_doctor(report["environment"])))
    lines.append("清理边界：")
    lines.extend("  - " + line for line in report["limitations"])
    return "\n".join(lines)
