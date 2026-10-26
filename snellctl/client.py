"""Read-only, explicit secret display for this tool's completed main node."""

import configparser
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re

from .activation import BINARIES
from .deployment import NodeSecrets, NodeSpec, file_targets, render_files
from .hostprep import Preparation, read_owned_files
from .installer import Terminal, confirm


class ClientError(Exception):
    pass


@dataclass(frozen=True)
class ClientData:
    domain: str = field(repr=False)
    public_port: int
    keys: NodeSecrets = field(repr=False)

    def __post_init__(self):
        # Reuse domain/port validation without inventing backend port conflicts.
        NodeSpec(self.domain)
        if type(self.public_port) is not int or not 1 <= self.public_port <= 65535 or not isinstance(self.keys, NodeSecrets):
            raise ClientError("客户端参数未通过校验。")

    def surge_line(self, address):
        address = public_ipv4(address)
        return (f"snellctl-main = snell, {address}, {self.public_port}, psk={self.keys.psk}, version=5, "
                f"shadow-tls-password={self.keys.shadowtls_password}, shadow-tls-version=3, "
                f"shadow-tls-sni={self.domain}, block-quic=on")


def public_ipv4(value):
    try:
        if not isinstance(value, str):
            raise ValueError
        address = ipaddress.IPv4Address(value)
        if not address.is_global or address.is_multicast:
            raise ValueError
        return str(address)
    except (ValueError, TypeError):
        raise ClientError("请输入公网 IPv4 地址；暂不接受域名、IPv6、内网地址或地址加端口。") from None


def _endpoint_port(value, host):
    if not isinstance(value, str):
        raise ClientError("配置地址类型异常。")
    match = re.fullmatch(re.escape(host) + r":([1-9][0-9]{0,4})", value)
    if not match:
        raise ClientError("配置监听范围不符。")
    return int(match[1])


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ClientError("JSON 配置含重复字段。")
        result[key] = value
    return result


def _parse_snapshot(snapshot):
    base = "/etc/snellctl/nodes/main/"
    snell = configparser.ConfigParser(interpolation=None, strict=True)
    snell.read_string(snapshot[base + "snell.conf"].decode("utf-8"))
    if snell.defaults() or snell.sections() != ["snell-server"] or set(snell["snell-server"]) != {"listen", "psk"}:
        raise ClientError("Snell 配置结构不符。")
    shadow = json.loads(snapshot[base + "shadowtls.json"], object_pairs_hook=_no_duplicate_keys)
    server = shadow["server"]
    nginx = snapshot["/etc/nginx/conf.d/snellctl-main.conf"].decode("utf-8")
    domains = re.findall(r"^    server_name ([^\s;]+);$", nginx, re.M)
    if len(domains) != 1:
        raise ClientError("未找到唯一的已部署证书域名。")
    # Representative syntax only, not a claim about the installed Nginx version.
    syntax = "1.26.3" if "    http2 on;\n" in nginx else "1.22.1"
    spec = NodeSpec(domains[0], public_port=_endpoint_port(server["listen"], "0.0.0.0"),
                    snell_port=_endpoint_port(server["server_addr"], "127.0.0.1"),
                    tls_port=_endpoint_port(server["tls_addr"]["fallback"], "127.0.0.1"),
                    nginx_version=syntax)
    keys = NodeSecrets(snell["snell-server"]["psk"], server["password"])
    # Extraction is followed by an exact match against all six supported templates.
    # This is not a general Nginx parser and does not accept hand-edited templates.
    for item in render_files(spec, keys, public_entry=True):
        if snapshot[item.target.path] != item.content.encode("utf-8"):
            raise ClientError("磁盘配置不符合本工具当前支持的模板。")
    return spec, keys


def read_deployment(prep):
    """Read current canonical templates and ownership; caller holds prep._lock().

    The returned spec carries a syntax representative, not the installed Nginx
    version. Mutating callers must resolve that version and check its binding.
    """
    prep._no_pending_change()
    return _read_deployment_snapshot(prep)


def _read_deployment_snapshot(prep):
    """Ownership/template checks only; caller must separately gate pending changes."""
    for path in ("/etc/snellctl", "/etc/snellctl/nodes", "/etc/snellctl/nodes/main"):
        with prep.files.directory(path, private=True):
            pass
    record = prep._read_record("public-ready")
    binding = record.get("binding")
    if not isinstance(binding, str) or not re.fullmatch(r"[a-f0-9]{64}", binding):
        raise ClientError("公网启用记录无效。")
    node = record.get("node")
    if (not isinstance(node, dict) or node.get("binding") != binding
            or prep._read_record("public-files") != node
            or prep._read_record("renewal-test-ready") != {"binding": binding}
            or prep._read_record("renewal-enable-ready").get("binding") != binding):
        raise ClientError("完成记录不一致。")
    paths = file_targets(NodeSpec("placeholder.invalid"))
    expected = {**{path: 0o755 for path in BINARIES}, **{t.path: t.mode for t in paths}}
    snapshot = read_owned_files(prep.files, expected, node)
    spec, keys = _parse_snapshot(snapshot)
    prep.credential_path(spec)
    if prep._read_record("certificate-ready") != {"domain_sha256": hashlib.sha256(spec.domain.encode()).hexdigest()}:
        raise ClientError("证书域名记录不一致。")
    if prep._read_record("public-firewall-added") != {
        "port": spec.public_port, "family": 4, "protocol": "tcp", "comment": "snellctl-main",
    }:
        raise ClientError("入口记录不一致。")
    for unit in (spec.snell_service, spec.shadowtls_service, "nginx.service"):
        for prefix in ("/etc/systemd/system/", "/run/systemd/system/", "/usr/lib/systemd/system/"):
            if prep.files.info(prefix + unit + ".d") is not None:
                raise ClientError("发现服务覆盖，停止操作。")
        if prep.files.info("/run/systemd/system/" + unit) is not None:
            raise ClientError("发现运行时服务覆盖，停止操作。")
    return spec, keys, record


def read_client(*, root=Path("/")):
    """Read a completed deployment under its lock; no commands, network or writes."""
    def no_commands(_command):
        raise ClientError("客户端导出不执行系统命令。")

    try:
        with Preparation(root, no_commands) as prep, prep._lock():
            spec, keys, _record = read_deployment(prep)
            return ClientData(spec.domain, spec.public_port, keys)
    except Exception:
        raise ClientError("未能核对完整部署记录、配置归属或权限；未输出密钥，也未修改任何配置。") from None


def real_reader():
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise ClientError("仅在部署主机的 Linux root 会话中读取。")
    return read_client()


def run_client(*, reader=real_reader, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("客户端配置含密钥，仅允许交互终端显示；不接受管道、文件重定向或 JSON 导出。")
        return 2
    display_attempted = False
    try:
        ui.say("此操作只读取本工具已完成部署的 main 节点，不接管旧脚本或手工部署。")
        ui.say("配置包含两项明文密钥；终端回滚缓冲、录屏或会话记录可能保留它。不要发送给 AI 或公开分享。")
        ui.say("不会联网、自动获取 IP、写文件、换密钥或更改 Surge；配置读取也不代表服务健康。")
        address = public_ipv4(ui.ask("本台 VPS 的公网 IPv4（仅地址，不含端口）：").strip())
        if not confirm(ui, "读取并显示含明文密钥的完整配置？"):
            ui.say("已取消；未读取或显示节点密钥。")
            return 130
        if not ui.interactive():
            ui.say("终端状态发生变化，已停止；未读取节点密钥。")
            return 2
        data = reader()
        line = data.surge_line(address)
        ui.say("以下是一整行 [Proxy] 节点配置；复制时不要手动换行，也不要覆盖现有配置文件：")
        if not ui.interactive():
            raise ClientError("输出终端状态改变。")
        display_attempted = True
        ui.say(line)
        ui.say("显示完成。仅为 IPv4/TCP 基线，block-quic=on 不等于关闭全部 UDP；外部使用仍待验收。")
        return 0
    except (EOFError, KeyboardInterrupt):
        ui.say("已中断；终端可能已显示部分密钥，请按敏感信息处理。" if display_attempted
               else "已取消显示；未输出节点密钥。")
        return 130
    except Exception:
        ui.say("显示未完成；终端可能已包含部分密钥。未修改服务器配置。" if display_attempted else
               "导出已停止：检查 IPv4、部署完成记录、文件权限或配置变动；未显示密钥，未修改服务器。")
        return 1
