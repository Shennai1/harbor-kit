"""Validated, in-memory deployment candidates. No file I/O or system changes."""

from dataclasses import dataclass, field
import json
import re
import secrets


SNELL_VERSION = "5.0.1"
SHADOWTLS_VERSION = "0.2.25"
SNELL_BINARY = f"/opt/snellctl/snell/{SNELL_VERSION}/snell-server"
SHADOWTLS_BINARY = f"/opt/snellctl/shadow-tls/{SHADOWTLS_VERSION}/shadow-tls"
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"


@dataclass(frozen=True)
class NodeSpec:
    domain: str
    node: str = "main"
    public_port: int = 443
    snell_port: int = 31001
    tls_port: int = 31443
    nginx_version: str = "1.26.3"

    def __post_init__(self) -> None:
        if not isinstance(self.node, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", self.node):
            raise ValueError("节点名称须为小写字母开头的 1 至 32 位字母、数字或连字符。")
        if (
            not isinstance(self.domain, str) or len(self.domain) > 253
            or not re.fullmatch(rf"(?:{LABEL}\.)+[a-z](?:[a-z0-9-]{{0,61}}[a-z0-9])?", self.domain)
        ):
            raise ValueError("请输入完整小写 ASCII 域名，不含协议、路径、通配符或末尾句点。")
        for port, lower, label in (
            (self.public_port, 1, "公网端口"),
            (self.snell_port, 1024, "Snell 本机端口"),
            (self.tls_port, 1024, "Nginx 本机端口"),
        ):
            if type(port) is not int or not lower <= port <= 65535:
                raise ValueError(f"{label}须为 {lower} 至 65535 的整数。")
        if len({self.public_port, self.snell_port, self.tls_port}) != 3:
            raise ValueError("公网、Snell 和 Nginx 的三个端口不能相同。")
        if not isinstance(self.nginx_version, str) or not re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", self.nginx_version):
            raise ValueError("Nginx 语法版本须为三个数字段，不包含软件包修订号。")
        if self.nginx_release < (1, 19, 4):
            raise ValueError("该 Nginx 版本不支持本方案的握手拒绝指令。")

    @property
    def nginx_release(self) -> tuple[int, ...]:
        return tuple(int(part) for part in self.nginx_version.split("."))

    @property
    def node_dir(self) -> str:
        return f"/etc/snellctl/nodes/{self.node}"

    @property
    def cert_dir(self) -> str:
        return f"/etc/letsencrypt/live/{self.domain}"

    @property
    def nginx_conf(self) -> str:
        return f"/etc/nginx/conf.d/snellctl-{self.node}.conf"

    @property
    def snell_service(self) -> str:
        return f"snellctl-snell-{self.node}.service"

    @property
    def shadowtls_service(self) -> str:
        return f"snellctl-shadowtls-{self.node}.service"


@dataclass(frozen=True)
class NodeSecrets:
    psk: str = field(repr=False)
    shadowtls_password: str = field(repr=False)

    def __post_init__(self) -> None:
        for value in (self.psk, self.shadowtls_password):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError("候选密钥须为 64 位小写十六进制值；未显示输入内容。")
        if self.psk == self.shadowtls_password:
            raise ValueError("Snell 与 ShadowTLS 必须使用不同的密钥。")


def new_node_secrets() -> NodeSecrets:
    """Call only for an explicitly authorized new node, never for a preview."""
    psk = secrets.token_hex(32)
    password = secrets.token_hex(32)
    while password == psk:
        password = secrets.token_hex(32)
    return NodeSecrets(psk, password)


@dataclass(frozen=True)
class FileTarget:
    path: str
    mode: int
    sensitive: bool = False


@dataclass(frozen=True)
class CandidateFile:
    target: FileTarget
    content: str = field(repr=False)


def file_targets(spec: NodeSpec) -> tuple[FileTarget, ...]:
    return (
        FileTarget(f"{spec.node_dir}/snell.conf", 0o600, True),
        FileTarget(f"{spec.node_dir}/shadowtls.json", 0o600, True),
        FileTarget(spec.nginx_conf, 0o644),
        FileTarget(f"/etc/systemd/system/{spec.snell_service}", 0o644),
        FileTarget(f"/etc/systemd/system/{spec.shadowtls_service}", 0o644),
        FileTarget(f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{spec.node}-nginx", 0o700),
    )


def _unit(description: str, dependencies: str, credential: str, command: str,
          *, low_port: bool = False, environment: str = "") -> str:
    capabilities = "CapabilityBoundingSet=\n"
    if low_port:
        capabilities = "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"
    return (
        f"[Unit]\nDescription={description}\n{dependencies}"
        "StartLimitIntervalSec=60\nStartLimitBurst=3\n\n"
        f"[Service]\nType=exec\nDynamicUser=yes\nLoadCredential={credential}\n"
        f"ExecStart={command}\n{environment}"
        "Restart=on-failure\nRestartSec=3\nNoNewPrivileges=yes\n"
        "ProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n"
        f"{capabilities}LimitNOFILE=32768\nLimitCORE=0\nUMask=0077\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def render_files(spec: NodeSpec, keys: NodeSecrets, *, public_entry: bool = True) -> tuple[CandidateFile, ...]:
    """Render using supplied keys; repeated calls do not rotate or persist them."""
    if type(public_entry) is not bool:
        raise ValueError("必须明确选择入口监听范围。")
    snell = f"[snell-server]\nlisten = 127.0.0.1:{spec.snell_port}\npsk = {keys.psk}\n"
    shadowtls = json.dumps({
        "v3": True, "strict": True,
        "server": {
            "listen": f"{'0.0.0.0' if public_entry else '127.0.0.1'}:{spec.public_port}",
            "server_addr": f"127.0.0.1:{spec.snell_port}",
            "tls_addr": {"dispatch": {}, "fallback": f"127.0.0.1:{spec.tls_port}", "wildcard_sni": "off"},
            "password": keys.shadowtls_password, "wildcard_sni": "off",
        },
    }, indent=2) + "\n"
    # Legacy HTTP/2 is a listener option, so keep it consistent in both blocks.
    modern_http2 = spec.nginx_release >= (1, 25, 1)
    listen = f"listen 127.0.0.1:{spec.tls_port} ssl" + ("" if modern_http2 else " http2")
    http2_line = "    http2 on;\n" if modern_http2 else ""
    nginx = (
        f"server {{\n    {listen} default_server;\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_reject_handshake on;\n"
        "    server_tokens off;\n    access_log off;\n    return 404;\n}\n"
        f"server {{\n    {listen};\n    server_name {spec.domain};\n"
        f"    ssl_certificate {spec.cert_dir}/fullchain.pem;\n"
        f"    ssl_certificate_key {spec.cert_dir}/privkey.pem;\n"
        f"    ssl_protocols TLSv1.2 TLSv1.3;\n{http2_line}"
        "    server_tokens off;\n    access_log off;\n    return 404;\n}\n"
    )
    snell_unit = _unit(
        f"Snell backend - snellctl {spec.node}", "After=network.target\n",
        f"snell.conf:{spec.node_dir}/snell.conf", f"{SNELL_BINARY} -c %d/snell.conf",
    )
    shadowtls_unit = _unit(
        f"ShadowTLS frontend - snellctl {spec.node}",
        f"Wants=nginx.service {spec.snell_service}\nAfter=network.target nginx.service {spec.snell_service}\n",
        f"shadowtls.json:{spec.node_dir}/shadowtls.json",
        f"{SHADOWTLS_BINARY} config --config %d/shadowtls.json",
        low_port=spec.public_port < 1024,
        environment=("Environment=RUST_LOG=warn\n"
                     "UnsetEnvironment=CONFIG_FILE SS_REMOTE_HOST SS_REMOTE_PORT "
                     "SS_LOCAL_HOST SS_LOCAL_PORT SS_PLUGIN_OPTIONS\n"),
    )
    hook = (
        '#!/bin/sh\nset -eu\n: "${RENEWED_LINEAGE:?RENEWED_LINEAGE is required}"\n'
        f'[ "$RENEWED_LINEAGE" = \'{spec.cert_dir}\' ] || exit 0\n'
        f"test -s {spec.nginx_conf}\n/usr/sbin/nginx -t\n"
        "/usr/bin/systemctl reload nginx.service\n"
        "printf '%s\\n' 'snellctl: nginx reload command succeeded'\n"
    )
    return tuple(CandidateFile(target, content) for target, content in zip(
        file_targets(spec), (snell, shadowtls, nginx, snell_unit, shadowtls_unit, hook), strict=True,
    ))


def preview(spec: NodeSpec) -> dict:
    """Non-secret plan only. Does not inspect this machine or create keys."""
    return {
        "plan_format": 1, "mode": "preview-only", "environment_checked": False,
        "node": spec.node, "domain": spec.domain,
        "validated_platform": "Debian 13 / amd64 / IPv4 TCP",
        "versions": {"snell": SNELL_VERSION, "shadowtls": SHADOWTLS_VERSION,
                     "snell_protocol": 5, "shadowtls_protocol": 3,
                     "nginx_syntax": spec.nginx_version},
        "listeners": {"shadowtls_tcp": f"0.0.0.0:{spec.public_port}",
                      "snell_tcp_udp": f"127.0.0.1:{spec.snell_port}",
                      "nginx_tcp": f"127.0.0.1:{spec.tls_port}"},
        "files": [{"path": target.path, "mode": f"{target.mode:04o}",
                   "owner": "root:root", "contains_secret": target.sensitive}
                  for target in file_targets(spec)],
        "credential_path": f"/etc/snellctl/credentials/cloudflare-{spec.node}.ini",
        "certificate_lineage": spec.cert_dir,
        "pending_checks": ["目标平台与配置归属", "APT 软件源与安全更新", "端口占用与 SSH 保护",
                           "DNS 与凭据权限", "证书签发及 Nginx 配置测试", "服务、续期及客户端验收"],
    }


def render_preview(plan: dict) -> str:
    versions = plan["versions"]
    lines = [
        "部署计划预览（未执行）", f"节点：{plan['node']}；域名：{plan['domain']}",
        f"已实机验证的范围：{plan['validated_platform']}",
        f"Snell {versions['snell']} / 协议 v5；ShadowTLS {versions['shadowtls']} / 协议 v3",
        f"Nginx 模板语法版本：{versions['nginx_syntax']}（不是安全补丁检查结果）",
        f"公网入口：{plan['listeners']['shadowtls_tcp']} TCP",
        f"本机后端：Snell {plan['listeners']['snell_tcp_udp']}；Nginx {plan['listeners']['nginx_tcp']}",
        "候选文件（尚未写入）：",
    ]
    lines.extend(f"  {item['mode']} {item['owner']} {item['path']}" for item in plan["files"])
    lines.extend([
        "未生成密钥、未读取 Token、未联网、未修改任何服务或防火墙。",
        "未检查当前机器，也未确认域名归属、证书、路径或端口可用。",
        "实验安装须另行明确开启；此预览不能作为可安装或部署成功的证明。",
    ])
    return "\n".join(lines)
