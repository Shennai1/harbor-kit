"""Internal, single-node local activation; no public listener or UFW changes.

The preparation lock spans file writes and external operations. This is not an
atomic transaction: interruptions retain intent and require operator inspection.
The experimental wizard is opt-in; Linux integration acceptance remains pending.
"""

from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import re
import time

from .artifacts import CATALOG, verify
from .deployment import (
    SNELL_BINARY, SHADOWTLS_BINARY, NodeSpec, file_targets, new_node_secrets, render_files,
)
from .hostprep import CREDENTIAL, POLICY, POLICY_BYTES, STAGING, UNITS, PreparationError, read_owned_files


DEFAULT_LINK = "/etc/nginx/sites-enabled/default"
PACKAGE_CONFIGS = {"/etc/nginx/nginx.conf", "/etc/nginx/mime.types", "/etc/nginx/sites-available/default"}
BINARIES = (SNELL_BINARY, SHADOWTLS_BINARY)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _binding(spec):
    return _digest(json.dumps(asdict(spec), sort_keys=True).encode())


class Activation:
    """Requires an explicit Preparation instance and an explicit local TLS probe."""

    def __init__(self, preparation, probe, *, readiness_timeout=10):
        self.prep = preparation
        self.files = preparation.files
        self.probe = probe
        self.readiness_timeout = readiness_timeout

    def _entries(self, path):
        with self.files.directory(path) as fd:
            return set(os.listdir(fd))

    def _version(self, spec):
        output = self.prep._run(["nginx", "-v"], capture_stderr=True)
        match = re.fullmatch(r"nginx version: nginx/([0-9]+\.[0-9]+\.[0-9]+)\s*", output)
        if not match:
            raise PreparationError("无法核对实际 Nginx 版本。")
        return replace(spec, nginx_version=match[1])

    def _no_overrides(self, units):
        for unit in units:
            for prefix in ("/etc/systemd/system/", "/run/systemd/system/", "/usr/lib/systemd/system/"):
                if self.files.info(prefix + unit + ".d") is not None:
                    raise PreparationError("发现额外服务覆盖目录，不自动接管。")

    def _nginx_package_config(self):
        # Package checksums detect local edits; they are not upstream signatures.
        output = self.prep._run(["dpkg-query", "-W", "-f=${Conffiles}\n", "nginx-common"])
        hashes = {}
        for line in output.splitlines():
            match = re.fullmatch(r" (/\S+) ([a-f0-9]{32})", line)
            if match:
                hashes[match[1]] = match[2]
        for path in PACKAGE_CONFIGS:
            data = self.files.read(path)
            if hashlib.md5(data, usedforsecurity=False).hexdigest() != hashes.get(path):
                raise PreparationError("Nginx 基础配置不是未修改的软件包配置，停止接管。")

    def _nginx_dump(self, expected):
        output = self.prep._run(["nginx", "-T"])
        loaded = re.findall(r"^# configuration file (.+):$", output, re.M)
        if len(loaded) != len(expected) or set(loaded) != expected:
            raise PreparationError("Nginx 加载了非预期配置文件，暂不启动。")

    def _vacant(self, spec):
        for port in (spec.public_port, spec.snell_port, spec.tls_port):
            if self.prep._run(["ss", "-H", "-lntu", "sport = :" + str(port)]).strip():
                raise PreparationError("本次端口已有监听，未写入配置或启动服务。")

    def _pending_guards(self):
        record = self.prep._read_record("guards")
        for path in (POLICY, "/etc/systemd/system/certbot.service", "/etc/systemd/system/certbot.timer"):
            if self.files.identity(path) != record.get(path):
                raise PreparationError("剩余启动保护已改变，停止。")
            if path == POLICY:
                if self.files.read(path, mode=0o755) != POLICY_BYTES:
                    raise PreparationError("剩余启动策略已改变，停止。")
            elif self.files.readlink(path) != "/dev/null":
                raise PreparationError("续期服务保护已改变，停止。")
        for unit in UNITS[1:]:
            output = self.prep._run(["systemctl", "show", unit, "-p", "LoadState,ActiveState"])
            if set(output.splitlines()) != {"LoadState=masked", "ActiveState=inactive"}:
                raise PreparationError("续期服务保护状态不符，停止。")

    def _running(self, spec, *, public_entry=False):
        pids = {}
        for unit in ("nginx.service", spec.snell_service, spec.shadowtls_service):
            output = self.prep._run(["systemctl", "show", unit, "-p",
                                     "ActiveState,SubState,MainPID,ExecMainStatus,NRestarts,DropInPaths,FragmentPath"])
            fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
            expected_fragment = ("/usr/lib/systemd/system/" if unit == "nginx.service" else "/etc/systemd/system/") + unit
            if (fields.get("ActiveState") != "active" or fields.get("SubState") != "running"
                    or fields.get("ExecMainStatus") != "0" or fields.get("NRestarts") != "0"
                    or fields.get("DropInPaths") != "" or fields.get("FragmentPath") != expected_fragment
                    or not re.fullmatch(r"[1-9][0-9]*", fields.get("MainPID", ""))):
                raise PreparationError("服务未保持预期运行状态，或存在额外覆盖。")
            pids[unit] = int(fields["MainPID"])
        expected = {("tcp", spec.public_port): pids[spec.shadowtls_service],
                    ("tcp", spec.snell_port): pids[spec.snell_service],
                    ("udp", spec.snell_port): pids[spec.snell_service],
                    ("tcp", spec.tls_port): pids["nginx.service"]}
        seen = set()
        output = self.prep._run(["ss", "-H", "-lntup"])
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 7:
                raise PreparationError("无法识别完整的监听检查结果。")
            address = fields[4]
            if ":" not in address or not address.rsplit(":", 1)[1].isdigit():
                raise PreparationError("无法识别监听地址。")
            host, port = address.rsplit(":", 1)
            port = int(port)
            key = (fields[0], port)
            pids_here = {int(v) for v in re.findall(r"pid=([0-9]+)", line)}
            managed = bool(set(pids.values()) & pids_here)
            if port not in {spec.public_port, spec.snell_port, spec.tls_port} and not managed:
                continue
            expected_host = "0.0.0.0" if public_entry and key == ("tcp", spec.public_port) else "127.0.0.1"
            if (key not in expected or host != expected_host or key in seen
                    or expected[key] not in pids_here):
                raise PreparationError("组件监听范围或进程与本机验收方案不符。")
            seen.add(key)
        if seen != set(expected):
            raise PreparationError("组件监听尚未齐备。")

    def _verify_owned(self, spec, record):
        expected = {**{path: 0o755 for path in BINARIES}, **{t.path: t.mode for t in file_targets(spec)}}
        return read_owned_files(self.files, expected, record)

    def _wait_running(self, spec, *, public_entry=False):
        deadline = time.monotonic() + self.readiness_timeout
        while True:
            try:
                self._running(spec, public_entry=public_entry)
                return
            except PreparationError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)

    def _health(self, spec, record, *, public_entry=False, check_guards=True, allowed_deploy_hook=None):
        if check_guards:
            self._pending_guards()
        self._verify_owned(spec, record)
        self._nginx_package_config()
        self._nginx_dump({"/etc/nginx/nginx.conf", "/etc/nginx/mime.types", spec.nginx_conf})
        certificate = self.prep._verify_certificate(spec, allowed_deploy_hook=allowed_deploy_hook)
        self._running(spec, public_entry=public_entry)
        for port in (spec.tls_port, spec.public_port):
            if self.probe(spec, port, certificate) is not True:
                raise PreparationError("本机 TLS 检查未明确通过。")
        self._running(spec, public_entry=public_entry)

    def activate(self, spec: NodeSpec, downloads: dict[str, bytes]):
        if spec.node != "main":
            raise PreparationError("首轮新机激活仅支持单节点 main。")
        with self.prep._lock():
            if self.prep._exists("public-intent") or self.prep._exists("renewal-enable-intent"):
                raise PreparationError("已进入公网启用阶段，不能再按本机初次激活流程操作。")
            spec = self._version(spec)
            binding = _binding(spec)
            if self.prep._exists("activation-ready"):
                record = self.prep._read_record("activation-ready")
                if record.get("binding") != binding:
                    raise PreparationError("已激活参数不同；不隐式改域名、端口或密钥。")
                self._health(spec, record)
                return "already-local-active"
            if self.prep._exists("activation-intent"):
                raise PreparationError("存在未完成的激活；先核查现场，不自动覆盖或重试。")
            if self.prep._read_record("certificate-ready") != {"domain_sha256": _digest(spec.domain.encode())}:
                raise PreparationError("正式证书准备记录与域名不符。")
            if self.prep._installed() != self.prep._read_record("packages-ready").get("versions"):
                raise PreparationError("已准备的软件包发生变化，先重新核查。")
            self.prep._guards()
            self.prep._verify_certificate(spec)
            self._no_overrides((*UNITS, spec.snell_service, spec.shadowtls_service))
            for unit in UNITS:
                if self.files.info("/run/systemd/system/" + unit) is not None:
                    raise PreparationError("发现运行时服务覆盖，暂不解除启动保护。")
            self._vacant(spec)
            for unit in (spec.snell_service, spec.shadowtls_service):
                for prefix in ("/etc/systemd/system/", "/run/systemd/system/", "/usr/lib/systemd/system/"):
                    if self.files.info(prefix + unit) is not None:
                        raise PreparationError("同名节点服务已存在，不接管。")
                output = self.prep._run(["systemctl", "show", unit, "-p", "LoadState,ActiveState"])
                if set(output.splitlines()) != {"LoadState=not-found", "ActiveState=inactive"}:
                    raise PreparationError("同名节点服务已经加载或正在运行，不接管。")
            for path in ("/opt/snellctl", "/etc/snellctl/nodes", *(t.path for t in file_targets(spec))):
                if self.files.info(path) is not None:
                    raise PreparationError("安装目标已存在，不覆盖。")
            if (self._entries("/etc/nginx/sites-enabled") != {"default"}
                    or self._entries("/etc/nginx/conf.d") or self._entries("/etc/nginx/modules-enabled")
                    or self.files.readlink(DEFAULT_LINK) != "/etc/nginx/sites-available/default"):
                raise PreparationError("Nginx 不是预期的新安装状态，不修改已有站点。")
            self._nginx_package_config()
            self._nginx_dump({"/etc/nginx/nginx.conf", "/etc/nginx/mime.types", DEFAULT_LINK})
            if set(downloads) != {a.name for a in CATALOG}:
                raise PreparationError("缺少固定版本下载文件。")
            binaries = [verify(artifact, downloads[artifact.name]) for artifact in CATALOG]
            default_identity = self.files.identity(DEFAULT_LINK)
            self.prep._record("activation-intent", {"binding": binding, "default_link_identity": default_identity})
            started = []
            try:
                for path, data in zip(BINARIES, binaries, strict=True):
                    with self.files.directory(str(Path(path).parent), create=True):
                        pass
                    self.files.write_new(path, data, 0o755)
                for path, pattern in ((SNELL_BINARY, r"\bsnell-server v5\.0\.1(?:\s|$)"),
                                      (SHADOWTLS_BINARY, r"\bshadow-tls 0\.2\.25(?:\s|$)")):
                    if not re.search(pattern, self.prep._run([path, "--version"], 5, capture_stderr=True)):
                        raise PreparationError("程序报告的版本不符合固定版本。")
                for path in ("/etc/snellctl/nodes", spec.node_dir):
                    self.files.private_directory_new(path)
                candidates = render_files(spec, new_node_secrets(), public_entry=False)
                modes = {path: 0o755 for path in BINARIES}
                for item in candidates:
                    with self.files.directory(str(Path(item.target.path).parent), create=True):
                        pass
                    self.files.write_new(item.target.path, item.content.encode(), item.target.mode)
                    modes[item.target.path] = item.target.mode
                record = {"binding": binding, "files": {path: {
                    "identity": self.files.identity(path), "mode": mode,
                    "sha256": _digest(self.files.read(path, mode=mode, limit=32 * 1024**2)),
                } for path, mode in modes.items()}}
                self.prep._record("activation-files", record)
                self.prep._run(["systemd-analyze", "verify", "/etc/systemd/system/" + spec.snell_service,
                                "/etc/systemd/system/" + spec.shadowtls_service])
                self.prep._run(["nginx", "-t"])
                self.files.unlink_owned(DEFAULT_LINK, default_identity)
                self._nginx_dump({"/etc/nginx/nginx.conf", "/etc/nginx/mime.types", spec.nginx_conf})
                self.prep._guards()
                mask = "/etc/systemd/system/nginx.service"
                self.files.unlink_owned(mask, self.prep._read_record("guards")[mask])
                self.prep._run(["systemctl", "daemon-reload"])
                for unit in ("nginx.service", spec.snell_service, spec.shadowtls_service):
                    started.append(unit)
                    self.prep._run(["systemctl", "start", unit])
                self._wait_running(spec)
                self._health(spec, record)
                self.prep._record("activation-ready", record)
            except BaseException:
                cleanup_failed = False
                for unit in reversed(started):
                    try:
                        self.prep._run(["systemctl", "stop", unit])
                    except BaseException:
                        cleanup_failed = True
                if cleanup_failed:
                    raise PreparationError("激活失败且未能确认服务全部停止；保留现场，必须人工核查。") from None
                raise PreparationError("激活未完成；已停止本轮尝试启动的服务，保留文件及意图记录，不自动重试。") from None
            return "local-active-public-entry-not-enabled"

    def test_renewal(self, spec: NodeSpec, *, confirm_test: bool):
        if confirm_test is not True:
            raise PreparationError("模拟续期会访问 CA 和修改验证 TXT，需要明确确认。")
        with self.prep._lock():
            spec = self._version(spec)
            record = self.prep._read_record("activation-ready")
            if record.get("binding") != _binding(spec):
                raise PreparationError("续期检查参数与本机激活记录不符。")
            self._health(spec, record)
            if self.prep._exists("renewal-test-ready"):
                return "already-renewal-tested"
            if self.prep._exists("renewal-test-intent"):
                raise PreparationError("上次模拟续期结果不确定，先核查，不自动重复请求。")
            self.prep._certbot_config()
            self.files.read(CREDENTIAL, mode=0o600)
            hook = f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{spec.node}-nginx"
            self.prep._record("renewal-test-intent", {"binding": _binding(spec)})
            output = self.prep._run([
                "certbot", "renew", "--non-interactive", "--cert-name", spec.domain,
                "--dry-run", "--server", STAGING, "--run-deploy-hooks", "--no-directory-hooks",
                "--deploy-hook", hook, "--config-dir", "/etc/letsencrypt",
                "--work-dir", "/var/lib/letsencrypt", "--logs-dir", "/var/log/letsencrypt",
                "--max-log-backups", "3",
            ], 600, capture_stderr=True)
            # Certbot can exit zero even when a hook fails; require its success marker.
            if "snellctl: nginx reload command succeeded" not in {line.strip() for line in output.splitlines()}:
                raise PreparationError("模拟续期未确认部署钩子成功，不登记通过。")
            self._health(spec, record)
            self.prep._record("renewal-test-ready", {"binding": _binding(spec)})
            return "renewal-tested-timer-still-blocked"
