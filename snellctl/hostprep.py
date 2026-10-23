"""Preparation engine behind the opt-in experimental installation wizard.

Package/DNS/CA operations are not filesystem transactions. Intent records are
written before irreversible commands; uncertain operations require inspection.
Tests inject a command runner and a private filesystem root. No default runner
exists here, so importing or constructing the engine never executes commands.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
import configparser
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .deployment import NodeSpec
from .preflight import DEPENDENCIES, candidates


STATE = "/var/lib/snellctl/preparation"
APT_LISTS = "/var/lib/snellctl/apt-lists"
CREDENTIAL = "/etc/snellctl/credentials/cloudflare-main.ini"
UNITS = ("nginx.service", "certbot.service", "certbot.timer")
POLICY = "/usr/sbin/policy-rc.d"
POLICY_BYTES = b'''#!/bin/sh
# snellctl: temporary package-start guard, not a general service policy.
if [ "$1" = "--quiet" ]; then shift; fi
case "$1" in
    nginx|nginx.service|certbot|certbot.service|certbot.timer) exit 101 ;;
esac
exit 0
'''
PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
SOURCES = b'''Types: deb
URIs: https://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: https://security.debian.org/debian-security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
'''
APT_SECURITY = (
    "-o", "APT::Get::AllowUnauthenticated=false",
    "-o", "Acquire::AllowInsecureRepositories=false",
    "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
    "-o", "Acquire::https::Verify-Peer=true",
    "-o", "Acquire::https::Verify-Host=true",
    "-o", "Acquire::Check-Valid-Until=true",
)


class PreparationError(Exception):
    """Fixed, nonsecret operator messages only."""


@dataclass(frozen=True)
class Command:
    argv: tuple[str, ...]
    timeout: int = 30
    # No inherited environment, shell expansion, arbitrary hooks or API token.
    env: tuple[tuple[str, str], ...] = (
        ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), ("LC_ALL", "C"),
        ("DEBIAN_FRONTEND", "noninteractive"), ("NEEDRESTART_MODE", "l"),
        ("HOME", STATE + "/home"),
    )
    capture_stderr: bool = False


@dataclass(frozen=True)
class Reply:
    code: int
    output: str = field(default="", repr=False)
    # A killed/timed-out process may already have completed a remote operation.
    uncertain: bool = False


class HostFiles:
    """No-follow, owner-checked access to fixed host paths or a test root."""

    def __init__(self, root: Path):
        root = Path(root)
        if not root.is_absolute() or ".." in root.parts:
            raise PreparationError("文件根目录必须是没有上级跳转的绝对路径。")
        self.fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in root.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd)
                os.close(self.fd)
                self.fd = child
        except BaseException:
            os.close(self.fd)
            raise

    def close(self):
        os.close(self.fd)

    @contextmanager
    def directory(self, path, *, create=False, private=False):
        parts = Path(path).parts
        if not Path(path).is_absolute() or ".." in parts:
            raise PreparationError("内部路径无效。")
        fd = os.dup(self.fd)
        try:
            for index, part in enumerate(parts[1:]):
                created = False
                mode = 0o700 if private and index == len(parts) - 2 else 0o755
                if create:
                    try:
                        os.mkdir(part, mode, dir_fd=fd)
                        created = True
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    info = os.fstat(child)
                    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                        raise PreparationError("目录归属或写入权限异常，未修改原有目录。")
                    if created:
                        os.fchmod(child, mode)
                        os.fsync(child)
                        info = os.fstat(child)
                    if private and index == len(parts) - 2 and stat.S_IMODE(info.st_mode) != 0o700:
                        raise PreparationError("凭据或状态目录权限必须为 0700。")
                except BaseException:
                    os.close(child)
                    raise
                os.close(fd)
                fd = child
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def parent(self, path):
        path = Path(path)
        with self.directory(str(path.parent)) as fd:
            yield fd, path.name

    def info(self, path):
        try:
            with self.parent(path) as (fd, name):
                return os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def read(self, path, *, mode=None, limit=65536):
        with self.parent(path) as (fd, name):
            source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > limit
                    or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
                raise PreparationError("文件类型、归属、权限或大小异常，保留现场。")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise PreparationError("文件超过允许大小。")
            return data

    def write_new(self, path, content, mode=0o600):
        with self.parent(path) as (fd, name):
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(out, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fchmod(stream.fileno(), mode)
                os.fsync(stream.fileno())
            os.fsync(fd)

    def private_directory_new(self, path):
        path = Path(path)
        with self.directory(str(path.parent), create=True) as fd:
            os.mkdir(path.name, 0o700, dir_fd=fd)
            os.fsync(fd)

    def replace_owned(self, path, content, *, identity, digest, mode):
        """Same-directory atomic replacement, only after rechecking managed identity.

        An interrupted write can leave the private candidate for inspection. This
        is not protection against a concurrent malicious root administrator.
        """
        def check():
            if (self.identity(path) != identity
                    or hashlib.sha256(self.read(path, mode=mode)).hexdigest() != digest):
                raise PreparationError("待切换配置已被其他操作修改，不覆盖。")
        check()
        candidate = path + ".snellctl-new"
        self.write_new(candidate, content, mode)
        candidate_identity = self.identity(candidate)
        check()
        if (self.identity(candidate) != candidate_identity
                or self.read(candidate, mode=mode) != content):
            raise PreparationError("待切换的新配置被修改，保留现场，不发布。")
        with self.parent(path) as (fd, name):
            os.replace(name + ".snellctl-new", name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)

    def mask_new(self, unit):
        path = "/etc/systemd/system/" + unit
        with self.parent(path) as (fd, name):
            os.symlink("/dev/null", name, dir_fd=fd)
            os.fsync(fd)

    def readlink(self, path):
        with self.parent(path) as (fd, name):
            return os.readlink(name, dir_fd=fd)

    def identity(self, path):
        info = self.info(path)
        if info is None:
            raise PreparationError("本工具创建的文件已丢失，停止操作。")
        return [info.st_dev, info.st_ino]

    def unlink_owned(self, path, identity):
        with self.parent(path) as (fd, name):
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if [info.st_dev, info.st_ino] != identity:
                raise PreparationError("文件归属记录不符，不删除外部替换的文件。")
            os.unlink(name, dir_fd=fd)
            os.fsync(fd)


def read_owned_files(files, expected, record):
    """Read one owner-checked snapshot for a fixed manifest; never follow its paths."""
    if not isinstance(record, dict) or not isinstance(record.get("files"), dict) or set(record["files"]) != set(expected):
        raise PreparationError("文件清单不完整，停止核查。")
    snapshot = {}
    for path, mode in expected.items():
        item = record["files"][path]
        if (not isinstance(item, dict) or item.get("mode") != mode
                or not isinstance(item.get("identity"), list) or len(item["identity"]) != 2
                or any(type(v) is not int or v < 0 for v in item["identity"])
                or not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])):
            raise PreparationError("文件身份记录损坏，停止核查。")
        if files.identity(path) != item["identity"]:
            raise PreparationError("文件身份已改变，停止核查。")
        data = files.read(path, mode=mode, limit=32 * 1024**2)
        if files.identity(path) != item["identity"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise PreparationError("文件内容或身份已改变，停止核查。")
        snapshot[path] = data
    return snapshot


class Preparation:
    def __init__(self, root: Path, runner):
        self.files = HostFiles(root)
        self.runner = runner

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.files.close()

    def _run(self, args, timeout=30, *, capture_stderr=False):
        result = self.runner(Command(tuple(args), timeout, capture_stderr=capture_stderr))
        if not isinstance(result, Reply) or result.uncertain:
            raise PreparationError("操作结果不确定；已停止，不会自动重试可能已完成的安装或签发。")
        if result.code != 0:
            raise PreparationError("外部操作失败；未继续下一步，原始输出未复制到诊断报告。")
        return result.output

    def _record(self, name, value):
        self.files.write_new(STATE + "/" + name + ".json", (json.dumps(value, sort_keys=True) + "\n").encode())

    def _read_record(self, name):
        try:
            value = json.loads(self.files.read(STATE + "/" + name + ".json", mode=0o600))
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (ValueError, UnicodeError):
            raise PreparationError("准备状态记录不完整或损坏；不自动清理或认领。") from None

    def _exists(self, name):
        return self.files.info(STATE + "/" + name + ".json") is not None

    @contextmanager
    def _lock(self):
        with self.files.directory(STATE, private=True):
            pass
        path = STATE + "/lock"
        with self.files.parent(path) as (fd, name):
            lock = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise PreparationError("准备锁文件异常。")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PreparationError("已有准备操作进行中；不要删除锁文件。") from None
            if self._read_record("owner") != {"format": 1, "scope": "new-host-preparation"}:
                raise PreparationError("缺少本工具创建的准备记录。")
            yield
        finally:
            os.close(lock)

    def initialize(self):
        # Read-only checks must succeed before the first host file is created.
        release_path = "/etc/os-release"
        info = self.files.info(release_path)
        if info is not None and stat.S_ISLNK(info.st_mode):
            if self.files.readlink(release_path) not in {"../usr/lib/os-release", "/usr/lib/os-release"}:
                raise PreparationError("系统发行版链接指向非预期位置。")
            release_path = "/usr/lib/os-release"
        release = self.files.read(release_path).decode("utf-8")
        from .doctor import os_release
        if os_release(release) != {"ID": "debian", "VERSION_ID": "13"}:
            raise PreparationError("此轮只接受 Debian 13。")
        if self._run(["dpkg", "--print-architecture"]).strip() != "amd64":
            raise PreparationError("此轮只接受 amd64。")
        for path in (STATE, APT_LISTS, "/opt/snellctl", "/etc/nginx", "/etc/letsencrypt", "/etc/snellctl", POLICY):
            if self.files.info(path) is not None:
                raise PreparationError("检测到已有组件或策略文件，新机准备不会覆盖。")
        for unit in UNITS:
            for prefix in ("/etc/systemd/system/", "/run/systemd/system/", "/usr/lib/systemd/system/"):
                if self.files.info(prefix + unit) is not None:
                    raise PreparationError("检测到已有服务或 mask，不自动接管。")
            status = self._run(["systemctl", "show", unit, "-p", "LoadState,ActiveState"])
            # `show` must return an explicit absent/inactive state, not empty output.
            if set(status.splitlines()) != {"LoadState=not-found", "ActiveState=inactive"}:
                raise PreparationError("无法确认目标服务尚未安装且未运行。")
        self.files.private_directory_new(STATE)
        self.files.write_new(STATE + "/lock", b"")
        self._record("owner", {"format": 1, "scope": "new-host-preparation"})

    def _apt_options(self):
        return [*APT_SECURITY,
                "-o", "Dir::Etc::sourcelist=" + STATE + "/debian.sources",
                "-o", "Dir::Etc::sourceparts=-",
                "-o", "Dir::State::lists=" + APT_LISTS]

    def _check_archive_keyring(self):
        keyring = "/usr/share/keyrings/debian-archive-keyring.gpg"
        target = "/usr/share/keyrings/debian-archive-keyring.pgp"
        info = self.files.info(keyring)
        # Debian 13 ships this exact compatibility alias; do not follow other links.
        if info is not None and stat.S_ISLNK(info.st_mode):
            if (info.st_uid != os.geteuid() or info.st_nlink != 1
                    or self.files.readlink(keyring) not in {Path(target).name, target}):
                raise PreparationError("Debian 密钥环链接归属或目标异常，停止操作。")
            keyring = target
        self.files.read(keyring, limit=1024**2)

    def _guards(self):
        record = self._read_record("guards")
        expected = {POLICY, *("/etc/systemd/system/" + u for u in UNITS)}
        if set(record) != expected:
            raise PreparationError("启动保护记录异常。")
        for path, identity in record.items():
            if self.files.identity(path) != identity:
                raise PreparationError("启动保护已被外部替换，停止操作。")
            if path == POLICY:
                if self.files.read(path, mode=0o755) != POLICY_BYTES:
                    raise PreparationError("启动策略内容已改变，停止操作。")
            elif self.files.readlink(path) != "/dev/null":
                raise PreparationError("服务 mask 内容已改变，停止操作。")
        for unit in UNITS:
            output = self._run(["systemctl", "show", unit, "-p", "LoadState,ActiveState"])
            if set(output.splitlines()) != {"LoadState=masked", "ActiveState=inactive"}:
                raise PreparationError("启动保护未生效；不安装软件或签发证书。")

    def packages(self):
        with self._lock():
            if self._exists("packages-ready"):
                self._guards()
                record = self._read_record("packages-ready")
                if self._installed() != record.get("versions"):
                    raise PreparationError("已准备的软件包版本发生变化，需重新核对，未重新安装。")
                return "already-prepared"
            if self._exists("packages-intent") or self._exists("guards-intent"):
                raise PreparationError("存在未完成的准备操作；先人工核查，不盲目重跑 APT。")
            self._run(["apt-get", *APT_SECURITY, "update", "--error-on=any"], 300)
            if self._run(["dpkg", "--audit"]).strip():
                raise PreparationError("存在未完成的软件包操作。")
            # Separate signed Debian indices avoid selecting packages from third-party sources.
            self._check_archive_keyring()
            with self.files.directory(STATE + "/home", create=True, private=True):
                pass
            with self.files.directory(APT_LISTS, create=True):
                pass
            source = STATE + "/debian.sources"
            if self.files.info(source) is None:
                self.files.write_new(source, SOURCES)
            elif self.files.read(source, mode=0o600) != SOURCES:
                raise PreparationError("专用软件源文件被改动，停止操作。")
            options = self._apt_options()
            self._run(["apt-get", *options, "update", "--error-on=any"], 300)
            versions = candidates(self._run(["apt-cache", *options, "policy", *DEPENDENCIES]))
            if set(versions) != set(DEPENDENCIES):
                raise PreparationError("无法确认全部 Debian 候选包。")
            requested = [name + "=" + versions[name] for name in DEPENDENCIES]
            simulation = self._run(["apt-get", *options, "--simulate", "--no-remove", "--no-install-recommends", "install", *requested])
            if re.search(r"^(Remv|Purg)\s", simulation, re.M):
                raise PreparationError("依赖方案涉及移除软件包，已停止。")
            self._record("guards-intent", {"format": 1})
            self.files.write_new(POLICY, POLICY_BYTES, 0o755)
            for unit in UNITS:
                self.files.mask_new(unit)
            identities = {path: self.files.identity(path) for path in [POLICY, *("/etc/systemd/system/" + u for u in UNITS)]}
            self._record("guards", identities)
            self._run(["systemctl", "daemon-reload"])
            self._guards()
            self._record("packages-intent", {"versions": versions})
            self._run(["apt-get", *options, "--no-remove", "--no-install-recommends", "-y", "install", *requested], 900)
            self._guards()
            if self._run(["dpkg", "--audit"]).strip() or self._installed() != versions:
                raise PreparationError("安装后的软件包状态与计划不符。")
            self._record("packages-ready", {"versions": versions})
            return "packages-prepared-services-blocked"

    def _installed(self):
        output = self._run(["dpkg-query", "-W", "-f=${Package}\t${db:Status-Abbrev}\t${Version}\n", *DEPENDENCIES])
        found = {}
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[0] in DEPENDENCIES and parts[1].strip() == "ii" and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,100}", parts[2]):
                found[parts[0]] = parts[2]
        return found

    def status(self):
        """Report recorded progress only, not current certificate or service health."""
        with self._lock():
            phases = {}
            for phase, ready in (("guards", "guards"), ("packages", "packages-ready"),
                                 ("dns-test", "dns-test-ready"), ("certificate", "certificate-ready")):
                if self._exists(ready):
                    self._read_record(ready)
                    phases[phase] = "completion-recorded"
                elif self._exists(phase + "-intent"):
                    self._read_record(phase + "-intent")
                    phases[phase] = "needs-inspection"
                else:
                    phases[phase] = "not-started"
            if phases["guards"] != "not-started" and phases["packages"] != "completion-recorded":
                phases["packages"] = "needs-inspection"
            for phase in ("activation", "renewal-test", "renewal-enable", "public"):
                phases[phase] = "not-started"
                for suffix, label in (("-ready", "completion-recorded"), ("-intent", "needs-inspection")):
                    if self._exists(phase + suffix):
                        self._read_record(phase + suffix)
                        phases[phase] = label
                        break
            return {"format": 1, "mode": "preparation-records-only", "phases": phases,
                    "deploy_ready": False, "renewal_enabled_by_this_engine": self._exists("renewal-enable-ready"),
                    "current_service_health": "not-checked"}

    def credential(self, token: str):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token):
            raise PreparationError("Token 格式不符合要求；内容不会显示。")
        with self._lock():
            if not self._exists("packages-ready"):
                raise PreparationError("软件准备尚未完成。")
            self._guards()
            if self.files.info(CREDENTIAL) is not None:
                raise PreparationError("凭据文件已存在，不覆盖或轮换。")
            for path in ("/etc/snellctl", "/etc/snellctl/credentials"):
                with self.files.directory(path, create=True, private=True):
                    pass
            self.files.write_new(CREDENTIAL, ("dns_cloudflare_api_token = " + token + "\n").encode("ascii"))
            return "credential-created"

    def _certbot_config(self):
        path = "/etc/letsencrypt/cli.ini"
        if self.files.info(path) is not None:
            try:
                config = configparser.ConfigParser(interpolation=None)
                config.read_string("[options]\n" + self.files.read(path).decode("utf-8"))
                values = dict(config["options"])
                if config.sections() != ["options"] or not set(values) <= {"max-log-backups", "preconfigured-renewal"}:
                    raise ValueError
                if "max-log-backups" in values and not re.fullmatch(r"[0-9]{1,3}", values["max-log-backups"]):
                    raise ValueError
                if "preconfigured-renewal" in values and values["preconfigured-renewal"].lower() not in {"true", "false"}:
                    raise ValueError
            except (ValueError, UnicodeError, configparser.Error):
                raise PreparationError("发现非预期 Certbot 全局设置；不继承钩子或其他签发参数。") from None
        with self.files.directory(STATE + "/home", private=True) as fd:
            if os.listdir(fd):
                raise PreparationError("证书操作的隔离 HOME 不为空，停止以免继承其他凭据。")

    def certificate(self, domain: str, *, production: bool, agree_tos: bool, confirm_issue: bool = False):
        spec = NodeSpec(domain)
        if type(production) is not bool:
            raise PreparationError("必须明确选择演练或正式签发模式。")
        if agree_tos is not True or (production and confirm_issue is not True):
            raise PreparationError("需要明确同意 CA 条款；正式签发还需要单独确认。")
        with self._lock():
            if not self._exists("packages-ready"):
                raise PreparationError("软件准备尚未完成。")
            self._guards()
            credential = self.files.read(CREDENTIAL, mode=0o600)
            if not re.fullmatch(rb"dns_cloudflare_api_token = [A-Za-z0-9_-]{20,256}\n", credential):
                raise PreparationError("凭据文件格式已改变，未显示内容或继续签发。")
            self._certbot_config()
            binding = hashlib.sha256(domain.encode()).hexdigest()
            phase = "certificate" if production else "dns-test"
            if self._exists(phase + "-ready"):
                record = self._read_record(phase + "-ready")
                if record.get("domain_sha256") != binding:
                    raise PreparationError("本次准备已绑定其他域名；不自动替换。")
                if production:
                    self._verify_certificate(spec)
                return "already-completed"
            if self._exists(phase + "-intent"):
                raise PreparationError("之前的签发或演练结果不确定；先核查 CA 与本机结果，禁止自动重试。")
            if production:
                if not self._exists("dns-test-ready") or self._read_record("dns-test-ready") != {"domain_sha256": binding}:
                    raise PreparationError("正式签发前须完成同一域名的 DNS 验证演练。")
            for path in (spec.cert_dir, "/etc/letsencrypt/archive/" + domain, "/etc/letsencrypt/renewal/" + domain + ".conf"):
                if self.files.info(path) is not None:
                    raise PreparationError("发现已有证书或续期配置，不自动认领、覆盖或重新签发。")
            self._record(phase + "-intent", {"domain_sha256": binding})
            args = ["certbot", "certonly", "--non-interactive", "--agree-tos",
                    "--register-unsafely-without-email", "--no-directory-hooks",
                    "--dns-cloudflare", "--dns-cloudflare-credentials", CREDENTIAL,
                    "--dns-cloudflare-propagation-seconds", "60", "--key-type", "ecdsa",
                    "--elliptic-curve", "secp256r1", "--cert-name", domain, "-d", domain,
                    "--server", PRODUCTION if production else STAGING,
                    "--config-dir", "/etc/letsencrypt", "--work-dir", "/var/lib/letsencrypt",
                    "--logs-dir", "/var/log/letsencrypt", "--max-log-backups", "3"]
            if not production:
                args.append("--dry-run")
            self._run(args, 600)
            self._guards()
            if production:
                self._verify_certificate(spec)
            elif self.files.info(spec.cert_dir) is not None:
                raise PreparationError("演练后意外出现运行证书路径，停止核查。")
            self._record(phase + "-ready", {"domain_sha256": binding})
            return "certificate-verified-services-blocked" if production else "dns-test-passed"

    def _verify_certificate(self, spec, *, allowed_deploy_hook=None):
        # Certbot live symlinks are accepted only when pointing at this lineage's archive.
        archive_files = {}
        for name in ("cert", "chain", "fullchain", "privkey"):
            live = spec.cert_dir + "/" + name + ".pem"
            target = self.files.readlink(live)
            match = re.fullmatch(r"\.\./\.\./archive/" + re.escape(spec.domain) + "/" + name + r"([1-9][0-9]*)\.pem", target)
            if not match:
                raise PreparationError("证书链接指向非预期位置。")
            path = "/etc/letsencrypt/archive/" + spec.domain + "/" + name + match[1] + ".pem"
            self.files.read(path, mode=0o600 if name == "privkey" else None, limit=65536)
            archive_files[name] = path
        cert = archive_files["cert"]
        chain = archive_files["chain"]
        if self.files.read(archive_files["fullchain"]) != self.files.read(cert) + self.files.read(chain):
            raise PreparationError("fullchain 与证书及链文件不一致。")
        self._run(["openssl", "x509", "-in", cert, "-noout", "-checkend", "604800"])
        self._run(["openssl", "verify", "-purpose", "sslserver", "-verify_hostname", spec.domain,
                   "-CAfile", "/etc/ssl/certs/ca-certificates.crt", "-untrusted", chain, cert])
        public_cert = self._run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"])
        public_key = self._run(["openssl", "pkey", "-in", archive_files["privkey"], "-pubout"])
        if not public_cert.startswith("-----BEGIN PUBLIC KEY-----\n") or public_cert != public_key:
            raise PreparationError("证书与私钥不匹配。")
        try:
            renewal = self.files.read("/etc/letsencrypt/renewal/" + spec.domain + ".conf").decode("utf-8")
            config = configparser.ConfigParser(interpolation=None)
            config.read_string("[lineage]\n" + renewal)
            params = config["renewalparams"]
            if (params.get("authenticator") != "dns-cloudflare" or params.get("server") != PRODUCTION
                    or params.get("dns_cloudflare_credentials") != CREDENTIAL
                    or params.get("key_type") != "ecdsa"
                    or params.get("autorenew", "true").lower() not in {"true", "1"}
                    or any(params.get(key, "").strip() for key in ("pre_hook", "post_hook", "installer"))
                    or any(params.get(key, "").strip() not in {"", allowed_deploy_hook}
                           for key in ("renew_hook", "deploy_hook"))):
                raise ValueError
        except (KeyError, ValueError, UnicodeError, configparser.Error):
            raise PreparationError("续期配置与本次 DNS-01 方案不符。") from None
        return self.files.read(cert)
