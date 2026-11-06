"""Opt-in reinstall after a verified uninstall, with a stable lock and history.

This is not a rollback or a recovery engine. A durable intent precedes every
mutation; the same preparation lock stays held through archive and deployment.
"""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import threading
import uuid

from .activation import Activation, BINARIES, DEFAULT_LINK, _binding
from .deployment import NodeSpec
from .hostcommands import DebianCommands
from .hostprep import Preparation, PreparationError, STATE, UNITS
from .installer import Cancelled, Installation, Terminal, _confirm, _confirm_public, _port
from .reinstallplan import NODE_UNITS, ReinstallPlan, SUCCESS as PLAN_SUCCESS
from .tlsprobe import LocalTLSProbe
from .tokenchange import TokenChange


INTENT = "reinstall-intent"
COMPLETE = "reinstall-ready"
GENERATIONS = STATE + "/generations"
SUCCESS = "reinstalled-external-test-required"
HISTORY_FILES = {"debian.sources", "credential-current.json", "domain-current.json", "reinstall-ready.json"}
HISTORY_FILES.update(name + ".json" for name in (
    "guards-intent", "guards", "packages-intent", "packages-ready", "dns-test-intent", "dns-test-ready",
    "certificate-intent", "certificate-ready", "activation-intent", "activation-files", "activation-ready",
    "renewal-test-intent", "renewal-test-ready", "renewal-enable-intent", "renewal-enable-ready",
    "public-intent", "public-files", "public-firewall-added", "public-ready", "uninstall-ready",
    "token-diagnostic-started", "token-diagnostic-report", "token-permission-recheck-started",
    "token-permission-recheck-report", "token-resume-started", "token-resume-report",
))
HISTORY_DIR = re.compile(r"(?:token-(?:diagnostic|permission-recheck|resume)-logs|"
                         r"(?:domain-change|renewal-pause-probe)-[a-f0-9]{64}|"
                         r"(?:retired-cleanup|uninstall)-[a-f0-9]{32})")


def _json(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def _require(condition):
    if not condition:
        raise PreparationError("重装归属、历史或现场发生变化；保留现场，不自动修复或重试。")


class ReinstallPreparation(Preparation):
    """Only this engine may nest operations while holding its original flock."""

    def __init__(self, root, runner):
        super().__init__(root, runner)
        self._lease_thread = None
        self._lease_identity = None
        self._authorized_intent = None

    @contextmanager
    def session(self):
        _require(self._lease_thread is None)
        with super()._lock():
            self._lease_thread = threading.get_ident()
            self._lease_identity = self.files.identity(STATE + "/lock")
            try:
                yield
            finally:
                self._lease_thread = self._lease_identity = self._authorized_intent = None

    @contextmanager
    def _lock(self):
        if self._lease_thread == threading.get_ident():
            _require(self.files.identity(STATE + "/lock") == self._lease_identity)
            _require(self._read_record("owner") == {"format": 1, "scope": "new-host-preparation"})
            yield
        else:
            with super()._lock():
                yield

    def _reinstall_gate(self):
        if self._exists(INTENT):
            _require(self._lease_thread == threading.get_ident() and self._authorized_intent is not None)
            identity, content = self._authorized_intent
            path = STATE + "/" + INTENT + ".json"
            _require(self.files.identity(path) == identity and self.files.read(path, mode=0o600) == content)


class Reinstallation:
    def __init__(self, installation, progress=lambda phase: None):
        _require(isinstance(installation.prep, ReinstallPreparation))
        self.installation = installation
        self.prep, self.local, self.public = installation.prep, installation.local, installation.public
        self.files = self.prep.files
        self.plan = ReinstallPlan(TokenChange(self.public))
        self.progress, self.phase = progress, "not-started"
        self.changed = False
        self.archive = None
        self.archived_tree = None
        self.finished = False
        self.requested = None

    def step(self, phase):
        self.phase = phase
        self.progress(phase)

    def _tree(self, base, names):
        """Bounded metadata snapshot; never read raw historical logs or secrets."""
        result = {}
        def visit(relative, depth):
            _require(depth <= 12 and len(result) < 20000)
            path = base + "/" + relative
            info = self.files.info(path)
            _require(info is not None and info.st_uid == os.geteuid())
            mode = stat.S_IMODE(info.st_mode)
            directory = stat.S_ISDIR(info.st_mode)
            _require((directory and mode == 0o700) or
                     (stat.S_ISREG(info.st_mode) and mode == 0o600 and info.st_nlink == 1))
            result[relative] = ["directory" if directory else "file", info.st_dev, info.st_ino,
                                mode, info.st_uid, info.st_gid, 0 if directory else info.st_size, info.st_mtime_ns]
            if directory:
                with self.files.directory(path, private=True) as fd:
                    children = os.listdir(fd)
                _require(len(children) <= 20000 - len(result))
                for name in sorted(children):
                    visit(relative + "/" + name, depth + 1)
        for name in sorted(names):
            _require(name not in {"", ".", ".."} and "/" not in name)
            visit(name, 0)
        return result

    def _history(self):
        with self.files.directory(STATE, private=True) as fd:
            names = set(os.listdir(fd))
        _require({"owner.json", "lock", "home", "uninstall-ready.json"} <= names)
        for name in names - {"owner.json", "lock", "home", "generations"}:
            _require(name in HISTORY_FILES or HISTORY_DIR.fullmatch(name) is not None)
            info = self.files.info(STATE + "/" + name)
            _require(info is not None and (stat.S_ISREG(info.st_mode) if name in HISTORY_FILES else stat.S_ISDIR(info.st_mode)))
        selected = sorted(names - {"owner.json", "lock", "home", "generations"})
        tree = self._tree(STATE, selected)
        if "generations" in names:
            with self.files.directory(GENERATIONS, private=True) as fd:
                generations = os.listdir(fd)
            _require(all(re.fullmatch(r"[a-f0-9]{32}", name) for name in generations))
            self._tree(GENERATIONS, generations)
        return selected, tree

    def _empty_paths(self):
        paths = ["/etc/snellctl/nodes/main", "/etc/snellctl/nodes"]
        programs = [PurePosixPath(path) for path in BINARIES]
        paths += [str(p.parent) for p in programs]
        paths += sorted({str(p.parent.parent) for p in programs})
        paths.append("/opt/snellctl")
        for prefix in ("/etc/systemd/system/", "/run/systemd/system/"):
            paths += [prefix + unit + ".d" for unit in (*NODE_UNITS, *UNITS)
                      if self.files.info(prefix + unit + ".d") is not None]
        return paths

    def preflight(self, spec, ssh_port):
        self.step("uninstalled-state-check")
        _require(self.plan.check()["result"] == PLAN_SUCCESS)
        with self.prep._lock():
            _require(type(ssh_port) is int and ssh_port == self.prep._read_record("public-ready")["ssh_port"])
            self.public.check_new_host(spec, ssh_port)
            self.local._vacant(spec)
            # Empty vendor drop-ins are still external configuration; do not remove them.
            for unit in (*NODE_UNITS, *UNITS):
                _require(self.files.info("/usr/lib/systemd/system/" + unit + ".d") is None)
            self.step("history-layout-check")
            return self._history()

    def _move_history(self, name, expected):
        _require(self._tree(STATE, [name]) == {k: v for k, v in expected.items() if k == name or k.startswith(name + "/")})
        with self.files.directory(STATE, private=True) as source:
            with self.files.directory(self.archive + "/records", private=True) as target:
                _require(name not in os.listdir(target))
                os.rename(name, name, src_dir_fd=source, dst_dir_fd=target)
                os.fsync(source)
                os.fsync(target)

    def _remove_empty(self, path, identity):
        with self.files.directory(path) as fd:
            _require(not os.listdir(fd) and self.files.identity(path) == identity)
        with self.files.parent(path) as (fd, name):
            _require(self.files.identity(path) == identity)
            os.rmdir(name, dir_fd=fd)
            os.fsync(fd)

    @contextmanager
    def prepare(self, spec, ssh_port, *, confirmed=False):
        _require(confirmed is True and not self.changed)
        with self.prep.session():
            names, tree = self.preflight(spec, ssh_port)
            self.requested = spec, ssh_port
            empty = {p: self.files.identity(p) for p in self._empty_paths()}
            generation = uuid.uuid4().hex
            self.archive = GENERATIONS + "/" + generation
            intent = {"format": 1, "operation": "managed-reinstall", "generation": generation,
                      "new_domain_sha256": hashlib.sha256(spec.domain.encode()).hexdigest(),
                      "public_port": spec.public_port, "snell_port": spec.snell_port,
                      "tls_port": spec.tls_port, "ssh_port": ssh_port}
            self.step("reinstall-intent")
            self.changed = True
            self.prep._record(INTENT, intent)
            path = STATE + "/" + INTENT + ".json"
            self.prep._authorized_intent = (self.files.identity(path), _json(intent))
            self.prep._reinstall_gate()
            self.step("history-archive")
            with self.files.directory(GENERATIONS, create=True, private=True):
                pass
            self.files.private_directory_new(self.archive)
            self.files.write_new(self.archive + "/manifest.json", _json({
                "format": 1, "original_prefix": STATE, "records_prefix": self.archive + "/records",
                "metadata": tree, "absolute_historical_paths_rewritten": False,
            }))
            self.files.private_directory_new(self.archive + "/records")
            for name in names:
                self._move_history(name, tree)
            _require(self._tree(self.archive + "/records", names) == tree)
            self.archived_tree = (names, tree)
            self.step("empty-layout-preparation")
            for path, identity in empty.items():
                self._remove_empty(path, identity)
            yield
            _require(self.finished)

    def prepare_default_site(self):
        """An installed nginx-common may not recreate its deleted default link."""
        _require(self.prep._lease_thread == threading.get_ident() and self.prep._exists(INTENT))
        self.prep._reinstall_gate()
        self.prep._guards()
        self.local._nginx_package_config()
        with self.files.directory("/etc/nginx/sites-enabled") as fd:
            names = os.listdir(fd)
            if not names:
                os.symlink("/etc/nginx/sites-available/default", "default", dir_fd=fd)
                os.fsync(fd)
            else:
                _require(names == ["default"])
        _require(self.files.readlink(DEFAULT_LINK) == "/etc/nginx/sites-available/default")

    def finish(self):
        self.step("reinstall-completion")
        _require(self.prep._lease_thread == threading.get_ident() and self.prep._exists(INTENT))
        self.prep._reinstall_gate()
        _require(self.files.identity(STATE + "/lock") == self.prep._lease_identity)
        _require(self.archive is not None and self.archived_tree is not None)
        names, tree = self.archived_tree
        _require(self._tree(self.archive + "/records", names) == tree)
        for name in ("certificate-ready", "renewal-test-ready", "renewal-enable-ready", "public-ready"):
            self.prep._read_record(name)
        spec, ssh_port = self.requested
        spec = self.local._version(spec)
        record = self.prep._read_record("public-ready")
        _require(record.get("binding") == _binding(spec) and record.get("ssh_port") == ssh_port)
        self.public._public_health(spec, record)
        self.prep._record(COMPLETE, {"format": 1, "operation": "managed-reinstall", "result": SUCCESS,
                                    "generation": self.archive.rsplit("/", 1)[1]})
        self.prep._reinstall_gate()
        self.files.unlink_owned(STATE + "/" + INTENT + ".json", self.prep._authorized_intent[0])
        self.finished = True


@contextmanager
def real_reinstallation():
    with ReinstallPreparation(Path("/"), DebianCommands()) as prep:
        installation = Installation(prep, Activation(prep, LocalTLSProbe()), preflight_check=lambda spec: None)
        yield Reinstallation(installation)


def run_reinstall(*, factory=real_reinstallation, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("重装要求交互终端；不接受管道、自动确认或明文 Token 参数。")
        return 2
    engine = None
    try:
        ui.say("实验版受控重装：仅限本工具已成功卸载的 Debian 13 / amd64 main，尚未实机验收。")
        ui.say("保留软件包、ACME 账户和历史；生成新节点密钥，不复用已删除的凭据，不安装快捷入口。")
        with factory() as engine:
            engine.progress = lambda phase: ui.say("重装阶段：" + phase)
            domain = ui.ask("本次完整小写域名（留空取消）：").strip()
            if not domain:
                return 130
            spec = NodeSpec(domain, public_port=_port(ui, "ShadowTLS 公网 TCP 端口", 443),
                            snell_port=_port(ui, "Snell 本机端口", 31001),
                            tls_port=_port(ui, "Nginx 本机 TLS 端口", 31443))
            ssh_port = _port(ui, "当前 SSH TCP 端口")
            engine.preflight(spec, ssh_port)
            ui.say(f"重装域名：{spec.domain}；IPv4 TCP {spec.public_port}；保留 SSH TCP {ssh_port}。")
            _confirm(ui, "将归档上一轮私有记录，复用已核查的空目录和软件包；不删除历史或 ACME 账户。\n"
                     "仅用于没有其他消费者的本项目测试机；不修改 SSH、内核或第三方软件源。", "资源仅用于本项目并允许归档重装")
            _confirm(ui, "请确认独立 SSH 新连接及恢复控制台可用。失败可能留下部分部署和停用状态；不自动回退或接续。", "备用连接可用")
            _confirm(ui, "请阅读现行 CA 条款：https://letsencrypt.org/repository/\n"
                     "本次不提供账户邮箱；签发会使用 CA 配额并公开证书域名。", "有域名授权并同意现行 CA 条款")
            engine.step("official-downloads")
            downloads = engine.installation.downloads()
            _confirm(ui, "即将写入重装标记、归档历史、刷新软件源并安装候选组件。\n"
                     "保持连接，不并行管理或运行 Certbot。中断后不可直接重跑新机安装、重装或接续命令。", "执行本次受控重装")
            with engine.prepare(spec, ssh_port, confirmed=True):
                engine.step("packages")
                engine.prep.packages()
                engine.prepare_default_site()
                engine.step("credential")
                token = ui.secret()
                try:
                    engine.prep.credential(token)
                finally:
                    token = None
                engine.step("dns-test")
                engine.prep.certificate(spec.domain, production=False, agree_tos=True)
                _confirm(ui, "DNS 演练已通过。正式签发会使用 CA 配额并公开证书域名。", "正式签发")
                engine.step("certificate")
                engine.prep.certificate(spec.domain, production=True, agree_tos=True, confirm_issue=True)
                engine.step("activation")
                engine.local.activate(spec, downloads)
                downloads.clear()
                _confirm(ui, "将再次执行 DNS 演练并验证 Nginx 重载；尚未开放公网入口。", "续期演练")
                engine.step("renewal-test")
                engine.local.test_renewal(spec, confirm_test=True)
                _confirm_public(ui, spec)
                engine.step("public")
                engine.public.enable(spec, ssh_port=ssh_port, confirm_public=True,
                                     confirm_renewal=True, confirm_ssh_reconnected=True)
                engine.finish()
            ui.say(json.dumps({"format": 1, "operation": "managed-reinstall", "result": SUCCESS,
                               "history_archived": True, "original_lock_preserved": True,
                               "external_acceptance_required": True, "automatic_retry": False}, indent=2))
            ui.say("服务端重装完成，历史保留。请单独导出新客户端配置，再做外部使用及重启验收；不会自动重启。")
            return 0
    except (Exception, KeyboardInterrupt) as error:
        cancelled = isinstance(error, (Cancelled, EOFError, KeyboardInterrupt))
        changed = engine is not None and engine.changed
        ui.say(json.dumps({"format": 1, "operation": "managed-reinstall",
                           "result": "cancelled" if cancelled else "stopped",
                           "phase": engine.phase if engine else "platform",
                           "host_changes_attempted": changed, "automatic_retry": False}, indent=2))
        ui.say("保留历史和现场；不要删除标记、重跑安装或直接重启。先查看 install-status。" if changed else
               "本轮未写入系统配置；原卸载状态及历史保留。")
        return 130 if cancelled else 1
