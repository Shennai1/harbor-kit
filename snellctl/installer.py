"""Explicitly experimental, terminal-only new-host installation workflow."""

from contextlib import contextmanager
import getpass
import json
from pathlib import Path
import re
import sys
import warnings

from .activation import Activation
from .artifacts import CATALOG, download, verify
from .deployment import NodeSpec
from .doctor import Result
from .hostcommands import DebianCommands
from .hostprep import Command, Preparation, PreparationError, STATE
from .preflight import check
from .publish import Publication
from .tlsprobe import LocalTLSProbe


PHASES = {
    "platform": ("执行环境", "仅支持 Debian 13 / amd64、root、systemd 和交互终端。"),
    "inputs": ("部署参数", "检查完整小写域名及四个互不冲突的端口；SSH 端口没有默认值。"),
    "preflight": ("新机检查", "先运行只读 preflight；检查已有组件、UFW、SSH、软件源和端口占用。"),
    "downloads": ("官方程序下载校验", "检查官方来源的 HTTPS 可达性；不能关闭证书或指纹校验。"),
    "consent": ("安装及条款确认", "未明确确认则不开始系统写入。"),
    "initialize": ("初始化归属记录", "检查是否已有部署记录；不要删除记录来绕过重复安装保护。"),
    "packages": ("软件包准备", "检查 APT/软件包状态和启动保护；不要直接解除 mask 或删除 policy-rc.d。"),
    "credential": ("Cloudflare 凭据", "需要可隐藏输入的终端和专用 Token；不要向对话发送令牌或凭据文件。"),
    "dns-test": ("DNS 验证演练", "检查 Token 的区域权限、DNS 传播及出站连接；不要重复签发或贴原始日志。"),
    "certificate": ("正式证书签发", "先核对本机证书及 CA 结果；失败或超时不代表远端没有完成。"),
    "activation": ("本机服务与 TLS 验收", "检查服务、端口及配置归属；服务是否全部停止仍需按现场确认。"),
    "renewal-test": ("模拟续期与重载验收", "检查续期配置、钩子与运行证书；此时尚未启用正式定时续期。"),
    "renewal-enable": ("正式自动续期启用", "有完成记录不代表定时器当前健康；另行核查运行状态。"),
    "public-consent": ("公网及自动续期确认", "本机测试完成不等于部署完成；未确认开放时入口仍为回环。"),
    "public": ("自动续期与公网启用", "检查入口、UFW 和定时器；失败可能已留下规则或已启用续期，不自动回滚。"),
    "resume-state": ("接续阶段检查", "仅支持本机验收和续期演练已完成、自动续期及公网启用均未开始的阶段；其他状态保留现场。"),
    "resume-check": ("接续现场复查", "核对原部署参数、配置归属、证书、服务和防火墙；不自动启动已停止的服务或修复变化。"),
    "complete": ("服务端流程完成", "仍需外部客户端及重启验收；本工具不会自动重启机器。"),
}

PENDING_PUBLIC_PHASES = {
    **dict.fromkeys(("guards", "packages", "dns-test", "certificate", "activation", "renewal-test"),
                   "completion-recorded"),
    "renewal-enable": "not-started", "public": "not-started",
}


class Cancelled(Exception):
    pass


class Terminal:
    def interactive(self):
        return all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr))

    def say(self, text):
        print(text, flush=True)

    def ask(self, prompt):
        return input(prompt)

    def secret(self):
        # getpass otherwise falls back to visible stdin on an unsuitable terminal.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("粘贴本机专用 CF API Token（隐藏输入，回车确认）：")
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", value):
            raise PreparationError("凭据输入未通过格式检查。")
        return value


def confirm(ui, prompt):
    """Only an explicit ASCII y/Y authorizes; blank or any other input cancels."""
    return ui.ask(prompt + " [y/n]（默认 n）：").strip().lower() == "y"


def _confirm(ui, message, action):
    ui.say(message)
    if not confirm(ui, f"确认{action}？"):
        raise Cancelled


def _port(ui, prompt, default=None):
    value = ui.ask(prompt + (f" [{default}]" if default is not None else "（必填）") + "：").strip()
    if not value and default is not None:
        return default
    if not re.fullmatch(r"[0-9]{1,5}", value) or not 1 <= int(value) <= 65535:
        raise ValueError("端口无效。")
    return int(value)


def _confirm_public(ui, spec):
    _confirm(ui, "将启用正式证书自动续期和服务开机启动，必要时 Certbot 会联系正式 CA。", "自动续期")
    _confirm(ui, "保留本会话。请从另一终端新建 SSH 连接并确认可以登录，再回到这里确认。", "已重连")
    _confirm(ui, f"将 ShadowTLS 切换至 0.0.0.0:{spec.public_port}，只新增该 IPv4 TCP 的 UFW 放行规则。\n"
             "不会更改 SSH 规则；本机 TLS 验收不能证明外部客户端一定可用。", "开放")


class Installation:
    def __init__(self, preparation, activation, *, preflight_check, downloader=download):
        self.prep = preparation
        self.local = activation
        self.public = Publication(activation)
        self.preflight_check = preflight_check
        self.downloader = downloader

    def preflight(self, spec, ssh_port):
        if self.prep.files.info(STATE) is not None:
            raise PreparationError("已有安装阶段记录；不自动继续或重装。")
        if self.preflight_check(spec).get("limited_checks_passed") is not True:
            raise PreparationError("新机预检查未通过。")
        # Reject known firewall conflicts before installing packages or contacting a CA.
        self.public.check_new_host(spec, ssh_port)

    def downloads(self):
        result = {}
        for artifact in CATALOG:
            data = self.downloader(artifact)
            verify(artifact, data)
            result[artifact.name] = data
        return result


@contextmanager
def real_installation():
    runner = DebianCommands()

    def readonly(args):
        reply = runner(Command(tuple(args)))
        return Result(-1 if reply.uncertain else reply.code, "" if reply.uncertain else reply.output)

    with Preparation(Path("/"), runner) as prep:
        yield Installation(prep, Activation(prep, LocalTLSProbe()),
                           preflight_check=lambda spec: check(spec, runner=readonly))


def _failure(ui, phase, changed, cancelled):
    label, hint = PHASES[phase]
    ui.say(("已取消：" if cancelled else "已停止：") + label + "。")
    ui.say(hint)
    if changed:
        ui.say("本轮已进入系统写入阶段，可能留下软件包、凭据、服务或远端操作结果；不自动清理或重试。")
        ui.say("先查看 install-status 的脱敏阶段记录；不要重跑安装、删除状态目录或重置防火墙。")
        ui.say("保留当前 SSH 会话，使用另一会话确认 SSH；不要为了排错直接重启。")
    else:
        ui.say("本轮尚未执行本工具的系统配置写入；此前安装状态仍须保留和核查。")
    # Only fixed enums and booleans, never exception text or subprocess output.
    ui.say("snellctl-diagnostic: " + json.dumps({
        "format": 1, "result": "cancelled" if cancelled else "stopped",
        "phase": phase, "host_changes_attempted": changed, "automatic_retry": False,
    }, sort_keys=True))


def run_wizard(*, factory=real_installation, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("安装向导要求标准输入、输出和错误输出均连接交互终端；不接受管道或明文 Token 参数。")
        return 2
    phase, changed = "platform", False

    def step(name):
        nonlocal phase
        phase = name
        ui.say("\n当前阶段：" + PHASES[name][0])

    try:
        ui.say("实验版新机安装：已完成一轮含人工接续的实测，完整向导仍待复测。不会接管现有节点。")
        ui.say("仅支持 Debian 13 / amd64、单节点 main、IPv4 TCP；没有通用自动恢复或卸载入口。")
        with factory() as engine:
            step("inputs")
            domain = ui.ask("完整小写域名：").strip()
            spec = NodeSpec(domain, public_port=_port(ui, "ShadowTLS 公网 TCP 端口", 443),
                            snell_port=_port(ui, "Snell 本机端口", 31001),
                            tls_port=_port(ui, "Nginx 本机 TLS 端口", 31443))
            ssh_port = _port(ui, "当前 SSH TCP 端口")
            if ssh_port in {spec.public_port, spec.snell_port, spec.tls_port}:
                raise ValueError("SSH 端口不能与节点端口重复。")
            step("preflight")
            engine.preflight(spec, ssh_port)
            ui.say("有限新机检查通过；未检查全部内核自定义规则、云安全组或公网可达性。")
            ui.say(f"域名：{spec.domain}\n公网入口：IPv4 TCP {spec.public_port}\n"
                   f"本机后端：127.0.0.1:{spec.snell_port} / 127.0.0.1:{spec.tls_port}\n"
                   f"保留 SSH TCP {ssh_port}；不开放后端或新增 IPv6 业务规则。")
            step("consent")
            _confirm(ui, "将下载官方固定版本，刷新软件源、安装组件并写入受限配置。\n"
                     "软件包和证书操作不能靠删除文件完整撤销；仅用于可恢复的新测试 VPS。", "安装")
            _confirm(ui, "请先阅读 Let's Encrypt 现行 Subscriber Agreement：\n"
                     "https://letsencrypt.org/repository/\n"
                     "本次不提供账户邮箱；会请求 DNS 演练，正式签发的域名将进入公开证书透明度记录。\n"
                     "继续表示你有域名管理授权，并同意现行条款；正式签发前还会单独确认。", "同意")
            step("downloads")
            downloads = engine.downloads()
            step("initialize")
            changed = True
            engine.prep.initialize()
            step("packages")
            engine.prep.packages()
            step("credential")
            ui.say("Token 仅用于选定 Cloudflare 区域的 DNS 编辑；保存在 root-only 文件供自动续期使用。")
            token = ui.secret()
            try:
                engine.prep.credential(token)
            finally:
                token = None
            step("dns-test")
            engine.prep.certificate(spec.domain, production=False, agree_tos=True)
            step("certificate")
            _confirm(ui, "DNS 演练已通过。现在请求正式证书，会使用 CA 配额并公开证书域名。", "签发")
            engine.prep.certificate(spec.domain, production=True, agree_tos=True, confirm_issue=True)
            step("activation")
            engine.local.activate(spec, downloads)
            downloads.clear()
            step("renewal-test")
            _confirm(ui, "将再次执行 DNS 演练并测试 Nginx 重载；尚不启用正式定时续期。", "续期演练")
            engine.local.test_renewal(spec, confirm_test=True)
            step("public-consent")
            _confirm_public(ui, spec)
            step("public")
            engine.public.enable(spec, ssh_port=ssh_port, confirm_public=True,
                                 confirm_renewal=True, confirm_ssh_reconnected=True)
            step("complete")
            ui.say("服务端安装流程已完成；入口、自动续期及开机启动已核对。")
            ui.say("尚需客户端配置导出、外部实际使用及重启验收。请单独使用 client 或菜单 5 确认显示配置；本向导不显示密钥，也不会自动重启。")
            return 0
    except (Cancelled, EOFError, KeyboardInterrupt):
        _failure(ui, phase, changed, True)
        return 130
    except Exception:
        _failure(ui, phase, changed, False)
        return 1


def run_resume(*, factory=real_installation, terminal=None):
    """Explicit continuation of only the verified, not-yet-published checkpoint."""
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("接续要求标准输入、输出和错误输出均连接交互终端；不接受管道或自动确认。")
        return 2
    phase, changed = "platform", False
    try:
        ui.say("实验版受限接续：只处理本机验收及续期演练完成、尚未开始公网开放的 main 节点。")
        ui.say("先确认旧安装程序已退出，不要在其他会话同时安装或修改配置。不会下载、重装、换密钥或重跑初次签发。")
        with factory() as engine:
            phase = "resume-state"
            report = engine.prep.status()
            ui.say(render_status({**report, "state": "records-found"}))
            if report["phases"] != PENDING_PUBLIC_PHASES:
                raise PreparationError("不属于允许接续的阶段。")
            phase = "inputs"
            domain = ui.ask("原部署的完整小写域名：").strip()
            spec = NodeSpec(domain, public_port=_port(ui, "原定 ShadowTLS 公网 TCP 端口"),
                            snell_port=_port(ui, "原 Snell 本机端口"),
                            tls_port=_port(ui, "原 Nginx 本机 TLS 端口"))
            ssh_port = _port(ui, "当前 SSH TCP 端口")
            if ssh_port in {spec.public_port, spec.snell_port, spec.tls_port}:
                raise ValueError("SSH 端口不能与节点端口重复。")
            phase = "resume-check"
            ui.say("正在只读复查现场；不会仅凭完成记录继续。")
            engine.public.check_pending(spec, ssh_port=ssh_port)
            ui.say(f"现场复查通过：{spec.domain}；IPv4 TCP {spec.public_port}；保留 SSH TCP {ssh_port}。")
            ui.say(f"本机后端：127.0.0.1:{spec.snell_port} / 127.0.0.1:{spec.tls_port}；不新增 IPv6 或 UDP 入口。")
            phase = "public-consent"
            _confirm_public(ui, spec)
            phase, changed = "public", True
            ui.say("重新核查现场并执行最后阶段；失败或再次断线时保留记录，不自动重试。")
            engine.public.enable(spec, ssh_port=ssh_port, confirm_public=True,
                                 confirm_renewal=True, confirm_ssh_reconnected=True, require_pending=True)
            ui.say("接续完成：公网入口、自动续期和开机启动已核对；仍需客户端与重启验收。")
            ui.say("使用 client 或菜单 5 单独确认显示配置；这里不显示密钥，也不会自动重启。")
            return 0
    except (Cancelled, EOFError, KeyboardInterrupt):
        _failure(ui, phase, changed, True)
        return 130
    except Exception:
        _failure(ui, phase, changed, False)
        return 1


def installation_status(*, root=Path("/")):
    """Read local progress only; never create state or execute a system command."""
    def no_commands(_command):
        raise PreparationError("状态读取不执行系统命令。")

    try:
        with Preparation(root, no_commands) as prep:
            if prep.files.info(STATE) is None:
                return {"format": 1, "state": "absent", "current_service_health": "not-checked"}
            return {**prep.status(), "state": "records-found"}
    except Exception:
        return {"format": 1, "state": "unreadable-or-busy", "current_service_health": "not-checked"}


def render_status(report):
    lines = ["安装阶段记录（只读；不代表当前服务健康）"]
    if report["state"] == "absent":
        lines.append("未找到本工具的准备记录；不代表机器上没有其他服务或残留。")
    elif report["state"] == "unreadable-or-busy":
        lines.append("记录无法安全读取或有操作正在进行；不要删除锁或状态目录。")
    else:
        labels = {"completion-recorded": "有完成记录", "needs-inspection": "未确认完成，需要核查", "not-started": "未记录开始"}
        for phase, value in report["phases"].items():
            name = PHASES.get(phase, ("软件启动保护", ""))[0]
            lines.append(name + "：" + labels[value])
        if report.get("key_rotation") == "needs-inspection":
            lines.append("密钥更换：未确认完成；不要重试、删除记录、手动重启入口或导出配置。")
        if report.get("port_change") == "needs-inspection":
            lines.append("端口更换：未确认完成；保留防火墙及状态，不重试、重启或导出配置。")
        if report.get("token_change") == "needs-inspection":
            lines.append("Token 更换：未确认完成；自动续期可能已停用，保留新旧令牌并核查，不重试或删除记录。")
        if report.get("domain_change") == "needs-inspection":
            lines.append("域名更换：未确认完成；保留新旧证书、凭据及日志，核查当前 SNI 和续期状态，不重试或删除记录。")
        if report.get("retired_cleanup") == "needs-inspection":
            lines.append("旧域名清理：未确认完成；文件可能已部分删除、自动续期可能停用，保留现场，不重试或删除标记。")
        if (report["phases"] == PENDING_PUBLIC_PHASES
                and report.get("key_rotation") != "needs-inspection"
                and report.get("port_change") != "needs-inspection"
                and report.get("token_change") != "needs-inspection"
                and report.get("domain_change") != "needs-inspection"
                and report.get("retired_cleanup") != "needs-inspection"):
            lines.append("记录符合受限接续候选阶段；可使用 resume --experimental 先复查现场，不代表已经允许开放。")
    lines.append("报告不含域名、IP、Token、密钥或原始日志；不会自动恢复、签发或删除任何文件。")
    return "\n".join(lines)
