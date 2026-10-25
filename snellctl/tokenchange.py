"""Stage a new Cloudflare credential, test it, then replace the fixed file.

This is not a rollback transaction. Interruptions retain an inspection marker
and attempt to disable renewal, without stopping the working proxy services.
The caller must not run other Certbot instances or root mutations concurrently.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import re

from .activation import _binding, _digest
from .client import read_deployment
from .hostprep import CREDENTIAL, STATE, STAGING, PreparationError
from .installer import Terminal, confirm, real_installation


INTENT = "token-change-intent"
CURRENT = "credential-current"
CANDIDATE = "/etc/snellctl/credentials/cloudflare-main.candidate.ini"
UNCHANGED_RECORDS = ("public-ready", "public-files", "public-firewall-added",
                     "renewal-test-ready", "renewal-enable-ready", "certificate-ready")


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def dry_run_args(spec, credential):
    hook = f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{spec.node}-nginx"
    return [
        "certbot", "renew", "--non-interactive", "--cert-name", spec.domain,
        "--dry-run", "--server", STAGING, "--dns-cloudflare-credentials", credential,
        "--dns-cloudflare-propagation-seconds", "60", "--run-deploy-hooks", "--no-directory-hooks",
        "--deploy-hook", hook, "--config-dir", "/etc/letsencrypt", "--work-dir", "/var/lib/letsencrypt",
        "--logs-dir", "/var/log/letsencrypt", "--max-log-backups", "3", "-v",
    ]


def dry_run_evidence(spec, output):
    lines = {line.strip() for line in output.splitlines()}
    return {
        "fresh_dns_challenge": "dns-01 challenge for " + spec.domain in lines,
        "propagation_wait": "Waiting 60 seconds for DNS changes to propagate" in lines,
        "nginx_reload": "snellctl: nginx reload command succeeded" in lines,
        "simulated_renewal": spec.cert_dir + "/fullchain.pem (success)" in lines,
        "no_cached_authorization_warning": "unable to obtain fresh authorizations" not in output,
        "no_known_txt_cleanup_error": "CloudFlareAPIError deleting TXT record" not in output,
    }


@dataclass(frozen=True)
class TokenPlan:
    domain: str = field(repr=False)
    revision: str = field(repr=False)


class TokenChange:
    def __init__(self, publication):
        self.public = publication
        self.local = publication.local
        self.prep = publication.prep
        self.files = publication.files

    def _snapshot(self, path, mode=None):
        identity = self.files.identity(path)
        content = self.files.read(path, mode=mode)
        if identity != self.files.identity(path):
            raise PreparationError("核查期间文件已变化。")
        return {"identity": identity, "sha256": _digest(content)}

    def _expect(self, path, snapshot, mode=None):
        if self._snapshot(path, mode) != snapshot:
            raise PreparationError("文件被其他操作修改，停止更换。")

    def _credential(self, path):
        snapshot = self._snapshot(path, 0o600)
        content = self.files.read(path, mode=0o600)
        if (not re.fullmatch(rb"dns_cloudflare_api_token = [A-Za-z0-9_-]{20,256}\n", content)
                or _digest(content) != snapshot["sha256"]):
            raise PreparationError("凭据格式或内容异常，未显示内容。")
        return snapshot

    def _idle(self):
        if self.public._fields("certbot.service", "ActiveState,SubState,MainPID,Job") != {
                "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "Job": ""}:
            raise PreparationError("Certbot 正在执行或存在排队任务；不停止签发进程。")

    def _paused(self):
        if self.public._fields("certbot.timer", "ActiveState,SubState,UnitFileState") != {
                "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "disabled"}:
            raise PreparationError("未确认定时续期已暂停。")
        self._idle()

    def _lineage(self, spec):
        # Verify the supported symlinks before snapshotting their archive targets.
        hook = f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{spec.node}-nginx"
        self.prep._verify_certificate(spec, allowed_deploy_hook=hook)
        result = {}
        for name in ("cert", "chain", "fullchain", "privkey"):
            live = spec.cert_dir + "/" + name + ".pem"
            target = self.files.readlink(live)
            match = re.fullmatch(r"\.\./\.\./archive/" + re.escape(spec.domain) + "/" + name + r"[1-9][0-9]*\.pem", target)
            if not match:
                raise PreparationError("证书链接发生变化。")
            path = "/etc/letsencrypt/" + target.removeprefix("../../")
            result[live] = {"target": target, **self._snapshot(path, 0o600 if name == "privkey" else None)}
        path = "/etc/letsencrypt/renewal/" + spec.domain + ".conf"
        result[path] = self._snapshot(path)
        return result

    def _check(self):
        spec, _keys, record = read_deployment(self.prep)
        spec = self.local._version(spec)
        if record["binding"] != _binding(spec):
            raise PreparationError("版本与当前部署不一致。")
        self.public._validate_node(spec, record["ssh_port"])
        self.public._public_health(spec, record)
        self._idle()
        with self.files.directory("/etc/snellctl/credentials", private=True):
            pass
        for path in (CANDIDATE, CREDENTIAL + ".snellctl-new", STATE + "/" + CURRENT + ".json.snellctl-new"):
            if self.files.info(path) is not None:
                raise PreparationError("有未处理的凭据候选文件；不覆盖或删除。")
        credential = self._credential(CREDENTIAL)
        current = None
        if self.prep._exists(CURRENT):
            if self.prep._read_record(CURRENT) != {"format": 1, **credential}:
                raise PreparationError("凭据与最近更换记录不一致。")
            current = self._snapshot(STATE + "/" + CURRENT + ".json", 0o600)
        unchanged = {"lineage": self._lineage(spec), "records": {
            STATE + "/" + name + ".json": self._snapshot(STATE + "/" + name + ".json", 0o600)
            for name in UNCHANGED_RECORDS}}
        revision = _digest(_json_bytes({"public": record, "credential": credential,
                                       "current": current, "unchanged": unchanged}))
        return TokenPlan(spec.domain, revision), spec, record, credential, current, unchanged

    def check(self):
        with self.prep._lock():
            return self._check()[0]

    def _dry_run(self, spec, credential):
        output = self.prep._run(dry_run_args(spec, credential), 600, capture_stderr=True)
        # A zero exit status alone can mean skipped validation or failed hooks.
        if not all(dry_run_evidence(spec, output).values()):
            raise PreparationError("未取得新的 DNS 验证及重载成功证据；不把退出码当作通过。")

    def _expect_records(self, unchanged):
        for path, snapshot in unchanged["records"].items():
            self._expect(path, snapshot, 0o600)

    def _health_paused(self, spec, record, unchanged):
        self._paused()
        self._expect_records(unchanged)
        self.public._public_health(spec, record, renewal_timer=False)
        if self._lineage(spec) != unchanged["lineage"]:
            raise PreparationError("演练改变了正式证书或续期配置，保留现场。")

    def _failure(self, intent):
        uncertain = False
        try:
            if not self.prep._exists(INTENT):
                self.prep._record(INTENT, intent)
        except BaseException:
            uncertain = True
        try:
            self.prep._run(["systemctl", "disable", "--now", "certbot.timer"])
            self._paused()
        except BaseException:
            uncertain = True
        raise PreparationError("Token 更换未完成，不自动回退、删除候选凭据或撤销令牌；节点服务未被本操作停用。" +
                               ("续期停用或记录结果不确定，须立即核查。" if uncertain else
                                "自动续期已暂停并禁用，必须人工核查后恢复。")) from None

    def change(self, plan, token, *, confirm_change):
        if not isinstance(plan, TokenPlan) or confirm_change is not True:
            raise PreparationError("必须确认 Token 更换与 DNS 演练。")
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token):
            raise PreparationError("新 Token 格式无效，未显示内容。")
        content = ("dns_cloudflare_api_token = " + token + "\n").encode("ascii")
        with self.prep._lock():
            current_plan, spec, record, old, current, unchanged = self._check()
            if current_plan != plan or old["sha256"] == _digest(content):
                raise PreparationError("现场已变化或新旧 Token 相同；未更换。")
            intent = {"format": 1, "binding": record["binding"], "before_sha256": old["sha256"],
                      "after_sha256": _digest(content)}
            try:
                self.prep._record(INTENT, intent)
                marker = self._snapshot(STATE + "/" + INTENT + ".json", 0o600)
                # Disable persists across reboot; never interrupt an active ACME job.
                self.prep._run(["systemctl", "disable", "--now", "certbot.timer"])
                self._health_paused(spec, record, unchanged)
                self.files.write_new(CANDIDATE, content, 0o600)
                candidate = self._credential(CANDIDATE)
                if candidate["sha256"] != _digest(content):
                    raise PreparationError("候选凭据被修改。")
                self._dry_run(spec, CANDIDATE)
                self._health_paused(spec, record, unchanged)
                self._expect(CANDIDATE, candidate, 0o600)
                self._expect(CREDENTIAL, old, 0o600)
                self.files.replace_owned(CREDENTIAL, content, identity=old["identity"], digest=old["sha256"], mode=0o600)
                saved = self._credential(CREDENTIAL)
                if saved["sha256"] != _digest(content):
                    raise PreparationError("正式凭据写入结果不符。")
                # Re-test the unchanged renewal path, not just the candidate override.
                self._dry_run(spec, CREDENTIAL)
                self._health_paused(spec, record, unchanged)
                self._expect(CREDENTIAL, saved, 0o600)
                self._expect(CANDIDATE, candidate, 0o600)
                value = {"format": 1, **saved}
                path = STATE + "/" + CURRENT + ".json"
                if current is None:
                    self.prep._record(CURRENT, value)
                else:
                    self.files.replace_owned(path, _json_bytes(value), identity=current["identity"],
                                             digest=current["sha256"], mode=0o600)
                committed = self._snapshot(path, 0o600)
                if self.prep._read_record(CURRENT) != value:
                    raise PreparationError("当前凭据记录不符。")
                self.files.unlink_owned(CANDIDATE, candidate["identity"])
                self.prep._run(["systemctl", "enable", "--now", "certbot.timer"])
                self.public._public_health(spec, record)
                self._expect_records(unchanged)
                self._expect(CREDENTIAL, saved, 0o600)
                self._expect(path, committed, 0o600)
                self._expect(STATE + "/" + INTENT + ".json", marker, 0o600)
                self.files.unlink_owned(STATE + "/" + INTENT + ".json", marker["identity"])
            except BaseException:
                self._failure(intent)
        return "token-changed-renewal-tested"


@contextmanager
def real_token_change():
    with real_installation() as installation:
        yield TokenChange(installation.public)


def run_token_change(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("Token 更换仅允许交互终端；不接受明文参数、管道或自动确认。")
        return 2
    attempted = False
    token = None
    try:
        ui.say("实验版 CF Token 更换：仅限本工具完整部署的 main 节点，尚待实机验收。")
        with factory() as engine:
            ui.say("正在只读核对配置、凭据权限、证书、服务及防火墙。")
            plan = engine.check()
            ui.say(f"证书域名：{plan.domain}；仅更换本机 Cloudflare API Token，不改节点密钥、端口或域名。")
            ui.say("请先创建同一区域 DNS 编辑权限的新令牌；暂不撤销旧令牌，不与其他 Certbot/root 操作并行。")
            ui.say("会暂停定时续期，执行两次 DNS 演练和 Nginx 重载；会访问 Cloudflare/测试 CA 并增删验证 TXT。")
            ui.say("正式证书不会因演练替换。成功后恢复自动续期，届时可能执行到期续签；失败保留现场，自动续期可能保持停用。")
            if not confirm(ui, "确认更换 CF API Token 并执行上述验证？"):
                ui.say("已取消；未读取新 Token 或修改配置。")
                return 130
            if not ui.interactive():
                raise PreparationError("终端状态改变。")
            token = ui.secret()
            if not ui.interactive():
                raise PreparationError("终端状态改变。")
            ui.say("开始验证，DNS 传播每次至少等待 60 秒；请保持连接，不重复执行。")
            attempted = True
            result = engine.change(plan, token, confirm_change=True)
            if result != "token-changed-renewal-tested":
                raise PreparationError("更换结果未明确成功。")
            ui.say("Token 已更换，两次 DNS 演练及本机检查通过，自动续期已恢复；不需要更新 Surge。")
            ui.say("确认新令牌及本机状态后，仅在旧令牌没有其他用途时到 Cloudflare 撤销旧令牌；本工具不会代为撤销。")
            ui.say("节点可用不等于续期正常；本次也不代表真实到期证书轮换已发生。")
            return 0
    except (Exception, KeyboardInterrupt) as exc:
        ui.say("更换未确认完成：自动续期可能已停用，节点服务未被本操作停用。保留新旧令牌和现场，查看 install-status；不要重试、删除标记或直接重启。" if attempted
               else "已停止：未执行 Token 更换；核查完成记录及当前状态，原始错误未显示。")
        ui.say("snellctl-diagnostic: " + json.dumps({"format": 1, "operation": "token-change",
                                                    "host_changes_attempted": attempted, "result": "stopped"}))
        return 130 if isinstance(exc, (EOFError, KeyboardInterrupt)) else 1
    finally:
        token = None
