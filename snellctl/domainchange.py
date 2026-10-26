"""One-shot domain/credential replacement; retain the retired lineage, never roll back.

The old node remains configured during issuance. Once switching starts, failures
retain the intent and pause renewal. This is not a crash-recovery transaction.
"""

from copy import deepcopy
from dataclasses import dataclass, field, replace
import json
import re
import time

from .activation import _binding, _digest
from .client import _read_deployment_snapshot
from .deployment import NodeSpec, render_files
from .hostprep import DOMAIN_CURRENT, PRODUCTION, STATE, STAGING, Command, PreparationError, domain_credential
from .installer import Terminal, confirm
from .publish import RENEW_DROPIN, renewal_dropin
from .tokenchange import CURRENT, _json_bytes, dry_run_args, real_token_change
from .tokendiag import summarize


INTENT = "domain-change-intent"
RECORDS = ("public-files", "public-ready", "renewal-test-ready", "renewal-enable-ready", "certificate-ready")


def log_directory(spec):
    return STATE + "/domain-change-" + _digest(spec.domain.encode())


def certificate_paths(spec):
    return (spec.cert_dir, "/etc/letsencrypt/archive/" + spec.domain,
            "/etc/letsencrypt/renewal/" + spec.domain + ".conf")


def issue_args(spec, logs, *, production):
    args = ["certbot", "certonly", "--non-interactive", "--agree-tos",
            "--register-unsafely-without-email", "--no-directory-hooks",
            "--dns-cloudflare", "--dns-cloudflare-credentials", domain_credential(spec),
            "--dns-cloudflare-propagation-seconds", "60", "--key-type", "ecdsa",
            "--elliptic-curve", "secp256r1", "--cert-name", spec.domain, "-d", spec.domain,
            "--server", PRODUCTION if production else STAGING,
            "--config-dir", "/etc/letsencrypt", "--work-dir", "/var/lib/letsencrypt",
            "--logs-dir", logs, "--max-log-backups", "3", "-v"]
    if not production:
        args.append("--dry-run")
    return args


@dataclass(frozen=True)
class DomainPlan:
    old_domain: str = field(repr=False)
    new_domain: str = field(repr=False)
    revision: str = field(repr=False)


class DomainChange:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens = tokens
        self.prep, self.files, self.public, self.local = tokens.prep, tokens.files, tokens.public, tokens.local
        self.progress = progress
        self.phase = "not-started"

    def _phase(self, name):
        self.phase = name
        self.progress(name)

    def _absent(self, paths):
        if any(self.files.info(path) is not None for path in paths):
            raise PreparationError("发现已有目标、临时文件或其他变更；不接管、不删除。")

    def _other_changes_absent(self):
        self._absent([STATE + "/" + name + ".json" for name in
                      ("key-rotation-intent", "port-change-intent", "token-change-intent")])

    def _wait_tls(self, spec, node):
        # Reload is asynchronous. Retry only read-only TLS probes, never issuance
        # or configuration writes; ownership/credential errors remain immediate.
        deadline = time.monotonic() + self.local.readiness_timeout
        hook = f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{spec.node}-nginx"
        while True:
            self._other_changes_absent()
            self.tokens._paused()
            self.local._verify_owned(spec, node)
            certificate = self.prep._verify_certificate(spec, allowed_deploy_hook=hook)
            try:
                for port in (spec.tls_port, spec.public_port):
                    if self.local.probe(spec, port, certificate) is not True:
                        raise PreparationError("新域名 TLS 尚未确认生效。")
                return
            except PreparationError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)

    def _check(self, domain):
        NodeSpec(domain)
        self._phase("current-deployment-check")
        _plan, old, record, credential, current, unchanged = self.tokens._check()
        if domain == old.domain:
            raise PreparationError("新旧域名相同；未进行更换。")
        new = replace(old, domain=domain)
        self.public._validate_node(new, record["ssh_port"])
        self._absent((*certificate_paths(new), domain_credential(new), log_directory(new)))
        paths = [old.nginx_conf, RENEW_DROPIN,
                 f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{old.node}-nginx",
                 *(STATE + "/" + name + ".json" for name in (*RECORDS, DOMAIN_CURRENT, CURRENT))]
        self._absent([p + ".snellctl-new" for p in paths])
        extra = {RENEW_DROPIN: self.tokens._snapshot(RENEW_DROPIN, 0o644)}
        for name in (DOMAIN_CURRENT, CURRENT):
            path = STATE + "/" + name + ".json"
            extra[path] = self.tokens._snapshot(path, 0o600) if self.prep._exists(name) else None
        revision = _digest(_json_bytes({"new": _binding(new), "record": record, "credential": credential,
                                       "current": current, "unchanged": unchanged, "extra": extra}))
        return DomainPlan(old.domain, new.domain, revision), old, new, record, credential, unchanged, extra

    def check(self, domain):
        with self.prep._lock():
            return self._check(domain)[0]

    def _expect_extra(self, extra):
        for path, snapshot in extra.items():
            if snapshot is None:
                self._absent([path])
            else:
                self.tokens._expect(path, snapshot, 0o644 if path == RENEW_DROPIN else 0o600)

    def _command(self, spec, args, logs, report, key, kind):
        self.files.private_directory_new(logs)
        reply = self.prep.runner(Command(tuple(args), 600, capture_stderr=True))
        value = summarize(spec, reply)
        if kind != "renew":
            lines = {line.strip() for line in reply.output.splitlines()}
            value["evidence"] = {
                "fresh_dns_challenge": "dns-01 challenge for " + spec.domain in lines,
                "propagation_wait": "Waiting 60 seconds for DNS changes to propagate" in lines,
                "dry_run_success": "The dry run was successful." in lines,
                "no_known_txt_cleanup_error": "CloudFlareAPIError deleting TXT record" not in reply.output,
            }
        report[key] = value
        self.files.write_new(logs + "/command-output.txt", reply.output.encode(), 0o600)
        if (value["exit_code"] != 0 or value["execution_uncertain"] or any(value["signals"].values())
                or value["error_types_seen"] or value["errno_seen"]
                or (kind in {"dry-run", "renew"} and not all(value["evidence"].values()))
                or (kind == "issue" and not value["evidence"]["no_known_txt_cleanup_error"])):
            raise PreparationError("证书操作未完整通过，详见脱敏阶段报告；不自动重试。")

    def _replace_record(self, name, value, snapshot):
        path = STATE + "/" + name + ".json"
        if snapshot is None:
            self.prep._record(name, value)
        else:
            self.files.replace_owned(path, _json_bytes(value), identity=snapshot["identity"],
                                     digest=snapshot["sha256"], mode=0o600)
        if self.prep._read_record(name) != value:
            raise PreparationError("更新后的归属记录不符。")
        return self.tokens._snapshot(path, 0o600)

    def change(self, plan, token, *, confirm_change, agree_tos, confirm_issue, confirm_ssh_reconnected):
        if not isinstance(plan, DomainPlan) or any(value is not True for value in (
                confirm_change, agree_tos, confirm_issue, confirm_ssh_reconnected)):
            raise PreparationError("需要明确确认条款、正式签发、域名切换及独立 SSH 连接。")
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token):
            raise PreparationError("新区域令牌格式不符；未显示内容。")
        content = ("dns_cloudflare_api_token = " + token + "\n").encode("ascii")
        with self.prep._lock():
            checked, old, new, record, old_credential, unchanged, extra = self._check(plan.new_domain)
            if plan != checked:
                raise PreparationError("确认期间现场发生变化；未更换域名。")
            old_path, new_path = self.prep.credential_path(old), domain_credential(new)
            logs = log_directory(new)
            intent = {"format": 1, "before_binding": _binding(old), "after_binding": _binding(new)}
            marker = None
            switched = False
            started = time.monotonic()
            report = {"format": 1, "operation": "domain-change", "result": "stopped",
                      "host_changes_attempted": True, "switch_attempted": False, "report_saved": False,
                      "old_renewal_restored_verified": False, "renewal_restored_verified": False,
                      "renewal_paused_verified_after": False, "automatic_retry": False}

            def old_unchanged():
                self.tokens._expect(old_path, old_credential, 0o600)
                if self.tokens._lineage(old, credential_path=old_path) != unchanged["lineage"]:
                    raise PreparationError("旧证书或续期文件发生变化。")

            def old_health():
                self._other_changes_absent()
                self.tokens._health_paused(old, record, unchanged)
                self._expect_extra(extra)
                old_unchanged()

            try:
                self._phase("intent-record")
                self.prep._record(INTENT, intent)
                marker = self.tokens._snapshot(STATE + "/" + INTENT + ".json", 0o600)
                self.files.private_directory_new(logs)
                self._phase("renewal-pause")
                self.prep._run(["systemctl", "disable", "--now", "certbot.timer"])
                old_health()
                self._phase("new-credential")
                self.files.write_new(new_path, content, 0o600)
                candidate = self.tokens._credential(new_path)
                if candidate["sha256"] != _digest(content):
                    raise PreparationError("新凭据保存结果不符。")
                self._phase("new-domain-dry-run")
                path = logs + "/dns-test"
                self._command(new, issue_args(new, path, production=False), path, report, "dns_test", "dry-run")
                old_health()
                self.tokens._expect(new_path, candidate, 0o600)
                self._absent(certificate_paths(new))
                self._phase("new-certificate-issue")
                path = logs + "/certificate"
                self._command(new, issue_args(new, path, production=True), path, report, "certificate", "issue")
                new_lineage = self.tokens._lineage(new, credential_path=new_path)
                old_health()
                self.tokens._expect(new_path, candidate, 0o600)
                self.tokens._expect(STATE + "/" + INTENT + ".json", marker, 0o600)

                self._phase("configuration-switch")
                switched = report["switch_attempted"] = True
                updated = {name: deepcopy(self.prep._read_record(name)) for name in RECORDS}
                node = updated["public-files"]
                node["binding"] = _binding(new)
                hook = f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{new.node}-nginx"
                for item in render_files(new, _read_deployment_snapshot(self.prep)[1]):
                    path, mode, data = item.target.path, item.target.mode, item.content.encode()
                    previous = node["files"][path]
                    if _digest(data) == previous["sha256"]:
                        continue
                    if path not in {old.nginx_conf, hook}:
                        raise PreparationError("域名更换不应改变节点密钥、端口或服务配置。")
                    self.files.replace_owned(path, data, identity=previous["identity"], digest=previous["sha256"], mode=mode)
                    node["files"][path] = {"identity": self.files.identity(path), "mode": mode, "sha256": _digest(data)}
                previous = extra[RENEW_DROPIN]
                self.files.replace_owned(RENEW_DROPIN, renewal_dropin(new), identity=previous["identity"],
                                         digest=previous["sha256"], mode=0o644)
                current_records = {}
                current_records[DOMAIN_CURRENT] = self._replace_record(DOMAIN_CURRENT,
                    {"format": 1, "domain_sha256": _digest(new.domain.encode())}, extra[STATE + "/" + DOMAIN_CURRENT + ".json"])
                current_records[CURRENT] = self._replace_record(CURRENT, {"format": 1, **candidate},
                                                               extra[STATE + "/" + CURRENT + ".json"])
                updated["public-ready"].update(binding=_binding(new), node=node)
                updated["renewal-test-ready"] = {"binding": _binding(new)}
                updated["renewal-enable-ready"] = {"binding": _binding(new), "identity": self.files.identity(RENEW_DROPIN)}
                updated["certificate-ready"] = {"domain_sha256": _digest(new.domain.encode())}
                self.prep._run(["nginx", "-t"])
                self.prep._run(["systemctl", "daemon-reload"])
                self.prep._run(["systemd-analyze", "verify", "certbot.service", "certbot.timer"])
                if self.public._fields("certbot.service", "NeedDaemonReload") != {"NeedDaemonReload": "no"}:
                    raise PreparationError("续期服务配置未确认重新加载。")
                self.prep._run(["systemctl", "reload", "nginx.service"])

                def new_health(*, timer=False):
                    self._other_changes_absent()
                    if not timer:
                        self.tokens._paused()
                    self.public._public_health(new, updated["public-ready"],
                                              renewal_record=updated["renewal-enable-ready"], renewal_timer=timer)
                    self.tokens._expect(new_path, candidate, 0o600)
                    for name, snapshot in current_records.items():
                        self.tokens._expect(STATE + "/" + name + ".json", snapshot, 0o600)
                    old_unchanged()

                self._phase("new-tls-check")
                self._wait_tls(new, node)
                new_health()
                self._phase("new-renewal-test")
                path = logs + "/renewal-test"
                args = dry_run_args(new, new_path)
                args[args.index("--logs-dir") + 1] = path
                args.append("--no-random-sleep-on-renew")
                self._command(new, args, path, report, "renewal_test", "renew")
                new_health()
                if self.tokens._lineage(new) != new_lineage:
                    raise PreparationError("续期演练改变了新正式证书或配置。")
                self.tokens._expect_records({"records": {p: s for p, s in unchanged["records"].items()
                    if p != STATE + "/" + DOMAIN_CURRENT + ".json"}})
                self._phase("current-records")
                for name in RECORDS:
                    current_records[name] = self._replace_record(name, updated[name], unchanged["records"][STATE + "/" + name + ".json"])
                new_health()
                spec, _keys, checked_record = _read_deployment_snapshot(self.prep)
                if spec.domain != new.domain or checked_record != updated["public-ready"]:
                    raise PreparationError("切换后的运行配置与记录不一致。")
                self._phase("renewal-enable")
                self.prep._run(["systemctl", "enable", "--now", "certbot.timer"])
                self._phase("enabled-postcheck")
                new_health(timer=True)
                # The firewall ownership record is not one of the updated records.
                path = STATE + "/public-firewall-added.json"
                self.tokens._expect(path, unchanged["records"][path], 0o600)
                self.tokens._expect(STATE + "/" + INTENT + ".json", marker, 0o600)
                self._phase("intent-cleanup")
                self.files.unlink_owned(STATE + "/" + INTENT + ".json", marker["identity"])
                report["renewal_restored_verified"] = True
                report["result"] = "domain-changed-external-test-required"
            except BaseException:
                report["failure_phase"] = self.phase
                try:
                    if not self.prep._exists(INTENT):
                        self.prep._record(INTENT, intent)
                    self.prep._run(["systemctl", "disable", "--now", "certbot.timer"])
                    self.tokens._paused()
                    report["renewal_paused_verified_after"] = True
                    # Before switching, restore the old schedule only after the
                    # original credential, lineage, configuration and rules match.
                    if not switched and marker is not None:
                        self.tokens._expect(STATE + "/" + INTENT + ".json", marker, 0o600)
                        old_health()
                        self.prep._run(["systemctl", "enable", "--now", "certbot.timer"])
                        self.public._public_health(old, record)
                        self.tokens._expect_records(unchanged)
                        self._expect_extra(extra)
                        self.tokens._expect(old_path, old_credential, 0o600)
                        report["old_renewal_restored_verified"] = True
                        report["renewal_paused_verified_after"] = False
                except BaseException:
                    report["renewal_paused_verified_after"] = False
                    try:
                        self.prep._run(["systemctl", "disable", "--now", "certbot.timer"])
                        self.tokens._paused()
                        report["renewal_paused_verified_after"] = True
                    except BaseException:
                        pass
            finally:
                report["elapsed_seconds"] = int(time.monotonic() - started)
                try:
                    self.files.write_new(logs + "/report.json", _json_bytes({**report, "report_saved": True}), 0o600)
                    report["report_saved"] = True
                except BaseException:
                    pass
            return report


def run_domain_change(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("域名更换仅允许交互终端，不接受 Token 参数、管道或自动确认。")
        return 2
    engine = None
    token = None
    attempted = False
    try:
        ui.say("实验版域名更换：限完整受管 main 节点，尚待实机验收；失败不自动回退或重试。")
        domain = ui.ask("新的完整小写域名（留空取消，不含 https://）：").strip()
        if not domain:
            return 130
        with factory() as tokens:
            engine = DomainChange(tokens, lambda phase: ui.say("更换阶段：" + phase))
            plan = engine.check(domain)
            ui.say(f"域名：{plan.old_domain} -> {plan.new_domain}；仅换证书、凭据及续期目标，不改节点密钥、端口或 SSH/UFW。")
            ui.say("先验证并签发新证书，再切换 Nginx 和续期任务；新 SNI 生效后旧 SNI 不再受理新的握手，需更新 Surge。")
            ui.say("保留旧证书及有效凭据，不自动撤销令牌或删除 DNS；切换成功后受管定时任务只续期新证书。")
            ui.say("会暂停续期、访问 Cloudflare/CA、增删 TXT、重载 Nginx。失败保留记录，续期可能停用，须及时核查。")
            ui.say("请阅读 Let's Encrypt 现行条款：https://letsencrypt.org/repository/；正式签发使用 CA 配额并公开证书域名。")
            for prompt in ("有新域名管理授权并同意现行 CA 条款？", "DNS 演练通过后，允许正式签发新域名证书？",
                           "保留本会话，已从另一终端新建 SSH 并确认登录成功？",
                           "确认切换域名及续期目标，并在成功后修改客户端 SNI？"):
                if not confirm(ui, prompt):
                    ui.say("已取消；未读取新令牌、签发证书或更换配置。")
                    return 130
            if not ui.interactive():
                raise PreparationError("终端状态改变。")
            ui.say("输入新域名所在区域的 DNS 编辑令牌；不要输入现用域名的旧区域令牌。")
            token = ui.secret()
            if not ui.interactive():
                raise PreparationError("终端状态改变。")
            ui.say("开始执行；每次 DNS 传播等待 60 秒，单次证书命令最长 10 分钟。保持连接，不并行运行 Certbot。")
            attempted = True
            report = engine.change(plan, token, confirm_change=True, agree_tos=True,
                                   confirm_issue=True, confirm_ssh_reconnected=True)
            ui.say(json.dumps(report, indent=2))
            if report["result"] == "domain-changed-external-test-required":
                ui.say(f"服务端切换及续期演练通过。Surge 的 shadow-tls-sni 改为 {plan.new_domain}；其余字段不变。")
                ui.say("仍需客户端延迟和实际使用验收；旧证书、凭据及 root-only 日志保留，暂不清理。")
                return 0
            ui.say("更换未确认完成；保留新旧域名、令牌及日志，不重试、删除标记或重启。只分享 JSON，不分享原始日志。")
            return 1
    except (Exception, KeyboardInterrupt):
        ui.say(json.dumps({"format": 1, "operation": "domain-change", "result": "stopped",
                           "phase": engine.phase if engine else "parameters", "host_changes_attempted": attempted}))
        ui.say("未确认完成；不显示原始异常。若已开始执行，保留现场并核查续期状态，不重试。")
        return 1
    finally:
        token = None
