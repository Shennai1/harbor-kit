"""Read-only scope review for a completed managed node, never deletion authority."""

from contextlib import contextmanager
import json
from pathlib import PurePosixPath
import re

from .activation import BINARIES
from .deployment import file_targets
from .domaininventory import CREDENTIALS, ROOTS, Inventory
from .hostprep import PreparationError
from .installer import Terminal, confirm
from .publish import RENEW_DROPIN
from .renewalprobe import read_only_command
from .retiredplan import PARTS, RetiredPlan, ScopeBlocked, _require
from .tokenchange import RenewalStateMismatch, real_token_change


SUCCESS = "uninstall-scope-checked-no-changes"
LIMITATIONS = (
    "只核对本工具完整受管 main 的固定范围；不接管手工、第三方、损坏或部分安装。",
    "归属记录、内容摘要和模板一致不证明全机独占；没有搜索全部服务、任务、容器或外部引用。",
    "会读取现用节点配置、CF 凭据及证书材料作内存核验；不输出秘密、指纹、域名或完整路径。",
    "其他节点、程序版本、证书、凭据、站点或额外续期钩子需要另行核查，不自动认领或清理。",
    "本机健康及 SSH 监听核查不证明公网节点、独立 SSH 新连接或恢复控制台可用。",
    "复用协作锁并复核现场，不是全系统原子快照，不能阻止外部 root 或 Certbot 并发修改。",
    "不执行 Certbot、下载、DNS 操作、暂停续期、服务变更、UFW 写入、软件包操作或删除。",
    "状态查询使用临时输出，本机 HTTPS 可能产生常规服务日志；不保存新的报告、意图或归属记录。",
    "报告没有执行能力或删除授权；未来卸载仍需独立确认停机、资源归属及删除范围，并重新核查。",
)


class UninstallPlan:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens, self.prep, self.files = tokens, tokens.prep, tokens.files
        self.progress, self.phase = progress, "not-started"

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    @contextmanager
    def _commands(self):
        original = self.prep.runner
        def guarded(command):
            if not read_only_command(command.argv):
                raise PreparationError("卸载预检查只允许已有的只读健康查询。")
            return original(command)
        self.prep.runner = guarded
        try:
            yield
        finally:
            self.prep.runner = original

    def _directory(self, inventory, path, expected, reason, *, private=False):
        names, state = inventory.scan(path, private=private)
        _require(state == "observed" and set(names) == set(expected), reason)

    def _layout(self, inventory, spec, credential):
        self._directory(inventory, "/etc/snellctl", {"nodes", "credentials"}, "additional-managed-root-entry", private=True)
        self._directory(inventory, "/etc/snellctl/nodes", {spec.node}, "additional-node", private=True)
        self._directory(inventory, spec.node_dir, {"snell.conf", "shadowtls.json"}, "additional-node-file", private=True)
        self._directory(inventory, CREDENTIALS, {PurePosixPath(credential).name}, "additional-credential", private=True)

        # Derive version directories from the supported binary paths, not user examples.
        programs = [PurePosixPath(path) for path in BINARIES]
        self._directory(inventory, "/opt/snellctl", {path.parent.parent.name for path in programs}, "additional-program")
        for path in programs:
            self._directory(inventory, str(path.parent.parent), {path.parent.name}, "additional-program-version")
            self._directory(inventory, str(path.parent), {path.name}, "additional-program-file")

        expected = {**{path: 0o755 for path in BINARIES},
                    **{target.path: target.mode for target in file_targets(spec)}, RENEW_DROPIN: 0o644}
        for path, mode in expected.items():
            _require(inventory.metadata(path, "file", private=mode == 0o600) == "observed", "managed-file-metadata")
        _require(inventory.metadata(credential, "file", private=True) == "observed", "credential-metadata")
        self._directory(inventory, str(PurePosixPath(RENEW_DROPIN).parent), {PurePosixPath(RENEW_DROPIN).name},
                        "additional-renewal-override")

    def _certificate(self, inventory, spec, credential):
        for label in ("archive", "renewal"):
            name = spec.domain + (".conf" if label == "renewal" else "")
            self._directory(inventory, ROOTS[label], {name}, "additional-certificate-or-renewal")
        names, state = inventory.scan(ROOTS["live"])
        _require(state == "observed" and set(names) in ({spec.domain}, {spec.domain, "README"}),
                 "additional-live-certificate")
        if "README" in names:
            _require(inventory.metadata(ROOTS["live"] + "/README", "file") == "observed", "certificate-readme-metadata")

        # Reuse the strict Certbot path parser and bounded shared-reference checks.
        scope = RetiredPlan(self.tokens)
        params = scope._renewal(inventory, spec.domain)
        _require(params.get("dns_cloudflare_credentials") == credential, "current-credential-reference")
        scope._references(inventory, spec, credential)
        _require(inventory.links(spec.domain) == "structure-checked-only", "certificate-links")
        names, state = inventory.scan(spec.cert_dir)
        expected = {part + ".pem" for part in PARTS}
        _require(state == "observed" and set(names) in (expected, expected | {"README"}), "certificate-live-entries")
        if "README" in names:
            _require(inventory.metadata(spec.cert_dir + "/README", "file") == "observed", "certificate-readme-metadata")
        archive = ROOTS["archive"] + "/" + spec.domain
        names, state = inventory.scan(archive)
        _require(state == "observed" and bool(names), "certificate-archive-entries")
        generations = {}
        for name in names:
            match = re.fullmatch(r"(cert|chain|fullchain|privkey)([1-9][0-9]{0,9})\.pem", name)
            _require(match is not None, "certificate-archive-entries")
            _require(inventory.metadata(archive + "/" + name, "file", private=match[1] == "privkey") == "observed",
                     "certificate-archive-metadata")
            generations.setdefault(match[2], set()).add(match[1])
        _require(all(parts == set(PARTS) for parts in generations.values()), "certificate-incomplete-generation")
        target = self.files.readlink(spec.cert_dir + "/cert.pem")
        cert = ROOTS["archive"] + "/" + spec.domain + "/" + PurePosixPath(target).name
        output = self.prep._run(["openssl", "x509", "-in", cert, "-noout", "-ext", "subjectAltName"])
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        _require(lines in (["X509v3 Subject Alternative Name:", "DNS:" + spec.domain],
                          ["X509v3 Subject Alternative Name: critical", "DNS:" + spec.domain]),
                 "certificate-not-single-domain")
        return len(generations)

    def _firewall(self, spec, record):
        rules, _hashes, running = self.tokens.public._firewall(record["ssh_port"])
        candidates = [rule for rule in rules if rule.port == spec.public_port or rule.comment == "snellctl-" + spec.node]
        _require(len(candidates) == 1 and candidates[0].action == "allow"
                 and candidates[0].port == spec.public_port and candidates[0].source in {"any", "0.0.0.0/0"}
                 and candidates[0].comment == "snellctl-" + spec.node, "entry-rule-not-unique-recorded-ipv4")
        # UFW can display IPv4 any as "any"; require the recorded IPv4 kernel entry too.
        entry = ("-A", "ufw-user-input", "-p", "tcp", "--dport", str(spec.public_port), "-j", "ACCEPT")
        _require(running.count(entry) == 1, "entry-rule-not-unique-recorded-ipv4")

    def inspect_locked(self):
        """Internal snapshot shared with the separately confirmed executor."""
        self._phase("current-deployment-check")
        before = self.tokens._check()
        spec = before[1]
        credential = self.prep.credential_path(spec)
        inventory = Inventory(self.files)
        self._phase("managed-layout-check")
        self._layout(inventory, spec, credential)
        self._phase("certificate-and-shared-scope")
        generations = self._certificate(inventory, spec, credential)
        self._phase("entry-rule-check")
        self._firewall(spec, before[2])
        self._phase("unchanged-health-check")
        _require(self.tokens._check()[0] == before[0], "current-deployment-changed")
        inventory.recheck()
        return before, inventory, generations

    def check(self):
        report = {"format": 1, "operation": "uninstall-plan", "result": "blocked-preserve-all",
                  "scope": "managed-main", "uninstall_implemented": True, "uninstall_authorized": False,
                  "host_changes_attempted": False, "all_assets_preserved": True, "report_saved": False,
                  "current_service_health": "not-confirmed", "global_reference_check": "not-performed",
                  "limitations": list(LIMITATIONS)}
        try:
            self._phase("preparation-lock")
            with self._commands(), self.prep._lock():
                _before, _inventory, generations = self.inspect_locked()
                report.update(result=SUCCESS, current_service_health="local-checks-passed",
                              managed_configuration="records-content-and-live-checks-passed",
                              review_counts={"node_configurations": 2, "dedicated_services": 2, "nginx_sites": 1,
                                             "deploy_hooks": 1, "renewal_overrides": 1, "versioned_programs": len(BINARIES),
                                             "certificate_lineages": 1, "archive_generations": generations,
                                             "local_credentials": 1, "recorded_ipv4_entry_rules": 1},
                              review_only=["managed-node-files-and-services", "current-certificate-and-credential",
                                           "nginx-site-and-renewal-integration", "versioned-programs", "single-recorded-ipv4-entry-rule"],
                              preserve=["ssh", "ufw-and-all-other-rules", "packages-and-vendor-units", "kernel-and-apt-sources",
                                        "acme-account", "cloudflare-tokens-and-dns", "preparation-records-and-history",
                                        "unrelated-resources"],
                              required_before_uninstall=["separate-uninstall-entry-and-live-acceptance",
                                  "operator-confirms-no-other-consumers", "independent-ssh-and-console-verification",
                                  "explicit-node-outage-and-deletion-consent", "nginx-and-renewal-final-state-decision",
                                  "fresh-live-recheck"])
        except ScopeBlocked as error:
            report.update(failure_phase=self.phase, reason=error.code)
        except RenewalStateMismatch as error:
            report.update(failure_phase=self.phase, reason="renewal-unit-state-mismatch", unit_state_check=error.evidence)
        except (KeyboardInterrupt, EOFError):
            report.update(failure_phase=self.phase, reason="interrupted")
        except Exception:
            report.update(failure_phase=self.phase, reason="unreadable-busy-unsupported-or-check-failed")
        return report


def run_uninstall_plan(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("卸载范围预检查需要交互终端；不接受自动确认或目标参数。")
        return 2
    try:
        ui.say("只读卸载范围预检查：仅限本工具完整受管 main，本入口不能执行卸载。")
        ui.say("从已验证配置读取现用域名和端口；不输入 Token，不显示密钥，不安装快捷指令。")
        ui.say("会读取现用受限配置作内存核验并检查本机 TLS；不暂停续期、不改服务或 SSH/UFW，不删除文件。")
        ui.say("请勿同时运行 Certbot 或其他管理操作；本次确认不是停机或删除授权。")
        if not confirm(ui, "确认只核查卸载范围，保留全部资源及运行状态？"):
            ui.say("已取消，未执行核查或更改。")
            return 130
        if not ui.interactive():
            return 2
        with factory() as tokens:
            report = UninstallPlan(tokens, lambda phase: ui.say("核查阶段：" + phase)).check()
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        ui.say("本次没有卸载或授权删除；现用节点、证书和续期保持不变。只分享最后 JSON。")
        return 0 if report["result"] == SUCCESS else 1
    except (KeyboardInterrupt, EOFError):
        ui.say("预检查已中断，未执行配置变更或删除。")
        return 130
    except Exception:
        ui.say("预检查未完成，输入或环境未核对；原始异常未显示，没有执行配置变更或删除。")
        return 1
