"""Read-only, interactive scope check for one explicitly selected retired domain.

Old releases did not retain a complete retired-resource ownership manifest.
Historical hints must never become deletion authority. No apply entry exists.
"""

import configparser
import hashlib
import json
import re

from .client import read_deployment
from .deployment import NodeSpec
from .domainchange import log_directory
from .domaininventory import BASE, ROOTS, Inventory, collect_locked
from .hostprep import CREDENTIAL, PRODUCTION, STATE, PreparationError, domain_credential
from .installer import Terminal, confirm
from .tokenchange import real_token_change


PARTS = ("cert", "chain", "fullchain", "privkey")
LIMITATIONS = (
    "只核对受管 main、固定 Nginx/Certbot 范围及用户选择的证书组，不是全机引用搜索。",
    "历史域名摘要或成功报告仅提供关联线索，不证明当前旧文件的完整历史归属。",
    "读取现用受管秘密作内存校验，不输出内容或指纹；旧 Token 和旧私钥只检查元数据。",
    "本机 TLS 检查不证明客户端公网可用；其他进程仍可能改变现场，删除前必须重新核对。",
    "不执行 Certbot、DNS 操作、续期暂停、服务重载、软件包操作或删除，不生成可执行删除命令。",
    "系统检查使用临时命令输出，本机 HTTPS 请求可能产生常规服务日志；不保存新的计划或归属记录。",
)


class ScopeBlocked(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code):
    if not condition:
        raise ScopeBlocked(code)


class RetiredPlan:
    def __init__(self, tokens, progress=lambda phase: None):
        self.tokens = tokens
        self.prep, self.files = tokens.prep, tokens.files
        self.progress = progress
        self.phase = "not-started"

    def _phase(self, phase):
        self.phase = phase
        self.progress(phase)

    def _history(self, inventory, target, current):
        digest_path = STATE + "/dns-test-ready.json"
        inventory.info(digest_path)
        initial = (self.prep._read_record("dns-test-ready") == {
            "domain_sha256": hashlib.sha256(target.domain.encode()).hexdigest()})

        def successful(spec):
            directory = log_directory(spec)
            path = directory + "/report.json"
            inventory.info(directory)
            if inventory.info(path) is None:
                return False
            with self.files.directory(directory, private=True):
                value = json.loads(self.files.read(path, mode=0o600))
            return (isinstance(value, dict) and type(value.get("format")) is int and value["format"] == 1
                    and value.get("operation") == "domain-change"
                    and value.get("result") == "domain-changed-external-test-required"
                    and value.get("renewal_restored_verified") is True)

        return {"initial_domain_digest_match": initial,
                "target_domain_change_success_record": successful(target),
                "current_domain_change_success_record": successful(current),
                "historical_file_ownership_proven": False}

    def _renewal(self, inventory, name):
        path = ROOTS["renewal"] + "/" + name + ".conf"
        _require(inventory.metadata(path, "file") == "observed", "renewal-metadata")
        config = configparser.ConfigParser(interpolation=None, strict=True)
        config.read_string("[lineage]\n" + self.files.read(path).decode("utf-8"))
        _require(not config.defaults() and config.sections() == ["lineage", "renewalparams"], "renewal-structure")
        lineage = dict(config["lineage"])
        expected = {part: ROOTS["live"] + "/" + name + "/" + part + ".pem" for part in PARTS}
        expected["archive_dir"] = ROOTS["archive"] + "/" + name
        _require(set(lineage) == {*expected, "version"}
                 and all(lineage[key] == value for key, value in expected.items()), "renewal-paths")
        _require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", lineage["version"]) is not None, "renewal-version")
        return dict(config["renewalparams"])

    def _target(self, inventory, target, current_credential):
        for label in ("live", "archive"):
            _require(inventory.metadata(ROOTS[label] + "/" + target.domain, "directory") == "observed",
                     "target-directory")
        params = self._renewal(inventory, target.domain)
        credential = params.get("dns_cloudflare_credentials")
        hook = "/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-main-nginx"
        _require(params.get("authenticator") == "dns-cloudflare" and params.get("server") == PRODUCTION
                 and params.get("key_type") == "ecdsa", "target-renewal-settings")
        _require(not any(params.get(key, "").strip() for key in ("pre_hook", "post_hook", "installer"))
                 and all(params.get(key, "").strip() in {"", hook} for key in ("renew_hook", "deploy_hook")),
                 "target-renewal-hooks")
        _require(credential != current_credential, "current-credential-shared")
        _require(credential in {CREDENTIAL, domain_credential(target)}, "target-credential-path")
        _require(inventory.metadata(credential, "file", private=True) == "observed", "target-credential-metadata")
        _require(inventory.links(target.domain) == "structure-checked-only", "target-links")

        live_names, state = inventory.scan(target.cert_dir)
        expected = {part + ".pem" for part in PARTS}
        _require(state == "observed" and set(live_names) in (expected, expected | {"README"}), "target-live-entries")
        if "README" in live_names:
            _require(inventory.metadata(target.cert_dir + "/README", "file") == "observed", "target-readme-metadata")
        archive = ROOTS["archive"] + "/" + target.domain
        archive_names, state = inventory.scan(archive)
        _require(state == "observed" and bool(archive_names), "target-archive-entries")
        generations = {}
        for name in archive_names:
            match = re.fullmatch(r"(cert|chain|fullchain|privkey)([1-9][0-9]{0,9})\.pem", name)
            _require(match is not None, "target-archive-entries")
            _require(inventory.metadata(archive + "/" + name, "file", private=match[1] == "privkey") == "observed",
                     "target-archive-metadata")
            generations.setdefault(match[2], set()).add(match[1])
        _require(all(parts == set(PARTS) for parts in generations.values()), "target-incomplete-generation")
        target_link = self.files.readlink(target.cert_dir + "/cert.pem")
        cert = BASE + "/" + target_link.removeprefix("../../")
        output = self.prep._run(["openssl", "x509", "-in", cert, "-noout", "-ext", "subjectAltName"])
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        _require(lines in (["X509v3 Subject Alternative Name:", "DNS:" + target.domain],
                          ["X509v3 Subject Alternative Name: critical", "DNS:" + target.domain]), "target-san-not-single-domain")
        return credential, {"archive_generations": len(generations), "archive_files": len(archive_names),
                            "live_entries": len(live_names), "renewal_files": 1, "local_credential_files": 1}

    def _references(self, inventory, target, credential):
        names, state = inventory.scan(ROOTS["renewal"])
        _require(state == "observed", "renewal-scan-incomplete")
        refs = []
        for filename in names:
            _require(filename.endswith(".conf"), "unknown-renewal-entry")
            name = filename[:-5]
            NodeSpec(name)
            params = self._renewal(inventory, name)
            if params.get("dns_cloudflare_credentials") == credential:
                refs.append(name)
        _require(refs == [target.domain], "credential-shared-with-other-renewal")
        known = {
            "/etc/nginx/conf.d": {"snellctl-main.conf"},
            "/etc/nginx/sites-enabled": set(),
            "/etc/nginx/sites-available": {"default"},
            "/etc/nginx/modules-enabled": set(),
            BASE + "/renewal-hooks/pre": set(),
            BASE + "/renewal-hooks/post": set(),
            BASE + "/renewal-hooks/deploy": {"50-snellctl-main-nginx"},
        }
        for path, expected in known.items():
            names, state = inventory.scan(path)
            _require(state in {"observed", "missing"} and set(names) == expected, "extra-nginx-or-renewal-hook-scope")

    def inspect_locked(self, domain):
        """Internal live snapshot; caller holds the preparation lock."""
        self._phase("target-validation")
        target = NodeSpec(domain)
        current = read_deployment(self.prep)[0]
        _require(target.domain != current.domain, "target-is-current-domain")
        self._phase("current-health-check")
        before = self.tokens._check()
        current = before[1]
        self._phase("bounded-inventory")
        initial_inventory = collect_locked(self.prep)
        _require(initial_inventory["collection_complete"], "inventory-incomplete")
        inventory = Inventory(self.files)
        self._phase("target-lineage-check")
        credential, counts = self._target(inventory, target, self.prep.credential_path(current))
        self._phase("history-check")
        history = self._history(inventory, target, current)
        _require(history["initial_domain_digest_match"] or history["target_domain_change_success_record"],
                 "target-history-not-found")
        self._phase("shared-reference-check")
        self._references(inventory, target, credential)
        self._phase("unchanged-health-check")
        _require(self.tokens._check()[0] == before[0], "current-deployment-changed")
        _require(collect_locked(self.prep) == initial_inventory, "inventory-changed")
        inventory.recheck()
        return target, before, inventory, credential, counts, history

    def check(self, domain):
        report = {"format": 1, "operation": "retired-domain-plan", "result": "blocked-preserve-all",
                  "cleanup_authorized": False, "host_changes_attempted": False, "report_saved": False,
                  "all_assets_preserved": True, "current_service_health": "not-confirmed",
                  "global_reference_check": "not-performed", "limitations": list(LIMITATIONS)}
        try:
            with self.prep._lock():
                _target, _before, _inventory, _credential, counts, history = self.inspect_locked(domain)
                report.update(result="scope-checked-confirmation-required", current_service_health="local-checks-passed",
                              history=history, target_counts=counts, target_credential="independent-only-target-renewal",
                              review_scope=["selected-retired-certificate-lineage", "its-renewal-configuration",
                                            "its-independent-local-credential-file"],
                              excluded=["current-node-and-certificate", "ssh-and-firewall", "packages",
                                        "acme-account", "cloudflare-token-revocation", "dns-records", "historical-logs"],
                              required_before_cleanup=["operator-confirms-resource-ownership-and-no-other-consumers",
                                                       "separate-explicit-deletion-confirmation", "fresh-live-recheck"])
        except ScopeBlocked as exc:
            report.update(failure_phase=self.phase, reason=exc.code)
        except (KeyboardInterrupt, EOFError):
            report.update(failure_phase=self.phase, reason="interrupted")
        except Exception:
            report.update(failure_phase=self.phase, reason="unreadable-busy-unsupported-or-check-failed")
        return report


def run_retired_plan(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        ui.say("旧资源范围核查需要交互终端；不接受域名参数、管道或自动确认。")
        return 2
    try:
        ui.say("旧域名清理预检查：仅核对范围，没有删除入口，也不会安装快捷指令。")
        domain = ui.ask("待核查的旧完整小写域名（不是现用域名；留空取消）：").strip()
        if not domain:
            return 130
        NodeSpec(domain)
        ui.say(f"仅检查旧域名：{domain}。不要使用 other-1 等报告编号。")
        ui.say("会读取现用受限配置/凭据作内存核验，并执行系统状态和本机 TLS 检查；不显示秘密。")
        ui.say("不访问 Cloudflare/CA、不暂停续期、不重载服务、不删除文件。请勿并行运行管理变更或 Certbot。")
        if not confirm(ui, "确认仅核查以上旧域名的清理范围？"):
            ui.say("已取消；未执行核查或修改。")
            return 130
        if not ui.interactive():
            return 2
        with factory() as tokens:
            report = RetiredPlan(tokens, lambda phase: ui.say("核查阶段：" + phase)).check(domain)
        ui.say(json.dumps(report, ensure_ascii=False, indent=2))
        ui.say("预检查没有授权删除；现用节点及全部旧资源保留。只分享 JSON，不分享凭据或原始配置。")
        return 0 if report["result"] == "scope-checked-confirmation-required" else 1
    except (KeyboardInterrupt, EOFError):
        ui.say("已退出预检查；未执行配置变更或删除。")
        return 130
    except Exception:
        ui.say("无法完成预检查；输入无效或环境未核对，原始输入与异常未显示。未执行配置变更或删除。")
        return 1
