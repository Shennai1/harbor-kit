"""Internal IPv4 publication after local acceptance; never resets a firewall.

Package, systemd and firewall operations are not atomic. Intent precedes side
effects; unknown results stop for inspection rather than blindly undoing rules.
"""

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import json
import re
import shlex

from .activation import _binding, _digest
from .hostprep import POLICY, POLICY_BYTES, STATE, PreparationError


RENEW_DROPIN = "/etc/systemd/system/certbot.service.d/50-snellctl.conf"
UFW_UNCHANGED = ("/etc/default/ufw", "/etc/ufw/ufw.conf", "/etc/ufw/before.rules",
                 "/etc/ufw/before6.rules", "/etc/ufw/after.rules", "/etc/ufw/after6.rules",
                 "/etc/ufw/user6.rules")


@dataclass(frozen=True)
class Rule:
    action: str
    port: int
    source: str = "any"
    comment: str = ""


def parse_rules(output):
    """Accept a small unambiguous UFW TCP subset; never evaluate printed commands."""
    result = []
    for line in output.splitlines():
        if not line.strip() or line == "Added user rules (see 'ufw status' for running firewall):":
            continue
        try:
            words = shlex.split(line)
            if len(words) < 3 or words[0] != "ufw" or words[1] not in {"allow", "deny", "reject", "limit"}:
                raise ValueError
            action, words = words[1], words[2:]
            comment = ""
            if "comment" in words:
                index = words.index("comment")
                if index != len(words) - 2:
                    raise ValueError
                comment, words = words[-1], words[:index]
            if words and words[0] == "in":
                words = words[1:]
            if len(words) == 1 and re.fullmatch(r"[0-9]+/tcp", words[0]):
                port, source = int(words[0][:-4]), "any"
            else:
                if words.count("proto") != 1:
                    raise ValueError
                index = words.index("proto")
                if words[index:index + 2] != ["proto", "tcp"]:
                    raise ValueError
                words = words[:index] + words[index + 2:]
                if len(words) != 6 or words[0] != "from" or words[2:5] != ["to", "any", "port"]:
                    raise ValueError
                source, port = words[1], int(words[5])
                if source != "any":
                    source = str(ipaddress.ip_network(source, strict=False))
            if not 1 <= port <= 65535:
                raise ValueError
            result.append(Rule(action, port, source, comment))
        except (ValueError, IndexError):
            raise PreparationError("存在当前无法安全识别的 UFW 规则；不自动改动防火墙。") from None
    return result


def _rules_digest(rules):
    return _digest(json.dumps([asdict(rule) for rule in rules], sort_keys=True).encode())


def input_rules(text, *, saved=False):
    """Compare persistent IPv4 user rules to the running chain, ignoring implied tcp module."""
    result = []
    for line in text.splitlines():
        if saved and not line.startswith("-A ufw-user-input "):
            continue
        if not saved and line == "-N ufw-user-input":
            continue
        if not line.strip():
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            raise PreparationError("无法识别 IPv4 规则，停止核查。") from None
        if tokens[:2] != ["-A", "ufw-user-input"]:
            raise PreparationError("IPv4 用户规则链包含非预期输出。")
        normalized = []
        index = 0
        while index < len(tokens):
            if tokens[index:index + 2] in (["-m", "tcp"], ["-s", "0.0.0.0/0"], ["-d", "0.0.0.0/0"]):
                index += 2
                continue
            normalized.append(tokens[index])
            index += 1
        result.append(tuple(normalized))
    return result


def renewal_dropin(spec):
    hook = f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{spec.node}-nginx"
    # All substituted fields have already passed NodeSpec validation. No secrets.
    return (
        "[Unit]\nWants=network-online.target nginx.service\nAfter=network-online.target nginx.service\n"
        "[Service]\nExecStart=\n"
        f"ExecStart=/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME={STATE}/home "
        f"/usr/bin/certbot -q renew --non-interactive --no-random-sleep-on-renew --cert-name {spec.domain} "
        f"--no-directory-hooks --deploy-hook {hook} --config-dir /etc/letsencrypt "
        "--work-dir /var/lib/letsencrypt --logs-dir /var/log/letsencrypt --max-log-backups 3\n"
        "ExecStartPost=\nExecStartPost=/usr/sbin/nginx -t\n"
        "ExecStartPost=/usr/bin/systemctl reload nginx.service\n"
        "WorkingDirectory=/\nUMask=0077\nTimeoutStartSec=600\n"
    ).encode()


class Publication:
    def __init__(self, activation):
        self.local = activation
        self.prep = activation.prep
        self.files = activation.files

    def _fields(self, unit, properties):
        output = self.prep._run(["systemctl", "show", unit, "-p", properties])
        return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)

    def check_new_host(self, spec, ssh_port):
        """Read-only early firewall gate, repeated immediately before publication."""
        if (type(ssh_port) is not int or not 1 <= ssh_port <= 65535
                or ssh_port in {spec.public_port, spec.snell_port, spec.tls_port}):
            raise PreparationError("SSH 端口无效或与节点端口冲突。")
        result = self._firewall(ssh_port)
        if any(rule.port == spec.public_port or rule.comment == "snellctl-" + spec.node for rule in result[0]):
            raise PreparationError("入口端口或本工具标签已有 UFW 规则，暂不认领或覆盖。")
        return result

    def _firewall(self, ssh_port):
        output = self.prep._run(["ufw", "status", "verbose"])
        if ("Status: active" not in output.splitlines()
                or not re.search(r"^Default: deny \(incoming\), allow \(outgoing\),", output, re.M)):
            raise PreparationError("UFW 必须已启用且默认拒绝入站、允许出站；不会自动重置。")
        if self.prep._run(["systemctl", "is-enabled", "ufw.service"]).strip() != "enabled":
            raise PreparationError("UFW 尚未登记开机启用，先人工确认。")
        rules = parse_rules(self.prep._run(["ufw", "show", "added"]))
        if not any(r.action in {"allow", "limit"} and r.port == ssh_port for r in rules):
            raise PreparationError("没有找到指定 SSH 端口的 UFW 放行规则。")
        listeners = self.prep._run(["ss", "-H", "-lntp"])
        ssh_found = False
        for line in listeners.splitlines():
            fields = line.split()
            # Without -u, ss omits the Netid column.
            if len(fields) >= 6 and fields[0] == "LISTEN" and '"sshd"' in line:
                address = fields[3]
                if address.rsplit(":", 1)[-1] == str(ssh_port) and not address.startswith(("127.", "[::1]:")):
                    ssh_found = True
        if not ssh_found:
            raise PreparationError("没有确认指定端口的 SSH 公网监听，停止操作。")
        hashes = {}
        for path in UFW_UNCHANGED:
            data = self.files.read(path)
            if path.endswith(".rules") and re.search(rb"CN_GEO_BLOCK|--match-set|DOCKER-USER", data):
                raise PreparationError("发现地理阻断或额外规则链，需要人工审查，不自动绕过。")
            hashes[path] = _digest(data)
        for program, chain in (("iptables", "INPUT"), ("ip6tables", "INPUT"), ("ip6tables", "ufw6-user-input")):
            output = self.prep._run([program, "-S", chain])
            if chain == "INPUT" and "-P INPUT DROP" not in output.splitlines():
                raise PreparationError("内核默认入站策略不是 DROP，先核查防火墙。")
            if re.search(r"CN_GEO_BLOCK|--match-set|DOCKER-USER", output):
                raise PreparationError("发现额外内核规则链，需要人工审查。")
            hashes[program + ":" + chain] = _digest(output.encode())
        running = input_rules(self.prep._run(["iptables", "-S", "ufw-user-input"]))
        saved = input_rules(self.files.read("/etc/ufw/user.rules").decode("utf-8"), saved=True)
        if running != saved:
            raise PreparationError("运行中的 IPv4 用户规则与保存的规则不一致，停止操作。")
        return rules, hashes, running

    def _vendor_certbot(self):
        content = self.files.read("/var/lib/dpkg/info/certbot.md5sums", limit=1024**2).decode("ascii")
        sums = {}
        for line in content.splitlines():
            match = re.fullmatch(r"([a-f0-9]{32})  (\S+)", line)
            if match:
                sums["/" + match[2]] = match[1]
        for unit in ("certbot.service", "certbot.timer"):
            path = "/usr/lib/systemd/system/" + unit
            if hashlib.md5(self.files.read(path), usedforsecurity=False).hexdigest() != sums.get(path):
                raise PreparationError("Certbot 软件包服务或定时器已改变，暂不启用。")
            if self.files.info("/run/systemd/system/" + unit) is not None:
                raise PreparationError("发现运行时 Certbot 服务覆盖，停止操作。")

    def _renewal_health(self, spec, record, *, timer):
        if record.get("binding") != _binding(spec):
            raise PreparationError("续期启用记录与节点参数不符。")
        if (self.files.identity(RENEW_DROPIN) != record.get("identity")
                or self.files.read(RENEW_DROPIN, mode=0o644) != renewal_dropin(spec)):
            raise PreparationError("定时任务配置已改变，不自动覆盖。")
        self._vendor_certbot()
        self.prep._certbot_config()
        for unit in ("certbot.service", "certbot.timer"):
            fields = self._fields(unit, "LoadState,FragmentPath,DropInPaths")
            if (fields.get("LoadState") != "loaded"
                    or fields.get("FragmentPath") != "/usr/lib/systemd/system/" + unit
                    or fields.get("DropInPaths") != (RENEW_DROPIN if unit == "certbot.service" else "")):
                raise PreparationError("Certbot 实际加载的服务配置不符合预期。")
        if timer:
            fields = self._fields("certbot.timer", "ActiveState,SubState,UnitFileState,Triggers,NextElapseUSecRealtime")
            if (fields.get("ActiveState") != "active" or fields.get("SubState") not in {"waiting", "running"}
                    or fields.get("UnitFileState") != "enabled" or fields.get("Triggers") != "certbot.service"
                    or (fields.get("SubState") == "waiting" and fields.get("NextElapseUSecRealtime", "") in {"", "0", "n/a"})):
                raise PreparationError("自动续期定时器未进入预期启用状态。")

    def _enable_renewal(self, spec, local_record):
        if self.prep._exists("renewal-enable-intent"):
            raise PreparationError("存在未完成的续期启用，先核查现场。")
        self._vendor_certbot()
        self.local._no_overrides(("certbot.service", "certbot.timer"))
        self.prep._certbot_config()
        self.prep._record("renewal-enable-intent", {"binding": _binding(spec)})
        self.files.private_directory_new("/etc/systemd/system/certbot.service.d")
        self.files.write_new(RENEW_DROPIN, renewal_dropin(spec), 0o644)
        record = {"binding": _binding(spec), "identity": self.files.identity(RENEW_DROPIN)}
        try:
            self.local._pending_guards()
            guards = self.prep._read_record("guards")
            for unit in ("certbot.service", "certbot.timer"):
                path = "/etc/systemd/system/" + unit
                self.files.unlink_owned(path, guards[path])
            self.prep._run(["systemctl", "daemon-reload"])
            self.prep._run(["systemd-analyze", "verify", "certbot.service", "certbot.timer"])
            self._renewal_health(spec, record, timer=False)
            # Exercise the actual systemd environment. This may perform a due renewal.
            self.prep._run(["systemctl", "start", "certbot.service"], 660)
            fields = self._fields("certbot.service", "ActiveState,SubState,Result,ExecMainStatus")
            if fields != {"ActiveState": "inactive", "SubState": "dead", "Result": "success", "ExecMainStatus": "0"}:
                raise PreparationError("定时任务的首次执行未明确成功。")
            hook = f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{spec.node}-nginx"
            self.local._health(spec, local_record, check_guards=False, allowed_deploy_hook=hook)
            self.prep._run(["systemctl", "enable", "--now", "certbot.timer"])
            self._renewal_health(spec, record, timer=True)
            if self.files.read(POLICY, mode=0o755) != POLICY_BYTES:
                raise PreparationError("临时启动策略被修改，不删除外部变更。")
            self.files.unlink_owned(POLICY, guards[POLICY])
            self.prep._record("renewal-enable-ready", record)
        except BaseException:
            failures = False
            for args in (["systemctl", "stop", "certbot.timer"], ["systemctl", "disable", "certbot.timer"],
                         ["systemctl", "stop", "certbot.service"]):
                try:
                    self.prep._run(args)
                except BaseException:
                    failures = True
            raise PreparationError("续期启用失败，保留现场；" +
                                   ("无法确认任务已停止，必须人工核查。" if failures else "已停止并禁用定时器，不自动重试。")) from None
        return record

    def _public_health(self, spec, record):
        hook = f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{spec.node}-nginx"
        self._renewal_health(spec, self.prep._read_record("renewal-enable-ready"), timer=True)
        self.local._health(spec, record["node"], public_entry=True, check_guards=False, allowed_deploy_hook=hook)
        rules, hashes, running = self._firewall(record["ssh_port"])
        if (_rules_digest(rules) != record["rules_sha256"] or hashes != record["unchanged_ufw"]
                or _digest(json.dumps(running).encode()) != record["ipv4_input_sha256"]):
            raise PreparationError("防火墙已变化，需要重新核查，未修改规则。")
        for unit in ("nginx.service", spec.snell_service, spec.shadowtls_service):
            if self.prep._run(["systemctl", "is-enabled", unit]).strip() != "enabled":
                raise PreparationError("节点服务开机启动状态不符。")

    @staticmethod
    def _validate_node(spec, ssh_port):
        if type(ssh_port) is not int or not 1 <= ssh_port <= 65535 or ssh_port in {spec.public_port, spec.snell_port, spec.tls_port}:
            raise PreparationError("SSH 端口无效或与节点端口冲突。")
        if spec.node != "main":
            raise PreparationError("首轮仅支持单节点 main。")

    def _pending(self, spec, ssh_port):
        # Caller holds the preparation lock. A ready record never repairs an intent.
        self.prep._no_key_rotation()
        for name in ("public-ready", "public-intent", "public-files", "public-firewall-added",
                     "renewal-enable-intent", "renewal-enable-ready"):
            if self.prep._exists(name):
                raise PreparationError("公网或自动续期启用已经开始或完成，不按待开放阶段接续。")
        records = {name: self.prep._read_record(name) for name in (
            "guards", "packages-ready", "dns-test-ready", "certificate-ready",
            "activation-ready", "renewal-test-ready",
        )}
        spec = self.local._version(spec)
        domain = {"domain_sha256": _digest(spec.domain.encode())}
        local_record = records["activation-ready"]
        if (records["dns-test-ready"] != domain or records["certificate-ready"] != domain
                or local_record.get("binding") != _binding(spec)
                or records["renewal-test-ready"] != {"binding": _binding(spec)}):
            raise PreparationError("本机部署记录与输入参数不符，不隐式更换域名、端口或密钥。")
        if self.prep._installed() != records["packages-ready"].get("versions"):
            raise PreparationError("软件包版本与准备记录不符，先人工核查。")
        self.local._health(spec, local_record)
        firewall = self.check_new_host(spec, ssh_port)
        if self._fields(spec.shadowtls_service, "UnitFileState") != {"UnitFileState": "disabled"}:
            raise PreparationError("公网切换前入口服务必须尚未登记开机启动。")
        self._vendor_certbot()
        self.local._no_overrides(("certbot.service", "certbot.timer"))
        self.prep._certbot_config()
        return spec, local_record, firewall

    def check_pending(self, spec, *, ssh_port):
        """Read-only live check; not a reservation or permission to skip rechecking."""
        self._validate_node(spec, ssh_port)
        with self.prep._lock():
            self._pending(spec, ssh_port)
        return "pending-publication-verified"

    def enable(self, spec, *, ssh_port, confirm_public, confirm_renewal, confirm_ssh_reconnected,
               require_pending=False):
        if not all(value is True for value in (confirm_public, confirm_renewal, confirm_ssh_reconnected)):
            raise PreparationError("需确认开放 IPv4 TCP、启用正式续期，并确认另一个 SSH 新连接正常。")
        if type(require_pending) is not bool:
            raise PreparationError("待开放阶段限制必须明确指定。")
        self._validate_node(spec, ssh_port)
        with self.prep._lock():
            self.prep._no_key_rotation()
            if self.prep._exists("public-ready") and not require_pending:
                spec = self.local._version(spec)
                record = self.prep._read_record("public-ready")
                if record.get("binding") != _binding(spec) or record.get("ssh_port") != ssh_port:
                    raise PreparationError("公网启用参数已改变，不隐式更新配置。")
                self._public_health(spec, record)
                return "already-public-enabled-external-test-required"
            spec, local_record, (rules_before, hashes, running_before) = self._pending(spec, ssh_port)
            comment = "snellctl-" + spec.node
            self.prep._record("public-intent", {"binding": _binding(spec), "ssh_port": ssh_port,
                                              "rules_before_sha256": _rules_digest(rules_before)})
            entry_attempted = False
            try:
                self._enable_renewal(spec, local_record)
                self.prep._run(["systemctl", "stop", spec.shadowtls_service])
                entry_attempted = True
                path = spec.node_dir + "/shadowtls.json"
                data = json.loads(self.files.read(path, mode=0o600))
                if data["server"]["listen"] != f"127.0.0.1:{spec.public_port}":
                    raise PreparationError("入口配置不是预期的本机试运行状态。")
                data["server"]["listen"] = f"0.0.0.0:{spec.public_port}"
                old = local_record["files"][path]
                content = (json.dumps(data, indent=2) + "\n").encode()
                self.files.replace_owned(path, content, identity=old["identity"], digest=old["sha256"], mode=0o600)
                node_record = json.loads(json.dumps(local_record))
                node_record["files"][path] = {"identity": self.files.identity(path), "mode": 0o600, "sha256": _digest(content)}
                self.prep._record("public-files", node_record)
                current, current_hashes, current_running = self._firewall(ssh_port)
                if current != rules_before or current_hashes != hashes or current_running != running_before:
                    raise PreparationError("操作期间防火墙被修改，停止追加。")
                args = ["ufw", "allow", "in", "proto", "tcp", "from", "0.0.0.0/0", "to", "any",
                        "port", str(spec.public_port), "comment", comment]
                self.prep._run(args)
                after, after_hashes, running_after = self._firewall(ssh_port)
                candidates = [r for r in after if r.action == "allow" and r.port == spec.public_port
                              and r.source in {"any", "0.0.0.0/0"} and r.comment == comment]
                remaining = list(after)
                if len(candidates) != 1:
                    raise PreparationError("没有确认唯一的 IPv4 TCP 放行规则，停止。")
                remaining.remove(candidates[0])
                if remaining != rules_before or after_hashes != hashes:
                    raise PreparationError("原有 UFW 或 IPv6 配置发生变化，停止并保留现场。")
                expected_rule = ("-A", "ufw-user-input", "-p", "tcp", "--dport", str(spec.public_port), "-j", "ACCEPT")
                if running_after != [*running_before, expected_rule]:
                    raise PreparationError("IPv4 内核规则增量不符，停止并保留现场。")
                self.prep._record("public-firewall-added", {"port": spec.public_port, "family": 4,
                                                           "protocol": "tcp", "comment": comment})
                self.prep._run(["systemctl", "start", spec.shadowtls_service])
                self.local._wait_running(spec, public_entry=True)
                hook = f"/etc/letsencrypt/renewal-hooks/deploy/50-snellctl-{spec.node}-nginx"
                self.local._health(spec, node_record, public_entry=True, check_guards=False, allowed_deploy_hook=hook)
                for unit in ("nginx.service", spec.snell_service, spec.shadowtls_service):
                    self.prep._run(["systemctl", "enable", unit])
                record = {"binding": _binding(spec), "ssh_port": ssh_port, "node": node_record,
                          "rules_sha256": _rules_digest(after), "unchanged_ufw": hashes,
                          "ipv4_input_sha256": _digest(json.dumps(running_after).encode())}
                self._public_health(spec, record)
                self.prep._record("public-ready", record)
            except BaseException:
                failed = False
                if entry_attempted:
                    for action in ("stop", "disable"):
                        try:
                            self.prep._run(["systemctl", action, spec.shadowtls_service])
                        except BaseException:
                            failed = True
                if failed:
                    raise PreparationError("公网启用失败，无法确认入口已停止或禁用；必须立即人工核查。") from None
                raise PreparationError("公网启用未完成，保留现场；未删除任何防火墙规则或回滚已启用的续期。请核查意图记录。") from None
            return "public-enabled-external-test-required"
