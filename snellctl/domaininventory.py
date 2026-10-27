"""Bounded reference inventory; no commands, credential reads or deletion authority."""

import configparser
import os
from pathlib import Path
import platform
import re
import stat

from .client import read_deployment
from .hostprep import Preparation, PreparationError, PRODUCTION
from .publish import RENEW_DROPIN, renewal_dropin


LIMIT = 128
BASE = "/etc/letsencrypt"
CREDENTIALS = "/etc/snellctl/credentials"
ROOTS = {name: BASE + "/" + name for name in ("live", "archive", "renewal")}
ROOTS["credentials"] = CREDENTIALS
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,252}\Z", re.ASCII)
LIMITATIONS = (
    "只检查受管 main 配置、固定 Certbot 目录及凭据目录；不是全机引用搜索。",
    "读取并校验受管节点配置和程序摘要，但不输出节点密钥；不读取 CF Token、证书私钥或日志内容。",
    "证书只检查目录、链接和目标元数据；不验证证书内容、有效期、密钥对应或运行中的 TLS。",
    "current 表示当前受管配置引用；other-N 只是本次匿名编号，不证明属于旧部署，也不是删除标识。",
    "未在已读续期文件发现引用，不代表没有其他站点、任务、容器或外部配置引用；全部资源保留。",
    "只核对受管续期覆盖文件，不检查 systemd 实际加载状态、定时器或其他续期任务。",
    "未限定证书名称的 Certbot renew 仍可能处理保留的其他续期配置；本报告不执行 Certbot。",
    "使用已有协作锁并复查文件变动，但不构成全系统原子快照；没有联网、写入、删除或停止服务。",
)


def _no_commands(_command):
    raise PreparationError("只读盘点不执行系统命令。")


class Inventory:
    def __init__(self, files):
        self.files = files
        self.watched = {}
        self.issues = set()

    def info(self, path):
        item = self.files.info(path)
        fingerprint = None if item is None else tuple(getattr(item, key) for key in (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))
        if path in self.watched and self.watched[path] != fingerprint:
            raise PreparationError("盘点期间文件发生变动。")
        self.watched[path] = fingerprint
        return item

    def scan(self, path, *, private=False):
        self.info(path)
        try:
            with self.files.directory(path, private=private) as fd, os.scandir(fd) as entries:
                names = []
                for entry in entries:
                    if len(names) == LIMIT:
                        self.issues.add("directory-limit")
                        return sorted(names), "limited"
                    names.append(entry.name)
            return sorted(names), "observed"
        except FileNotFoundError:
            return [], "missing"

    def metadata(self, path, kind, *, private=False):
        item = self.info(path)
        if item is None:
            return "missing"
        safe = item.st_uid == os.geteuid() and not item.st_mode & 0o022
        if kind == "directory":
            safe = safe and stat.S_ISDIR(item.st_mode)
            if safe:
                with self.files.directory(path, private=private):
                    pass
        else:
            safe = safe and stat.S_ISREG(item.st_mode) and item.st_nlink == 1
            if private:
                safe = safe and stat.S_IMODE(item.st_mode) == 0o600
        if not safe:
            self.issues.add("unsafe-metadata")
        return "observed" if safe else "needs-inspection"

    def renewal(self, name):
        path = ROOTS["renewal"] + "/" + name + ".conf"
        if self.metadata(path, "file") != "observed":
            return None
        try:
            parser = configparser.ConfigParser(interpolation=None, strict=True)
            parser.read_string("[lineage]\n" + self.files.read(path).decode("utf-8"))
            if parser.defaults() or not parser.has_section("renewalparams"):
                raise ValueError
            params = parser["renewalparams"]
            reference = params.get("dns_cloudflare_credentials", "")
            if params.get("authenticator") != "dns-cloudflare" or not reference:
                self.issues.add("unrecognized-renewal")
                return None
            # Never open a path supplied by a renewal file. Match only scanned names.
            return dict(params)
        except (ValueError, UnicodeError, configparser.Error):
            self.issues.add("unrecognized-renewal")
            return None

    def links(self, name):
        for part in ("cert", "chain", "fullchain", "privkey"):
            path = ROOTS["live"] + "/" + name + "/" + part + ".pem"
            item = self.info(path)
            if item is None or not stat.S_ISLNK(item.st_mode) or item.st_uid != os.geteuid():
                return "needs-inspection"
            target = self.files.readlink(path)
            match = re.fullmatch(r"\.\./\.\./archive/" + re.escape(name) + "/" + part + r"([1-9][0-9]{0,9})\.pem", target)
            if not match:
                return "needs-inspection"
            resolved = ROOTS["archive"] + "/" + name + "/" + part + match[1] + ".pem"
            if self.metadata(resolved, "file", private=part == "privkey") != "observed":
                return "needs-inspection"
        return "structure-checked-only"

    def recheck(self):
        for path in tuple(self.watched):
            self.info(path)


def _collect(prep, report):
    before = read_deployment(prep)
    spec = before[0]
    current_credential = prep.credential_path(spec)
    inventory = Inventory(prep.files)
    inventory.info(RENEW_DROPIN)
    record = prep._read_record("renewal-enable-ready")
    if (prep.files.read(RENEW_DROPIN, mode=0o644) != renewal_dropin(spec)
            or prep.files.identity(RENEW_DROPIN) != record.get("identity")):
        raise PreparationError("受管续期配置与记录不一致。")

    listings = {}
    for label, path in ROOTS.items():
        listings[label], state = inventory.scan(path, private=label == "credentials")
        report["directories"][label] = {"status": state, "entries_seen": len(listings[label])}
        if state != "observed":
            inventory.issues.add("incomplete-directories")

    names = {spec.domain}
    for label in ("live", "archive", "renewal"):
        for name in listings[label]:
            if label == "live" and name == "README":
                continue
            if label == "renewal":
                if not name.endswith(".conf"):
                    inventory.issues.add("unrecognized-entry")
                    continue
                name = name[:-5]
            if NAME.fullmatch(name):
                names.add(name)
            else:
                inventory.issues.add("unrecognized-entry")
    ordered = [spec.domain] + sorted(names - {spec.domain})
    if len(ordered) > LIMIT:
        inventory.issues.add("lineage-limit")
        ordered = ordered[:LIMIT]
    aliases = {name: "current" if i == 0 else f"other-{i}" for i, name in enumerate(ordered)}

    credentials = {current_credential}
    credentials.update(CREDENTIALS + "/" + name for name in listings["credentials"])
    ordered_credentials = [current_credential] + sorted(credentials - {current_credential})
    credential_aliases = {path: "current" if i == 0 else f"other-{i}"
                          for i, path in enumerate(ordered_credentials)}
    references = {path: [] for path in credentials}
    for name in ordered:
        item = {"id": aliases[name], "preserve": True, "ownership": "not-established",
                "referenced_by_managed_nginx": name == spec.domain,
                "selected_by_managed_renewal_file": name == spec.domain}
        for label in ("live", "archive"):
            item[label] = inventory.metadata(ROOTS[label] + "/" + name, "directory")
        item["links"] = (inventory.links(name) if item["live"] == item["archive"] == "observed"
                         else "not-checked")
        params = inventory.renewal(name)
        item["renewal"] = "recognized-cloudflare-reference" if params is not None else "missing-or-unrecognized"
        reference = params.get("dns_cloudflare_credentials") if params else None
        item["credential"] = credential_aliases.get(reference, "outside-observed-credentials" if reference else "unknown")
        if reference in references:
            references[reference].append(aliases[name])
        else:
            inventory.issues.add("unresolved-credential-reference")
        if (name == spec.domain and (not params or reference != current_credential
                or params.get("server") != PRODUCTION or params.get("key_type") != "ecdsa")):
            raise PreparationError("现用续期配置与受管域名不一致。")
        if item["links"] != "structure-checked-only" or params is None:
            inventory.issues.add("incomplete-lineage")
        report["lineages"].append(item)

    for path in ordered_credentials:
        state = inventory.metadata(path, "file", private=True)
        if state != "observed":
            inventory.issues.add("incomplete-credentials")
        report["credentials"].append({
            "id": credential_aliases[path], "metadata": state,
            "referenced_by_observed_renewals": references[path],
            "current_managed_credential": path == current_credential,
            "contents_read": False, "ownership": "not-established", "preserve": True,
        })

    # The cooperative lock cannot stop external root/Certbot changes.
    inventory.recheck()
    if (read_deployment(prep) != before or prep.credential_path(spec) != current_credential
            or prep._read_record("renewal-enable-ready") != record):
        raise PreparationError("受管部署在盘点期间发生变动。")
    inventory.recheck()
    report["managed_configuration"] = "disk-references-verified"
    report["findings"] = sorted(inventory.issues)
    report["collection_complete"] = not inventory.issues
    report["state"] = "review-required" if not inventory.issues else "partial-preserve-all"


def _empty_report():
    return {
        "format": 1, "mode": "read-only-domain-inventory", "scope": "managed-main",
        "state": "unsupported", "collection_complete": False, "cleanup_authorized": False,
        "managed_configuration": "not-checked", "current_service_health": "not-checked",
        "global_reference_check": "not-performed", "directories": {}, "lineages": [],
        "credentials": [], "findings": [], "limitations": list(LIMITATIONS),
    }


def collect_locked(prep):
    """Internal collector; caller must hold the preparation lock."""
    report = _empty_report()
    _collect(prep, report)
    return report


def collect(*, root=Path("/"), system=None, euid=None):
    report = _empty_report()
    if (platform.system() if system is None else system) != "Linux":
        return report
    if (os.geteuid() if euid is None else euid) != 0:
        report["state"] = "root-required"
        return report
    try:
        with Preparation(root, _no_commands) as prep, prep._lock():
            _collect(prep, report)
    except Exception:
        # Do not expose parser exceptions, paths, tokens or a half-verified snapshot.
        report.update(state="unverified-preserve-all", collection_complete=False,
                      managed_configuration="not-verified", directories={}, lineages=[], credentials=[],
                      findings=["busy-pending-unreadable-or-changed"])
    return report


def exit_code(report):
    if report["state"] in {"unsupported", "root-required"}:
        return 2
    return 0 if report["collection_complete"] else 1


def render(report):
    lines = ["域名资源只读盘点；没有执行或授权清理。", "状态：" + report["state"]]
    for item in report["lineages"]:
        lines.append(f"证书组 {item['id']}：续期凭据 {item['credential']}；{item['links']}；保留")
    for item in report["credentials"]:
        refs = ", ".join(item["referenced_by_observed_renewals"]) or "在本次已读续期文件中未发现"
        lines.append(f"凭据 {item['id']}：引用 {refs}；{item['metadata']}；保留")
    lines.extend(report["limitations"])
    return "\n".join(lines)
