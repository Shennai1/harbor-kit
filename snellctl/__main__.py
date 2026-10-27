"""Read-only tools, sandbox transactions, and an opt-in experimental installer."""

import argparse
import json
import sys

from . import __version__
from .doctor import collect, render
from .deployment import NodeSpec, preview, render_preview
from .menu import run_menu


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # Unknown arguments may contain an accidentally pasted credential.
        self.print_usage(sys.stderr)
        self.exit(2, "参数无效；原始输入未显示。请使用 --help 查看允许的命令和参数。\n")


def _spec_arguments(parser):
    parser.add_argument("--domain", required=True, help="完整小写域名")
    parser.add_argument("--node", default="main", help="节点名称，默认 main")
    parser.add_argument("--public-port", type=int, default=443)
    parser.add_argument("--snell-port", type=int, default=31001)
    parser.add_argument("--tls-port", type=int, default=31443)
    parser.add_argument("--nginx-version", default="1.26.3", help="模板语法版本；不表示安全补丁状态")


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(prog="snellctl", description="Snell 部署管理工具（开发版）")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command")
    doctor = commands.add_parser("doctor", help="只读检查当前机器，不修改配置")
    doctor.add_argument("--json", action="store_true", help="输出脱敏 JSON，不自动保存文件")
    menu = commands.add_parser("menu", help="SSH 中文交互菜单，默认只读")
    menu.add_argument("--experimental", action="store_true", help="显示安装、接续、密钥、端口及 Token 更换入口，仍需逐步确认")
    install = commands.add_parser("install", help="实验版新机安装向导，会修改系统；仅限交互终端")
    install.add_argument("--experimental", action="store_true", help="明确开启未实机验收的安装向导")
    resume = commands.add_parser("resume", help="实验版受限接续；只允许本机验收完成且公网尚未开始的阶段")
    resume.add_argument("--experimental", action="store_true", help="明确开启受限接续；现场复查后仍需确认")
    rotate = commands.add_parser("rotate-key", help="实验版：单独更换 Snell 或 ShadowTLS 密钥；会中断节点")
    rotate.add_argument("--experimental", action="store_true", help="明确开启密钥更换，仍需交互确认")
    port = commands.add_parser("change-port", help="实验版：更换 IPv4 TCP 公网端口；会中断节点并调整 UFW")
    port.add_argument("--experimental", action="store_true", help="明确开启端口更换，仍需交互确认")
    token = commands.add_parser("change-token", help="实验版：更换 Cloudflare Token 并验证续期；不改节点密钥")
    token.add_argument("--experimental", action="store_true", help="明确开启 Token 更换，仍需交互确认")
    diagnosis = commands.add_parser("diagnose-token", help="实验版：仅对未替换的候选 Token 执行一次诊断，不恢复更换")
    diagnosis.add_argument("--experimental", action="store_true", help="明确开启候选诊断，仍需交互确认")
    diagnosis.add_argument("--after-permission-fix", action="store_true", help="同一令牌的云端权限修正后单次复测；保留原诊断，不提交更换")
    token_resume = commands.add_parser("resume-token", help="实验版：权限复测通过后接续凭据替换和自动续期")
    token_resume.add_argument("--experimental", action="store_true", help="明确开启受限 Token 接续，仍需交互确认")
    domain_change = commands.add_parser("change-domain", help="实验版：更换域名及独立凭据，验证证书和续期；需更新客户端 SNI")
    domain_change.add_argument("--experimental", action="store_true", help="明确开启域名更换，仍需交互确认")
    status = commands.add_parser("install-status", help="只读查看脱敏的安装阶段记录，不恢复、不检查服务健康")
    status.add_argument("--json", action="store_true")
    commands.add_parser("client", help="确认后在终端显示 Surge 配置（含密钥）；只读，不写文件")
    cleanup = commands.add_parser("cleanup-plan", help="清理前只读盘点 main；不认领、不卸载、不生成删除命令")
    cleanup.add_argument("--json", action="store_true", help="输出脱敏报告，不自动保存文件")
    inventory = commands.add_parser("domain-inventory", help="只读盘点现用及保留证书的凭据引用；不清理")
    inventory.add_argument("--json", action="store_true", help="输出匿名引用报告，不保存文件")
    commands.add_parser("retired-domain-plan", help="交互核查一个旧域名的资源范围及现用节点健康；不清理")
    retired_cleanup = commands.add_parser("clean-retired-domain", help="实验版：确认后删除单个旧域名的本机证书、续期配置和独立凭据")
    retired_mode = retired_cleanup.add_mutually_exclusive_group()
    retired_mode.add_argument("--experimental", action="store_true", help="开启不可撤销的受限清理，仍需交互确认")
    retired_mode.add_argument("--check-only", action="store_true", help="只读复核清理条件并输出脱敏结果，不删除或暂停续期")
    plan = commands.add_parser("plan", help="离线预览部署计划，不读取或更改当前机器")
    _spec_arguments(plan)
    plan.add_argument("--json", action="store_true", help="输出不含密钥的计划 JSON")
    preflight = commands.add_parser("preflight", help="新机只读预检查；不刷新软件源、不安装")
    _spec_arguments(preflight)
    preflight.add_argument("--json", action="store_true")
    artifacts = commands.add_parser("artifacts", help="固定版本官方程序清单与下载暂存；不执行程序")
    artifact_actions = artifacts.add_subparsers(dest="artifact_action", required=True)
    artifact_actions.add_parser("list", help="离线显示固定来源及基线指纹")
    fetch = artifact_actions.add_parser("fetch", help="联网下载并校验，只写入新的暂存目录")
    fetch.add_argument("--output", required=True, help="新目录的绝对路径；父目录须存在且不能含符号链接")
    sandbox = commands.add_parser("sandbox", help="开发用离线文件事务；仅写入明确初始化的独立测试目录")
    actions = sandbox.add_subparsers(dest="sandbox_action", required=True)
    for action, help_text in (
        ("init", "初始化空测试目录"), ("prepare", "生成并写入沙盒候选配置，不安装服务"),
        ("status", "核对沙盒记录与候选文件"), ("recover", "继续或取消未完成的沙盒写入"),
    ):
        command = actions.add_parser(action, help=help_text)
        command.add_argument("--root", required=True, help="独立测试目录的绝对路径，不允许系统根目录")
        if action == "prepare":
            _spec_arguments(command)
        elif action == "recover":
            command.add_argument("--action", required=True, choices=("resume", "rollback"))
    args = parser.parse_args(argv)
    if args.command == "clean-retired-domain":
        if args.check_only:
            from .retiredcleanup import run_retired_cleanup_check
            return run_retired_cleanup_check()
        if not args.experimental:
            print("旧域名清理需要 --experimental，仍需分别确认归属和本机删除。", file=sys.stderr)
            return 2
        from .retiredcleanup import run_retired_cleanup
        return run_retired_cleanup()
    if args.command == "retired-domain-plan":
        from .retiredplan import run_retired_plan
        return run_retired_plan()
    if args.command == "domain-inventory":
        from .domaininventory import collect as inventory_collect, exit_code, render as inventory_render
        report = inventory_collect()
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else inventory_render(report))
        return exit_code(report)
    if args.command == "cleanup-plan":
        from .cleanup import collect as cleanup_collect, exit_code, render as cleanup_render
        report = cleanup_collect()
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else cleanup_render(report))
        return exit_code(report)
    if args.command == "client":
        from .client import run_client
        return run_client()
    if args.command == "rotate-key":
        if not args.experimental:
            print("密钥更换仍属实验功能；需要明确提供 --experimental，不会自动执行。", file=sys.stderr)
            return 2
        from .rotation import run_rotation
        return run_rotation()
    if args.command == "change-port":
        if not args.experimental:
            print("端口更换仍属实验功能；需要明确提供 --experimental，不会自动执行。", file=sys.stderr)
            return 2
        from .portchange import run_port_change
        return run_port_change()
    if args.command == "change-token":
        if not args.experimental:
            print("Token 更换仍属实验功能；需要明确提供 --experimental，不会自动执行。", file=sys.stderr)
            return 2
        from .tokenchange import run_token_change
        return run_token_change()
    if args.command == "diagnose-token":
        if not args.experimental:
            print("候选诊断需要明确提供 --experimental，且仍需交互确认。", file=sys.stderr)
            return 2
        from .tokendiag import run_token_diagnostic
        return run_token_diagnostic(after_permission_fix=args.after_permission_fix)
    if args.command == "change-domain":
        if not args.experimental:
            print("域名更换需要 --experimental，且仍需交互确认。", file=sys.stderr)
            return 2
        from .domainchange import run_domain_change
        return run_domain_change()
    if args.command == "resume-token":
        if not args.experimental:
            print("Token 接续需要 --experimental，且仍需交互确认。", file=sys.stderr)
            return 2
        from .tokenresume import run_token_resume
        return run_token_resume()
    if args.command == "install":
        if not args.experimental:
            print("安装尚未完成实机验收；需要明确提供 --experimental，不会自动执行。", file=sys.stderr)
            return 2
        from .installer import run_wizard
        return run_wizard()
    if args.command == "resume":
        if not args.experimental:
            print("接续仍属实验功能；需要明确提供 --experimental，不会自动执行。", file=sys.stderr)
            return 2
        from .installer import run_resume
        return run_resume()
    if args.command == "install-status":
        from .installer import installation_status, render_status
        report = installation_status()
        print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else render_status(report))
        return 1 if report["state"] == "unreadable-or-busy" else 0
    if args.command == "artifacts":
        from .artifacts import run
        return run(args)
    if args.command == "sandbox":
        from .sandbox_cli import run
        return run(args)
    if args.command in {None, "menu"}:
        if not sys.stdin.isatty():
            parser.print_help()
            print("交互菜单需要终端；非交互调用请指定 doctor 或 plan。", file=sys.stderr)
            return 2
        return run_menu(experimental=True) if getattr(args, "experimental", False) else run_menu()
    if args.command in {"plan", "preflight"}:
        try:
            spec = NodeSpec(args.domain, args.node, args.public_port, args.snell_port, args.tls_port, args.nginx_version)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if args.command == "preflight":
            from .preflight import check, render as render_preflight
            report = check(spec)
            print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else render_preflight(report))
            return 0 if report["limited_checks_passed"] else 1
        plan_report = preview(spec)
        print(json.dumps(plan_report, ensure_ascii=False, indent=2) if args.json else render_preview(plan_report))
        return 0
    report = collect()
    print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else render(report))
    if not report["platform_supported"]:
        return 2
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
