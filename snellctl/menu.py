"""SSH terminal routes; host changes require explicit experimental opt-in."""

from .deployment import NodeSpec, preview, render_preview
from .doctor import collect, render


# The same flag controls both visibility and dispatch; command names are fixed.
_SUBMENUS = {
    "15": ("组件维护", {
        "1": ("本机组件盘点（不联网、不升级）", "maintenance-plan", False),
        "2": ("原更新任务状态（只读，不恢复）", "package-update-status", False),
        "3": ("联网检查更新方案（写缓存，不升级）", "package-update-plan", True),
        "4": ("下载升级包审查材料（不安装）", "package-update-review", True),
        "5": ("实际 Debian 包更新（会停机，未实机验收）", "package-update", True),
        "6": ("原更新任务受限恢复（不重装，未实机验收）", "package-update-resume", True),
    }),
    "16": ("卸载与重装", {
        "1": ("只读核查卸载范围（不停止节点）", "uninstall-plan", False),
        "2": ("只读核查卸载后的重装条件", "reinstall-plan", False),
        "3": ("卸载受管节点（停机并永久删除受管资源）", "uninstall", True),
        "4": ("成功卸载后的受控重装（生成新密钥）", "reinstall", True),
    }),
}


def _action_status(result, *, changes_attempted):
    if type(result) is int and result == 0:
        return 0
    if changes_attempted:
        print("操作可能已改变系统，请先查看阶段记录并保留现场。")
    if type(result) is int and result == 130:
        print("已取消或中断，菜单已退出；若操作已开始写入，请先核查记录，不自动重试。")
        return 130
    print("操作未确认完成，菜单已退出；请查看该操作的结果，不自动重试或重启。")
    return result if type(result) is int and result in (1, 2) else 1


def _port(prompt: str, default: int) -> int:
    value = input(f"{prompt} [{default}]：").strip()
    if not value:
        return default
    if not value.isascii() or not value.isdecimal() or len(value) > 5:
        raise ValueError("端口须为 1 至 65535 的整数。")
    return int(value)


def run_menu(*, experimental=False) -> int:
    changes_attempted = False
    view = None
    try:
        while True:
            if view is not None:
                title, actions = _SUBMENUS[view]
                print(f"\n{title}（{'实验入口已显示，操作仍需独立确认' if experimental else '查询模式'}）")
                if view == "15":
                    print("不提供 Snell/ShadowTLS 程序自动升级；实际 Debian 升级及恢复仍待实机验收。")
                for number, (label, command, opt_in) in actions.items():
                    if not opt_in or experimental:
                        print(f"{number}. {label}")
                print("0. 返回主菜单")
                choice = input("选择：").strip()
                if choice == "0":
                    view = None
                    continue
                action = actions.get(choice)
                if action is None or (action[2] and not experimental):
                    print("请选择菜单中已有的编号。")
                    continue
                _, command, opt_in = action
                changes_attempted = changes_attempted or opt_in
                # Reuse CLI adapters, including terminal checks and confirmations.
                from .__main__ import main
                result = _action_status(
                    main([command] + (["--experimental"] if opt_in else [])),
                    changes_attempted=changes_attempted,
                )
                if result:
                    return result
                continue
            print("\nsnellctl（开发版）\n1. 检查当前机器\n2. 新部署计划预览")
            if experimental:
                print("3. 实验版新机安装（会修改系统）")
            print("4. 查看脱敏安装阶段记录\n5. 显示 Surge 配置（含密钥，需确认）\n6. 清理前只读盘点（不卸载）")
            if experimental:
                print("7. 中断后检查并继续（仅限待开放阶段，会修改系统）")
                print("8. 单独更换节点密钥（会中断节点，需更新客户端）")
                print("9. 更换公网入口端口（会中断节点并调整 UFW）")
                print("10. 更换 Cloudflare Token（会暂停续期并执行 DNS 演练）")
                print("11. 更换域名和证书（需新区域令牌及更新客户端 SNI）")
            print("12. 域名资源只读盘点（不清理）")
            print("13. 旧域名清理预检查（需确认目标，不删除）")
            if experimental:
                print("14. 清理单个旧域名（不可撤销，需分别确认归属及删除）")
            print("15. 组件维护\n16. 卸载与重装")
            if not experimental:
                print("当前仅显示查询入口；Surge 配置包含密钥，显示前仍需确认。")
            print("0. 退出")
            choice = input("选择：").strip()
            if choice == "0":
                return 0
            if choice in _SUBMENUS:
                view = choice
                continue
            result = 0
            if choice == "1":
                print(render(collect()))
            elif choice == "2":
                try:
                    node = input("节点名称 [main]：").strip() or "main"
                    domain = input("完整小写域名：").strip()
                    public_port = _port("ShadowTLS 对外 TCP 端口", 443)
                    snell_port = _port("Snell 本机端口", 31001)
                    tls_port = _port("Nginx 本机 TLS 端口", 31443)
                    spec = NodeSpec(domain, node, public_port, snell_port, tls_port)
                    print(render_preview(preview(spec)))
                except ValueError as exc:
                    print(str(exc))
            elif choice == "3" and experimental:
                from .installer import run_wizard
                changes_attempted = True
                result = run_wizard()
            elif choice == "4":
                from .installer import installation_status, render_status
                print(render_status(installation_status()))
            elif choice == "5":
                from .client import run_client
                result = run_client()
            elif choice == "6":
                from .cleanup import collect as cleanup_collect, render as cleanup_render
                print(cleanup_render(cleanup_collect()))
            elif choice == "7" and experimental:
                from .installer import run_resume
                changes_attempted = True
                result = run_resume()
            elif choice == "8" and experimental:
                from .rotation import run_rotation
                changes_attempted = True
                result = run_rotation()
            elif choice == "9" and experimental:
                from .portchange import run_port_change
                changes_attempted = True
                result = run_port_change()
            elif choice == "10" and experimental:
                from .tokenchange import run_token_change
                changes_attempted = True
                result = run_token_change()
            elif choice == "11" and experimental:
                from .domainchange import run_domain_change
                changes_attempted = True
                result = run_domain_change()
            elif choice == "12":
                from .domaininventory import collect as inventory_collect, render as inventory_render
                print(inventory_render(inventory_collect()))
            elif choice == "13":
                from .retiredplan import run_retired_plan
                result = run_retired_plan()
            elif choice == "14" and experimental:
                from .retiredcleanup import run_retired_cleanup
                changes_attempted = True
                result = run_retired_cleanup()
            else:
                print("请选择菜单中已有的编号。")
            result = _action_status(result, changes_attempted=changes_attempted)
            if result:
                return result
    except (EOFError, KeyboardInterrupt):
        print("\n已退出；操作可能已改变系统，请查看阶段记录。" if changes_attempted
              else "\n已退出；未执行部署或配置变更。")
        return 130
    except Exception:
        print("\n菜单操作异常，原始异常未显示；已退出，不自动重试。")
        if changes_attempted:
            print("操作可能已改变系统，请先查看阶段记录并保留现场。")
        return 1
