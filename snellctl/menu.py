"""SSH terminal menu; installation stays hidden unless explicitly opted in."""

from .deployment import NodeSpec, preview, render_preview
from .doctor import collect, render


def _port(prompt: str, default: int) -> int:
    value = input(f"{prompt} [{default}]：").strip()
    if not value:
        return default
    if not value.isascii() or not value.isdecimal() or len(value) > 5:
        raise ValueError("端口须为 1 至 65535 的整数。")
    return int(value)


def run_menu(*, experimental=False) -> int:
    changes_attempted = False
    try:
        while True:
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
            print("0. 退出")
            choice = input("选择：").strip()
            if choice == "0":
                return 0
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
                run_wizard()
            elif choice == "4":
                from .installer import installation_status, render_status
                print(render_status(installation_status()))
            elif choice == "5":
                from .client import run_client
                run_client()
            elif choice == "6":
                from .cleanup import collect as cleanup_collect, render as cleanup_render
                print(cleanup_render(cleanup_collect()))
            elif choice == "7" and experimental:
                from .installer import run_resume
                changes_attempted = True
                run_resume()
            elif choice == "8" and experimental:
                from .rotation import run_rotation
                changes_attempted = True
                run_rotation()
            elif choice == "9" and experimental:
                from .portchange import run_port_change
                changes_attempted = True
                run_port_change()
            elif choice == "10" and experimental:
                from .tokenchange import run_token_change
                changes_attempted = True
                run_token_change()
            elif choice == "11" and experimental:
                from .domainchange import run_domain_change
                changes_attempted = True
                run_domain_change()
            elif choice == "12":
                from .domaininventory import collect as inventory_collect, render as inventory_render
                print(inventory_render(inventory_collect()))
            elif choice == "13":
                from .retiredplan import run_retired_plan
                run_retired_plan()
            else:
                print("请选择菜单中已有的编号。")
    except (EOFError, KeyboardInterrupt):
        print("\n已退出；操作可能已改变系统，请查看阶段记录。" if changes_attempted
              else "\n已退出；未执行部署或配置变更。")
        return 130
