"""Offline sandbox commands; deliberately no production apply switch."""

import json
import os
from pathlib import Path
import sys

from .deployment import NodeSpec


def run(args) -> int:
    if os.name != "posix":
        print("沙盒文件事务仅支持 POSIX 系统。", file=sys.stderr)
        return 2
    from .storage import SandboxStore, StoreError, initialize

    messages = {
        "initialized": "测试目录已初始化。",
        "created": "候选配置已写入测试目录，尚未部署或启动服务。",
        "unchanged": "参数、文件与权限一致，未写入，也未重新生成密钥。",
        "cancelled": "未完成的候选写入已取消；现有节点未更改，空框架目录可能保留。",
        "committed-cleanup": "该操作已经提交，仅完成准备材料清理；未删除已提交节点。",
        "nothing-pending": "没有待恢复操作。",
    }
    try:
        root = Path(args.root)
        if args.sandbox_action == "init":
            result = initialize(root)
        else:
            with SandboxStore(root) as store:
                if args.sandbox_action == "prepare":
                    spec = NodeSpec(args.domain, args.node, args.public_port, args.snell_port, args.tls_port, args.nginx_version)
                    result = store.prepare(spec)
                elif args.sandbox_action == "recover":
                    result = store.recover(args.action)
                else:
                    report = store.status()
                    print(json.dumps(report, ensure_ascii=False, indent=2))
                    return 1 if report["pending"] != "none" or any(node["state"] != "candidates-intact" for node in report["nodes"]) else 0
        print("沙盒模式：" + messages[result])
        return 0
    except StoreError as exc:
        print(f"沙盒操作停止 [{exc.code}]：{exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError:
        print("沙盒文件操作失败：请检查目录、权限、磁盘空间及同一文件系统条件；保留现有材料，勿盲目重试。", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("沙盒操作已中断；请先检查 sandbox status，再决定继续或取消。", file=sys.stderr)
        return 130
