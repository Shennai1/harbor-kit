"""Opt-in first restoration of the original successful package installation."""

import json

from .installer import Terminal, confirm
from .packagecontents import require
from .packageflow import PackageFlow
from .packageprompts import PackagePrompts
from .packagesubmit import read_active_job
from .tokenchange import real_token_change


def run_package_resume(*, factory=real_token_change, terminal=None):
    ui = terminal if terminal is not None else Terminal()
    if not ui.interactive():
        return 2
    report = {"format": 1, "operation": "package-restoration-resume", "result": "inspection-required",
              "host_changes_attempted": False, "installation_submission_attempted": False,
              "upgrade_completed": False, "external_acceptance_required": True,
              "automatic_retry": False, "report_saved": False, "phase": "active-task-selection"}
    try:
        ui.say("实验版安装后受限恢复：只处理同次开机中原安装已明确成功、且从未尝试恢复的任务。")
        ui.say("先只读核查原记录及现场；会读取受限配置、凭据和证书作内存核验，不显示秘密或读取原始日志。")
        ui.say("不重新安装、下载或提交后台任务，不接续部分恢复；已重启、记录不全或现场改变将停止。")
        ui.say("确认后可能启动 Nginx、执行 DNS 演练并恢复续期；失败不回退或重试，保留剩余保护和现场。")
        ui.say("请保持连接，不并行运行 APT/Certbot 或其他管理操作；本入口尚未实机恢复验收。")
        if not confirm(ui, "确认先核查原任务，后续恢复及 DNS/续期仍分别确认？"):
            return 130
        require(ui.interactive())
        with factory() as tokens:
            with tokens.prep._lock():
                job, _stamp = read_active_job(tokens.files)
            prompts = PackagePrompts(ui, job)
            def decision(stage):
                require(ui.interactive())
                if stage == "restore":
                    for item in job.changes:
                        ui.say(f"原任务：{item.name}: {item.before} -> {item.after}")
                    if not confirm(ui, "已确认独立 SSH 新连接和恢复控制台可用？"):
                        return False
                    require(ui.interactive())
                approved = prompts(stage)
                require(ui.interactive())
                return approved
            flow = PackageFlow(tokens, progress=lambda phase: ui.say("恢复阶段：" + phase))
            report = flow.resume_staged(job, confirm=decision)
    except (EOFError, KeyboardInterrupt):
        report["result"] = "interrupted-inspection-required"
    except Exception:
        pass
    ui.say(json.dumps(report, ensure_ascii=False, indent=2))
    if report["result"] == "packages-restored-external-test-required":
        ui.say("原安装后的本机服务及续期验收通过；没有重新安装。仍需客户端使用及重启验收，不自动重启。")
        return 0
    if report["host_changes_attempted"]:
        ui.say("恢复未确认完成，可能部分恢复，剩余保护和记录保留；不要重试、重启、删标记或手动解除保护。")
    else:
        ui.say("本次未开始恢复，原服务及保护未由本命令改变；取消不等于回滚安装，请及时核查停用状态。")
    ui.say("只分享最后的脱敏 JSON；不是通用修复入口，也不会重试原安装任务。")
    return 130 if report["result"].startswith(("cancelled-", "interrupted-")) else 1
