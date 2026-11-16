"""Chinese staged confirmations, shared with the opt-in operator adapter."""

from .hostprep import PreparationError
from .installer import confirm
from .packagejob import JobSpec


QUESTIONS = {
    "download": ("将重新核对官方索引并下载精确版本，保留独立缓存；这一步不安装或停机。",
                 "确认联网检查并下载待审查的软件包？"),
    "outage": ("软件包内容须已独立审查。随后将暂停续期并停止 Nginx，新节点握手会暂时不可用。"
               "拒绝安装前的确认不会进入停机；请勿并行运行其他管理操作。",
               "已确认独立 SSH 和恢复控制台可用，并接受本次维护停机？"),
    "install": ("仅升级列出的 Debian 修订版本；不会升级 Snell/ShadowTLS、修改密钥、端口或 SSH/UFW。"
                "后台任务只提交一次；失败或断线不自动重试、回退、解除保护或重启。",
                "确认安装这些已审查的精确版本？"),
    "restore": ("后台安装已明确成功退出，但尚未完成配置、TLS 和续期验收。"
                "此时取消不会回滚安装，Nginx/续期可能仍停用，必须及时核查。",
                "确认执行安装后核查并恢复服务？"),
    "dns-test": ("将访问 Cloudflare/测试 CA、增删验证 TXT 并重载 Nginx；演练不替换正式证书。",
                 "确认执行 DNS 续期演练？"),
    "renewal": ("验收通过后恢复正式定时续期，可能发生真实到期签发；仍需客户端及重启验收。"
                "没有自动重启或失败回退。",
                "确认验收通过后恢复自动续期？"),
}


class PackagePrompts:
    def __init__(self, ui, job):
        if type(job) is not JobSpec or not ui.interactive():
            raise PreparationError("更新确认必须来自交互终端及本轮受限任务。")
        self.ui, self.job = ui, job

    def __call__(self, stage):
        if stage not in QUESTIONS or not self.ui.interactive():
            raise PreparationError("更新确认阶段或终端状态不受支持。")
        if stage in {"download", "install"}:
            for item in self.job.changes:
                self.ui.say(f"{item.name}: {item.before} -> {item.after}")
        message, question = QUESTIONS[stage]
        self.ui.say(message)
        return confirm(self.ui, question)
