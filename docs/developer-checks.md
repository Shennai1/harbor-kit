# 开发回归与交付检查

本入口用于独立开发环境，不是 VPS 健康检查、安装器或部署验收。不要在生产 VPS 上运行测试集。
使用普通用户、POSIX 系统、Python 3.11+、OpenSSL 命令行及支持 TLS 1.3 的 Python。
测试会创建临时文件、子进程和一次性测试证书，并使用 IPv4 回环监听；需要允许本机连接。
节点服务、APT、Cloudflare 和 CA 操作使用测试替身，不需要真实 Token 或 SSH 凭据。
这不是阻止任意代码访问网络/主机的安全沙箱；仅在已审查源码及可丢弃测试环境运行。

## 统一入口

从可信源码目录运行：

```bash
python3 -E -s -B -m tools.check
```

入口首先核对公开文件白名单、基础敏感模式、Python 源码完整性及 Python 3.11 语法。
新增代码或测试没有加入交付清单会失败，不悄悄漏掉文件。
然后检查 OpenSSL 与本机监听能力，执行 tests/test_*.py 全集，最后复查公开源码摘要。
不下载软件、不安装依赖、不发布、不自动修复，不提供跳过 TLS 或只跑部分测试的成功通道。
缺失环境、发现失败、零测试、跳过测试或检查期间源码改变均返回非零状态。
测试输出在 stderr，最后汇总 JSON 在 stdout；不自动保存或上传日志。
测试成功不证明真实系统安装、断线恢复、长期运行或安全审计通过。

## GitHub 自动检查

.github/workflows/check.yml 已经获批发布；首次云端运行发现两项文件替换测试失败。
修正测试构造后，[固定提交 99aabcb 的云端运行](https://github.com/Shennai1/harbor-kit/actions/runs/44496609800)
在 Python 3.11.18 和 3.13.18 上各完成 1657 项，零失败、错误或跳过；这不是后续任意提交的验收证明。
[后续固定提交 07d42f1 的云端运行](https://github.com/Shennai1/harbor-kit/actions/runs/44590773500)
在两种 Python 上各完成 1670 项，零失败、错误或跳过；该结果覆盖已经发布的源码打包工具，
不覆盖本地新增的固定提交源码获取入口。后者须另行获批发布并在对应提交复测。
在 main 推送、普通 pull_request 和手动触发时执行，使用 GitHub 托管 Ubuntu 24.04，
分别测试 Python 3.11 和 3.13；不是 Debian 12/13 部署支持矩阵，不扩展已验收平台范围。
不使用 self-hosted、pull_request_target、sudo、项目秘密或 SSH；只有 contents: read 权限。
检出代码不保留凭据，官方 checkout/setup-python 固定完整提交，而不是浮动版本标签。
每任务最多 20 分钟，同一分支新的检查取消旧检查；不会取消 VPS 或用户本机任务。
云端准备 runner/Python 会联网；回归入口本身不查询上游、Cloudflare 或 CA。
没有自动发布、Release、附件上传或部署步骤。后续修复发布仍需独立批准。

固定 Actions 版本核对及最小权限依据：
[GitHub 安全指南](https://docs.github.com/en/actions/reference/security/secure-use)、
[checkout](https://github.com/actions/checkout)、[setup-python](https://github.com/actions/setup-python)。
完整提交锁定不能替代内容审查；托管镜像和 Python 小版本仍可能更新。

## 文件替换测试边界

同内容替换测试必须先保证设备号/inode 确实改变，不能假定删除后重建必然取得新编号。
测试保留旧文件的打开句柄，重建后断言内容相同、身份不同，再验证操作被拒绝且没有变更命令。
打开句柄会保留已解除目录链接的文件，直到句柄关闭，参见 [Linux unlink 手册](https://man7.org/linux/man-pages/man2/unlink.2.html)。
运行代码的设备号/inode 与内容摘要核对不是完整变更历史：旧编号回收后，若编号、内容及其他受检属性均一致，
不能据此证明文件从未被删除重建，也不能防御并发恶意 root 操作；本批测试修正不改变这一边界。

## 交付关卡

本地全集通过后再请求发布批准。发布时仍需逐文件核对允许范围、固定提交和下载归档摘要，
并用实际下载的源码复跑检查。CI 通过不自动授权修改 VPS，也不自动产生正式发行版。
不把私人笔记、work、运行配置、密钥或诊断日志纳入公开文件。
本地[源码交付包](source-bundle.md)沿用同一白名单；打包不会运行测试或自动取得发布授权。
