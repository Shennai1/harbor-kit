# 软件包与证书准备引擎

内部执行模块 `hostprep.py` 与 `hostcommands.py` 已连接显式开启的[实验安装向导](install-wizard.md)。
**不要在现有节点上通过 Python 导入并手动调用这些内部方法。**
真实执行适配器具备更改 Debian 主机的能力；默认只读菜单不代表实验安装也是只读的。
本批只在隔离目录、模拟系统命令和无害的本地子进程中测试，没有连接 VPS、CF 或 ACME。

## 操作边界

准备流程拆分为初始化、软件包准备、凭据写入、DNS 演练、正式签发五个方法，
每一步独立检查，失败不进入下一步。上层向导先执行新机预检查，
确认 UFW、SSH、端口和文件归属，再请求用户授权；串联已完成，尚待 Debian 实机验收。

真实执行适配器只允许 Debian 13 / amd64、root 且存在 systemd 运行环境。
不通过 shell 执行拼接的命令，不从调用者继承环境变量，外部命令输出不直接打印。
测试可注入模拟执行器，但不能因此声称 APT/systemd 实机验收通过。

## 软件准备

1. 拒绝已有 Nginx、Certbot 配置、目标 unit/mask、凭据目录、准备记录或 `policy-rc.d`。
   不删除、覆盖或假定原有 mask 由本工具创建。
2. 要求当前所有 APT 源刷新成功。源失效时停止，不自动删源、放松签名验证或升级内核。
3. 在单独的索引目录刷新限定 Debian 官方 HTTPS 源，明确使用 Debian 归档密钥环。
   不改 `/etc/apt/sources.list*`，不从第三方源选择这批待安装包；保留 APT 的默认降权下载机制。
4. 根据该次索引选择版本，先模拟依赖；涉及删除现有包或模拟失败时停止。
   实际安装指定本次候选版本并禁止移除包，不执行全面升级、自动清理或 pip 升级。
5. 在包安装前记录意图，创建仅拦截 Nginx/Certbot 的临时服务启动策略，
   并持久 mask `nginx.service`、`certbot.service`、`certbot.timer`。
   确认三者均 masked/inactive 后才安装，安装后再次核对。
6. 核对软件包完整配置及版本后记录成功。重复调用只检查，不重新安装。

专用包清单目前为 CA 证书、Nginx、Certbot 和 Cloudflare DNS 插件，
因此仍可能安装或更新它们必需的依赖，不保证整个系统其他文件毫无变化。
HTTPS 软件源访问要求主机已有可用的系统 CA、正确时间和网络。
独立索引只限定该次包选择；系统原有 APT 配置和可信根仍属管理者的信任边界，
并不能防御已被篡改的 root 环境或恶意包管理钩子。
应避免同时运行其他包管理或部署操作，工具自己的锁不能代替全系统变更协调。

Debian 13 的官方归档密钥环可能将 `debian-archive-keyring.gpg` 作为指向同目录
`debian-archive-keyring.pgp` 的兼容链接。准备引擎接受普通 `.gpg` 文件，或该唯一目标的
相对/绝对链接；链接本身仍须属于当前管理身份，目标仍须通过普通文件、归属、权限、
链接数和大小检查，不递归跟随其他链接，也不改变系统密钥环或放松 APT 签名验证。
旧代码会拒绝这个官方链接；本地回归测试已覆盖修复，具体 VPS 停止原因仍应结合本机状态核对。

**本阶段结束后启动保护仍保留。** 它不仅阻止开机启动，也阻止正常的服务启动请求。
这是尚未配置本机 HTTPS 站点时的预期状态，不是节点已部署完成。
后续本机激活模块会核对保护文件身份、完成站点与服务配置检查，再受控解除 Nginx 保护；
当前没有通用“删除全部 mask”或自动回滚卸载功能。

## 凭据与证书

- CF Token 只写入 `/etc/snellctl/credentials/cloudflare-main.ini`，目录 `0700`、文件 `0600`。
  该文件是续期所需的运行凭据，不写进命令参数、状态记录或第二份秘密数据库。
  现有文件不覆盖；Token 轮换及终端隐藏输入界面还没有接入。
- 签发只使用 Certbot 的 Cloudflare DNS-01 和 `certonly`，不使用 Nginx 安装插件、
  不开放入站端口、不启用公网默认站点。CF Token 的有效性通过实际 DNS 演练确认，
  本批自动测试使用假 Token，没有访问账户。
- Certbot 子进程使用隔离的 HOME；拒绝非预期全局签发参数、继承的钩子和其他凭据。
  本阶段禁用目录钩子，后续激活续期时需重新检查钩子和保存的续期设置。
- DNS 演练显式使用 Let's Encrypt staging，正式签发显式使用 production。
  正式签发须同一域名的演练成功、明确同意 CA 条款、另行确认正式申请。
  当前内部接口采用不提供邮箱的注册方式，未来菜单应向用户说明此选择。
- 已有 lineage、归档或续期配置不自动认领；已有成功记录则复核，不重复申请。
  初次正式签发会公开证书中的域名，不能把 DNS-01 当成隐藏域名的机制。

正式签发返回成功后还需检查：

- live 链接只能指向本域名的 Certbot archive，私钥须为本机所有者的 `0600` 普通文件。
- fullchain 与叶证书、链文件一致；证书剩余有效期至少七天。
- 系统受信 CA 验证证书链、域名和服务器用途，并比较证书公钥与私钥导出的公钥。
- 续期配置仍使用本次 Cloudflare 凭据路径、production ACME 和 ECDSA，且没有非预期安装器或钩子。

这些检查不证明 Nginx 已加载证书，也不证明客户端节点可用。
本准备阶段的证书定时器仍被保护阻止启动；自动续期由后续独立的公网启用阶段处理，不能仅凭签发成功认为已启用。
后续本机激活模块已接入作用范围受限的部署钩子、重载后的运行证书对比及模拟续期检查，尚待 Debian 联调。
Certbot 自己仍可能保留日志与 ACME 账户数据，本工具不承诺系统无日志。

## 状态与中断

`/var/lib/snellctl/preparation` 保存权限受限的非秘密阶段记录和锁文件；
`/var/lib/snellctl/apt-lists` 是单独的 APT 索引目录。
记录包含包版本、启动保护文件的身份及域名摘要，不含 Token、节点密钥或证书私钥。
域名摘要只是减少直接暴露，不应视为加密或匿名化。

- 更新源失败且尚未创建保护时，可重新检查后尝试；不会在已知源失败时继续安装。
- 创建保护、安装软件、DNS 演练和正式签发前均有意图记录。
- 已有意图但没有成功记录，视为结果不确定；禁止自动重试或删除现场。
  即使证书文件已出现，也可能是 CA 成功而后续检查失败，不能盲目再申请一次。
- 命令超时或执行被中断会停止后续步骤。超时不等于远端操作没有完成。
- `status()` 只报告已记录的进度，不把记录等同当前服务健康、部署成功或续期启用。
- 原始命令输出不复制进诊断。恢复时应在主机核对包管理状态、守护进程、证书及 TXT 清理结果，
  不把未经脱敏的日志交给公开平台。

目前中断恢复采取保守停止，尚无自动恢复入口；不要删除状态记录强行重新签发。
无法通过本地回滚撤销已消耗的 CA 配额、远端 DNS 操作或包安装副作用。

## 本批验证与下一步

准备阶段完成时测试套件共 179 项通过，其中 52 项涉及准备流程与执行器；最新总数见项目 README。
验证了真实临时目录中的权限、冲突保护、阶段顺序、重复操作和失败停止；
真实执行了服务策略脚本的无副作用返回值测试，以及无害子进程的超时退出、环境隔离和输出限制测试。
APT/systemd/CF/ACME 和证书验收命令由模拟器响应，不是真实软件安装、域名验证或证书验证。
当前 Mac 的系统 LibreSSL 缺少目标 Debian OpenSSL 的部分验证选项，没有把它替代为放宽校验的命令。

后续进展见 [本机激活与续期演练](local-activation.md)：配置写入、本机启动与 TLS/续期检查已接入内部控制器。
后续 [公网启用模块](public-enablement.md) 已补上定时任务环境和 UFW 增量放行的内部实现；上层安装流程与 Debian 实机联调仍待完成。
在此之前不发布正式远程安装命令，也不要求修改已正常工作的节点。

## 官方依据

- [Debian 13 密钥环构建与兼容链接](https://sources.debian.org/src/debian-archive-keyring/2025.1/Makefile/)
- [Debian 服务启动策略](https://manpages.debian.org/trixie/init-system-helpers/invoke-rc.d.8.en.html)
- [systemctl mask 行为](https://manpages.debian.org/trixie/systemd/systemctl.1.en.html)
- [APT 安装与模拟选项](https://manpages.debian.org/trixie/apt/apt-get.8.en.html)
- [Certbot 使用指南](https://eff-certbot.readthedocs.io/en/stable/using.html)
- [Cloudflare DNS 插件与凭据](https://certbot-dns-cloudflare.readthedocs.io/en/stable/)
- [Certbot 4.0.0 测试服务器选择](https://github.com/certbot/certbot/blob/v4.0.0/certbot/certbot/_internal/cli/cli_utils.py)
