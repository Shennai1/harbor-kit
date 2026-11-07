# 组件更新边界与版本基线

当前仍没有升级执行器。本轮集中版本元数据、增加离线版本比较，不更新运行中的节点。
这不是组件维护完成，也不是只改一个版本号就能安全升级的承诺。

## 已实现的基础

`snellctl/releases.py` 集中两个已审核程序的版本、下载地址、基线 SHA256、文件格式、
安装路径、版本输出前缀及协议版本。下载器、服务模板、安装版本校验、执行命令白名单
和客户端导出使用同一份元数据。元数据来自项目审核，不从命令参数、环境变量或网页动态加载。

现有基线仍为 Snell 5.0.1 / 协议 v5 与 ShadowTLS 0.2.25 / 协议 v3。
ShadowTLS 的程序版本不等于协议版本，不能按程序版本的第一段生成客户端协议字段。
现有模板、安装路径、配置绑定摘要、下载清单及客户端导出保持兼容；不迁移或重写历史记录。

版本校验只在既有安装阶段运行已校验程序的 `--version`，不是验证正在运行进程的版本。
拒绝版本后缀、相近前缀或重复/矛盾版本标记；版本输出不是上游签名或安全保证。

## 离线比较

可在本地源码目录运行，不需要 root 或部署主机：

```bash
python3 -B -m snellctl artifacts compare --component snell --current 5.0.1 --target 5.0.1
python3 -B -m snellctl artifacts compare --component snell --current 5.0.1 --target 6.0.0
```

当前和目标版本都是调用者显式提供的数字，不是从主机或网络检测到的结果。
只接受规范的三段数字版本和 `snell` / `shadow-tls`，不接受 `latest`、URL、路径或预发布后缀。
Snell v6 的数字版本即使没有 beta 后缀，也不意味着已经稳定或可用。

- `same-reviewed-version-no-action`：与已审核基线相同，无操作，退出码 0。
- `current-version-not-reviewed`：显式当前版本不在本工具现有基线中，停止。
- `downgrade-not-supported`：不将降级当作自动回退；恢复必须针对已核对现场另行实现。
- `protocol-migration-required`：Snell 目标跨协议大版本，需要独立配置和客户端兼容性验收。
- `target-version-not-reviewed`：包括看似普通补丁的未知版本，不能仅凭版本号允许安装。

后四种结果退出码 1；输入不合法返回 2，不回显无效输入。所有结果始终
`update_implemented=false`、`update_authorized=false`、`update_ready=false`。
比较不读节点配置、Token 或证书，不联网、不下载、不启动进程、不写文件，不输出执行命令。
它没有把任何未知版本加入下载清单，也不提供绕过审核的版本参数。

## 2026-11-07 上游核对

- [Snell 官方发布说明](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell)
  列出了 v6.0.0，并说明处于 beta 测试阶段。它不是现有 v5 的普通补丁，本项目不自动采用。
- [ShadowTLS 官方发布页](https://github.com/ihciah/shadow-tls/releases/latest)
  当日指向 v0.2.25，与项目基线一致。
- [Debian Nginx 安全跟踪](https://security-tracker.debian.org/tracker/source-package/nginx)
  当日列出的 trixie-security 版本为 1.26.3-3+deb13u10。

这些是日期限定的网页观察，不是目标主机签名索引刷新或完整漏洞审计；搜索结果摘要可能比
官方正文旧。不能把上述观察写成永久的“最新版本”，也不因短版本号较低而切换 Debian 发行版。

## 尚待实现

1. 程序更新：候选单独审核、可信下载与文件校验、版本化并存、配置与历史归属记录的兼容迁移、
   有限停机、运行验证以及针对本次变更的恢复。原程序保留不等于任何场景都能自动回退。
2. Debian 软件包更新：签名索引与依赖模拟已有独立[检查入口](package-update-plan.md)，尚待实机验收；
   真正更新仍需审查完整依赖/模块及删除或 hold 变化、包管理启动保护、
   明确批准后更新、检查配置和续期，并更新受管记录。包脚本的副作用不能靠复制文件完整撤销。
3. 实际运行与客户端验收、菜单与快捷入口整合；升级失败和中断路径须独立验证。

目前只支持既有两项固定版本的部署读取。不得通过修改 `BASELINES`、手工替换程序或改安装
记录模拟升级；新版本的执行及记录迁移尚未实现。Nginx/Certbot 不纳入此三段版本比较，
Debian 包的 epoch、修订及 backport 版本不能使用这个比较器判断先后。
