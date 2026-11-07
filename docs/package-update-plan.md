# Debian 更新方案检查

`package-update-plan --experimental` 是交互式检查入口，不是升级执行器。
仅限本工具完整受管的 Debian 13 / amd64 / main。当前只完成本地测试，尚待 Debian 实机验收；
不接入菜单、不安装快捷指令，也不改变已有新机安装路径。

## 授权范围

使用 `[y/n]`，默认取消；不接受自动确认、Token、软件包名、版本或下载地址参数。
确认后会联网并写入独立缓存，因此不能称为纯只读。不会安装、升级、卸载软件、运行 Certbot，
也不会改变节点配置、系统 APT 源和原有索引、SSH/UFW、服务启用状态或自动续期。

在已验证的源码目录中，入口为：

```bash
python3 -E -s -B -m snellctl package-update-plan --experimental
```

没有升级执行入口，不能将报告当作稍后直接安装的授权或固定方案。

## 检查过程

1. 复用只读维护盘点及协作锁，要求四个直接组件仍符合记录、没有 hold，服务状态符合预期。
2. 在 `/var/cache/snellctl/package-review/` 下创建新的随机目录，不复用旧索引。
   只存放公共索引及固定配置，不复制节点配置、Token 或证书。保留 `_apt` 沙箱用户及目录访问条件。
3. 通过 `APT_CONFIG` 在 APT 加载系统片段前指定独立配置，隔离系统源、偏好、代理、认证文件及 hooks。
   只使用 Debian trixie、trixie-updates、trixie-security 的 HTTPS main 源和本机 Debian 公共密钥环。
   保持签名、TLS 和索引有效期验证；刷新失败或出现 APT 警告时停止，不借用陈旧缓存。
4. 查询 `ca-certificates`、`nginx`、`certbot`、`python3-certbot-dns-cloudflare` 的候选，
   用 `dpkg --compare-versions` 比较完整 Debian 版本，拒绝降级。候选必须在本轮官方索引中可见。
5. 固定四项候选做模拟，核对动作与汇总一致，拒绝删除、降级、hold 变化、架构切换及不完整输出。
   对每个拟变化依赖另查官方索引；展示额外依赖变化，但不认定可以自动升级。
6. 复查受管文件、全部包状态查询及服务状态是否变化。不停止并发任务，变化时要求人工复核。

系统自定义更新策略不纳入此方案；忽略偏好不意味着修改或取消原偏好。
它不是整个操作系统的升级建议，也不处理 Snell/ShadowTLS 的程序升级。

## 报告

`package-candidates-reviewed-no-upgrade` 仅表示本次有限检查完成。`proposed_changes=[]` 表示
四个直接目标的这次模拟没有变化，不能推导为全机最新或没有漏洞。
`additional_dependencies_require_review=true` 表示还需审查附带依赖变化及其影响。

失败返回 `blocked-no-upgrade`，只显示阶段及固定原因，不复制原始 APT 输出。
缓存可能已部分写入，通过 `host_changes_attempted`、`cache_state` 说明；不自动删除或重试。
没有持久化报告或新部署归属记录，已有维护记录不改变。

所有结果均保持 `update_implemented=false`、`update_authorized=false`、`update_ready=false`。
成功退出码 0，阻断为 1，取消为 130，缺少实验开关或非交互终端为 2。只分享最后 JSON。

## 限制

签名校验依赖本机可信 APT 程序和 Debian 公共密钥环，不重新证明历史安装包来源，也不查询漏洞库。
模拟不是执行，尚未包含升级启动保护、维护记录迁移、Nginx 模块兼容审查和升级后的 TLS/客户端验收。
服务观察不是健康判定；本入口不读取证书或验证公网连接。

锁只约束本工具，不阻止外部 root、软件包管理器或续期操作。检查期间不要并行管理。
输出解析严格限制已支持格式；不能识别的输出会停止，不能把解析失败当作无更新。
每次检查的索引缓存都会保留，重复检查会占用额外磁盘；本阶段未提供自动缓存清理功能。
新缓存不在节点归属目录内，不能把其存在视为节点已安装或可以升级。

## 依据

[APT 配置加载顺序](https://manpages.debian.org/trixie/apt/apt.conf.5.en.html)说明
`APT_CONFIG` 先于系统配置，命令行选项在后；仅使用 `-o` 不足以确保系统 hooks 从未加载。
[apt-get 文档](https://manpages.debian.org/trixie/apt/apt-get.8.en.html)说明模拟与指定版本安装的边界，
[apt-cache 文档](https://manpages.debian.org/trixie/apt/apt-cache.8.en.html)说明候选来自缓存。
APT 动作解析参考其官方[模拟实现](https://github.com/Debian/apt/blob/main/apt-pkg/algorithms.cc)，
并严格核对全部动作与汇总；尚不能替代目标系统实测。
