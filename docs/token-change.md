# Cloudflare API Token 更换（实验版）

只接受本工具完整部署且当前核查通过的 Debian 13 / amd64 / IPv4 TCP 单节点 main。
当前仅有本地测试，系统命令、Cloudflare、ACME 和此流程的 TLS 探针使用模拟依赖；
尚未进行 Token 更换的 VPS 实测，不把此前节点可用或端口验收作为凭据续期证据。

## 入口与确认

取得经校验的固定版本源码，在部署主机的 root 交互终端执行：

```bash
python3 -E -s -B -m snellctl change-token --experimental
```

也可进入 `menu --experimental` 选择 10。普通菜单不显示此项。
不接受 Token 参数、管道、重定向、`--yes` 或强制执行选项。
风险说明后用 `[y/n]` 确认；仅 `y`/`Y` 继续，回车、`n` 或其他输入取消。
Token 采用隐藏输入，不要求向 AI、聊天或 GitHub 发送令牌。

先在 Cloudflare 创建新令牌，限制到当前证书所属区域的 DNS 编辑权限；不要先撤销旧令牌。
不能只凭 Token 的 valid/active 判断域名权限足够；本功能要求新凭据实际完成 DNS-01 演练。
不更改域名或区域、不创建 A/AAAA、不修改橙云状态，也不通过 API 创建或撤销令牌。

## 验证和替换

1. 只读核对当前配置、完成记录、受限凭据目录、正式证书、服务、UFW 和续期任务。
   已有待核查标记、候选文件、配置漂移、Certbot 活跃或排队任务均停止。
2. 隐藏输入新 Token 后重新加锁并核对现场；同一 Token 拒绝重复更换。
3. 写入待核查记录，停止并禁用 `certbot.timer`，确认 Certbot 服务空闲。
   不杀死正在执行的 Certbot；须避免另一个终端同时运行 Certbot 或修改配置。
4. 将新 Token 写入 root-only 临时文件，当前凭据保持不动。
   通过当前证书的 `certbot renew --dry-run`，临时指定候选路径，访问 Let's Encrypt staging。
5. 必须取得新的 DNS-01、传播等待、模拟成功及 Nginx 重载证据，而不是只检查退出码。
   不接受复用授权警告或已识别的 TXT 删除错误。之后核对正式证书、续期配置及服务仍符合预期。
6. 用同目录原子替换更新固定凭据路径，再通过该路径执行第二次 DNS/重载演练。
   不修改 Certbot 保存的凭据路径，不强制正式签发，不替换节点密钥或域名。
7. 保存当前凭据身份和指纹，删除本次候选文件，恢复定时续期并核对服务状态，最后移除待核查标记。
   恢复 timer 时可能触发已到期的正常续签，不宣称全程不会联系正式 CA。

两次 DNS 演练各等待 60 秒传播，整轮通常还需额外网络处理时间。
会在 Cloudflare 增删 ACME 验证 TXT，并由 Certbot 写入其正常日志/账户状态；这不是纯本地操作。
Nginx 重载会执行已有受管钩子，使用当前正式证书，不加载测试证书。
不会停止 Snell/ShadowTLS、修改 UFW/SSH、重装软件、变更节点端口或更新 Surge。

## 凭据与记录

- 当前凭据：`/etc/snellctl/credentials/cloudflare-main.ini`，root:root 0600，父目录 0700。
- 临时候选：同目录的 `cloudflare-main.candidate.ini`，0600，成功后删除；失败保留供人工检查。
- 更换意图：`/var/lib/snellctl/preparation/token-change-intent.json`，0600，含参数摘要及新旧内容指纹，不含明文 Token。
- 当前指纹：同状态目录的 `credential-current.json`，0600；成功后更新，不保存旧 Token 副本或完整配置数据库。

早期安装器没有单独登记凭据身份。第一次更换只在完整受管节点、固定续期引用、凭据格式和权限均通过时接受当前文件，
不宣称能证明它从安装以来从未被改动；后续更换须匹配最近的凭据身份记录。
删除文件不等于从磁盘、快照或内存安全擦除。不要公开凭据文件或 Certbot 原始日志。

## 失败与中断

第一次演练前后失败时，旧凭据通常仍在原路径；替换后失败时，原路径可能已经是新 Token。
程序不自动回退、不备份旧 Token、不自动重复 DNS 请求、不删除不确定的 TXT 或候选文件。
错误处理会尝试停止并禁用自动续期，但不会停用正在工作的节点，也不会杀死正在签发的任务。
若停用失败会报告结果不确定；`SIGKILL`、断电或未处理的 SSH 终止可能绕过错误处理。
标记不是开机拦截器；不得据标记猜测当前凭据、TXT 清理情况或 timer 状态。

存在意图时，当前版本的导出、密钥/端口/Token 更换与公网启用拒绝继续。
`install-status` 和 `cleanup-plan` 会提示 Token 更换待核查与续期风险。
保留独立 SSH、新旧令牌和现场，先检查当前服务、timer 及脱敏记录；不要删除意图、重跑、重启或用旧工具绕过。
没有通用恢复命令。节点仍能使用不代表自动续期正常，必须核查并恢复续期。

成功后也不自动撤销旧 Token：确认新令牌及本机状态正常，且旧 Token 不再供其他用途使用，再由用户到 Cloudflare 撤销。
当前实现不独立查询 DNS 来证明所有 TXT 已删除，异常时须核查残留；不承诺未来权限/域名不变或到期必然续签成功。

## 实机验收待办

- 新 Token 的两次 DNS 演练、钩子及本机 TLS 检查通过，正式证书和续期路径保持。
- 新凭据权限正确，候选与意图已移除，timer 已恢复，服务/端口/UFW 未改变。
- 原 Surge 配置仍可使用；不重新导出含密钥配置作为 Token 验证。
- 撤销旧令牌前确认其没有其他用途；真实到期续签及中断恢复另行验收，不在工作节点制造失败。

依据：[Certbot DNS Cloudflare 凭据](https://certbot-dns-cloudflare.readthedocs.io/en/stable/)、
[Certbot 续期演练和钩子](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates)、
[Certbot 4.0 新授权处理](https://github.com/certbot/certbot/blob/v4.0.0/certbot/certbot/_internal/client.py)、
[Cloudflare 插件的 TXT 清理边界](https://github.com/certbot/certbot/blob/v4.0.0/certbot-dns-cloudflare/certbot_dns_cloudflare/_internal/dns_cloudflare.py)。
