# 更换域名和证书（实验版）

`change-domain --experimental` 或实验菜单 11，面向本工具完整部署、当前健康的
Debian 13 / amd64 / IPv4 TCP 单节点 main。仅有本地模拟流程测试，尚待实机验收。
不接管第三方节点，不升级组件，不提供通用恢复、自动回退或旧资源删除。

## 参数与准备

- 当前域名、端口、节点密钥和 SSH 信息从现有配置与归属记录读取，不使用测试机固定值。
- 在终端输入新完整小写域名；文档的 `other.example.org` 只是示例，`xxx` 不作为真实域名。
- 新域名可以属于不同 Cloudflare 区域；本工具不要求账户与原账户相同，也不保存账户 ID。
  新 Token 必须拥有目标区域的 `Zone:DNS:Edit`，不需要把权限扩大到旧区域。
- 用户自行准备指向本机 IPv4 的 DNS-only A 记录；程序只增删验证 TXT，不创建 A/AAAA 或修改代理状态。
  DNS-01 成功不证明 A 记录正确或公网可达，仍需客户端验证。
- 保留原域名当前有效的令牌及 DNS；不要把上轮已淘汰的 Token 与现用 Token 混淆。
- 先确认独立 SSH 和恢复控制台可用。保持会话，不并行运行 Certbot 或其他 root 管理操作。

从经校验的固定版本源码目录执行：

```bash
python3 -E -s -B -m snellctl change-domain --experimental
```

不接受明文 Token/域名参数、管道输入或自动确认。先显示新旧目标与影响范围，分别用
`[y/n]` 确认 CA 条款、演练通过后的正式签发、独立 SSH 和切换；仅 y/Y 继续，默认取消。
全部确认后才隐藏读取新 Token。正式签发会占用 CA 配额，证书域名进入公开透明度记录。

## 执行范围

1. 加锁复核完整部署、文件归属、证书、续期任务、监听和 UFW，拒绝其他待核查变更及外部改动。
   目标已有证书、凭据、此次操作目录或临时文件时停止，不覆盖、不续接旧操作。
2. 写入域名更换意图，暂停续期定时器，确认 Certbot 空闲。不会杀死正在签发的 Certbot。
3. 将新 Token 保存到独立永久路径，先进行新域名 staging DNS 演练，再正式申请一张独立证书。
   这个阶段保留原 Nginx 配置、原证书和原凭据；每个阶段之后重新核查。
4. 新证书的域名、有效期、证书链、私钥对应及续期引用通过检查后，更新 Nginx、限定域名的续期钩子和定时任务。
   仅重载 Nginx，不重启 Snell/ShadowTLS、不改节点密钥或任何端口、不增删 SSH/UFW 规则。
5. 检查新域名 TLS 1.3、运行与磁盘证书一致、HTTPS 404，以及错误/缺失 SNI 拒绝。
   Nginx 重载是异步的，会有限等待本机 TLS 生效；不重复签发、重载或其他变更命令。
6. 使用新域名的永久凭据路径进行一次续期演练，要求实际 DNS 验证及 Nginx 重载证据。
   DNS 传播等待 60 秒，每条证书命令最长 600 秒，续期演练关闭随机等待。
7. 更新当前归属记录，启用定时器并复核，最后清理本次意图。仍需客户端验收。

成功结果是 `domain-changed-external-test-required`。使用本项目 IP 形式的 Surge 配置时，
只更换 `shadow-tls-sni` 为输入的新域名，IP、端口和两项节点密钥不变。
验证新连接的延迟与实际使用；既有连接可能继续存在，不能据旧长连接判断 SNI 切换是否生效。
若用户自行把客户端服务器地址改成了域名，需要另行处理该地址和 DNS。

## 文件与后续维护

- 初次部署兼容原有 `cloudflare-main.ini`。更换域名后采用
  `/etc/snellctl/credentials/cloudflare-domain-<完整域名的 SHA-256>.ini`，root:root 0600，父目录 0700。
  该路径被新证书续期配置直接引用，不依赖临时凭据。
- `preparation/domain-current.json` 仅记录当前域名摘要；凭据指纹使用既有 `credential-current.json`。
  后续更换 Token、诊断及受限接续按当前域名选择路径，不再假定原初路径。
- 旧证书及其原凭据不删除、不覆盖。受管定时任务只续期当前新证书，旧证书会自然到期；
  手工执行未限定证书名称的 `certbot renew` 仍可能处理旧证书。
- 可以再次更换到另一个未使用域名；同一目标已存在资源时拒绝，尚不支持直接切回保留的旧域名。
- 每次操作的独立日志目录为 `/var/lib/snellctl/preparation/domain-change-<域名摘要>/`（0700），
  内有 `dns-test/`、`certificate/`、`renewal-test/` 和 `report.json`。输出及报告 0600。
  原始 Certbot 日志可能含敏感数据，只分享最后的脱敏 JSON。
- 正式签发阶段不要求出现演练成功文字，报告里该阶段 `dry_run_success=false` 并非签发失败。
  正式签发通过条件包括命令成功和随后对磁盘证书的检查，不能只看这一布尔值。

## 失败边界

`domain-change-intent.json` 存在时，导出与其他管理变更均停止，不允许删除标记后重跑。
失败不会撤销 Cloudflare Token、删除 DNS 或证书，也不会自动回退已写入的配置。

- 切换尚未开始时：仅在原配置、凭据、证书、归属及防火墙仍一致时尝试恢复旧定时器。
  即使恢复成功，新的部分资源和意图仍保留，必须核查后才能处理。
- 切换开始后：尝试停用续期，保留已更换文件及意图；节点可能仍能用，也可能需要人工修复。
  `switch_attempted=true` 不表示切换成功，不能据此直接修改客户端或撤销旧 Token。
- `SIGKILL`、断电或部分 SSH 终止可能跳过异常处理，标记不是启动拦截器。
  不能承诺失败时续期必定已停用或节点必定可用；以报告和当前状态核查为准。

没有域名更换恢复/清理命令。失败时保留独立 SSH、新旧凭据和现场，不重启、不重跑、
不删除状态目录或手动拼凑恢复；先分享 JSON 并核查定时续期，不能长期保持停用而不处理。

## 实机验收待办

- 跨 CF 区域的新域名 DNS 演练、正式证书及永久路径续期演练通过。
- 新 SNI 的客户端延迟与实际使用正常；节点密钥、端口和 SSH/UFW 保持。
- 意图已清理、服务及定时器正常，随后再独立验收正常重启恢复。
- 旧资源清理、切回已存在域名、真实到期续签、失败恢复和其他平台不在本轮通过范围。

依据：[Certbot Cloudflare 凭据与续期路径](https://certbot-dns-cloudflare.readthedocs.io/en/stable/)、
[Certbot 证书管理](https://eff-certbot.readthedocs.io/en/stable/using.html#managing-certificates)、
[Certbot 4.0 签发流程](https://github.com/certbot/certbot/blob/v4.0.0/certbot/certbot/_internal/main.py)、
[Nginx 配置重载](https://nginx.org/en/docs/control.html)。
