# Cloudflare API Token 更换（实验版）

只接受本工具完整部署且当前核查通过的 Debian 13 / amd64 / IPv4 TCP 单节点 main。
更换正常路径目前只有本地测试，系统命令、Cloudflare、ACME 和此流程的 TLS 探针使用模拟依赖；
首次 Token 更换的 VPS 实测未完成；后续独立诊断出现 TXT 写入认证失败，用户确认候选原为 DNS 读取权限。
用户将同一令牌改为 DNS 编辑后，候选 DNS 演练、钩子及后置核查已实机通过；正式凭据仍未替换、续期仍暂停。
原更换输出缺失，不能证明首次失败只有这一原因。正常更换及恢复续期路径仍未验收。
不把此前节点可用或端口验收作为凭据续期证据。

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
没有通用恢复命令。下面的受限接续仅处理权限复测已经通过且正式替换尚未发生的状态。
节点仍能使用不代表自动续期正常，必须核查并恢复续期。

### 未替换候选的单次诊断

`python3 -E -s -B -m snellctl diagnose-token --experimental` 是单独诊断，不是重试更换或恢复入口。
仅接受有效的 Token 更换意图、正式凭据匹配更换前指纹、候选匹配更换后指纹、
timer 已 disabled/inactive、Certbot 服务空闲，以及受管配置/证书/服务/UFW 核查通过的现场。
其他密钥或端口待核查状态、替换已发生、残留临时文件均拒绝。普通导出和管理入口的阻断保持。

- 先只读核查，再用 `[y/n]` 确认；不接收新 Token，不提供自动确认参数。
- 只调用一次现有候选路径的 staging 续期演练，明确关闭随机等待，但保留 60 秒 DNS 传播等待和 600 秒命令超时。
  会访问 Cloudflare/测试 CA、增删验证 TXT，并通过已核对的既有钩子重载 Nginx。
- 使用独立日志目录，不轮转原 `/var/log/letsencrypt` 日志。更换日志位置和关闭随机等待意味着它不是原失败的完全重放。
  本次通过只能证明本次演练结果，不能据此解释上一次失败或宣布更换已完成。
- 不替换正式凭据，不主动修改正式证书/续期配置，不启停节点，不调整 SSH/UFW，不恢复 timer，不删除任何原更换标记或候选。
  演练后检查这些文件和服务状态；漂移只报告，不自动修复。
- 输出直接退出码、执行是否不确定、固定错误类别/errno、DNS/钩子证据和复核结果；不打印原始异常或命令输出。
  适配器超时/中断等不确定返回不冒充真实退出码；此时捕获的输出可能不可用，远端 TXT 状态也须检查。
- root-only 状态文件为 `preparation/token-diagnostic-started.json` 和 `token-diagnostic-report.json`。
  独立日志为 `/var/lib/snellctl/preparation/token-diagnostic-logs/`（0700），
  `command-output.txt`（0600）及 Certbot 日志可能含敏感信息，不要上传；只分享 JSON 报告。
  报告落盘失败会注明 `report_saved=false`，终端仍尝试显示结果。
- 诊断开始后阻止重复执行，即使第一次不完整也不自动重试。不要通过删除诊断记录绕过。
  没有新增通用恢复功能，自动续期仍需在后续人工核查后恢复，不能长期忽略。

该诊断的实机失败路径已取得明确 API 错误及后置核查结果；尚未取得成功演练或更换完成证据。

### 同一令牌权限修正后的单次复测

在 Cloudflare 修正同一令牌的目标区域 DNS 编辑权限后，可明确选择：

```bash
python3 -E -s -B -m snellctl diagnose-token --experimental --after-permission-fix
```

- 不重新输入令牌。若重新生成了令牌字符串而不是修改原令牌权限，不适用此入口。
- 只接受原诊断退出码 1、已保存报告、前次后置核查/续期暂停确认通过，且保存输出明确是
  `10000 Authentication error` 的 TXT 添加失败，尚未到 DNS 传播或钩子执行阶段。
  会交叉核对原报告与输出、部署绑定及凭据指纹；不接受超时、不确定执行或其他错误。
- 继续执行全部现时配置、证书、服务、UFW 和定时器核查，并重新要求 `[y/n]` 确认。
  工具不能从本地证明云端权限已经修正；用户确认后只执行一次 staging DNS 演练。
- 原诊断和日志不变，新记录为 `token-permission-recheck-started.json`、
  `token-permission-recheck-report.json`；独立日志为同状态目录下的 `token-permission-recheck-logs/`。
  目录 0700、输出和记录 0600，原始日志仍不得分享。已存在新记录或日志则拒绝，不自动第三次尝试。
- 和原诊断一样，不提交凭据、不清理候选/意图、不恢复自动续期。
  成功结果仍是 `candidate-probe-passed-not-committed`；后续须另行核查并完成更换/恢复，不能据此撤销旧令牌。

权限复测已实机通过；该结果不是正式替换、定时续期恢复或真实到期轮换的验收。

### 复测通过后的受限接续

```bash
python3 -E -s -B -m snellctl resume-token --experimental
```

仅在上述权限复测成功、旧凭据仍匹配意图的 before 指纹、候选仍匹配 after 指纹、
定时器 disabled/inactive、Certbot 服务空闲且受管配置/证书/服务/UFW 仍符合预期时提供。
必须存在两次完整诊断记录及输出，且复测的 DNS/传播/重载/模拟成功证据完整、没有已识别错误。
交互确认期间再次核对文件身份和内容；不接受已经开始过接续、已替换凭据或其他待核查变更。

1. `[y/n]` 明确确认替换凭据、执行演练、恢复自动续期；不要求重新输入 Token。
2. 新建 `token-resume-started.json`（0600），保留原意图及诊断记录。原子替换正式凭据，仍为 0600。
3. 从正式凭据路径执行一次 staging DNS 演练和既有 Nginx 重载钩子，不再重复候选演练。
   关闭随机等待，传播等待 60 秒、命令最长 600 秒；正式证书及续期路径必须保持不变。
4. 完整后置核查通过后，更新 `credential-current.json`，核对并删除本次候选。
5. 启用定时器并核查服务/配置/防火墙及凭据记录，最后按身份核对删除原 Token 更换意图。
   定时器启用后可能发生真实到期续签，此时核查有效的运行证书，不要求旧证书字节永远不变。

本次报告为 `token-resume-report.json`，独立日志为 `token-resume-logs/`（0700），
`command-output.txt` 为 0600；都位于 `/var/lib/snellctl/preparation/`。
JSON 只包含固定阶段、状态、退出码和脱敏证据；原始日志可能敏感，不要上传。
历史诊断和接续记录保留，未提供自动轮转或通用清理。仅本次候选和更换意图在完成时移除。

失败不自动回退、不覆盖外部修改、不重试或清理现场；尝试停用续期，但不杀死正在执行的 Certbot。
正式凭据可能已替换，候选也可能已清理；报告的 `fixed_credential_matches` 和暂停复核结果须结合现场判断。
`SIGKILL`、断电及部分 SSH 终止可能绕过错误处理，不承诺失败时定时器必然已停用。
接续记录存在即拒绝重跑，不要删除记录绕过。只有 `token-changed-renewal-tested` 才表示此轮完成；
报告保存失败会明确 `report_saved=false`，不能将历史安装记录当作本次健康证明。
此接续目前仅有本地模拟流程测试，尚待实机验收，不改动 Snell/ShadowTLS 密钥、端口或 SSH/UFW。

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
