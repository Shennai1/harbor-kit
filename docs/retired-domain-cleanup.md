# 旧域名资源清理

实验入口，尚待实机验收。仅支持本工具完整管理的 Debian 13 / amd64 / IPv4 TCP 单节点 main。
先完成 `domain-inventory`、`retired-domain-plan` 的有限检查，再在已校验源码的 root SSH 终端执行：

```bash
python3 -E -s -B -m snellctl clean-retired-domain --experimental
```

也可从实验菜单 14 进入；普通菜单不提供删除操作。没有自动确认、域名或目录命令行参数。
不会安装常驻管理命令或修改快捷入口。

清理确认前的只读复核：

```bash
python3 -E -s -B -m snellctl clean-retired-domain --check-only
```

此模式与 `--experimental` 互斥，不提供删除入口，不暂停续期、不执行 Certbot、不修复权限，
不保存新状态或诊断日志。输入同一个旧完整域名并确认只读检查后，输出脱敏阶段、原因和结果。
现用受限配置只用于内存校验；本机 TLS 检查及临时命令输出仍可能产生常规日志，不声称文件系统零写入。
`cleanup-check-passed-no-changes` 只表示本轮完整清理前检查通过，不授权删除。
`linux_style_live_links_checked` 仅是本轮保留范围中按 Linux 0777 形式检查的合法证书链接数，不含域名或路径。

## 确认范围

输入真实旧完整小写域名。现用域名、匿名报告编号、未知或缺失资源均拒绝。
交互预检查后分别用默认取消的 `[y/n]` 确认：

1. 旧证书和本机凭据属于已淘汰节点，且没有其他站点、脚本、容器或任务使用它们。
2. 不可撤销地删除这些本机资源，并在核查通过后恢复自动续期。

只有 y/Y 继续；两次确认都不会询问 Token 或节点密码。早期代码没有完整历史归属清单，
所以管理员声明仍是必要条件，`historical_file_ownership_proven=false` 不会变成 true。
历史关联和有限引用检查不能排除所有全机或外部消费者，不能以“没查到”代替确认。

只删除选定旧域名的 Certbot live/archive 证书组、对应 renewal 配置以及独立本机凭据文件。
保留现用节点、现用证书和凭据、密钥/端口/SNI、SSH/UFW、软件包、ACME 账户和历史日志。
不撤销 Cloudflare Token 或证书，不删除 DNS，不联系旧域名的 Cloudflare/CA 做验证。
删除本机凭据不影响其他机器保存的同一个 Token；不是云端撤销或安全擦除。

## 执行顺序

- 在协作锁下重新执行预检查，要求确认前后部署及目标元数据指纹未变。
- 有界记录其他证书/续期/凭据和 ACME 账户的元数据，不读取旧 Token、旧私钥或账户秘密。
- 先写 root-only 待核查意图，再停止并禁用 `certbot.timer`，确认 Certbot 服务空闲。
  不停止已经运行的 Certbot；存在任务时停止本次清理，保留待核查状态。
- 复查引用、现用健康及文件变化后，只调用一次指定 `--cert-name` 的 `certbot delete`。
  不手动删除 Certbot 目录，不跟随续期配置中的非标准或跨证书组路径。
- 即使退出码为零，也必须确认目标 live/archive/renewal 三条路径全部消失。
  再次验证现用节点与保留资源，旧凭据的元数据及身份仍一致才删除该文件。
- 再次核对目标已消失、保留资源未变、当前 TLS 和配置正常，才恢复定时器并检查实际状态。
  重新启用定时器可能触发当前证书的真实到期续签，因此启用后允许合法的当前证书轮换。
- 成功后删除本次意图，保存脱敏结果。无需修改 Surge，仍需用户测试当前节点延迟与实际使用。

这是不可撤销操作，本轮不额外备份秘密，也不提供通用重试、自动回退或中断恢复。
协作锁和前后检查不能防止其他 root 进程并行改写，执行期间不要并行管理或运行 Certbot。

## 结果和中断

`retired-domain-cleaned`、两个 `*_removed_verified=true`、`renewal_restored_verified=true`，
且 `current_service_health=local-checks-passed` 表示本轮删除和本机验收完成，不代表公网或真实续期已测。

失败给出 `failure_phase`。可能已经删除部分证书，甚至旧资源全部删除但续期恢复未确认。
进入续期操作后失败会尝试保持定时器禁用，不重复删除、不中止现用节点或进行回退。
`renewal_paused_verified_after=false` 在失败报告中表示未确认暂停，不可当成“续期正常”。

`install-status` 的 `retired_cleanup=needs-inspection` 表示待核查；相关管理变更和导出会拒绝继续。
不要删除标记、重跑清理、手动拼凑文件或为排错直接重启。保留独立 SSH，会同报告及时核查续期，
不能长期忽略已暂停的自动续期。断线或强制终止可能来不及输出 JSON，但预先写入的意图仍用于阻止重试。
旧版本代码不知道新增标记，不能换用旧源码继续变更。

本次记录及 Certbot 输出放在准备目录下新建的随机 `retired-cleanup-*` 私有目录。
目录 0700、由本工具写入的文件 0600；原始日志可能含域名和配置路径，仅分享最后 JSON。
不清理历史日志，不声称普通文件删除是物理擦除。`report_saved=false` 表示结果没有成功保存，
须保留终端 JSON 并核查，不能为了补报告重跑删除。

自动测试使用临时文件系统和系统服务/Certbot 模拟器，不直接访问 VPS、Cloudflare 或 ACME。
删除边界依据 [Certbot 安全删除说明](https://eff-certbot.readthedocs.io/en/stable/using.html#safely-deleting-certificates)
及 [Certbot 4.0 存储实现](https://github.com/certbot/certbot/blob/v4.0.0/certbot/certbot/_internal/storage.py)。

## 当前实测与修正

首轮实测停在两次删除确认之前；没有进入续期暂停或删除阶段，不能记作清理成功。
代码随后复现了 Linux 符号链接权限误判：保留资源遍历把链接的 0777 当作普通文件的可写权限。
Linux 普通符号链接的权限位恒为 0777，且不用于访问检查，见 [Linux symlink(7)](https://man7.org/linux/man-pages/man7/symlink.7.html)。
修正只针对证书 live 链接：继续校验所有者、固定文件名、同证书组 archive 目标及目标文件权限，
不跟随任意链接；普通文件/目录的可写权限限制不变。
新增 Linux 链接元数据语义的回归测试及独立只读复核。该模拟不等于 Linux 整机验收；
修复后的只读检查已取得用户实测通过反馈；随后正式清理在 `renewal-pause` 停止，尚未尝试删除证书或凭据。
事后系统状态及使用原执行器的只读核查均确认暂停正常、节点可用，但不能据此还原失败瞬间或认定根因。
此阶段不记作删除验收通过，不自动重跑。

## 删除前停止后的续期恢复

```bash
python3 -E -s -B -m snellctl restore-retired-renewal --experimental
```

仅限原失败报告明确停在 `renewal-pause` 且未尝试证书或凭据删除的现场。
读取现有受限记录，不接受域名、路径或秘密参数，确认默认 n；不会安装快捷入口。
恢复前重新核查原意图/失败报告、无其他待处理变更、定时器已停用且 Certbot 空闲、
现用受管配置/凭据/证书/本机 TLS/SSH-UFW 状态，以及旧资源完整存在、旧凭据元数据仍匹配原记录。
核对实际加载的续期覆盖配置仍只选择当前证书；不是恢复旧证书的自动续期，也不重新执行 DNS 演练。

确认后再次比对现场，先保存 0600 的恢复尝试记录，再仅执行一次 `systemctl enable --now certbot.timer`。
可能触发现用证书真实到期续签；后置检查允许合法的当前证书轮换，但不允许旧资源或管理记录变化。
不直接运行 Certbot、不暂停/停止服务、不改节点/防火墙、不删除任何旧资源或原清理意图。
本机 TLS 请求与系统命令仍可能产生常规日志，恢复结果写入原私有清理日志目录。

成功结果为 `renewal-restored-cleanup-still-pending`，`renewal_restored_verified=true`，
`old_resources_unchanged_verified=true`，同时 `cleanup_still_pending=true`、`cleanup_completed=false`。
`install-status` 继续显示清理待核查是预期；恢复续期不等于完成清理，不能手动删除标记或重跑删除。
原失败报告不覆盖，另存 `renewal-restore-started.json`、`renewal-restore-report.json`。

已有恢复尝试/报告、删除可能已开始、旧资源缺失或现场不符时均拒绝，不是通用恢复器。
启用失败或结果不确定时，不自动重试，也不反向停用可能已经恢复的定时器，需核查实际状态。
`report_saved=false` 需要保留终端输出；不能靠重复执行补报告。
此入口已有模拟测试，仍需独立实机验收；不把恢复续期标记为根因已修复或删除已验收。
