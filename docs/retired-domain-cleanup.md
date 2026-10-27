# 旧域名资源清理

实验入口，尚待实机验收。仅支持本工具完整管理的 Debian 13 / amd64 / IPv4 TCP 单节点 main。
先完成 `domain-inventory`、`retired-domain-plan` 的有限检查，再在已校验源码的 root SSH 终端执行：

```bash
python3 -E -s -B -m snellctl clean-retired-domain --experimental
```

也可从实验菜单 14 进入；普通菜单不提供删除操作。没有自动确认、域名或目录命令行参数。
不会安装常驻管理命令或修改快捷入口。

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
