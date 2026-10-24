# 新机自动部署实测清单

这是**可复用的验收清单，未勾选项不代表已通过**。
已有一轮用户实测：实验安装在 SSH 断线后，经人工核查和一次性命令接续，
客户端使用及正常重启恢复通过。完整向导、新菜单接续、真实到期轮换仍待独立验证。
此前手工部署成功不能替代这些验收。目前不改动现有正常运行节点。
当前范围：Debian 13 / amd64、新机、单节点 main、Snell 5.0.1 + ShadowTLS 0.2.25 / v3、IPv4 TCP。
后续两项密钥分别更换及正常重启恢复的用户实测结果，单独记录在[密钥更换说明](key-rotation.md#已取得的实测证据)。
这不补齐本清单中尚未完成的全新安装或其他平台验收项目。

若计划清理既有测试机后复用，先盘点并单独确认卸载范围，再按干净环境复查。
本文不表示清理已经完成或已经获得卸载授权。
首轮继续验证 Debian 13；安装器目前拒绝 Debian 12，不可绕过检查或把 trixie 软件源用于 Debian 12。

## 开始条件

- [ ] 用户明确选定可恢复的测试 VPS；复用旧测试机时已单独完成获授权的清理，再授权实验安装。
- [ ] 有服务商控制台或其他恢复方式；能保留当前 SSH 会话并另建新会话。
- [ ] 确认实际 SSH 端口、系统及架构，不照抄历史 VPS 的值。
- [ ] UFW 已启用并登记开机启动，默认拒绝入站、允许出站，SSH 已放行；不重置已有规则。
- [ ] 没有已有 Nginx、Certbot、节点或本工具准备记录；遇到残留先审查，不自动删除。
- [ ] APT 源、系统时钟和出站 DNS/HTTPS 正常；不会绕过签名验证或替用户删除第三方源。
- [ ] 准备独立测试域名及仅授权对应 Cloudflare 区域的 DNS 编辑 Token；令牌只在目标机隐藏输入。
- [ ] 明确要用的公网 TCP 端口和两个回环端口，均空闲且不与 SSH 冲突。
- [ ] 如果客户端连接地址使用域名，A 记录指向本机 IPv4且仅 DNS；不要增加尚未配置的 IPv6 业务记录。
- [ ] 确认本次代码版本及交付来源，固定已核对的完整提交标识；不使用未知一键脚本。

开发源码来源见 [源码交付](source-delivery.md)，不在公开仓库提交个人笔记与运行凭据。
代码到达测试机后才执行后续命令。当前没有全局 `snellctl` 启动器，下列命令在项目目录运行。

复用机器前需区分手工节点和本工具创建的资源，核对节点服务、版本目录、Nginx 站点、证书/续期钩子、
凭据及入口 UFW 规则的实际引用。不能仅因路径相似就认领或删除，更不能拿其他 VPS 的端口套用。
保护 SSH、UFW 基础规则、其他站点/证书和业务；不执行通用“清空防火墙”、删除全部证书或内核自动清理命令。
卸载和通用恢复功能尚未实现；受限接续不能替代清理或处理未知中断，不能把本清单当作卸载脚本。

现在可先用 `python3 -m snellctl cleanup-plan --json`（普通菜单 6）做
[清理前只读盘点](cleanup-inventory.md)。前提是代码已交付至目标机；它不停止服务、不删除文件，
不能把没有安装器记录的手工节点认领为自动安装器管理的节点。

## 只读盘点

```bash
cat /etc/os-release
uname -m
python3 -m snellctl doctor --json
```

在交互 Bash 中输入本次域名后进行只读预检查：

```bash
read -r -p '本次完整小写域名：' DOMAIN
python3 -m snellctl preflight --domain "$DOMAIN"
unset DOMAIN
```

以上预检查采用默认候选端口；非默认端口须同时提供 `--public-port`、`--snell-port`、`--tls-port`。
向导也会用最终输入的端口重新检查。有限预检查成功不表示公网可达、所有自定义规则安全或安装已完成。
只回报脱敏结果，不公开主机 IP、真实域名、凭据、全量日志或 shell 历史。

## 分阶段安装

明确授权后，在选定的新机交互终端运行：

```bash
python3 -m snellctl install --experimental
```

- [ ] 新机及早期防火墙检查通过；预览中的角色/地址/端口与本机实际相符。
- [ ] 官方固定版本下载及校验通过；没有忽略校验错误。
- [ ] 软件包准备成功，Nginx 默认公网站点未提前启动，UFW/SSH 未被卸载或重置。
- [ ] DNS 演练成功后才单独确认正式签发；不把 staging 证书当作正式证书使用。
- [ ] 本机 TLS 证书链、域名、当前磁盘/运行证书一致性及错误/缺失 SNI 检查通过。
- [ ] 三组件先通过回环启动验收；模拟续期、钩子与重载后的验收通过。
- [ ] 另建 SSH 会话登录成功，之后才确认自动续期和公网入口开放。
- [ ] 向导明确完成公网启用；未以历史完成记录代替本次运行检查。

发生失败：保留当前 SSH，不重跑安装、不重置 UFW、不删除状态、mask 或 policy-rc.d，也不直接重启。
先查看 `python3 -m snellctl install-status --json` 和终端固定的阶段错误。
软件包、DNS、CA 操作不支持整体事务回滚；失败可能已产生远端结果或新增规则。

接续入口需在独立授权的测试部署上验证：本机验收和续期演练已通过，
在公网确认处取消或断开后，确认旧程序退出，再运行 `resume --experimental` 或实验菜单 7。
核对先只读复查、三项重新确认、不重新签发/换密钥，接续后继续以下验收。
取消应保留现场，已完成节点及部分公网启用结果应拒绝接续；不要在现用节点上制造故障测试。

## 服务端复查

```bash
python3 -m snellctl install-status --json
python3 -m snellctl doctor --json
systemctl --no-pager show snellctl-snell-main.service snellctl-shadowtls-main.service nginx.service \
  -p Id,ActiveState,SubState,UnitFileState,NRestarts,ExecMainStatus
systemctl --no-pager show ufw.service certbot.timer \
  -p Id,ActiveState,SubState,UnitFileState
systemctl list-timers --all certbot.timer --no-pager --full
```

- [ ] 三服务 enabled、active/running；退出状态和重启次数无异常。
- [ ] UFW active；SSH 放行保留，只新增所选 IPv4 TCP 入口；IPv6 既有规则保持。
- [ ] ShadowTLS 为 `0.0.0.0:所选公网端口`；Snell TCP/UDP 和 Nginx TLS 都只监听 `127.0.0.1`。
- [ ] 无额外 Nginx 公网 80/443、无新 UDP 或 IPv6 节点入口。
- [ ] Certbot timer enabled/active，有下次执行安排；到点运行中则稍后复查，不将运行中误判为失败。

`install-status` 是历史阶段记录；`doctor` 是通用盘点，安装后提示已有组件是预期信息，不适合代替上面的运行检查。
UFW 服务的 `active/exited` 和空闲 Certbot service 的 `inactive/dead` 不等于故障。
若 routed 显示 disabled，不为改变文字而启用内核转发。
本清单不提供自动修复或重启命令。

## 外部 TLS 与 Surge

从外部测试机检查入口，不能只从 VPS 访问自身。机器需有支持 TLS 1.3 的 curl 和正常的 CA 信任库。
以下为 Bash 语法，macOS 默认 zsh 会话可先进入 `bash`。需要输入实际域名、IPv4 和入口端口，不包含节点密码：

```bash
read -r -p '证书域名：' DOMAIN
read -r -p 'VPS IPv4：' IPV4
read -r -p '公网 TCP 端口：' PORT
curl --noproxy '*' --proto '=https' --tlsv1.3 --tls-max 1.3 --http1.1 \
  --resolve "$DOMAIN:$PORT:$IPV4" --connect-timeout 10 --max-time 20 \
  --silent --show-error --output /dev/null \
  --write-out 'HTTP=%{http_code} TLS_VERIFY=%{ssl_verify_result}\n' "https://$DOMAIN:$PORT/"
unset DOMAIN IPV4 PORT
```

- [ ] 命令退出成功且 `HTTP=404 TLS_VERIFY=0`。404 是本方案预期响应，不是要求返回真实网站首页。
- [ ] 没有添加 `-k` 或关闭域名/证书验证来绕过错误。

此项只验证普通 TLS/HTTPS 转发，不验证 Snell/ShadowTLS 密钥认证。
测试未使用 DNS 解析业务 A 记录；域名作为节点连接地址时还需另验其实际解析。
curl 显式不使用环境代理，但不保证绕过系统 VPN/Surge 隧道；选择不经待测节点的测试路径，避免循环或假象。

在 VPS 用 `python3 -m snellctl client` 或菜单 5 明确确认显示配置，按 [导出说明](client-export.md) 加入 Surge。
不覆盖原节点/规则；已有同名节点时先修改新行等号左侧名称。

- [ ] 配置作为单行加入 `[Proxy]`，客户端没有格式错误。
- [ ] 新节点延迟测试成功，节点诊断与下载测试成功。
- [ ] 将明确的测试网站或应用域名定向到新节点，连接记录确认使用了该节点，没有回退到其他节点或直连。
- [ ] 实际 TCP 使用成功，例如下载或媒体播放；不必使用固定网站。
- [ ] 只回报结果，不发回客户端配置行或两项密钥。

错误密钥测试尚未完成，记录为“未测”，不记为通过。
延迟、下载、TCP 播放通过不代表 UDP、QUIC Proxy Mode、IPv6 或长期稳定性通过。

## 重启与续期

完成前述检查、确认控制台可恢复并得到用户同意后，再安排测试机正常重启，工具不自动执行。
回来后核对 `uptime -s`，重复服务端复查以及 Surge 延迟和实际使用。
只做正常重启就记录“正常重启”，不要写成“断电恢复”验收。

- [ ] SSH 新连接可用，三组件和 UFW 开机状态、监听范围不变。
- [ ] Certbot timer 恢复安排，客户端无需重新导出/换密钥即可使用。
- [ ] 安装期间包含钩子的续期演练已通过；不为了重复确认而反复签发或强制续期。
- [ ] 真实证书到期轮换后，再独立比较新磁盘证书与实际握手证书，验证重载；尚未发生时明确写“未测”。

## 结果回报

只需提供：系统/架构、程序版本、安装阶段、SSH/入口范围是否符合预期、外部 TLS、
Surge 延迟/实际使用、重启恢复、续期演练分别为通过/失败/未测，以及脱敏错误阶段。
不必保存完整配置副本或提交整段命令历史。未完成项保留为未测，不自动勾选清单。

即使以上通过，仍不能发布“全功能管理器”：更新、换域名/Token/密钥、恢复、卸载、
IPv6、其他平台和最终 GitHub 下载入口需要各自实现并验收。受限接续不代表通用恢复已完成。
