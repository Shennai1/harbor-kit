# 测试版快捷远程安装

目标是把一段命令粘贴到**新的** Debian 13 / x86_64 VPS 的 root 交互 SSH 终端，
校验固定版本源码后进入原有安装向导。不是无人值守安装，也不适用于第三方节点迁移。
目前尚未在另一台全新 VPS 验收这条组合入口；每台机器仍须单独测试。

## 开始前

- 备好独立 SSH 新连接和 VPS 恢复控制台；确认 SSH 端口已被 UFW/云防火墙允许。
- 准备仅 DNS 的 A 记录、该 Cloudflare 区域的 DNS 编辑 Token；不用把 Token 发给他人。
- 确认拟用的公网 TCP 端口空闲且能开放，Snell 与 Nginx 后端端口只用于本机回环。
- 机器已有 `python3` 3.11+、`curl`、`sha256sum` 和可用的系统 CA；APT 源正常。
- 从已审查的交付记录取得四项固定值：完整提交号、单文件入口 SHA-256、GitHub 归档 SHA-256、公开源码快照 SHA-256。不要从未经核对的网页复制所谓“最新”校验值。

## 一次粘贴的交互流程

**以下四处 `PASTE_...` 是占位符，不能原样执行。** 每次发布后应在交付信息中给出该版本的实际值。
先进入 root 的 Bash 交互终端，再将整段作为一个命令粘贴；不要使用 `curl | bash`。

```bash
(
  set -euo pipefail
  umask 077
  [ "$(id -u)" -eq 0 ] && [ -t 0 ] || { printf '需要 root 交互终端。\n' >&2; exit 1; }
  for cmd in python3 curl sha256sum; do command -v "$cmd" >/dev/null || { printf '缺少 %s。\n' "$cmd" >&2; exit 1; }; done
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { printf '需要 Python 3.11+。\n' >&2; exit 1; }
  commit='PASTE_FULL_COMMIT'
  entry_sha256='PASTE_ENTRY_SHA256'
  archive_sha256='PASTE_ARCHIVE_SHA256'
  snapshot_sha256='PASTE_SNAPSHOT_SHA256'
  stage="$(mktemp -d /root/harbor-kit.XXXXXXXX)"
  printf '本次源码暂存目录：%s\n' "$stage"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --noproxy '*' --connect-timeout 20 --max-time 180 \
    "https://raw.githubusercontent.com/Shennai1/harbor-kit/$commit/tools/source_fetch.py" \
    --output "$stage/source_fetch.py"
  printf '%s  %s\n' "$entry_sha256" "$stage/source_fetch.py" | sha256sum -c - >/dev/null
  python3 -I -B "$stage/source_fetch.py" --commit "$commit" \
    --archive-sha256 "$archive_sha256" --snapshot-sha256 "$snapshot_sha256" \
    --output "$stage/verified"
  cd "$stage/verified/source"
  python3 -E -s -B -m snellctl install --experimental
)
```

前两次校验通过后才执行下载到本机的项目代码；安装向导随后仍逐项确认域名、端口、
Let's Encrypt 条款、正式签发、续期及开放公网。Token 在终端隐藏输入，命令行里没有 Token。
固定摘要用于传输与内容核验，**不是作者签名或安全审计**；手工确认校验值来源仍然必要。

成功后，在保留的源码目录中运行 `python3 -E -s -B -m snellctl client`，按提示显示 Surge 配置。
外部客户端须验证延迟、实际使用以及独立 SSH 新连接；如需永久的 `snellctl` 快捷命令，
再单独运行 `python3 -E -s -B -m snellctl install-command --experimental` 并确认。
安装成功不自动更新客户端、重启 VPS 或声明长期稳定。

如果入口、摘要、网络、CA、平台或安装阶段任一项失败，保留暂存目录及现场，
不要重复执行整段、手动删除标记、关闭 UFW 或跳过证书校验。
从该目录只读查看 `python3 -E -s -B -m snellctl install-status --json`，
依据阶段记录决定下一步；已存在节点不能用新机入口覆盖。
GitHub 自动归档的压缩字节可能随时间改变，旧归档摘要失配时须重新审查交付值，不能自动接受。

此测试版仅把获取与原安装流程串起来。Debian 12、ARM64、IPv6、第三方节点、真实包升级及通用失败恢复均不在首版承诺范围。
