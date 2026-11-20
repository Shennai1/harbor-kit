# 固定提交源码获取

这是可单文件运行的源码下载与暂存工具。首次在新机器使用时，仍须先取得此文件的
固定提交地址及独立核对的 SHA-256，再执行；不能把未校验的网络内容直接交给解释器。
工具本身不执行下载的代码、安装节点或更新当前目录。配套的人工确认安装流程见
[测试版快捷远程安装](quick-install.md)。

使用完整的 40 位小写提交号、该提交归档的 SHA-256、公开源码快照 SHA-256。
三者必须来自事先核对的交付记录，不接受 `main`、标签、缩写或自动发现的最新版本。
从可信代码目录、普通用户会话运行（以下值为占位符）：

```bash
python3 -E -s -B -m tools.source_fetch \
  --commit 'PASTE_FULL_COMMIT' \
  --archive-sha256 'PASTE_ARCHIVE_SHA256' \
  --snapshot-sha256 'PASTE_SOURCE_SNAPSHOT_SHA256' \
  --output /absolute/new-stage-directory
```

目标须为不存在的绝对路径，父目录须已存在且不是符号链接。
下载来源固定为本仓库的 GitHub codeload HTTPS 提交归档；禁用代理，只接受固定主机的 HTTPS 重定向。
使用系统 TLS 信任链，不提供跳过证书校验的选项。网络请求与展开大小都有限制。
没有可用直连网络或受信 CA 时会停止，不能因此改用不校验证书的下载。

只有归档摘要、目录结构、文件类型和公开源码快照全部匹配才写入文件。
不使用通用 `extractall`：逐个复制已经检查的普通文件，不跟随目标路径中的符号链接。
目标目录、文件分别为 0700/0600；`receipt.json` 最后写入，内容包含来源和核对结果。
`source.tar.gz` 保留原始下载字节；`source/` 是已核对的源码副本。
成功后仍需人工审查源码并运行适当测试，才能考虑任何节点操作。

失败或中断保留暂存目录；没有完成记录的目录不能使用，不自动清理、覆盖或重试。
已存在的目标也直接拒绝。有限的目录权限与校验不防御同一用户或 root 的恶意并发修改。
直接运行单文件时可使用 `python3 -I -B /absolute/path/source_fetch.py`，不需要先安装本项目；
受信 CA 必须可被该 Python 识别。证书验证失败时应修复系统 CA，不得跳过 TLS 校验。

GitHub [官方说明](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives)
指出固定提交的文件内容保持一致，但自动生成归档的压缩字节可能随时间变化。
因此旧归档摘要失配时必须重新核对公开文件并批准新的交付值，工具不会自动接受新摘要。
提供的摘要是内容核对，不是独立作者签名；它不能证明提交未被替换、来源可信或代码安全。
本入口与[本地源码打包工具](source-bundle.md)的归档格式不同，两者摘要不能互换。
