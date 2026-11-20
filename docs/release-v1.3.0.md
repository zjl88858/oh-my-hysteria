# oh-my-hysteria v1.3.0

本版新增可选混淆 **NetFront**，采用已通过代理功能验收的 `.2` 实现。主端口沿用 Presto 的分片、填充与发送节奏，承载大部分流量；两到三个经过双向验证的副端口间歇发送小包。密码决定每路偏向成串活动还是稀疏心跳，每个会话重新抽样，不按固定比例分流。代价是多开放几个 UDP 端口，以及验证、封装和填充产生的额外流量。

## 升级与配置

从 v1.2.1 升级且继续使用原来的混淆时，直接替换程序即可，无需新增端口。默认仍不启用额外混淆；默认 BBR、已有预设、Brutal 带宽协商及 TLS 校验规则不变。从源码构建时使用随仓库提供的 `third_party/quic-go/`，本版已移除公开 v1.2.1 源码中会导致重复声明等问题的过期文件。

启用 NetFront 时，两端均升级至 v1.3.0，并在两份配置中加入同一段：

```yaml
obfs:
  type: netfront
  netfront:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
    extraPorts: [31011, 31012]  # 也可加第三个，例如 31013
```

服务端 `listen: :443`、客户端 `server: example.com:443` 都只填主端口。`extraPorts` 是**服务端**副端口，两端顺序须一致；在防火墙、容器或 NAT 上一并放行或映射。混淆密码独立于登录 `auth`。NetFront 需要固定端口，不与端口跳跃、Realms 或 Mimic 组合。`share` 会将副端口写入链接的 `netfront-extra-ports` 参数。

## 验证

`.2` 公网验收中，两副路、三副路配置分别通过 HTTP 打开网页、HTTPS CONNECT 下载并校验文件、SOCKS5 上传并校验文件，以及 SOCKS5 UDP 查询 DNS。另有 13 次 NetFront 公网连接全部通过同一 TCP 流的前后两段内容校验。弱网 UDP 回显有缺失；逐组数据见[验收报告](network-test-netfront-2026-11-20.md)。

最终 v1.3.0 Windows 程序在回环上复验了同样四种代理事务，以及两种配置的分享链接往返解析。`.2` 和 v1.3.0 分别担任客户端、服务端的两次互通测试均收到 72/72 条正确的 UDP 回显。

本版包含副路续期修复：同一已验证地址最多宽限 2 秒接收旧凭证的在途包，不延长原到期时间。旧凭证只收不发，副路地址改变时立即撤销。

## 下载

| 平台 | 附件 |
| --- | --- |
| Windows x64 | `oh-my-hysteria-windows-amd64.exe` |
| Linux x86-64 | `oh-my-hysteria-linux-amd64` |
| Linux ARM64 | `oh-my-hysteria-linux-arm64` |

二进制沿用 v1.2.1 的文件名。`SHA256SUMS` 列出这三个文件和 `LICENSES.zip` 的 SHA256；分发程序时请一并保留许可包，内含 MIT-0、第三方许可及本地 QUIC 分支说明。

[NetFront 配置与限制](netfront.md) · [混淆选型](obfuscation.md) · [更新日志](../CHANGELOG.md)
