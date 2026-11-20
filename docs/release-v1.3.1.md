# oh-my-hysteria v1.3.1

本版新增两个独立的混淆模式：单端口的 **PrestoLite**，以及保留两到三个认证小包副端口的 **NetFrontLite**。两者保留握手、数据阶段的四状态包长、分片、随机填充和逐片认证，仅在持续发送大包时跳过部分计划停顿。收益是更高的应用吞吐；代价是**大流的时序混淆减弱**。需要完整节奏时，继续选择标准 Presto 或 NetFront。

## 从 v1.3.0 升级

继续使用原来的模式，只需替换程序，配置无需改动。默认仍是 BBR、不开启额外混淆。Lite 与拥塞预设、Brutal 带宽协商以及正常 TLS 校验独立。

要启用 Lite，客户端和服务端都升级到 v1.3.1，选择下列一段配置。混淆密码与登录 `auth` 分开，示例值请替换为相同的随机秘密：

```yaml
obfs:
  type: prestolite
  prestolite:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

```yaml
obfs:
  type: netfrontlite
  netfrontlite:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
    extraPorts: [31011, 31012]  # 也可加第三个服务端 UDP 副端口
```

NetFrontLite 的 `listen` / `server` 只写主端口。两端按相同顺序配置 `extraPorts`，在服务端放行并映射这些 UDP 端口；分享链接由 `share` 写入 `netfrontlite-extra-ports`。标准与 Lite 使用不同的认证密钥标签：即使密码相同也不能混配，不会自动回退。没有 `profile: lite` 参数。

## 吞吐与适用范围

同一 Windows 程序、IPv4 回环、正常 TLS、BBRv3 standard；三份密码分别上传和下载 64 MiB 随机文件，以下是接收端中位数（Mbit/s）：

| 标准 → Lite | 上传 | 下载 |
| --- | ---: | ---: |
| Presto → PrestoLite | 16.6 → **46.2** | 18.1 → **34.5** |
| NetFront → NetFrontLite，2 个副端口 | 23.9 → **46.8** | 16.3 → **48.4** |
| NetFront → NetFrontLite，3 个副端口 | 23.7 → **44.3** | 16.5 → **39.0** |

这些数值来自入选实现的开发构建 `v1.3.0+lite.dev`。36/36 个文件通过 SHA256 校验；排除首个 16 MiB 后，18/18 对中 Lite 仍更快。公网速度和抗识别能力不能从环回结果推断。各密码、各方向的数据见[完整实测](network-test-lite-2026-11-20.md)。

最终 v1.3.1 Windows Release 程序在本机回环分别复验了 PrestoLite、NetFrontLite 两副路和三副路：三种配置的分享链接往返解析、HTTP 网页、HTTPS 下载、SOCKS5 HTTPS 上传和 SOCKS5 UDP DNS 均通过。Linux 两种架构为交叉编译产物。

## 下载与校验

| 平台 | 附件 |
| --- | --- |
| Windows x64 | `oh-my-hysteria-windows-amd64.exe` |
| Linux x86-64 | `oh-my-hysteria-linux-amd64` |
| Linux ARM64 | `oh-my-hysteria-linux-arm64` |

`SHA256SUMS` 列出以上三个文件及 `LICENSES.zip` 的摘要。分发程序时请保留许可包（含 MIT-0、第三方许可和本地 QUIC 分支说明）。解压或运行后可用 `version` 核对 `Version: v1.3.1`、`BuildType: release`。

[PrestoLite 机制与边界](prestolite.md) · [NetFrontLite 配置与副路](netfrontlite.md) · [更新日志](../CHANGELOG.md)
