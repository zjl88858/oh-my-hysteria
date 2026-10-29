# oh-my-hysteria

基于 [Hysteria 2](https://github.com/HyNetworks/hysteria) 的增强版代理工具。**v1.0.0**
提供更多拥塞控制选择和可选的 Blink UDP 混淆，保留 Hysteria2 的常用配置与分享链接。

[下载 Releases](https://github.com/zjl88858/oh-my-hysteria/releases) ·
[项目仓库](https://github.com/zjl88858/oh-my-hysteria) ·
[更新日志](CHANGELOG.md)

## 特性

- **拥塞控制**：默认 BBR，支持 Reno、CUBIC，以及实验性 BBRv3、COPA、Geodesic。
- **启动与预设**：CUBIC / Reno 可启用 HyStart++；BBR / BBRv3 提供保守、标准、激进三档。
- **混淆**：支持 Salamander、Gecko，以及具有认证封装、动态填充和可选分片的实验性 Blink。
- **代理方式**：SOCKS5、HTTP、TCP / UDP 转发、TUN 等 Hysteria2 功能继续可用。

## 目录

- [快速开始](#快速开始)
- [拥塞控制](#拥塞控制)
- [混淆配置](#混淆配置)
- [分享链接](#分享链接)
- [配置文件与日志](#配置文件与日志)
- [源码构建与容器](#源码构建与容器)
- [更多文档](#更多文档)
- [许可与致谢](#许可与致谢)

## 快速开始

### 1. 下载程序

从 Releases 下载对应平台的程序：

| 平台 | 文件名 |
| --- | --- |
| Linux x86-64 | `oh-my-hysteria-linux-amd64` |
| Linux ARM64 | `oh-my-hysteria-linux-arm64` |
| Windows x86-64 | `oh-my-hysteria-windows-amd64.exe` |

以下命令以 Linux x86-64 为例。Linux 下载后先执行：

```sh
chmod +x oh-my-hysteria-linux-amd64
```

### 2. 配置服务端

准备域名和对应的 TLS 证书，放行服务端的 **UDP 443**。保存为 `server.yaml`，
将证书路径和示例密码替换为自己的内容：

```yaml
listen: :443

tls:
  cert: /etc/oh-my-hysteria/server.crt
  key: /etc/oh-my-hysteria/server.key

auth:
  type: password
  password: "CHANGE-ME-AUTH-PASSWORD"
```

启动服务端（Linux 绑定 443 需要相应端口权限）：

```sh
./oh-my-hysteria-linux-amd64 server -c server.yaml
```

### 3. 配置客户端

保存为 `client.yaml`。`auth` 与服务端的 `auth.password` 一致，域名替换为自己的：

```yaml
server: proxy.example.com:443
auth: "CHANGE-ME-AUTH-PASSWORD"

tls:
  sni: proxy.example.com

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080
```

```sh
./oh-my-hysteria-linux-amd64 client -c client.yaml
```

Windows 使用对应的可执行文件：

```powershell
.\oh-my-hysteria-windows-amd64.exe client -c client.yaml
```

随后将应用的 SOCKS5 代理设为 `127.0.0.1:1080`，或 HTTP 代理设为 `127.0.0.1:8080`。
以上配置使用默认 BBR，不启用额外混淆。下面的配置片段可合并到现有 YAML 中，同类示例选一种即可。

## 拥塞控制

客户端和服务端分别配置**自己的发送方向**，两端可以选择不同算法。

| 配置项 | 默认值 | 可选值与用途 |
| --- | --- | --- |
| `congestion.type` | `bbr` | 选择下表中的算法 |
| `congestion.bbrProfile` | `standard` | `conservative` / `standard` / `aggressive`；仅对 `bbr`、`bbr3` 生效 |
| `congestion.slowStart` | `legacy` | `legacy` / `hystart++`；HyStart++ 仅支持 `cubic`、`reno`，其他算法保留默认值 |

### 算法选择

| `type` | 说明 | 状态 |
| --- | --- | --- |
| `bbr` | 原有 BBRv1 派生实现，按带宽与时延估计控制发送 | 默认 |
| `reno` | 传统的基于丢包的拥塞控制 | 可选 |
| `cubic` | CUBIC 拥塞控制，可搭配 HyStart++ | 新增 |
| `bbr3` | 独立的 BBRv3 实现，支持三档预设 | **实验性** |
| `copa` | 延迟驱动的拥塞控制 | **实验性** |
| `geodesic` | 参考 KCC / UCP 的往返时延基线跟踪；动态路径估计仍在完善 | **实验性** |

保留默认 BBR，也可以调整它的预设：

```yaml
congestion:
  type: bbr
  bbrProfile: standard
```

CUBIC + HyStart++，根据时延变化调整慢启动退出时机：

```yaml
congestion:
  type: cubic
  slowStart: hystart++
```

BBRv3（实验性）：

```yaml
congestion:
  type: bbr3
  bbrProfile: standard
```

`bbrProfile` 的三档含义：`conservative` 减少探测压力，`standard` 为默认平衡设置，
`aggressive` 更积极地探测带宽。BBR 与 BBRv3 的同名预设使用各自的参数。
选择 COPA 或 Geodesic 时，将 `type` 改为 `copa` 或 `geodesic` 即可，当前没有额外配置项。

### 与带宽设置配合

要使用上述自适应拥塞控制，**省略客户端的 `bandwidth.up/down`** 即可。
服务端也可以设置：

```yaml
ignoreClientBandwidth: true
```

相关选项如下：

| 配置项 | 默认值 | 作用 |
| --- | --- | --- |
| `bandwidth.up` / `bandwidth.down` | 未设置 | 指定本端上传 / 下载带宽，如 `20 mbps`；具体协商行为沿用 Hysteria2 |
| `bandwidth.disableLossCompensation` | `false` | 关闭 Brutal 的丢包补偿，仅在使用 Brutal 时生效 |
| `ignoreClientBandwidth` | `false` | **仅服务端**；忽略客户端带宽请求，使用配置的自适应拥塞控制 |

明确带宽协商成功的发送方向仍优先使用 **Brutal**。`brutal` 不是 `congestion.type` 的可选值。

## 混淆配置

两端的混淆类型和混淆密码需要一致。**混淆密码与前面用于登录的 `auth` 是两项独立设置。**

| `obfs.type` | 说明 |
| --- | --- |
| `plain` 或省略 `obfs` | 不加额外混淆，连接仍使用 QUIC / TLS |
| `salamander` | Salamander 数据报混淆 |
| `gecko` | Salamander 混淆，加上握手阶段的分片与填充 |
| `blink` | 认证封装、动态填充和可选用户态分片；**实验性** |

### Blink（实验性）

在客户端、服务端都加入以下配置即可启用默认 Blink：

```yaml
obfs:
  type: blink
  blink:
    password: "CHANGE-ME-TO-A-LONG-RANDOM-SECRET"
```

全部 Blink 参数位于 `obfs.blink` 下，未填写的选项使用默认值：

| 参数 | 默认值 | 范围 / 说明 |
| --- | --- | --- |
| `password` | 必填 | 16..1024 字节；建议使用至少 32 字节的随机密码 |
| `maxPacketSize` | `1400` | 本端发送的 UDP payload 上限，512..1400 字节；不分片时至少为 1272 |
| `paddingMax` | `32` | 每个内层数据报最多追加的填充字节，0..128；`0` 关闭填充 |
| `junkPackets` | 客户端 `2`；服务端 `0` | 首次发送前的干扰包数量，0..4；服务端只能省略或设为 `0` |
| `fragmentation` | `false` | 启用用户态分片与重组；开启时两端都设为 `true` |
| `maxSessions` | `1024` | 本端接收会话数量上限，1..4096 |
| `maxReassemblyBytes` | `1048576`（1 MiB） | 分片重组数据缓存的总字节预算，1200..8388608；另有全局条目数量限制 |
| `verifyPacketsPerSecond` | `32768` | 每秒报文认证预算，64..262144；允许短时突发，来源分组速率为全局的 1/4 |

除 `paddingMax`、`junkPackets` 外，数字参数设为 `0` 表示使用默认值。
其他预算可由两端各自设置，不要求相同。

需要较小的外层包时，可在两端使用以下配置：

```yaml
obfs:
  type: blink
  blink:
    password: "CHANGE-ME-TO-A-LONG-RANDOM-SECRET"
    maxPacketSize: 1232
    fragmentation: true
    paddingMax: 32
```

- `maxPacketSize` 指 UDP payload，不是 IP MTU；分片会增加包数和额外开销。
- 可选填充还受内层长度 10% 和外层剩余空间限制，固定封装开销另计。
- 每个 IPv4 地址 / IPv6 `/64` 最多保留 8 个接收会话；高速线路可按服务器能力调整验签预算。
- Blink 自动将内层 QUIC 限制为 1200 字节并关闭其 PMTU 探测，无需另外配置；当前不支持端口跳跃。

### Gecko

两端使用相同密码：

```yaml
obfs:
  type: gecko
  gecko:
    password: "CHANGE-ME-OBFS-PASSWORD"
    minPacketSize: 512
    maxPacketSize: 1200
```

| `obfs.gecko` 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `password` | 必填 | 混淆密码，至少 4 字节 |
| `minPacketSize` | `512` | 握手分片的最小目标长度，大于 0 且不超过 `maxPacketSize` |
| `maxPacketSize` | `1200` | 握手分片的最大目标长度，不超过 2048 字节；不是所有数据报的硬上限 |

### Salamander

```yaml
obfs:
  type: salamander
  salamander:
    password: "CHANGE-ME-OBFS-PASSWORD"
```

`obfs.salamander.password` 必填，至少 4 字节，两端一致。

## 分享链接

支持 `hysteria2://` 和 `hy2://`。使用客户端配置生成链接或二维码：

```sh
./oh-my-hysteria-linux-amd64 share -c client.yaml
./oh-my-hysteria-linux-amd64 share -c client.yaml --qr
```

Blink 链接使用以下查询参数：

| 参数 | 对应配置 |
| --- | --- |
| `obfs=blink` | `obfs.type` |
| `obfs-password` | `obfs.blink.password` |
| `blink-max-packet-size` | `maxPacketSize` |
| `blink-fragmentation=1` | `fragmentation: true` |
| `blink-padding-max` | `paddingMax` |
| `blink-junk-packets` | `junkPackets` |

使用 Blink 的两端都需要支持 Blink。分享链接包含连接凭证；拥塞控制和本地资源配额仍由各端配置选择。

## 配置文件与日志

使用 `-c` 指定配置最直接。未指定时，依次查找当前目录、`$HOME/.oh-my-hysteria/`、
`/etc/oh-my-hysteria/` 中的 `config.yaml` / `config.yml`，也支持 JSON 配置。

| 命令行选项 | 默认值 | 用途 |
| --- | --- | --- |
| `-c` / `--config` | 自动查找 | 配置文件路径 |
| `-l` / `--log-level` | `info` | `debug` / `info` / `warn` / `error` |
| `-f` / `--log-format` | `console` | `console` / `json` |

| 环境变量 | 用途 |
| --- | --- |
| `OH_MY_HYSTERIA_LOG_LEVEL` | 日志级别 |
| `OH_MY_HYSTERIA_LOG_FORMAT` | 日志格式 |
| `OH_MY_HYSTERIA_ACME_DIR` | ACME 证书存储目录；默认 `acme`，配置中的 `acme.dir` 优先 |

上述三个变量兼容对应的 `HYSTERIA_*` 旧名称，`OH_MY_HYSTERIA_*` 优先。
更新程序请从本项目 Releases 下载；程序不会自动向上游检查更新。

<details>
<summary>实验性拥塞控制诊断开关</summary>

设置为 `1` 时向 stderr 输出相应控制器的模型快照，默认关闭：

| 环境变量 | 控制器 |
| --- | --- |
| `OH_MY_HYSTERIA_BBR3_DEBUG` | BBRv3 |
| `OH_MY_HYSTERIA_COPA_DEBUG` | COPA |
| `OH_MY_HYSTERIA_GEODESIC_DEBUG` | Geodesic |

</details>

## 源码构建与容器

### 本机与交叉编译

需要 **Go 1.26.0+** 和 **Python 3.11+**。在完整源码根目录运行，保留其中的 `third_party/` 目录：

```sh
python hyperbole.py build -r
```

产物位于 `build/`，默认构建本机平台。构建脚本支持以下环境变量：

| 环境变量 | 默认值 | 用途 |
| --- | --- | --- |
| `OH_MY_HYSTERIA_PLATFORMS` | 本机平台 | 逗号分隔的目标平台，如 `windows/amd64,linux/amd64,linux/arm64` |
| `OH_MY_HYSTERIA_VERSION` | `VERSION` 文件中的版本 | 覆盖构建版本 |
| `OH_MY_HYSTERIA_COMMIT` | 当前 Git 提交 | 覆盖构建提交信息 |

例如在 PowerShell 中构建 Linux 两种架构：

```powershell
$env:OH_MY_HYSTERIA_PLATFORMS = "linux/amd64,linux/arm64"
python hyperbole.py build -r
```

### Docker

先在源码目录构建镜像：

```sh
docker build -t oh-my-hysteria:1.0.0 .
```

再在存放 `server.yaml`、`server.crt`、`server.key` 的配置目录启动：

```sh
docker run -d --name oh-my-hysteria \
  -p 443:443/udp \
  -v "$PWD:/etc/oh-my-hysteria:ro" \
  oh-my-hysteria:1.0.0 server -c /etc/oh-my-hysteria/server.yaml
```

## 更多文档

- [Hysteria2 常规配置与使用](https://hysteria.network/)
- [CUBIC / HyStart++](docs/congestion.md)
- [BBRv3](docs/bbrv3-implementation.md) · [BBRv3 预设](docs/bbrv3-profiles.md)
- [COPA](docs/copa.md) · [Geodesic](docs/geodesic.md)
- [Blink 协议与资源预算](docs/blink.md)

<details>
<summary>贡献代码：运行测试</summary>

```sh
python -m unittest discover -s tests
uv sync --locked
uv run python hyperbole.py test
go test ./third_party/quic-go ./third_party/quic-go/internal/... ./third_party/quic-go/http3
```

</details>

## 许可与致谢

项目原创新增内容采用 [MIT-0](LICENSE.md)。继承的 Hysteria2 / quic-go 代码保留 MIT，
COPA 适配保留 TQUIC Apache-2.0，Geodesic 适配保留 KCC 的 BSD 选项及 UCP MIT。
完整声明见 [第三方许可](LICENSE-THIRD-PARTY.md)；分发二进制时请一并保留随附许可文件。

感谢 Hysteria2、quic-go 及相关算法与工具项目的开发者。

- Maintainer：[zjl88858](https://github.com/zjl88858)
- Co-Developer：**GPT-6.1 Sol（OpenAI）**
