# oh-my-hysteria

oh-my-hysteria（OMHY）是 [Hysteria 2](https://hysteria.network/zh/) 的增强版。它保留了原有的代理方式和分享链接，主要扩展了两件事：**混淆**决定数据以什么样的包发出去，**拥塞控制**决定网络还能承受多快的发送速度。两者可以分别选择；默认使用 BBR，不启用额外混淆。

当前源码版本 **v1.3.0** 新增可选的 [NetFront](docs/netfront.md)：主端口传送大部分数据，另用两到三个固定 UDP 端口收发小包。沿用 Hysteria v2.14.0 的表达式访问规则（ACL）、UDP 转发优化和带有 OMHY 扩展的[本地 quic-go 分支](third_party/quic-go/OHMY-FORK.md)。

[下载已发布版本](https://github.com/zjl88858/oh-my-hysteria/releases) · [v1.3.0 发布说明](docs/release-v1.3.0.md) · [混淆配置](#混淆配置) · [拥塞控制](#拥塞控制) · [更新日志](CHANGELOG.md)

## 混淆配置

同一份数据，可以改变**包有多大、什么时候发、发到哪个端口**，也可以改变**哪些数据装进同一个包**，或者改变**包里的字节怎样排列**。它们改变的是外层 UDP 包；连接本身仍由 QUIC/TLS 加密。

### 改变包的大小和发送节奏

- **Salamander / Gecko** 是上游提供的两种方式。Salamander 把密码和每包新生成的随机值组合起来，用算出的掩码改写包内容。原来一个包仍发成一个包，大小固定增加 8 字节。Gecko 在此基础上把握手数据拆开并填充，因此主要改变刚建立连接时看到的包长和包数。
- **[Blink](docs/blink.md)** 给每个包加上接收方可以验证的封装，再随机补入少量字节。这样即使原始数据一样长，发出去的包也可以不同长。你可以限定最多补多少、是否拆包，以及客户端在开头发几个不带业务数据的包；上限越小，对流量的影响越可控。
- **[Presto](docs/presto.md)** 改的是一串包之间的关系。密码决定一套规则，例如大包之后更可能接什么长度的包、连续发多少包后稍停一下。每次连接都按这套规则重新抽样，再通过拆分和填充调整包长。因此，同一密码下的流量有相似的节奏，但不会重播同一串包。代价是额外流量，以及两批包之间的短暂等待。
- **[NetFront](docs/netfront.md)** 在 Presto 的基础上，让一个主端口承担大部分通信，另外两三个端口间歇地交换小包。例如，一路像有人按下语音键，说几句又停下；另一路像偶尔上报一次状态。密码决定各端口偏向哪种节奏，每次连接再抽样，不按固定比例分包。副路通过双向验证后可携带真实小帧；如果只有大包，大包继续走主路，有余额才另发小包。代价是额外的 UDP 端口和流量。

### 重新组合数据，或为丢包留一份修复材料

- **[Servo](docs/servo.md)** 改变原始数据报和外层包之间的边界。例如，一个外层包可以同时装下上一条数据的尾部和下一条的开头；接收端再把它们分别拼回去。这样，连续到来的小包可以分摊封装开销，不必靠填充凑长度。代价是发送端会短暂等待下一份数据；如果只有一个孤立小包，就没有其他数据能和它分摊。
- **[Tasman](docs/tasman.md)** 把几毫秒内到来的数据凑成一组，切成等宽的片，按密码选定的节奏分批发送。它还可以用同组数据算出修复片：如果丢了一片数据，但其余数据和一片修复片都到了，接收端就能算回缺失的那一片，不必等 QUIC 重传。Tasman 按约两倍输入数据量安排发送，先给真实数据留足空间，有余量才加修复片或填充。这个比例不是每包的上限：对只有几个字节的消息，光是包头就可能比数据本身还长。

### 改变一个包内部的字节

- **[Trident](docs/trident.md)** 用密码生成一套有 64 条“指令”的编码规则，再把加密后的数据写成一串指令和参数。接收端用同一套规则读回数据，并不执行这些指令。换一个密码，哪些字节代表指令、每条后面要读多长都会改变。指令和对齐所占的空间会让包变大，大包需要拆开发送。
- **[Carakan](docs/carakan.md)** 改变的是**哪些字节常见、哪些少见**。它用密码生成一张可反查的编码表，把原本分布接近均匀的密文改写成另一种字节分布。`targetEntropy` 越低，输出越集中在少数字节上，表示同一份数据通常也就越长。例如，默认值 `4.0` 下，纯编码理想上就需要约两倍空间，还没算分片和修复片。它用更多流量换取指定的分布，不是压缩。
- **[Mariner](docs/mariner.md)** 改变的是**不同位置的字节之间有什么关系**。例如，它从密文里选出几个字节，按密码指定的规则算出一个新字节，再把它穿插回包里。接收端知道该看哪些位置，可以核对关系、取回密文并验证这个包。这里多出的字节不能修复另一个丢掉的包。在 6532 字节混合输入的回环测试中，实际发出的 UDP 数据约为输入的 1.41～1.46 倍；测试尚未证实这种结构比 Presto 更难识别。

### 如何配置

不启用混淆时，省略 `obfs` 即可。要启用，在客户端和服务端配置的顶层各放**一段**下面的 YAML，两端选择同一种模式。把示例 `password` 换成同一个随机混淆密码，与登录密码 `auth` 分开。可用 `python -c "import secrets; print(secrets.token_urlsafe(32))"` 生成密码。共同部署要求详见[混淆选型指南](docs/obfuscation.md)。

<details>
<summary>Salamander · 只需密码</summary>

```yaml
obfs:
  type: salamander
  salamander:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

详见 [Hysteria 2 官方混淆配置](https://v2.hysteria.network/zh/docs/advanced/Full-Server-Config/#_3)。

</details>

<details>
<summary>Gecko · 可调握手分片大小</summary>

```yaml
obfs:
  type: gecko
  gecko:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
    minPacketSize: 512
    maxPacketSize: 1200
```

`minPacketSize` 和 `maxPacketSize` 指定握手分片的目标大小范围，单位是字节。上面是默认值；只填密码也能用。调小上限，一次握手可能拆成更多包。这两个值不限制握手之后的普通数据包。详见 [Hysteria 2 官方 Gecko 配置](https://v2.hysteria.network/zh/docs/advanced/Full-Server-Config/#_3)。

</details>

<details>
<summary>Blink · 可调包长、填充和拆包</summary>

```yaml
obfs:
  type: blink
  blink:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
    maxPacketSize: 1232
    fragmentation: true
    paddingMax: 32
    junkPackets: 2  # 客户端默认值；服务端请删除此行或改为 0
```

- **限制包长：** `maxPacketSize` 限制每个发出包的 UDP 载荷大小，默认 1400 字节。示例收紧到 1232 字节，所以两端都要开 `fragmentation`，让放不下的数据可以拆开发送。不拆包时上限至少要设为 1272。
- **改变包长和开头的包数：** `paddingMax: 32` 表示每条原始数据最多额外填充 32 字节，并非每次填满；设为 `0` 可关闭填充。`junkPackets` 控制客户端开头发几个不带业务数据的包，默认 2 个，设为 `0` 可关闭。服务端省略它或填 `0`。
- **限制接收端资源：** `maxSessions` 限制同时保留多少个会话，`maxReassemblyBytes` 限制为拼回分片能缓存多少字节，`verifyPacketsPerSecond` 限制每秒尝试验证多少个包。一般保留默认值即可。

详见 [Blink 完整参数与取值范围](docs/blink.md#配置)。

</details>

<details>
<summary>Presto · 只需密码</summary>

```yaml
obfs:
  type: presto
  presto:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

包长和发送间隔由密码生成，无需另设。详见 [Presto 技术文档](docs/presto.md)。

</details>

<details>
<summary>NetFront · 主端口之外，再配置两到三个 UDP 端口</summary>

```yaml
obfs:
  type: netfront
  netfront:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
    extraPorts: [31011, 31012, 31013]
```

例如主端口是 443，服务端仍写 `listen: :443`，客户端仍写 `server: example.com:443`。`extraPorts` 填的是**服务端**额外监听的端口，可以只填两个；两端按相同顺序填写，在服务端放行这些 UDP 端口。有 NAT 或容器端口映射时也要分别转发。详见 [NetFront 技术文档](docs/netfront.md)及 [HTTP、SOCKS5 和 UDP 代理实测](docs/network-test-netfront-2026-11-20.md)。

</details>

<details>
<summary>Servo · 只需密码</summary>

```yaml
obfs:
  type: servo
  servo:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

每包能装多少数据、等多久再发，都由密码决定。详见 [Servo 技术文档](docs/servo.md)。

</details>

<details>
<summary>Tasman · 只需密码</summary>

```yaml
obfs:
  type: tasman
  tasman:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

无需手动填修复片数；发送端按密码生成的规则和可用流量预算决定实际发多少。详见 [Tasman 技术文档](docs/tasman.md)。

</details>

<details>
<summary>Trident · 只需密码</summary>

```yaml
obfs:
  type: trident
  trident:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

两端用密码生成同一套编码规则，无需交换指令表。详见 [Trident 技术文档](docs/trident.md)。

</details>

<details>
<summary>Carakan · 可调字节分布</summary>

```yaml
obfs:
  type: carakan
  carakan:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
    targetEntropy: 4.0
```

`targetEntropy` 控制输出集中在少数字节上的程度：越低越集中，通常也越费流量。可选 `1.00`～`7.50`，省略时为 `4.00`；两端必须一致。详见 [Carakan 各档实测开销与完整配置](docs/carakan.md)。

</details>

<details>
<summary>Mariner · 只需密码</summary>

```yaml
obfs:
  type: mariner
  mariner:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

包中哪些字节相关、怎样排列，都由两端从密码算出，无需额外配置。详见 [Mariner 技术文档](docs/mariner.md)。

</details>

## 拥塞控制

发送太慢会浪费带宽，发得比线路能送达的速度快，数据就会排队，延迟随之升高，甚至丢包。各算法的核心区别在于：**它把什么当成线路已满的信号，又怎样判断可以重新加速。**

| 算法 | 它根据什么调速 |
| --- | --- |
| **BBR**（`bbr`，默认） | 看对端每秒实际收到了多少数据，以及包最快多久能来回一次，据此估算同时发出多少数据能把线路用满。它会短暂提速试探余量，再降速让积压的数据排出去，不必等到丢包才调整。 |
| **[BBRv3](docs/bbrv3-implementation.md)**（`bbr3`，实验性） | 同样估算带宽和往返时间，但会用探测期间的丢包和网络给出的拥塞标记修正上限。如果提速开始造成持续损失，它会收紧允许在途的数据量，再寻找下次探测的机会。 |
| **[Reno](docs/congestion.md)**（`reno`） | 在稳定传输时，随着数据被确认，逐步增加可以同时发出的数据量；遇到拥塞就减小，再从较低水平线性增长。规则简单，但在带宽大、往返时间长的线路上，回到原速可能较慢。 |
| **[CUBIC](docs/congestion.md)**（`cubic`） | 和 Reno 一样会在拥塞后退让，但恢复速度取决于距上次拥塞过了多久。它先较快接近上次的发送水平，在旧高点附近放慢增长；如果迟迟没有再拥塞，就加快增长，试探更高的带宽。 |
| **[COPA](docs/copa.md)**（`copa`，实验性） | 把近期的往返时间与观测到的最低值相比，用多出来的时间估算排队程度。队列短时多发，队列持续变长时少发，因此往往能在丢包前做出调整；和持续把队列填满的连接竞争时，也可能让出较多带宽。 |
| **[Geodesic](docs/geodesic.md)**（`geodesic`，实验性） | 线路换了一条更远的路径，和路上暂时排了队，都会让回包变慢。它观察连续多轮传输：若每轮最快的回包都比原来慢，且有足够的数据样本，才上调对线路基础延迟的估计，再结合带宽调整发送量。这样不会因为一次延迟尖峰就认定路径变长，代价是确认真实变化也需要时间。 |

**配置时看发送方向。** 客户端的选择影响上传，服务端的选择影响下载，两端可以不同。省略客户端的 `bandwidth.up/down` 即可使用自适应算法；若明确设置带宽且协商成功，对应方向优先用 **Brutal**，按协商的速率发送并默认补偿丢包。服务端可用 `ignoreClientBandwidth: true` 忽略客户端的带宽请求。

```yaml
congestion:
  type: bbr
  bbrProfile: standard
```

两个容易混淆的设置：

- **`bbrProfile` 调的是试探带宽的力度。** `standard` 是默认值，`conservative` 较克制，`aggressive` 更积极。激进模式可能更早用上空闲带宽，也可能只增加排队。BBR 和 BBRv3 都有这三档，但[具体参数](docs/bbrv3-profiles.md)各自独立。
- **`slowStart: hystart++` 调的是起步阶段，只用于 Reno 或 CUBIC。** 刚开始发送时，如果连续采样发现回包变慢，它会先放缓增长。延迟回落就恢复原来的增长速度，持续偏高才结束快速起步，避免把一次抖动误判成线路已满。

## 使用与构建

常规客户端、服务端和证书配置见 [Hysteria 2 官方指南](https://hysteria.network/zh/)。OMHY 沿用 `hy2://` / `hysteria2://` 分享链接；`share -c client.yaml --qr` 可从客户端配置生成链接和二维码，二者都包含登录凭证。

从源码构建使用 Go 1.26.10、Python 3.11+，并保留仓库中的 `third_party/`：

```sh
python hyperbole.py build -r
```

本机平台的产物位于 `build/`。也可在源码目录运行 `docker build -t oh-my-hysteria:1.3.0 .` 构建服务端镜像。各版本的测试环境、流量开销和已知限制见[构建与测试记录](BUILD-REPORT.md)。

## 许可与致谢

感谢 Hysteria 2、quic-go 以及相关开源项目的开发者。

| 贡献者 | 工作 |
| --- | --- |
| [zjl88858](https://github.com/zjl88858) | 项目维护者 |
| **GPT-6.1 Sol（OpenAI）** | 共同开发者（Co-Developer），负责截至 **v1.2.0（含）** 的开发工作 |
| **GPT-6.2 Astra（OpenAI）** | 共同开发者（Co-Developer），从 **v1.2.1** 起接手后续开发 |
| **Gemini-4 Carbon** | 负责此前版本的代码审查（Code Review） |

项目原创新增内容采用 [MIT-0 许可](LICENSE.md)。Hysteria 2、quic-go 及其他第三方代码保留各自许可，详见[第三方许可声明](LICENSE-THIRD-PARTY.md)。分发程序时请一并保留随附的许可文件。
