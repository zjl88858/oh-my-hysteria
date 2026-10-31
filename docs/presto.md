# Presto：密码派生流量语法

Presto 使用 **Protocol Genome Compiler**，从一个随机密码生成双向包长、长度转移、
前导、分片和突发语法。每个会话在同一语法内随机采样，因此同密码形态相近，具体包序列不同。
当前派生域为 `oh-my-hysteria/presto/v1`。

[混淆选型、部署要求与安全说明](obfuscation.md) · [返回 README](../README.md)

## 配置

两端配置相同密码：

```yaml
obfs:
  type: presto
  presto:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

唯一参数 `obfs.presto.password` 接受 32..1024 字节。分享链接使用
`obfs=presto&obfs-password=...`，没有额外形态参数。

密码和角色确定完整语法，不依赖 IP、端口、机器 ID、外部文件或服务端下发种子。
同密码、同角色在 Windows / Linux 上编译一致；需要不同形态的服务器应使用不同随机密码。

## 编译与采样

HKDF-SHA256 的四个独立 info 域为 `aead/client-to-server`、`aead/server-to-client`、
`genome/client-to-server`、`genome/server-to-client`，分别生成双向 AEAD 密钥和语法输入。

每方向有四个隐状态。每个状态编译出：

- 目标包长中心 520..1184 字节、扰动宽度 8..40 字节。
- 突发长度 4..24 包、计划间隔基值 100..2300μs。
- 四个严格为正的整数转移权重，并增加一个密码选择的目标状态权重。

运行时以独立 32 字节随机种子初始化 ChaCha8 形态采样器，随机选择初态及
`[-12,12]` 字节会话偏移。AEAD nonce、会话 ID 和填充仍使用 `crypto/rand`。
每片依转移矩阵选择下一状态和目标长度，按密码派生的倾向及容量限制切片。

不足目标长度时在填充预算内补足一部分。语法定义的是有界变换规则，实际分布还会受
输入负载、MTU 和分片上限影响。突发计数耗尽后才在后续外层包前等待计划间隔；
不聚合 QUIC 数据报，也不在空闲时主动发送。

## 分片、前导与开销

| 项目 | 范围 / 行为 |
| --- | --- |
| 内层 / 外层上限 | 1200 字节 / 1232 字节 UDP payload |
| 分片 | 最多 4 个不等长片，独立认证 |
| 固定认证封装 | 每片 84 字节 |
| 填充 | 每内层数据报最多其长度的 1/3，且每片最多 512 字节 |
| 客户端前导 | 每发送会话最多 4 包，合计最多 768 字节 |
| 服务端前导 | 建立认证回包路由后发送 cover 帧，最多 3 包 / 480 字节 |
| 突发间隔 | 计划值最多 2.5ms，实际等待还受调度与排队影响 |

前导不等待确认，也不重传。发送同步执行，无后台发送队列，Close 和写 deadline
可中断等待。共享 socket 的短暂等待可能产生队头阻塞。

## 报文与接收

每片格式为 `nonce[24] || XChaCha20-Poly1305(header || payload || padding)`。
没有明文协议编号、长度头或 genome 标识。44 字节加密头如下，整数为 big-endian：

| 偏移 | 长度 | 内容 |
| --- | ---: | --- |
| 0 | 16 | 随机发送会话 ID |
| 16 | 8 | 消息 ID；分片共享 ID，cover 使用独立 ID |
| 24 | 8 | 发送会话出生 Unix 秒 |
| 32 | 2 | 原始数据报长度 |
| 34 | 2 | 本片偏移 |
| 36 | 2 | 本片数据长度 |
| 38 | 1 | 片序号 |
| 39 | 1 | 总片数 |
| 40 | 1 | 类型：0 数据、1 服务端前导 cover |
| 41 | 1 | 版本 1 |
| 42 | 2 | 保留 0 |

先检查长度和来源预算，AEAD 与头校验通过后才分配会话。接收拒绝重叠、重复片、
片数/总长冲突和重组缺口；不跟随发送端 Markov 状态，因此丢包不会导致永久语法失步。
同一活动会话绑定源端点及出生时间，新客户端会话完成认证后可更新服务端回包会话。

| 接收资源 | 上限 |
| --- | --- |
| 会话 | 1024；每 IPv4 / IPv6 `/64` 最多 8 个；空闲 TTL 2 分钟 |
| 重组 | 全局 512 项、每会话 32 项、payload 600KiB；缺片 TTL 3 秒 |
| 验签 | 全局 32768/s、burst 4096；256 来源桶各 8192/s、burst 2048 |
| 新会话准入 | 64/s、burst 128 |
| 重放窗口 | 256 消息 |

会话重组槽满时仅淘汰自身最旧未完成项；发送会话空闲 1 分钟或存活 10 分钟后轮换。

## 验证摘要

- 两批本机流量语法实验各完成 **128/128 会话**（16 密码 × 8 会话），同密码各会话
  长度序列均不同。前 4 会话训练、后 4 会话留出；最终包长/转移分类为 **64/64**，
  仅时序为 59/64。这验证密码确实改变形态，不是未知流量的抗识别测试。
- 同一混合尺寸负载下，各密码的外层 payload / 内层均值为 **1.314..1.502**。
- Windows / Linux 正常 TLS 的 IPv4/IPv6 TCP 和代理 UDP 回环通过；Linux 隔离回环
  MTU1280、netem 20ms 条件通过。Linux 相关 race、三模块 vet 及三组 fuzz 通过；
  四个实现文件语句覆盖率 **94.0%**。
- 2026-10-31 公网测试的 **3 个随机密码均完成双向各 128KiB**，前后 Gecko 对照也完成。
  测试使用发布 CLI、旧 BBR standard 和正常 TLS；中途控制端退出导致原定重复 A 未执行，
  已保留该中断，不将两段短测试作为连续性能比较。

完整形态、开销和公网记录在 `build/presto/`；详细经过见
[构建与验证历史](../BUILD-REPORT.md)。

## 本机复现与来源

在仓库根目录执行，实验输出目录需为新目录：

```sh
go test ./extras/obfs ./app/cmd -run Presto -count=1
OMHY_PRESTO_TRACE_DIR="$PWD/presto-traces" \
  go test ./extras/obfs -run '^TestPrestoTrafficGrammarExperiment$' -count=1 -timeout=6m -v
python tests/network/presto_analyze.py presto-traces --output presto-summary.json
```

实验仅使用本机回环 UDP，记录包长和用户态接收时序，不保存载荷。
设计参考 Winter / Pulls / Fuss 的 [2013 年论文](https://arxiv.org/html/1305.3199v1)
中共享秘密准入及可变流量形态的理念。实现及测试为原创 MIT-0，未引入 ScrambleSuit /
obfsproxy 的实现、握手或票据格式，与 Tor Project 无隶属关系。
