# Trident：密码编译字节码方言

Trident 使用 **Key-Compiled Bytecode Dialect**：从密码编译 64 指令的自定义 ISA，
将认证密文编码为可独立解析的字节码程序。字节码仅承载数据，不执行指令。
当前派生域为 `oh-my-hysteria/trident/v1`。

[混淆选型、部署要求与安全说明](obfuscation.md) · [返回 README](../README.md)

## 配置

两端配置相同密码：

```yaml
obfs:
  type: trident
  trident:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
```

唯一参数 `obfs.trident.password` 接受 32..1024 字节。分享链接使用
`obfs=trident&obfs-password=...`；ISA、对齐与分片均自动确定，无额外参数。
同密码服务器共享 ISA，双向认证密钥分别派生。

## ISA 编译

HKDF-SHA256 的 info 分别为 `isa`、`aead/client-to-server`、`aead/server-to-client`，
各取 32 字节。ISA 种子作为 ChaCha20 key，零 nonce、计数器 0 生成编译流。

编译器从小端 uint16 做拒绝采样，再执行 Fisher–Yates，从 256 个字节值中无放回
选择 64 个 opcode。操作数长度分布为 `8×0、8×1、8×2、16×4、24×8` 字节，置换
后分配给指令；对齐取 1 / 2 / 4，且不大于非零操作数长度。

编译只在创建 PacketConn 时执行；运行时直接索引，不搜索操作码或重新派生密码。

## Byte-Split Packing

先使用方向分离的 XChaCha20-Poly1305 加密，再编码。令
`ciphertext = AEAD(header[44] || fragment)`、`raw = nonce[24] || ciphertext`，
编码输入为：

```text
nonce[24] || uint16_be(len(raw)) || ciphertext
```

长度两字节同时作为 AEAD AAD。位流按 LSB-first 读取：每次取 6 位作为指令索引，
写入 opcode，将操作数起点按相对 UDP payload 的偏移对齐，再写规定数量的 8 位操作数。
对齐字节、最后不足位和不足操作数字节均补零。

接收使用 256 项反向表恢复索引位及操作数；192 个非 opcode 值在指令位置非法。
读到第 26 字节后确定 raw 长度，必须在承载全部源位的第一条完整指令结束；
后续指令、非零尾位或对齐字节均拒绝。之后验证 AEAD 和分片头，再建立接收状态。

每条指令至少承载 6 位，编解码时间为 O(输入+输出)，无需跨报文词典或同步状态。
`raw≤600`，最坏外层长度满足 `wire < 2×(raw+2)+18 ≤1222`，同时显式检查 1232 上限。

## 握手分片与开销

| 项目 | 范围 / 行为 |
| --- | --- |
| 内层 / 外层上限 | 1200 字节 / 1232 字节 UDP payload |
| 数据片容量 | 每片最多 516 字节，raw 最多 600 字节 |
| 分片 | 最多 4 片；1200 字节握手及数据报必分 3–4 片 |
| 固定认证封装 | 每片 84 字节，另加字节码编码开销 |
| 发送方式 | 同步发送，无主动延迟、前导、空闲 cover 或外层重传 |

对至少 256 字节的数据报，以 1/2 概率增加一片（总数不超过 4）。按照剩余容量、
片数及最多 64 字节的最小分片下界随机切分不等长区间，末片取剩余数据。
握手后仍使用同一分片规则；缺任意片时不交付该内层数据报，可靠重传由 QUIC 负责。

## 认证分片头与资源

44 字节加密头如下，整数为 big-endian：

| 偏移 | 长度 | 内容 |
| --- | ---: | --- |
| 0 | 16 | 随机发送会话 ID |
| 16 | 8 | 消息 ID，同一数据报各片共享 |
| 24 | 8 | 发送会话出生 Unix 秒 |
| 32 | 2 | 内层数据报总长 |
| 34 | 2 | 本片偏移 |
| 36 | 2 | 本片数据长度 |
| 38 | 1 | 片序号 |
| 39 | 1 | 总片数 |
| 40 | 1 | 保留 0 |
| 41 | 1 | 版本 1 |
| 42 | 2 | 保留 0 |

每片使用随机 24 字节 nonce；头后只有数据，不另加认证层填充。接收拒绝重复片、
重叠、缺口、总长/片数冲突、过期、源端点迁移及完成消息重放。

| 接收资源 | 上限 |
| --- | --- |
| 会话 | 1024；每 IPv4 / IPv6 `/64` 最多 8 个；空闲 TTL 2 分钟 |
| 重组 | 全局 512 项、每会话 32 项、payload 600KiB；缺片 TTL 3 秒 |
| 解码 / 验签 | 全局 32768/s、burst 4096；256 来源桶各 8192/s、burst 2048 |
| 新会话准入 | 64/s、burst 128 |
| 重放窗口 | 256 消息 |

会话重组槽满时仅淘汰自身最旧未完成项；发送会话空闲 1 分钟或存活 10 分钟后轮换。
Close、deadline 与 socket 接口遵守 PacketConn 约定，批量/GSO 路径不能绕过封装。

## 验证摘要

- 本机 16 密码 × 4 会话，**64/64 完成**；42,021 个收到的 UDP 程序均通过已知 ISA
  的规范解析。16 个 opcode 集互异，同密码双向共享指令集，全部方向序列哈希不同。
- 同一混合负载的外层 payload / 内层字节为 **1.4986**，每密码均值 1.4525..1.5428。
- Windows / Linux 正常 TLS 的 IPv4/IPv6 TCP、代理 UDP 回环通过；Linux 隔离回环
  MTU1280、netem 20ms 条件通过。Linux 相关 race、三模块 vet、四组各 20 秒 fuzz
  通过；四个实现文件覆盖率 **434/455（95.4%）**。
- 600 字节 raw 编码/解码微基准均为 **0 B/op、0 allocs/op**。
- 2026-10-31 公网的 **3 个随机密码均完成双向各 128KiB**，前后 Gecko 对照也完成。
  使用发布 CLI、旧 BBR standard 和正常 TLS。实际 3508 个 Trident 外层包均通过
  已知 ISA 的独立语法检查；发布 CLI 未导出公网验签/重组丢弃计数。
  三次 Trident 整连接 IPv4 字节均值比两次对照高约 47.9%，包含握手与控制流量。

完整记录在 `build/trident/`，开发过程与环境限制见
[构建与验证历史](../BUILD-REPORT.md)。

## 本机复现与来源

在仓库根目录执行，实验输出目录需为新目录：

```sh
go test ./extras/obfs ./app/cmd -run Trident -count=1
go test ./extras/obfs -run '^$' -bench BenchmarkTridentPacking -benchmem
python -m unittest discover -s tests -p test_trident_reference.py
OMHY_TRIDENT_TRACE_DIR="$PWD/trident-traces" \
  go test ./extras/obfs -run '^TestTridentBytecodeExperiment$' -count=1 -v
```

实验仅监听本机回环，记录包长、opcode 计数与序列哈希，不保存密文或载荷。
实现及测试为原创 MIT-0，仅使用现有 Go 标准库和 x/crypto；没有引入真实 VM 或浏览器引擎。
