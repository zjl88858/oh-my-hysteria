# Carakan：逆向 tANS 降熵整形

Carakan 使用 **tANS Target-Spectrum Homophonic Shaping**，将认证密文作为高熵
比特流输入 tANS 解码状态机，输出密码派生的低熵字节符号；接收端反向编码恢复。
当前仅提供带认证纠删修复的线格式 **v3**，密码派生域为 `oh-my-hysteria/carakan/v3`。

[混淆选型、部署要求与安全说明](obfuscation.md) · [返回 README](../README.md)

## 配置

客户端和服务端使用相同密码、相同目标熵：

```yaml
obfs:
  type: carakan
  carakan:
    password: "REPLACE-WITH-AT-LEAST-32-RANDOM-BYTES"
    targetEntropy: 4.0
```

| 参数 | 默认值 | 范围 |
| --- | --- | --- |
| `password` | 必填 | 32..1024 字节 |
| `targetEntropy` | `4.00` | 1.00..7.50 bits/byte，步长 0.01 |

显式 0、非有限数、越界或更细精度会被拒绝。分享链接使用 `obfs=carakan`、
`obfs-password` 和可选 `carakan-target-entropy`。从旧开发构建升级时需同时更新两端。

## 目标熵与开销

目标熵控制量化表的名义字节谱，不要求每个短包精确命中，也不保证严格 IID。
有限状态、随机初态及收尾会影响实测边际 Shannon 熵；它与含状态相关性的熵率不同。

这是可逆整形而非压缩。符号层理想膨胀约为 `8/H`，另外需要支付认证、结束路径、
分片与修复成本。容量使用 `floor(H)` 的最坏界，因此靠近整数下界时仍有分片台阶。

当前实现的本机混合尺寸负载结果如下；每档为 8 个密码 × 2 个会话，每方向 64 条消息：

| 目标 H | 平均实测边际熵 | 外层 payload / 内层字节 | 1200 字节数据片 + 修复片 |
| --- | ---: | ---: | ---: |
| 1.00 | 0.999999 | 16.7424 | 13 + 4 |
| 2.50 | 2.506339 | 5.6576 | 5 + 2 |
| 4.00 | 3.999932 | 3.1092 | 3 + 1 |
| 4.50 | 4.503886 | 2.7920 | 3 + 1 |
| 7.50 | 7.496751 | 1.7296 | 2 + 1 |

熵按每个密码、会话和方向分别计算后取均值，未混合不同密码的直方图。
上述 80/80 会话完成，所有外层 payload 均不超过 1232 字节。

## 编译目标谱

目标熵规范化为 `code=round(H*100)`，参与谱及双向 AEAD 派生域。
`spectrum/<code>` 经 HKDF-SHA256 派生 32 字节 ChaCha20 密钥，使用零 nonce、
计数器 0 生成确定性编译流；little-endian uint16 拒绝采样用于 Fisher–Yates 置换。

1. 表大小 `L=16384`，`R=14`。令 `m=floor(H)`、`B=2^m`、`U=L/B`。
2. 在 `n=0..U/2` 中选使 `m+h2(n/U)` 最接近 H 的整数，平局取较小 n。
   每个基础类拆成频数 `U-n` 与 `n` 的两个 homophone，再映射到密码置换后的字节值。
3. 对非零频数 `f_s` 创建 `j=f_s..2*f_s-1` 的行，
   `nb=R-floor(log2(j))`、`base=(j<<nb)-L`，然后置换完整解码行。
4. 每行输出符号 s，取 nb 位 v，进入 `state=base+v`。接收端用 s 和后继状态反查。
   编码索引共 L 项；每步至少消费 m 位。
5. 从终态 0 反向 BFS 生成最短收尾路径，要求全部状态可达、最远不超过 32 个符号。
   最多尝试 16 张确定性候选表，编译失败报配置错误。

表只在初始化时编译，运行时不通过筛选密文、追加无界填充或载荷重采样逼近目标。

## 认证与整形格式

先使用方向分离的 XChaCha20-Poly1305 加密认证，再进行整形：

- 密钥 info：`aead/client-to-server/<code>`、`aead/server-to-client/<code>`。
- nonce：`random_session_id[16] || uint64_be(message<<5 | index)`，完整 24 字节。
  会话前缀为 128 位随机数，消息号 59 位、片号 5 位；发送失败也消费消息号。
- 每片加密头 12 字节：`born8 || packed_total_k2 || width2`，整数为 big-endian。
  packed 高 5 位为 `k-1`，低 11 位为内层总长；片大小由认证明文长度得到。
- `raw = nonce || ciphertext_and_tag`，固定认证开销 52 字节；
  AEAD AAD 为 `uint16_be(len(raw))`。

tANS 源序列为：

```text
(nonce XOR SHA256(ciphertext_and_tag)[:24])[24]
    || uint16_be(len(raw)) || ciphertext_and_tag
```

公开可逆的白化分散结构化 nonce 对初态的影响。全部字节按 LSB-first 取位，前 14 位
构成初态；状态机消费剩余输入，末次不足位规范补零，再沿最短收尾路径到状态 0。

完整符号序列 P 按密码派生的位移循环左移，不增加线上字节。`interleave/<code>`
派生 HMAC-SHA256 密钥，其输入为 `uint16_be(len(P)) || 256个uint16_be字节计数`；
MAC 前 8 字节按 big-endian uint64 取模 `len(P)` 得位移。直方图旋转不变，接收端可
计算同一位移后右移。交织保持包长及单包直方图，只分散收尾接缝的位置。

接收端从终态 0 倒序恢复位流，读取 raw 长度并逆白化，再重新整形与交织，要求与
收到的 payload 完全一致。规范解码、AEAD 验证和头校验全部通过后才建立接收状态。
编码、解码与最多 1232 个符号线性相关。

## 握手分片与纠删修复

握手和数据使用同一路径：内层 1..1200 字节，外层 UDP payload ≤1232 字节。
由表的 `maxTail` 与 m 计算容量：

```text
rawMax  = min(684, floor((1232-maxTail)*m/8)-2)
partMax = rawMax-52
k       = ceil(inner/partMax)
r       = 0                         if k == 1
          min(4, ceil(k/4))          otherwise
```

单片时 `width=inner`；多片时在
`ceil(inner/k)..min(partMax, floor((inner-1)/(k-1)))` 中一次随机选择片宽。
前 k-1 个数据片等宽，末片保存余下正长度。`partMax` 为 96..632 字节，故 1200 字节
内层报文总是分为 2..13 个数据片及 1..4 个修复片，共 3..17 个外层包。

采用系统 Cauchy GF(256) 纠删码，多项式 `0x11d`，修复行 j、数据列 i 的系数为
`inverse(j XOR (32+i))`。末数据片在计算中补零，修复片宽度均为 width。
nonce index 的 `0..k-1` 为数据，`k..k+r-1` 为修复。

每片独立认证。收到任意 k 个不同合法片后，可恢复最多 r 个缺失数据片，最多求解
4 阶矩阵；恢复出的末片补零区必须为零。接收允许 `k≤28`、`k+r≤32`，并检查
`(k-1)*width < total ≤ k*width` 及每片精确长度。

数据片先发、修复片后发；没有外层反馈重传、主动延迟、前导或空闲 cover。
超过冗余能力、重组期限或资源上限的消息仍依赖 QUIC 处理。

## 接收资源与统计

| 项目 | 上限 / 策略 |
| --- | --- |
| 接收会话 | 1024；每 IPv4 / IPv6 `/64` 最多 8 个；空闲 2 分钟清理 |
| 发送会话 | 空闲 1 分钟或存活 10 分钟后轮换 |
| 重组 | 全局 512 组、每会话 32 组；TTL 3 秒 |
| 重组字节 | 数据及修复合计 600KiB；单组最多 1832 字节 |
| 重放窗口 | 256 个消息 |
| 解码 / 验签 | 全局 16384/s、burst 2048；256 来源桶各 4096/s、burst 1024 |
| 新会话准入 | 64/s、burst 128 |

完整认证数据报交付后才建立回包路由。同步发送沿用 socket deadline，Close 释放阻塞
读取并清空接收状态。`CarakanStats()` 提供目标/名义谱熵、容量、收发及丢弃计数，
并报告修复片字节、恢复消息数、恢复数据片数和恢复失败数。

交付后迟到的修复片计为 `RedundantRepairPackets`；提前修复后迟到的原数据片可能计为
`ReplayDrops`。发送字节分析需包含 `SentRepairBytes`。

## 验证摘要

- 独立 Python 与 Go 编译/纠删向量一致；13+4 码字至多 4 片擦除的 **3214 种子集全部恢复**。
- 相同本机 36 条件计划（3 密码 × 3 目标 × 4 损伤条件）完成 **36/36**；仅测试性关闭
  修复的消融为 33/36。H=1.5、20% 下行独立丢包组为 3/3 完成，关闭修复后为 0/3。
- 正常 TLS 的 TCP/代理 UDP、IPv4/IPv6 集成和认证/资源边界回归通过；五个实现文件
  覆盖率 617/659（93.63%），四组各 20 秒 fuzz 通过。
- 2026-10-31 公网使用同核心观测构建，正常 TLS，每档一次冷连接、双向各 4KiB：

  | H | 建连耗时 | 结果 | Windows 恢复消息 / 数据片 |
  | --- | ---: | --- | ---: |
  | 2.0 | 0.4975 秒 | 完成 | 2 / 2 |
  | 1.5 | 0.5127 秒 | 完成 | 7 / 9 |

  H=1.5 的一个 1200 字节消息在缺 3 个数据片时仍由 10 数据 + 3 修复恢复，内层指纹
  与发送端一致。直接恢复计数与事件顺序联接相符。该观测端点不是发布 CLI 测速；
  当前格式的公网样本仅覆盖以上两档，默认 H=4 的验证来自本机测试。

完整证据在 `build/carakan-fec/`，包括 `comparison.json`、`spectrum-final-summary.json`
和 `public/summary.json`。历史阶段单列于 [构建与验证历史](../BUILD-REPORT.md)。

## 本机复现与来源

在仓库根目录执行：

```sh
go test ./extras/obfs ./app/cmd -run Carakan -count=1
python -m unittest discover -s tests -p 'test_carakan*.py'
OMHY_CARAKAN_TRACE_DIR="$PWD/carakan-traces" \
  go test ./extras/obfs -run '^TestCarakanSpectrumExperiment$' -count=1 -v
python tests/analyze_carakan.py carakan-traces --output carakan-summary.json
```

谱实验只使用本机回环，输出目录需为新目录。实现为原创 MIT-0；数学背景参考 Jarek Duda
的 [ANS 论文](https://arxiv.org/abs/1311.2540)。未引入 FSE、Zstandard 或 JavaScript
引擎依赖，名称不表示与 Opera 存在关联。
