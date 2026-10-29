# Blink v1：实验性 L4 UDP 混淆

Blink 是可选的、与 Gecko 不互通的独立外层；不改变 Hysteria2 的 QUIC/TLS、
应用认证、拥塞控制默认值或 Brutal 协商。两端显式选择 `obfs.type: blink`，
不自动探测、不回退 Gecko/Salamander/裸 QUIC。同端口不混用这些协议。

## 配置

两端至少配置相同的高熵密码；建议密码管理器生成32字节以上随机值，勿使用示例。

```yaml
obfs:
  type: blink
  blink:
    password: "REPLACE-WITH-A-LONG-RANDOM-SECRET"
    maxPacketSize: 1232
    fragmentation: true
    paddingMax: 32
    # 客户端可用；服务端不要设为非零
    junkPackets: 2
```

服务端删除 `junkPackets` 或设 `0`。分片发送与接收都需 `fragmentation: true`，
不协商降级；开销较低的默认配置是不分片、外层上限1400。`1232 + 分片` 适用于
IPv6最小1280字节IP MTU（不含额外隧道/扩展头）；512字节上限可用于测试，
不是推荐的吞吐配置。所有大小字段均指 **UDP payload**，不是IP MTU。

| 字段 | 默认 / 硬边界 | 含义 |
| --- | --- | --- |
| `password` | 必填16..1024字节 | 至少16字节不代表足够熵；AEAD使弱密码可被离线猜测 |
| `maxPacketSize` | 1400；512..1400 | 本端发送UDP payload上限；不分片至少1272 |
| `paddingMax` | 32；0..128 | 每内层数据报的可选padding上限，另受10%比例/外层空间限制 |
| `junkPackets` | 客户端2，服务端0；0..4 | 每客户端socket仅一轮，显式0关闭 |
| `fragmentation` | false | 两端显式启用；接收最多4片 |
| `maxSessions` | 1024；1..4096 | 本端已验签的接收会话上限 |
| `maxReassemblyBytes` | 1MiB；1200..8MiB | 重组payload总预算，另受512条目硬限额约束 |
| `verifyPacketsPerSecond` | 32768；64..262144 | 全局AEAD尝试token速率，不是带宽限速器 |

`paddingMax` / `junkPackets` 省略与显式0不同。其他数字字段0选择默认值。
分享URI支持 `obfs=blink`、`obfs-password` 及 `blink-fragmentation=1`、
`blink-max-packet-size`、`blink-padding-max`、`blink-junk-packets`；本地内存/CPU
限额不随URI导出。URI含密码，应视作凭证。首版不支持端口跳跃，显式拒绝而非退回裸UDP。
普通固定UDP端点的NAT源端口变化可产生新的接收会话；Realm等复合传输未做专项验收。

## 设计参考与独立性

参考 AmneziaWG Go 固定版本
[`b5928efb6ca19f0153958460c3d141f04abc5c2e`](https://github.com/amnezia-vpn/amneziawg-go/tree/b5928efb6ca19f0153958460c3d141f04abc5c2e)
（2026-08-28）的README与 `device/send.go` / `receive.go`，核对了Git blob和SHA256。
借鉴的是有限junk、消息长度/padding变化、每会话参数差异，以及不超过底层MTU的原则。
没有复制/链接/执行上游实现，不使用WireGuard的H1..H4、S1..S4、Noise握手、
接收者索引、cookie或重密钥消息格式；不假扮DNS/DTLS等无关应用协议。
Blink新代码独立使用MIT-0；已有Go密码库的许可证义务保持不变。

## 独立封装（实验性v1，未作第三方密码审计）

```text
24-byte CSPRNG nonce || XChaCha20-Poly1305(ciphertext || 16-byte tag)
plaintext: 16-byte session ID | 8-byte message ID | total(u16) | size(u16)
           | fragment index(u8) | fragment count(u8) | version(1) | reserved(0)
           | fragment payload | optional padding
```

无公开固定magic、消息类型或QUIC长/短头透传；头、payload和padding全部认证加密。
固定开销 **72字节/片**。密码通过HKDF-SHA256与Blink v1域标签派生两个方向的
独立密钥，阻止直接反射；使用标准库HKDF与x/crypto的XChaCha20-Poly1305，
不自行实现密码原语。nonce每片独立使用 `crypto/rand`，失败显式返回错误。

每个发送会话随机128-bit ID、padding上限（配置上限的一半到上限），每个数据报
重新选padding；分片与否还受随机选择和有界credit约束。双向会话ID不必相同；
接收方无需在验签前猜测参数或轮询密钥。会话参数变化不是密钥轮换，不提供外层
前向保密；内层QUIC仍负责TLS前向保密、业务认证和可靠性。

完成/放弃消息有固定256消息的重放窗口；重复片不延长条目TTL，乱序可重组。
重放保护只在接收会话状态存续期间有效，超出窗口的旧消息丢弃；状态过期后可能
再次交付历史合法外层包给QUIC，不替代TLS/QUIC的重放或0-RTT安全策略。

## 流量、MTU和CPU预算

- **前导干扰**：仅客户端首次 `WriteTo` 前一轮，0..4包，每包64..192字节，
  至多768字节UDP payload（IP/UDP头另计）。写失败也消耗这轮机会；不随每次
  QUIC PTO重复，没有延时器、周期保活干扰或服务端干扰响应。重新建立socket
  会重新产生一轮，重连风暴仍需上层退避。
- **Padding**：每个内层数据报的总padding≤`floor(inner/10)`、配置上限、会话
  上限及外层剩余空间的最小值。72字节固定头/tag不算可选padding，小包的总
  相对开销可能很高，不能宣称“总流量增加≤10%”。
- **分片**：内层只接收1..1200字节，协议硬上限4片。由于外层MTU不足导致的
  必要分片有固定倍增成本；额外随机二分只用于≥512字节的消息，credit从0开始，
  每4个合格消息最多增加一个额外数据报，credit上限8。接收端不重传或自行重试，
  丢一片即整个QUIC数据报暂时丢失，可能增加QUIC重传开销。
- **PMTU**：结构化PacketConn opt-in契约使Blink下QUIC固定1200字节、关闭
  内层PMTU探测和Chrome-parrot初始1250字节扩张，禁用GSO；其他混淆/原UDP
  不改。可传递底层DF/socket buffer操作，但不暴露会绕过封装的ReadMsgUDP/
  WriteMsgUDP批量接口；不支持ECN透传。外层 `EMSGSIZE` 不自动放大/分片重试，
  需调低外层上限并启用用户态分片。平台/底层wrapper不能设置DF时，不能保证
  内核绝不做IPv4分片；未部署自动外层DPLPMTUD或ICMP黑洞恢复。
- **CPU**：长度先筛选，AEAD最多一次/收到的片。全局token默认32768次/秒、
  burst4096；固定256槽的keyed-hash源桶各为全局速率1/4、burst2048。IPv4按IP，
  IPv6按/64，不随源端口分配新桶；哈希碰撞和共享公网IP会共享预算。每次有效
  输入最多清理8个过期重组+8个过期会话，无全表扫描；重放窗口常数4个word。
  这约束验签工作，不约束网卡中断、socket读取或操作系统成本；大规模DDoS仍
  需要防火墙/上游限速。超过预算也可能丢合法包，不做“可信流量”承诺。
  以1200字节内层消息计，默认单源8192次/秒在1/2/3片时对应理论内层上限约
  79/39/26Mbps（尚未计ACK、小包、无效包和共享桶）；不是线路吞吐保证。
  高速部署需显式评估提高CPU预算或减少分片，不能把默认限额当作无成本的防护。

## 服务端状态与放大边界

1. 无效长度、错误方向/密码、篡改或不支持的版本在分配会话/重组状态前丢弃；
   未验签源地址不进入map。随机junk不携带认证，也不触发任何响应。
2. 验签后新会话准入全局64/秒、burst128；每IP/IPv6 /64最多8个接收会话，
   防止改变端口绕过配额，但大型CGNAT下也会限制合法客户端。
3. 每会话最多32个未完成消息、全局最多512个，同时按原始总长度预留payload
   内存预算；默认实际payload硬界≤`min(1MiB,512*1200)`=600KiB。元数据、map、
   slab/Go heap/GC及socket buffer另计，**不是整个进程RSS≤1MiB**。
4. 满槽时只O(1)回收该会话自己的最旧缺片消息，不驱逐其他会话。跨会话的总
   预算耗尽时拒绝新条目，旧片/冲突片不能扩大分配。合法持钥恶意用户仍可占满
   本人的额度或全局预算；共享PSK不是逐用户认证。
5. 缺片TTL3秒、接收会话空闲TTL2分钟，按I/O惰性清理；没有每会话goroutine或
   无限GC队列。完全空闲时有界内存可能保持到下次有效I/O或Close；Close清空状态。
6. 服务端不会仅因junk/未认证外层包发送challenge、echo或分配重组；只有完整
   认证数据交给QUIC。QUIC继续负责路径验证和抗放大，额外framing/padding会
   改变物理字节比，因此不能把内层QUIC的3倍规则宣称为精确的外层3倍上限。
   持钥者可以伪造外层源地址，本层不提供源地址所有权证明。
   捕获过合法密文的攻击者也可能将它从不同源地址重放，消耗有界的新会话准入；
   重放窗口按端点/会话隔离，不是全网密文去重。硬预算限制资源占用，不保证合法
   客户端在此类攻击下仍能进入；未实现stateless地址cookie或逐用户外层密钥。

## 验证边界

单元/有界fuzz覆盖头验证、篡改/反射、重放、重复/乱序/缺片、过期、每来源/会话/
全局内存与条目限额、无效包洪泛零会话分配、短写和超长UDP的Windows EMSGSIZE。
正常TLS证书验证下测试1MiB随机TCP回环SHA256和32次UDP回环，包含IPv4默认、
IPv6外层1232和外层512三种模式；不是运营商线路抗DPI测试。
IPv6在回环上测试外层大小约束，没有实际修改链路MTU。TCP与UDP验证阶段之间
等待250ms使默认源验签桶恢复；不把高速TCP突发限速下的QUIC DATAGRAM视作
无损通道。首轮Linux512字节模式在紧接TCP突发的UDP阶段超时，原始失败保留；
此阶段划分不改变生产限速，也未增加UDP重试，不能宣称混合负载下零丢包。

首轮低burst+4重组槽在高速回环中出现多秒自限速；保留在 `build/blink/initial/`。
修正为有界更大的burst和32槽，并增加“仅回收本会话旧缺片”的进展规则；不删除
反例，也不把通过一次传输当作丢包/吞吐/抗识别的全面验证。Windows race有
运行库启动错误时单列为不可用，不伪报通过。具体结果追加在 `BUILD-REPORT.md`。

Blink比Gecko多了外层认证、全数据报封装、明确预算和会话差异，但“更难被特定
DPI识别”尚未证明。包长、时间、目标IP、流量方向、重连行为和此封装自身的统计
特征仍可识别；没有真实对手模型、盲测或第三方审计，不承诺“无法封锁/不可探测”。

最终Linux三模块全量测试、Blink/Gecko/Salamander兼容race、三类有界fuzz及vet
通过；Blink文件语句覆盖率93.5%。最终三个分相TLS/TCP/UDP回环均通过并回收状态。
Linux 1200字节null-sink封装微基准约2.9µs（仅封装）、4.6µs（默认padding）、
6.0µs（1232分片）、9.6µs（512分片），稳态发送0 alloc/op；不含系统调用或网络，
不是实际吞吐。完整数字/原始失败在 `BUILD-REPORT.md` 与 `build/blink/`。
上述实现验证阶段没有公网Blink或LTE测试，UDP443/命名空间/本轮远端进程均核验
为空；VPS保留。随后经用户明确授权的公网测试另记如下，不覆盖前阶段证据。

## 首次有界公网验证（2026-10-29）

按预声明顺序Gecko → Blink默认1400/不分片 → Blink1232/分片 → Gecko运行
4个冷连接，统一旧BBR standard、正常域名TLS校验和固定Windows客户端名；
每连接下载/上传各256KiB，合计2MiB应用数据，无重试或协议回退。

| 条件 | 下载Mbps | 上传Mbps | 端到端wall秒 | 观测IPv4字节 | 包数 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Gecko前对照 | 2.95 | 2.06 | 3.250 | 680683 | 727 |
| Blink默认 | 2.88 | 2.08 | 3.250 | 633112 | 658 |
| Blink1232分片 | 2.89 | 2.04 | 3.281 | 682021 | 1126 |
| Gecko后对照 | 2.94 | 2.13 | 3.187 | 635679 | 677 |

wall使用本机Python 3.11.1的GetTickCount64，分辨率约15.6ms；几十毫秒的差异
不能解读为稳定的延迟优劣，分方向speed也不是包含握手/收尾的总吞吐。

4/4完成；Blink默认最大观测UDP payload为1304字节，分片模式为1227字节，分别
未超1400/1232上限。合计观测2,631,495 IPv4字节，低于6MiB预算，capture drops=0；
这不等于网络无丢包，也不是运营商计费量，不含漫游隧道/链路层开销和VPS前丢失
的上行。整连接字节含握手、ACK、控制、重传及收尾，不能直接当作纯padding开销。

在这组短连接小负载下，Blink传输表现接近Gecko，但分片明显增加包数；不能由
一两个样本证明不劣于Gecko、抗DPI更强、长期稳定或混合负载零丢包。此轮仅TCP
测速流经QUIC/UDP，未做公网代理UDP回环或攻击洪泛；release CLI不导出BlinkStats，
因此没有公网验签/重组丢弃率、CPU/RSS或精确网络丢包率的证据。

服务、抓包、临时客户端/服务端配置已清理，无UDP443监听或本轮远端进程；VPS
继续保留。结果/包长直方图/清理在 `build/blink/public/`，无包内容落盘，不改变源码
或已测试二进制。未扩大LTE负载，也未据结果调参。
