# BBRv3 实验性 profiles

`bbrProfile` 现在按 `congestion.type` 独立解释：旧 `bbr` 的 profiles 不变，
`bbr3` 使用自己的三档预设，不复制 BBRv1 的采样器、状态机或完整参数集合。

```yaml
congestion:
  type: bbr3
  bbrProfile: aggressive # standard（默认）/ conservative / aggressive
```

两端分别设置，各自影响发送方向。不填写客户端 bandwidth 以免协商到 Brutal；
服务端需要时用 `ignoreClientBandwidth: true`。仍拒绝 BBRv3 + HyStart++。
大小写归一，空值归一为 `standard`，未知值报配置错误。

## 参数与意图

| 参数 | conservative | standard | aggressive |
| --- | --- | --- | --- |
| Startup pacing gain | 2.25 | 2.77 | 3.00 |
| 常规 cwnd gain（含 Startup） | 1.75 | 2.00 | 2.25 |
| ProbeBW_UP pacing gain | 1.15 | 1.25 | 1.35 |
| ProbeBW_UP cwnd gain | 2.00 | 2.25 | 2.50 |
| 已建立长期 flight 上限的 headroom | 20% | 15% | 10% |
| 探测时间等待范围 | [3,4) 秒 | [2,3) 秒 | [1,2) 秒 |
| Reno 风格探测 round 上限 | 80 | 63 | 48 |

时间和 packet-round 条件先满足者触发；round 阈值还取决于估计 BDP / cwnd，
所以等待范围不是保证每次探测间隔恰好落在该区间。headroom 只在长期上限
已建立时生效，不是始终主动闲置相应比例的链路。

`standard` 保持之前已验证的 BBRv3 参数和默认行为。另两档是预先声明的、
偏离该草案基线的**本地策略实验**，不是 IETF 的额外标准档位，也不是针对一条
线路自动寻找出的最优解。保守旨在减小探测压力；激进旨在更快 / 更强地尝试
获得带宽，可能增加队列、丢包和对其他连接的影响，不能保证有效吞吐更高。

## 不随 profile 改变的机制

- delivery-rate 采样、未知 ACK、PMTU、PTO、退休及字节计账。
- 2% loss 阈值、0.7 模型退避和 Classic CE 响应；不把忽略丢包当作“激进”。
- Startup 平台 / 恢复退出条件、ACK phases、spurious undo 的完整性要求。
- Drain / DOWN pacing gain、初始 32 包、四包窗口下限、最大窗口及历史容量。
- ProbeRTT 的 5 秒调度、10 秒 RTT filter、半 BDP、200ms 加完整 round。

profile 和参数保存在控制器不可变部分，路径重置、PMTU 和采样错误恢复均不会
静默丢失选择。`OH_MY_HYSTERIA_BBR3_DEBUG=1` 的快照增加 `profile` 字段。

## 验证与小流量公网原则

单元测试覆盖标准参数保真、三档 gain / headroom / 探测调度、重置保持、CE /
loss / ProbeRTT 不变量、配置归一及非法配置。Gecko 集成分别验证三档的 TLS、
1 MiB TCP echo SHA256 与 32 次 UDP 回环；这些回环不消耗 LTE 流量。
Sender fuzz 覆盖三档及路径重置，Linux race / 受控网络结果见构建报告。

受控网络使用 VPS 内部隔离命名空间，`--modes bbr3-conservative bbr3 bbr3-aggressive`
及可选 `--stress`，不会通过公网 / LTE。上传、SSH、日志回收和本地构建走用户
普通宽带，不因 LTE 流量顾虑而缩减这些验证。

LTE 公网只计划每档两轮、每方向 256 KiB，合计 **3 MiB 应用负载**；首个失败
即停止，不自动重试、不回退裸 QUIC。VPS 公网接口另按 IPv4 / UDP 测试端口
累计观测 IP 长度，超过 6 MiB 或计数异常便停止测试服务。
该计数不是运营商账单：不含以太网 / 漫游隧道 / 链路重传，也看不到到达 VPS
之前已丢失的上行报文。最终应报告实际观测量，而非把应用负载当作全部计费量。

短连接主要观察 Startup；即使完成，也不足以根据一次不稳定 LTE 出口的结果
宣布某一档全局最优。实际结果及局限统一见 [BUILD-REPORT.md](../BUILD-REPORT.md)。

## 本次结果（2026-10-29）

- Windows / Linux 新包覆盖率 96.1%；Linux 三模块、本地 QUIC、拥塞包 race、
  三档 Gecko race、30 秒 profile Sender fuzz、vet 通过。Python 21/21 通过。
- 五个隔离场景、每档两次、每方向 4 MiB：**30/30 双向完成**，三档均观察到
  七个状态，采样错误为零。240 MiB 应用负载留在 VPS 内部，不消耗 LTE。
- LTE 六次小流量对照 **6/6 双向完成**，没有失败重试或裸 QUIC 回退；三档
  `profile` 快照与配置匹配、采样错误为零。公网仅观察到 Startup。

公网各档的两次结果（Mbit/s，中位数及范围；不作性能排名）：

| profile | 下载 | 上传 |
| --- | --- | --- |
| conservative | 2.845（2.77–2.92） | 2.090（2.07–2.11） |
| standard | 2.840（2.61–3.07） | 2.230（2.20–2.26） |
| aggressive | 2.675（2.40–2.95） | 2.265（2.24–2.29） |

实际应用负载 **3,145,728 字节（3 MiB）**；VPS eth0 观测 IPv4 IP 长度总计
**4,031,132 字节（约 3.84 MiB）**，低于 6 MiB 观测预算，抓包丢弃为 0。
只计长度，不落盘报文内容；该值仍不是运营商计费量，尤其不能覆盖到达 VPS
前已丢失的上行数据或漫游隧道开销。SSH、上传及日志回收没有计入 LTE 测试量。

原始结果、模型统计、预算及产物 / 源码 SHA256 位于 `build/bbr3-profiles/`。
没有根据六个短样本重设默认档位，也没有宣称 aggressive 比 standard 更快。
