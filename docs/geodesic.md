# Geodesic：更实验性的 KCC/UCP QUIC 适配

```yaml
congestion:
  type: geodesic
```

客户端 / 服务端分别配置各自发送方向；省略客户端 `bandwidth.up/down`，服务端
需要时用 `ignoreClientBandwidth: true`，否则原有 Brutal 带宽协商仍优先。
默认仍是旧 `bbr`，回退改回 `type: bbr`。不支持 `slowStart: hystart++`；
`legacy` 只是兼容配置值，实际使用独立 Startup。`bbrProfile` 不参与本算法，
不新增三档 Geodesic 或自动选优策略。

## 来源、版本和许可

- Linux 模块 [liulilittle/kcc](https://github.com/liulilittle/kcc/tree/c8bead4638c9257c98760c386a0a5cf4fe2e3d20)，
  固定 `c8bead4638c9257c98760c386a0a5cf4fe2e3d20`（2026-10-19）。
- 用户态 [liulilittle/ucp](https://github.com/liulilittle/ucp/tree/927cb83bb509f293a44bd26be52edd34dae09863)，
  固定 `927cb83bb509f293a44bd26be52edd34dae09863`（2026-08-05），C++ 与 C# 交叉核对。

KCC 根许可明确允许 BSD 或 GPL 二选一；本项目对适配策略选择其 **两条款 BSD**
选项，UCP 部分保留 **MIT**。完整原许可（含 KCC 两选项原文）原样保存在
`third_party/geodesic/`，构建产物 / Docker 附带两个对应许可文件。Go 传输适配、
采样 / pacing 基础设施、诊断与新测试为 MIT-0；混合来源文件保留声明和修改说明。
不导入 Linux/Google BBR C 文件，不加载内核模块，不替换 TCP，不引入 UCP 的
可靠传输、FEC、SACK/NAK、私有 ACK 字段或全局带宽 KF。

## 研究发现：不能直接照抄较早 UCP

UCP 中 G2 每 ACK 增长 12.2%，G3 也按 ACK 累积 6/7 次；批量 ACK 下会在一个
RTT 内误将本端探测队列认作路径增长。较新 KCC 已明确修正为 **每 RTT round**
的 G2 / 已完成 round 最小 RTT 的 G3，并为 probe-up 添加 2 RTT 超时。
本适配采用修正方向，绝不把每个被确认包当作独立 RTT 样本或独立 round。

较早 UCP 的字节 / segment 换算、10 个 ACK 样本替代 10 round 的窗口、
`flight+ACK <= cwnd` 恢复条件的自满足问题也不直接照搬。
基于本项目已验证的独立 delivery sampler 做连接本地副本，**不复用旧 BBR
sampler，不改动 BBRv3 包**。速率取发送 / ACK 间隔较长者，而不是直接把每个
ACK 的 bytes / ACK 间隔当作容量，避免 ACK 压缩制造假带宽。

## 机制与固定基线

| 项目 | 本实现 |
| --- | --- |
| 状态 | Startup → Drain → ProbeBW；不设 ProbeRTT |
| Startup / Drain pacing gain | 739/256 ≈2.887 / 88/256 ≈0.344，另乘 0.99 |
| ProbeBW 八相位 gain | 1.25、0.75、1、1、1、1、1、1，另乘 0.99 |
| cwnd gain | Startup / Drain 739/256，ProbeBW 2 |
| 初始 / 下限 / 上限窗口 | 32 / 4 / 20000 MSS |
| full-bandwidth | 3 个有效、非 app-limited round 未增加 25% |
| BW 窗口 | 10 个有效容量 round 的 max；只随有效、非 app-limited、交付至少1 MSS的样本推进；低控制流/空闲不淘汰容量，高 app-limited 样本仍可抬高估计 |
| G1 | 新鲜 RTT ≤估计时立即下降 x；x 有 10 位微秒小数 |
| G2 | 每 round 至多一次 x +=12.2%，且不超过观测 |
| G3 fast / slow | 连续 6 个 completed round ≥1.10×基线 / 7 个 ≥1.05×基线 |
| G3 QUIC 证据准入 | 仅 ProbeBW 且 completed round 有合格非 app-limited 数据容量样本才允许上调；Startup/Drain/控制流断开向上证据，下降确认独立 |
| G3 区域 | 观察到的 round min ≥7.5ms 才有 slow；5..7.5ms 仅 fast |
| 短路径锁 | 初始 / 已确认基线 ≤5ms 且观测 <5ms；7 个连续 round ≥7.5ms 可解锁 |
| min RTT 下降 | >4×下降需 2 round；其他明显下降需 5 round；<5% 小降可直接接受 |
| G4 / BDP | 只用已确认 min RTT，不用尚未确认的 min(x,minRTT) 直接削窗口 |
| staleness | 128 round 未更新且 x≤1.10×基线时，向下拉至不高于 0.95×基线；不低于 1µs |
| SRTT guard | 低于基线90%连续5 round；确认升高后抑制24 round |
| queue / jitter | 7/8 EWMA；queue 针对已确认基线，不针对刚增加的 x |
| ACK aggregation | 双窗口、每5 round轮换；按字节补偿，上限 BW×100ms，仅完整带宽后且 RTT≥7.5ms |
| GSO / quantum | 按速率 / jitter 估计分段，1..127 包；QUIC quantum 最多64KiB |
| loss recovery | 实际丢失字节扣减一次；packet-number episode 限制 conservation / 退出 |
| LT policer | 两个相近的高 loss、4..16 round 窗口，带 queue/SRTT gate；有效至多48 round |
| CE | Classic CE 每 flight episode 至多一次 cwnd×0.7，转 Drain / 下探；本地安全扩展 |

没有迁入全局 KF、UCP 初始 12.5 MB/s 假设、用接收窗口直接抬高初始 cwnd、
Linux TCP 状态机 / EDT 队列预测。QUIC 已独立负责流控，接收窗口不能冒充拥塞窗口。
由于 rich API 只提供 CE 事件而非完整 CE byte fraction，不能复刻可选 ECN EWMA，
更不能声称 L4S / DCTCP 支持。基线固定于测试前，不按一次线路结果临时重调。

## QUIC 合约与安全边界

- 只处理 Application 包号空间；legacy 逐包回调不重复记账。after-send flight
  已含本包，不再加一次。全部活跃历史硬上限131072，累积字节溢出显式恢复。
- RTT 只在 rich `RTTUpdated` 且有已知新 ACK 时更新；纯 loss、重复 / 未知 ACK、
  PMTU probe 不注入 RTT。混合 PMTU 批次也不更新延迟估计。ACK/loss 用保存的
  实际包大小，不信任重复回调的字节声明。
- socket 接收时间可早于已经处理的 send；模型时钟取单调最大值，不因此丢 ACK。
  真正早于上一 RTT 观测的样本不刷新估计。completed round 无 RTT 时断开 G3
  连续证据，不能跨观察空洞拼满6/7次。
- app-limited 由实际传输层通知，不把 pacing / cwnd / 流控等待误判为空闲。
  app-limited 样本不导致 Startup 平台退出；空闲恢复重置探测相位计时 / ACK epoch。
- PMTU 增长保留已建立字节窗口，初始窗口随 MSS 调整；迁移 / Retry 重置全部
  Geo / bandwidth / packet-history 模型。不修改模块缓存或 QUIC 报文。
- spurious undo 只在完整 episode 的全部相关 loss 都证明虚假时恢复窗口；
  episode 集合最多64包，退休 / 超界 / CE 会使 undo 失效，不能撤销 CE 退避。
  该 undo 只恢复窗口；已经累计的 loss / LT policer 统计不追溯撤销，不等于完整
  BBRv3 模型 undo。
- QUIC PTO 不当作 TCP RTO；rich API 没有独立 persistent-congestion 标志，
  不宣称实现 RFC 9002 全部持续拥塞恢复策略。

`OH_MY_HYSTERIA_GEODESIC_DEBUG=1` 向 stderr 输出限频 `geodesic snapshot {..}`，
含模式、八相位、速率 / 窗口、确认基线、x、queue/jitter EWMA、G1/G2/G3、
锁 / policer、采样错误和未知 ACK。无认证、地址或包内容；并发 Snapshot 受锁保护。
另含 `BandwidthRound` / `RejectedBandwidthSamples` / `RoundQualified` /
`LastSampleAppLimited`，区分容量窗口时钟与一般 delivery round。
其中 confidence 是有界启发式计数，**不是 Kalman 协方差或统计置信度**。

## 必须保留的实验限制

“Geodesic / 网络测地线”在此是参考项目的工程命名，不是求解时空流形的测地线，
更不是全网最优性证明。一个端到端 RTT 不能在无额外假设时唯一分解成传播、
排队、噪声；移动网链路重传 / 调度噪声可能与拥塞相关。G3 的连续高 RTT 也
可能来自持久外部队列，而不是真实路径变长，不能用源仓库仿真 / 证明文案为
本 QUIC 适配的公平性、鲁棒性或物理最优背书。

短路径锁仍有明确盲区：锁定后真实基线若仅升到5..7.5ms，可能不会解锁，需要
显式路径重置；保留该参考边界并有回归测试，不宣称所有路径变化都可识别。
没有 ProbeRTT 会降低主动测底噪的干扰，但也缺少强制排空来校验传播基线，不能
保证竞争环境长期正确。LT policer 可能误判；真实多流公平性和高包率尚需专项验证。

容量准入的“至少1 MSS交付”是字节启发式，不是对 STREAM payload 的识别；
rich API没有逐包应用payload长度，大量控制流仍可能过门槛，而只发小包的应用
可能保持旧估计/初始seed。该门槛避免本次几十字节控制包淘汰容量，不构成所有
app-limited、反向流量或真实带宽下降场景的完备分类。

## 初版问题与修正动机

首轮56个VPS内部样本均完成，但Geodesic有一次116.23秒的端到端收尾长停顿，
server容量从约603KB/s塌至228B/s；分方向upload speed 3.78Mbps没有包含
等待summary的时间，不能据此判定验证通过。另有静态200ms链路G3误上调至
242.666ms，以及静态80ms链路Drain阶段上调至113.748ms。原始日志、快照、
源归档和匹配二进制保存在 `build/geodesic/initial/`，不删除失败证据。

因此修正容量窗口时钟及G3上调证据准入，并添加控制包30+round容量保持、
真实满载容量下降、Startup/Drain/app-limited向上证据阻断等回归；gain与G3
阈值不变。初版问题发现后暂缓LTE，不用公网小样本掩盖隔离链路缺陷。修正版
网络结果与局限追加在 `BUILD-REPORT.md`。

## 修正版隔离验证结果（2026-10-29）

Windows相关完整测试、Linux三模块/本地QUIC测试、race、vet与有界fuzz通过，
Geodesic包覆盖率96.2%。7场景×4算法×2次共56/56完成，静态4MiB/方向、
动态16MiB/方向，合计832MiB应用数据全部留在VPS隔离网络。Geodesic三状态和
八相位可见，SamplingErrors=0，UnknownACKs最大2，History最大601；未观测
policer激活。**这些是有限样本，不是生产就绪或动态模型正确性的验收。**

- 350ms/1%loss两个静态样本wall time为19.44/19.89秒，未再复现初版116.23秒
  收尾或几百B/s容量塌缩。10个Geodesic静态样本均未观测G3上调，不能推断
  所有静态队列下都不会误判。
- 80→240ms：两次client均确认到约240.1ms；server一次确认，另一次因合格
  连续证据不足仍保持约80.1ms，最终容量约399KB/s。门控降低误判但也会漏检，
  不能说上升路径已可靠识别。
- 240→80ms：负载中曾观测到约80.1ms，但server一次出现3次额外向上确认；
  最终client约114.1/116.7ms，server约80.1/116.9ms。持续队列仍可能污染确认
  基线，**不能说下降已稳定恢复到真实传播RTT**。
- 200ms深队列Geodesic负载ping约397.2ms，COPA约229.1、BBRv3约361.3、
  旧BBR约290.7ms；这批结果不支持Geodesic更低延迟或全面更快。动态场景和
  初版负载不同，不将其速度差解释为修正带来的性能收益。

因此保留 opt-in、更实验性标记和全部反例；不继续调gain/阈值来追逐这一批结果。
公网小负载冒烟仅验证Gecko/TLS连通传输，不用于补齐动态估计、公平性或性能证明。

首先用本地单元、fuzz / Linux race、Gecko + 正常 TLS TCP/UDP 和 VPS 隔离链路
验证。受控 benchmark 显式 `--modes geodesic bbr3 copa bbr`，不增加默认负载。
可选 `--path-change` 增加80→240ms / 240→80ms整形阶跃，客户端启动2秒后执行，
不迁移网络地址、不触发显式 QUIC path reset。替换qdisc可能丢掉当时队列，且
qdisc计数会重置，不把其末尾统计解读为全程丢包；这是合成链路变化，不是真实
传播路径切换的证明。计时器未执行或整形失败则样本无效，线程在清理前回收。
`--path-change-data-size` 可仅为动态场景预声明4..32MiB/方向负载；不改变默认
或静态样本大小。报告必须保留端到端 wall time，不能仅用分方向 speed 掩盖收尾等待。
若做公网 LTE 冒烟，限定2连接、每方向256KiB（合计1MiB应用负载），VPS观测
3MiB IPv4长度预算，首次失败即停，无自动重试或裸 QUIC 回退；不把IP观测量当
运营商账单。普通宽带、SSH、上传及VPS内部测试不受LTE流量预算限制。

本轮Gecko-only、正常TLS验证的LTE冒烟2/2完成，每方向256KiB，共1MiB应用
负载；总wall约5.30/5.38秒，VPS观测IPv4长度1,308,066字节（1395包），
低于3MiB预算，capture drops=0。该观测不含漫游隧道/链路层开销，也看不到到达
VPS前丢失的上行包，不等于运营商计费量。不自动重试，不回退裸QUIC。UDP443、
本轮进程和隔离命名空间均已停止，VPS保留至正式发布。
