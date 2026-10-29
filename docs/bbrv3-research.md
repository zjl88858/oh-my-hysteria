# 当前 BBR 版本确认与 BBRv3 接入研究

研究日期：2026-10-28。范围：当前 oh-my-hysteria 源码及其固定的
`github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c` 依赖。

**结论：当前 BBR 属于 BBRv1 派生实现，包含后续改进，但不是完整 BBRv2/v3。
BBRv3 可以引入，不过需要独立控制器和采样 / 传输接口适配，不是调参升级。
本次仅研究，没有新增可用的 `type: bbr3`，没有改动当前 BBR 或默认行为。**

后续状态（2026-10-29）：已接入独立实验性 `congestion.type: bbr3` 控制器，
并在版本化的 `third_party/quic-go/` 增加 opt-in 事件适配。
阶段、输入契约及验证边界见 [实施状态](bbrv3-implementation.md)。下文保留
**研究当时**的证据与建议；其中“未接入 / 接口缺口”不是当前实现状态。

## 1. 当前版本的判断依据

实际安装路径是 `core/internal/congestion/utils.go` 的 `UseBBR` 调用本项目
`bbr.NewBbrSender`，不是 Linux TCP 的 BBR，也不是 quic-go 内置控制器。

`core/internal/congestion/bbr/bbr_sender.go` 的证据：

| 位置 | 观察 | 判断意义 |
| --- | --- | --- |
| `defaultHighGain`（约第 38 行） | 默认启动 pacing gain 为 2.885 | 典型 v1 参数之一，单独不足以定版本 |
| `pacingGain`（约第 46 行） | `[1.25, 0.75, 1, 1, 1, 1, 1, 1]` | v1 的固定八阶段 ProbeBW 增益循环 |
| `bbrMode` / `updateGainCyclePhase` | Startup、Drain、ProbeBw、ProbeRtt，ProbeBw 内轮转增益下标 | 没有 v2/v3 的 Down / Cruise / Refill / Up 子状态模型 |
| `bandwidthWindowSize` / `maxBandwidth` | 最大带宽按约 10 个 packet-timed RTT 过滤 | 不是 v3 的跨 ProbeBW 周期模型及短期拥塞约束 |
| `probeRttCongestionWindow` | 返回最小窗口，即 4 个报文 | 保留 v1 风格 ProbeRTT 行为 |
| `configForProfile` / `applyProfile` | conservative、standard、aggressive 调整增益及启发式选项 | 是预设参数，不是不同代际算法 |

这与 Google 在 [BBR 仓库 README][google-bbr] 的“BBR v1 releases”中指向的
QUICHE `bbr_sender.cc` 的增益循环和状态结构一致。

必须保留一个限定：当前实现并非“完全未经修改的原始 BBRv1”。例如
`shouldExitStartupDueToLoss` 已使用丢包事件数和 2% 阈值来退出启动，采样器也
包含 ACK 聚合 / 过估计抑制等改进。源码中的 `quicBbr2DefaultLossThreshold`
名称不能证明已经实现 BBRv2：缺失完整网络模型及状态机才是决定性证据。

因此准确称呼应为 **“BBRv1 派生版 / 带改进的 BBRv1”**，而非完全忽略丢包的
原版 v1，也不能标作 v2 或 v3。

## 2. BBRv3 的参考规范与代码

### 2.1 主依据：IETF BBRv3 草案

本次核验的最新版本为 [draft-ietf-ccwg-bbr-06][draft]，发布日期 2026-07-06。
摘要和正文明确说明其描述 **BBRv3**。目前仍为面向 Experimental RFC 的
Internet-Draft，不应写成“BBRv3 已成为正式 RFC”。

相较当前实现，主要工作包括：

- ProbeBW 的 Down / Cruise / Refill / Up 子状态及 ACK 反馈阶段。
- 带宽和在途数据的短期 / 长期约束，基于丢包更新路径模型及留出 headroom。
- 跨 ProbeBW 周期的最大带宽过滤、Reno/CUBIC 共存探测调度。
- 完整的每包发送快照、delivery-rate、app-limited、丢包率采样。
- 区分 min-RTT 过滤窗口与 ProbeRTT 调度，处理空闲重启及聚合补偿。
- 在传输层报告整个恢复事件为误判时，恢复相应网络模型和状态。

新版草案使用 `bw_shortterm`、`inflight_shortterm`、`inflight_longterm` 等名称；
较早代码常见 `bw_lo`、`inflight_lo`、`inflight_hi`。必须先固定规范版本再做
逐项映射，不能把不同年代的参数和伪代码随意拼接。

### 2.2 候选实现及其用途

| 来源 | 可利用之处 | 不能直接照搬的原因 |
| --- | --- | --- |
| [Google Linux BBRv3][linux-bbr3] | 明确标注 BBR_VERSION=3；完整状态、损失响应和恢复逻辑；GPL-2.0 OR BSD-3-Clause | 是内核 TCP C 代码，依赖 TCP 发送、重传、采样和 offload 语义，不能直接用于 Go QUIC |
| [Google QUICHE][quiche-bbr2] | 官方 QUIC 模型、采样器、测试；草案第 6 节将 `bbr2_sender` 路径列为公开 BBRv3 实现参考 | 文件 / 类型仍叫 Bbr2，存在选项及历史差异；不能仅凭文件名或整段翻译就宣称符合当前 v3 草案 |
| [Tencent TQUIC BBR3][tquic] | Rust QUIC 中的状态拆分、采样和集成参考 | 当前文件仍引用旧草案和 2023 年演讲，需要核对与 -06 的差异；不是可导入的 Go 包 |
| [bompus/quic-go-bbr3][go-port] | 已有约 1350 行 Go 控制器和模拟测试，可辅助研究移植及在途字节同步 | README 明确说是实验、不是受支持库；基于 upstream quic-go v0.64.1 内部接口并直接替换 Reno，不适配当前 apernet 公开接口；测试不足以证明普遍性能与公平性 |

本次记录的参考修订：

- Google 2026-09-16 BBRv3 分支：`674859761ded9f32690c7bdaf22ef585531452ed`。
- Google QUICHE main：`fc4f6dd734c2d94dddbc6dd38871d9c67f1817a7`。
- Tencent TQUIC develop：`938e90adb460b5ff08b2bc6d11a3e1ba52c27a8d`。
- bompus/quic-go-bbr3 main：`b5b4468f46b53a6c03be40c74cd2946a5120111c`。

参考代码并非已审计、可直接合入的依赖。本次没有导入这些实现。
主线 quic-go 的 [BBRv3 issue #4565][upstream-issue] 在核验时仍为 open，
不能把“升级 quic-go”当成已经获得官方 Go BBRv3 的方案。

## 3. 当前 QUIC 接口能提供什么

依赖中的 `congestion/interface.go` 已提供：

- `OnPacketSent`：发送时间、包号、报文大小、在途字节数。
- `OnCongestionEventEx`：ACK / loss 批次、事件时间、处理前在途字节数。
- `RTTStatsProvider`、`SetMaxDatagramSize`：RTT 及 PMTU 更新。
- `TimeUntilSend` / `HasPacingBudget` / `CanSend` / `GetCongestionWindow`：
  pacing 与窗口控制。

所以**使用纯 Go 在当前接口上实现 BBRv3 原型是可行的**，无需更改 Hysteria2
线上协议，也不需要对端采用相同算法。沿用认证成功后安装控制器的方式即可。
但接口存在下列限制；原型可用不等于完整规范适配或生产可用。

## 4. 必须审计的适配问题

### 4.1 发送时在途字节的语义已经不一致

当前 quic-go `internal/ackhandler/sent_packet_handler.go` 在约第 315–325 行，
先将当前报文计入 `h.bytesInFlight`，再调用 `OnPacketSent`。

而本项目 `bbr/bandwidth_sampler.go` 约第 590–595 行，在记录发送快照时又传入
`bytesInFlight + bytes`。例如空连接发送 1200 字节，回调已传入 1200，采样器
的快照却记录成 2400。对照调用链，这里存在静态可见的重复计入问题。

迁移前应以测试固定“发送前 / 发送后”的契约，校正 tx-in-flight、空闲重启及
app-limited 判断。**不能将现有 sampler 原样复用到 BBRv3。**本次没有修改
旧 BBR，也没有据此推断具体的吞吐损失幅度。

### 4.2 非 ACK / loss 的报文移除与 PMTU 探测

`DropPackets`、`QueueProbePacket`、Retry 等路径可能直接减少传输层在途字节，
没有对应的完整自定义控制器通知。单纯依靠“发送加、ACK / loss 减”的自有
计数会漂移，可能影响 ProbeRTT 等待退出。

本依赖还有一个容易误判的差异：PMTU 探测报文丢失时，不调用普通
`OnCongestionEvent`，但仍会加入 `lostPacketsInfo` 给 Ex 回调；公开记录又不带
`IsPathMTUProbePacket` 标记。BBRv3 不能把所有 PMTU 探测失败直接计入普通
拥塞丢包率，也不能漏掉这些报文的在途字节回收。

建议补充权威在途计数读取 / 移除通知及报文标记。原型至少应利用传输层提供的
在途计数校准，记录尚不能精确处理的情况。

### 4.3 app-limited、cwnd-limited 与误判丢包

- 当前接口没有明确的“应用已无待发数据”通知。不能将 pacing-limited、
  flow-control-limited 或 cwnd-limited 简单等同于 app-limited。
- `detectSpuriousLosses` 能发现已报丢包后来收到 ACK 的情况，但目前只清理
  内部记录并写 qlog，没有向控制器报告误判丢包恢复事件。
- 草案第 5.2.5 / 5.5.11 节描述了相应的恢复模型步骤；仅凭当前公开接口不能
  无条件声称已实现完整的 spurious-loss undo。
- 当前接口虽然声明 `OnRetransmissionTimeout`，生产 ACK handler 中没有
  找到主动调用它的路径。QUIC PTO 不等于 TCP RTO，不能依赖这个方法获得
  Linux TCP 的超时状态转换。

### 4.4 ECN 不是“不支持就忽略”

草案 -06 第 3.7 节没有规定一种固定的 Classic ECN / L4S 响应算法，因此
**ECN/L4S 计数不是实现 BBRv3 原型的绝对前提**。

但同一节明确要求：如果连接通过 ECT(0) / ECT(1) 宣称支持 ECN，就必须将 CE
视作拥塞。当前接口只能给出普通 `OnCongestionEvent(..., lostBytes=0, ...)`
形式的拥塞通知，没有完整 ECT / CE 计数。现有 BBR 的该方法为空，不能照搬
这个行为到新控制器后仍宣称 ECN 支持正确。需要实现明确、经测试的 CE 响应，
或在传输层明确不宣称 ECN 支持；不能伪造计数或静默吞掉 CE。

### 4.5 pacing、GSO、迁移与回调顺序

- 现有批次回调前还会触发逐包 ACK / loss 回调；BBRv3 每个事件只能记账一次，
  同时正确支持 loss-only、重排 ACK 和没有 RTT 更新的 ACK 批次。
- `AckedPacketInfo.ReceivedTime` 虽有字段，但当前 ACK handler 填充时没有
  赋值；不能把该字段直接当作有效时间戳，事件时间应使用实际提供的参数。
- 需要核对发送量单位、pacing 预算与 send quantum / GSO 的关系，以及 PMTU
  增长后的窗口与采样历史，避免直接搬用 Linux 的 TCP 段数假设。
- 主动路径迁移仍会把控制器重置为内置 Reno。完整接入应有控制器工厂 / 重置
  机制；不能让“配置了 bbr3，但迁移后其实已是 Reno”成为无提示的行为。

## 5. 推荐落地路线

1. **保持回退**：保留 `type: bbr` 的现有含义与 profiles，新建独立 `bbr3`
   控制器。通过实验性显式选项进入，不直接替换默认 BBR。
2. **固定目标**：以草案 -06 为行为依据，固定参考代码 SHA，列明规范、Linux、
   QUICHE 之间采用了哪些差异。不要仅修改 2.885 → 2.77 或增加几个状态名。
3. **先验证采样契约**：为发送快照、delivery rate、RTT、loss、app-limited、
   PMTU、报文移除和回调顺序建立可重放测试。短期不重构旧 BBR，以保留可靠
   的对照组。
4. **分离原型与完整适配**：纯公开接口可以做带限制的实验原型；若目标是
   较完整的规范行为，应在受版本管理的 quic-go Fork 中增加可选的事件上下文、
   应用空闲 / 报文移除 / 误判恢复通知，以及迁移时的控制器生命周期支持。
   不修改 Go 模块缓存，也不通过 unsafe 读取内部结构。
5. **功能集成**：接入两端配置、非法组合校验和调试指标。BBRv3 使用自身
   Startup，不套用 CUBIC / Reno 的 HyStart++；Brutal 带宽协商优先级不变。
6. **验证后再考虑默认值**：单元测试和回环传输只是起点。先做受控链路实验，
   再进行具备观测指标的真实部署与 A/B；吞吐、丢包率、排队时延、ProbeRTT
   驻留、恢复时间、CPU / 内存和多流公平性都需评估。

建议至少覆盖：浅 / 深缓冲、多种 RTT / BDP、随机及突发丢包、ACK 压缩 / 稀疏、
应用受限、带宽骤升骤降、PMTU、PTO、重排 / 误判丢包、GSO 开关，以及
BBRv3 与 BBRv1 / CUBIC / Reno 的竞争。草案附录 A 的 22 个用例可作为测试
清单的重要依据，但不能替代生产观察。

BBRv3 的目标包括改善队列压力及共存，不保证在所有代理线路上比 BBRv1 更快，
尤其不能把 Linux TCP 或第三方单一网络的测量结果直接当成本项目 QUIC 的收益。

## 6. 许可和“不需要做”的事情

- 不需要升级 Linux 内核或设置 `net.ipv4.tcp_congestion_control=bbr` 来实现
  此功能；这些设置影响内核 TCP，不会升级 Hysteria 外层用户态 QUIC 的 BBR。
- 不需要更改 Hysteria2 认证头、分享 URI 或强制对端升级。
- 如果移植 Google / 第三方代码，按对应 BSD / Apache 等条款保留许可、版权、
  修改说明及适用的 NOTICE，不能将继承代码整体改成 MIT-0。
- Google 双许可代码可以选择 BSD 分支，但不能据此假设 Linux 源码树的其他
  文件都具有相同双许可；例如 delivery-rate 参考代码也须逐文件核验。
- 本次没有引入任何第三方源码或新增运行时依赖，没有进行 BBRv3 编译、性能
  或生产可用性验证。

[google-bbr]: https://github.com/google/bbr/blob/master/README.md
[draft]: https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html
[linux-bbr3]: https://github.com/google/bbr/blob/674859761ded9f32690c7bdaf22ef585531452ed/net/ipv4/tcp_bbr3.c
[quiche-bbr2]: https://github.com/google/quiche/blob/fc4f6dd734c2d94dddbc6dd38871d9c67f1817a7/quiche/quic/core/congestion_control/bbr2_sender.cc
[tquic]: https://github.com/Tencent/tquic/blob/938e90adb460b5ff08b2bc6d11a3e1ba52c27a8d/src/congestion_control/bbr3.rs
[go-port]: https://github.com/bompus/quic-go-bbr3/tree/b5b4468f46b53a6c03be40c74cd2946a5120111c
[upstream-issue]: https://github.com/quic-go/quic-go/issues/4565
